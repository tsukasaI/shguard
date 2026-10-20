//! Replays `tests/golden/legacy_units.jsonl`: the inputs of the `gate` and
//! `rules` unit tests, with the decision (gate) or matcher result (rules)
//! each produced, kept so the corpus outlives those tests (RFC R0).
//!
//! The embedded-rule gate rows go through the public [`shguard::analyze`]
//! here. `rules` is a private module, so the rules rows and the gate rows
//! built on a custom rule set are replayed by the library test
//! `legacy_units::tests::corpus_replays` (`cargo test --lib legacy_units`).
//!
//! `harness = false` so the summary line shows in a plain `cargo test`.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use serde_json::Value;

#[path = "common/golden.rs"]
#[allow(dead_code)]
mod golden;

const CORPUS: &str = include_str!("golden/legacy_units.jsonl");

struct Corpus {
    gate_public: Vec<Value>,
    gate_internal: usize,
    rules: usize,
    excluded: usize,
    config_ids: BTreeSet<String>,
}

/// FNV-1a-64 of the text, as 16 hex digits: the id `legacy_units::config_id`
/// gives a `config` header row.
fn config_id(text: &str) -> String {
    let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{hash:016x}")
}

fn str_field_of<'a>(fields: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    fields.get(name).and_then(Value::as_str)
}

/// Header rows precede the rows that cite them, so an id not yet seen is
/// unknown.
fn check_config_refs(
    fields: &serde_json::Map<String, Value>,
    known: &BTreeSet<String>,
) -> Result<(), String> {
    for source in ["rules", "allowlist"] {
        let id = fields
            .get("config")
            .and_then(|config| config.get(source))
            .and_then(|source| source.get("parse_ref"));
        if let Some(id) = id {
            let id = id.as_str().ok_or("parse_ref is not a string")?;
            if !known.contains(id) {
                return Err(format!("unknown config id {id:?}"));
            }
        }
    }
    Ok(())
}

fn is_unreplayable(config: &Value) -> bool {
    ["rules", "allowlist"].iter().any(|source| {
        config
            .get(source)
            .and_then(Value::as_object)
            .is_some_and(|object| object.contains_key("unreplayable"))
    })
}

fn load(text: &str) -> Result<Corpus, String> {
    let mut keys = BTreeMap::new();
    let mut corpus = Corpus {
        gate_public: Vec::new(),
        gate_internal: 0,
        rules: 0,
        excluded: 0,
        config_ids: BTreeSet::new(),
    };
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let row: Value = serde_json::from_str(line)
            .map_err(|err| format!("legacy_units.jsonl line {number}: {err}"))?;
        let Value::Object(mut fields) = row else {
            return Err(format!("legacy_units.jsonl line {number}: not an object"));
        };
        let kind = fields
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("legacy_units.jsonl line {number}: missing kind"))?
            .to_string();
        if kind == "config" {
            if let Some(key) = fields
                .keys()
                .find(|key| !["kind", "id", "toml"].contains(&key.as_str()))
            {
                return Err(format!(
                    "line {number}: config row with unknown key {key:?}"
                ));
            }
            let id = str_field_of(&fields, "id")
                .ok_or_else(|| format!("line {number}: config row without id"))?;
            let toml = str_field_of(&fields, "toml")
                .ok_or_else(|| format!("line {number}: config row without toml"))?;
            if id != config_id(toml) {
                return Err(format!(
                    "line {number}: config id {id:?} is not the id of its toml"
                ));
            }
            if !corpus.config_ids.insert(id.to_string()) {
                return Err(format!("line {number}: duplicate config id {id:?}"));
            }
            continue;
        }
        check_config_refs(&fields, &corpus.config_ids)
            .map_err(|err| format!("line {number}: {err}"))?;
        let expect = fields.remove("expect");
        let reason = fields.get("reason").cloned();
        let mut identity = fields.clone();
        if fields.get("config").is_some_and(is_unreplayable) {
            // No rule set is named, so the result is part of the row's identity.
            identity.insert("expect".to_string(), expect.clone().unwrap_or(Value::Null));
        }
        if let Some(first) = keys.insert(Value::Object(identity).to_string(), number) {
            return Err(format!(
                "legacy_units.jsonl line {number}: duplicate of line {first}"
            ));
        }
        match kind.as_str() {
            "gate" => {
                if fields.contains_key("config") || fields.contains_key("cwd") {
                    corpus.gate_internal += 1;
                } else {
                    let command = fields
                        .get("command")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("line {number}: gate row without command"))?;
                    let expect = expect.ok_or_else(|| format!("line {number}: no expect"))?;
                    corpus
                        .gate_public
                        .push(serde_json::json!({ "command": command, "expect": expect }));
                }
            }
            "rules" => corpus.rules += 1,
            "excluded" => {
                if reason.is_none() {
                    return Err(format!("line {number}: excluded row without reason"));
                }
                corpus.excluded += 1;
            }
            other => return Err(format!("line {number}: unknown kind {other:?}")),
        }
    }
    if keys.is_empty() {
        return Err("legacy_units.jsonl has no rows".to_string());
    }
    Ok(corpus)
}

fn str_field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

/// Why a replayed row failed. A watchdog trip says the row ran out of time
/// or memory, not that the engine disagrees with the corpus.
enum Failure {
    Mismatch(String),
    Watchdog(String),
}

fn replay(row: &Value) -> Result<(), Failure> {
    let command = str_field(row, "command").unwrap_or_default();
    let expect = &row["expect"];
    let verdict = shguard::analyze(command);
    if verdict
        .reason()
        .is_some_and(|reason| reason.as_str().ends_with(golden::WATCHDOG_REASON_SUFFIX))
    {
        return Err(Failure::Watchdog(format!("{command:?}")));
    }
    let got = serde_json::json!({
        "decision": format!("{:?}", verdict.decision()).to_lowercase(),
        "reason": verdict.reason().map(|r| r.as_str()),
        "rule": verdict.matched_rule().map(|r| r.as_str()),
        "deny_message": verdict.deny_message().map(|m| m.as_str()),
        "suppressed_by": verdict.suppressed_by().map(|r| r.as_str()),
    });
    if got == *expect {
        Ok(())
    } else {
        Err(Failure::Mismatch(format!(
            "{command:?}\n  expected {expect}\n  got      {got}"
        )))
    }
}

const MAX_REPLAY_THREADS: usize = 8;

/// Replays `rows` on up to [`MAX_REPLAY_THREADS`] threads, each taking one
/// contiguous chunk. Chunks are joined in spawn order, so failures come out
/// in corpus order whatever the scheduling.
fn replay_all(rows: &[Value]) -> Vec<Failure> {
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_REPLAY_THREADS);
    let chunk_len = rows.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = rows
            .chunks(chunk_len)
            .map(|chunk| {
                scope.spawn(|| {
                    chunk
                        .iter()
                        .filter_map(|row| replay(row).err())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    })
}

fn main() -> ExitCode {
    if let Err(err) = loader_rejects_damage() {
        eprintln!("legacy_units: {err}");
        return ExitCode::FAILURE;
    }
    let corpus = match load(CORPUS) {
        Ok(corpus) => corpus,
        Err(err) => {
            eprintln!("legacy_units: invalid corpus: {err}");
            return ExitCode::FAILURE;
        }
    };
    let failures = replay_all(&corpus.gate_public);
    println!(
        "legacy_units: {} gate rows replayed through the public API; {} gate rows (custom rule \
         set or cwd) and {} rules rows replayed by `cargo test --lib legacy_units`; {} tests \
         excluded with a reason",
        corpus.gate_public.len(),
        corpus.gate_internal,
        corpus.rules,
        corpus.excluded,
    );
    if failures.is_empty() {
        return ExitCode::SUCCESS;
    }
    for failure in &failures {
        match failure {
            Failure::Mismatch(row) => eprintln!("legacy_units: MISMATCH {row}"),
            Failure::Watchdog(row) => eprintln!(
                "legacy_units: HARNESS FAILURE the row tripped the evaluation watchdog, so its \
                 decision is not its real one: {row}"
            ),
        }
    }
    eprintln!(
        "legacy_units: {} of {} rows failed",
        failures.len(),
        corpus.gate_public.len()
    );
    ExitCode::FAILURE
}

/// The loader must reject an empty file, a malformed line, a duplicate key, a
/// config reference to an unknown id (including one that precedes its header),
/// a duplicate config id, and a config header with a wrong id or extra key, or
/// a damaged corpus would pass as a smaller one.
fn loader_rejects_damage() -> Result<(), String> {
    let row = "{\"kind\":\"excluded\",\"test\":\"a\",\"reason\":\"r\"}\n";
    let id = config_id("a");
    let header = format!("{{\"kind\":\"config\",\"id\":\"{id}\",\"toml\":\"a\"}}\n");
    let reference = format!(
        "{{\"kind\":\"gate\",\"config\":{{\"rules\":{{\"parse_ref\":\"{id}\"}}}},\"command\":\"ls\",\"expect\":{{}}}}\n"
    );
    let damaged = [
        ("empty file", String::new(), None),
        ("malformed line", format!("{row}not json\n"), None),
        ("duplicate key", format!("{row}{row}"), None),
        (
            "config header with a duplicate id",
            format!("{row}{header}{header}"),
            Some("duplicate config id"),
        ),
        (
            "config header with a wrong id",
            format!("{row}{{\"kind\":\"config\",\"id\":\"0\",\"toml\":\"a\"}}\n"),
            Some("is not the id of its toml"),
        ),
        (
            "config header with an unknown key",
            format!("{row}{{\"kind\":\"config\",\"id\":\"{id}\",\"toml\":\"a\",\"x\":1}}\n"),
            Some("unknown key"),
        ),
        (
            "config reference before its header",
            format!("{reference}{header}"),
            None,
        ),
        (
            "config reference to an unknown id",
            format!(
                "{row}{{\"kind\":\"gate\",\"config\":{{\"rules\":{{\"parse_ref\":\"nope\"}}}},\"command\":\"ls\",\"expect\":{{}}}}\n"
            ),
            None,
        ),
    ];
    for (what, text, cause) in damaged {
        let Err(err) = load(&text) else {
            return Err(format!("the loader accepted a corpus with a {what}"));
        };
        if let Some(cause) = cause
            && !err.contains(cause)
        {
            return Err(format!(
                "the loader rejected a corpus with a {what} for the wrong reason: {err}"
            ));
        }
    }
    Ok(())
}
