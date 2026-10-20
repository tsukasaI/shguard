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

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde_json::Value;

const CORPUS: &str = include_str!("golden/legacy_units.jsonl");

struct Corpus {
    gate_public: Vec<Value>,
    gate_internal: usize,
    rules: usize,
    excluded: usize,
}

fn load(text: &str) -> Result<Corpus, String> {
    let mut keys = BTreeMap::new();
    let mut corpus = Corpus {
        gate_public: Vec::new(),
        gate_internal: 0,
        rules: 0,
        excluded: 0,
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
        let expect = fields.remove("expect");
        let reason = fields.get("reason").cloned();
        let mut identity = fields.clone();
        if fields
            .get("config")
            .is_some_and(|config| config.to_string().contains("\"unreplayable\""))
        {
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

fn replay(row: &Value) -> Result<(), String> {
    let command = str_field(row, "command").unwrap_or_default();
    let expect = &row["expect"];
    let verdict = shguard::analyze(command);
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
        Err(format!(
            "{command:?}\n  expected {expect}\n  got      {got}"
        ))
    }
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
    let failures: Vec<String> = corpus
        .gate_public
        .iter()
        .filter_map(|row| replay(row).err())
        .collect();
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
        eprintln!("legacy_units: MISMATCH {failure}");
    }
    eprintln!(
        "legacy_units: {} of {} rows mismatched",
        failures.len(),
        corpus.gate_public.len()
    );
    ExitCode::FAILURE
}

/// The loader must reject an empty file, a malformed line and a duplicate
/// key, or a damaged corpus would pass as a smaller one.
fn loader_rejects_damage() -> Result<(), String> {
    let row = "{\"kind\":\"excluded\",\"test\":\"a\",\"reason\":\"r\"}\n";
    let damaged = [
        ("empty file", String::new()),
        ("malformed line", format!("{row}not json\n")),
        ("duplicate key", format!("{row}{row}")),
    ];
    for (what, text) in damaged {
        if load(&text).is_ok() {
            return Err(format!("the loader accepted a corpus with a {what}"));
        }
    }
    Ok(())
}
