//! Shared comparator for the golden-snapshot gate (RFC #658 stage 1,
//! issue #659). See `tests/golden_snapshot.rs` for what the snapshot is
//! for and how to bless it.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use shguard::verdict::Decision;

const UPDATE_ENV: &str = "SHGUARD_GOLDEN_UPDATE";
const MAX_REPORTED_PER_BUCKET: usize = 40;

// Not `contains("fail-closed")`: only the watchdog's own verdicts end this
// way, and a loaded runner tripping its 2s budget is a harness failure, not
// a behaviour change worth recording.
const WATCHDOG_REASON_SUFFIX: &str = "refusing to evaluate (fail-closed)";

// Field order is the serialized key order; kept alphabetical so a record
// reads the same as a sorted-keys JSON dump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    command: String,
    decision: String,
    deny_message: Option<String>,
    matched_rule: Option<String>,
}

/// Whether the run blesses the snapshots.
///
/// An exported `SHGUARD_GOLDEN_UPDATE=1` must not turn a gate into a rewrite,
/// so blessing under lefthook or CI is an error rather than a quiet pass.
pub fn update_requested(var: impl Fn(&str) -> Option<OsString>) -> Result<bool, String> {
    if var(UPDATE_ENV).as_deref() != Some(OsStr::new("1")) {
        return Ok(false);
    }
    for guard in ["LEFTHOOK", "CI"] {
        if var(guard).is_some() {
            return Err(format!(
                "{UPDATE_ENV}=1 is set while {guard} is set: refusing to bless snapshots from a \
                 hook or CI run; unset {UPDATE_ENV} (an exported value is the usual cause)"
            ));
        }
    }
    Ok(true)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Resolve the checkout this test binary AND the `shguard` lib it links were
/// built from.
///
/// The snapshots are read (and, when blessing, written) at run time, so a
/// binary reused from a shared `CARGO_TARGET_DIR` by a checkout that did not
/// rebuild would otherwise compare against the OTHER checkout's snapshots and
/// pass falsely. `cargo test` sets `CARGO_MANIFEST_DIR` at run time to the
/// checkout being tested; it must match the test crate's compiled-in one and
/// the lib's, because Cargo decides freshness per unit and can relink another
/// checkout's stale lib into a rebuilt test binary.
///
/// Fails closed on any difference. Paths are compared canonicalized, so a
/// symlinked checkout is the same checkout; on a case-insensitive filesystem
/// two spellings of one directory that canonicalize differently are rejected,
/// which is the safe side.
pub fn resolve(
    test_build: &Path,
    lib_build: &Path,
    runtime: Option<&OsStr>,
) -> Result<PathBuf, String> {
    let runtime = runtime.map(PathBuf::from).ok_or_else(|| {
        "CARGO_MANIFEST_DIR is not set at run time; run the golden tests via `cargo test` \
         (running the binary directly, e.g. from a debugger or IDE, or through \
         `cargo nextest --workspace-remap`, is not supported)"
            .to_string()
    })?;
    for (what, built_for) in [("test binary", test_build), ("shguard lib", lib_build)] {
        if !same_dir(built_for, &runtime) {
            return Err(format!(
                "this {what} was built for {} but is running for {}: it was reused from a \
                 shared CARGO_TARGET_DIR without a rebuild, so it would check the wrong \
                 checkout's snapshots; rebuild, or use a per-checkout CARGO_TARGET_DIR",
                built_for.display(),
                runtime.display()
            ));
        }
    }
    Ok(runtime)
}

/// The checkout under test (see [`resolve`]).
///
/// # Panics
///
/// When the test binary or the linked lib was built for another checkout.
#[allow(dead_code)] // not every test crate that includes this module reads snapshots
pub fn checkout_dir() -> PathBuf {
    resolve(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        Path::new(shguard::BUILD_MANIFEST_DIR),
        std::env::var_os("CARGO_MANIFEST_DIR").as_deref(),
    )
    .unwrap_or_else(|err| panic!("{err}"))
}

/// `tests/golden` of the checkout under test (see [`resolve`]).
pub fn golden_dir() -> PathBuf {
    checkout_dir().join("tests/golden")
}

fn declaration_name(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let line = line.strip_prefix("pub ").unwrap_or(line);
    let rest = line
        .strip_prefix("const ")
        .or_else(|| line.strip_prefix("static "))?;
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    Some(&rest[..end])
}

fn without_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Names of the `const`/`static` items in `source` whose type is a case
/// table (a tuple holding a `&str` command), and the `let` bindings that
/// build one inline. The type may wrap across lines.
fn case_tables(source: &str) -> (Vec<String>, Vec<String>) {
    let lines: Vec<&str> = source.lines().collect();
    let mut declared = Vec::new();
    let mut local = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = declaration_name(line) {
            let header: String = lines[index..]
                .iter()
                .map(|l| without_whitespace(l))
                .collect::<Vec<_>>()
                .join("");
            let header = header.split('=').next().unwrap_or_default();
            if header.contains("(&str,") {
                declared.push(name.to_string());
            }
        } else if let Some(binding) = line.trim_start().strip_prefix("let ") {
            let window: String = std::iter::once(binding)
                .chain(lines[index + 1..].iter().copied())
                .map(without_whitespace)
                .collect::<Vec<_>>()
                .join("")
                .chars()
                .take(80)
                .collect();
            if window.contains("[(\"") || window.contains("(&str,") {
                local.push(binding.trim_end().to_string());
            }
        }
    }
    (declared, local)
}

fn duplicates<'a>(names: &[&'a str]) -> Vec<&'a str> {
    let mut seen = std::collections::BTreeSet::new();
    names
        .iter()
        .copied()
        .filter(|name| !seen.insert(*name))
        .collect()
}

/// Compares the case tables declared in `source` with the set of names in
/// `registered` plus `exempt`.
///
/// # Errors
///
/// Lists every table that is declared but neither registered nor exempt,
/// every registered or exempt name that is not declared, every name listed
/// twice (or both registered and exempt), and every case table built inside a
/// function with `let` rather than declared as a module `const`.
#[allow(dead_code)] // only tests/guardfall.rs checks a table registry
pub fn check_table_registry(
    source: &str,
    registered: &[&str],
    exempt: &[&str],
) -> Result<(), String> {
    let (declared, local) = case_tables(source);
    let mut problems = Vec::new();
    for binding in local {
        problems.push(format!(
            "  case table built inline, not a module const: `let {binding}`"
        ));
    }
    for name in &declared {
        if !registered.contains(&name.as_str()) && !exempt.contains(&name.as_str()) {
            problems.push(format!(
                "  {name} is declared but neither registered nor exempt"
            ));
        }
    }
    for (what, names) in [("registered", registered), ("exempt", exempt)] {
        for name in names {
            if !declared.iter().any(|declared| declared == name) {
                problems.push(format!("  {what} name {name} is not a declared case table"));
            }
        }
        for name in duplicates(names) {
            problems.push(format!("  {name} is {what} more than once"));
        }
    }
    for name in registered {
        if exempt.contains(name) {
            problems.push(format!("  {name} is both registered and exempt"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "Allow",
        Decision::Ask => "Ask",
        Decision::Block => "Block",
    }
}

fn record(command: &str) -> Result<Record, String> {
    let verdict = shguard::analyze(command);
    if let Some(reason) = verdict.reason()
        && reason.as_str().ends_with(WATCHDOG_REASON_SUFFIX)
    {
        return Err(reason.as_str().to_string());
    }
    Ok(Record {
        command: command.to_string(),
        decision: decision_label(verdict.decision()).to_string(),
        deny_message: verdict.deny_message().map(|m| m.as_str().to_string()),
        matched_rule: verdict.matched_rule().map(|r| r.as_str().to_string()),
    })
}

fn render(records: &BTreeMap<String, Record>) -> String {
    records
        .values()
        .map(|r| serde_json::to_string(r).expect("a Record always serializes") + "\n")
        .collect()
}

fn parse(path: &Path, text: &str) -> BTreeMap<String, Record> {
    let mut records = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let record: Record = serde_json::from_str(line).unwrap_or_else(|err| {
            panic!(
                "{}:{}: malformed snapshot line: {err}",
                path.display(),
                index + 1
            )
        });
        assert!(
            records.insert(record.command.clone(), record).is_none(),
            "{}:{}: duplicate command",
            path.display(),
            index + 1
        );
    }
    records
}

fn describe_change(expected: &Record, actual: &Record) -> String {
    let mut parts = Vec::new();
    if expected.decision != actual.decision {
        parts.push(format!(
            "DECISION {} -> {}",
            expected.decision, actual.decision
        ));
    }
    if expected.matched_rule != actual.matched_rule {
        parts.push(format!(
            "matched_rule {:?} -> {:?}",
            expected.matched_rule, actual.matched_rule
        ));
    }
    if expected.deny_message != actual.deny_message {
        parts.push(format!(
            "deny_message {:?} -> {:?}",
            expected.deny_message, actual.deny_message
        ));
    }
    parts.join("; ")
}

fn diff_report(expected: &BTreeMap<String, Record>, actual: &BTreeMap<String, Record>) -> String {
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for (command, actual_record) in actual {
        match expected.get(command) {
            Some(expected_record) if expected_record != actual_record => changed.push(format!(
                "  changed {command:?}: {}",
                describe_change(expected_record, actual_record)
            )),
            Some(_) => {}
            None => added.push(format!(
                "  not in snapshot {command:?}: {}",
                actual_record.decision
            )),
        }
    }
    for (command, expected_record) in expected {
        if !actual.contains_key(command) {
            removed.push(format!(
                "  no longer in corpus {command:?}: {}",
                expected_record.decision
            ));
        }
    }
    let mut report = format!(
        "{} changed, {} not in snapshot, {} no longer in corpus\n",
        changed.len(),
        added.len(),
        removed.len()
    );
    for bucket in [&changed, &added, &removed] {
        for line in bucket.iter().take(MAX_REPORTED_PER_BUCKET) {
            let _ = writeln!(report, "{line}");
        }
        if bucket.len() > MAX_REPORTED_PER_BUCKET {
            let _ = writeln!(
                report,
                "  ... {} more",
                bucket.len() - MAX_REPORTED_PER_BUCKET
            );
        }
    }
    report
}

/// Records every command in `commands` and compares the result against
/// `tests/golden/<corpus>.jsonl`, or rewrites that file when
/// `SHGUARD_GOLDEN_UPDATE=1`.
///
/// # Panics
///
/// On any mismatch, a missing or malformed snapshot, or a command whose
/// verdict came from the evaluation watchdog rather than the pipeline.
pub fn check<S: AsRef<str>>(corpus: &str, commands: impl IntoIterator<Item = S>) {
    // Resolved before the corpus is evaluated so a stale binary fails fast.
    let path = golden_dir().join(format!("{corpus}.jsonl"));
    let mut actual = BTreeMap::new();
    let mut watchdog_trips = Vec::new();
    for command in commands {
        let command = command.as_ref();
        if actual.contains_key(command) {
            continue;
        }
        match record(command) {
            Ok(record) => {
                actual.insert(command.to_string(), record);
            }
            Err(reason) => watchdog_trips.push(format!("  {command:?}: {reason}")),
        }
    }
    assert!(
        watchdog_trips.is_empty(),
        "golden corpus {corpus}: the evaluation watchdog fired, so these verdicts say nothing \
         about the decision pipeline (re-run on a less loaded machine):\n{}",
        watchdog_trips.join("\n")
    );

    let rendered = render(&actual);

    if update_requested(|name| std::env::var_os(name)).unwrap_or_else(|err| panic!("{err}")) {
        let previous = std::fs::read_to_string(&path)
            .ok()
            .map(|text| parse(&path, &text));
        std::fs::create_dir_all(path.parent().expect("the snapshot path has a parent"))
            .expect("tests/golden should be creatable");
        std::fs::write(&path, rendered)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
        eprintln!(
            "golden corpus {corpus}: wrote {} records to {}",
            actual.len(),
            path.display()
        );
        match previous {
            Some(previous) => eprint!("{}", diff_report(&previous, &actual)),
            None => eprintln!("  there was no previous snapshot"),
        }
        return;
    }

    let snapshot = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "golden corpus {corpus}: cannot read {} ({err}); record it with \
             {UPDATE_ENV}=1 cargo test golden_snapshot",
            path.display()
        )
    });
    if snapshot == rendered {
        return;
    }
    let expected = parse(&path, &snapshot);
    assert!(
        expected != actual,
        "golden corpus {corpus}: {} holds the right records but not in canonical form \
         (sorted by command, one JSON object per line); re-bless with {UPDATE_ENV}=1",
        path.display()
    );
    panic!(
        "golden corpus {corpus}: current behaviour differs from {}\n{}\
         If the change is intended, re-bless with {UPDATE_ENV}=1 cargo test golden_snapshot \
         and justify every DECISION change in the PR.",
        path.display(),
        diff_report(&expected, &actual)
    );
}
