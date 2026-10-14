//! Shared comparator for the golden-snapshot gate (RFC #658 stage 1,
//! issue #659). See `tests/golden_snapshot.rs` for what the snapshot is
//! for and how to bless it.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
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

/// Resolve the checkout this test binary was built from.
///
/// The snapshots are read (and, when blessing, written) at run time, so a
/// binary reused from a shared `CARGO_TARGET_DIR` by a checkout that did not
/// rebuild would otherwise compare against the OTHER checkout's snapshots and
/// pass falsely. `cargo test` sets `CARGO_MANIFEST_DIR` at run time to the
/// checkout being tested; it must match the one compiled in.
pub fn resolve(compile: &Path, runtime: Option<&OsStr>) -> Result<PathBuf, String> {
    let runtime = runtime.map(PathBuf::from).ok_or_else(|| {
        "CARGO_MANIFEST_DIR is not set at run time; run the golden tests via `cargo test`"
            .to_string()
    })?;
    let same = match (compile.canonicalize(), runtime.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => compile == runtime,
    };
    if same {
        Ok(runtime)
    } else {
        Err(format!(
            "this test binary was built for {} but is running for {}: it was reused from a \
             shared CARGO_TARGET_DIR without a rebuild, so it would check the wrong \
             checkout's snapshots; rebuild, or use a per-checkout CARGO_TARGET_DIR",
            compile.display(),
            runtime.display()
        ))
    }
}

/// `tests/golden` of the checkout under test (see [`resolve`]).
pub fn golden_dir() -> PathBuf {
    let manifest_dir = resolve(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        std::env::var_os("CARGO_MANIFEST_DIR").as_deref(),
    )
    .unwrap_or_else(|err| panic!("{err}"));
    manifest_dir.join("tests/golden")
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

    let path = golden_dir().join(format!("{corpus}.jsonl"));
    let rendered = render(&actual);

    if std::env::var(UPDATE_ENV).as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("the snapshot path has a parent"))
            .expect("tests/golden should be creatable");
        std::fs::write(&path, rendered)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
        eprintln!(
            "golden corpus {corpus}: wrote {} records to {}",
            actual.len(),
            path.display()
        );
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
