//! The fail-open baseline of the evaluation-core redesign (docs/rfc-redesign.md
//! "Risks", stage R0, issue #836).
//!
//! `tests/golden/must_not_allow.jsonl` lists commands that must never be
//! Allow under the embedded rules with no user config (the `analyze` entry
//! point, equivalent to `SHGUARD_CONFIG=/dev/null`): every payload that is
//! Allow under the embedded rules with no config and is named in the RFC
//! "Problem" section or in the issues the RFC maps to R1 and R2. The golden
//! snapshots encode today's fail-open Allows, so "no new Allow" alone would
//! keep them; this file is the baseline that says which Allows are bugs.
//!
//! Each row is `{"command", "status", "source", "note"?}`:
//!
//! - `closed`: the command is not Allow today. The test fails if it is.
//! - `open`: the command is still Allow on main (a known fail-open). The test
//!   fails when an open row stops being Allow, with the instruction to flip it
//!   to `closed`, so the baseline only ratchets one way.
//!
//! The number of open rows is pinned in [`EXPECTED_OPEN`] and printed on every
//! run. It must reach 0 on the new core (R2). Fixing a bug means flipping its
//! rows to `closed` and lowering the constant in the same change; adding a
//! newly found fail-open means adding an `open` row and raising it.
//!
//! No approval file can override a row: nothing in this target reads
//! `strangler_tightenings.jsonl`, `relaxations.jsonl` or any other approval
//! list, so a differential approval cannot hide a fail-open here.
//!
//! The strict-parse checks of the reader run first, in `main`.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use serde::Deserialize;
use shguard::verdict::Decision;

#[path = "common/golden.rs"]
#[allow(dead_code)]
mod golden;

/// Rows that are still Allow on main. Lower it when rows flip to `closed`.
const EXPECTED_OPEN: usize = 115;

/// Rows that are not Allow today. Raise it when a row is added as `closed` or
/// flipped from `open`.
const EXPECTED_CLOSED: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Open,
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    command: String,
    status: Status,
    /// The issue number (`#836`) or RFC section the payload comes from.
    source: String,
    #[allow(dead_code)]
    note: Option<String>,
}

fn parse_rows(origin: &str, text: &str) -> Result<Vec<Row>, String> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = format!("{origin}:{}", index + 1);
        let row: Row =
            serde_json::from_str(line).map_err(|err| format!("{at}: malformed row: {err}"))?;
        if row.source.trim().is_empty() {
            return Err(format!("{at}: empty `source`"));
        }
        if row.command.trim().is_empty() {
            return Err(format!("{at}: empty `command`"));
        }
        if !seen.insert(row.command.clone()) {
            return Err(format!("{at}: duplicate command {:?}", row.command));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("{origin}: no rows"));
    }
    Ok(rows)
}

/// The reader must reject what a hand edit is likely to get wrong.
fn check_reader() -> Result<(), String> {
    let ok = r#"{"command":"ls","status":"closed","source":"x"}"#;
    parse_rows("ok", ok)?;
    let cases = [
        ("empty file", ""),
        ("blank file", "\n  \n"),
        (
            "unknown status",
            r#"{"command":"ls","status":"fixed","source":"x"}"#,
        ),
        ("missing status", r#"{"command":"ls","source":"x"}"#),
        (
            "unknown key",
            r#"{"command":"ls","status":"open","source":"x","extra":1}"#,
        ),
        ("missing source", r#"{"command":"ls","status":"open"}"#),
        (
            "empty source",
            r#"{"command":"ls","status":"open","source":" "}"#,
        ),
        ("not json", "ls"),
    ];
    for (what, text) in cases {
        if parse_rows(what, text).is_ok() {
            return Err(format!("reader accepted: {what}"));
        }
    }
    let duplicate = format!("{ok}\n{ok}\n");
    if parse_rows("duplicate", &duplicate).is_ok() {
        return Err("reader accepted: duplicate commands".to_string());
    }
    Ok(())
}

fn evaluate(rows: &[Row]) -> Result<(usize, usize), Vec<String>> {
    let mut problems = Vec::new();
    let (mut open, mut closed) = (0, 0);
    for row in rows {
        let verdict = shguard::analyze(&row.command);
        if verdict
            .reason()
            .is_some_and(|reason| reason.as_str().ends_with(golden::WATCHDOG_REASON_SUFFIX))
        {
            problems.push(format!(
                "harness failure: the evaluation watchdog tripped, so this row's decision is \
                 not its real one ({:?})",
                row.command
            ));
            continue;
        }
        let decision = verdict.decision();
        match (row.status, decision) {
            (Status::Open, Decision::Allow) => open += 1,
            (Status::Open, other) => problems.push(format!(
                "{} is now {other:?}: flip it to \"closed\" in tests/golden/must_not_allow.jsonl \
                 and lower EXPECTED_OPEN in tests/must_not_allow.rs ({:?})",
                row.source, row.command
            )),
            (Status::Closed, Decision::Allow) => problems.push(format!(
                "{} is Allow but marked closed: a fixed fail-open regressed ({:?})",
                row.source, row.command
            )),
            (Status::Closed, _) => closed += 1,
        }
    }
    if problems.is_empty() {
        Ok((open, closed))
    } else {
        Err(problems)
    }
}

fn run(path: &Path) -> Result<(), Vec<String>> {
    check_reader().map_err(|err| vec![err])?;
    let text = std::fs::read_to_string(path)
        .map_err(|err| vec![format!("failed to read {}: {err}", path.display())])?;
    let rows = parse_rows(&path.display().to_string(), &text).map_err(|err| vec![err])?;
    let (open, closed) = evaluate(&rows)?;
    println!("must_not_allow: {open} open / {closed} closed rows");
    let mut problems = Vec::new();
    if open != EXPECTED_OPEN {
        problems.push(format!(
            "{open} open rows but EXPECTED_OPEN is {EXPECTED_OPEN}: set EXPECTED_OPEN to {open} \
             in tests/must_not_allow.rs (a row was added or flipped)"
        ));
    }
    if closed != EXPECTED_CLOSED {
        problems.push(format!(
            "{closed} closed rows but EXPECTED_CLOSED is {EXPECTED_CLOSED}: set EXPECTED_CLOSED \
             to {closed} in tests/must_not_allow.rs (a row was added or flipped)"
        ));
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(())
}

fn main() -> ExitCode {
    let path = golden::golden_dir().join("must_not_allow.jsonl");
    match run(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problems) => {
            for problem in problems {
                eprintln!("must_not_allow: {problem}");
            }
            ExitCode::FAILURE
        }
    }
}
