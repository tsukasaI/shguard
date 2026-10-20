//! Strict readers for the `tests/golden/*.jsonl` corpora, shared by the
//! R0 metrics (`tests/metrics.rs`), the fail-open baseline
//! (`tests/must_not_allow.rs`) and the differential skeleton
//! (`tests/differential.rs`), issue #836.
//!
//! Every reader fails closed: a missing file, an empty file, a malformed
//! line, an unknown key or a duplicate command is an error, never a silently
//! shorter corpus.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

/// Reads the `command` of every line of a JSONL corpus whose rows are JSON
/// objects with a string `command` key (extra keys are allowed: the golden
/// snapshots carry a recorded decision next to it).
///
/// # Errors
///
/// When the file cannot be read, is empty, has a malformed line, a line
/// without a string `command`, or repeats a command.
pub fn read_commands(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut commands = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = format!("{}:{}", path.display(), index + 1);
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("{at}: malformed line: {err}"))?;
        let command = value
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{at}: missing string `command`"))?
            .to_string();
        if !seen.insert(command.clone()) {
            return Err(format!("{at}: duplicate command {command:?}"));
        }
        commands.push(command);
    }
    if commands.is_empty() {
        return Err(format!("{}: corpus is empty", path.display()));
    }
    Ok(commands)
}
