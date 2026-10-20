//! Row classification for `tests/golden/legacy_units.jsonl`, shared by the
//! public-API replay (`tests/legacy_units.rs`) and the differential
//! (`tests/differential.rs`), so both pick the same gate rows and reject the
//! same unknown kinds.

#![allow(dead_code)]

use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A header row carrying a shared TOML text; not a test input.
    Config,
    Gate,
    Rules,
    Excluded,
}

/// # Errors
///
/// When the row has no string `kind`, or one that is not a known kind.
pub fn kind(row: &Map<String, Value>) -> Result<Kind, String> {
    match row.get("kind").and_then(Value::as_str) {
        Some("config") => Ok(Kind::Config),
        Some("gate") => Ok(Kind::Gate),
        Some("rules") => Ok(Kind::Rules),
        Some("excluded") => Ok(Kind::Excluded),
        Some(other) => Err(format!("unknown kind {other:?}")),
        None => Err("missing string `kind`".to_string()),
    }
}

/// A gate row the public `shguard::analyze` can replay: recorded on the
/// embedded rule set (no `config`) and with no `cwd`. Any other gate row is
/// only meaningful under the rule set or directory it was recorded in.
pub fn is_public_gate(row: &Map<String, Value>) -> bool {
    !row.contains_key("config") && !row.contains_key("cwd")
}

/// # Errors
///
/// When the gate row has no string `command`.
pub fn gate_command(row: &Map<String, Value>) -> Result<&str, String> {
    row.get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| "gate row without a string `command`".to_string())
}
