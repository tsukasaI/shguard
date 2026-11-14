//! Helpers shared by the integration tests. Each `tests/*.rs` is its own
//! crate, so every file includes this module with `mod common;` and uses only
//! part of it.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::decision::Decision;

pub fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

pub fn decide(l: &Loaded, cmd: &str) -> Decision {
    let Ok(script) = shguard_syntax::parse(cmd.as_bytes()) else {
        panic!("`{cmd}` is outside the subset");
    };
    shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
}

pub fn assert_all(cmds: &[&str], want: Decision) {
    let l = embedded();
    for cmd in cmds {
        assert_eq!(decide(&l, cmd), want, "`{cmd}`");
    }
}

pub fn assert_allow(cmds: &[&str]) {
    assert_all(cmds, Decision::Allow);
}

pub fn assert_not_allow(cmds: &[&str]) {
    let l = embedded();
    for cmd in cmds {
        assert_ne!(decide(&l, cmd), Decision::Allow, "`{cmd}`");
    }
}

/// Why a coverage check cannot give an answer.
#[derive(Debug, PartialEq, Eq)]
pub enum CoverageError {
    BadToml(String),
    NoRows,
    UnknownExempt(String),
    StaleExempt(String),
}

fn row_keys(toml_text: &str) -> Result<Vec<Vec<String>>, CoverageError> {
    let doc: toml::Table = match toml_text.parse() {
        Ok(t) => t,
        Err(e) => return Err(CoverageError::BadToml(e.to_string())),
    };
    let Some(rows) = doc.get("row").and_then(toml::Value::as_array) else {
        return Err(CoverageError::NoRows);
    };
    let mut keys = Vec::new();
    for row in rows {
        let Some(key) = row.get("key").and_then(toml::Value::as_array) else {
            return Err(CoverageError::BadToml("a [[row]] without a key".to_owned()));
        };
        let mut words = Vec::new();
        for word in key {
            let Some(w) = word.as_str() else {
                return Err(CoverageError::BadToml("a non-string key word".to_owned()));
            };
            words.push(w.to_owned());
        }
        keys.push(words);
    }
    if keys.is_empty() {
        return Err(CoverageError::NoRows);
    }
    Ok(keys)
}

/// The `[[row]]` keys of `toml_text`, space-joined, that no command in `cmds`
/// is headed by. A command counts for the longest row key that equals its
/// leading words. Rows named in `exempt` are left out of the result.
///
/// # Errors
///
/// When the text is not valid TOML or a `[[row]]` has no string-list `key`,
/// the text has no rows, an exempt key is not a row key, or an exempt key is
/// covered by a command.
pub fn uncovered_row_keys(
    toml_text: &str,
    cmds: &[&str],
    exempt: &[&[&str]],
) -> Result<Vec<String>, CoverageError> {
    let keys = row_keys(toml_text)?;
    let mut covered = vec![false; keys.len()];
    for cmd in cmds {
        // A command with a control, redirect or substitution byte may run something else
        // after its head, so it proves nothing about the head's row.
        if cmd.bytes().any(|b| b"|&;<>()\n`".contains(&b)) {
            continue;
        }
        let words: Vec<&str> = cmd.split_whitespace().collect();
        let mut best: Option<(usize, usize)> = None;
        for (i, key) in keys.iter().enumerate() {
            let heads =
                key.len() <= words.len() && key.iter().zip(&words).all(|(k, w)| k.as_str() == *w);
            if heads && best.is_none_or(|(_, len)| key.len() > len) {
                best = Some((i, key.len()));
            }
        }
        if let Some((i, _)) = best
            && let Some(slot) = covered.get_mut(i)
        {
            *slot = true;
        }
    }
    let mut exempt_rows = vec![false; keys.len()];
    for ex in exempt {
        let Some(i) = keys
            .iter()
            .position(|k| k.iter().map(String::as_str).eq(ex.iter().copied()))
        else {
            return Err(CoverageError::UnknownExempt(ex.join(" ")));
        };
        if covered.get(i).copied().unwrap_or(false) {
            return Err(CoverageError::StaleExempt(ex.join(" ")));
        }
        if let Some(slot) = exempt_rows.get_mut(i) {
            *slot = true;
        }
    }
    let mut missing = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let done = covered.get(i).copied().unwrap_or(false)
            || exempt_rows.get(i).copied().unwrap_or(false);
        if !done {
            missing.push(key.join(" "));
        }
    }
    Ok(missing)
}

/// Fails unless every `[[row]]` of the embedded catalog file `source`
/// (e.g. `embedded:core.toml`) has a command in `cmds`, except the `exempt`
/// keys, which no command may head.
pub fn assert_rows_covered(source: &str, cmds: &[&str], exempt: &[&[&str]]) {
    let Some(found) = EMBEDDED.iter().find(|s| s.name == source) else {
        panic!("no embedded catalog file is named `{source}`");
    };
    match uncovered_row_keys(found.text, cmds, exempt) {
        Ok(missing) => assert!(
            missing.is_empty(),
            "rows of `{source}` with no command in this test: {missing:?}"
        ),
        Err(e) => panic!("coverage check of `{source}` failed: {e:?}"),
    }
}

/// The hook input for a Bash call.
pub fn bash(command: &str) -> Vec<u8> {
    serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": command } })
        .to_string()
        .into_bytes()
}

/// Does not isolate the child from the developer's environment: the caller
/// must set or remove both `HOME` and `SHGUARD_CONFIG`.
pub fn spawn(mut cmd: Command, stdin: &[u8]) -> Output {
    let Ok(mut child) = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        panic!("cannot run shguard");
    };
    if let Some(mut pipe) = child.stdin.take() {
        // The hook stops reading at its cap, so a large write may hit a
        // closed pipe; that is not a failure.
        drop(pipe.write_all(stdin));
    }
    match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => panic!("cannot wait for shguard: {e}"),
    }
}

/// The JSON the hook wrote, after checking the status is 0.
pub fn answer(out: &Output) -> Value {
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(
        v.get("hookSpecificOutput")
            .and_then(|o| o.get("hookEventName"))
            .and_then(Value::as_str),
        Some("PreToolUse")
    );
    v
}

pub fn decision(out: &Output) -> Option<String> {
    answer(out)
        .get("hookSpecificOutput")
        .and_then(|o| o.get("permissionDecision"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
