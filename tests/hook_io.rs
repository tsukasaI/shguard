//! Hook stdin→stdout integration tests (issue #13's Definition of Done):
//! drives the real `shguard` binary through [`assert_cmd`] so the test
//! exercises the actual composition root (`src/bin/shguard.rs`), not just
//! the adapter module in isolation.

#![allow(clippy::expect_used)]

use assert_cmd::Command;
use serde_json::Value;

fn run_hook(stdin: &str) -> Value {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .write_stdin(stdin)
        .assert()
        .success();
    let output = assert.get_output();
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
}

fn permission_decision(output: &Value) -> &str {
    output["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .expect("permissionDecision should be a string")
}

fn permission_reason(output: &Value) -> &str {
    output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("permissionDecisionReason should be a string")
}

/// DoD 1: a Block-triggering Bash command denies with a non-empty reason.
#[test]
fn block_triggering_command_denies_with_reason() {
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"hook_event_name":"PreToolUse"}"#;
    let output = run_hook(stdin);
    assert_eq!(permission_decision(&output), "deny");
    assert!(!permission_reason(&output).is_empty());
}

/// DoD 2: an unresolvable-but-legitimate construct asks.
#[test]
fn ask_case_asks() {
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"hook_event_name":"PreToolUse"}"#;
    let output = run_hook(stdin);
    assert_eq!(permission_decision(&output), "ask");
}

/// DoD 3: a benign Bash command allows.
#[test]
fn allow_case_allows() {
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"hook_event_name":"PreToolUse"}"#;
    let output = run_hook(stdin);
    assert_eq!(permission_decision(&output), "allow");
}

/// DoD 4: malformed stdin fails closed to `ask` without crashing the
/// process — the binary still exits 0 and emits well-formed JSON.
#[test]
fn malformed_stdin_fails_closed_without_crashing() {
    let output = run_hook("this is not json");
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

/// A non-Bash tool call is out of scope for shguard and is allowed through
/// unguarded rather than asking on every non-shell tool call.
#[test]
fn non_bash_tool_allows() {
    let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"},"hook_event_name":"PreToolUse"}"#;
    let output = run_hook(stdin);
    assert_eq!(permission_decision(&output), "allow");
}

/// `--version` prints the crate version and does not touch stdin.
#[test]
fn version_flag_prints_version() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("--version")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}
