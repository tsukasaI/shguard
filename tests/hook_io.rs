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

/// Issue #51: an expansion-position substitution (assignment RHS here) that
/// was previously never scanned at all denies with a non-empty reason —
/// exercised end-to-end through the real binary, not just `gate.rs`'s unit
/// tests, the same reasoning `block_triggering_command_denies_with_reason`
/// above already applies to argv-position rules. Safe to run non-isolated
/// (no `SHGUARD_CONFIG`/env stubbing): the embedded blocklist alone already
/// blocks `rm -rf /`, and `crate::rules::apply_allowlist` is structurally
/// Block-immune, so no host-local user config could downgrade this.
#[test]
fn assignment_rhs_substitution_denies() {
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"X=$(rm -rf /)"},"hook_event_name":"PreToolUse"}"#;
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

// issue #208 follow-up: an unrecognized or malformed flag must be reported
// as an error (exit 2), not silently fall through to hook mode — the
// PreToolUse hook contract never passes shguard any arguments, so
// rejecting a flag-shaped argument here can never reject real hook
// traffic, only a human's typo.

#[test]
fn unrecognized_flag_exits_with_error_instead_of_falling_through_to_hook_mode() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("--check-confg")
        .assert()
        .failure()
        .code(2);
}

// A bare positional argument (no leading `-` at all) must be rejected the
// same way — the catch-all guard is `first_arg.is_some()`, not
// `starts_with('-')`, specifically so a typo like `check-config` (missing
// dashes) doesn't silently fall through to hook mode either.
#[test]
fn non_flag_positional_argument_exits_with_error_instead_of_falling_through_to_hook_mode() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("check-config")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn version_flag_with_trailing_argument_exits_with_error() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["--version", "extra"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn check_config_flag_with_trailing_argument_exits_with_error() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["--check-config", "extra"])
        .assert()
        .failure()
        .code(2);
}

// Issue #109: `shguard check <command>` dry-run mode. Each case below
// mirrors an existing hook-path test above for the same command
// (`block_triggering_command_denies_with_reason`, `ask_case_asks`,
// `allow_case_allows`) so the two entry points are asserted to agree,
// demonstrating `check` reuses `analyze_with_policy` rather than a
// reimplemented decision path.

#[test]
fn check_block_command_exits_nonzero_and_prints_decision() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "rm -rf /"])
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Block"));
}

#[test]
fn check_allow_command_exits_zero() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "echo hello"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Allow"));
}

#[test]
fn check_ask_command_exits_zero() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "$(which python3)"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Ask"));
}

#[test]
fn check_json_flag_emits_expected_schema() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "rm -rf /", "--json"])
        .assert()
        .failure()
        .code(1);
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["command"], "rm -rf /");
    assert_eq!(value["decision"], "Block");
    assert!(value["reason"].is_string());
    assert!(value.get("matched_rule_id").is_some());
    assert!(value.get("deny_message").is_some());
}

#[test]
fn check_json_flag_before_command_is_also_accepted() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "--json", "echo hello"])
        .assert()
        .success();
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["decision"], "Allow");
}

#[test]
fn check_missing_command_exits_with_usage_error() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn check_too_many_positional_arguments_exits_with_usage_error() {
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .args(["check", "echo hello", "echo world"])
        .assert()
        .failure()
        .code(2);
}
