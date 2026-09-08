//! Hook stdin→stdout integration tests (issue #13's Definition of Done):
//! drives the real `shguard` binary through [`assert_cmd`] so the test
//! exercises the actual composition root (`src/bin/shguard.rs`), not just
//! the adapter module in isolation.

#![allow(clippy::expect_used)]

use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn run_hook(stdin: &str) -> Value {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB")
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
/// above already applies to argv-position rules.
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

/// A non-Bash tool call is out of scope for shguard and genuinely defers to
/// Claude Code's normal permission flow (issue #462) — no `permissionDecision`
/// field at all, rather than an explicit `allow` that would auto-approve it.
#[test]
fn non_bash_tool_defers() {
    let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"},"hook_event_name":"PreToolUse"}"#;
    let output = run_hook(stdin);
    assert!(output["hookSpecificOutput"]["permissionDecision"].is_null());
    assert_eq!(
        output["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .expect("hookEventName should be a string"),
        "PreToolUse"
    );
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

// Issue #109: `shguard check <command>` dry-run mode. The embedded-rule
// cases below mirror an existing hook-path test above for the same command
// (`block_triggering_command_denies_with_reason`, `ask_case_asks`,
// `allow_case_allows`) — that mirroring demonstrates `check` and the real
// hook path AGREE on these particular embedded-rule-only commands, but
// does NOT by itself prove `check` reuses `analyze_with_policy` (any of
// these commands would decide the same way even through the config-blind
// `shguard::analyze`, since none of them depend on a user config). The
// dedicated `check_respects_user_config_*` tests below close that gap by
// using a command a user config denies that the embedded blocklist alone
// would allow — that's what actually pins config-loading, not the mirrors.
//
// Every test that reaches config loading or hook evaluation (i.e.
// everything except the pure usage-error/`--version` cases above, which
// `main`'s argument dispatch rejects before any config or env read)
// isolates the environment the same way `tests/user_config.rs` does, via
// `run_hook`/`isolated_check`, so a host machine's own `SHGUARD_CONFIG`/
// config file can't make these spuriously fail or pass.

fn isolated_check(args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB")
        .args(args);
    cmd
}

fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("tempdir should create");
    let path = dir.path().join("config.toml");
    fs::write(&path, contents).expect("config file should write");
    (dir, path)
}

#[test]
fn check_block_command_exits_nonzero_and_prints_decision() {
    let assert = isolated_check(&["check", "rm -rf /"])
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Block"));
}

#[test]
fn check_allow_command_exits_zero() {
    let assert = isolated_check(&["check", "echo hello"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Allow"));
}

#[test]
fn check_ask_command_exits_zero() {
    let assert = isolated_check(&["check", "$(which python3)"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("Decision: Ask"));
}

#[test]
fn check_json_flag_emits_expected_schema() {
    let assert = isolated_check(&["check", "rm -rf /", "--json"])
        .assert()
        .failure()
        .code(1);
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["command"], "rm -rf /");
    assert_eq!(value["decision"], "Block");
    assert!(value["reason"].is_string());
    // `.get(..).is_some()` alone would also pass for a present `null` —
    // confirm `matched_rule_id` is actually a non-null string on a Block
    // that matched an embedded rule, not just present-as-something.
    assert!(value.get("matched_rule_id").is_some_and(Value::is_string));
    assert!(value.get("deny_message").is_some());
}

#[test]
fn check_json_flag_before_command_is_also_accepted() {
    let assert = isolated_check(&["check", "--json", "echo hello"])
        .assert()
        .success();
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["decision"], "Allow");
    // The documented schema keeps `reason`/`matched_rule_id`/`deny_message`
    // present as `null` on Allow, never omitted — indexing a MISSING key
    // also yields `Value::Null`, so `contains_key` first is what actually
    // distinguishes "present and null" from "absent" here.
    let object = value
        .as_object()
        .expect("check --json should emit an object");
    for key in ["reason", "matched_rule_id", "deny_message"] {
        assert!(object.contains_key(key), "missing key {key:?}: {value}");
        assert!(value[key].is_null(), "expected {key:?} to be null: {value}");
    }
}

#[test]
fn check_missing_command_exits_with_usage_error() {
    isolated_check(&["check"]).assert().failure().code(2);
}

#[test]
fn check_too_many_positional_arguments_exits_with_usage_error() {
    isolated_check(&["check", "echo hello", "echo world"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn check_respects_user_config_deny_rule_not_visible_to_embedded_rules_alone() {
    // The actual regression guard for "check reuses analyze_with_policy,
    // not a config-blind analyze()": `scary-tool` matches no embedded
    // rule, so this can ONLY deny if `check` genuinely loaded and applied
    // the user config — a config-blind decision path would Allow here.
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    );
    let assert = isolated_check(&["check", "scary-tool --run", "--json"])
        .env("SHGUARD_CONFIG", &config_path)
        .assert()
        .failure()
        .code(1);
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["decision"], "Block");
    assert_eq!(value["matched_rule_id"], "user-deny-scary-tool");
}

#[test]
fn check_nonexistent_config_path_exits_with_usage_error() {
    isolated_check(&["check", "echo hello"])
        .env(
            "SHGUARD_CONFIG",
            "/nonexistent/shguard-config-for-test.toml",
        )
        .assert()
        .failure()
        .code(2);
}

// Issue #468: `permission_mode` (and, inside a subagent, `agent_id`/
// `agent_type`) is read from PreToolUse stdin and recorded on the decision
// log. With no `ask_outcome` configured (this file's `run_hook` never sets
// `SHGUARD_CONFIG`, so the embedded-only default `ask_outcome =
// AskOutcome::Global(Decision::Ask)` applies), it never changes the
// Allow/Ask/Block decision either — issue #469's `[ask_outcome]` table is
// the one config shape that does key a decision off `permission_mode`/
// `agent_id` (see `tests/ask_outcome_per_mode.rs`), out of scope here. Each
// variant below is asserted against the SAME fixed command to prove that.

/// The command whose decision must stay identical across every
/// `permission_mode` variant below: a real embedded-blocklist Block, the
/// same one `block_triggering_command_denies_with_reason` already covers.
const FIXED_BLOCK_COMMAND: &str = "rm -rf /";

fn stdin_with_permission_mode(command: &str, permission_mode: Option<&str>) -> String {
    let mut input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    if let Some(mode) = permission_mode {
        input["permission_mode"] = serde_json::Value::String(mode.to_string());
    }
    input.to_string()
}

#[test]
fn permission_mode_never_changes_the_decision() {
    for (command, expected) in [(FIXED_BLOCK_COMMAND, "deny"), ("echo hello", "allow")] {
        let baseline =
            permission_decision(&run_hook(&stdin_with_permission_mode(command, None))).to_string();
        assert_eq!(baseline, expected);
        for mode in [
            "default",
            "plan",
            "acceptEdits",
            "auto",
            "dontAsk",
            "bypassPermissions",
            "some-future-mode",
        ] {
            let output = run_hook(&stdin_with_permission_mode(command, Some(mode)));
            assert_eq!(
                permission_decision(&output),
                baseline,
                "permission_mode {mode:?} changed the decision for {command:?}"
            );
        }
    }
}

/// A `permission_mode`/`agent_id`/`agent_type` of the wrong JSON type (not a
/// string) must be treated the same as absent, not fail the whole stdin
/// parse closed — these are `serde_json::Value` fields precisely so a
/// present-but-wrong-typed value can't turn into an adapter-level parse
/// failure (`src/adapter.rs`'s `HookInput` doc).
#[test]
fn non_string_permission_mode_and_agent_fields_do_not_change_the_decision() {
    let baseline =
        permission_decision(&run_hook(&stdin_with_permission_mode("echo hello", None))).to_string();
    for stdin in [
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"permission_mode":123}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"agent_id":{"x":1}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"agent_type":["a"]}"#,
    ] {
        let output = run_hook(stdin);
        assert_eq!(
            permission_decision(&output),
            baseline.as_str(),
            "non-string field changed the decision for {stdin:?}"
        );
    }

    // A non-Bash `tool_name` still genuinely defers (no `permissionDecision`
    // field at all — issue #462) regardless of a wrong-typed `permission_mode`.
    let output = run_hook(r#"{"tool_name":"Read","tool_input":{},"permission_mode":123}"#);
    assert!(output["hookSpecificOutput"]["permissionDecision"].is_null());
}

#[test]
fn check_nonexistent_config_path_with_json_flag_emits_json_error() {
    let assert = isolated_check(&["check", "echo hello", "--json"])
        .env(
            "SHGUARD_CONFIG",
            "/nonexistent/shguard-config-for-test.toml",
        )
        .assert()
        .failure()
        .code(2);
    let stdout = assert.get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert!(value["error"].is_string());
}
