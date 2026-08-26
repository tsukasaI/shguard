//! Structured decision-output logging integration tests (issue #108):
//! drives the real `shguard` binary through both entry points —
//! `shguard check` and the PreToolUse hook's stdin contract — the same way
//! `tests/hook_io.rs` does, so these tests exercise the actual composition
//! root rather than `src/decision_log.rs` in isolation (that module's own
//! unit tests already cover the JSONL shape and fail-open write behavior).
//!
//! Isolates the environment the same way `tests/user_config.rs` and
//! `tests/hook_io.rs`'s `check_respects_user_config_*` tests do, so a host
//! machine's own `SHGUARD_CONFIG`/config file can't make these spuriously
//! fail or pass.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn write_config(contents: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir should create");
    let path = dir.path().join("config.toml");
    fs::write(&path, contents).expect("config file should write");
    (dir, path)
}

fn isolated_command(config_path: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", config_path);
    cmd
}

fn read_jsonl_lines(path: &std::path::Path) -> Vec<Value> {
    let contents = fs::read_to_string(path).expect("log file should be readable");
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line should be valid JSON"))
        .collect()
}

#[test]
fn decision_logging_is_off_by_default_when_config_omits_the_key() {
    let log_path_holder = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_path_holder.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config("");

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .success();

    assert!(
        !log_path.exists(),
        "no decision log file should be created without decision_log_path configured"
    );
}

#[test]
fn empty_decision_log_path_fails_config_load_closed() {
    let (_config_dir, config_path) = write_config(
        r#"
        decision_log_path = ""
        "#,
    );

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn check_subcommand_appends_a_decision_log_line_matching_the_verdict() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "rm -rf /"])
        .assert()
        .failure()
        .code(1);

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["command"], "rm -rf /");
    assert_eq!(lines[0]["decision"], "Block");
    assert_eq!(
        lines[0]["matched_rule_id"],
        "rm-recursive-force-dangerous-target"
    );
    assert!(lines[0]["normalized_argv"].is_array());
    assert!(
        !lines[0]["normalized_argv"]
            .as_array()
            .expect("normalized_argv should be an array")
            .is_empty()
    );
}

/// The core parity property this feature exists to have (mirroring #109's
/// own "check must never diverge from the real hook" concern): a hook-path
/// invocation and a `check` CLI invocation of the SAME command, under the
/// SAME config, produce equivalent decision/matched_rule_id/normalized_argv
/// log content — because both go through the one shared
/// `analyze_with_policy` call site that does the logging (`src/lib.rs`).
#[test]
fn hook_path_and_check_cli_produce_equivalent_log_content_for_the_same_command() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "rm -rf /"])
        .assert()
        .failure()
        .code(1);

    let hook_stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"hook_event_name":"PreToolUse"}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(
        lines.len(),
        2,
        "both invocations should each append one line"
    );
    for field in ["command", "decision", "matched_rule_id", "normalized_argv"] {
        assert_eq!(
            lines[0][field], lines[1][field],
            "field {field:?} diverged between check and the hook path: {lines:?}"
        );
    }
}

#[test]
fn allow_decision_logs_a_null_matched_rule_id() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "Allow");
    assert!(lines[0]["matched_rule_id"].is_null());
}
