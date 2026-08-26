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
fn decision_log_path_naming_an_existing_directory_fails_config_load_closed() {
    let existing_dir = tempfile::tempdir().expect("tempdir should create");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        existing_dir.path().to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .failure()
        .code(2);
}

/// A FIFO is the concrete reproduction a round-1/round-2 review used for
/// the blocking-log-target hazard `src/lib.rs`'s doc comment and the
/// README describe — rejecting it at load time (alongside the directory
/// case above) closes the one shape of that hazard this crate can detect
/// up front (an already-existing non-regular target), leaving only a
/// target that starts hanging later (a stale network mount) as a
/// disclosed, undetectable-at-load-time residual risk.
#[test]
#[cfg(unix)]
fn decision_log_path_naming_an_existing_fifo_fails_config_load_closed() {
    let dir = tempfile::tempdir().expect("tempdir should create");
    let fifo_path = dir.path().join("decisions.fifo");
    let c_path = std::ffi::CString::new(fifo_path.to_str().expect("utf8 path"))
        .expect("path should have no interior nul");
    // SAFETY: `mkfifo(3)` with a valid, nul-terminated path and standard
    // owner-only permission bits; no aliasing/lifetime hazards. `libc` is
    // already a dependency of this crate (RSS measurement in
    // `src/watchdog.rs`), reused here rather than adding a new one.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo should succeed in a fresh tempdir");

    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        fifo_path.to_string_lossy()
    ));

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

/// A watchdog-trip verdict (`tests/fail_closed_exit_paths.rs`'s
/// `heredoc_inside_unterminated_command_substitution_fails_closed_to_ask`
/// repro, same payload) must still produce a logged line — this is the
/// exact case a round-1 review found missing when `decision_log::append`
/// lived *inside* `watchdog::bounded`'s closure: a detached, still-running
/// worker was the only thing that could have logged, so a trip logged
/// nothing at all. `src/lib.rs`'s `analyze_with_policy` now calls `append`
/// on the value `watchdog::bounded` actually returns, closing that gap.
///
/// Exercised via `shguard check`, not the PreToolUse hook path. `check` now
/// also has its own outer watchdog (`evaluate_with_timeout`,
/// `src/bin/shguard.rs`), bounding `analyze_with_policy` to
/// `EVALUATION_TIMEOUT` plus a grace margin so an internal trip like this
/// one has time to surface as `analyze_with_policy`'s own returned verdict
/// rather than losing the race to `check`'s outer bound — this test relies
/// on that: the repro below trips the fast memory-budget branch (~0.45s),
/// well inside both bounds, so it still pins the module-level "the value
/// `watchdog::bounded` actually returns gets logged" guarantee precisely.
/// The hook path sits behind its own outer watchdog too (`src/lib.rs`'s doc
/// comment, README's "PreToolUse hook path caveat") that this test does not
/// and cannot exercise from here.
#[test]
fn watchdog_trip_verdict_is_still_logged() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .timeout(std::time::Duration::from_secs(30))
        .args(["check", "<<$( |] "])
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "Ask");
    let reason = lines[0]["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(
        reason.contains("time budget") || reason.contains("memory budget"),
        "expected a watchdog fail-closed reason to be logged, got: {reason}"
    );
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
