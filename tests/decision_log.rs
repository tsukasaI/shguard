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
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB")
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

/// Issue #458 item 1: a symlink at `decision_log_path` used to be followed
/// (symlink-following `std::fs::metadata` at load, symlink-following open
/// at append), letting it redirect every appended line into any
/// user-writable file. `Policy::load` now uses `symlink_metadata` and
/// rejects `is_symlink()` outright.
#[test]
#[cfg(unix)]
fn decision_log_path_naming_a_symlink_fails_config_load_closed() {
    let dir = tempfile::tempdir().expect("tempdir should create");
    let real_target = dir.path().join("redirected.txt");
    fs::write(&real_target, "").expect("target file should write");
    let symlink_path = dir.path().join("decisions.jsonl");
    std::os::unix::fs::symlink(&real_target, &symlink_path).expect("symlink should create");

    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        symlink_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .failure()
        .code(2);
}

/// Issue #458 item 2: `decision_log_path`'s parent directory not existing
/// used to pass the load-time check (`NotFound` was accepted
/// unconditionally) and then fail every future append forever, silently
/// dropped. `Policy::load` now requires the parent directory to already
/// exist.
#[test]
fn decision_log_path_with_a_missing_parent_directory_fails_config_load_closed() {
    let dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = dir
        .path()
        .join("nonexistent-subdir")
        .join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .failure()
        .code(2);
}

/// Issue #458 item 3: a relative `decision_log_path` used to load and
/// resolve against the hook's per-invocation cwd (the guarded repo, not a
/// stable location). `Policy::load` now rejects any non-absolute value.
#[test]
fn relative_decision_log_path_fails_config_load_closed() {
    let (_config_dir, config_path) = write_config(
        r#"
        decision_log_path = "decisions.jsonl"
        "#,
    );

    isolated_command(&config_path)
        .args(["check", "echo hello"])
        .assert()
        .failure()
        .code(2);
}

/// A trailing `/` is dropped by `Path::parent()`/`components()`, so
/// without a dedicated check `decision_log_path = "$dir/newsub/"` would
/// pass the missing-parent-directory check (its parent, `$dir`, exists)
/// while naming something the OS can never open as a regular file.
#[test]
fn decision_log_path_with_a_trailing_slash_fails_config_load_closed() {
    let dir = tempfile::tempdir().expect("tempdir should create");
    let log_path_with_trailing_slash = format!("{}/", dir.path().join("newsub").display());
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {log_path_with_trailing_slash:?}
        "#,
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
/// The hook path's own outer watchdog trip is a different code path
/// entirely (`src/bin/shguard.rs`'s `log_trip_best_effort`, issue #459) —
/// see `hook_path_watchdog_trip_is_still_logged` below for that one.
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

/// Issue #459: unlike `check`, the PreToolUse hook path's own outer
/// watchdog (`src/bin/shguard.rs`'s `EVALUATION_TIMEOUT`, started before
/// config load and stdin read) always wins the wall-clock race against
/// `analyze_with_policy`'s internal watchdog for a genuine hang — see
/// `tests/fail_closed_exit_paths.rs`'s
/// `heredoc_inside_unterminated_command_substitution_fails_closed_to_ask`
/// for the same repro exercised against stdout alone. That means the
/// worker computing the real decision is abandoned mid-evaluation and
/// never reaches `analyze_with_policy`'s own `sink.append` call, which used
/// to leave this exact case — the hook-path input most worth auditing —
/// entirely unlogged. `run`'s `early_tx` send (right after parsing the
/// stdin JSON, before handing the command to `analyze_with_policy`) gives
/// `emit_first_result`'s trip arm a command and context to log against even
/// though the worker itself never gets there.
///
/// Uses `SHGUARD_TEST_MEM_LIMIT_MB=64` (debug-only, same injection point
/// `tests/fail_closed_exit_paths.rs`'s own
/// `memory_budget_trip_fails_closed_to_ask` pins) rather than the plain
/// wall-clock trip: the binary's outer memory arm and
/// `analyze_with_policy`'s internal one poll RSS independently and can, in
/// principle, race each other for a plain unbounded-allocation trip.
/// `LogState` (`src/bin/shguard.rs`) resolves that race in the outer trip's
/// favor whenever it gets there first (claiming ownership of the log
/// before it even emits stdout), but the worker can still occasionally
/// claim it a few microseconds earlier, in which case the logged reason is
/// the worker's own rather than the one this trip prints to stdout — a
/// disclosed, narrow tie, not this test's concern. Forcing the outer arm's
/// 64 MiB threshold far below the internal watchdog's 256 MiB one removes
/// that race entirely, so this test pins the intended code path (the outer
/// trip's own `log_trip_best_effort`) deterministically instead of
/// depending on which side happens to win.
#[cfg_attr(
    not(debug_assertions),
    ignore = "SHGUARD_TEST_MEM_LIMIT_MB injection point is compiled out in release builds"
)]
#[test]
fn hook_path_watchdog_trip_is_still_logged() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin = r#"{"tool_name":"Bash","tool_input":{"command":"<<$( |] "},"hook_event_name":"PreToolUse"}"#;
    isolated_command(&config_path)
        .env("SHGUARD_TEST_MEM_LIMIT_MB", "64")
        .timeout(std::time::Duration::from_secs(30))
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["command"], "<<$( |] ");
    assert_eq!(lines[0]["decision"], "Ask");
    let reason = lines[0]["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(
        reason.contains("memory budget") && !reason.contains("growth"),
        "expected the binary's own outer-watchdog memory-trip reason to be logged, got: {reason}"
    );
}

// Issue #468: `permission_mode`/`agent_id` from PreToolUse stdin are
// recorded on the decision log line, and `null` when the hook stdin omits
// them (or, for `shguard check`, doesn't exist at all).

#[test]
fn hook_path_logs_permission_mode_and_agent_id_when_present() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"permission_mode":"bypassPermissions","agent_id":"agent-42","agent_type":"explore"}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["permission_mode"], "bypassPermissions");
    assert_eq!(lines[0]["agent_id"], "agent-42");
}

#[test]
fn hook_path_logs_null_permission_mode_and_agent_id_when_absent() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert!(lines[0]["permission_mode"].is_null());
    assert!(lines[0]["agent_id"].is_null());
}

#[test]
fn hook_path_logs_an_unrecognized_permission_mode_verbatim() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"permission_mode":"some-future-mode"}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["permission_mode"], "some-future-mode");
}

/// Pins the `null` (absent) vs `"default"` (present) distinction
/// `HookContext` exists to preserve (issue #468) — a present `"default"`
/// must log as the string `"default"`, not `null`.
#[test]
fn hook_path_logs_the_default_permission_mode_as_the_string_default_not_null() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin =
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"permission_mode":"default"}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["permission_mode"], "default");
}

/// A non-string `permission_mode` must log as `null`, the same as an
/// absent field, not fail the whole stdin parse closed. `agent_id` is
/// different: its presence alone (any non-null value) is what issue
/// #469's `subagent` `ask_outcome` override keys on, so a present,
/// non-string `agent_id` still logs its stringified value rather than
/// `null` -- pinned separately below.
#[test]
fn hook_path_logs_null_for_a_non_string_permission_mode() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin =
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"permission_mode":123}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "Allow");
    assert!(lines[0]["permission_mode"].is_null());
}

/// A present, non-string `agent_id` (a JSON object here) is not treated
/// the same as an absent one: it still logs (stringified), since its
/// mere presence is what the `subagent` `ask_outcome` override keys on.
#[test]
fn hook_path_logs_a_present_non_string_agent_id_stringified() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin =
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"agent_id":{"x":1}}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "Allow");
    assert_eq!(lines[0]["agent_id"], r#"{"x":1}"#);
}

/// A JSON `null` `agent_id` (explicitly present but null) logs the same
/// as an absent field -- only a present, non-null value counts as a
/// subagent context.
#[test]
fn hook_path_logs_null_for_an_explicitly_null_agent_id() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let hook_stdin =
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"},"agent_id":null}"#;
    isolated_command(&config_path)
        .write_stdin(hook_stdin)
        .assert()
        .success();

    let lines = read_jsonl_lines(&log_path);
    assert_eq!(lines.len(), 1);
    assert!(lines[0]["agent_id"].is_null());
}

#[test]
fn check_subcommand_logs_null_permission_mode_and_agent_id() {
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
    assert!(lines[0]["permission_mode"].is_null());
    assert!(lines[0]["agent_id"].is_null());
}

// Issue #458 item 4: the log path itself used to be undefended -- `rm`
// and `ln -sf` against it were both `Allow` (only `~/.bashrc`-class
// targets were floored by `shell-init-ln`), so the audit trail was
// deletable/redirectable by the very agent it audits. `Policy::load` now
// folds the log path itself into the same self-protection deny-rule
// generation the config file gets, scoped to the exact log path (not its
// whole containing directory, to avoid over-protecting unrelated files a
// user-chosen log directory might also hold -- see `self_protection_toml`'s
// `exact_target` doc comment in `src/config.rs`).

#[test]
fn rm_against_the_decision_log_path_is_blocked() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let assert = isolated_command(&config_path)
        .args(["check", &format!("rm {:?}", log_path.to_string_lossy())])
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains("Decision: Block"),
        "expected rm against the decision log path to Block, got: {stdout}"
    );
}

/// Not a self-protection rule: `truncate -s0`/`--size` against ANY target
/// already `Block`s via the pre-existing, global `truncate-zero` rule
/// (`rules/blocklist.toml`), regardless of `decision_log_path`. Pinned
/// here anyway so a future narrowing of `truncate-zero` (e.g. adding a
/// `targets` restriction it doesn't have today) doesn't silently leave
/// the decision log truncatable.
#[test]
fn truncate_against_the_decision_log_path_is_blocked() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let assert = isolated_command(&config_path)
        .args([
            "check",
            &format!("truncate -s0 {:?}", log_path.to_string_lossy()),
        ])
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains("Matched rule: truncate-zero"),
        "expected truncate -s0 against the decision log path to Block via the global \
         truncate-zero rule, got: {stdout}"
    );
}

#[test]
fn ln_sf_over_the_decision_log_path_is_blocked() {
    let log_dir = tempfile::tempdir().expect("tempdir should create");
    let log_path = log_dir.path().join("decisions.jsonl");
    let (_config_dir, config_path) = write_config(&format!(
        r#"
        decision_log_path = {:?}
        "#,
        log_path.to_string_lossy()
    ));

    let assert = isolated_command(&config_path)
        .args([
            "check",
            &format!("ln -sf ./notes.txt {:?}", log_path.to_string_lossy()),
        ])
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains("Decision: Block"),
        "expected ln -sf over the decision log path to Block, got: {stdout}"
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
