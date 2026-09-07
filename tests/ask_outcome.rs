//! `ask_outcome` user-config key integration tests (issue #467): floors
//! every terminal `Ask` verdict `shguard::analyze_with_policy` would
//! otherwise return to `Block` when the user config sets `ask_outcome =
//! "deny"`. Drives the real `shguard` binary through both entry points —
//! `shguard check` and the PreToolUse hook's stdin contract — the same way
//! `tests/decision_log.rs` does, so these tests exercise the actual
//! composition root rather than `src/lib.rs::apply_ask_outcome` in
//! isolation.
//!
//! Isolates the environment the same way `tests/user_config.rs` and
//! `tests/decision_log.rs` do, so a host machine's own `SHGUARD_CONFIG`/
//! config file can't make these spuriously fail or pass.
//!
//! The `ask_outcome` parse matrix (absent/"ask"/"deny" succeed at load,
//! "allow"/"block"/"" fail closed) needs `crate::rules::UserConfig::parse`,
//! a `pub(crate)` item integration tests cannot reach — that matrix lives
//! in `src/gate.rs`'s existing inline `mod tests`, next to the
//! `escalation_floor_*_is_rejected_at_config_load`/`escalation_floor_rejects_unknown_value`
//! tests it mirrors.

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

fn run_check_json(config_path: &std::path::Path, command: &str) -> Value {
    let assert = isolated_command(config_path)
        .args(["check", command, "--json"])
        .assert();
    let output = assert.get_output();
    serde_json::from_slice(&output.stdout).expect("check --json stdout should be valid JSON")
}

fn run_hook(config_path: &std::path::Path, stdin: &str) -> Value {
    let assert = isolated_command(config_path)
        .write_stdin(stdin)
        .assert()
        .success();
    let output = assert.get_output();
    serde_json::from_slice(&output.stdout).expect("hook stdout should be valid JSON")
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

// ==== structural Ask, remapped ====

/// A structural fallback Ask (an unresolved `$(...)` in command position,
/// the same repro `src/adapter.rs`'s own `bash_ask_command_asks` test uses)
/// stays `Ask` with no `ask_outcome` configured — today's unmodified
/// behavior.
#[test]
fn structural_ask_stays_ask_with_no_ask_outcome_configured() {
    let (_dir, config_path) = write_config("");
    let output = run_check_json(&config_path, "$(which python3)");
    assert_eq!(output["decision"], "Ask");
    assert!(output["matched_rule_id"].is_null());
}

/// The same structural Ask is remapped to `Block` once `ask_outcome =
/// "deny"` is configured: `matched_rule_id` stays `null` (this is not an
/// ordinary rule-matched Block), the reason combines the original Ask
/// reason with the `ask_outcome = "deny"` explanation, and a `deny_message`
/// is attached telling the agent how to rewrite the command.
#[test]
fn structural_ask_is_remapped_to_block_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_check_json(&config_path, "$(which python3)");
    assert_eq!(output["decision"], "Block");
    assert!(output["matched_rule_id"].is_null());
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(
        reason.contains("ask_outcome = \"deny\""),
        "reason should name the key that floored this Ask: {reason}"
    );
    let deny_message = output["deny_message"]
        .as_str()
        .expect("deny_message should be a string");
    assert!(!deny_message.is_empty());
}

/// The same structural-Ask remap, exercised through the PreToolUse hook's
/// stdin contract instead of `shguard check` — both entry points share
/// `src/lib.rs::analyze_with_policy`, so this pins that the remap is not
/// somehow reachable only from one of them.
#[test]
fn structural_ask_is_remapped_to_deny_via_the_hook_path_too() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"}}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "deny");
}

// ==== rule-table Ask, remapped ====

/// A rule-table `decision = "ask"` match (`tar-directory-root-or-home`,
/// same repro `src/gate.rs`'s `escalation_floor_deny_upgrades_an_ask_decision_rule_match_too`
/// test uses) stays `Ask`, naming the matched rule, with no `ask_outcome`
/// configured.
#[test]
fn rule_table_ask_stays_ask_with_no_ask_outcome_configured() {
    let (_dir, config_path) = write_config("");
    let output = run_check_json(&config_path, "tar -C / -f a.tar");
    assert_eq!(output["decision"], "Ask");
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(reason.contains("tar-directory-root-or-home"));
}

/// The same rule-table Ask is remapped to `Block` once `ask_outcome =
/// "deny"` is configured — `matched_rule_id` still goes `null` even though
/// a specific rule id drove the original Ask, matching the structural
/// case's own shape (a reason-based `jq` filter, not `matched_rule_id`
/// alone, is what isolates a floored Ask uniformly — several pre-existing
/// structural Blocks also carry a null rule id).
#[test]
fn rule_table_ask_is_remapped_to_block_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_check_json(&config_path, "tar -C / -f a.tar");
    assert_eq!(output["decision"], "Block");
    assert!(output["matched_rule_id"].is_null());
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(reason.contains("tar-directory-root-or-home"));
    assert!(reason.contains("ask_outcome = \"deny\""));
}

// ==== existing Block/Allow verdicts are untouched ====

/// An ordinary rule-matched `Block` (`rm -rf /`, same repro
/// `tests/decision_log.rs` uses) keeps its own `matched_rule_id` and reason
/// verbatim under `ask_outcome = "deny"` — the remap only ever touches a
/// terminal `Ask`, never a `Block` gate already decided on its own.
#[test]
fn existing_block_with_rule_is_untouched_by_ask_outcome() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_check_json(&config_path, "rm -rf /");
    assert_eq!(output["decision"], "Block");
    assert_eq!(
        output["matched_rule_id"],
        "rm-recursive-force-dangerous-target"
    );
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(!reason.contains("ask_outcome"));
}

/// An ordinary `Allow` (a clean command) stays `Allow` under `ask_outcome =
/// "deny"` — the key only ever floors an `Ask`, never touches an `Allow`.
#[test]
fn existing_allow_is_untouched_by_ask_outcome() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_check_json(&config_path, "echo hello");
    assert_eq!(output["decision"], "Allow");
}

// ==== [[allow]] downgrade still wins over the remap ====

/// `rm -rf $HOME` — rule 4's except-target refinement, the same genuine
/// structural Ask `src/gate.rs`'s own
/// `config_allow_rule_downgrades_a_structural_ask` test uses — downgraded to
/// `Allow` by a matching `[[allow]]` entry, stays `Allow` under
/// `ask_outcome = "deny"`: `apply_allowlist_downgrade` (`src/gate.rs`) runs
/// INSIDE `gate::analyze_with_policy`, before `src/lib.rs::apply_ask_outcome`
/// ever sees the verdict, so a rescued command must never come back as a
/// `Block`.
///
/// A user `[[ask]]`-rule match would NOT demonstrate this the same way:
/// `apply_ask_floor` (`src/gate.rs`) — the step that turns a plain `Allow`
/// into `Ask` for a user `[[ask]]` entry — runs AFTER
/// `apply_allowlist_downgrade`, so an `[[allow]]` entry can only ever rescue
/// an `Ask` `core` evaluation (a blocklist/gate rule) already produced, not
/// one the ask-floor step introduces later in the same call
/// (`src/gate.rs`'s own `config_ask_beats_allow_when_both_match_the_same_command`
/// pins exactly this: `Ask` wins even with a matching `[[allow]]` entry).
#[test]
fn allowlisted_command_stays_allow_not_remapped_to_block() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"

        [[allow]]
        id = "user-allow-rm"
        reason = "trust me"
        command = "rm"
        "#,
    );
    let output = run_check_json(&config_path, "rm -rf $HOME");
    assert_eq!(output["decision"], "Allow");
    // `Allow` alone would also pass for a command that was never an Ask in
    // the first place — assert the allowlist-downgrade reason specifically,
    // so this test actually fails if the rescue stopped happening.
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(
        reason.contains("user-allow-rm"),
        "expected the allowlist-downgrade reason naming the rescuing entry, got: {reason}"
    );
}

// ==== compound command: the remap must not steal a real Block's identity ====

/// A compound command where an earlier simple command would Ask on its own
/// (an unresolved `$(...)`) but a later one is an outright rule-matched
/// `Block` (`rm -rf /`) must keep the `rm` rule's id and reason —
/// `crate::gate::fold_worst` already resolved the whole line to `Block`
/// before this function's remap ever runs, and the remap only fires on a
/// verdict whose FINAL decision is `Ask`, so it never has a chance to
/// overwrite this `Block` with its own generic reason/`null` rule id.
#[test]
fn compound_command_keeps_the_real_block_rule_id_over_the_remap() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_check_json(&config_path, "$(which python3); rm -rf /");
    assert_eq!(output["decision"], "Block");
    assert_eq!(
        output["matched_rule_id"],
        "rm-recursive-force-dangerous-target"
    );
}

// ==== a rule-authored deny_message survives the remap ====

/// A user `[[ask]]` rule that already declares its own `deny_message` must
/// keep it verbatim after the remap, not lose it to the generic
/// rewrite-guidance message: `src/lib.rs::apply_ask_outcome` cannot tell a
/// rule-authored `Ask` from a structural one (`Verdict::matched_rule`
/// returns `None` for `Ask` either way), so it must never assume the
/// generic $VAR/$(...) guidance applies and overwrite a message that was
/// never about that at all.
#[test]
fn rule_authored_deny_message_survives_the_remap() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"

        [[ask]]
        id = "user-ask-gh"
        reason = "confirm every gh invocation"
        command = "gh"
        deny_message = "run `gh auth status` first"
        "#,
    );
    let output = run_check_json(&config_path, "gh pr view");
    assert_eq!(output["decision"], "Block");
    assert_eq!(output["deny_message"], "run `gh auth status` first");
}

// ==== watchdog timeout Ask is excluded from the remap ====

/// The watchdog-timeout Ask (`src/watchdog.rs`'s own fail-closed `Ask`,
/// same repro `tests/decision_log.rs::watchdog_trip_verdict_is_still_logged`
/// uses) is created OUTSIDE `gate::analyze_with_policy` entirely, so it
/// must stay `Ask` even under `ask_outcome = "deny"` — remapping it would
/// misrepresent a time/memory budget trip as an ordinary structural
/// decision. `src/lib.rs::apply_ask_outcome` runs inside the closure
/// `watchdog::bounded` wraps, on `gate::analyze_with_policy`'s own return
/// value only, specifically so a watchdog trip's `Ask` never reaches it.
#[test]
fn watchdog_timeout_ask_is_not_remapped_even_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let assert = isolated_command(&config_path)
        .timeout(std::time::Duration::from_secs(30))
        .args(["check", "<<$( |] ", "--json"])
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(output["decision"], "Ask");
    let reason = output["reason"]
        .as_str()
        .expect("reason should be a string");
    assert!(
        reason.contains("time budget") || reason.contains("memory budget"),
        "expected a watchdog fail-closed reason, got: {reason}"
    );
}

// ==== adapter / composition-root fail-closed paths (issue #467) ====

/// Malformed stdin JSON stays `ask` with no `ask_outcome` configured — the
/// hook path's ordinary fail-closed default, unaffected by this issue.
#[test]
fn malformed_stdin_asks_with_no_ask_outcome_configured() {
    let (_dir, config_path) = write_config("");
    let output = run_hook(&config_path, "not json");
    assert_eq!(permission_decision(&output), "ask");
}

/// Malformed stdin JSON emits `deny` once `ask_outcome = "deny"` is
/// configured: `crate::adapter::respond` passes the loaded `Policy`'s own
/// `ask_outcome()` into `fail_closed_with` for exactly this path.
#[test]
fn malformed_stdin_denies_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let output = run_hook(&config_path, "not json");
    assert_eq!(permission_decision(&output), "deny");
    assert!(!permission_reason(&output).is_empty());
}

/// A `Bash` payload missing `tool_input.command` stays `ask` by default.
#[test]
fn missing_command_field_asks_with_no_ask_outcome_configured() {
    let (_dir, config_path) = write_config("");
    let stdin = r#"{"tool_name":"Bash","tool_input":{}}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "ask");
}

/// The same missing-`command`-field payload denies under `ask_outcome =
/// "deny"`.
#[test]
fn missing_command_field_denies_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let stdin = r#"{"tool_name":"Bash","tool_input":{}}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "deny");
}

/// Oversized stdin (over `MAX_STDIN_BYTES`, `src/bin/shguard.rs`) stays
/// `ask` by default — the composition-root path `run` takes before a
/// command ever reaches `handle_with_policy`/`analyze_with_policy`, same
/// repro `tests/fail_closed_exit_paths.rs::oversized_stdin_fails_closed_to_ask`
/// uses.
#[test]
fn oversized_stdin_asks_with_no_ask_outcome_configured() {
    const MAX_STDIN_BYTES: usize = 10 * 1024 * 1024;
    let (_dir, config_path) = write_config("");
    let oversized_stdin = "a".repeat(MAX_STDIN_BYTES + 1);
    let output = run_hook(&config_path, &oversized_stdin);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("exceeds"));
}

/// The same oversized-stdin path denies under `ask_outcome = "deny"`:
/// `run` (`src/bin/shguard.rs`) already has `policy` loaded at this point,
/// and passes `policy.ask_outcome()` into `fail_closed_with`.
#[test]
fn oversized_stdin_denies_when_ask_outcome_is_deny() {
    const MAX_STDIN_BYTES: usize = 10 * 1024 * 1024;
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let oversized_stdin = "a".repeat(MAX_STDIN_BYTES + 1);
    let output = run_hook(&config_path, &oversized_stdin);
    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("exceeds"));
}

/// Invalid UTF-8 on stdin makes `read_to_string` fail with `InvalidData`
/// regardless of length (`src/bin/shguard.rs`'s own "A read error also
/// covers..." comment) — the genuine stdin-read-error path, distinct from
/// the oversized-but-valid-UTF-8 path above. Stays `ask` by default.
#[test]
fn invalid_utf8_stdin_asks_with_no_ask_outcome_configured() {
    let (_dir, config_path) = write_config("");
    let assert = isolated_command(&config_path)
        .write_stdin(&b"\xff\xfe not valid utf-8"[..])
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("could not read stdin"));
}

/// The same invalid-UTF-8 stdin-read-error path denies under `ask_outcome
/// = "deny"`.
#[test]
fn invalid_utf8_stdin_denies_when_ask_outcome_is_deny() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    let assert = isolated_command(&config_path)
        .write_stdin(&b"\xff\xfe not valid utf-8"[..])
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("could not read stdin"));
}
