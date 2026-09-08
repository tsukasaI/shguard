//! Per-`permission_mode` `[ask_outcome]` table integration tests (issue
//! #469): resolves the #467 `ask_outcome` floor against the PreToolUse
//! hook's `permission_mode`/`agent_id`, instead of one config-wide switch.
//! Drives the real `shguard` binary through both entry points — `shguard
//! check --permission-mode <mode>` and the PreToolUse hook's stdin
//! contract — the same way `tests/ask_outcome.rs` does.
//!
//! The `[ask_outcome]` table's own parse matrix (every key, an empty
//! table, an unrecognized key, `"allow"` in any slot, `subagent`
//! resolution) needs `crate::rules::UserConfig::parse`/`AskOutcome`, both
//! `pub(crate)` and unreachable from an integration test — that matrix
//! lives in `src/gate.rs`'s existing inline `mod tests`, next to the #467
//! matrix it extends.

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

fn run_check_json(
    config_path: &std::path::Path,
    command: &str,
    permission_mode: Option<&str>,
) -> Value {
    let mut args = vec!["check", command, "--json"];
    if let Some(mode) = permission_mode {
        args.push("--permission-mode");
        args.push(mode);
    }
    let assert = isolated_command(config_path).args(args).assert();
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

fn read_jsonl_lines(path: &std::path::Path) -> Vec<Value> {
    let contents = fs::read_to_string(path).expect("log file should be readable");
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line should be valid JSON"))
        .collect()
}

fn permission_decision(output: &Value) -> &str {
    output["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .expect("permissionDecision should be a string")
}

/// The `[ask_outcome]` table this whole file drives: half the modes ask,
/// half deny, so the per-mode matrix below actually distinguishes a mode
/// resolving `Ask`-vs-`Block` rather than merely "any mode resolves the
/// same thing".
const PER_MODE_CONFIG: &str = r#"
[ask_outcome]
default           = "ask"
plan              = "ask"
acceptEdits       = "ask"
auto              = "deny"
dontAsk           = "deny"
bypassPermissions = "deny"
"#;

// ==== structural Ask, `[[ask]]` rule Ask, Block, Allow, across every mode ====

/// One table-driven check per `(mode, command)` pair covering a structural
/// Ask (`$(which python3)`), a rule-table Ask (`tar -C / -f a.tar`,
/// `tar-directory-root-or-home`), an outright Block (`rm -rf /`), and a
/// clean Allow (`echo hello`) — `apply_ask_outcome` (`src/lib.rs`) only
/// ever remaps a verdict whose FINAL decision is `Ask`, so Block/Allow
/// must stay untouched under every mode, while the two Ask flavors must
/// track `PER_MODE_CONFIG`'s own per-mode "ask"/"deny" split exactly.
#[test]
fn per_mode_matrix_across_ask_block_and_allow() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);

    let cases: &[(&str, &str, &str, &str)] = &[
        ("default", "$(which python3)", "Ask", "structural"),
        ("plan", "$(which python3)", "Ask", "structural"),
        ("acceptEdits", "$(which python3)", "Ask", "structural"),
        ("auto", "$(which python3)", "Block", "structural"),
        ("dontAsk", "$(which python3)", "Block", "structural"),
        (
            "bypassPermissions",
            "$(which python3)",
            "Block",
            "structural",
        ),
        ("default", "tar -C / -f a.tar", "Ask", "rule-table"),
        ("auto", "tar -C / -f a.tar", "Block", "rule-table"),
        ("dontAsk", "tar -C / -f a.tar", "Block", "rule-table"),
        (
            "bypassPermissions",
            "tar -C / -f a.tar",
            "Block",
            "rule-table",
        ),
        ("default", "rm -rf /", "Block", "existing-block"),
        ("auto", "rm -rf /", "Block", "existing-block"),
        ("default", "echo hello", "Allow", "existing-allow"),
        ("auto", "echo hello", "Allow", "existing-allow"),
    ];

    for (mode, command, expected, flavor) in cases {
        let output = run_check_json(&config_path, command, Some(mode));
        assert_eq!(
            output["decision"], *expected,
            "mode {mode:?}, command {command:?} ({flavor}): {output}"
        );
    }
}

/// `permission_mode` absent from the hook stdin resolves the same
/// conservative way `Unknown` does — `Ask`, even under `PER_MODE_CONFIG`,
/// which sets three named modes to `deny`.
#[test]
fn absent_permission_mode_resolves_ask_even_with_denying_modes_configured() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"}}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "ask");
}

/// An unrecognized `permission_mode` value resolves the same way absence
/// does — `Ask` — regardless of what any named mode in the table
/// resolves to.
#[test]
fn unrecognized_permission_mode_resolves_ask() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"some-future-mode"}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "ask");
}

// ==== fail-closed adapter paths under a table-form `ask_outcome` ====
//
// Mirrors `tests/ask_outcome.rs`'s own #467 fail-closed matrix (malformed
// stdin, a missing `command` field, oversized stdin), but against
// `PER_MODE_CONFIG`'s table instead of a bare string, to pin issue #469's
// "fall back to the string-form value if set, else ask" rule for a
// `permission_mode` this binary genuinely cannot read at that point in the
// adapter, distinct from the case where it can.

/// A missing `command` field is NOT a "permission_mode unreadable" case:
/// `extract_bash_command` (`src/adapter.rs`) parses `permission_mode`
/// before it ever checks for `command`, so this failure's `HookContext`
/// carries the real, stdin-derived `permission_mode` — the table resolves
/// against it exactly the way a successfully-analyzed command would.
#[test]
fn missing_command_field_resolves_against_the_readable_permission_mode() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);

    let stdin = r#"{"tool_name":"Bash","tool_input":{},"permission_mode":"auto"}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "deny");

    let stdin = r#"{"tool_name":"Bash","tool_input":{},"permission_mode":"default"}"#;
    let output = run_hook(&config_path, stdin);
    assert_eq!(permission_decision(&output), "ask");
}

/// Malformed JSON never gets far enough to parse `permission_mode` at
/// all -- `extract_bash_command` returns `HookContext::none()` for this
/// case specifically -- so it resolves the same conservative way an
/// absent `permission_mode` always does, even though `PER_MODE_CONFIG`
/// sets `auto`/`dontAsk`/`bypassPermissions` to `"deny"`.
#[test]
fn malformed_stdin_resolves_ask_under_a_table_form_ask_outcome() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let output = run_hook(&config_path, "not json");
    assert_eq!(permission_decision(&output), "ask");
}

/// Oversized stdin is a composition-root path (`src/bin/shguard.rs`) that
/// never reaches `extract_bash_command`/`HookContext` at all -- `run`
/// resolves it via `policy.ask_outcome(&HookContext::none())` directly --
/// so it resolves the same conservative way malformed JSON does.
#[test]
fn oversized_stdin_resolves_ask_under_a_table_form_ask_outcome() {
    const MAX_STDIN_BYTES: usize = 10 * 1024 * 1024;
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let oversized_stdin = "a".repeat(MAX_STDIN_BYTES + 1);
    let output = run_hook(&config_path, &oversized_stdin);
    assert_eq!(permission_decision(&output), "ask");
}

// ==== subagent override ====

/// `subagent = "deny"` overrides the mode-keyed value only when `agent_id`
/// is present in the hook stdin — the same command, same `permission_mode`
/// ("default", which the table alone would resolve to "ask"), differs only
/// by whether `agent_id` is present.
#[test]
fn subagent_override_applies_only_when_agent_id_is_present() {
    let (_dir, config_path) = write_config(
        r#"
        [ask_outcome]
        default  = "ask"
        subagent = "deny"
        "#,
    );

    let without_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"default"}"#;
    let output = run_hook(&config_path, without_agent_id);
    assert_eq!(permission_decision(&output), "ask");

    let with_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"default","agent_id":"agent-1"}"#;
    let output = run_hook(&config_path, with_agent_id);
    assert_eq!(permission_decision(&output), "deny");
}

/// `subagent`'s override applies even when `agent_id` is present but not a
/// JSON string (a number here) -- its mere presence (any non-null value)
/// is what the override keys on, not its type. A JSON `null` `agent_id`,
/// by contrast, is treated as absent.
#[test]
fn subagent_override_applies_to_a_non_string_agent_id() {
    let (_dir, config_path) = write_config(
        r#"
        [ask_outcome]
        default  = "ask"
        subagent = "deny"
        "#,
    );

    let non_string_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"default","agent_id":42}"#;
    let output = run_hook(&config_path, non_string_agent_id);
    assert_eq!(permission_decision(&output), "deny");

    let null_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"default","agent_id":null}"#;
    let output = run_hook(&config_path, null_agent_id);
    assert_eq!(permission_decision(&output), "ask");
}

/// The same non-string-`agent_id` presence check applies on the
/// missing-`command` fail-closed path too, not only the analyzed-command
/// path above -- both go through the same `subagent_id` extraction in
/// `src/adapter.rs`, but only one of them was previously covered.
#[test]
fn subagent_override_applies_to_a_non_string_agent_id_on_the_missing_command_path() {
    let (_dir, config_path) = write_config(
        r#"
        [ask_outcome]
        default  = "ask"
        subagent = "deny"
        "#,
    );

    let non_string_agent_id =
        r#"{"tool_name":"Bash","tool_input":{},"permission_mode":"default","agent_id":42}"#;
    let output = run_hook(&config_path, non_string_agent_id);
    assert_eq!(permission_decision(&output), "deny");

    let null_agent_id =
        r#"{"tool_name":"Bash","tool_input":{},"permission_mode":"default","agent_id":null}"#;
    let output = run_hook(&config_path, null_agent_id);
    assert_eq!(permission_decision(&output), "ask");
}

/// `subagent` overrides in either direction: `subagent = "ask"` loosens a
/// mode's own `"deny"` back to `"ask"` for subagent calls specifically,
/// not only tightening a mode's `"ask"` to `"deny"`.
#[test]
fn subagent_override_can_loosen_a_denying_mode_back_to_ask() {
    let (_dir, config_path) = write_config(
        r#"
        [ask_outcome]
        auto     = "deny"
        subagent = "ask"
        "#,
    );

    let without_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"auto"}"#;
    let output = run_hook(&config_path, without_agent_id);
    assert_eq!(permission_decision(&output), "deny");

    let with_agent_id = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"},"permission_mode":"auto","agent_id":"agent-1"}"#;
    let output = run_hook(&config_path, with_agent_id);
    assert_eq!(permission_decision(&output), "ask");
}

/// A table slot with a wrong-typed value (a number instead of a string)
/// fails config load closed, not silently ignored/defaulted.
#[test]
fn wrong_typed_table_slot_fails_config_load_closed() {
    let (_dir, config_path) = write_config(
        r#"
        [ask_outcome]
        default = 5
        "#,
    );
    isolated_command(&config_path)
        .args(["check", "echo hi", "--json"])
        .assert()
        .failure()
        .code(2);
}

// ==== `check --permission-mode` / hook log parity ====

/// `shguard check --permission-mode auto` on a command reproduces exactly
/// the same `decision_log_path` line the PreToolUse hook would have
/// written for the same command under `permission_mode: "auto"` — both
/// entry points share `src/lib.rs::analyze_with_policy`, and `check` has
/// no `agent_id` of its own to pass, so the only difference the log line
/// could show is a spurious one. Asserted as whole-line equality, not
/// field-by-field, so a future field this test doesn't name explicitly
/// (`deny_message`, `matched_rule_id`, `normalized_argv`, …) is still
/// covered.
#[test]
fn check_permission_mode_flag_matches_the_hook_paths_own_log_line() {
    // Every documented mode, plus one this binary doesn't recognize — the
    // PR's central parity claim ("check --permission-mode reproduces
    // exactly what the hook path would decide") must hold for all of them,
    // not only `auto`.
    for mode in [
        "default",
        "plan",
        "acceptEdits",
        "auto",
        "dontAsk",
        "bypassPermissions",
        "some-future-mode",
    ] {
        let log_dir = tempfile::tempdir().expect("tempdir should create");
        let hook_log_path = log_dir.path().join("hook.jsonl");
        let check_log_path = log_dir.path().join("check.jsonl");

        let (_hook_dir, hook_config_path) = write_config(&format!(
            r#"
            decision_log_path = {:?}
            {PER_MODE_CONFIG}
            "#,
            hook_log_path.to_string_lossy()
        ));
        let (_check_dir, check_config_path) = write_config(&format!(
            r#"
            decision_log_path = {:?}
            {PER_MODE_CONFIG}
            "#,
            check_log_path.to_string_lossy()
        ));

        let command = "$(which python3)";
        let hook_stdin = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":{command:?}}},"permission_mode":{mode:?}}}"#
        );
        let hook_output = run_hook(&hook_config_path, &hook_stdin);
        let check_output = run_check_json(&check_config_path, command, Some(mode));
        assert_eq!(
            permission_decision(&hook_output) == "deny",
            check_output["decision"] == "Block",
            "mode {mode:?}: hook decision {:?} and check decision {:?} disagree",
            permission_decision(&hook_output),
            check_output["decision"]
        );

        let hook_lines = read_jsonl_lines(&hook_log_path);
        let check_lines = read_jsonl_lines(&check_log_path);
        assert_eq!(hook_lines.len(), 1);
        assert_eq!(check_lines.len(), 1);

        assert_eq!(hook_lines[0]["permission_mode"], mode);
        assert!(hook_lines[0]["agent_id"].is_null());
        assert_eq!(
            hook_lines[0], check_lines[0],
            "mode {mode:?}: the hook and `check --permission-mode` log lines \
             for the same command under the same mode must be identical"
        );
    }
}

/// `shguard check` with no `--permission-mode` flag behaves exactly as it
/// did before this flag existed: `permission_mode` resolves as absent
/// (`Ask`, per the conservative fallback), matching the hook path with no
/// `permission_mode` field at all.
#[test]
fn check_without_permission_mode_flag_matches_the_hook_with_no_permission_mode_field() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let command = "$(which python3)";

    let check_output = run_check_json(&config_path, command, None);
    assert_eq!(check_output["decision"], "Ask");

    let hook_stdin = format!(r#"{{"tool_name":"Bash","tool_input":{{"command":{command:?}}}}}"#);
    let hook_output = run_hook(&config_path, &hook_stdin);
    assert_eq!(permission_decision(&hook_output), "ask");
}

// ==== `--permission-mode` CLI parsing ====

#[test]
fn check_permission_mode_missing_value_is_a_usage_error() {
    let (_dir, config_path) = write_config("");
    isolated_command(&config_path)
        .args(["check", "echo hi", "--permission-mode"])
        .assert()
        .failure()
        .code(2);
}

/// issue #465: a usage error still emits `{"error": "..."}` on stdout when
/// `--json` was already parsed before the error is raised, instead of
/// leaving a `--json` caller with empty stdout it can't parse. `--json`
/// here precedes `--permission-mode`, so it has already been observed by
/// the time the missing-value error fires.
#[test]
fn check_permission_mode_missing_value_usage_error_is_json_when_json_precedes_it() {
    let (_dir, config_path) = write_config("");
    let assert = isolated_command(&config_path)
        .args(["check", "echo hi", "--json", "--permission-mode"])
        .assert()
        .failure()
        .code(2);
    let output = assert.get_output();
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("--json usage error should be valid JSON");
    assert!(
        value.get("error").is_some_and(Value::is_string),
        "expected an \"error\" string field, got {value:?}"
    );
}

/// A flag-shaped `--permission-mode` value (e.g. `--json` following it) is
/// a usage error, not silently consumed as an `Unknown("--json")` mode
/// value — the loop must not swallow the next real flag.
#[test]
fn check_permission_mode_value_looking_like_a_flag_is_a_usage_error() {
    let (_dir, config_path) = write_config("");
    isolated_command(&config_path)
        .args(["check", "echo hi", "--permission-mode", "--json"])
        .assert()
        .failure()
        .code(2);
}

/// A second `--permission-mode` occurrence is a usage error, not a silent
/// last-one-wins.
#[test]
fn check_permission_mode_given_twice_is_a_usage_error() {
    let (_dir, config_path) = write_config("");
    isolated_command(&config_path)
        .args([
            "check",
            "echo hi",
            "--permission-mode",
            "auto",
            "--permission-mode",
            "default",
        ])
        .assert()
        .failure()
        .code(2);
}

/// A `--`-prefixed positional (e.g. `--permission-mode=auto` typo'd
/// without a space) is rejected as an unrecognized flag, not silently
/// analyzed as the literal command string -- a typo that skips the check
/// and exits 0 anyway would be the worst failure mode for a checking
/// tool.
#[test]
fn check_dash_dash_prefixed_positional_is_a_usage_error_not_a_command() {
    let (_dir, config_path) = write_config("");
    isolated_command(&config_path)
        .args(["check", "--permission-mode=auto", "--json"])
        .assert()
        .failure()
        .code(2);
}

/// An unrecognized `--permission-mode` value is not itself a usage error
/// (it parses to `PermissionMode::Unknown`, the same as an unrecognized
/// hook stdin value would) — resolves `Ask` under `PER_MODE_CONFIG`, the
/// same as the absent/`Unknown` cases above.
#[test]
fn check_permission_mode_unrecognized_value_resolves_ask_not_a_usage_error() {
    let (_dir, config_path) = write_config(PER_MODE_CONFIG);
    let output = run_check_json(&config_path, "$(which python3)", Some("some-future-mode"));
    assert_eq!(output["decision"], "Ask");
}

// ==== bare-string (#467) form still applies unconditionally ====

/// The bare-string form (`ask_outcome = "deny"`) still floors every
/// terminal Ask unconditionally, regardless of `--permission-mode` — this
/// is #467's own existing behavior, pinned here specifically against the
/// new flag to guard against a regression where introducing per-mode
/// resolution accidentally narrowed the bare-string form's scope.
#[test]
fn bare_string_form_ignores_permission_mode_flag() {
    let (_dir, config_path) = write_config(
        r#"
        ask_outcome = "deny"
        "#,
    );
    for mode in [
        None,
        Some("default"),
        Some("auto"),
        Some("some-future-mode"),
    ] {
        let output = run_check_json(&config_path, "$(which python3)", mode);
        assert_eq!(output["decision"], "Block", "mode {mode:?}");
    }
}
