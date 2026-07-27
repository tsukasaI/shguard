//! Fail-closed exit-path regression tests (issue #52): before this fix,
//! deeply nested `{`/`(` input crashed the process (`SIGABRT`, empty
//! stdout — an uncaught stack overflow deep inside brush-parser's own PEG
//! grammar), an oversized stdin stream was read to completion with no
//! bound, and an unanticipated panic anywhere in the composition root
//! propagated past `main` uncaught. Every one of those is a fail-*open*
//! failure mode for a PreToolUse hook: Claude Code proceeds unguarded when
//! the hook produces no decision at all. These tests drive the real
//! `shguard` binary (`assert_cmd`, like `tests/hook_io.rs`) and pin that
//! each path now exits 0 with a well-formed `ask` decision instead.
//!
//! Uses `tests/user_config.rs`'s env-isolation pattern (`SHGUARD_CONFIG`/
//! `XDG_CONFIG_HOME`/`HOME` all `env_remove`d on the child process) rather
//! than `tests/hook_io.rs`'s unisolated `run_hook`, so results here depend
//! only on the embedded rules, never on whatever config happens to exist
//! on the host machine running the test.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use serde_json::Value;

/// Runs the real binary against `stdin` with the environment fully reset,
/// mirroring `tests/user_config.rs`'s `run_hook`.
fn run_hook(stdin: &str) -> Value {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME");
    let assert = cmd.write_stdin(stdin).assert().success();
    let output = assert.get_output();
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
}

fn bash_command(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "hook_event_name": "PreToolUse",
    })
    .to_string()
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

// ==== B-1: raw {/}/(/) nesting depth cap ====

/// Before the fix: `rc=134` (`SIGABRT`), empty stdout — the crash happens
/// inside brush-parser's own PEG grammar, before shguard's AST or its
/// AST-level depth cap ever runs, so only a pre-parse raw scan can catch
/// it (`src/parser.rs::reject_excessive_raw_nesting`).
#[test]
fn deep_brace_nesting_fails_closed_to_ask_instead_of_aborting() {
    let command = format!("echo {}a{}", "{a,".repeat(8000), "}".repeat(8000));
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// Before the fix: `rc=134`, empty stdout, `fatal runtime error: stack
/// overflow` — confirmed to abort even though it never touches shguard's
/// own AST (brush-parser's `command_substitution` grammar recurses
/// unboundedly on its own). Only the `(`/`)` half of the raw scan catches
/// this; the `{`/`}` half alone would miss it entirely.
#[test]
fn deep_substitution_nesting_fails_closed_to_ask_instead_of_aborting() {
    let command = format!("{}echo hi{}", "$(".repeat(4000), ")".repeat(4000));
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// `${` is `$` followed by an ordinary `{` — the raw scan's `{` counter
/// catches this shape automatically, with no separate handling needed;
/// this test pins that the shared counter really does cover it.
#[test]
fn deep_parameter_expansion_nesting_fails_closed_to_ask() {
    let command = format!("{}a{}", "${".repeat(4000), "}".repeat(4000));
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// False-positive pin: ordinary, realistic brace nesting (2-3 levels) must
/// still resolve normally, not get caught by the new depth cap.
#[test]
fn brace_nesting_within_cap_still_allows() {
    let output = run_hook(&bash_command("echo {a,{b,{c,d}}}"));
    assert_eq!(permission_decision(&output), "allow");
}

/// False-positive pin for the `(` half of the raw cap: ordinary nested
/// command substitution, in argument position (rule 3 in `src/gate.rs`'s
/// module docs is Allow-transparent here), must still recurse and resolve
/// to `allow`, not get caught by the new depth cap.
#[test]
fn substitution_nesting_within_cap_still_recurses() {
    let output = run_hook(&bash_command("echo $(echo $(echo hi))"));
    assert_eq!(permission_decision(&output), "allow");
}

// ==== B-2: stdin size cap ====

/// Before the fix: stdin was read to completion with no bound at all.
/// `MAX_STDIN_BYTES` (`src/bin/shguard.rs`) is not importable from an
/// integration test (it is a private binary-crate constant, and
/// integration tests only see the library's public API per
/// `coding-guidelines/languages/rust.md`'s testing policy) — kept in sync
/// with that constant by inspection, not by a shared symbol.
#[test]
fn oversized_stdin_fails_closed_to_ask() {
    const MAX_STDIN_BYTES: usize = 10 * 1024 * 1024;
    let oversized_stdin = "a".repeat(MAX_STDIN_BYTES + 1);
    let output = run_hook(&oversized_stdin);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("exceeds"));
}

// ==== B-3: catch_unwind boundary ====

/// Before the fix: no `catch_unwind` boundary existed at all, so any panic
/// reached through the composition root would propagate past `main`
/// uncaught. `SHGUARD_TEST_PANIC` is a debug-only injection point
/// (`#[cfg(debug_assertions)]` in `src/bin/shguard.rs::run`) that exists
/// specifically so this fail-closed guarantee has a regression test, since
/// no naturally reachable panic in this binary is currently known.
///
/// The injection point is compiled out under `cargo test --release`
/// (`#[cfg(debug_assertions)]`), so `SHGUARD_TEST_PANIC` would be a no-op
/// there and `echo hi` would resolve to `allow`, not `ask` — `ignore`d
/// rather than asserted unconditionally so a release test run does not fail
/// on behavior this test was never meant to cover.
#[cfg_attr(
    not(debug_assertions),
    ignore = "SHGUARD_TEST_PANIC injection point is compiled out in release builds"
)]
#[test]
fn injected_panic_fails_closed_to_ask() {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_TEST_PANIC", "1")
        .write_stdin(bash_command("echo hi"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}
