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

// ==== B-1 follow-up: raw compound-command keyword nesting count ====
//
// The bracket counters above only catch `{`/`(` recursion. brush-parser's
// recursive-descent grammar recurses exactly as unboundedly on nested
// `if`/`while`/`until`/`for`/`case` compound commands — none of which
// involve a brace or paren at all — so each of these independently aborted
// (`rc=134`, empty stdout) before `reject_excessive_raw_nesting` grew a
// keyword counter (`src/ast.rs::MAX_KEYWORD_NESTING_COUNT`).

/// Before the fix: `rc=134`, empty stdout, `fatal runtime error: stack
/// overflow` (live-confirmed abort threshold: 448 levels on an 8MiB
/// main-thread stack).
#[test]
fn deep_if_nesting_fails_closed_to_ask_instead_of_aborting() {
    let command = format!(
        "{}echo hi{}",
        "if true; then ".repeat(2000),
        "; fi".repeat(2000)
    );
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// Before the fix: same abort (live-confirmed threshold: 401 levels, the
/// lowest of the five keywords measured — [`MAX_KEYWORD_NESTING_COUNT`]'s
/// margin is sized against this one).
#[test]
fn deep_case_nesting_fails_closed_to_ask_instead_of_aborting() {
    let command = format!(
        "{}echo hi{}",
        "case x in x) ".repeat(2000),
        ";; esac".repeat(2000)
    );
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// Before the fix: same abort (live-confirmed threshold: 420 levels).
#[test]
fn deep_for_nesting_fails_closed_to_ask_instead_of_aborting() {
    let command = format!(
        "{}echo hi{}",
        "for x in y; do ".repeat(2000),
        "; done".repeat(2000)
    );
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
}

/// Regression pin for why [`MAX_KEYWORD_NESTING_COUNT`] counts openers only
/// and never decrements on a closer word: `fi`/`done`/`esac` are ordinary,
/// valid arguments (`echo fi` resolves normally), so a counter that
/// decremented on those words could be driven back toward zero by
/// interleaving them as arguments inside input that still recurses past the
/// overflow threshold. This nests `if` far past the cap while injecting
/// `echo fi` at every level; it must still fail closed.
#[test]
fn keyword_nesting_is_not_defeated_by_closer_words_in_argument_position() {
    let command = format!(
        "{}echo done{}",
        "if true; then echo fi; ".repeat(2000),
        " fi".repeat(2000)
    );
    let output = run_hook(&bash_command(&command));
    assert_eq!(permission_decision(&output), "ask");
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

// ==== Evaluation watchdog ====

/// Before the fix: a heredoc operator (`<<`) with no delimiter word,
/// appearing inside a `$(` command substitution that is never closed,
/// drove brush-parser's tokenizer into an unbounded allocating loop —
/// neither a panic (`catch_unwind` above cannot help) nor a return
/// (`reject_excessive_raw_nesting`'s depth cap cannot help either, since
/// this input never exceeds it), so no decision was ever emitted and the
/// process ran until the OS killed it for memory exhaustion. Pins that the
/// real binary now exits 0 with a well-formed `ask` decision instead,
/// within the `EVALUATION_TIMEOUT`/`MEMORY_LIMIT_BYTES` budget
/// (`src/bin/shguard.rs`). Which of the two trips first for this repro is
/// allocation-rate-dependent — live-confirmed to be the memory bound in
/// both a debug build (well under a second) and a release build (~0.5s,
/// well under `EVALUATION_TIMEOUT`) on this machine, but that could differ
/// on a slower or more memory-constrained host, so this only asserts
/// fail-closed `ask` with *a* watchdog reason, not which one.
///
/// Inlines `run_hook` to add a child-process timeout: if *both* watchdog
/// bounds regress, this input reverts to an unbounded multi-GB/s
/// allocating hang, and without a bound the test would thrash and wait
/// for the OS to OOM-kill something rather than fail cleanly. 30s is
/// ~15x the 2s `EVALUATION_TIMEOUT`, so it can never fire on the passing
/// path.
#[test]
fn heredoc_inside_unterminated_command_substitution_fails_closed_to_ask() {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .timeout(std::time::Duration::from_secs(30))
        .write_stdin(bash_command("<<$( |] "))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(permission_decision(&output), "ask");
    let reason = permission_reason(&output);
    assert!(
        reason.contains("time budget") || reason.contains("memory budget"),
        "expected a watchdog fail-closed reason, got: {reason}"
    );
}

/// Dedicated regression pin for the memory-bound watchdog itself (follow-up
/// to the wall-clock-only watchdog above: a host or container with less
/// free memory than the runaway allocation can consume within
/// `EVALUATION_TIMEOUT` gets SIGKILLed before the wall-clock bound alone
/// ever fires). Uses `SHGUARD_TEST_MEM_LIMIT_MB` (debug-only, mirrors
/// `SHGUARD_TEST_PANIC`'s pattern) set to `1` MB — comfortably below any
/// process's baseline RSS — against an ordinary, otherwise-`allow`able
/// command, so the memory arm trips on the very first poll without this
/// test itself needing to allocate hundreds of MB to exercise it.
#[cfg_attr(
    not(debug_assertions),
    ignore = "SHGUARD_TEST_MEM_LIMIT_MB injection point is compiled out in release builds"
)]
#[test]
fn memory_budget_trip_fails_closed_to_ask() {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_TEST_MEM_LIMIT_MB", "1")
        .write_stdin(bash_command("echo hi"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("memory budget"));
}
