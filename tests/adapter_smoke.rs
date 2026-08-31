//! Adapter-layer smoke test (issue #106): `tests/guardfall.rs` already
//! proves the decision core's behavior via `shguard::analyze()` directly,
//! independent of any hook adapter — but that alone doesn't guarantee an
//! adapter's own stdin-JSON parsing/translation layer actually extracts
//! the right command and reaches the same decision. This test closes that
//! loop: for each hook TARGET (Claude Code today; a Codex/Cursor adapter
//! once one lands), it builds that target's own hook-input JSON shape for
//! a representative command, runs it through the target's own `handle`
//! entry point, and asserts the resulting decision matches
//! `shguard::analyze()`'s decision for the same bare command string.
//!
//! Adding a second target is one more `Target` entry in [`TARGETS`], not a
//! new test function or file (the issue's own acceptance criterion) —
//! including a target whose own output schema/decision-string mapping
//! differs from Claude Code's, since both live on the `Target` itself
//! (`extract_decision`/`expected_decision_str`), not hardcoded in the test
//! body.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shguard::verdict::Decision;

/// One hook target's shape: a name (for failure messages), a function
/// building that target's own stdin-JSON payload from a bare command
/// string, that target's own `handle`-shaped entry point, a function
/// pulling the decision string back out of that target's own output
/// shape, and a mapping from `Decision` to that same target's own
/// decision-string spelling — kept per-target (not assumed global)
/// since a future adapter is free to use different field names/values.
struct Target {
    name: &'static str,
    build_payload: fn(command: &str) -> String,
    handle: fn(stdin: &str) -> serde_json::Value,
    extract_decision: fn(output: &serde_json::Value) -> Option<&str>,
    expected_decision_str: fn(decision: Decision) -> &'static str,
}

fn claude_code_payload(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

fn claude_code_extract_decision(output: &serde_json::Value) -> Option<&str> {
    output["hookSpecificOutput"]["permissionDecision"].as_str()
}

/// `shguard::verdict::Decision` as the `permissionDecision` string
/// Claude Code's own adapter contract emits (`src/adapter.rs`'s own
/// verified-schema doc: Allow -> "allow", Ask -> "ask", Block -> "deny").
fn claude_code_expected_decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Block => "deny",
    }
}

/// Every target this test currently covers. A future Codex adapter
/// (issue #106's own sibling RFC) extends this list with one more entry
/// — its own payload shape, `handle` fn, decision extractor, and decision-
/// string mapping — not a rewrite of the test logic below.
const TARGETS: &[Target] = &[Target {
    name: "claude_code",
    build_payload: claude_code_payload,
    handle: shguard::adapter::handle,
    extract_decision: claude_code_extract_decision,
    expected_decision_str: claude_code_expected_decision_str,
}];

#[test]
fn every_target_adapter_matches_analyze_for_representative_commands() {
    assert!(!TARGETS.is_empty(), "TARGETS must not be empty");

    // A representative slice, not the full guardfall table: this test's
    // job is proving the ADAPTER LAYER doesn't lose or misroute the
    // command on the way to `analyze()`, not re-covering the decision
    // core's own regression suite (`tests/guardfall.rs`) — one command
    // per decision outcome is enough to catch a broken extraction path.
    let commands: &[&str] = &[
        "rm -rf /",                 // Block
        "$(echo x)",                // Ask
        "echo hello",               // Allow
        "rm$IFS-rf$IFS/",           // Block via $IFS splitting
        "git commit -m 'rm -rf /'", // Allow (quoted, not executed)
    ];

    for target in TARGETS {
        for command in commands {
            let expected = (target.expected_decision_str)(shguard::analyze(command).decision());
            let payload = (target.build_payload)(command);
            let output = (target.handle)(&payload);
            let actual = (target.extract_decision)(&output).unwrap_or_else(|| {
                panic!(
                    "target {:?}, command {command:?}: missing decision in {output}",
                    target.name
                )
            });
            assert_eq!(
                actual, expected,
                "target {:?}, command {command:?}: adapter said {actual:?}, \
                 analyze() said {expected:?}",
                target.name
            );
        }
    }
}
