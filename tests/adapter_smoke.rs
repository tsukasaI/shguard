//! Adapter-layer smoke test (issue #106): `tests/guardfall.rs` already
//! proves the decision core's behavior via `shguard::analyze()` directly,
//! independent of any hook adapter — but that alone doesn't guarantee an
//! adapter's own stdin-JSON parsing/translation layer actually extracts
//! the right command and reaches the same decision. This test closes that
//! loop: for each hook TARGET (Claude Code today; a Codex/Cursor adapter
//! once one lands), it builds that target's own hook-input JSON shape for
//! a representative command, runs it through the target's own `handle`
//! entry point, and asserts the resulting `permissionDecision` matches
//! `shguard::analyze()`'s decision for the same bare command string.
//!
//! Adding a second target is one more `Target` entry in [`TARGETS`], not a
//! new test function or file (the issue's own acceptance criterion).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shguard::verdict::Decision;

/// One hook target's shape: a name (for failure messages) and a function
/// building that target's own stdin-JSON payload from a bare command
/// string, paired with that target's own `handle`-shaped entry point.
struct Target {
    name: &'static str,
    build_payload: fn(command: &str) -> String,
    handle: fn(stdin: &str) -> serde_json::Value,
}

fn claude_code_payload(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// Every target this test currently covers. A future Codex adapter
/// (issue #106's own sibling RFC) extends this list with one more entry
/// — its own payload shape and its own module's `handle` function — not a
/// rewrite of the test logic below.
const TARGETS: &[Target] = &[Target {
    name: "claude_code",
    build_payload: claude_code_payload,
    handle: shguard::adapter::handle,
}];

/// `shguard::verdict::Decision` as the `permissionDecision` string every
/// adapter's own stdout contract emits (`src/adapter.rs`'s own verified-
/// schema doc: Allow -> "allow", Ask -> "ask", Block -> "deny").
fn expected_permission_decision(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Block => "deny",
    }
}

#[test]
fn every_target_adapter_matches_analyze_for_representative_commands() {
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
            let expected = expected_permission_decision(shguard::analyze(command).decision());
            let payload = (target.build_payload)(command);
            let output = (target.handle)(&payload);
            let actual = output["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "target {:?}, command {command:?}: missing permissionDecision in {output}",
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

/// Same property, but for `handle_with_policy` — the config-aware sibling
/// every target's own composition root actually calls in production
/// (`handle` alone is the embedded-only path `tests/hook_io.rs` already
/// covers at the binary level for Claude Code specifically).
#[test]
fn claude_code_handle_with_policy_matches_analyze_with_policy() {
    let policy = shguard::config::Policy::load().expect("embedded-only policy should load");
    let commands: &[&str] = &["rm -rf /", "$(echo x)", "echo hello"];

    for command in commands {
        let expected =
            expected_permission_decision(shguard::analyze_with_policy(command, &policy).decision());
        let payload = claude_code_payload(command);
        let output = shguard::adapter::handle_with_policy(&payload, &policy);
        let actual = output["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap();
        assert_eq!(
            actual, expected,
            "command {command:?}: handle_with_policy said {actual:?}, \
             analyze_with_policy() said {expected:?}"
        );
    }
}
