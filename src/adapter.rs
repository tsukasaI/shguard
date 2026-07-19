//! Claude Code PreToolUse hook adapter (issue #13, plan.md §1.2's "hook
//! adapter" contract) — the boundary between the Claude Code hook's
//! stdin→stdout JSON and [`crate::analyze`].
//!
//! This module owns every Claude-Code-specific field name (`tool_name`,
//! `tool_input.command`, `hookSpecificOutput`, …). The composition root
//! (`src/bin/shguard.rs`) calls only [`handle`]; nothing else in the crate
//! depends on this module, and this module never depends on anything in
//! `src/bin/`. A future Codex/Cursor adapter is a sibling module with its
//! own `handle`-shaped entry point, not a change here (plan.md's "dependencies
//! point inward").
//!
//! # Verified stdin/stdout schema
//!
//! Re-verified against code.claude.com/docs/en/hooks on 2026-07-19 (plan.md
//! §0.2's "adapter issue re-fetches the doc before implementation"):
//!
//! - **stdin**: a JSON object. `tool_name: string`; when `tool_name ==
//!   "Bash"`, `tool_input.command: string` holds the raw shell command
//!   line. Other context fields (`session_id`, `cwd`, `permission_mode`,
//!   `hook_event_name`) may be present and are ignored here.
//! - **stdout**: exit 0, plus
//!   ```json
//!   {
//!     "hookSpecificOutput": {
//!       "hookEventName": "PreToolUse",
//!       "permissionDecision": "allow" | "deny" | "ask",
//!       "permissionDecisionReason": "…"
//!     }
//!   }
//!   ```
//!   `permissionDecision` maps directly from [`crate::verdict::Decision`]:
//!   `Allow` → `"allow"`, `Ask` → `"ask"`, `Block` → `"deny"`.
//!
//! # Fail-closed posture
//!
//! - Malformed/missing stdin JSON, or a `tool_name == "Bash"` payload whose
//!   `tool_input.command` is missing or not a string → `ask`, with a
//!   reason describing what could not be read. Never a crash, never an
//!   undocumented silent allow.
//! - `tool_name != "Bash"` → `allow`: shguard only analyses shell commands
//!   run through the Bash tool, so a non-Bash tool call is out of scope by
//!   design — the hook defers to Claude Code's normal permission flow
//!   instead of asking on every non-shell tool call.

use serde::Deserialize;
use serde_json::Value;

use crate::verdict::Decision;

/// The subset of the Claude Code PreToolUse stdin payload shguard reads.
///
/// `tool_input` is kept as a raw [`Value`] rather than a nested struct: the
/// hook schema is fast-moving (plan.md §0.2), so only the `command` field
/// is pulled out, defensively, at the point of use instead of committing to
/// a rigid shape that could start failing to deserialize on a spec change.
#[derive(Debug, Deserialize)]
struct HookInput {
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
}

/// The three `permissionDecision` values the hook contract defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionDecision {
    Allow,
    Deny,
    Ask,
}

impl PermissionDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        }
    }
}

impl From<Decision> for PermissionDecision {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Ask => Self::Ask,
            Decision::Block => Self::Deny,
        }
    }
}

/// Builds the `hookSpecificOutput` JSON envelope for a decision + reason.
fn output_json(decision: PermissionDecision, reason: &str) -> Value {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.as_str(),
            "permissionDecisionReason": reason,
        }
    })
}

/// The fail-closed `ask` output, for I/O failures the composition root
/// encounters before it even has stdin text to hand to [`handle`] (e.g. a
/// stdin read error).
#[must_use]
pub fn fail_closed(reason: &str) -> Value {
    output_json(PermissionDecision::Ask, reason)
}

/// Reads and analyses one Claude Code PreToolUse stdin payload, returning
/// the `hookSpecificOutput` JSON the composition root writes to stdout.
///
/// Never panics: every error path (malformed JSON, missing fields, wrong
/// field types) folds to an `ask` decision with a descriptive reason — the
/// same "single fold point, never crash, never silently allow" posture
/// [`crate::analyze`] documents for its own internal failure modes.
#[must_use]
pub fn handle(stdin: &str) -> Value {
    let input: HookInput = match serde_json::from_str(stdin) {
        Ok(input) => input,
        Err(err) => {
            return fail_closed(&format!(
                "shguard: could not parse PreToolUse stdin as JSON: {err}"
            ));
        }
    };

    if input.tool_name != "Bash" {
        return output_json(
            PermissionDecision::Allow,
            "shguard only analyses commands run through the Bash tool",
        );
    }

    let Some(command) = input.tool_input.get("command").and_then(Value::as_str) else {
        return fail_closed("shguard: Bash tool_input is missing a string \"command\" field");
    };

    let verdict = crate::analyze(command);
    let decision = PermissionDecision::from(verdict.decision());
    let reason = verdict
        .reason()
        .map_or("shguard: command cleared all checks", |r| r.as_str());

    output_json(decision, reason)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn permission_decision(output: &Value) -> &str {
        output["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap()
    }

    fn permission_reason(output: &Value) -> &str {
        output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
    }

    #[test]
    fn bash_block_command_denies_with_reason() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "deny");
        assert!(!permission_reason(&output).is_empty());
    }

    #[test]
    fn bash_ask_command_asks() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn bash_allow_command_allows() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "allow");
    }

    #[test]
    fn malformed_json_fails_closed_to_ask() {
        let output = handle("not json");
        assert_eq!(permission_decision(&output), "ask");
        assert!(!permission_reason(&output).is_empty());
    }

    #[test]
    fn empty_stdin_fails_closed_to_ask() {
        let output = handle("");
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn non_bash_tool_allows() {
        let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "allow");
    }

    #[test]
    fn bash_missing_command_field_fails_closed_to_ask() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn bash_non_string_command_fails_closed_to_ask() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":42}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }
}
