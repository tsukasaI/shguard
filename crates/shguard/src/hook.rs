//! The hook wire format: the `PreToolUse` input we read and the output we
//! write. Nothing here decides anything.
//!
//! Fields of the legacy (v0.9.5) adapter that are not carried over:
//!
//! - `cwd`: the kernel has no cwd input, so M14 rule targets must be
//!   absolute or start with `~`.
//! - `permission_mode`.
//! - The `agent_id` override of `ask_outcome` for subagents (#469).
//!
//! M16 may revive them.

use serde_json::{Value, json};

/// What the hook input asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// A tool other than Bash. The hook gives no decision for it.
    NotBash,
    /// A Bash call and its command.
    Command(String),
    /// The input is not what the hook contract promises. The text says why
    /// and never contains input bytes.
    Malformed(&'static str),
}

/// Reads the hook input. Only `tool_name` and, for Bash, `tool_input.command`
/// matter; every other field is ignored.
#[must_use]
pub fn parse_request(stdin: &[u8]) -> Request {
    let Ok(value) = serde_json::from_slice::<Value>(stdin) else {
        return Request::Malformed("hook input is not valid UTF-8 JSON");
    };
    let Some(tool) = value.get("tool_name").and_then(Value::as_str) else {
        return Request::Malformed("hook input has no string `tool_name`");
    };
    if tool != "Bash" {
        return Request::NotBash;
    }
    match value
        .get("tool_input")
        .and_then(|i| i.get("command"))
        .and_then(Value::as_str)
    {
        Some(command) => Request::Command(command.to_owned()),
        None => Request::Malformed("Bash call has no string `tool_input.command`"),
    }
}

/// What the hook tells Claude Code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// No decision: Claude Code carries on as if no hook were installed.
    NoDecision,
    /// Run without asking.
    Allow(String),
    /// Ask the user.
    Ask(String),
    /// Refuse.
    Deny(String),
}

/// The JSON object written to stdout.
#[must_use]
pub fn render(response: &Response) -> Value {
    let (decision, reason) = match response {
        Response::NoDecision => {
            return json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse" } });
        }
        Response::Allow(r) => ("allow", r),
        Response::Ask(r) => ("ask", r),
        Response::Deny(r) => ("deny", r),
    };
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
}

/// The bytes of a rendered response, newline-terminated. Serializing a
/// [`Value`] cannot fail; if it somehow did, the fixed deny is written.
#[must_use]
pub fn to_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_else(|_| FALLBACK_DENY.as_bytes().to_vec());
    bytes.push(b'\n');
    bytes
}

const FALLBACK_DENY: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"shguard: internal error"}}"#;

/// The output of the panic hook: a fixed deny, so a crash blocks the call
/// instead of failing open (a panic exits 101, which Claude Code treats as a
/// non-blocking error).
#[must_use]
pub fn panic_output() -> Vec<u8> {
    let mut bytes = FALLBACK_DENY.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(r: &Response) -> Option<String> {
        render(r)["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .map(str::to_owned)
    }

    #[test]
    fn parses_requests() {
        let bash = br#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/"}"#;
        assert_eq!(parse_request(bash), Request::Command("ls".to_owned()));
        assert_eq!(
            parse_request(br#"{"tool_name":"Read","tool_input":{}}"#),
            Request::NotBash
        );
        for bad in [
            &b""[..],
            b"not json",
            b"[]",
            b"{}",
            br#"{"tool_name":1}"#,
            br#"{"tool_name":"Bash"}"#,
            br#"{"tool_name":"Bash","tool_input":{"command":3}}"#,
            b"{\"tool_name\":\"\xff\"}",
        ] {
            assert!(
                matches!(parse_request(bad), Request::Malformed(_)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn renders_decisions() {
        assert_eq!(decision(&Response::NoDecision), None);
        assert_eq!(
            decision(&Response::Allow(String::new())).as_deref(),
            Some("allow")
        );
        assert_eq!(
            decision(&Response::Ask(String::new())).as_deref(),
            Some("ask")
        );
        assert_eq!(
            decision(&Response::Deny(String::new())).as_deref(),
            Some("deny")
        );
        let none = render(&Response::NoDecision);
        assert_eq!(none["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn panic_output_is_a_deny() {
        let Ok(v) = serde_json::from_slice::<Value>(&panic_output()) else {
            panic!("panic output is not JSON");
        };
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(panic_output().last(), Some(&b'\n'));
    }
}
