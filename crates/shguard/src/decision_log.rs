//! The opt-in decision log: one JSON object per Bash decision, written by
//! `main` as one line appended to the file `decision_log` names.
//!
//! A line holds the command text as the hook received it, so the file can
//! hold secrets that were typed on a command line. It records what shguard
//! answered; it says nothing about whether a command is harmless.

use serde_json::{Value, json};

use crate::hook::Response;

/// The log line for one answer, or `None` when there is nothing to log
/// (a non-Bash tool gets no decision). `unix_secs` is the time of the
/// answer; `command` is the Bash command, if the input had one.
#[must_use]
pub fn entry(unix_secs: u64, command: Option<&str>, response: &Response) -> Option<Value> {
    let (decision, reason) = match response {
        Response::NoDecision => return None,
        Response::Allow(r) => ("allow", r),
        Response::Ask(r) => ("ask", r),
        Response::Deny(r) => ("deny", r),
    };
    Some(json!({
        "ts": unix_secs,
        "decision": decision,
        "reason": reason,
        "command": command,
    }))
}

/// The bytes of one log line, newline-terminated. Serializing a [`Value`]
/// cannot fail; if it somehow did, the line is dropped.
#[must_use]
pub fn line(entry: &Value) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec(entry).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        assert_eq!(entry(1, Some("ls"), &Response::NoDecision), None);
        let Some(e) = entry(7, Some("ls -l"), &Response::Allow("r".to_owned())) else {
            panic!("an Allow is logged");
        };
        assert_eq!(e["ts"], 7);
        assert_eq!(e["decision"], "allow");
        assert_eq!(e["reason"], "r");
        assert_eq!(e["command"], "ls -l");
        let Some(e) = entry(7, None, &Response::Ask("bad".to_owned())) else {
            panic!("an Ask is logged");
        };
        assert_eq!(e["decision"], "ask");
        assert!(e["command"].is_null());
        let Some(e) = entry(7, Some("rm -rf /"), &Response::Deny("no".to_owned())) else {
            panic!("a Deny is logged");
        };
        assert_eq!(e["decision"], "deny");
    }

    #[test]
    fn a_line_is_one_json_object() {
        let Some(e) = entry(1, Some("echo 'a\nb'"), &Response::Allow(String::new())) else {
            panic!("logged");
        };
        let Some(bytes) = line(&e) else {
            panic!("serializes");
        };
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
    }
}
