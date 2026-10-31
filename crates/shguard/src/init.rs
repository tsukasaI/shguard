//! `shguard init`: the config file it writes and the Claude Code settings
//! snippet it prints. `main` does the file system work.

use serde_json::{Value, json};

/// The config `shguard init` writes. Asks reach the user instead of being
/// refused, and the decision log stays off.
pub const CONFIG_TEXT: &str = r#"# shguard config. See the README for the full schema.

# What an Ask becomes: "ask" lets Claude Code ask you, "deny" refuses it
# (the default when this line is missing, for sessions nobody watches).
ask_outcome = "ask"

# Append one JSON line per Bash decision to this absolute path. Each line
# holds the command text, so the file can hold secrets typed on a command
# line. Off unless set.
# decision_log = "/home/you/.local/state/shguard/decisions.jsonl"

# Rows widen what can be allowed; rules only raise a decision. Both use the
# catalog schema (catalog/*.toml in the shguard repository).
# [[rule]]
# id = "ask-every-rm"
# key = ["rm"]
# outcome = "ask"
"#;

/// The `hooks` entry for Claude Code's settings.json that runs `exe` before
/// every Bash call. `onFailure = "block"` makes a crash, a timeout or an
/// exit status other than 0 and 2 refuse the call; without it Claude Code
/// runs the tool.
#[must_use]
pub fn settings_snippet(exe: &str) -> Value {
    json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": exe,
                            "onFailure": "block",
                        }
                    ]
                }
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AskOutcome, settings};

    #[test]
    fn config_text_loads_with_ask_outcome_ask() {
        let Ok(s) = settings(&[], Some(("init", CONFIG_TEXT))) else {
            panic!("the init config does not load");
        };
        assert_eq!(s.ask_outcome, AskOutcome::Ask);
        assert_eq!(s.decision_log, None);
    }

    #[test]
    fn snippet_blocks_on_failure() {
        let v = settings_snippet("/usr/local/bin/shguard");
        let hook = &v["hooks"]["PreToolUse"][0];
        assert_eq!(hook["matcher"], "Bash");
        assert_eq!(hook["hooks"][0]["type"], "command");
        assert_eq!(hook["hooks"][0]["command"], "/usr/local/bin/shguard");
        assert_eq!(hook["hooks"][0]["onFailure"], "block");
    }
}
