//! The decision flow of hook mode. It is pure: `main` reads stdin, the
//! environment and the config, and writes the result.
//!
//! 1. A non-Bash tool gets no decision.
//! 2. If the config or catalog failed to load, every Bash call is denied
//!    with the first load error, whatever `ask_outcome` says.
//! 3. Input that is not the hook contract, an empty command and a command
//!    outside the parsed subset are Asks.
//! 4. Otherwise the kernel decides.
//! 5. Every Ask goes through `ask_outcome`; a Block is always a deny.
//!
//! The reasons say what was found. None of them says a command is safe.

use shguard_kernel::decide::{Verdict, decide};
use shguard_kernel::verdict::{Addr, Reason, UnknownKind};
use shguard_syntax::parse;

use crate::catalog::LoadError;
use crate::config::{AskOutcome, Settings};
use crate::hook::{Request, Response, parse_request, render};
use serde_json::Value;

/// The most stdin the hook reads. More is malformed.
pub const INPUT_CAP: usize = 1024 * 1024;

/// What the flow concluded before `ask_outcome` is applied.
enum Judged {
    Allow(String),
    Ask(String),
    Deny(String),
}

/// The hook output for one stdin.
#[must_use]
pub fn respond(stdin: &[u8], settings: Result<&Settings, &[LoadError]>) -> Value {
    render(&answer(stdin, settings).1)
}

/// The Bash command of one stdin, if it had one, and the answer to it.
#[must_use]
pub fn answer(
    stdin: &[u8],
    settings: Result<&Settings, &[LoadError]>,
) -> (Option<String>, Response) {
    let request = if stdin.len() > INPUT_CAP {
        Request::Malformed("hook input is larger than 1 MiB")
    } else {
        parse_request(stdin)
    };
    let command = match &request {
        Request::Command(c) => Some(c.clone()),
        Request::NotBash | Request::Malformed(_) => None,
    };
    (command, response(request, settings))
}

fn response(request: Request, settings: Result<&Settings, &[LoadError]>) -> Response {
    if request == Request::NotBash {
        return Response::NoDecision;
    }
    let settings = match settings {
        Ok(s) => s,
        Err(errs) => return Response::Deny(load_reason(errs)),
    };
    let judged = match request {
        Request::NotBash => return Response::NoDecision,
        Request::Malformed(why) => Judged::Ask(why.to_owned()),
        Request::Command(command) => judge(&command, settings),
    };
    match judged {
        Judged::Allow(r) => Response::Allow(r),
        Judged::Deny(r) => Response::Deny(r),
        Judged::Ask(r) => match settings.ask_outcome {
            AskOutcome::Ask => Response::Ask(r),
            AskOutcome::Deny => Response::Deny(format!("{r} (ask_outcome = deny)")),
        },
    }
}

fn load_reason(errs: &[LoadError]) -> String {
    let more = match errs.len() {
        0 | 1 => String::new(),
        n => format!(" (+{} more)", n - 1),
    };
    match errs.first() {
        // The TOML error would echo config lines into the model's context.
        Some(LoadError::Toml { file, .. }) => {
            format!(
                "shguard cannot load its config or catalog: {file}: invalid TOML or schema{more}"
            )
        }
        Some(first) => format!("shguard cannot load its config or catalog: {first}{more}"),
        None => "shguard cannot load its config or catalog".to_owned(),
    }
}

fn judge(command: &str, settings: &Settings) -> Judged {
    if command.trim().is_empty() {
        return Judged::Ask("the command is empty".to_owned());
    }
    let script = match parse(command.as_bytes()) {
        Ok(s) => s,
        Err(u) => return Judged::Ask(format!("outside the supported subset: {u}")),
    };
    let loaded = &settings.loaded;
    match decide(&loaded.catalog, &loaded.rules, script) {
        Verdict::Allow(_) => Judged::Allow("covered by the catalog; no rule hit".to_owned()),
        Verdict::Ask(_, reason) => Judged::Ask(reason_text(&reason, &loaded.rule_ids)),
        Verdict::Block(_, reason) => Judged::Deny(reason_text(&reason, &loaded.rule_ids)),
    }
}

fn reason_text(reason: &Reason, rule_ids: &[String]) -> String {
    match reason {
        Reason::Unknown(kind, addr) => format!("{} ({})", unknown(*kind), addr_text(*addr)),
        Reason::Rule(id, addr) => {
            let name = usize::try_from(id.0)
                .ok()
                .and_then(|i| rule_ids.get(i))
                .map_or_else(|| format!("#{}", id.0), Clone::clone);
            format!("rule `{name}` hit ({})", addr_text(*addr))
        }
    }
}

fn addr_text(a: Addr) -> String {
    let base = format!("item {}, link {}, cmd {}", a.item, a.link, a.cmd);
    match a.word {
        Some(w) => format!("{base}, word {w}"),
        None => base,
    }
}

fn unknown(kind: UnknownKind) -> &'static str {
    match kind {
        UnknownKind::NoRow => "no catalog row matches the command",
        UnknownKind::OpaqueCommandName => "the command name is not a literal",
        UnknownKind::UnknownOption => "an option the catalog row does not list",
        UnknownKind::OpaqueOption => "an option position holds a non-literal word",
        UnknownKind::MissingValue => "an option that takes a value has none",
        UnknownKind::FlagGivenValue => "a flag was given a value",
        UnknownKind::DashDashNotAllowed => "`--` in option position is not allowed here",
        UnknownKind::ExtraOperand => "an operand beyond what the catalog row allows",
        UnknownKind::OptionAfterOperand => "a word after an operand might be an option",
        UnknownKind::PlusWord => "a `+` word in option position",
        UnknownKind::CodeRole => "a position whose value is code",
        UnknownKind::RunsCode => "the catalog row marks the command as running other code",
        UnknownKind::UnknownSubcommand => "a subcommand the catalog does not list",
        UnknownKind::PathOpaque => "a path word that cannot be compared with rule targets",
        UnknownKind::PathDotDot => "a path with a `..` segment",
        UnknownKind::PathNonAscii => "a path with a non-ASCII byte",
        UnknownKind::PathAfterCd => "a relative path after a command that changes directory",
        UnknownKind::SensitiveAfterCd => {
            "a command that reads its directory's configuration, after a command that changes directory"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Source;
    use crate::config::settings;

    const CATALOG: &str = r#"
[[row]]
key = ["ls"]
source = "https://example.com"
order = "permute"
dashdash = "ends"
rest = "path"
[[row.opt]]
short = "l"
[[row.opt]]
short = "a"
"#;

    fn bash(cmd: &str) -> Vec<u8> {
        let v = serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": cmd } });
        v.to_string().into_bytes()
    }

    fn decision(v: &Value) -> Option<&str> {
        v["hookSpecificOutput"]["permissionDecision"].as_str()
    }

    fn with(ask: &str) -> Settings {
        let embedded = [Source {
            name: "t.toml",
            text: CATALOG,
        }];
        let cfg = format!("ask_outcome = \"{ask}\"\n");
        match settings(&embedded, Some(("c.toml", &cfg))) {
            Ok(s) => s,
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn flow() {
        let deny = with("deny");
        let ask = with("ask");
        let d = |s: &Settings, input: &[u8]| respond(input, Ok(s));
        assert_eq!(decision(&d(&deny, &bash("ls -la"))), Some("allow"));
        assert_eq!(decision(&d(&ask, &bash("ls -la"))), Some("allow"));
        for cmd in ["", "  \n", "echo $(id)", "uname"] {
            assert_eq!(decision(&d(&deny, &bash(cmd))), Some("deny"), "{cmd:?}");
            assert_eq!(decision(&d(&ask, &bash(cmd))), Some("ask"), "{cmd:?}");
        }
        let other = br#"{"tool_name":"Read"}"#;
        assert_eq!(decision(&d(&deny, other)), None);
    }

    #[test]
    fn load_failure_denies_bash_only() {
        let errs = [LoadError::OptionLikeKey {
            file: "f".to_owned(),
            item: "row `x`".to_owned(),
        }];
        let v = respond(&bash("ls"), Err(&errs));
        assert_eq!(decision(&v), Some("deny"));
        assert_eq!(decision(&respond(b"junk", Err(&errs))), Some("deny"));
        assert_eq!(
            decision(&respond(br#"{"tool_name":"Read"}"#, Err(&errs))),
            None
        );
    }

    #[test]
    fn oversized_input_is_malformed() {
        let ask = with("ask");
        let mut big = bash("ls");
        big.resize(INPUT_CAP + 1, b' ');
        assert_eq!(decision(&respond(&big, Ok(&ask))), Some("ask"));
    }
}
