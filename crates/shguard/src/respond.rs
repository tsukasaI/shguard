//! The decision flow of hook mode. It is pure: `main` reads stdin, the
//! environment and the config, and writes the result.
//!
//! 1. A non-Bash tool gets no decision.
//! 2. If the config or catalog failed to load, every Bash call is denied
//!    with the first load error, whatever `ask_outcome` says.
//! 3. Input that is not the hook contract, an empty command and a command
//!    outside the parsed subset are Asks.
//! 4. Otherwise the kernel decides. An Allow that the embedded catalog alone
//!    would not give (it needs a user `[[row]]`) says so in its reason.
//! 5. Every Ask goes through `ask_outcome`; a Block is always a deny.
//!
//! The reasons say what was found. None of them says a command is safe, and
//! none holds bytes of the command: a rule's `reason` and a hint's `text`
//! come from the catalog files.

use shguard_kernel::ast::{Part, Script};
use shguard_kernel::decide::{Verdict, decide};
use shguard_kernel::verdict::{Addr, Reason, UnknownKind, simple_at};
use shguard_syntax::parse;

use crate::catalog::{GuidanceText, Hint, LoadError, Loaded};
use crate::config::{AskOutcome, Settings};
use crate::hook::{Request, Response, parse_request};

/// The most stdin the hook reads. More is malformed.
pub const INPUT_CAP: usize = 1024 * 1024;

/// Where the catalog coverage behind an Allow comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowKind {
    /// The embedded catalog covers the command.
    Catalog,
    /// The embedded catalog alone would not Allow the command; a user `[[row]]`
    /// covers it.
    UserRow,
}

impl AllowKind {
    fn reason(self) -> &'static str {
        match self {
            Self::Catalog => "covered by the catalog; no rule hit",
            Self::UserRow => "covered by the catalog through a user [[row]]; no rule hit",
        }
    }
}

/// What the flow concluded before `ask_outcome` is applied.
enum Judged {
    Allow(AllowKind),
    Ask(String),
    Deny(String),
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
    match (request, settings) {
        (Request::NotBash, Ok(_) | Err(_)) => Response::NoDecision,
        (Request::Malformed(_) | Request::Command(_), Err(errs)) => {
            Response::Deny(load_reason(errs))
        }
        (Request::Malformed(why), Ok(s)) => settle(Judged::Ask(why.to_owned()), s),
        (Request::Command(command), Ok(s)) => settle(judge(&command, s), s),
    }
}

fn settle(judged: Judged, settings: &Settings) -> Response {
    match judged {
        Judged::Allow(kind) => Response::Allow(kind.reason().to_owned()),
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
                "shguard cannot load its config or catalog: {file:?}: invalid TOML or schema{more}"
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
    // `decide` consumes the script, and `Allowed` exposes none back, so the
    // copy for the embedded-only decision is taken before it; only a config
    // with a `[[row]]` pays for it.
    let for_embedded = settings.embedded_only.as_ref().map(|e| (e, script.clone()));
    match decide(&loaded.catalog, &loaded.rules, script) {
        Verdict::Allow(_) => Judged::Allow(allow_kind(for_embedded)),
        Verdict::Ask(script, reason) => Judged::Ask(reason_text(&reason, &script, loaded)),
        Verdict::Block(script, reason) => Judged::Deny(reason_text(&reason, &script, loaded)),
    }
}

/// Whether the embedded catalog alone would Allow the script too. `None` means
/// the config adds no `[[row]]` (`Settings::embedded_only`), so no user row can
/// have made the Allow.
fn allow_kind(for_embedded: Option<(&Loaded, Script)>) -> AllowKind {
    let Some((embedded, script)) = for_embedded else {
        return AllowKind::Catalog;
    };
    let embedded_allows = matches!(
        decide(&embedded.catalog, &embedded.rules, script),
        Verdict::Allow(_)
    );
    if embedded_allows {
        AllowKind::Catalog
    } else {
        AllowKind::UserRow
    }
}

/// The reason for a verdict, with its guidance text appended.
fn reason_text(reason: &Reason, script: &Script, loaded: &Loaded) -> String {
    let base = match reason {
        Reason::Unknown(kind, addr) => format!("{} ({})", unknown(*kind), addr_text(*addr)),
        Reason::Rule(id, addr) => {
            let name = usize::try_from(id.0)
                .ok()
                .and_then(|i| loaded.rule_ids.get(i))
                .map_or_else(|| format!("#{}", id.0), Clone::clone);
            format!("rule `{name}` hit ({})", addr_text(*addr))
        }
    };
    match guidance(reason, script, loaded) {
        Some(text) => format!("{base}; {text}"),
        None => base,
    }
}

/// The text a catalog file attaches to a verdict's reason: the hit rule's
/// `reason`, or the hint for an Unknown command's key. It comes from the
/// catalog files, never from the command.
fn guidance<'a>(reason: &Reason, script: &Script, loaded: &'a Loaded) -> Option<&'a str> {
    match reason {
        Reason::Unknown(_, addr) => hint_for(script, *addr, &loaded.hints),
        Reason::Rule(id, _) => usize::try_from(id.0)
            .ok()
            .and_then(|i| loaded.rule_reasons.get(i))
            .and_then(|r| r.as_ref().map(GuidanceText::as_str)),
    }
}

/// The text of the hint with the longest key that the command at `addr`
/// starts with. Only the literal words at the start of the command are
/// compared; the first word with an opaque part ends the comparison.
fn hint_for<'a>(script: &Script, addr: Addr, hints: &'a [Hint]) -> Option<&'a str> {
    // Verdict addresses are always `valid_addr`, so simple_at's extra word bound never drops a hint.
    let simple = simple_at(script, addr)?;
    let mut words: Vec<Vec<u8>> = Vec::new();
    for w in simple.words() {
        let mut bytes = Vec::new();
        for part in w.parts() {
            match part {
                Part::Lit(b) => bytes.extend_from_slice(b),
                Part::Opaque(_) => return longest(&words, hints),
            }
        }
        words.push(bytes);
    }
    longest(&words, hints)
}

fn longest<'a>(words: &[Vec<u8>], hints: &'a [Hint]) -> Option<&'a str> {
    hints
        .iter()
        .filter(|h| words.starts_with(&h.key))
        .max_by_key(|h| h.key.len())
        .map(|h| h.text.as_str())
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
    use crate::catalog::{Origin, Source};
    use crate::config::settings;
    use crate::hook::render;
    use serde_json::Value;

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

    fn respond(stdin: &[u8], settings: Result<&Settings, &[LoadError]>) -> Value {
        render(&answer(stdin, settings).1)
    }

    fn bash(cmd: &str) -> Vec<u8> {
        let v = serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": cmd } });
        v.to_string().into_bytes()
    }

    fn decision(v: &Value) -> Option<&str> {
        v["hookSpecificOutput"]["permissionDecision"].as_str()
    }

    fn with(ask: &str) -> Settings {
        let embedded = [Source {
            origin: Origin::Embedded,
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
        assert_eq!(decision(&d(&deny, b"junk")), Some("deny"));
        assert_eq!(decision(&d(&ask, b"junk")), Some("ask"));
    }

    fn reason(v: &Value) -> &str {
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
    }

    #[test]
    fn rule_reasons_and_hints_change_only_the_text() {
        let embedded = [Source {
            origin: Origin::Embedded,
            name: "t.toml",
            text: CATALOG,
        }];
        let rules =
            "[[rule]]\nid = \"ls-a\"\nkey = [\"ls\"]\nopts = [[\"-a\"]]\noutcome = \"ask\"\n";
        let plain = match settings(&embedded, Some(("c.toml", rules))) {
            Ok(s) => s,
            Err(e) => panic!("{e:?}"),
        };
        let cfg = format!(
            "{rules}reason = \"hidden files; list them by name\"\n\
             [[hint]]\nkey = [\"find\"]\ntext = \"use fd or rg --files\"\n\
             [[hint]]\nkey = [\"git\"]\ntext = \"git hint\"\n\
             [[hint]]\nkey = [\"git\", \"checkout\"]\ntext = \"use git switch\"\n"
        );
        let with = match settings(&embedded, Some(("c.toml", &cfg))) {
            Ok(s) => s,
            Err(e) => panic!("{e:?}"),
        };
        for cmd in [
            "ls -a",
            "ls -l",
            "find . -name x",
            "git checkout main",
            "git status",
            "ls && find .",
            "\"${X}\" checkout",
        ] {
            let a = respond(&bash(cmd), Ok(&plain));
            let b = respond(&bash(cmd), Ok(&with));
            assert_eq!(decision(&a), decision(&b), "{cmd}");
        }
        // The guidance each command gets, read without the wording around it.
        let g = |cmd: &str| -> Option<String> {
            let script = parse(cmd.as_bytes()).ok()?;
            let l = &with.loaded;
            match decide(&l.catalog, &l.rules, script) {
                Verdict::Allow(_) => None,
                Verdict::Ask(sc, r) | Verdict::Block(sc, r) => {
                    guidance(&r, &sc, l).map(str::to_owned)
                }
            }
        };
        let some = |t: &str| Some(t.to_owned());
        assert_eq!(g("ls -a"), some("hidden files; list them by name"));
        assert_eq!(g("find . -name x"), some("use fd or rg --files"));
        assert_eq!(g("ls && find ."), some("use fd or rg --files"));
        // The longest key wins.
        assert_eq!(g("git checkout main"), some("use git switch"));
        assert_eq!(g("git status"), some("git hint"));
        assert_eq!(g("uname"), None);
        // An opaque word ends the key comparison.
        assert_eq!(g("\"${X}\" checkout"), None);
        assert_eq!(g("ls -l"), None);
        // The hook reason carries the text.
        let r = |cmd: &str| reason(&respond(&bash(cmd), Ok(&with))).to_owned();
        assert!(r("find . -name x").contains("use fd or rg --files"));
    }

    fn allow_reason_for(cfg: &str, cmd: &str) -> (String, Value) {
        let embedded = [Source {
            origin: Origin::Embedded,
            name: "t.toml",
            text: CATALOG,
        }];
        let s = match settings(&embedded, Some(("c.toml", cfg))) {
            Ok(s) => s,
            Err(e) => panic!("{e:?}"),
        };
        let (command, response) = answer(&bash(cmd), Ok(&s));
        assert_eq!(decision(&render(&response)), Some("allow"), "{cmd}");
        let line = crate::decision_log::entry(1, command.as_deref(), &response);
        (
            reason(&render(&response)).to_owned(),
            line.unwrap_or_default(),
        )
    }

    #[test]
    fn an_allow_that_needs_a_user_row_says_so() {
        let user_row = "[[row]]\nkey = [\"uname\"]\nsource = \"https://example.com\"\n\
                        order = \"permute\"\ndashdash = \"ends\"\n";
        let (user, logged) = allow_reason_for(user_row, "uname");
        assert_eq!(user, AllowKind::UserRow.reason());
        assert_eq!(logged["reason"], AllowKind::UserRow.reason());
        // The embedded catalog already Allows `ls`, with or without a user row.
        let (embedded, _) = allow_reason_for(user_row, "ls -l");
        assert_eq!(embedded, AllowKind::Catalog.reason());
        let (none, _) = allow_reason_for("", "ls -l");
        assert_eq!(none, AllowKind::Catalog.reason());
        assert_ne!(AllowKind::UserRow.reason(), AllowKind::Catalog.reason());
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
