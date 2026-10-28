use super::parse;
use crate::lex::tests::interesting_bytes;
use crate::{Unsupported, UnsupportedKind as K};
use proptest::prelude::*;
use shguard_kernel::ast::{
    AndOr, Connector, Link, Opaque, Part, Pipeline, Redir, Script, Simple, Word,
};

fn lit(s: &str) -> Part {
    Part::Lit(s.as_bytes().to_vec())
}

fn w(parts: Vec<Part>) -> Word {
    Word::new(parts).unwrap()
}

fn bare(s: &str) -> Word {
    w(vec![lit(s)])
}

fn cmd(words: &[&str]) -> Simple {
    cmd_r(words, Vec::new())
}

fn cmd_r(words: &[&str], redirs: Vec<Redir>) -> Simple {
    Simple::new(words.iter().map(|s| bare(s)).collect(), redirs).unwrap()
}

fn pipe(cmds: Vec<Simple>) -> Pipeline {
    Pipeline::new(cmds).unwrap()
}

fn one(c: Simple) -> Pipeline {
    pipe(vec![c])
}

fn and_or(first: Pipeline, rest: Vec<(Connector, Pipeline)>) -> AndOr {
    AndOr::new(
        first,
        rest.into_iter().map(|(op, p)| Link::new(op, p)).collect(),
    )
}

fn single(c: Simple) -> AndOr {
    and_or(one(c), Vec::new())
}

fn script(items: Vec<AndOr>) -> Script {
    Script::new(items)
}

fn err(input: &str) -> (K, usize) {
    let Unsupported { kind, offset } = parse(input.as_bytes()).unwrap_err();
    (kind, offset)
}

#[test]
fn accepted_inputs() {
    use Connector::{And, Or};
    let cases: Vec<(&str, Script)> = vec![
        ("", script(vec![])),
        ("\n\n", script(vec![])),
        ("  \t\n ", script(vec![])),
        ("ls -la", script(vec![single(cmd(&["ls", "-la"]))])),
        (
            "git log --oneline | head -5",
            script(vec![and_or(
                pipe(vec![
                    cmd(&["git", "log", "--oneline"]),
                    cmd(&["head", "-5"]),
                ]),
                vec![],
            )]),
        ),
        (
            "a && b || c; d",
            script(vec![
                and_or(
                    one(cmd(&["a"])),
                    vec![(And, one(cmd(&["b"]))), (Or, one(cmd(&["c"])))],
                ),
                single(cmd(&["d"])),
            ]),
        ),
        (
            "a; b",
            script(vec![single(cmd(&["a"])), single(cmd(&["b"]))]),
        ),
        (
            "a\n\nb",
            script(vec![single(cmd(&["a"])), single(cmd(&["b"]))]),
        ),
        ("\n\na\n", script(vec![single(cmd(&["a"]))])),
        ("a;", script(vec![single(cmd(&["a"]))])),
        ("a;\n", script(vec![single(cmd(&["a"]))])),
        (
            "a;\n\n b",
            script(vec![single(cmd(&["a"])), single(cmd(&["b"]))]),
        ),
        (
            "a &&\n b",
            script(vec![and_or(
                one(cmd(&["a"])),
                vec![(And, one(cmd(&["b"])))],
            )]),
        ),
        (
            "a ||\n\n b",
            script(vec![and_or(one(cmd(&["a"])), vec![(Or, one(cmd(&["b"])))])]),
        ),
        (
            "a |\n b",
            script(vec![single_pipe(vec![cmd(&["a"]), cmd(&["b"])])]),
        ),
        (
            "cmd 2>&1 >/dev/null",
            script(vec![single(cmd_r(
                &["cmd"],
                vec![Redir::Dup { from: 2, to: 1 }, Redir::DevNull { fd: 1 }],
            ))]),
        ),
        (
            "cmd >/dev/null 2>&1",
            script(vec![single(cmd_r(
                &["cmd"],
                vec![Redir::DevNull { fd: 1 }, Redir::Dup { from: 2, to: 1 }],
            ))]),
        ),
        (
            ">/dev/null cmd",
            script(vec![single(cmd_r(
                &["cmd"],
                vec![Redir::DevNull { fd: 1 }],
            ))]),
        ),
        (
            "echo >&2 hi",
            script(vec![single(cmd_r(
                &["echo", "hi"],
                vec![Redir::Dup { from: 1, to: 2 }],
            ))]),
        ),
        ("'FOO=1' cmd", script(vec![single(cmd(&["FOO=1", "cmd"]))])),
        ("'if' x", script(vec![single(cmd(&["if", "x"]))])),
        (r"\if x", split_if(vec![lit("i"), lit("f")])),
        (r#"i""f x"#, split_if(vec![lit("i"), lit(""), lit("f")])),
        ("echo if", script(vec![single(cmd(&["echo", "if"]))])),
        (
            "echo if done",
            script(vec![single(cmd(&["echo", "if", "done"]))]),
        ),
        ("env A=b", script(vec![single(cmd(&["env", "A=b"]))])),
        (
            r#"echo "$HOME" ~"#,
            script(vec![single(
                Simple::new(
                    vec![
                        bare("echo"),
                        w(vec![Part::Opaque(Opaque::Var(b"HOME".to_vec()))]),
                        w(vec![Part::Opaque(Opaque::Tilde)]),
                    ],
                    vec![],
                )
                .unwrap(),
            )]),
        ),
        (
            "~/bin/x a",
            script(vec![single(
                Simple::new(
                    vec![
                        w(vec![Part::Opaque(Opaque::Tilde), lit("/bin/x")]),
                        bare("a"),
                    ],
                    vec![],
                )
                .unwrap(),
            )]),
        ),
        (
            "\"$X\" a",
            script(vec![single(
                Simple::new(
                    vec![w(vec![Part::Opaque(Opaque::Var(b"X".to_vec()))]), bare("a")],
                    vec![],
                )
                .unwrap(),
            )]),
        ),
    ];
    for (input, want) in cases {
        assert_eq!(parse(input.as_bytes()), Ok(want), "input: {input:?}");
    }
}

/// `<parts> x` where the first word has several parts.
fn split_if(parts: Vec<Part>) -> Script {
    script(vec![single(
        Simple::new(vec![w(parts), bare("x")], vec![]).unwrap(),
    )])
}

fn single_pipe(cmds: Vec<Simple>) -> AndOr {
    and_or(pipe(cmds), Vec::new())
}

#[test]
fn rejected_inputs() {
    let cases: Vec<(&str, K, usize)> = vec![
        (";a", K::LeadingSeparator, 0),
        ("a; ;b", K::LeadingSeparator, 3),
        ("a\n;b", K::LeadingSeparator, 2),
        ("a ;|b", K::MissingCommand, 3),
        ("a |", K::MissingCommand, 3),
        ("a |\n", K::MissingCommand, 4),
        ("a &&", K::MissingCommand, 4),
        ("a ||", K::MissingCommand, 4),
        ("| a", K::MissingCommand, 0),
        ("&& a", K::MissingCommand, 0),
        ("a || | b", K::MissingCommand, 5),
        ("a |||b", K::MissingCommand, 4),
        ("a && ; b", K::LeadingSeparator, 5),
        (">/dev/null", K::RedirectOnly, 0),
        ("a; 2>&1", K::RedirectOnly, 3),
        ("a | >/dev/null", K::RedirectOnly, 4),
        ("FOO=1 cmd", K::Assignment, 0),
        ("FOO=1", K::Assignment, 0),
        ("a; FOO+=1 b", K::Assignment, 3),
        (">/dev/null A=b cmd", K::Assignment, 11),
        ("if true", K::ReservedWord, 0),
        ("a | then", K::ReservedWord, 4),
        ("a && fi", K::ReservedWord, 5),
        ("time ls", K::ReservedWord, 0),
        ("! ls", K::ReservedWord, 0),
        ("coproc x", K::ReservedWord, 0),
        ("in x", K::ReservedWord, 0),
        ("do x", K::ReservedWord, 0),
        ("]] x", K::ReservedWord, 0),
        ("a\nwhile x", K::ReservedWord, 2),
        // Lexer findings win over earlier parser findings.
        ("if x; echo $(y)", K::UnquotedDollar, 11),
        (";a $(b)", K::UnquotedDollar, 3),
    ];
    for (input, kind, offset) in cases {
        assert_eq!(err(input), (kind, offset), "input: {input:?}");
    }
}

#[test]
fn word_limit() {
    let at_limit = "a ".repeat(4096);
    assert!(parse(at_limit.as_bytes()).is_ok());
    let over = "a ".repeat(4097);
    assert_eq!(err(&over), (K::TooManyWords, 4096 * 2));
    // The limit is for the whole script, not per command.
    let across = "a b; ".repeat(2049);
    assert_eq!(err(&across), (K::TooManyWords, 2048 * 5));
}

// ---- proptest ----

/// Every reserved word that can reach the parser (`[[`, `{` and `}` are
/// rejected by the lexer).
const RESERVED_SAMPLES: &[&str] = &[
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
    "done", "in", "function", "time", "coproc", "!", "]]",
];

#[test]
fn every_reserved_word_is_rejected() {
    for word in RESERVED_SAMPLES {
        assert_eq!(
            err(&format!("{word} x")),
            (K::ReservedWord, 0),
            "word: {word:?}"
        );
    }
}

const BAD_NAMES: &[&str] = &["FOO=1", "a_b=", "X+=y", "_1=2"];

#[derive(Debug, Clone)]
enum GWord {
    Bare(String),
    Single(String),
    Mixed(String, String),
    DqVar(String),
    /// Double-quoted text without expansions; may be empty.
    Dq(String),
    /// Every byte backslash-escaped.
    Esc(String),
    Tilde,
}

impl GWord {
    fn render(&self) -> String {
        match self {
            GWord::Bare(s) => s.clone(),
            GWord::Single(s) => format!("'{s}'"),
            GWord::Mixed(a, b) => format!("{a}'{b}'"),
            GWord::DqVar(n) => format!("\"${n}\""),
            GWord::Dq(s) => format!("\"{s}\""),
            GWord::Esc(s) => s.chars().map(|c| format!("\\{c}")).collect(),
            GWord::Tilde => "~".to_string(),
        }
    }

    fn word(&self) -> Word {
        match self {
            GWord::Bare(s) | GWord::Single(s) | GWord::Dq(s) | GWord::Esc(s) => w(vec![lit(s)]),
            GWord::Mixed(a, b) => w(vec![lit(a), lit(b)]),
            GWord::DqVar(n) => w(vec![Part::Opaque(Opaque::Var(n.as_bytes().to_vec()))]),
            GWord::Tilde => w(vec![Part::Opaque(Opaque::Tilde)]),
        }
    }
}

fn gword() -> impl Strategy<Value = GWord> {
    let bare_s = "[a-z0-9./-]{1,6}";
    let quoted = "[a-z ;|&$<>()]{0,6}";
    prop_oneof![
        4 => bare_s.prop_map(GWord::Bare),
        2 => quoted.prop_map(GWord::Single),
        1 => (bare_s, quoted).prop_map(|(a, b)| GWord::Mixed(a, b)),
        1 => "[A-Za-z_][A-Za-z0-9_]{0,4}".prop_map(GWord::DqVar),
        1 => "[a-z ;|&<>()]{0,6}".prop_map(GWord::Dq),
        1 => "[a-z;|&<>()$ ]{1,4}".prop_map(GWord::Esc),
        1 => Just(GWord::Tilde),
    ]
}

/// A command name that is neither reserved nor assignment-shaped.
fn gname() -> impl Strategy<Value = GWord> {
    prop_oneof![
        3 => "x[a-z0-9./-]{0,5}".prop_map(GWord::Bare),
        1 => "[a-z ;|&$<>()]{0,6}".prop_map(GWord::Single),
        1 => Just(GWord::Tilde),
    ]
}

#[derive(Debug, Clone)]
struct GSimple {
    name: GWord,
    args: Vec<GWord>,
    redirs: Vec<Redir>,
    placement: Placement,
}

/// Where the redirects of a generated command are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Before the command name.
    Before,
    /// After the last word.
    After,
    /// One after each word, between the words; leftovers go last.
    Between,
}

fn gredir() -> impl Strategy<Value = Redir> {
    prop_oneof![
        (0u8..10, 0u8..10).prop_map(|(from, to)| Redir::Dup { from, to }),
        (0u8..10).prop_map(|fd| Redir::DevNull { fd }),
    ]
}

fn render_redir(r: Redir) -> String {
    match r {
        Redir::Dup { from, to } => format!("{from}>&{to}"),
        Redir::DevNull { fd } => format!("{fd}>/dev/null"),
    }
}

fn gsimple() -> impl Strategy<Value = GSimple> {
    (
        gname(),
        prop::collection::vec(gword(), 0..4),
        prop::collection::vec(gredir(), 0..3),
        prop_oneof![
            Just(Placement::Before),
            Just(Placement::After),
            Just(Placement::Between),
        ],
    )
        .prop_map(|(name, args, redirs, placement)| GSimple {
            name,
            args,
            redirs,
            placement,
        })
}

impl GSimple {
    /// Renders with `name` standing in for the command name when given.
    fn render(&self, name: Option<&str>) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut redirs = self.redirs.iter().copied().map(render_redir);
        if self.placement == Placement::Before {
            parts.extend(redirs.by_ref());
        }
        parts.push(name.map_or_else(|| self.name.render(), str::to_string));
        for arg in &self.args {
            if self.placement == Placement::Between {
                parts.extend(redirs.next());
            }
            parts.push(arg.render());
        }
        parts.extend(redirs);
        parts.join(" ")
    }

    fn simple(&self) -> Simple {
        Simple::new(
            std::iter::once(&self.name)
                .chain(&self.args)
                .map(GWord::word)
                .collect(),
            self.redirs.clone(),
        )
        .unwrap()
    }
}

#[derive(Debug, Clone)]
struct GAndOr {
    first: Vec<GSimple>,
    rest: Vec<(bool, bool, Vec<GSimple>)>, // (is_and, newline_after, pipeline)
    pipe_newlines: Vec<bool>,
}

fn gpipeline() -> impl Strategy<Value = Vec<GSimple>> {
    prop::collection::vec(gsimple(), 1..4)
}

fn gand_or() -> impl Strategy<Value = GAndOr> {
    (
        gpipeline(),
        prop::collection::vec((any::<bool>(), any::<bool>(), gpipeline()), 0..3),
        prop::collection::vec(any::<bool>(), 8),
    )
        .prop_map(|(first, rest, pipe_newlines)| GAndOr {
            first,
            rest,
            pipe_newlines,
        })
}

#[derive(Debug, Clone)]
struct GScript {
    items: Vec<GAndOr>,
    seps: Vec<&'static str>,
    trailing: &'static str,
}

fn gscript() -> impl Strategy<Value = GScript> {
    let sep = prop::sample::select(vec![";", "; ", " ;", "\n", "\n\n", ";\n", " ; \n "]);
    let trailing = prop::sample::select(vec!["", ";", "\n", " ; ", "\n\n"]);
    (
        prop::collection::vec(gand_or(), 1..4),
        prop::collection::vec(sep, 4),
        trailing,
    )
        .prop_map(|(items, seps, trailing)| GScript {
            items,
            seps,
            trailing,
        })
}

fn render_pipeline(
    p: &[GSimple],
    newlines: &[bool],
    bad: &mut Option<(usize, &str)>,
    n: &mut usize,
) -> String {
    let mut out = String::new();
    for (i, s) in p.iter().enumerate() {
        if i > 0 {
            let nl = newlines.get(i - 1).copied().unwrap_or(false);
            out.push_str(if nl { " |\n " } else { " | " });
        }
        let name = match bad {
            Some((at, name)) if *at == *n => Some(*name),
            Some(_) | None => None,
        };
        if name.is_some() {
            *bad = None;
        }
        *n += 1;
        out.push_str(&s.render(name));
    }
    out
}

impl GScript {
    fn simple_count(&self) -> usize {
        self.items
            .iter()
            .map(|a| a.first.len() + a.rest.iter().map(|r| r.2.len()).sum::<usize>())
            .sum()
    }

    fn render(&self, mut bad: Option<(usize, &str)>) -> String {
        let mut out = String::new();
        let mut n = 0;
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                out.push_str(self.seps.get(i - 1).copied().unwrap_or(";"));
            }
            out.push_str(&render_pipeline(
                &item.first,
                &item.pipe_newlines,
                &mut bad,
                &mut n,
            ));
            for (is_and, nl, p) in &item.rest {
                out.push_str(match (is_and, nl) {
                    (true, false) => " && ",
                    (true, true) => " &&\n ",
                    (false, false) => " || ",
                    (false, true) => " ||\n ",
                });
                out.push_str(&render_pipeline(p, &item.pipe_newlines, &mut bad, &mut n));
            }
        }
        out.push_str(self.trailing);
        out
    }

    fn script(&self) -> Script {
        Script::new(
            self.items
                .iter()
                .map(|item| {
                    AndOr::new(
                        pipe_of(&item.first),
                        item.rest
                            .iter()
                            .map(|(is_and, _, p)| {
                                Link::new(
                                    if *is_and {
                                        Connector::And
                                    } else {
                                        Connector::Or
                                    },
                                    pipe_of(p),
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
        )
    }
}

fn pipe_of(p: &[GSimple]) -> Pipeline {
    Pipeline::new(p.iter().map(GSimple::simple).collect()).unwrap()
}

proptest! {
    #[test]
    fn never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse(&bytes);
    }

    #[test]
    fn never_panics_on_interesting_bytes(bytes in interesting_bytes()) {
        let _ = parse(&bytes);
    }

    #[test]
    fn round_trip(s in gscript()) {
        let input = s.render(None);
        prop_assert_eq!(parse(input.as_bytes()), Ok(s.script()), "input: {:?}", input);
    }

    #[test]
    fn reserved_or_assignment_in_command_position_is_rejected(
        s in gscript(),
        pick in any::<prop::sample::Index>(),
        bad in prop::sample::select(
            RESERVED_SAMPLES.iter().chain(BAD_NAMES).copied().collect::<Vec<_>>()
        ),
    ) {
        let at = pick.index(s.simple_count());
        let input = s.render(Some((at, bad)));
        prop_assert!(parse(input.as_bytes()).is_err(), "input: {:?}", input);
    }
}
