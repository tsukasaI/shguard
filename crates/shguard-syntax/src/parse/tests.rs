use super::parse;
use crate::generate::{gscript, lit, w};
use crate::lex::tests::interesting_bytes;
use crate::{Unsupported, UnsupportedKind as K};
use proptest::prelude::*;
use shguard_kernel::ast::{
    AndOr, Connector, Link, Opaque, Part, Pipeline, Redir, Script, Simple, Word,
};

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
