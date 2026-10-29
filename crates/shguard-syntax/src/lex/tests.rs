use super::{
    LexPart, LexRedir, LexWord, Op, Quoting, Token, Unsupported, UnsupportedKind as K, lex,
};
use proptest::prelude::*;

fn unq(s: &str) -> LexPart {
    LexPart::Lit {
        bytes: s.as_bytes().to_vec(),
        quoting: Quoting::Unquoted,
    }
}

fn quo(s: &str) -> LexPart {
    LexPart::Lit {
        bytes: s.as_bytes().to_vec(),
        quoting: Quoting::Quoted,
    }
}

fn var(s: &str) -> LexPart {
    LexPart::Var(s.as_bytes().to_vec())
}

fn word(parts: Vec<LexPart>) -> Token {
    let mut parts = parts.into_iter();
    let first = parts.next().unwrap();
    Token::Word(LexWord::new(first, parts.collect()))
}

fn bare(s: &str) -> Token {
    word(vec![unq(s)])
}

fn ok(input: &str) -> Vec<Token> {
    lex(input.as_bytes())
        .unwrap()
        .into_iter()
        .map(|l| l.token)
        .collect()
}

#[test]
fn lexemes_carry_start_and_end_offsets() {
    let got: Vec<(usize, usize, Token)> = lex(b"ab  2>&1 ; c\n|d")
        .unwrap()
        .into_iter()
        .map(|l| (l.offset, l.end, l.token))
        .collect();
    assert_eq!(
        got,
        vec![
            (0, 2, bare("ab")),
            (4, 8, Token::Redir(LexRedir::Dup { from: 2, to: 1 })),
            (9, 10, SEMI),
            (11, 12, bare("c")),
            (12, 13, NL),
            (13, 14, PIPE),
            (14, 15, bare("d")),
        ]
    );
}

#[test]
fn word_end_spans_quotes_and_escapes() {
    let input = br#"x 'a b'"c"\  >/dev/null  y"#;
    let texts: Vec<&[u8]> = lex(input)
        .unwrap()
        .iter()
        .map(|l| &input[l.offset..l.end])
        .collect();
    let expected: [&[u8]; 4] = [b"x", br#"'a b'"c"\ "#, b">/dev/null", b"y"];
    assert_eq!(texts, expected);
}

fn err(input: &[u8]) -> (K, usize) {
    let Unsupported { kind, offset } = lex(input).unwrap_err();
    (kind, offset)
}

const SEMI: Token = Token::Op(Op::Semi);
const PIPE: Token = Token::Op(Op::Pipe);
const NL: Token = Token::Op(Op::Newline);

#[test]
fn accepted_inputs() {
    let cases: Vec<(&str, Vec<Token>)> = vec![
        ("", vec![]),
        ("  \t ", vec![]),
        ("ls -la", vec![bare("ls"), bare("-la")]),
        (
            "git log --oneline | head -5",
            vec![
                bare("git"),
                bare("log"),
                bare("--oneline"),
                PIPE,
                bare("head"),
                bare("-5"),
            ],
        ),
        (
            "a && b || c; d",
            vec![
                bare("a"),
                Token::Op(Op::AndIf),
                bare("b"),
                Token::Op(Op::OrIf),
                bare("c"),
                SEMI,
                bare("d"),
            ],
        ),
        ("a\nb", vec![bare("a"), NL, bare("b")]),
        ("a\tb", vec![bare("a"), bare("b")]),
        (
            r#"echo "$HOME/x" '${y}' \$z"#,
            vec![
                bare("echo"),
                word(vec![var("HOME"), quo("/x")]),
                word(vec![quo("${y}")]),
                word(vec![quo("$"), unq("z")]),
            ],
        ),
        (
            "cmd 2>&1 >/dev/null",
            vec![
                bare("cmd"),
                Token::Redir(LexRedir::Dup { from: 2, to: 1 }),
                Token::Redir(LexRedir::DevNull { fd: 1 }),
            ],
        ),
        (
            "cmd 2>&1>/dev/null",
            vec![
                bare("cmd"),
                Token::Redir(LexRedir::Dup { from: 2, to: 1 }),
                Token::Redir(LexRedir::DevNull { fd: 1 }),
            ],
        ),
        (
            "cmd > /dev/null",
            vec![bare("cmd"), Token::Redir(LexRedir::DevNull { fd: 1 })],
        ),
        (
            "cmd 2>/dev/null",
            vec![bare("cmd"), Token::Redir(LexRedir::DevNull { fd: 2 })],
        ),
        (
            "cmd >\"/dev/null\"",
            vec![bare("cmd"), Token::Redir(LexRedir::DevNull { fd: 1 })],
        ),
        (
            "cmd >/dev/'null'",
            vec![bare("cmd"), Token::Redir(LexRedir::DevNull { fd: 1 })],
        ),
        (
            "cmd >&2",
            vec![bare("cmd"), Token::Redir(LexRedir::Dup { from: 1, to: 2 })],
        ),
        (
            "cmd >&2;ls",
            vec![
                bare("cmd"),
                Token::Redir(LexRedir::Dup { from: 1, to: 2 }),
                SEMI,
                bare("ls"),
            ],
        ),
        (
            "a>/dev/null",
            vec![bare("a"), Token::Redir(LexRedir::DevNull { fd: 1 })],
        ),
        (
            "a2>&1",
            vec![bare("a2"), Token::Redir(LexRedir::Dup { from: 1, to: 1 })],
        ),
        (
            "\"2\">&1",
            vec![
                word(vec![quo("2")]),
                Token::Redir(LexRedir::Dup { from: 1, to: 1 }),
            ],
        ),
        (
            "rm -rf ~/x",
            vec![
                bare("rm"),
                bare("-rf"),
                word(vec![LexPart::Tilde, unq("/x")]),
            ],
        ),
        ("~", vec![word(vec![LexPart::Tilde])]),
        (
            "echo ~;ls",
            vec![bare("echo"), word(vec![LexPart::Tilde]), SEMI, bare("ls")],
        ),
        ("\"~\"", vec![word(vec![quo("~")])]),
        ("echo 'it''s'", vec![bare("echo"), word(vec![quo("its")])]),
        ("a'b'c", vec![word(vec![unq("a"), quo("b"), unq("c")])]),
        ("\"\"", vec![word(vec![quo("")])]),
        ("''", vec![word(vec![quo("")])]),
        ("\"$X\"", vec![word(vec![var("X")])]),
        ("\"${X}y\"", vec![word(vec![var("X"), quo("y")])]),
        (
            "echo \"${HOME}日\"",
            vec![bare("echo"), word(vec![var("HOME"), quo("日")])],
        ),
        (
            "echo \"日$HOME\"",
            vec![bare("echo"), word(vec![quo("日"), var("HOME")])],
        ),
        ("\"$X_1-\"", vec![word(vec![var("X_1"), quo("-")])]),
        ("\"a$X\"\"\"", vec![word(vec![quo("a"), var("X"), quo("")])]),
        ("\"$\"", vec![word(vec![quo("$")])]),
        (r#""\$x \q \\ \"""#, vec![word(vec![quo(r#"$x \q \ ""#)])]),
        ("a\\ b", vec![word(vec![unq("a"), quo(" "), unq("b")])]),
        ("echo 日 本", vec![bare("echo"), bare("日"), bare("本")]),
        (
            "echo \"日本語\"",
            vec![bare("echo"), word(vec![quo("日本語")])],
        ),
        ("echo 日本", vec![bare("echo"), bare("日本")]),
        ("echo a#b", vec![bare("echo"), bare("a#b")]),
        ("echo a]", vec![bare("echo"), bare("a]")]),
        ("echo !", vec![bare("echo"), bare("!")]),
        ("echo a=b", vec![bare("echo"), bare("a=b")]),
        (
            "git log HEAD~1",
            vec![bare("git"), bare("log"), bare("HEAD~1")],
        ),
        ("scp h:~/f .", vec![bare("scp"), bare("h:~/f"), bare(".")]),
        ("x a+b=~", vec![bare("x"), bare("a+b=~")]),
        ("x --opt=~/x", vec![bare("x"), bare("--opt=~/x")]),
        ("a='x'~", vec![word(vec![unq("a="), quo("x"), unq("~")])]),
        ("'a\nb'", vec![word(vec![quo("a\nb")])]),
    ];
    for (input, want) in cases {
        assert_eq!(ok(input), want, "input: {input:?}");
    }
}

#[test]
fn unsupported_inputs() {
    let cases: Vec<(&[u8], K, usize)> = vec![
        (b"a\r\n", K::ControlByte, 1),
        (b"a\0b", K::ControlByte, 1),
        (b"a\x7f", K::ControlByte, 1),
        (b"'a\x01'", K::ControlByte, 2),
        (b"\"a\x01\"", K::ControlByte, 2),
        (b"a\\\x01", K::ControlByte, 2),
        (b"echo 'x", K::UnterminatedSingleQuote, 5),
        (b"echo \"x", K::UnterminatedDoubleQuote, 5),
        (b"a & b", K::BackgroundAmpersand, 2),
        (b"a &", K::BackgroundAmpersand, 2),
        (b"a |& b", K::PipeAmpersand, 2),
        (b"a ;; b", K::DoubleSemicolon, 2),
        (b"a ;& b", K::SemicolonAmpersand, 2),
        (b"(a)", K::Parenthesis, 0),
        (b"a )", K::Parenthesis, 2),
        (b"a < b", K::InputRedirect, 2),
        (b"a <<< b", K::InputRedirect, 2),
        (b"cat <(x)", K::InputRedirect, 4),
        (b"a >> b", K::AppendRedirect, 2),
        (b"a 2>> b", K::AppendRedirect, 2),
        (b"a >| b", K::ClobberRedirect, 2),
        (b"a &> b", K::AmpersandRedirect, 2),
        (b"a &>> b", K::AmpersandRedirect, 2),
        (b"a >(x)", K::ProcessSubstitution, 2),
        (b"echo {a,b}", K::Brace, 5),
        (b"echo a}", K::Brace, 6),
        (b"echo a*", K::Glob, 6),
        (b"echo ?", K::Glob, 5),
        (b"echo [a]", K::Glob, 5),
        (b"echo #b", K::Comment, 5),
        (b"echo $X", K::UnquotedDollar, 5),
        (b"echo ${X}", K::UnquotedDollar, 5),
        (b"echo $(x)", K::UnquotedDollar, 5),
        (b"echo $'x'", K::UnquotedDollar, 5),
        (b"echo a$", K::UnquotedDollar, 6),
        (b"echo `x`", K::Backquote, 5),
        (b"echo \"`x`\"", K::Backquote, 6),
        ("echo \"$HOME日\"".as_bytes(), K::NameBeforeNonAscii, 6),
        ("echo \"a$Xé\"".as_bytes(), K::NameBeforeNonAscii, 7),
        (b"echo \"$(x)\"", K::DollarParen, 6),
        (b"echo \"$((1))\"", K::DollarParen, 6),
        (b"echo \"${X:-y}\"", K::BracedParameter, 6),
        (b"echo \"${}\"", K::BracedParameter, 6),
        (b"echo \"${X\"", K::BracedParameter, 6),
        (b"echo \"$1\"", K::SpecialParameter, 6),
        (b"echo \"$@\"", K::SpecialParameter, 6),
        (b"echo \"$?\"", K::SpecialParameter, 6),
        (b"echo \"$$\"", K::SpecialParameter, 6),
        (b"echo \"$-\"", K::SpecialParameter, 6),
        (b"echo \"$!\"", K::SpecialParameter, 6),
        (b"echo \"$#\"", K::SpecialParameter, 6),
        (b"echo \"$*\"", K::SpecialParameter, 6),
        (b"echo \"$ \"", K::BareDollar, 6),
        (b"echo \"$", K::BareDollar, 6),
        (b"a\\\nb", K::LineContinuation, 1),
        (b"\"a\\\nb\"", K::LineContinuation, 2),
        (b"a\\", K::BackslashAtEnd, 1),
        (b"echo ~user", K::TildeForm, 5),
        (b"echo ~+", K::TildeForm, 5),
        (b"echo ~-", K::TildeForm, 5),
        (b"echo ~0", K::TildeForm, 5),
        (b"echo ~\"x\"", K::TildeForm, 5),
        (b"make prefix=~/x", K::TildeAssignment, 12),
        (b"a=b:~/c", K::TildeAssignment, 4),
        (b"a=~", K::TildeAssignment, 2),
        (b"a+=~", K::TildeAssignment, 3),
        ("echo ê=~".as_bytes(), K::TildeAssignment, 8),
        ("echo ê=a:~/x".as_bytes(), K::TildeAssignment, 10),
        ("echo ê+=~".as_bytes(), K::TildeAssignment, 9),
        ("echo xê=~".as_bytes(), K::TildeAssignment, 9),
        ("echo 日\\ 本".as_bytes(), K::BackslashAfterNonAscii, 8),
        ("echo \"é\\$X\"".as_bytes(), K::BackslashAfterNonAscii, 8),
        (b"make CFLAGS+=~/x", K::TildeAssignment, 13),
        (b"a+=b:~/c", K::TildeAssignment, 5),
        (b"a 12>&1", K::MultiDigitFd, 2),
        (b"x>&1y", K::DupOperand, 1),
        (b"x >&12", K::DupOperand, 2),
        (b"x >&-", K::DupOperand, 2),
        (b"x >&$X", K::DupOperand, 2),
        (b"x >&word", K::DupOperand, 2),
        (b"x >&", K::DupOperand, 2),
        (b"x >&1)", K::DupOperand, 2),
        (b"x > /dev/nullx", K::RedirectTarget, 2),
        (b"x > /dev/nul", K::RedirectTarget, 2),
        (b"x > ~/x", K::RedirectTarget, 2),
        (b"x > \"$X\"", K::RedirectTarget, 2),
        (b"x > f", K::RedirectTarget, 2),
        (b"x >", K::RedirectTarget, 2),
        (b"x > ; y", K::RedirectTarget, 2),
        (b"x > > y", K::RedirectTarget, 2),
        (b"x 2>f", K::RedirectTarget, 2),
    ];
    for (input, kind, offset) in cases {
        assert_eq!(
            err(input),
            (kind, offset),
            "input: {:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn size_boundary() {
    let at_limit = vec![b'a'; 65_536];
    assert_eq!(lex(&at_limit).unwrap().len(), 1);
    let over = vec![b'a'; 65_537];
    assert_eq!(err(&over), (K::InputTooLarge, 0));
}

#[test]
fn earliest_construct_wins() {
    assert_eq!(err(b"a ( \x01"), (K::Parenthesis, 2));
    assert_eq!(err(b"a \x01 ("), (K::ControlByte, 2));
}

// --- property tests ---

#[derive(Clone, Debug)]
enum DqSeg {
    Lit(String),
    Var(String, bool),
}

#[derive(Clone, Debug)]
enum Seg {
    Unq(String),
    Sq(String),
    Dq(Vec<DqSeg>),
    Esc(char),
    TildeSlash,
}

#[derive(Clone, Debug)]
enum Gen {
    Word(Vec<Seg>),
    Op(Op),
    Redir(LexRedir, u8),
}

fn seg() -> impl Strategy<Value = Seg> {
    prop_oneof![
        "[a-zA-Z0-9_./=+,@%^:!-]{1,6}".prop_map(Seg::Unq),
        "[ -&(-~]{0,8}".prop_map(Seg::Sq),
        prop::collection::vec(
            prop_oneof![
                "[ !#%-\\[\\]-_a-~]{0,6}".prop_map(DqSeg::Lit),
                ("[A-Za-z_][A-Za-z0-9_]{0,4}", any::<bool>()).prop_map(|(n, b)| DqSeg::Var(n, b)),
            ],
            0..4,
        )
        .prop_map(Seg::Dq),
        "[ -~]".prop_map(|c| Seg::Esc(c.chars().next().unwrap_or('a'))),
    ]
}

fn gen_token() -> impl Strategy<Value = Gen> {
    prop_oneof![
        3 => (any::<bool>(), prop::collection::vec(seg(), 1..4)).prop_map(|(tilde, mut segs)| {
            if tilde {
                segs.insert(0, Seg::TildeSlash);
            }
            Gen::Word(segs)
        }),
        1 => prop_oneof![
            Just(Op::Semi),
            Just(Op::Newline),
            Just(Op::AndIf),
            Just(Op::OrIf),
            Just(Op::Pipe)
        ]
        .prop_map(Gen::Op),
        1 => (0u8..10, 0u8..10, 0u8..6).prop_map(|(from, to, style)| Gen::Redir(LexRedir::Dup { from, to }, style)),
        1 => (0u8..10, 0u8..6).prop_map(|(fd, style)| Gen::Redir(LexRedir::DevNull { fd }, style)),
    ]
}

fn render_dq(segs: &[DqSeg]) -> String {
    let mut out = String::from("\"");
    for (i, s) in segs.iter().enumerate() {
        match s {
            DqSeg::Lit(l) => out.push_str(l),
            DqSeg::Var(name, braced) => {
                let next_is_name_byte = matches!(
                    segs.iter().skip(i + 1).find(|s| !matches!(s, DqSeg::Lit(l) if l.is_empty())),
                    Some(DqSeg::Lit(l)) if l.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
                );
                if *braced || next_is_name_byte {
                    out.push_str(&format!("${{{name}}}"));
                } else {
                    out.push_str(&format!("${name}"));
                }
            }
        }
    }
    out.push('"');
    out
}

fn render(g: &Gen) -> String {
    match g {
        Gen::Word(segs) => segs
            .iter()
            .map(|s| match s {
                Seg::Unq(u) => u.clone(),
                Seg::Sq(q) => format!("'{q}'"),
                Seg::Dq(d) => render_dq(d),
                Seg::Esc(c) => format!("\\{c}"),
                Seg::TildeSlash => "~/".to_string(),
            })
            .collect(),
        Gen::Op(Op::Semi) => ";".into(),
        Gen::Op(Op::Newline) => "\n".into(),
        Gen::Op(Op::AndIf) => "&&".into(),
        Gen::Op(Op::OrIf) => "||".into(),
        Gen::Op(Op::Pipe) => "|".into(),
        Gen::Redir(LexRedir::Dup { from, to }, style) => {
            let fd = if *style >= 3 && *from == 1 {
                String::new()
            } else {
                from.to_string()
            };
            format!("{fd}>&{to}")
        }
        Gen::Redir(LexRedir::DevNull { fd }, style) => {
            let fd_text = if *style >= 3 && *fd == 1 {
                String::new()
            } else {
                fd.to_string()
            };
            let target = match style % 3 {
                0 => ">/dev/null",
                1 => "> /dev/null",
                _ => ">\"/dev/null\"",
            };
            format!("{fd_text}{target}")
        }
    }
}

/// Blanks are dropped next to an operator, and between a non-numeric word
/// and a redirect without a descriptor; elsewhere they are needed (`2` then `>&1` would be a
/// descriptor, `>&2` then a word a bad dup operand).
fn join(tokens: &[Gen], rendered: &[String]) -> String {
    let mut out = String::new();
    for (i, text) in rendered.iter().enumerate() {
        if let (Some(prev), Some(cur)) =
            (i.checked_sub(1).and_then(|j| tokens.get(j)), tokens.get(i))
        {
            let tight = match (prev, cur) {
                (Gen::Op(_), Gen::Op(_)) => false,
                (Gen::Op(_), _) | (_, Gen::Op(_)) => true,
                (Gen::Word(_), Gen::Redir(..)) => {
                    let ends_in_digit = i
                        .checked_sub(1)
                        .and_then(|j| rendered.get(j))
                        .is_some_and(|w| w.bytes().last().is_some_and(|b| b.is_ascii_digit()));
                    text.starts_with('>') && !ends_in_digit
                }
                (Gen::Word(_) | Gen::Redir(..), _) => false,
            };
            if !tight {
                out.push(' ');
            }
        }
        out.push_str(text);
    }
    out
}

fn push_lit(parts: &mut Vec<LexPart>, s: &str, quoting: Quoting) {
    if let Some(LexPart::Lit { bytes, quoting: q }) = parts.last_mut()
        && *q == quoting
    {
        bytes.extend_from_slice(s.as_bytes());
        return;
    }
    parts.push(LexPart::Lit {
        bytes: s.as_bytes().to_vec(),
        quoting,
    });
}

fn expected(g: &Gen) -> Token {
    match g {
        Gen::Op(op) => Token::Op(*op),
        Gen::Redir(r, _) => Token::Redir(*r),
        Gen::Word(segs) => {
            let mut parts = Vec::new();
            for s in segs {
                match s {
                    Seg::Unq(u) => push_lit(&mut parts, u, Quoting::Unquoted),
                    Seg::Sq(q) => push_lit(&mut parts, q, Quoting::Quoted),
                    Seg::Esc(c) => push_lit(&mut parts, &c.to_string(), Quoting::Quoted),
                    Seg::TildeSlash => {
                        parts.push(LexPart::Tilde);
                        push_lit(&mut parts, "/", Quoting::Unquoted);
                    }
                    Seg::Dq(d) => {
                        let mut any = false;
                        for x in d {
                            match x {
                                DqSeg::Lit(l) if l.is_empty() => {}
                                DqSeg::Lit(l) => {
                                    push_lit(&mut parts, l, Quoting::Quoted);
                                    any = true;
                                }
                                DqSeg::Var(n, _) => {
                                    parts.push(var(n));
                                    any = true;
                                }
                            }
                        }
                        if !any {
                            push_lit(&mut parts, "", Quoting::Quoted);
                        }
                    }
                }
            }
            word(parts)
        }
    }
}

/// Bytes biased to the shell metacharacters, shared with the parser tests.
pub(crate) fn interesting_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            9 => prop::sample::select(b" \t\n;&|<>()'\"\\$`{}*?[~#=:+/0123456789aA_!".to_vec()),
            1 => any::<u8>(),
        ],
        0..128,
    )
}

proptest! {
    #[test]
    fn never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = lex(&bytes);
    }

    #[test]
    fn never_panics_on_interesting_bytes(bytes in interesting_bytes()) {
        let _ = lex(&bytes);
    }

    #[test]
    fn round_trip(tokens in prop::collection::vec(gen_token(), 0..8)) {
        let rendered: Vec<String> = tokens.iter().map(render).collect();
        let input = join(&tokens, &rendered);
        let want: Vec<Token> = tokens.iter().map(expected).collect();
        prop_assert_eq!(ok(&input), want, "input: {:?}", input);
    }

    #[test]
    fn inserted_expansion_is_rejected(
        tokens in prop::collection::vec(gen_token(), 0..6),
        at in 0usize..8,
        bad in prop::sample::select(vec!["`x`", "$(x)", "*", "a*b", "$X", "a`b"]),
    ) {
        let mut pieces: Vec<String> = tokens.iter().map(render).collect();
        pieces.insert(at.min(pieces.len()), bad.to_string());
        let input = pieces.join(" ");
        prop_assert!(lex(input.as_bytes()).is_err(), "input: {:?}", input);
    }
}
