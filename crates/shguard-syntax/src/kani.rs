//! Kani harnesses: totality and no-panic checks for [`lex`] and [`parse`].
//!
//! Kani also checks arithmetic overflow and out-of-bounds access implicitly.
//! These run in CI (`.github/workflows/kani.yaml`), not in `cargo test`; the
//! module exists only under `cfg(kani)`, so it indexes freely because Kani
//! proves every index in bounds.
//!
//! Bounds: every input byte at length 8 (`*_any_bytes_len_8`), and the
//! alphabet below at length 12. The unwind value must cover the longest loop
//! a harness reaches (see the comment on the `parse` harnesses).

use crate::{lex, parse};

/// Every byte that drives a different lexer or parser branch: blanks and
/// newline, the operator bytes, quotes, backslash, `$`, `~`, `#`, `=`, `:`,
/// `/`, the bytes the subset rejects (`(`, `{`, `}`, backquote, `*`, `!`),
/// `+`, a control byte, and digits and a letter standing for ordinary word
/// bytes.
// A `matches!`, not `slice::contains`: the slice search is a loop that would
// need its own unwind bound on every byte.
fn in_alphabet(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t'
            | b'\n'
            | b';'
            | b'&'
            | b'|'
            | b'<'
            | b'>'
            | b'\''
            | b'"'
            | b'\\'
            | b'$'
            | b'~'
            | b'#'
            | b'='
            | b':'
            | b'/'
            | b'('
            | b'{'
            | b'}'
            | b'`'
            | b'*'
            | b'!'
            | b'+'
            | 0x01
            | b'0'..=b'3' | b'a'
    )
}

/// A symbolic byte string of length at most `N`, together with its length.
fn symbolic_input<const N: usize>() -> ([u8; N], usize) {
    let len: usize = ::kani::any();
    ::kani::assume(len <= N);
    let bytes: [u8; N] = ::kani::any();
    (bytes, len)
}

// Not the input length plus a margin: `parse` searches the 22 reserved words
// with a loop, so every `parse` harness needs at least 23.
#[::kani::proof]
#[::kani::unwind(24)]
#[::kani::solver(cadical)]
fn parse_any_bytes_len_8() {
    let (bytes, len) = symbolic_input::<8>();
    match parse(&bytes[..len]) {
        Ok(_) => ::kani::cover!(true, "parse accepts"),
        Err(e) => {
            ::kani::cover!(true, "parse rejects");
            assert!(e.offset <= len);
        }
    }
}

// The alphabet bounds the branching, so the length can go to 12.
#[::kani::proof]
#[::kani::unwind(24)]
#[::kani::solver(cadical)]
fn parse_alphabet_len_12() {
    let (bytes, len) = symbolic_input::<12>();
    let mut i = 0;
    while i < len {
        ::kani::assume(in_alphabet(bytes[i]));
        i += 1;
    }
    match parse(&bytes[..len]) {
        Ok(_) => ::kani::cover!(true, "parse accepts"),
        Err(e) => {
            ::kani::cover!(true, "parse rejects");
            assert!(e.offset <= len);
        }
    }
}

/// `>/dev/null` between symbolic affixes: the only way to reach the
/// `DevNull` success path of the redirect lexer.
#[::kani::proof]
#[::kani::unwind(24)]
#[::kani::solver(cadical)]
fn parse_dev_null_redirect() {
    const LITERAL: &[u8; 10] = b">/dev/null";
    let prefix: [u8; 3] = ::kani::any();
    let prefix_len: usize = ::kani::any();
    ::kani::assume(prefix_len <= 3);
    let suffix: [u8; 3] = ::kani::any();
    let suffix_len: usize = ::kani::any();
    ::kani::assume(suffix_len <= 3);

    let mut input = [0u8; 16];
    let mut len = 0;
    let mut i = 0;
    while i < prefix_len {
        input[len] = prefix[i];
        len += 1;
        i += 1;
    }
    i = 0;
    while i < LITERAL.len() {
        input[len] = LITERAL[i];
        len += 1;
        i += 1;
    }
    i = 0;
    while i < suffix_len {
        input[len] = suffix[i];
        len += 1;
        i += 1;
    }
    match parse(&input[..len]) {
        Ok(_) => ::kani::cover!(true, "parse accepts"),
        Err(e) => {
            ::kani::cover!(true, "parse rejects");
            assert!(e.offset <= len);
        }
    }
}

#[::kani::proof]
#[::kani::unwind(10)]
#[::kani::solver(cadical)]
fn lex_any_bytes_len_8() {
    let (bytes, len) = symbolic_input::<8>();
    match lex(&bytes[..len]) {
        Ok(lexemes) => {
            ::kani::cover!(true, "lex accepts");
            let mut previous: Option<usize> = None;
            for lexeme in &lexemes {
                assert!(lexeme.offset < len);
                if let Some(p) = previous {
                    assert!(p < lexeme.offset);
                }
                previous = Some(lexeme.offset);
            }
        }
        Err(e) => {
            ::kani::cover!(true, "lex rejects");
            assert!(e.offset < len);
        }
    }
}
