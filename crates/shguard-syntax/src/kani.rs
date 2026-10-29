//! Kani harnesses: totality and no-panic checks for [`lex`] and [`parse`].
//!
//! Kani also checks arithmetic overflow and out-of-bounds access implicitly.
//! These run in CI (`.github/workflows/kani.yaml`), not in `cargo test`; the
//! module exists only under `cfg(kani)`, so it indexes freely because Kani
//! proves every index in bounds.
//!
//! Bounds: every input byte (`*_any_bytes`), or the alphabet below
//! (`parse_alphabet`), at a small length. The bounds are measured, and each
//! harness's length const records its measured CI time once known. The unwind
//! value covers the longest loop a harness reaches.

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

/// Longest input of `parse_any_bytes`. Measured CI time: not yet known.
const PARSE_ANY_LEN: usize = 4;

// Unwind: the input length plus the loop exits.
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn parse_any_bytes() {
    let (bytes, len) = symbolic_input::<PARSE_ANY_LEN>();
    match parse(&bytes[..len]) {
        Ok(_) => ::kani::cover!(true, "parse accepts"),
        Err(e) => {
            ::kani::cover!(true, "parse rejects");
            assert!(e.offset <= len);
        }
    }
}

/// Longest input of `parse_alphabet`. Measured CI time: not yet known.
const PARSE_ALPHABET_LEN: usize = 6;

// Unwind: the input length plus the loop exits.
#[::kani::proof]
#[::kani::unwind(8)]
#[::kani::solver(cadical)]
fn parse_alphabet() {
    let (bytes, len) = symbolic_input::<PARSE_ALPHABET_LEN>();
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
/// `DevNull` success path of the redirect lexer. Measured CI time: not yet
/// known.
const DEV_NULL_AFFIX_LEN: usize = 1;

// Unwind: the literal's 10 bytes plus the loop exits, with a margin for the
// affixes.
#[::kani::proof]
#[::kani::unwind(14)]
#[::kani::solver(cadical)]
fn parse_dev_null_redirect() {
    const LITERAL: &[u8; 10] = b">/dev/null";
    let prefix: [u8; DEV_NULL_AFFIX_LEN] = ::kani::any();
    let prefix_len: usize = ::kani::any();
    ::kani::assume(prefix_len <= DEV_NULL_AFFIX_LEN);
    let suffix: [u8; DEV_NULL_AFFIX_LEN] = ::kani::any();
    let suffix_len: usize = ::kani::any();
    ::kani::assume(suffix_len <= DEV_NULL_AFFIX_LEN);

    let mut input = [0u8; LITERAL.len() + 2 * DEV_NULL_AFFIX_LEN];
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

/// Longest input of `lex_any_bytes`. Measured CI time: not yet known.
const LEX_ANY_LEN: usize = 4;

// Unwind: the input length plus the loop exits.
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn lex_any_bytes() {
    let (bytes, len) = symbolic_input::<LEX_ANY_LEN>();
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

// TEMPORARY (#1061 measurement): exact-length inputs, no symbolic length.
// Each byte is still symbolic. Removed before merge.

#[::kani::proof]
#[::kani::unwind(4)]
#[::kani::solver(cadical)]
fn lex_exact_0() {
    let bytes: [u8; 0] = [];
    let _ = lex(&bytes);
}

#[::kani::proof]
#[::kani::unwind(4)]
#[::kani::solver(cadical)]
fn lex_exact_1() {
    let bytes: [u8; 1] = ::kani::any();
    let _ = lex(&bytes);
}

#[::kani::proof]
#[::kani::unwind(4)]
#[::kani::solver(cadical)]
fn lex_exact_2() {
    let bytes: [u8; 2] = ::kani::any();
    let _ = lex(&bytes);
}

#[::kani::proof]
#[::kani::unwind(4)]
#[::kani::solver(cadical)]
fn parse_exact_1() {
    let bytes: [u8; 1] = ::kani::any();
    let _ = parse(&bytes);
}

#[::kani::proof]
#[::kani::unwind(4)]
#[::kani::solver(cadical)]
fn parse_exact_2() {
    let bytes: [u8; 2] = ::kani::any();
    let _ = parse(&bytes);
}
