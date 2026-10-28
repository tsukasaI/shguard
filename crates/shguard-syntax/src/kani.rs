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
/// `/`, and digits and a letter standing for ordinary word bytes.
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
    if let Err(e) = parse(&bytes[..len]) {
        assert!(e.offset <= len);
    }
}

// Why not any byte at length 12: not measured yet; the alphabet bounds the
// branching instead. Record the measured limit here if CI shows a timeout.
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
    if let Err(e) = parse(&bytes[..len]) {
        assert!(e.offset <= len);
    }
}

#[::kani::proof]
#[::kani::unwind(10)]
#[::kani::solver(cadical)]
fn lex_any_bytes_len_8() {
    let (bytes, len) = symbolic_input::<8>();
    if let Ok(lexemes) = lex(&bytes[..len]) {
        let mut previous: Option<usize> = None;
        for lexeme in &lexemes {
            assert!(lexeme.offset < len);
            if let Some(p) = previous {
                assert!(p < lexeme.offset);
            }
            previous = Some(lexeme.offset);
        }
    }
}
