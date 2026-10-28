//! Kani harnesses: totality and no-panic checks for [`lex`] and [`parse`].
//!
//! Kani also checks arithmetic overflow and out-of-bounds access implicitly.
//! These run in CI (`.github/workflows/kani.yaml`), not in `cargo test`; the
//! module exists only under `cfg(kani)`, so it indexes freely because Kani
//! proves every index in bounds.
//!
//! Bounds: every input byte at length 8 (`*_any_bytes_len_8`), and the
//! alphabet below at length 12. Unwind values are the input length plus a
//! small margin for the loops in `lex`, `parse` and the `Vec` operations.

use crate::{lex, parse};

/// Every byte that drives a different lexer or parser branch: blanks and
/// newline, the operator bytes, quotes, backslash, `$`, `~`, `#`, `=`, `:`,
/// `/`, and a digit and a letter standing for ordinary word bytes.
const ALPHABET: &[u8] = b" \t\n;&|<>'\"\\$~#=:/0123a";

/// A symbolic byte string of length at most `N`, together with its length.
fn symbolic_input<const N: usize>() -> ([u8; N], usize) {
    let len: usize = ::kani::any();
    ::kani::assume(len <= N);
    let bytes: [u8; N] = ::kani::any();
    (bytes, len)
}

#[::kani::proof]
#[::kani::unwind(10)]
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
#[::kani::unwind(14)]
#[::kani::solver(cadical)]
fn parse_alphabet_len_12() {
    let (bytes, len) = symbolic_input::<12>();
    let mut i = 0;
    while i < len {
        ::kani::assume(ALPHABET.contains(&bytes[i]));
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
