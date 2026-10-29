//! Kani harnesses over small inner units of the lexer.
//!
//! Each harness checks that its unit does not panic, overflow or index out of
//! bounds (Kani checks all three implicitly), plus the postconditions stated
//! in the harness. They run in CI (`.github/workflows/kani.yaml`), not in
//! `cargo test`; the module exists only under `cfg(kani)`, so it indexes
//! freely because Kani proves every index in bounds.
//!
//! Whole-input [`lex`](crate::lex()) and [`parse`](crate::parse) are out of
//! Kani's reach (#1067): even a fixed one-byte symbolic input did not finish
//! in 20 minutes. Their totality is covered by the proptest and differential
//! tests instead.
//!
//! Bounds: a small symbolic input length per harness. Each harness's length
//! const records its measured CI time (Kani's "Verification Time", run
//! 40857677457). The unwind value is at least the input length plus two: the longest
//! byte loop in the unit runs once per byte, plus the exit check and the one
//! extra step of `take_while`/`get`.

use super::{Lexer, is_name_byte, is_name_start, starts_with_assignment};

/// A symbolic byte string of length at most `N`, together with its length.
fn symbolic_input<const N: usize>() -> ([u8; N], usize) {
    let len: usize = ::kani::any();
    ::kani::assume(len <= N);
    let bytes: [u8; N] = ::kani::any();
    (bytes, len)
}

/// Longest input of `io_number_any`. Measured CI time: 1.5 s.
const IO_NUMBER_LEN: usize = 4;

// Unwind: input length 4 plus 2.
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn io_number_any() {
    let (bytes, len) = symbolic_input::<IO_NUMBER_LEN>();
    let start: usize = ::kani::any();
    ::kani::assume(start <= len);
    let mut lexer = Lexer {
        input: &bytes[..len],
        pos: start,
    };
    match lexer.io_number() {
        Ok(Some(digit)) => {
            ::kani::cover!(true, "io_number finds a descriptor");
            assert!(digit <= 9);
            assert!(lexer.pos == start + 1);
        }
        Ok(None) => {
            ::kani::cover!(true, "io_number finds none");
            assert!(lexer.pos == start);
        }
        Err(e) => {
            ::kani::cover!(true, "io_number rejects");
            assert!(e.offset == start);
            assert!(lexer.pos == start);
        }
    }
}

/// Longest input of `escaped_byte_any`. Measured CI time: 0.3 s.
const ESCAPED_BYTE_LEN: usize = 3;

// Unwind: input length 3 plus 2 (the unit has no loop; the margin covers the
// `get` calls).
#[::kani::proof]
#[::kani::unwind(5)]
#[::kani::solver(cadical)]
fn escaped_byte_any() {
    let (bytes, len) = symbolic_input::<ESCAPED_BYTE_LEN>();
    let pos: usize = ::kani::any();
    ::kani::assume(pos < len);
    let lexer = Lexer {
        input: &bytes[..len],
        pos,
    };
    match lexer.escaped_byte() {
        Ok(c) => {
            ::kani::cover!(true, "escaped_byte accepts");
            assert!(pos + 1 < len);
            assert!(c == bytes[pos + 1]);
        }
        Err(e) => {
            ::kani::cover!(true, "escaped_byte rejects");
            assert!(e.offset == pos || e.offset == pos + 1);
            assert!(e.offset <= len);
        }
    }
}

/// Longest input of `name_at_any`. Measured CI time: 1.5 s.
const NAME_AT_LEN: usize = 4;

// Unwind: input length 4 plus 2 (`take_while` visits each byte once).
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn name_at_any() {
    let (bytes, len) = symbolic_input::<NAME_AT_LEN>();
    let from: usize = ::kani::any();
    // One past the end, to cover the out-of-range start.
    ::kani::assume(from <= len + 1);
    let lexer = Lexer {
        input: &bytes[..len],
        pos: 0,
    };
    let name = lexer.name_at(from);
    if name.is_empty() {
        ::kani::cover!(true, "name_at finds none");
    } else {
        ::kani::cover!(true, "name_at finds a name");
        assert!(from < len);
        assert!(name.len() <= len - from);
        assert!(is_name_start(name[0]));
        let mut i = 0;
        while i < name.len() {
            assert!(is_name_byte(name[i]));
            assert!(name[i] == bytes[from + i]);
            i += 1;
        }
    }
}

/// Longest input of `starts_with_assignment_any`. Measured CI time: 1.2 s.
const STARTS_WITH_ASSIGNMENT_LEN: usize = 5;

// Unwind: input length 5 plus 2 (`take_while` visits each byte once), plus 1
// for the `contains` scan below.
#[::kani::proof]
#[::kani::unwind(8)]
#[::kani::solver(cadical)]
fn starts_with_assignment_any() {
    let (bytes, len) = symbolic_input::<STARTS_WITH_ASSIGNMENT_LEN>();
    if starts_with_assignment(&bytes[..len]) {
        ::kani::cover!(true, "starts_with_assignment accepts");
        let mut found = false;
        let mut i = 0;
        while i < len {
            if bytes[i] == b'=' {
                found = true;
            }
            i += 1;
        }
        assert!(found);
    } else {
        ::kani::cover!(true, "starts_with_assignment rejects");
    }
}

/// Longest input of `single_quoted_any`. Measured CI time: 2.2 s.
const SINGLE_QUOTED_LEN: usize = 4;

// Unwind: input length 4 plus 2 (the scan loop runs once per byte; the
// `to_vec` copy is bounded by the same length).
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn single_quoted_any() {
    let (bytes, len) = symbolic_input::<SINGLE_QUOTED_LEN>();
    let pos: usize = ::kani::any();
    ::kani::assume(pos < len);
    ::kani::assume(bytes[pos] == b'\'');
    let mut lexer = Lexer {
        input: &bytes[..len],
        pos,
    };
    match lexer.single_quoted() {
        Ok(_) => {
            ::kani::cover!(true, "single_quoted accepts");
            assert!(lexer.pos >= 1);
            assert!(bytes[lexer.pos - 1] == b'\'');
            assert!(lexer.pos <= len);
        }
        Err(e) => {
            ::kani::cover!(true, "single_quoted rejects");
            assert!(e.offset < len);
        }
    }
}

/// Longest input of `dollar_in_quotes_any`. Measured CI time: 5.1 s.
const DOLLAR_IN_QUOTES_LEN: usize = 4;

// Unwind: input length 4 plus 2 (`name_at` visits each byte once; the
// `to_vec` copy is bounded by the same length).
#[::kani::proof]
#[::kani::unwind(6)]
#[::kani::solver(cadical)]
fn dollar_in_quotes_any() {
    let (bytes, len) = symbolic_input::<DOLLAR_IN_QUOTES_LEN>();
    let pos: usize = ::kani::any();
    ::kani::assume(pos < len);
    ::kani::assume(bytes[pos] == b'$');
    let mut lexer = Lexer {
        input: &bytes[..len],
        pos,
    };
    match lexer.dollar_in_quotes() {
        Ok(Some(name)) => {
            ::kani::cover!(true, "dollar_in_quotes finds a name");
            assert!(!name.is_empty());
            assert!(lexer.pos <= len);
        }
        Ok(None) => {
            ::kani::cover!(true, "dollar_in_quotes finds a literal dollar");
            assert!(lexer.pos == pos + 1);
        }
        Err(e) => {
            ::kani::cover!(true, "dollar_in_quotes rejects");
            assert!(e.offset == pos);
        }
    }
}
