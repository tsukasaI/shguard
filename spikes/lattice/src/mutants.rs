//! Negative controls: every item here MUST fail to prove. Not part of the
//! crate by default; enable with `#[cfg(creusot)] pub mod mutants;` in
//! `lib.rs` and run `cargo creusot 'mutants::*'` to confirm the provers are
//! not vacuously succeeding. Observed (M1): all three fail.
//!
//! A fourth control, forging a `Witness` without `certify`, has to live
//! inside `witness.rs` (the field is private):
//! `Witness { _sealed: (), words: snapshot!(*ws) }` -> `vc_mutant_forge ✘`.

use crate::decision::{Decision, join_l};
use creusot_std::prelude::*;

/// False lattice law -> `vc_mutant_false_lemma ✘`.
#[logic]
#[ensures(join_l(a, b) == a)]
pub fn mutant_false_lemma(a: Decision, b: Decision) {}

/// Non-decreasing variant in a function WITHOUT `#[check(terminates)]`
/// -> `vc_mutant_spin ✘ (1/2)`: loop variants are proved regardless.
#[allow(clippy::self_assignment, clippy::assign_op_pattern)]
pub fn mutant_spin(mut x: u32) {
    #[variant(x@)]
    while x > 0 {
        x = x;
    }
}
