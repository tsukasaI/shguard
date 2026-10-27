//! Negative controls: every item here MUST fail to prove. Compiled only
//! under `#[cfg(all(creusot, shguard_mutants))]` (see `lib.rs` and
//! `spikes/README.md` for the command), so they never break the default run
//! but cannot rot unnoticed when switched on.
//!
//! There are three controls: the two below, plus `witness::mutant_forge`,
//! which must live inside `witness.rs` because `Witness::_sealed` is
//! private. Observed (M1): all three fail.

use crate::decision::{Decision, join_l};
use creusot_std::prelude::*;

/// False lattice law -> `vc_mutant_false_lemma ✘`.
#[logic]
#[ensures(join_l(a, b) == a)]
pub fn mutant_false_lemma(a: Decision, b: Decision) {}

/// Non-decreasing variant in a function WITHOUT `#[check(terminates)]`
/// -> `vc_mutant_spin ✘ (1/2)`: loop variants are proved regardless.
pub fn mutant_spin(mut x: u32) {
    #[variant(x@)]
    while x > 0 {
        let unchanged = x;
        x = unchanged;
    }
}
