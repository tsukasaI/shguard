//! (d) A downstream module that only sees `Verdict`. Neither function has a
//! precondition tying `v` to any input, yet both can use the witness
//! invariant, because Creusot adds `inv(*v)` as an implicit precondition.

use crate::witness::Verdict;
#[cfg(creusot)]
use crate::words::Part;
#[cfg(creusot)]
use crate::words::words_lit;
use creusot_std::prelude::*;

/// The postcondition `words_lit(..)` is provable only from the invariant.
#[check(terminates)]
#[ensures(match *v {
    Verdict::Allow(w) => result && words_lit(*w.words),
    Verdict::Ask => !result,
})]
pub fn is_allow(v: &Verdict) -> bool {
    match v {
        Verdict::Allow(_) => true,
        Verdict::Ask => false,
    }
}

/// Pointwise use: any in-range part of an allowed verdict is `Lit`.
#[check(terminates)]
#[requires(match *v {
    Verdict::Allow(w) => i@ < w.words.len() && j@ < w.words[i@].parts@.len(),
    Verdict::Ask => true,
})]
#[cfg_attr(
    not(creusot),
    expect(unused_variables, reason = "i, j are spec-only; contracts are erased")
)]
pub fn part_is_lit(v: &Verdict, i: usize, j: usize) -> bool {
    match v {
        Verdict::Allow(w) => {
            proof_assert!(match w.words[i@].parts@[j@] {
                Part::Lit(_) => true,
                Part::Opaque(_) => false,
            });
            true
        }
        Verdict::Ask => false,
    }
}
