//! (d) Sealed witness: an `Allow` verdict can only be built by `certify`,
//! and its type invariant carries the proof that every word is literal.

#[cfg(creusot)]
use crate::words::words_lit;
use crate::words::{Word, all_lit};
use creusot_std::prelude::*;

/// Proof-carrying token. `_sealed` is private, so no code outside this
/// module can construct one; `words` is a ghost snapshot (zero-sized in a
/// normal build) of the input `certify` checked.
#[expect(
    clippy::manual_non_exhaustive,
    reason = "non_exhaustive seals only across crates; _sealed seals the module"
)]
pub struct Witness {
    _sealed: (),
    pub words: Snapshot<Seq<Word>>,
}

impl Invariant for Witness {
    #[logic(open)]
    fn invariant(self) -> bool {
        pearlite! { words_lit(*self.words) }
    }
}

pub enum Verdict {
    Allow(Witness),
    Ask,
}

/// The only constructor of `Witness`.
#[check(terminates)]
#[ensures(match result {
    Some(w) => *w.words == ws@,
    None => !words_lit(ws@),
})]
pub fn certify(ws: &[Word]) -> Option<Witness> {
    if all_lit(ws) {
        Some(Witness {
            _sealed: (),
            words: snapshot!(ws@),
        })
    } else {
        None
    }
}

#[check(terminates)]
#[ensures(match result {
    Verdict::Allow(w) => *w.words == ws@ && words_lit(ws@),
    Verdict::Ask => !words_lit(ws@),
})]
pub fn decide(ws: &[Word]) -> Verdict {
    match certify(ws) {
        Some(w) => Verdict::Allow(w),
        None => Verdict::Ask,
    }
}
