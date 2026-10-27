//! (b) Two-level `Vec` loop invariants over the v1 word shape.

use creusot_std::prelude::*;

pub enum Part {
    Lit(Vec<u8>),
    Opaque(Vec<u8>),
}

pub struct Word {
    pub parts: Vec<Part>,
}

#[logic(open)]
pub fn is_lit(p: Part) -> bool {
    match p {
        Part::Lit(_) => true,
        Part::Opaque(_) => false,
    }
}

/// Every part of the word is a literal.
#[logic(open)]
pub fn word_lit(w: Word) -> bool {
    pearlite! { forall<j> 0 <= j && j < w.parts@.len() ==> is_lit(w.parts@[j]) }
}

/// Every part of every word is a literal.
#[logic(open)]
pub fn words_lit(ws: Seq<Word>) -> bool {
    pearlite! { forall<i> 0 <= i && i < ws.len() ==> word_lit(ws[i]) }
}

#[check(terminates)]
#[ensures(result == words_lit(ws@))]
#[must_use]
pub fn all_lit(ws: &[Word]) -> bool {
    let mut i: usize = 0;
    #[variant(ws@.len() - i@)]
    #[invariant(i@ <= ws@.len())]
    #[invariant(forall<k> 0 <= k && k < i@ ==> word_lit(ws@[k]))]
    while i < ws.len() {
        let parts = &ws[i].parts;
        let mut j: usize = 0;
        #[variant(parts@.len() - j@)]
        #[invariant(j@ <= parts@.len())]
        #[invariant(forall<k> 0 <= k && k < j@ ==> is_lit(parts@[k]))]
        while j < parts.len() {
            match &parts[j] {
                Part::Lit(_) => {}
                Part::Opaque(_) => return false,
            }
            j += 1;
        }
        i += 1;
    }
    true
}

#[check(terminates)]
#[ensures(result == (a@ == b@))]
#[must_use]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    #[variant(a@.len() - i@)]
    #[invariant(i@ <= a@.len())]
    #[invariant(forall<k> 0 <= k && k < i@ ==> a@[k] == b@[k])]
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    proof_assert!(a@.ext_eq(b@));
    true
}
