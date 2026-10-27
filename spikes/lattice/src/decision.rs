//! (a) The verdict lattice: `Allow < Ask < Block`, `join` = max.

use creusot_std::prelude::{Clone, PartialEq, *};

#[derive(Clone, Copy, Debug, PartialEq, Eq, DeepModel)]
pub enum Decision {
    Allow,
    Ask,
    Block,
}

/// Position of a decision in the total order.
#[logic(open)]
pub fn rank(d: Decision) -> Int {
    match d {
        Decision::Allow => 0,
        Decision::Ask => 1,
        Decision::Block => 2,
    }
}

/// `a` is no stricter than `b`.
#[logic(open)]
pub fn le(a: Decision, b: Decision) -> bool {
    rank(a) <= rank(b)
}

/// Logical join, so lemmas can talk about `join` without calling a program fn.
#[logic(open)]
pub fn join_l(a: Decision, b: Decision) -> Decision {
    if rank(a) >= rank(b) { a } else { b }
}

#[check(ghost)]
#[ensures(rank(result) == rank(a).max(rank(b)))]
#[ensures(result == join_l(a, b))]
pub fn join(a: Decision, b: Decision) -> Decision {
    match (a, b) {
        (Decision::Block, _) | (_, Decision::Block) => Decision::Block,
        (Decision::Ask, _) | (_, Decision::Ask) => Decision::Ask,
        (Decision::Allow, Decision::Allow) => Decision::Allow,
    }
}

/// `rank` is injective, so equal ranks mean equal decisions.
#[logic]
#[ensures(rank(a) == rank(b) ==> a == b)]
pub fn lemma_rank_injective(a: Decision, b: Decision) {}

#[logic]
#[ensures(join_l(a, b) == join_l(b, a))]
pub fn lemma_join_comm(a: Decision, b: Decision) {}

#[logic]
#[ensures(join_l(join_l(a, b), c) == join_l(a, join_l(b, c)))]
pub fn lemma_join_assoc(a: Decision, b: Decision, c: Decision) {}

#[logic]
#[ensures(join_l(a, a) == a)]
pub fn lemma_join_idem(a: Decision) {}

#[logic]
#[ensures(join_l(Decision::Allow, a) == a)]
pub fn lemma_allow_identity(a: Decision) {}

#[logic]
#[ensures(join_l(Decision::Block, a) == Decision::Block)]
pub fn lemma_block_absorbs(a: Decision) {}

#[logic]
#[ensures(le(a, join_l(a, b)))]
pub fn lemma_le_join(a: Decision, b: Decision) {}

#[logic]
#[ensures(le(a, a))]
pub fn lemma_le_refl(a: Decision) {}

#[logic]
#[ensures(le(a, b) && le(b, c) ==> le(a, c))]
pub fn lemma_le_trans(a: Decision, b: Decision, c: Decision) {}

#[logic]
#[ensures(le(a, b) && le(b, a) ==> a == b)]
pub fn lemma_le_antisym(a: Decision, b: Decision) {}

/// `join` is the least upper bound: any common upper bound dominates it.
#[logic]
#[ensures(le(a, c) && le(b, c) ==> le(join_l(a, b), c))]
pub fn lemma_join_lub(a: Decision, b: Decision, c: Decision) {}

/// `join` is monotone (in the left argument; right follows by `lemma_join_comm`).
#[logic]
#[ensures(le(a, a2) ==> le(join_l(a, b), join_l(a2, b)))]
pub fn lemma_join_monotone(a: Decision, a2: Decision, b: Decision) {}
