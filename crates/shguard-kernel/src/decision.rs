//! The decision lattice `Allow < Ask < Block`, with `join` as its maximum
//! (theorem T1).
//!
//! The lattice laws are proved on the logic mirror `join_l`; `join` is tied
//! to it by its contract.

#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// The hook's answer for a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Decision {
    /// Run the command without asking.
    Allow,
    /// Ask the user before running the command.
    Ask,
    /// Refuse to run the command.
    Block,
}

/// Position of a decision in the total order.
#[cfg(creusot)]
#[logic(open)]
pub fn rank(d: Decision) -> Int {
    match d {
        Decision::Allow => 0,
        Decision::Ask => 1,
        Decision::Block => 2,
    }
}

/// `a` is no stricter than `b`.
#[cfg(creusot)]
#[logic(open)]
pub fn le(a: Decision, b: Decision) -> bool {
    rank(a) <= rank(b)
}

/// Logical join, so lemmas can talk about `join` without calling a program
/// function.
#[cfg(creusot)]
#[logic(open)]
pub fn join_l(a: Decision, b: Decision) -> Decision {
    if rank(a) >= rank(b) { a } else { b }
}

/// The stricter of two decisions.
#[cfg_attr(creusot, check(ghost))]
#[cfg_attr(creusot, ensures(rank(result) == rank(a).max(rank(b))))]
#[cfg_attr(creusot, ensures(result == join_l(a, b)))]
#[must_use]
pub fn join(a: Decision, b: Decision) -> Decision {
    match (a, b) {
        (Decision::Block, _) | (_, Decision::Block) => Decision::Block,
        (Decision::Ask, _) | (_, Decision::Ask) => Decision::Ask,
        (Decision::Allow, Decision::Allow) => Decision::Allow,
    }
}

/// `rank` is injective, so equal ranks mean equal decisions.
#[cfg(creusot)]
#[logic]
#[ensures(rank(a) == rank(b) ==> a == b)]
pub fn lemma_rank_injective(a: Decision, b: Decision) {}

/// `join` is commutative.
#[cfg(creusot)]
#[logic]
#[ensures(join_l(a, b) == join_l(b, a))]
pub fn lemma_join_comm(a: Decision, b: Decision) {}

/// `join` is associative.
#[cfg(creusot)]
#[logic]
#[ensures(join_l(join_l(a, b), c) == join_l(a, join_l(b, c)))]
pub fn lemma_join_assoc(a: Decision, b: Decision, c: Decision) {}

/// `join` is idempotent.
#[cfg(creusot)]
#[logic]
#[ensures(join_l(a, a) == a)]
pub fn lemma_join_idem(a: Decision) {}

/// `Allow` is the identity of `join`.
#[cfg(creusot)]
#[logic]
#[ensures(join_l(Decision::Allow, a) == a)]
pub fn lemma_allow_identity(a: Decision) {}

/// `Block` absorbs everything under `join`.
#[cfg(creusot)]
#[logic]
#[ensures(join_l(Decision::Block, a) == Decision::Block)]
pub fn lemma_block_absorbs(a: Decision) {}

/// `join` never lowers its left argument.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, join_l(a, b)))]
pub fn lemma_le_join(a: Decision, b: Decision) {}

/// `le` is reflexive.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, a))]
pub fn lemma_le_refl(a: Decision) {}

/// `le` is transitive.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, b) && le(b, c) ==> le(a, c))]
pub fn lemma_le_trans(a: Decision, b: Decision, c: Decision) {}

/// `le` is antisymmetric.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, b) && le(b, a) ==> a == b)]
pub fn lemma_le_antisym(a: Decision, b: Decision) {}

/// `join` is the least upper bound: any common upper bound dominates it.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, c) && le(b, c) ==> le(join_l(a, b), c))]
pub fn lemma_join_lub(a: Decision, b: Decision, c: Decision) {}

/// `join` is monotone in the left argument; the right follows by
/// `lemma_join_comm`.
#[cfg(creusot)]
#[logic]
#[ensures(le(a, a2) ==> le(join_l(a, b), join_l(a2, b)))]
pub fn lemma_join_monotone(a: Decision, a2: Decision, b: Decision) {}

#[cfg(test)]
mod tests {
    use super::{Decision, join};

    #[test]
    fn join_table() {
        use Decision::{Allow, Ask, Block};
        let table = [
            (Allow, Allow, Allow),
            (Allow, Ask, Ask),
            (Allow, Block, Block),
            (Ask, Allow, Ask),
            (Ask, Ask, Ask),
            (Ask, Block, Block),
            (Block, Allow, Block),
            (Block, Ask, Block),
            (Block, Block, Block),
        ];
        for (a, b, want) in table {
            assert_eq!(join(a, b), want, "join({a:?}, {b:?})");
        }
    }
}
