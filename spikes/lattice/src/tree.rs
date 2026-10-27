//! (c) Nested recursion.
//!
//! Attempts that Creusot 0.14 rejects at translation time (see README):
//! - `enum T { Leaf(u8), Node(Vec<T>) }`: "Illegal recursive type ...
//!   Recursive occurrence of tree::T under parameter 0 of type
//!   `std::vec::Vec`".
//! - Two types `T { Leaf, Node(Forest) }` / `Forest { Nil, Cons(Box<T>,
//!   Box<Forest>) }`: the types are accepted, but every function over them
//!   is mutually recursive (`ok`/`ok_forest`), which is rejected with
//!   "Mutually recursive functions: when calling `tree::ok_forest`...".
//!
//! What works: one self-recursive type whose children form a cons spine
//! under `Box` (transparent in the logic), so `ok` and `size` are
//! structurally recursive and `check` recurses with `#[variant(size(..))]`.

use creusot_std::prelude::*;

pub enum ConsTree {
    Leaf(u8),
    /// A node: `Node(first_child, rest)`, where `rest` is itself a node
    /// holding the remaining siblings (or `Nil`).
    Node(Box<ConsTree>, Box<ConsTree>),
    /// The empty node / end of a sibling spine.
    Nil,
}

/// Leaf predicate standing in for "this part is covered".
#[logic(open)]
pub fn leaf_ok(v: u8) -> bool {
    pearlite! { v@ < 10 }
}

/// Every leaf satisfies `leaf_ok`.
#[logic(open)]
pub fn ok(t: ConsTree) -> bool {
    match t {
        ConsTree::Leaf(v) => leaf_ok(v),
        ConsTree::Node(h, tl) => ok(*h) && ok(*tl),
        ConsTree::Nil => true,
    }
}

/// Termination measure for the executable walker.
#[logic(open)]
#[ensures(result >= 1)]
pub fn size(t: ConsTree) -> Int {
    match t {
        ConsTree::Leaf(_) => 1,
        ConsTree::Node(h, tl) => size(*h) + size(*tl) + 1,
        ConsTree::Nil => 1,
    }
}

/// Number of children of a node (length of its sibling spine).
#[logic(open)]
#[ensures(result >= 0)]
pub fn len(t: ConsTree) -> Int {
    match t {
        ConsTree::Node(_, tl) => len(*tl) + 1,
        ConsTree::Leaf(_) | ConsTree::Nil => 0,
    }
}

/// The `i`-th child of a node.
#[logic(open)]
#[requires(0 <= i && i < len(t))]
pub fn child(t: ConsTree, i: Int) -> ConsTree {
    match t {
        ConsTree::Node(h, tl) => {
            if i == 0 {
                *h
            } else {
                child(*tl, i - 1)
            }
        }
        ConsTree::Leaf(_) | ConsTree::Nil => ConsTree::Nil,
    }
}

/// Structural induction on the spine: an ok node has only ok children.
#[logic]
#[requires(ok(t))]
#[requires(0 <= i && i < len(t))]
#[ensures(ok(child(t, i)))]
pub fn lemma_child_ok(t: ConsTree, i: Int) {
    match t {
        ConsTree::Node(_, tl) => {
            if i != 0 {
                lemma_child_ok(*tl, i - 1)
            }
        }
        ConsTree::Leaf(_) | ConsTree::Nil => (),
    }
}

/// A well-formed sibling spine: `Node(_, Node(_, .. Nil))`. The encoding
/// can represent `Node(_, Leaf(_))`, which has no meaning; the converse lemma
/// below needs this predicate to exclude it (first attempt, requiring only
/// "not a Leaf" at the top, failed: `vc_lemma_children_ok ✘ (7/8)`).
#[logic(open)]
pub fn is_spine(t: ConsTree) -> bool {
    match t {
        ConsTree::Node(_, tl) => is_spine(*tl),
        ConsTree::Nil => true,
        ConsTree::Leaf(_) => false,
    }
}

/// Converse direction: a node whose children are all ok is ok.
#[logic]
#[requires(forall<i> 0 <= i && i < len(t) ==> ok(child(t, i)))]
#[requires(is_spine(t))]
#[ensures(ok(t))]
pub fn lemma_children_ok(t: ConsTree) {
    match t {
        ConsTree::Node(_, tl) => {
            pearlite! { proof_assert!(forall<i> 0 <= i && i < len(*tl) ==> child(*tl, i) == child(t, i + 1)) };
            lemma_children_ok(*tl)
        }
        ConsTree::Leaf(_) | ConsTree::Nil => (),
    }
}

#[check(terminates)]
#[variant(size(*t))]
#[ensures(result == ok(*t))]
#[must_use]
pub fn check(t: &ConsTree) -> bool {
    match t {
        ConsTree::Leaf(v) => *v < 10,
        ConsTree::Node(h, tl) => check(h) && check(tl),
        ConsTree::Nil => true,
    }
}
