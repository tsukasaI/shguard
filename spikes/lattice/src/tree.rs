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

pub enum T {
    Leaf(u8),
    /// A node: `Node(first_child, rest)`, where `rest` is itself a node
    /// holding the remaining siblings (or `Nil`).
    Node(Box<T>, Box<T>),
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
pub fn ok(t: T) -> bool {
    match t {
        T::Leaf(v) => leaf_ok(v),
        T::Node(h, tl) => ok(*h) && ok(*tl),
        T::Nil => true,
    }
}

/// Termination measure for the executable walker.
#[logic(open)]
#[ensures(result >= 1)]
pub fn size(t: T) -> Int {
    match t {
        T::Leaf(_) => 1,
        T::Node(h, tl) => size(*h) + size(*tl) + 1,
        T::Nil => 1,
    }
}

/// Number of children of a node (length of its sibling spine).
#[logic(open)]
#[ensures(result >= 0)]
pub fn len(t: T) -> Int {
    match t {
        T::Node(_, tl) => len(*tl) + 1,
        T::Leaf(_) | T::Nil => 0,
    }
}

/// The `i`-th child of a node.
#[logic(open)]
#[requires(0 <= i && i < len(t))]
pub fn child(t: T, i: Int) -> T {
    match t {
        T::Node(h, tl) => {
            if i == 0 {
                *h
            } else {
                child(*tl, i - 1)
            }
        }
        T::Leaf(_) | T::Nil => T::Nil,
    }
}

/// Structural induction on the spine: an ok node has only ok children.
#[logic]
#[requires(ok(t))]
#[requires(0 <= i && i < len(t))]
#[ensures(ok(child(t, i)))]
pub fn lemma_child_ok(t: T, i: Int) {
    match t {
        T::Node(_, tl) => {
            if i != 0 {
                lemma_child_ok(*tl, i - 1)
            }
        }
        T::Leaf(_) | T::Nil => (),
    }
}

/// A well-formed sibling spine: `Node(_, Node(_, .. Nil))`. The encoding
/// can represent `Node(_, Leaf(_))`, which has no meaning; the converse lemma
/// below needs this predicate to exclude it (first attempt, requiring only
/// "not a Leaf" at the top, failed: `vc_lemma_children_ok ✘ (7/8)`).
#[logic(open)]
pub fn is_spine(t: T) -> bool {
    match t {
        T::Node(_, tl) => is_spine(*tl),
        T::Nil => true,
        T::Leaf(_) => false,
    }
}

/// Converse direction: a node whose children are all ok is ok.
#[logic]
#[requires(forall<i> 0 <= i && i < len(t) ==> ok(child(t, i)))]
#[requires(is_spine(t))]
#[ensures(ok(t))]
pub fn lemma_children_ok(t: T) {
    match t {
        T::Node(_, tl) => {
            pearlite! { proof_assert!(forall<i> 0 <= i && i < len(*tl) ==> child(*tl, i) == child(t, i + 1)) };
            lemma_children_ok(*tl)
        }
        T::Leaf(_) | T::Nil => (),
    }
}

#[check(terminates)]
#[variant(size(*t))]
#[ensures(result == ok(*t))]
pub fn check(t: &T) -> bool {
    match t {
        T::Leaf(v) => *v < 10,
        T::Node(h, tl) => check(h) && check(tl),
        T::Nil => true,
    }
}
