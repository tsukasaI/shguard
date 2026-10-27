//! (c') Arena encoding of a rose tree: children live at strictly later
//! indices of one flat `Vec`, so the executable checker is two index loops
//! (no recursion) and only the logic spec recurses, on `len - k`.

use creusot_std::prelude::{vec, *};

pub enum Node2 {
    Leaf(u8),
    /// Children are `nodes[first .. first + len]`, all strictly after this
    /// node's own index.
    Node {
        first: usize,
        len: usize,
    },
}

pub struct Tree {
    pub nodes: Vec<Node2>,
}

#[logic(open)]
pub fn leaf_ok(v: u8) -> bool {
    pearlite! { v@ < 10 }
}

/// Well-formedness: every child range is in bounds and strictly after its
/// parent. This is what makes `ok_at` terminate.
#[logic(open)]
pub fn wf(s: Seq<Node2>) -> bool {
    pearlite! {
        forall<k> 0 <= k && k < s.len() ==> match s[k] {
            Node2::Leaf(_) => true,
            Node2::Node { first, len } => k < first@ && first@ + len@ <= s.len(),
        }
    }
}

/// Every leaf reachable from node `k` satisfies `leaf_ok`.
#[logic(open)]
#[requires(wf(s))]
#[requires(0 <= k && k < s.len())]
#[variant(s.len() - k)]
pub fn ok_at(s: Seq<Node2>, k: Int) -> bool {
    pearlite! {
        match s[k] {
            Node2::Leaf(v) => leaf_ok(v),
            Node2::Node { first, len } =>
                forall<c> first@ <= c && c < first@ + len@ ==> ok_at(s, c),
        }
    }
}

/// An ok node has only ok children (by unfolding `ok_at` once).
#[logic]
#[requires(wf(s))]
#[requires(0 <= k && k < s.len())]
#[requires(ok_at(s, k))]
#[ensures(match s[k] {
    Node2::Leaf(_) => true,
    Node2::Node { first, len } => forall<c> first@ <= c && c < first@ + len@ ==> ok_at(s, c),
})]
pub fn lemma_child_ok(s: Seq<Node2>, k: Int) {}

/// Bottom-up evaluation: `good[k]` is computed after every `good[c]` with
/// `c > k`, so each node reads only already-final children.
///
/// Not `#[check(terminates)]`: `vec![false; n]` calls `std::vec::from_elem`,
/// which 0.14 rejects in a terminates context ("called program function
/// `std::vec::from_elem` in program (terminates) context"). Allocation is
/// never `terminates` in creusot-std; the loop variants are still proved.
#[requires(wf(tree.nodes@))]
#[requires(tree.nodes@.len() > 0)]
#[ensures(result == ok_at(tree.nodes@, 0))]
pub fn check(tree: &Tree) -> bool {
    let nodes = &tree.nodes;
    let n = nodes.len();
    let mut good: Vec<bool> = vec![false; n];
    let mut k = n;
    #[variant(k@)]
    #[invariant(k@ <= n@)]
    #[invariant(good@.len() == n@)]
    #[invariant(forall<j> k@ <= j && j < n@ ==> good@[j] == ok_at(nodes@, j))]
    while k > 0 {
        k -= 1;
        let g = match &nodes[k] {
            Node2::Leaf(v) => *v < 10,
            Node2::Node { first, len } => {
                let end = *first + *len;
                let mut c = *first;
                let mut all = true;
                #[variant(end@ - c@)]
                #[invariant(first@ <= c@ && c@ <= end@)]
                #[invariant(all == (forall<d> first@ <= d && d < c@ ==> ok_at(nodes@, d)))]
                while c < end {
                    all = all && good[c];
                    c += 1;
                }
                all
            }
        };
        good[k] = g;
    }
    good[0]
}
