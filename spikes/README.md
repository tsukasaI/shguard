# M1 ADR: Creusot 0.14 proof spike

Status: accepted (spike done). Toolchain: Creusot 0.14.0 (nix `creusot-wrapped`,
nightly rustc 1.99.0-nightly 2026-08-02), why3find with alt-ergo / z3 / cvc5 / cvc4.

## Layout

One crate, `lattice/`, with one module per deliverable. That means one
`why3find.json`, one `verif/` tree and one replay command. Separate crates
would buy nothing because Creusot already gives each function its own `.coma`
and `proof.json`, and `cargo creusot 'mod::*'` proves one module.

| Module | Deliverable | Result | Cold prove (`--no-cache`, wall) |
|---|---|---|---|
| `decision.rs` | (a) lattice + 12 lemmas | proved | 1.9 s |
| `words.rs` | (b) nested index loops, `bytes_eq` | proved | 1.0 s |
| `tree.rs` | (c) recursion: `Vec<Self>` **rejected**; Box cons-spine proved | partial | 1.1 s |
| `arena.rs` | (c') arena, index loops, no recursion | proved | 1.0 s |
| `witness.rs` + `consumer.rs` | (d) sealed `Witness` + `Invariant` + `Snapshot` | proved | 0.9 + 1.0 s |
| `mutants.rs` + `witness::mutant_forge` | 3 negative controls (cfg `shguard_mutants`, off by default) | all fail as intended | n/a |

The whole crate takes 6.0 s wall cold (33 files, 28 s CPU). The cached replay
is about the same.

## Confirmed 0.14 spellings

- Import: `use creusot_std::prelude::*;`. With `#[derive(Clone)]` or `vec![]`
  you must write `use creusot_std::prelude::{Clone, *};` or `{vec, *}`.
  Otherwise you get E0659 "`Clone` is ambiguous", because the creusot derive
  or macro clashes with std's prelude.
- Logic functions:
  - `#[logic]` keeps the body opaque outside the module. `#[logic(open)]`
    exposes it.
  - Bodies with quantifiers or `==>` need `pearlite! { .. }`. Plain
    `match`/`&&` work without it.
- Lemmas: `#[logic] #[requires(..)] #[ensures(..)] pub fn lemma_x(args) {}`.
  - An inductive lemma is a recursive `#[logic]` fn that calls itself.
    Structural recursion needs no variant.
  - You cannot write `forall<..> { lemma(..); true }` in a `()`-returning
    lemma (E0308). State the lemma with parameters instead.
- Termination:
  - `#[check(terminates)]` on program fns. This works with loops and with
    self-recursion, despite the stale doc that says it does not.
  - `#[variant(e)]` goes on loops, recursive program fns and recursive logic
    fns.
  - Loop variants are proved even without `terminates`: mutant
    `vc_mutant_spin ✘ (1/2)`.
  - `vec![x; n]` (→ `std::vec::from_elem`) is **not** terminates; `Vec::new`
    and `push` are (see M3's `normalize_path`). The error is "called program
    function `std::vec::from_elem` in program (terminates) context".
- Ghost: `#[check(ghost)]` (used on `join`).
- Loop invariants: `#[invariant(..)]` placed directly on `while`.
- Quantifiers: `forall<i> 0 <= i && i < s.len() ==> ..`, or with types:
  `forall<f: Forest, i: Int>`. `exists<..>` uses the same syntax.
- Views:
  - `v@` turns `Vec<T>`/`&[T]` into `Seq<T>`, and `usize`/`u8` into `Int`.
  - `s[i]` and `s.len()` work on `Seq`.
  - `a@.ext_eq(b@)` proves sequence equality.
  - `Int::max`: `rank(a).max(rank(b))`.
- Int and usize: write `i@` in specs and `ws@.len() - i@` in variants. No
  casts are needed.
- Snapshot:
  - Create one with `snapshot!(ws@)`; the type is `Snapshot<Seq<Word>>`.
  - Read it in logic with `*w.words`. `w.words[i@]` auto-derefs.
  - It is zero-sized (`PhantomData`) in a normal build.
- `proof_assert!(..)` takes pearlite inside program code.
- Invariant:
  `impl Invariant for W { #[logic(open)] fn invariant(self) -> bool { .. } }`.
  Creusot adds `inv` as a pre- and postcondition everywhere, including
  `inv(*v)` for `v: &Verdict` through the enum and its fields.
- Recursive types: see (c). Mutually recursive functions are rejected
  outright.

## Results

**(a) Proved.**
- `join` carries `#[ensures(rank(result) == rank(a).max(rank(b)))]` and
  `result == join_l(a, b)`.
- The lemmas are stated on the logic mirror `join_l`: comm, assoc, idem,
  Allow identity, Block absorbs, `le(a, join(a,b))`, and le
  refl/trans/antisym, plus `rank` injectivity.
- Also proved: least upper bound
  (`le(a,c) ∧ le(b,c) ⇒ le(join(a,b), c)`) and monotonicity
  (`le(a,a2) ⇒ le(join(a,b), join(a2,b))`).
- `Decision` derives `Clone, Copy, Debug, PartialEq, Eq, DeepModel`.
  - Creusot's `PartialEq` derive requires `DeepModel`; without it you get
    E0277 "`Decision: DeepModel` is not satisfied".
  - `PartialOrd`/`Ord` are left out: creusot-std's `Ord` spec requires
    `DeepModelTy: OrdLogic`, and the derived deep model has no `OrdLogic`.
    Adding one means a hand-written `OrdLogic` impl with its laws; the
    lattice order lives in `rank`/`le` instead.

**(b) Proved on the first try.**
- `all_lit` uses nested index `while` loops with the per-level invariant
  `forall<k> k < i@ ==> word_lit(ws@[k])`.
- `bytes_eq` ensures `result == (a@ == b@)`, closed by `ext_eq`.

**(c) Partial: the requested encoding fails at translation, before any VC.**
- `enum T { Leaf(u8), Node(Vec<T>) }` fails with
  `error: Illegal recursive type ... Recursive occurrence of tree::T under parameter 0 of type std::vec::Vec`.
- The same error hits `Vec<Box<T>>` and `Box<[T]>` ("under slice"), and even
  a user-defined `List<Box<T>>` ("under parameter 0 of type tree::List").
  Creusot forbids recursion nested under *any* type parameter.
- `Option<Box<T>>` and a direct `Box<T>` are accepted.
- Two mutually recursive ADTs (`T`/`Forest`) are accepted as types. But every
  function over them is mutually recursive, and that is rejected:
  `error: Mutually recursive functions: when calling tree::ok_forest...`.
- What proved is a single self-recursive type,
  `ConsTree { Leaf(u8), Node(Box<ConsTree>, Box<ConsTree>), Nil }`, where
  children form a cons spine:
  - `ok`, `size`, `len` and `child` are structurally recursive with no
    variant.
  - `check` is self-recursive with `#[check(terminates)] #[variant(size(*t))]`
    and `ensures(result == ok(*t))`.
  - `lemma_child_ok` (`ok(t) ∧ i < len(t) ⇒ ok(child(t,i))`) is proved by
    structural induction.
  - The converse first failed (`vc_lemma_children_ok ✘ (7/8)`), because the
    encoding admits the meaningless `Node(_, Leaf)`. It needed an extra
    `is_spine` well-formedness predicate.

**(c') Proved on the first try.**
- The tree is `Tree { nodes: Vec<ArenaNode> }`, where
  `ArenaNode::Node { first, len }` points to strictly later indices.
- `wf(s)` is a quantified bounds/ordering predicate.
- `ok_at(s, k)` is a logic fn that recurses inside a `forall`, with
  `#[variant(s.len() - k)]`.
- `check` is two index loops that fill `good[k]` from the back. It is not
  terminates because it calls `vec!`, but its variants are proved.

**(d) Proved, with no fallback needed.**
- The type is `Witness { _sealed: (), pub words: Snapshot<Seq<Word>> }`, with
  `Invariant = words_lit(*self.words)`.
- `certify` ensures `Some(w) ⇒ *w.words == ws@` and `None ⇒ !words_lit(ws@)`.
- `decide` builds `Verdict::{Allow(Witness), Ask}` only through `certify`.
- In `consumer.rs`, a separate module with no precondition linking `v` to
  inputs:
  - `is_allow` proves `Allow(w) ⇒ words_lit(*w.words)`.
  - `part_is_lit` ensures `Allow(w) ⇒ result ∧ is_lit(w.words[i].parts[j])`
    for any in-range `i`, `j`.
  - Both proofs rely only on the implicit `inv(*v)`.
- Forging `Witness { .. snapshot!(ws@) }` without the check fails:
  `vc_mutant_forge ✘`.
- The field is `pub` because pearlite obeys Rust privacy. With it private,
  `consumer.rs` specs fail with `E0616: field words of struct
  witness::Witness is private`. A private field plus an `open` logic
  accessor was not tried. Construction stays sealed by `_sealed`.
  `#[non_exhaustive]` would only seal across crates, which is enough for a
  separate kernel crate.

## Negative controls

`src/mutants.rs` (a false lattice law, a loop whose variant never decreases)
and `witness::mutant_forge` (a `Witness` built without `all_lit`) sit behind
`#[cfg(all(creusot, shguard_mutants))]`. They are declared in `lib.rs` so
`cargo creusot` with `--cfg shguard_mutants` picks them up; no other build
compiles them. `shguard_mutants` is in
`Cargo.toml`'s `unexpected_cfgs` check-cfg list. There is no cargo feature.
Run them with:

```
RUSTFLAGS="--cfg shguard_mutants" cargo creusot --span-mode relative 'mutants::*' 'witness::mutant_forge'
```

The run **must fail** with exactly `vc_mutant_false_lemma ✘`,
`vc_mutant_forge ✘` and `vc_mutant_spin ✘ (1/2)` ("3 unproved files").
Observed in M1: exactly these three fail.

Changing `RUSTFLAGS` rebuilds creusot-std. The run leaves `verif/` entries
for the mutants. A plain `cargo creusot` afterwards does **not** retranslate,
because cargo's no-flags build is still fresh, so the mutants keep failing.
Force a retranslation, then clean:

```
touch src/lib.rs && cargo creusot --only coma && echo y | cargo creusot clean
```

## Files to commit and how proofs run

- **Commit:** `src/`, `Cargo.toml`, `Cargo.lock` (registry form) and
  `why3find.json`.
- **Ignore:** `target/`, `verif/` and `.why3find/` (#1005). Even with
  `--span-mode relative`, `verif/*.coma` embeds `../`-relative spans into
  wherever `creusot-std` lives (the nix store, or `~/.cargo/registry` with a
  registry-form lockfile), so the files change with the checkout path and
  would leak the home directory. Every gate re-proves from source instead.
- **Prove:** `cargo creusot --span-mode relative` (about 6 s for this crate).
  `--replay` only works against a local `verif/` from an earlier run.
  Re-prove one module with `cargo creusot 'tree::*'`.
- **Clean up after renames:** run `cargo creusot clean` after removing
  functions. It is interactive, so `echo y |` works; otherwise stale
  `verif/` dirs linger as "dangling" warnings.
- **Lockfile:** `cargo creusot` can rewrite `Cargo.lock` to the patched nix
  `creusot-std` (no `source`/`checksum`). The committed form is the registry
  one (#1009); restore it before committing.

## Stable build

`cargo build` and `cargo clippy` pass on stable rustc 1.93.1, the toolchain
installed here (not 1.99, which is the nix nightly). Contracts, logic fns and
`#[invariant]`/`#[variant]` on `while` are erased. The gotchas:

- `use` of a logic-only item fails with E0432, because the item is erased.
  Gate it with `#[cfg(creusot)] use ..`.
- Parameters used only in specs warn `unused_variables`. Use
  `#[cfg_attr(not(creusot), expect(unused_variables, reason = ".."))]`.
- Clippy reports `ptr_arg` for `&Vec`, so use `&[T]`, which Creusot handles
  fine. It reports `manual_non_exhaustive` for `_sealed: ()`, which is
  answered with `#[expect]`.

## Recommendation for v2 nesting

**Use the arena.** `Vec<Self>` is impossible in 0.14, and so is any
container-nested recursion. The alternatives are worse:

- A cons spine forces `Box` lists and needs a well-formedness predicate,
  because it admits ill-formed states.
- Typed `T`/`Forest` pairs hit the mutual-recursion ban.

The arena reuses exactly the proof shape v1 already needs: index loops, a
quantified `wf`, and recursion only in logic, decreasing on `len - k`. It
also keeps the parser's output flat:

- Store `Script { nodes: Vec<Node>, root }`, where each compound node holds
  `first/len` ranges into later indices.
- `wf` lives in an `Invariant` on the arena, so consumers get it for free, as
  in (d).
- Evaluate bottom-up with a `Vec<Decision>` scratch buffer, built with
  `push` (terminates) rather than `vec![x; n]` (not terminates).
  Alternatively, take a caller-provided `&mut [Decision]` to keep
  `#[check(terminates)]`.
