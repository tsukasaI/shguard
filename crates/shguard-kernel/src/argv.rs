//! Argv parsing against a catalog [`Grammar`].
//!
//! [`parse_argv`] is specified against `argv_spec`, a logic definition that
//! walks the words left to right (`argv_go`), classifying each word in option
//! position with `word_l`. The contract is a refinement: the parse equals
//! the spec's result exactly.
//!
//! How the spec reads a word:
//! - Its literal view is `lit_prefix` (the bytes of the `Lit` parts up to the
//!   first `Opaque`) and `has_opaque`. Empty `Lit` parts add nothing, so
//!   `''-x` reads as `-x`.
//! - Options end at `--` (when the grammar has `dashdash`) and, when it does
//!   not `permute`, at the first operand. After that every word is an
//!   operand.
//! - A long option matches a long name byte for byte (no abbreviation); a
//!   short cluster is walked byte by byte (`cluster_l`).
//! - The k-th operand gets `positionals[k]`, else `rest`.
//! - A `Code` role on an operand or an option value is Unknown. The first
//!   Unknown, left to right, wins.

use crate::ast::{Part, Word};
use crate::bytes::bytes_eq;
#[cfg(creusot)]
use crate::bytes::{lemma_concat_laws, lemma_snoc_pop, lemma_sub_snoc};
use crate::catalog::{Grammar, Opt, OptName, OptValue, Role};
use crate::verdict::UnknownKind;
#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

// Public because Creusot refuses to unfold an open logic function that
// mentions a less visible item.
/// The option marker.
pub const DASH: u8 = b'-';
/// The separator between a long option and its inline value.
pub const EQ: u8 = b'=';

/// What one argument word is in a successful parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Slot {
    /// An option word: one long option, or a cluster of short options.
    /// `Some(role)` when the word also carries the value of its last option
    /// inline (`--lines=5`, `-n5`); `None` otherwise.
    Opts(Option<Role>),
    /// The value of the option on the previous word (`5` in `-n 5`).
    OptValue(Role),
    /// An operand, with the role the grammar gives it.
    Operand(Role),
    /// The `--` that ends options.
    DashDash,
}

/// A successful parse of the words from `start` on.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Parse {
    /// One slot per word from `start`: `slots[j]` is word `start + j`.
    /// [`parse_argv`]'s contract proves the length; the alignment holds by
    /// construction of `argv_go` and is not stated separately.
    pub(crate) slots: Vec<Slot>,
    /// Indices into the grammar's `opts` of every option that occurs, in
    /// order, one entry per occurrence (`-rf` adds two).
    pub(crate) seen: Vec<usize>,
}

impl Parse {
    /// One slot per word from `start`: `slots()[j]` is word `start + j`.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.slots@))]
    #[must_use]
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Indices into the grammar's `opts` of the options that occur, in order.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.seen@))]
    #[must_use]
    pub fn seen(&self) -> &[usize] {
        &self.seen
    }
}

/// The result of [`parse_argv`].
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
#[expect(
    clippy::module_name_repetitions,
    reason = "`Result` alone would shadow `std::result::Result`"
)]
pub enum ArgvResult {
    /// Every word was read.
    Parsed(Parse),
    /// The grammar does not cover the argv; the index is the (absolute) word
    /// at which the first problem sits.
    Unknown(UnknownKind, usize),
}

/// How an option word ends, after its last option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Tail {
    /// The last option is a flag.
    Done,
    /// The last option takes a value of this role, given inline.
    Inline(Role),
    /// The last option takes a value of this role from the next word.
    Next(Role),
}

/// The spec's reading of one word in option position.
#[cfg(creusot)]
pub enum WordL {
    /// The word is an operand.
    Operand,
    /// Unknown at this word.
    Fail(UnknownKind),
    /// The `--` that ends options.
    EndOpts,
    /// Option word: the `seen` list after it, and how it ends.
    Opts(Seq<Int>, Tail),
}

/// The spec's result: the logic counterpart of [`ArgvResult`].
#[cfg(creusot)]
pub enum ArgvL {
    /// Slots and the `seen` option indices.
    Parsed(Seq<Slot>, Seq<Int>),
    /// Unknown kind and word index.
    Unknown(UnknownKind, Int),
}

/// The bytes of the `Lit` parts of `parts[j..]` up to the first `Opaque`:
/// a literal word's bytes, or an opaque word's known prefix.
#[cfg(creusot)]
#[logic(open)]
#[variant(parts.len() - j)]
pub fn lit_prefix(parts: Seq<Part>, j: Int) -> Seq<u8> {
    pearlite! {
        if j < 0 || j >= parts.len() {
            Seq::empty()
        } else {
            match parts[j] {
                Part::Lit(b) => b@.concat(lit_prefix(parts, j + 1)),
                Part::Opaque(_) => Seq::empty(),
            }
        }
    }
}

/// Some part of `parts[j..]` is `Opaque`.
#[cfg(creusot)]
#[logic(open)]
#[variant(parts.len() - j)]
pub fn has_opaque(parts: Seq<Part>, j: Int) -> bool {
    if j < 0 || j >= parts.len() {
        false
    } else {
        match parts[j] {
            Part::Lit(_) => has_opaque(parts, j + 1),
            Part::Opaque(_) => true,
        }
    }
}

/// `o` has the short name `c`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn has_short(o: Opt, c: u8) -> bool {
    match o.name {
        OptName::Short(s) => s == c,
        OptName::Long(_) => false,
        OptName::Both(s, _) => s == c,
    }
}

/// `o` has the long name `name`, byte for byte.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn has_long(o: Opt, name: Seq<u8>) -> bool {
    pearlite! {
        match o.name {
            OptName::Short(_) => false,
            OptName::Long(n) => n.bytes@ == name,
            OptName::Both(_, n) => n.bytes@ == name,
        }
    }
}

/// The index of the first option in `opts[j..]` with short name `c`, or
/// `opts.len()` when there is none.
#[cfg(creusot)]
#[logic(open(crate))]
#[variant(opts.len() - j)]
pub fn find_short_l(opts: Seq<Opt>, c: u8, j: Int) -> Int {
    if j >= opts.len() {
        opts.len()
    } else if has_short(opts[j], c) {
        j
    } else {
        find_short_l(opts, c, j + 1)
    }
}

/// The index of the first option in `opts[j..]` with long name `name`, or
/// `opts.len()` when there is none.
#[cfg(creusot)]
#[logic(open(crate))]
#[variant(opts.len() - j)]
pub fn find_long_l(opts: Seq<Opt>, name: Seq<u8>, j: Int) -> Int {
    if j >= opts.len() {
        opts.len()
    } else if has_long(opts[j], name) {
        j
    } else {
        find_long_l(opts, name, j + 1)
    }
}

/// The index of the first `x` in `b[j..]`, or `b.len()` when there is none.
#[cfg(creusot)]
#[logic(open)]
#[variant(b.len() - j)]
pub fn find_byte_l(b: Seq<u8>, x: u8, j: Int) -> Int {
    if j >= b.len() {
        b.len()
    } else if b[j] == x {
        j
    } else {
        find_byte_l(b, x, j + 1)
    }
}

/// The literal long option `b` (`--name` or `--name=value`), given the
/// `seen` list before it.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn long_l(opts: Seq<Opt>, b: Seq<u8>, seen: Seq<Int>) -> WordL {
    let e = find_byte_l(b, EQ, 2);
    let o = find_long_l(opts, b.subsequence(2, e), 0);
    if o >= opts.len() {
        WordL::Fail(UnknownKind::UnknownOption)
    } else {
        match opts[o].value {
            OptValue::Flag => {
                if e < b.len() {
                    WordL::Fail(UnknownKind::FlagGivenValue)
                } else {
                    WordL::Opts(seen.push_back(o), Tail::Done)
                }
            }
            OptValue::Takes(r) => {
                if e < b.len() {
                    WordL::Opts(seen.push_back(o), Tail::Inline(r))
                } else {
                    WordL::Opts(seen.push_back(o), Tail::Next(r))
                }
            }
        }
    }
}

/// The short cluster `b` (`-abc`) from byte `j` on, given the `seen` list
/// so far. A flag continues the walk; an option that takes a value takes
/// the rest of the cluster if any bytes remain, else the next word.
#[cfg(creusot)]
#[logic(open(crate))]
#[variant(b.len() - j)]
pub fn cluster_l(opts: Seq<Opt>, b: Seq<u8>, j: Int, seen: Seq<Int>) -> WordL {
    if j >= b.len() {
        WordL::Opts(seen, Tail::Done)
    } else {
        let o = find_short_l(opts, b[j], 0);
        if o >= opts.len() {
            WordL::Fail(UnknownKind::UnknownOption)
        } else {
            match opts[o].value {
                OptValue::Flag => cluster_l(opts, b, j + 1, seen.push_back(o)),
                OptValue::Takes(r) => {
                    if j + 1 < b.len() {
                        WordL::Opts(seen.push_back(o), Tail::Inline(r))
                    } else {
                        WordL::Opts(seen.push_back(o), Tail::Next(r))
                    }
                }
            }
        }
    }
}

/// A word in option position, given its literal view (`b`, `opaque`) and
/// the `seen` list before it.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn word_l(g: Grammar, b: Seq<u8>, opaque: bool, seen: Seq<Int>) -> WordL {
    pearlite! { if opaque {
        // `foo$X` cannot be an option; `$X` and `-$X` might be.
        if b.len() == 0 || b[0] == DASH {
            WordL::Fail(UnknownKind::OpaqueOption)
        } else {
            WordL::Operand
        }
    } else if b.len() >= 2 && b[0] == DASH && b[1] == DASH {
        if b.len() == 2 {
            if g.dashdash {
                WordL::EndOpts
            } else {
                WordL::Fail(UnknownKind::DashDashNotAllowed)
            }
        } else {
            long_l(g.opts@, b, seen)
        }
    } else if b.len() >= 2 && b[0] == DASH {
        cluster_l(g.opts@, b, 1, seen)
    } else {
        // `-`, the empty word and words without a leading `-`.
        WordL::Operand
    } }
}

/// The role of the operand with index `k` among operands, or `None` when
/// the grammar allows no such operand.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn operand_role_l(g: Grammar, k: Int) -> Option<Role> {
    pearlite! {
        if k < g.positionals@.len() {
            Some(g.positionals@[k])
        } else {
            g.rest
        }
    }
}

/// The parse of `ws[i..]`, given whether options have `ended`, the number
/// `k` of operands so far, and the `slots` and `seen` lists so far.
#[cfg(creusot)]
#[logic(open(crate))]
#[variant(ws.len() - i)]
pub fn argv_go(
    g: Grammar,
    ws: Seq<Word>,
    i: Int,
    ended: bool,
    k: Int,
    slots: Seq<Slot>,
    seen: Seq<Int>,
) -> ArgvL {
    pearlite! {
        if i >= ws.len() {
            ArgvL::Parsed(slots, seen)
        } else {
            let w = if ended {
                WordL::Operand
            } else {
                word_l(g, lit_prefix(ws[i].parts@, 0), has_opaque(ws[i].parts@, 0), seen)
            };
            match w {
                WordL::Operand => match operand_role_l(g, k) {
                    None => ArgvL::Unknown(UnknownKind::ExtraOperand, i),
                    Some(Role::Code) => ArgvL::Unknown(UnknownKind::CodeRole, i),
                    Some(r) => argv_go(g, ws, i + 1, ended || !g.permute, k + 1,
                        slots.push_back(Slot::Operand(r)), seen),
                },
                WordL::Fail(u) => ArgvL::Unknown(u, i),
                WordL::EndOpts => argv_go(g, ws, i + 1, true, k,
                    slots.push_back(Slot::DashDash), seen),
                WordL::Opts(s, Tail::Done) => argv_go(g, ws, i + 1, ended, k,
                    slots.push_back(Slot::Opts(None)), s),
                WordL::Opts(s, Tail::Inline(r)) => if r == Role::Code {
                    ArgvL::Unknown(UnknownKind::CodeRole, i)
                } else {
                    argv_go(g, ws, i + 1, ended, k, slots.push_back(Slot::Opts(Some(r))), s)
                },
                WordL::Opts(s, Tail::Next(r)) => if i + 1 >= ws.len() {
                    ArgvL::Unknown(UnknownKind::MissingValue, i)
                } else if r == Role::Code {
                    ArgvL::Unknown(UnknownKind::CodeRole, i + 1)
                } else {
                    argv_go(g, ws, i + 2, ended, k,
                        slots.push_back(Slot::Opts(None)).push_back(Slot::OptValue(r)), s)
                },
            }
        }
    }
}

/// The parse of the words of `ws` from `start` on (the words before it are
/// the command key).
#[cfg(creusot)]
#[logic(open(crate))]
pub fn argv_spec(g: Grammar, ws: Seq<Word>, start: Int) -> ArgvL {
    argv_go(g, ws, start, false, 0, Seq::empty(), Seq::empty())
}

/// The `Int` views of `s`, in order.
#[cfg(creusot)]
#[logic(open)]
#[variant(s.len())]
pub fn ints(s: Seq<usize>) -> Seq<Int> {
    pearlite! {
        if s.len() == 0 {
            Seq::empty()
        } else {
            ints(s.pop_back()).push_back(s[s.len() - 1]@)
        }
    }
}

/// The logic view of an [`ArgvResult`].
#[cfg(creusot)]
#[logic(open(crate))]
pub fn argv_view(r: ArgvResult) -> ArgvL {
    pearlite! {
        match r {
            ArgvResult::Parsed(p) => ArgvL::Parsed(p.slots@, ints(p.seen@)),
            ArgvResult::Unknown(u, i) => ArgvL::Unknown(u, i@),
        }
    }
}

/// `ints` distributes over appending one index.
#[cfg(creusot)]
#[logic]
#[ensures(ints(s.push_back(x)) == ints(s).push_back(x@))]
pub fn lemma_ints_snoc(s: Seq<usize>, x: usize) {
    lemma_snoc_pop(s, x)
}

/// `ints` keeps the length and maps each element to its `Int` view.
#[cfg(creusot)]
#[logic]
#[variant(s.len())]
#[ensures(ints(s).len() == s.len())]
#[ensures(forall<u> 0 <= u && u < s.len() ==> ints(s)[u] == s[u]@)]
pub fn lemma_ints_index(s: Seq<usize>) {
    if s.len() > 0 {
        lemma_ints_index(s.pop_back())
    }
}

/// The slot is not a code position. `argv_spec` never builds one: every
/// `Code` role is Unknown.
#[cfg(creusot)]
#[logic(open)]
pub fn slot_no_code(s: Slot) -> bool {
    match s {
        Slot::Opts(Some(r)) => r != Role::Code,
        Slot::OptValue(r) => r != Role::Code,
        Slot::Operand(r) => r != Role::Code,
        Slot::Opts(None) | Slot::DashDash => true,
    }
}

/// No slot of `slots` is a code position.
#[cfg(creusot)]
#[logic(open)]
pub fn no_code(slots: Seq<Slot>) -> bool {
    pearlite! { forall<t> 0 <= t && t < slots.len() ==> slot_no_code(slots[t]) }
}

/// A successful parse has no code position, given none so far.
#[cfg(creusot)]
#[logic(open(crate))]
#[variant(ws.len() - i)]
#[requires(no_code(slots))]
#[ensures(match argv_go(g, ws, i, ended, k, slots, seen) {
    ArgvL::Parsed(s2, _) => no_code(s2),
    ArgvL::Unknown(_, _) => true,
})]
pub fn lemma_go_no_code(
    g: Grammar,
    ws: Seq<Word>,
    i: Int,
    ended: bool,
    k: Int,
    slots: Seq<Slot>,
    seen: Seq<Int>,
) {
    pearlite! {
        if i < ws.len() {
            let w = if ended {
                WordL::Operand
            } else {
                word_l(g, lit_prefix(ws[i].parts@, 0), has_opaque(ws[i].parts@, 0), seen)
            };
            match w {
                WordL::Operand => match operand_role_l(g, k) {
                    None => (),
                    Some(Role::Code) => (),
                    Some(r) => lemma_go_no_code(g, ws, i + 1, ended || !g.permute, k + 1,
                        slots.push_back(Slot::Operand(r)), seen),
                },
                WordL::Fail(_) => (),
                WordL::EndOpts => lemma_go_no_code(g, ws, i + 1, true, k,
                    slots.push_back(Slot::DashDash), seen),
                WordL::Opts(s, Tail::Done) => lemma_go_no_code(g, ws, i + 1, ended, k,
                    slots.push_back(Slot::Opts(None)), s),
                WordL::Opts(s, Tail::Inline(r)) => if r == Role::Code {
                    ()
                } else {
                    lemma_go_no_code(g, ws, i + 1, ended, k, slots.push_back(Slot::Opts(Some(r))), s)
                },
                WordL::Opts(s, Tail::Next(r)) => if i + 1 >= ws.len() || r == Role::Code {
                    ()
                } else {
                    lemma_go_no_code(g, ws, i + 2, ended, k,
                        slots.push_back(Slot::Opts(None)).push_back(Slot::OptValue(r)), s)
                },
            }
        }
    }
}

/// The program-side reading of one word in option position; `word_kind`'s
/// result plus its update of `seen` mirror [`WordL`].
enum Kind {
    Operand,
    Fail(UnknownKind),
    EndOpts,
    Opts(Tail),
}

/// `r`, with `seen` going from `before` to `after`, is the reading `l`.
#[cfg(creusot)]
#[logic]
fn kind_is(r: Kind, l: WordL, before: Seq<usize>, after: Seq<usize>) -> bool {
    match r {
        Kind::Operand => l == WordL::Operand && after == before,
        Kind::Fail(u) => l == WordL::Fail(u),
        Kind::EndOpts => l == WordL::EndOpts && after == before,
        Kind::Opts(t) => l == WordL::Opts(ints(after), t),
    }
}

/// Appends an option index to `seen`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures((^seen)@ == seen@.push_back(o)))]
#[cfg_attr(creusot, ensures(ints((^seen)@) == ints(seen@).push_back(o@)))]
fn push_ix(seen: &mut Vec<usize>, o: usize) {
    #[cfg(creusot)]
    proof_assert! { lemma_ints_snoc(seen@, o); true };
    seen.push(o);
}

/// The literal view of `w`: its known bytes and whether it is opaque.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result.0@ == lit_prefix(w.parts@, 0)))]
#[cfg_attr(creusot, ensures(result.1 == has_opaque(w.parts@, 0)))]
pub(crate) fn word_view(w: &Word) -> (Vec<u8>, bool) {
    parts_view(&w.parts, 0)
}

/// The literal view of `parts[from..]`: the bytes of its `Lit` parts up to
/// the first `Opaque`, and whether there is an `Opaque`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(from@ <= parts@.len()))]
#[cfg_attr(creusot, ensures(result.0@ == lit_prefix(parts@, from@)))]
#[cfg_attr(creusot, ensures(result.1 == has_opaque(parts@, from@)))]
pub(crate) fn parts_view(parts: &[Part], from: usize) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    #[cfg(creusot)]
    proof_assert! {
        lemma_concat_laws(lit_prefix(parts@, from@), Seq::empty(), Seq::empty(), 0u8);
        out@.ext_eq(Seq::empty())
    };
    let mut j: usize = from;
    #[cfg_attr(creusot, variant(parts@.len() - j@))]
    #[cfg_attr(creusot, invariant(from@ <= j@ && j@ <= parts@.len()))]
    #[cfg_attr(creusot, invariant(out@.concat(lit_prefix(parts@, j@)) == lit_prefix(parts@, from@)))]
    #[cfg_attr(creusot, invariant(has_opaque(parts@, j@) == has_opaque(parts@, from@)))]
    while j < parts.len() {
        match &parts[j] {
            Part::Lit(lit) => {
                #[cfg(creusot)]
                let base = snapshot!(out@);
                #[cfg(creusot)]
                proof_assert! {
                    lemma_concat_laws(*base, Seq::empty(), Seq::empty(), 0u8);
                    lit@.subsequence(0, 0).ext_eq(Seq::empty())
                };
                let mut t: usize = 0;
                #[cfg_attr(creusot, variant(lit@.len() - t@))]
                #[cfg_attr(creusot, invariant(t@ <= lit@.len()))]
                #[cfg_attr(creusot, invariant(out@ == (*base).concat(lit@.subsequence(0, t@))))]
                while t < lit.len() {
                    #[cfg(creusot)]
                    proof_assert! {
                        lemma_sub_snoc(lit@, 0, t@);
                        lemma_concat_laws(*base, lit@.subsequence(0, t@), Seq::empty(), lit@[t@]);
                        true
                    };
                    out.push(lit[t]);
                    t += 1;
                }
                #[cfg(creusot)]
                proof_assert! {
                    lemma_concat_laws(*base, lit@, lit_prefix(parts@, j@ + 1), 0u8);
                    lit@.subsequence(0, lit@.len()).ext_eq(lit@)
                };
                j += 1;
            }
            Part::Opaque(_) => {
                #[cfg(creusot)]
                proof_assert! { lemma_concat_laws(out@, Seq::empty(), Seq::empty(), 0u8); true };
                return (out, true);
            }
        }
    }
    #[cfg(creusot)]
    proof_assert! { lemma_concat_laws(out@, Seq::empty(), Seq::empty(), 0u8); true };
    (out, false)
}

/// `o` has the short name `c`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == has_short(*o, c)))]
pub(crate) fn short_is(o: &Opt, c: u8) -> bool {
    match &o.name {
        OptName::Short(s) => *s == c,
        OptName::Long(_) => false,
        OptName::Both(s, _) => *s == c,
    }
}

/// `o` has the long name `name`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == has_long(*o, name@)))]
pub(crate) fn long_is(o: &Opt, name: &[u8]) -> bool {
    match &o.name {
        OptName::Short(_) => false,
        OptName::Long(n) => bytes_eq(&n.bytes, name),
        OptName::Both(_, n) => bytes_eq(&n.bytes, name),
    }
}

/// The index of the first option with short name `c`, or `opts.len()`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@ == find_short_l(opts@, c, 0)))]
#[cfg_attr(creusot, ensures(result@ <= opts@.len()))]
fn find_short(opts: &[Opt], c: u8) -> usize {
    let mut j: usize = 0;
    #[cfg_attr(creusot, variant(opts@.len() - j@))]
    #[cfg_attr(creusot, invariant(j@ <= opts@.len()))]
    #[cfg_attr(creusot, invariant(find_short_l(opts@, c, j@) == find_short_l(opts@, c, 0)))]
    while j < opts.len() {
        if short_is(&opts[j], c) {
            return j;
        }
        j += 1;
    }
    j
}

/// The index of the first option with long name `name`, or `opts.len()`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@ == find_long_l(opts@, name@, 0)))]
#[cfg_attr(creusot, ensures(result@ <= opts@.len()))]
fn find_long(opts: &[Opt], name: &[u8]) -> usize {
    let mut j: usize = 0;
    #[cfg_attr(creusot, variant(opts@.len() - j@))]
    #[cfg_attr(creusot, invariant(j@ <= opts@.len()))]
    #[cfg_attr(creusot, invariant(find_long_l(opts@, name@, j@) == find_long_l(opts@, name@, 0)))]
    while j < opts.len() {
        if long_is(&opts[j], name) {
            return j;
        }
        j += 1;
    }
    j
}

/// The index of the first `x` in `b[from..]`, or `b.len()`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(from@ <= b@.len()))]
#[cfg_attr(creusot, ensures(result@ == find_byte_l(b@, x, from@)))]
#[cfg_attr(creusot, ensures(from@ <= result@ && result@ <= b@.len()))]
fn find_byte(b: &[u8], x: u8, from: usize) -> usize {
    let mut j = from;
    #[cfg_attr(creusot, variant(b@.len() - j@))]
    #[cfg_attr(creusot, invariant(from@ <= j@ && j@ <= b@.len()))]
    #[cfg_attr(creusot, invariant(find_byte_l(b@, x, j@) == find_byte_l(b@, x, from@)))]
    while j < b.len() {
        if b[j] == x {
            return j;
        }
        j += 1;
    }
    j
}

/// Reads the literal long option `b` (`--name` or `--name=value`).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(b@.len() >= 2))]
#[cfg_attr(creusot, ensures(kind_is(result, long_l(opts@, b@, ints(seen@)), seen@, (^seen)@)))]
fn long_opt(opts: &[Opt], b: &[u8], seen: &mut Vec<usize>) -> Kind {
    let e = find_byte(b, EQ, 2);
    let o = find_long(opts, &b[2..e]);
    if o >= opts.len() {
        return Kind::Fail(UnknownKind::UnknownOption);
    }
    match opts[o].value {
        OptValue::Flag => {
            if e < b.len() {
                return Kind::Fail(UnknownKind::FlagGivenValue);
            }
            push_ix(seen, o);
            Kind::Opts(Tail::Done)
        }
        OptValue::Takes(r) => {
            push_ix(seen, o);
            if e < b.len() {
                Kind::Opts(Tail::Inline(r))
            } else {
                Kind::Opts(Tail::Next(r))
            }
        }
    }
}

/// Reads the short cluster `b` (`-abc`).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(b@.len() >= 1))]
#[cfg_attr(creusot, ensures(kind_is(result, cluster_l(opts@, b@, 1, ints(seen@)), seen@, (^seen)@)))]
fn cluster(opts: &[Opt], b: &[u8], seen: &mut Vec<usize>) -> Kind {
    #[cfg(creusot)]
    let target = snapshot!(cluster_l(opts@, b@, 1, ints(seen@)));
    let mut j: usize = 1;
    #[cfg_attr(creusot, variant(b@.len() - j@))]
    #[cfg_attr(creusot, invariant(1 <= j@ && j@ <= b@.len()))]
    #[cfg_attr(creusot, invariant(cluster_l(opts@, b@, j@, ints(seen@)) == *target))]
    while j < b.len() {
        let o = find_short(opts, b[j]);
        if o >= opts.len() {
            return Kind::Fail(UnknownKind::UnknownOption);
        }
        match opts[o].value {
            OptValue::Flag => {
                push_ix(seen, o);
                j += 1;
            }
            OptValue::Takes(r) => {
                push_ix(seen, o);
                return if j + 1 < b.len() {
                    Kind::Opts(Tail::Inline(r))
                } else {
                    Kind::Opts(Tail::Next(r))
                };
            }
        }
    }
    Kind::Opts(Tail::Done)
}

/// Reads a word in option position from its literal view.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(kind_is(result, word_l(*g, b@, opaque, ints(seen@)), seen@, (^seen)@)))]
fn word_kind(g: &Grammar, b: &[u8], opaque: bool, seen: &mut Vec<usize>) -> Kind {
    if opaque {
        if <[_]>::is_empty(b) || b[0] == DASH {
            return Kind::Fail(UnknownKind::OpaqueOption);
        }
        return Kind::Operand;
    }
    if b.len() >= 2 && b[0] == DASH && b[1] == DASH {
        if b.len() == 2 {
            if g.dashdash {
                return Kind::EndOpts;
            }
            return Kind::Fail(UnknownKind::DashDashNotAllowed);
        }
        return long_opt(&g.opts, b, seen);
    }
    if b.len() >= 2 && b[0] == DASH {
        return cluster(&g.opts, b, seen);
    }
    Kind::Operand
}

/// The role of the operand with index `k`, or `None` when there is none.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == operand_role_l(*g, k@)))]
fn operand_role(g: &Grammar, k: usize) -> Option<Role> {
    if k < g.positionals.len() {
        Some(g.positionals[k])
    } else {
        g.rest
    }
}

/// Parses the argv words `ws[start..]` against `g`. The words before
/// `start` are the command key and are ignored; `start > ws.len()` means
/// there are no arguments.
///
/// The result is exactly `argv_spec`: see the module docs for how words are
/// read. Besides, an Unknown index is a word of `ws`, and a parse has one
/// slot per word from `start`.
///
/// Only the length (`slots.len() == ws.len() - start`) is proved. That
/// `slots[j]` describes word `start + j` holds by construction of
/// `argv_go`, but the contract does not state it separately.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(argv_view(result) == argv_spec(*g, ws@, start@)))]
#[cfg_attr(creusot, ensures(match result {
    ArgvResult::Parsed(p) => start@ <= ws@.len() ==> p.slots@.len() == ws@.len() - start@,
    ArgvResult::Unknown(_, i) => i@ < ws@.len(),
}))]
#[must_use]
#[expect(
    clippy::module_name_repetitions,
    reason = "`parse` alone would be ambiguous at call sites"
)]
pub fn parse_argv(g: &Grammar, ws: &[Word], start: usize) -> ArgvResult {
    let mut slots: Vec<Slot> = Vec::new();
    let mut seen: Vec<usize> = Vec::new();
    let mut ended = false;
    let mut k: usize = 0;
    let mut i = start;
    #[cfg(creusot)]
    proof_assert! {
        slots@.ext_eq(Seq::empty()) && seen@.ext_eq(Seq::empty())
            && ints(seen@) == Seq::empty()
    };
    #[cfg_attr(creusot, variant(ws@.len() - i@))]
    #[cfg_attr(creusot, invariant(k@ <= i@))]
    #[cfg_attr(creusot, invariant(start@ <= ws@.len() ==>
        i@ <= ws@.len() && slots@.len() == i@ - start@))]
    #[cfg_attr(creusot, invariant(
        argv_go(*g, ws@, i@, ended, k@, slots@, ints(seen@)) == argv_spec(*g, ws@, start@)))]
    while i < ws.len() {
        let kind = if ended {
            Kind::Operand
        } else {
            let (b, opaque) = word_view(&ws[i]);
            word_kind(g, &b, opaque, &mut seen)
        };
        match kind {
            Kind::Operand => match operand_role(g, k) {
                None => return ArgvResult::Unknown(UnknownKind::ExtraOperand, i),
                Some(Role::Code) => return ArgvResult::Unknown(UnknownKind::CodeRole, i),
                Some(r @ (Role::Inert | Role::Path)) => {
                    slots.push(Slot::Operand(r));
                    k += 1;
                    if !g.permute {
                        ended = true;
                    }
                    i += 1;
                }
            },
            Kind::Fail(u) => return ArgvResult::Unknown(u, i),
            Kind::EndOpts => {
                slots.push(Slot::DashDash);
                ended = true;
                i += 1;
            }
            Kind::Opts(Tail::Done) => {
                slots.push(Slot::Opts(None));
                i += 1;
            }
            Kind::Opts(Tail::Inline(Role::Code)) => {
                return ArgvResult::Unknown(UnknownKind::CodeRole, i);
            }
            Kind::Opts(Tail::Inline(r @ (Role::Inert | Role::Path))) => {
                slots.push(Slot::Opts(Some(r)));
                i += 1;
            }
            Kind::Opts(Tail::Next(r)) => {
                if i + 1 >= ws.len() {
                    return ArgvResult::Unknown(UnknownKind::MissingValue, i);
                }
                if let Role::Code = r {
                    return ArgvResult::Unknown(UnknownKind::CodeRole, i + 1);
                }
                slots.push(Slot::Opts(None));
                slots.push(Slot::OptValue(r));
                i += 2;
            }
        }
    }
    ArgvResult::Parsed(Parse { slots, seen })
}

#[cfg(test)]
mod tests {
    use super::{ArgvResult, Parse, Slot, parse_argv};
    use crate::ast::{Opaque, Part, Word};
    use crate::catalog::{Grammar, LongName, Opt, OptName, OptValue, Role};
    use crate::verdict::UnknownKind;

    const R: usize = 0; // -r / --recursive, flag
    const F: usize = 1; // -f / --force, flag
    const N: usize = 2; // -n / --lines, takes an inert value
    const C: usize = 3; // --color, long only, takes an inert value
    // Index 4: -e, short only, takes code (never in a successful parse).

    fn long(s: &str) -> LongName {
        LongName::new(s.as_bytes().to_vec()).expect("non-empty")
    }

    fn opts() -> Vec<Opt> {
        vec![
            Opt::new(OptName::Both(b'r', long("recursive")), OptValue::Flag),
            Opt::new(OptName::Both(b'f', long("force")), OptValue::Flag),
            Opt::new(
                OptName::Both(b'n', long("lines")),
                OptValue::Takes(Role::Inert),
            ),
            Opt::new(OptName::Long(long("color")), OptValue::Takes(Role::Inert)),
            Opt::new(OptName::Short(b'e'), OptValue::Takes(Role::Code)),
        ]
    }

    /// GNU style: options anywhere, `--` ends them, any number of paths.
    fn gnu() -> Grammar {
        Grammar::new(opts(), Vec::new(), Some(Role::Path), true, true)
    }

    fn word(parts: Vec<Part>) -> Word {
        Word::new(parts).expect("non-empty")
    }

    fn lit(s: &str) -> Part {
        Part::Lit(s.as_bytes().to_vec())
    }

    fn var() -> Part {
        Part::Opaque(Opaque::Var(b"X".to_vec()))
    }

    /// `cmd` followed by literal words.
    fn argv(args: &[&str]) -> Vec<Word> {
        let mut ws = vec![word(vec![lit("cmd")])];
        for a in args {
            ws.push(word(vec![lit(a)]));
        }
        ws
    }

    fn parse(g: &Grammar, ws: &[Word]) -> ArgvResult {
        parse_argv(g, ws, 1)
    }

    fn parsed(slots: &[Slot], seen: &[usize]) -> ArgvResult {
        ArgvResult::Parsed(Parse {
            slots: slots.to_vec(),
            seen: seen.to_vec(),
        })
    }

    fn unknown(kind: UnknownKind, at: usize) -> ArgvResult {
        ArgvResult::Unknown(kind, at)
    }

    const OPTS: Slot = Slot::Opts(None);
    const PATH: Slot = Slot::Operand(Role::Path);

    #[test]
    fn clusters() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["-rf", "a"])),
            parsed(&[OPTS, PATH], &[R, F])
        );
        assert_eq!(
            parse(&g, &argv(&["-rfn5"])),
            parsed(&[Slot::Opts(Some(Role::Inert))], &[R, F, N])
        );
        assert_eq!(
            parse(&g, &argv(&["-rx"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
    }

    #[test]
    fn short_value_inline_next_and_missing() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["-n5"])),
            parsed(&[Slot::Opts(Some(Role::Inert))], &[N])
        );
        assert_eq!(
            parse(&g, &argv(&["-n", "5"])),
            parsed(&[OPTS, Slot::OptValue(Role::Inert)], &[N])
        );
        assert_eq!(
            parse(&g, &argv(&["a", "-n"])),
            unknown(UnknownKind::MissingValue, 2)
        );
        assert_eq!(
            parse(&g, &argv(&["-rn"])),
            unknown(UnknownKind::MissingValue, 1)
        );
        // The value word can be anything, even `-r` or an opaque word.
        assert_eq!(
            parse(&g, &argv(&["-n", "-r"])),
            parsed(&[OPTS, Slot::OptValue(Role::Inert)], &[N])
        );
        let ws = vec![
            word(vec![lit("cmd")]),
            word(vec![lit("-n")]),
            word(vec![var()]),
        ];
        assert_eq!(
            parse(&g, &ws),
            parsed(&[OPTS, Slot::OptValue(Role::Inert)], &[N])
        );
    }

    #[test]
    fn long_options() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["--lines=5"])),
            parsed(&[Slot::Opts(Some(Role::Inert))], &[N])
        );
        assert_eq!(
            parse(&g, &argv(&["--color=", "--lines", "5"])),
            parsed(
                &[
                    Slot::Opts(Some(Role::Inert)),
                    OPTS,
                    Slot::OptValue(Role::Inert)
                ],
                &[C, N]
            )
        );
        assert_eq!(
            parse(&g, &argv(&["--force", "--recursive"])),
            parsed(&[OPTS, OPTS], &[F, R])
        );
        assert_eq!(
            parse(&g, &argv(&["--force=1"])),
            unknown(UnknownKind::FlagGivenValue, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["--color"])),
            unknown(UnknownKind::MissingValue, 1)
        );
        // `-e` has no long name; `--e` is not `-e`.
        assert_eq!(
            parse(&g, &argv(&["--e"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["--=x"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
    }

    #[test]
    fn abbreviation_is_unknown() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["--recur"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["--lin=5"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["--recursivex"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
    }

    #[test]
    fn dashdash() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["--", "-r", "--"])),
            parsed(&[Slot::DashDash, PATH, PATH], &[])
        );
        let strict = Grammar::new(opts(), Vec::new(), Some(Role::Path), true, false);
        assert_eq!(
            parse(&strict, &argv(&["a", "--"])),
            unknown(UnknownKind::DashDashNotAllowed, 2)
        );
    }

    #[test]
    fn opaque_operand_after_dashdash() {
        let ws = vec![
            word(vec![lit("cmd")]),
            word(vec![lit("--")]),
            word(vec![var()]),
            word(vec![lit("-"), var()]),
        ];
        assert_eq!(
            parse(&gnu(), &ws),
            parsed(&[Slot::DashDash, PATH, PATH], &[])
        );
    }

    #[test]
    fn opaque_word_in_option_position() {
        let g = gnu();
        let cases = [
            (vec![var()], unknown(UnknownKind::OpaqueOption, 1)),
            (vec![lit("-"), var()], unknown(UnknownKind::OpaqueOption, 1)),
            (
                vec![lit(""), var(), lit("x")],
                unknown(UnknownKind::OpaqueOption, 1),
            ),
            (vec![lit("foo"), var()], parsed(&[PATH], &[])),
        ];
        for (parts, want) in cases {
            let ws = vec![word(vec![lit("cmd")]), word(parts)];
            assert_eq!(parse(&g, &ws), want);
        }
    }

    #[test]
    fn empty_lits_do_not_matter() {
        let g = gnu();
        let ws = vec![word(vec![lit("cmd")]), word(vec![lit(""), lit("-r")])];
        assert_eq!(parse(&g, &ws), parsed(&[OPTS], &[R]));
        let ws = vec![
            word(vec![lit("cmd")]),
            word(vec![lit("-"), lit(""), lit("-co"), lit("lor=1")]),
        ];
        assert_eq!(
            parse(&g, &ws),
            parsed(&[Slot::Opts(Some(Role::Inert))], &[C])
        );
    }

    #[test]
    fn single_dash_and_empty_word_are_operands() {
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["-", "", "-r"])),
            parsed(&[PATH, PATH, OPTS], &[R])
        );
    }

    #[test]
    fn permute_vs_not() {
        let ls = |permute| Grammar::new(opts(), Vec::new(), Some(Role::Path), permute, true);
        assert_eq!(
            parse(&ls(true), &argv(&["a", "-r"])),
            parsed(&[PATH, OPTS], &[R])
        );
        assert_eq!(
            parse(&ls(false), &argv(&["a", "-r", "--"])),
            parsed(&[PATH, PATH, PATH], &[])
        );
        // Not even an unknown option or an opaque word is read after the end.
        let mut ws = argv(&["a", "-z"]);
        ws.push(word(vec![var()]));
        assert_eq!(parse(&ls(false), &ws), parsed(&[PATH, PATH, PATH], &[]));
    }

    #[test]
    fn operand_roles() {
        let g = Grammar::new(opts(), vec![Role::Inert, Role::Path], None, true, true);
        assert_eq!(
            parse(&g, &argv(&["a", "-r", "b"])),
            parsed(&[Slot::Operand(Role::Inert), OPTS, PATH], &[R])
        );
        assert_eq!(
            parse(&g, &argv(&["a"])),
            parsed(&[Slot::Operand(Role::Inert)], &[])
        );
        assert_eq!(
            parse(&g, &argv(&["a", "b", "c"])),
            unknown(UnknownKind::ExtraOperand, 3)
        );
    }

    #[test]
    fn code_role() {
        let g = Grammar::new(opts(), vec![Role::Code], None, true, true);
        assert_eq!(
            parse(&g, &argv(&["-r", "x"])),
            unknown(UnknownKind::CodeRole, 2)
        );
        let g = gnu();
        assert_eq!(
            parse(&g, &argv(&["-e", "x"])),
            unknown(UnknownKind::CodeRole, 2)
        );
        assert_eq!(
            parse(&g, &argv(&["-rex"])),
            unknown(UnknownKind::CodeRole, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["-e"])),
            unknown(UnknownKind::MissingValue, 1)
        );
    }

    #[test]
    fn first_unknown_wins() {
        let g = Grammar::new(opts(), Vec::new(), None, true, true);
        assert_eq!(
            parse(&g, &argv(&["--bogus", "a"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["a", "--bogus"])),
            unknown(UnknownKind::ExtraOperand, 1)
        );
    }

    #[test]
    fn start_offsets() {
        let g = gnu();
        let ws = argv(&["-r", "a"]);
        assert_eq!(parse_argv(&g, &ws, 0), parsed(&[PATH, OPTS, PATH], &[R]));
        assert_eq!(parse_argv(&g, &ws, 2), parsed(&[PATH], &[]));
        assert_eq!(parse_argv(&g, &ws, 3), parsed(&[], &[]));
        assert_eq!(parse_argv(&g, &ws, 9), parsed(&[], &[]));
        let ws = argv(&["a", "-z"]);
        assert_eq!(
            parse_argv(&g, &ws, 2),
            unknown(UnknownKind::UnknownOption, 2)
        );
    }

    #[test]
    fn review_edge_cases() {
        let g = gnu();
        // A value word is taken whatever it is, even `--`.
        assert_eq!(
            parse(&g, &argv(&["-n", "--", "-r"])),
            parsed(&[OPTS, Slot::OptValue(Role::Inert), OPTS], &[N, R])
        );
        assert_eq!(
            parse(&g, &argv(&["---x"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
        assert_eq!(
            parse(&g, &argv(&["-n=5"])),
            parsed(&[Slot::Opts(Some(Role::Inert))], &[N])
        );

        let strict = Grammar::new(opts(), Vec::new(), Some(Role::Path), false, true);
        assert_eq!(
            parse(&strict, &argv(&["-", "-r"])),
            parsed(&[PATH, PATH], &[])
        );
        assert_eq!(
            parse(&strict, &argv(&["--", "-r"])),
            parsed(&[Slot::DashDash, PATH], &[])
        );

        let out = Grammar::new(
            vec![Opt::new(
                OptName::Both(b'o', long("output")),
                OptValue::Takes(Role::Path),
            )],
            Vec::new(),
            None,
            true,
            true,
        );
        assert_eq!(
            parse(&out, &argv(&["-o", "x"])),
            parsed(&[OPTS, Slot::OptValue(Role::Path)], &[0])
        );
        assert_eq!(
            parse(&out, &argv(&["--output=x"])),
            parsed(&[Slot::Opts(Some(Role::Path))], &[0])
        );

        // An option value is not counted as an operand.
        let one = Grammar::new(opts(), vec![Role::Inert], None, true, true);
        assert_eq!(
            parse(&one, &argv(&["-n", "5", "a"])),
            parsed(
                &[
                    OPTS,
                    Slot::OptValue(Role::Inert),
                    Slot::Operand(Role::Inert)
                ],
                &[N]
            )
        );

        // `~/x` has an empty known prefix, so it fails closed.
        let ws = vec![
            word(vec![lit("cmd")]),
            word(vec![Part::Opaque(Opaque::Tilde), lit("/x")]),
        ];
        assert_eq!(parse(&g, &ws), unknown(UnknownKind::OpaqueOption, 1));

        // On a name collision the first option in `opts` wins.
        let clash = Grammar::new(
            vec![
                Opt::new(OptName::Short(b'f'), OptValue::Flag),
                Opt::new(
                    OptName::Both(b'f', long("file")),
                    OptValue::Takes(Role::Path),
                ),
            ],
            Vec::new(),
            Some(Role::Path),
            true,
            true,
        );
        assert_eq!(
            parse(&clash, &argv(&["-f", "a"])),
            parsed(&[OPTS, PATH], &[0])
        );
        assert_eq!(
            parse(&clash, &argv(&["--file", "a"])),
            parsed(&[OPTS, Slot::OptValue(Role::Path)], &[1])
        );
    }
}
