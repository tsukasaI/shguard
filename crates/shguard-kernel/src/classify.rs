//! Catalog lookup and classification (theorem T2), and the sealed
//! [`Witness`].
//!
//! A simple command is covered (`covered_simple`) when SOME catalog row
//! covers it (`row_covers`). Key uniqueness is not assumed: with duplicate
//! keys, any row that covers is enough. A row covers a simple command when:
//! - its key matches: the first `key.len()` words are literal (every part is
//!   `Lit`; the bytes are their concatenation, the view of [`crate::argv`])
//!   and equal the key segments, in order and contiguous;
//! - it does not run code, and no row with a longer key that also matches
//!   the command runs code: `["python"]` must not cover `python -c x` when
//!   `["python", "-c"]` runs code (#1042);
//! - the words after the key parse against its grammar ([`parse_argv`]);
//! - it is not a parent row, or the parse has no operand. A parent row is
//!   one whose key another row strictly extends (derived, not stored), so
//!   `["git"]` covers `git --version` but not `git push`, where `push` would
//!   otherwise read as an inert operand.
//!
//! Redirects never affect coverage: every [`Redir`](crate::ast::Redir) value
//! only moves or discards descriptors 1 and 2, so none can write a file,
//! read input or run code. The catalog's global grammars (words
//! between key segments, as in `git -C x status`) are NOT used in v1: such a
//! command matches no row with the longer key, which is conservative (it
//! ends in Ask, never Allow).
//!
//! A script is covered (`covered_script`) when the simple command at every
//! valid address is. [`classify_script`] gives either a [`Witness`], which
//! owns the script and whose invariant is `covered_script` (#1006), or the
//! script back with the first uncovered command's address.
//!
//! An uncovered command's reason is deterministic: `OpaqueCommandName` at
//! word 0 when the first word is not literal, `NoRow` at 0 when no key
//! matches, and otherwise the reason of the first matching row in catalog
//! order (`RunsCode` at 0, the argv parse's Unknown, or `UnknownSubcommand`
//! at a parent row's first operand). The contracts pin only that the reason
//! sits at a valid address of an uncovered command, not which reason it is.

#[cfg(creusot)]
use crate::argv::{ArgvL, argv_spec, has_opaque, lit_prefix};
use crate::argv::{ArgvResult, Slot, parse_argv, word_view};
use crate::ast::{Pipeline, Script, Simple, Word};
use crate::bytes::bytes_eq;
use crate::catalog::{Catalog, Row};
use crate::verdict::{Addr, Reason, UnknownKind};
#[cfg(creusot)]
use crate::verdict::{simple_at_l, valid_addr};
#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// `w` is literal and its bytes are `seg`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn seg_is(w: Word, seg: Seq<u8>) -> bool {
    pearlite! { !has_opaque(w.parts@, 0) && lit_prefix(w.parts@, 0) == seg }
}

/// The words `ws` start with the literal key `key`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn key_matches(key: Seq<Vec<u8>>, ws: Seq<Word>) -> bool {
    pearlite! {
        key.len() <= ws.len()
            && forall<t> 0 <= t && t < key.len() ==> seg_is(ws[t], key[t]@)
    }
}

/// The key `long` strictly extends the key `short`.
#[cfg(creusot)]
#[logic(open)]
pub fn extends_l(long: Seq<Vec<u8>>, short: Seq<Vec<u8>>) -> bool {
    pearlite! {
        short.len() < long.len()
            && forall<t> 0 <= t && t < short.len() ==> long[t]@ == short[t]@
    }
}

/// `rows[j]` is a parent: some row's key strictly extends its key (#1027).
#[cfg(creusot)]
#[logic(open(crate))]
pub fn is_parent_l(rows: Seq<Row>, j: Int) -> bool {
    pearlite! {
        exists<m> 0 <= m && m < rows.len() && extends_l(rows[m].key@, rows[j].key@)
    }
}

/// Some row whose key strictly extends the key of `rows[j]` matches the words
/// `ws` and runs code: the command is that row's, not `rows[j]`'s (#1042).
#[cfg(creusot)]
#[logic(open(crate))]
pub fn code_child_l(rows: Seq<Row>, j: Int, ws: Seq<Word>) -> bool {
    pearlite! {
        exists<m> 0 <= m && m < rows.len() && extends_l(rows[m].key@, rows[j].key@)
            && key_matches(rows[m].key@, ws) && rows[m].runs_code
    }
}

/// `s` is an operand slot.
#[cfg(creusot)]
#[logic(open)]
pub fn is_operand(s: Slot) -> bool {
    match s {
        Slot::Operand(_) => true,
        Slot::Opts(_) | Slot::OptValue(_) | Slot::DashDash => false,
    }
}

/// Some slot of `slots` is an operand.
#[cfg(creusot)]
#[logic(open)]
pub fn has_operand(slots: Seq<Slot>) -> bool {
    pearlite! { exists<t> 0 <= t && t < slots.len() && is_operand(slots[t]) }
}

/// The row `rows[j]` covers a simple command with words `ws`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn row_covers(rows: Seq<Row>, j: Int, ws: Seq<Word>) -> bool {
    pearlite! {
        0 <= j && j < rows.len()
            && key_matches(rows[j].key@, ws)
            && !rows[j].runs_code
            && !code_child_l(rows, j, ws)
            && match argv_spec(rows[j].grammar, ws, rows[j].key@.len()) {
                ArgvL::Parsed(slots, _) => !is_parent_l(rows, j) || !has_operand(slots),
                ArgvL::Unknown(_, _) => false,
            }
    }
}

/// Some row of `cat` covers `s` (#1028: existential, no key uniqueness).
#[cfg(creusot)]
#[logic(open(crate))]
pub fn covered_simple(cat: Catalog, s: Simple) -> bool {
    pearlite! { exists<j> row_covers(cat.rows@, j, s.words@) }
}

/// Every simple command of `sc` is covered by `cat`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn covered_script(cat: Catalog, sc: Script) -> bool {
    pearlite! {
        forall<a: Addr> valid_addr(sc, a) ==> covered_simple(cat, simple_at_l(sc, a))
    }
}

/// `b` names a command before `a` in script order (item, then link, then
/// command); word indices are ignored.
#[cfg(creusot)]
#[logic(open)]
pub fn addr_before(b: Addr, a: Addr) -> bool {
    pearlite! {
        b.item@ < a.item@
            || (b.item@ == a.item@
                && (b.link@ < a.link@ || (b.link@ == a.link@ && b.cmd@ < a.cmd@)))
    }
}

/// Proof that a script is covered by a catalog: only [`classify_script`]
/// builds one (`_sealed` is private to this module, and the other fields are
/// crate-private), and it owns the script it certifies (#1006).
#[cfg_attr(not(creusot), derive(Debug))]
pub struct Witness {
    _sealed: (),
    /// The certified script.
    pub(crate) script: Script,
    /// The catalog the script was checked against (ghost).
    #[cfg(creusot)]
    pub(crate) cat: Snapshot<Catalog>,
}

#[cfg(creusot)]
impl Invariant for Witness {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { covered_script(*self.cat, self.script) }
    }
}

impl Witness {
    /// The certified script.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.script))]
    #[must_use]
    pub fn script(&self) -> &Script {
        &self.script
    }
}

/// The result of [`classify_script`].
#[cfg_attr(not(creusot), derive(Debug))]
pub enum Classified {
    /// Every simple command is covered.
    Covered(Witness),
    /// The script, unchanged, and why its first uncovered command is not
    /// covered.
    Uncovered(Script, Reason),
}

/// The result of [`classify_simple`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum SimpleClass {
    /// The row with this index covers the command.
    Covered {
        /// Index into the catalog's rows.
        row: usize,
    },
    /// No row covers the command; the reason and the word it is about.
    Unknown(UnknownKind, usize),
}

/// The words `ws` start with the literal key `key`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == key_matches(key@, ws@)))]
pub(crate) fn key_match(key: &[Vec<u8>], ws: &[Word]) -> bool {
    if key.len() > ws.len() {
        return false;
    }
    let mut t: usize = 0;
    #[cfg_attr(creusot, variant(key@.len() - t@))]
    #[cfg_attr(creusot, invariant(t@ <= key@.len()))]
    #[cfg_attr(creusot, invariant(forall<u> 0 <= u && u < t@ ==> seg_is(ws@[u], key@[u]@)))]
    while t < key.len() {
        let (b, opaque) = word_view(&ws[t]);
        if opaque || !bytes_eq(&b, &key[t]) {
            return false;
        }
        t += 1;
    }
    true
}

/// The key `long` strictly extends the key `short`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == extends_l(long@, short@)))]
fn extends(long: &[Vec<u8>], short: &[Vec<u8>]) -> bool {
    if long.len() <= short.len() {
        return false;
    }
    let mut t: usize = 0;
    #[cfg_attr(creusot, variant(short@.len() - t@))]
    #[cfg_attr(creusot, invariant(t@ <= short@.len()))]
    #[cfg_attr(creusot, invariant(forall<u> 0 <= u && u < t@ ==> long@[u]@ == short@[u]@))]
    while t < short.len() {
        if !bytes_eq(&long[t], &short[t]) {
            return false;
        }
        t += 1;
    }
    true
}

/// `rows[j]` is a parent row.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(j@ < rows@.len()))]
#[cfg_attr(creusot, ensures(result == is_parent_l(rows@, j@)))]
fn is_parent(rows: &[Row], j: usize) -> bool {
    let mut m: usize = 0;
    #[cfg_attr(creusot, variant(rows@.len() - m@))]
    #[cfg_attr(creusot, invariant(m@ <= rows@.len()))]
    #[cfg_attr(creusot, invariant(forall<n> 0 <= n && n < m@
        ==> !extends_l(rows@[n].key@, rows@[j@].key@)))]
    while m < rows.len() {
        if extends(&rows[m].key, &rows[j].key) {
            return true;
        }
        m += 1;
    }
    false
}

/// Some row whose key strictly extends the key of `rows[j]` matches `ws` and
/// runs code.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(j@ < rows@.len()))]
#[cfg_attr(creusot, ensures(result == code_child_l(rows@, j@, ws@)))]
fn code_child(rows: &[Row], j: usize, ws: &[Word]) -> bool {
    let mut m: usize = 0;
    #[cfg_attr(creusot, variant(rows@.len() - m@))]
    #[cfg_attr(creusot, invariant(m@ <= rows@.len()))]
    #[cfg_attr(creusot, invariant(forall<n> 0 <= n && n < m@
        ==> !(extends_l(rows@[n].key@, rows@[j@].key@)
            && key_matches(rows@[n].key@, ws@) && rows@[n].runs_code)))]
    while m < rows.len() {
        if rows[m].runs_code && extends(&rows[m].key, &rows[j].key) && key_match(&rows[m].key, ws) {
            return true;
        }
        m += 1;
    }
    false
}

/// The index of the first operand slot, if any.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    None => !has_operand(slots@),
    Some(k) => k@ < slots@.len() && is_operand(slots@[k@]),
}))]
fn first_operand(slots: &[Slot]) -> Option<usize> {
    let mut k: usize = 0;
    #[cfg_attr(creusot, variant(slots@.len() - k@))]
    #[cfg_attr(creusot, invariant(k@ <= slots@.len()))]
    #[cfg_attr(creusot, invariant(forall<u> 0 <= u && u < k@ ==> !is_operand(slots@[u])))]
    while k < slots.len() {
        match slots[k] {
            Slot::Operand(_) => return Some(k),
            Slot::Opts(_) | Slot::OptValue(_) | Slot::DashDash => {}
        }
        k += 1;
    }
    None
}

/// How one row relates to a simple command.
enum RowFit {
    /// The row covers the command.
    Covers,
    /// The key matches but the row does not cover; the reason and word.
    Miss(UnknownKind, usize),
    /// The key does not match.
    NoKey,
}

/// How `rows[j]` relates to the simple command with words `ws`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(j@ < rows@.len() && ws@.len() > 0))]
#[cfg_attr(creusot, ensures(match result {
    RowFit::Covers => row_covers(rows@, j@, ws@),
    RowFit::Miss(_, w) => !row_covers(rows@, j@, ws@) && w@ < ws@.len(),
    RowFit::NoKey => !row_covers(rows@, j@, ws@),
}))]
fn row_fit(rows: &[Row], j: usize, ws: &[Word]) -> RowFit {
    let row = &rows[j];
    if !key_match(&row.key, ws) {
        return RowFit::NoKey;
    }
    if row.runs_code {
        return RowFit::Miss(UnknownKind::RunsCode, 0);
    }
    if code_child(rows, j, ws) {
        // The longer key matches, so `ws` has a word past this row's key.
        return RowFit::Miss(UnknownKind::RunsCode, row.key.len());
    }
    match parse_argv(&row.grammar, ws, row.key.len()) {
        ArgvResult::Unknown(u, i) => RowFit::Miss(u, i),
        ArgvResult::Parsed(p) => {
            if !is_parent(rows, j) {
                return RowFit::Covers;
            }
            match first_operand(&p.slots) {
                None => RowFit::Covers,
                Some(k) => RowFit::Miss(UnknownKind::UnknownSubcommand, row.key.len() + k),
            }
        }
    }
}

/// Classifies one simple command against the catalog: the first row (in
/// catalog order) that covers it, or the reason none does (see the module
/// docs).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    SimpleClass::Covered { row } => row_covers(cat.rows@, row@, s.words@)
        && covered_simple(*cat, *s)
        && forall<m> 0 <= m && m < row@ ==> !row_covers(cat.rows@, m, s.words@),
    SimpleClass::Unknown(_, w) => !covered_simple(*cat, *s) && w@ < s.words@.len(),
}))]
#[must_use]
#[expect(
    clippy::module_name_repetitions,
    reason = "the milestone API names classify_simple and classify_script"
)]
pub fn classify_simple(cat: &Catalog, s: &Simple) -> SimpleClass {
    let ws = &s.words;
    let rows = &cat.rows;
    let (_, opaque) = word_view(&ws[0]);
    if opaque {
        #[cfg(creusot)]
        proof_assert! {
            forall<m> 0 <= m && m < rows@.len() ==> rows@[m].key@.len() > 0
                && !seg_is(ws@[0], rows@[m].key@[0]@)
        };
        return SimpleClass::Unknown(UnknownKind::OpaqueCommandName, 0);
    }
    let mut first: Option<(UnknownKind, usize)> = None;
    let mut j: usize = 0;
    #[cfg_attr(creusot, variant(rows@.len() - j@))]
    #[cfg_attr(creusot, invariant(j@ <= rows@.len()))]
    #[cfg_attr(creusot, invariant(forall<m> 0 <= m && m < j@ ==> !row_covers(rows@, m, ws@)))]
    #[cfg_attr(creusot, invariant(match first {
        Some((_, w)) => w@ < ws@.len(),
        None => true,
    }))]
    while j < rows.len() {
        match row_fit(rows, j, ws) {
            RowFit::Covers => return SimpleClass::Covered { row: j },
            RowFit::Miss(u, w) => {
                if first.is_none() {
                    first = Some((u, w));
                }
            }
            RowFit::NoKey => {}
        }
        j += 1;
    }
    match first {
        None => SimpleClass::Unknown(UnknownKind::NoRow, 0),
        Some((u, w)) => SimpleClass::Unknown(u, w),
    }
}

/// The first uncovered command of `p`: its index, reason and word.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    None => forall<c> 0 <= c && c < p.cmds@.len() ==> covered_simple(*cat, p.cmds@[c]),
    Some((c, _, w)) => c@ < p.cmds@.len() && w@ < p.cmds@[c@].words@.len()
        && !covered_simple(*cat, p.cmds@[c@])
        && forall<d> 0 <= d && d < c@ ==> covered_simple(*cat, p.cmds@[d]),
}))]
fn pipeline_uncovered(cat: &Catalog, p: &Pipeline) -> Option<(usize, UnknownKind, usize)> {
    let cmds = &p.cmds;
    let mut c: usize = 0;
    #[cfg_attr(creusot, variant(cmds@.len() - c@))]
    #[cfg_attr(creusot, invariant(c@ <= cmds@.len()))]
    #[cfg_attr(creusot, invariant(forall<d> 0 <= d && d < c@ ==> covered_simple(*cat, cmds@[d])))]
    while c < cmds.len() {
        match classify_simple(cat, &cmds[c]) {
            SimpleClass::Covered { .. } => {}
            SimpleClass::Unknown(u, w) => return Some((c, u, w)),
        }
        c += 1;
    }
    None
}

/// The first uncovered command of `sc` in address order, with its reason.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    None => covered_script(*cat, *sc),
    Some((_, a)) => valid_addr(*sc, a) && !covered_simple(*cat, simple_at_l(*sc, a))
        && forall<b: Addr> valid_addr(*sc, b) && addr_before(b, a)
            ==> covered_simple(*cat, simple_at_l(*sc, b)),
}))]
fn first_uncovered(cat: &Catalog, sc: &Script) -> Option<(UnknownKind, Addr)> {
    let items = &sc.items;
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(items@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= items@.len()))]
    #[cfg_attr(creusot, invariant(forall<b: Addr> valid_addr(*sc, b) && b.item@ < i@
        ==> covered_simple(*cat, simple_at_l(*sc, b))))]
    while i < items.len() {
        let ao = &items[i];
        if let Some((c, u, w)) = pipeline_uncovered(cat, &ao.first) {
            return Some((
                u,
                Addr {
                    item: i,
                    link: 0,
                    cmd: c,
                    word: Some(w),
                },
            ));
        }
        let mut k: usize = 0;
        #[cfg_attr(creusot, variant(ao.rest@.len() - k@))]
        #[cfg_attr(creusot, invariant(k@ <= ao.rest@.len()))]
        #[cfg_attr(creusot, invariant(forall<b: Addr> valid_addr(*sc, b) && b.item@ < i@
            ==> covered_simple(*cat, simple_at_l(*sc, b))))]
        #[cfg_attr(creusot, invariant(forall<b: Addr> valid_addr(*sc, b) && b.item@ == i@
            && b.link@ <= k@ ==> covered_simple(*cat, simple_at_l(*sc, b))))]
        while k < ao.rest.len() {
            if let Some((c, u, w)) = pipeline_uncovered(cat, &ao.rest[k].rhs) {
                return Some((
                    u,
                    Addr {
                        item: i,
                        link: k + 1,
                        cmd: c,
                        word: Some(w),
                    },
                ));
            }
            k += 1;
        }
        i += 1;
    }
    None
}

/// Classifies a script (theorem T2): a [`Witness`] that owns the script when
/// every simple command is covered, else the script, unchanged, with the
/// first uncovered command's address (the word is the reason's word).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    Classified::Covered(w) => w.script == sc && *w.cat == *cat
        && covered_script(*cat, w.script),
    Classified::Uncovered(sc2, r) => sc2 == sc && match r {
        Reason::Unknown(_, a) => valid_addr(sc2, a)
            && !covered_simple(*cat, simple_at_l(sc2, a))
            && forall<b: Addr> valid_addr(sc2, b) && addr_before(b, a)
                ==> covered_simple(*cat, simple_at_l(sc2, b)),
        Reason::Rule(_, _) => false,
    },
}))]
#[must_use]
#[expect(
    clippy::module_name_repetitions,
    reason = "the milestone API names classify_simple and classify_script"
)]
pub fn classify_script(cat: &Catalog, sc: Script) -> Classified {
    match first_uncovered(cat, &sc) {
        None => Classified::Covered(Witness {
            _sealed: (),
            script: sc,
            #[cfg(creusot)]
            cat: snapshot!(*cat),
        }),
        Some((u, a)) => Classified::Uncovered(sc, Reason::Unknown(u, a)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Classified, SimpleClass, classify_script, classify_simple};
    use crate::ast::{AndOr, Connector, Link, Opaque, Part, Pipeline, Script, Simple, Word};
    use crate::catalog::{
        Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role,
        Row, RunsCode, ShortName,
    };
    use crate::verdict::{Addr, Reason, UnknownKind};

    fn key(segs: &[&str]) -> Vec<Vec<u8>> {
        segs.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    fn short(b: u8) -> ShortName {
        ShortName::new(b).expect("printable, not '-'")
    }

    fn flag(c: u8) -> Opt {
        Opt::new(OptName::Short(short(c)), OptValue::Flag)
    }

    fn long_flag(name: &str) -> Opt {
        let name = LongName::new(name.as_bytes().to_vec()).expect("well-formed long name");
        Opt::new(OptName::Long(name), OptValue::Flag)
    }

    fn row(segs: &[&str], g: Grammar, runs_code: RunsCode) -> Row {
        Row::new(key(segs), g, runs_code, Cwd::Keeps).expect("valid key")
    }

    /// `ls [-l] [-a] [path...]`
    fn ls_grammar() -> Grammar {
        Grammar::new(
            vec![flag(b'l'), flag(b'a')],
            Vec::new(),
            Some(Role::Path),
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    /// `git [--version] [inert...]`: the parent row of the git subcommands.
    fn git_grammar() -> Grammar {
        Grammar::new(
            vec![long_flag("version")],
            Vec::new(),
            Some(Role::Inert),
            Order::Strict,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    fn no_args() -> Grammar {
        Grammar::new(
            Vec::new(),
            Vec::new(),
            None,
            Order::Strict,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    fn catalog() -> Catalog {
        Catalog::new(
            vec![
                row(&["ls"], ls_grammar(), RunsCode::No),
                row(&["git"], git_grammar(), RunsCode::No),
                row(&["git", "status"], no_args(), RunsCode::No),
                row(&["sh"], ls_grammar(), RunsCode::Yes),
            ],
            Vec::new(),
        )
    }

    fn lit_word(s: &str) -> Word {
        Word::new(vec![Part::Lit(s.as_bytes().to_vec())]).expect("non-empty")
    }

    fn cmd(words: &[&str]) -> Simple {
        Simple::new(words.iter().map(|w| lit_word(w)).collect(), Vec::new()).expect("non-empty")
    }

    fn pipeline(cmds: Vec<Simple>) -> Pipeline {
        Pipeline::new(cmds).expect("non-empty")
    }

    fn unknown(kind: UnknownKind, at: usize) -> SimpleClass {
        SimpleClass::Unknown(kind, at)
    }

    #[test]
    fn ls_la_is_covered() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["ls", "-la"])),
            SimpleClass::Covered { row: 0 }
        );
    }

    #[test]
    fn unknown_tool_has_no_row() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["unknowntool", "x"])),
            unknown(UnknownKind::NoRow, 0)
        );
    }

    #[test]
    fn opaque_command_name() {
        let var = Word::new(vec![Part::Opaque(Opaque::Var(b"X".to_vec()))]).expect("non-empty");
        let s = Simple::new(vec![var, lit_word("foo")], Vec::new()).expect("non-empty");
        assert_eq!(
            classify_simple(&catalog(), &s),
            unknown(UnknownKind::OpaqueCommandName, 0)
        );
    }

    #[test]
    fn subcommand_row_covers() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "status"])),
            SimpleClass::Covered { row: 2 }
        );
    }

    #[test]
    fn parent_row_rejects_unlisted_subcommand() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "push"])),
            unknown(UnknownKind::UnknownSubcommand, 1)
        );
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "push", "origin"])),
            unknown(UnknownKind::UnknownSubcommand, 1)
        );
        // `git_grammar` has no `permute`, so the argv parse fails first.
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "push", "--force"])),
            unknown(UnknownKind::OptionAfterOperand, 2)
        );
    }

    #[test]
    fn parent_row_without_operand_covers() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "--version"])),
            SimpleClass::Covered { row: 1 }
        );
    }

    #[test]
    fn leaf_row_with_operand_covers() {
        // `["ls"]` is not a parent, so its operands are fine.
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["ls", "src"])),
            SimpleClass::Covered { row: 0 }
        );
    }

    #[test]
    fn runs_code_row() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["sh", "x"])),
            unknown(UnknownKind::RunsCode, 0)
        );
    }

    /// `python [--version] [-c CMD]` with no operands.
    fn python_grammar() -> Grammar {
        Grammar::new(
            vec![
                long_flag("version"),
                Opt::new(OptName::Short(short(b'c')), OptValue::Takes(Role::Inert)),
            ],
            Vec::new(),
            None,
            Order::Strict,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    #[test]
    fn a_runs_code_child_blocks_its_parent() {
        // Without the child row, `["python"]` would cover `python -c x`.
        let alone = Catalog::new(
            vec![row(&["python"], python_grammar(), RunsCode::No)],
            Vec::new(),
        );
        assert_eq!(
            classify_simple(&alone, &cmd(&["python", "-c", "x"])),
            SimpleClass::Covered { row: 0 }
        );
        // (rows, index of the parent row)
        for (rows, parent) in [
            (
                vec![
                    row(&["python"], python_grammar(), RunsCode::No),
                    row(&["python", "-c"], no_args(), RunsCode::Yes),
                ],
                0,
            ),
            (
                vec![
                    row(&["python", "-c"], no_args(), RunsCode::Yes),
                    row(&["python"], python_grammar(), RunsCode::No),
                ],
                1,
            ),
        ] {
            let cat = Catalog::new(rows, Vec::new());
            assert!(matches!(
                classify_simple(&cat, &cmd(&["python", "-c", "x"])),
                SimpleClass::Unknown(UnknownKind::RunsCode, _)
            ));
            // No child key matches, so the parent still covers.
            assert_eq!(
                classify_simple(&cat, &cmd(&["python", "--version"])),
                SimpleClass::Covered { row: parent }
            );
        }
        let cat = Catalog::new(
            vec![
                row(&["python"], python_grammar(), RunsCode::No),
                row(&["python", "-c"], no_args(), RunsCode::Yes),
            ],
            Vec::new(),
        );
        assert_eq!(
            classify_simple(&cat, &cmd(&["python", "-c", "x"])),
            unknown(UnknownKind::RunsCode, 1)
        );
    }

    #[test]
    fn a_child_that_does_not_run_code_leaves_its_parent_covering() {
        let cat = Catalog::new(
            vec![
                row(&["python"], python_grammar(), RunsCode::No),
                row(&["python", "-c"], no_args(), RunsCode::No),
            ],
            Vec::new(),
        );
        assert_eq!(
            classify_simple(&cat, &cmd(&["python", "-c", "x"])),
            SimpleClass::Covered { row: 0 }
        );
    }

    #[test]
    fn argv_unknown_is_propagated() {
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["ls", "-l", "--bogus"])),
            unknown(UnknownKind::UnknownOption, 2)
        );
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "status", "x"])),
            unknown(UnknownKind::UnknownSubcommand, 1),
            "the first matching row's reason wins"
        );
    }

    #[test]
    fn globals_are_not_used() {
        assert!(matches!(
            classify_simple(&catalog(), &cmd(&["git", "-C", "x", "status"])),
            SimpleClass::Unknown(_, _)
        ));
        // `-C` is not in the `["git"]` grammar, and `["git", "status"]` fails at word 1.
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "-C", "x", "status"])),
            unknown(UnknownKind::UnknownOption, 1)
        );
    }

    #[test]
    fn duplicate_rows_second_covers() {
        let cat = Catalog::new(
            vec![
                row(&["ls"], no_args(), RunsCode::No),
                row(&["ls"], ls_grammar(), RunsCode::No),
            ],
            Vec::new(),
        );
        assert_eq!(
            classify_simple(&cat, &cmd(&["ls", "-la"])),
            SimpleClass::Covered { row: 1 }
        );
    }

    #[test]
    fn empty_script_is_covered() {
        let Classified::Covered(w) = classify_script(&catalog(), Script::new(Vec::new())) else {
            panic!("an empty script is covered");
        };
        assert_eq!(*w.script(), Script::new(Vec::new()));
    }

    #[test]
    fn covered_script_witness_owns_the_script() {
        // `ls -la | git status ; git --version`
        let sc = Script::new(vec![
            AndOr::new(
                pipeline(vec![cmd(&["ls", "-la"]), cmd(&["git", "status"])]),
                Vec::new(),
            ),
            AndOr::new(pipeline(vec![cmd(&["git", "--version"])]), Vec::new()),
        ]);
        let Classified::Covered(w) = classify_script(&catalog(), sc.clone()) else {
            panic!("covered");
        };
        assert_eq!(*w.script(), sc);
    }

    /// The script is uncovered at `want` with reason `kind`, and comes back unchanged.
    fn check_second_uncovered(sc: Script, want: Addr, kind: UnknownKind) {
        let Classified::Uncovered(back, reason) = classify_script(&catalog(), sc.clone()) else {
            panic!("uncovered");
        };
        assert_eq!(back, sc);
        assert_eq!(reason, Reason::Unknown(kind, want));
    }

    #[test]
    fn first_uncovered_in_a_link() {
        // `ls -la && unknowntool x ; ls`
        let sc = Script::new(vec![
            AndOr::new(
                pipeline(vec![cmd(&["ls", "-la"])]),
                vec![Link::new(
                    Connector::And,
                    pipeline(vec![cmd(&["unknowntool", "x"])]),
                )],
            ),
            AndOr::new(pipeline(vec![cmd(&["ls"])]), Vec::new()),
        ]);
        let want = Addr {
            item: 0,
            link: 1,
            cmd: 0,
            word: Some(0),
        };
        check_second_uncovered(sc, want, UnknownKind::NoRow);
    }

    #[test]
    fn first_uncovered_in_a_pipeline() {
        // `ls | ls --bogus | git push` reports the second command only.
        let sc = Script::new(vec![AndOr::new(
            pipeline(vec![
                cmd(&["ls"]),
                cmd(&["ls", "--bogus"]),
                cmd(&["git", "push"]),
            ]),
            Vec::new(),
        )]);
        let want = Addr {
            item: 0,
            link: 0,
            cmd: 1,
            word: Some(1),
        };
        check_second_uncovered(sc, want, UnknownKind::UnknownOption);
    }

    #[test]
    fn split_literal_key_word_matches() {
        // `gi''t status`: the key word's bytes are the concatenation.
        let gi_t = Word::new(vec![
            Part::Lit(b"gi".to_vec()),
            Part::Lit(Vec::new()),
            Part::Lit(b"t".to_vec()),
        ])
        .expect("non-empty");
        let s = Simple::new(vec![gi_t, lit_word("status")], Vec::new()).expect("non-empty");
        assert_eq!(
            classify_simple(&catalog(), &s),
            SimpleClass::Covered { row: 2 }
        );
    }

    #[test]
    fn opaque_operand_of_parent_is_unknown() {
        // `git $X`: the parent `["git"]` must not cover it.
        let var = Word::new(vec![Part::Opaque(Opaque::Var(b"X".to_vec()))]).expect("non-empty");
        let s = Simple::new(vec![lit_word("git"), var], Vec::new()).expect("non-empty");
        assert_eq!(
            classify_simple(&catalog(), &s),
            unknown(UnknownKind::OpaqueOption, 1)
        );
    }

    #[test]
    fn non_permuting_parent_operand_after_option() {
        // `git_grammar` has `permute: false`.
        assert_eq!(
            classify_simple(&catalog(), &cmd(&["git", "--version", "push"])),
            unknown(UnknownKind::UnknownSubcommand, 2)
        );
    }

    #[test]
    fn redirects_do_not_affect_coverage() {
        use crate::ast::Redir;
        let words = || vec![lit_word("ls"), lit_word("-la")];
        let redirs = [
            Redir::ErrToOut,
            Redir::OutToErr,
            Redir::OutDevNull,
            Redir::ErrDevNull,
        ];
        for r in redirs {
            let s = Simple::new(words(), vec![r]).expect("non-empty");
            assert_eq!(
                classify_simple(&catalog(), &s),
                SimpleClass::Covered { row: 0 },
                "{r:?}"
            );
        }
        let all = Simple::new(words(), redirs.to_vec()).expect("non-empty");
        assert_eq!(
            classify_simple(&catalog(), &all),
            SimpleClass::Covered { row: 0 }
        );
    }

    #[test]
    fn first_uncovered_in_a_later_item() {
        // `ls ; unknowntool ; ls`
        let sc = Script::new(vec![
            AndOr::new(pipeline(vec![cmd(&["ls"])]), Vec::new()),
            AndOr::new(pipeline(vec![cmd(&["unknowntool"])]), Vec::new()),
            AndOr::new(pipeline(vec![cmd(&["ls"])]), Vec::new()),
        ]);
        let want = Addr {
            item: 1,
            link: 0,
            cmd: 0,
            word: Some(0),
        };
        check_second_uncovered(sc, want, UnknownKind::NoRow);
    }

    #[test]
    fn first_uncovered_in_a_link_pipeline() {
        // `ls && ls | sh x` reports the third command, at link 1, cmd 1.
        let sc = Script::new(vec![AndOr::new(
            pipeline(vec![cmd(&["ls"])]),
            vec![Link::new(
                Connector::And,
                pipeline(vec![cmd(&["ls"]), cmd(&["sh", "x"])]),
            )],
        )]);
        let want = Addr {
            item: 0,
            link: 1,
            cmd: 1,
            word: Some(0),
        };
        check_second_uncovered(sc, want, UnknownKind::RunsCode);
    }
}
