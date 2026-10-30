//! Rule hits, path checks and the final [`Verdict`]: theorem T3 (`decide`
//! computes `decision_of`) and theorem T4 (`decision_of` is monotone in the
//! rules).
//!
//! Everything here only raises a decision. Soundness means no wrong Allow,
//! so a notion that fires more often than intended is safe, and the places
//! where this module deliberately does so are listed below.
//!
//! # Selected row
//!
//! A covered simple command's selected row is the first row, in catalog
//! order, that covers it (`selected_row`). Rules and path checks read the
//! command through that row's argv parse. An uncovered simple command
//! contributes Ask (its classification reason) and nothing else in v1, so a
//! Block rule on a command whose parse fails yields Ask, not Block.
//!
//! # Rule hits (`hit_row`)
//!
//! A rule hits a covered simple command when:
//! - its key matches the command the way row keys do (`key_matches`);
//! - every option name of the rule overlaps an option the parse saw: they
//!   share a short name, or have long names with equal bytes (#1025 A);
//! - for `Scope::Simple`: the target list is empty, or some target word
//!   matches some pattern. Target words are the words in `Operand(Path)`
//!   and `OptValue(Path)` slots, and the inline values of `Opts(Some(Path))`
//!   slots (`--file=/x`, `-t/x`): the bytes of the option word from the
//!   slot's offset on, read as a literal path word without `~` (#1034). An
//!   inline value that cannot be read (the word is opaque or the offset is
//!   outside it; `argv_spec` never builds that, but it is not proved) counts
//!   as matching any pattern;
//! - for `Scope::PipeInto`: the command is not the first of its pipeline.
//!   Targets are ignored.
//!
//! # Pattern match (`pat_matches`, #1026 A)
//!
//! Words and patterns are compared on a canonical view: adjacent `Lit`s
//! merged, empty `Lit`s dropped. Of that view the kernel keeps the head
//! (does it start with `~`), the lead (the literal bytes after the head, up
//! to the next opaque part) and whether more opaque parts follow.
//!
//! Words and patterns alike get a key (`path_key`) when no opaque part
//! follows the lead: a bare `~` has the key `/`, so `~`, `~/`, `~/.` and
//! `~//` share one key; a lead that starts with `/` is normalized with
//! `normalize_path` (`/etc/` and `/etc` share one key); any other lead is
//! its own key. With an opaque part after the lead, the key is the lead.
//! The heads must agree, and then a pattern matches when either reading
//! holds:
//! - on keys: `Exact` when the word has no further opaque part and the keys
//!   are equal; `Prefix` when the pattern's key is a byte prefix of the
//!   word's;
//! - on the pattern's raw lead against the word's normalized lead (without
//!   the `~` rule): the same two comparisons. This reading is the previous
//!   one, kept so the key reading only adds hits.
//!
//! A byte prefix over-matches (`/etc` matches `/etcfoo`), which is
//! acceptable for raise-only rules. A pattern whose canonical view is empty
//! (only empty `Lit`s) matches every word as `Prefix`, and as `Exact`
//! matches only a word that is itself empty.
//!
//! A `/`-led pattern never covers a `~` word, since the heads differ: to
//! cover the home directory, add a `~` `Prefix` target (`[Tilde]` as
//! `Prefix` matches every `~` word, `~` and `~/x` included).
//!
//! This equals the canonical-sequence comparison for every pattern without
//! an opaque part beyond a leading `~`, up to path normalization.
//! Deliberately more permissive: a pattern with such a part (`$HOME/x`)
//! matches every word.
//!
//! # Path checks (`word_path_fails`)
//!
//! On a covered simple command, each of these makes it Ask:
//! - `PathOpaque`: a path word that is neither fully literal nor `~`
//!   followed by literal bytes;
//! - `PathDotDot`: a `..` segment in the literal bytes of a path word. This
//!   also covers the bytes after a leading `~` (`~/../x`), a deliberate
//!   extension;
//! - `PathAfterCd`: a relative path word (no leading `/`, no `~`) after an
//!   earlier covered command, in address order, whose selected row has
//!   `changes_cwd`.
//!
//! The same three checks apply to an inline path value
//! (`inline_path_fails`). An empty value (`--file=`) is relative, so it fails
//! `PathAfterCd` after a `cd`. An unreadable value fails as `PathOpaque`.
//!
//! # The decision and the verdict
//!
//! `decision_of` is Block when some rule with a Block outcome hits at some
//! address; otherwise Ask when the script is not covered, a path check
//! fails, or an Ask rule hits; otherwise Allow. [`decide`] computes it
//! (T3) and returns a [`Verdict`] that owns the script (#1006). Its Allow
//! carries an [`Allowed`], which only `decide` builds, from the [`Witness`]
//! that `decide` itself obtains from `classify_script` on the catalog it was
//! given; its invariant states the plan's corollary.

#[cfg(creusot)]
use crate::argv::{
    ArgvL, Phase, SlotL, argv_spec, has_long, has_opaque, has_short, ints, lemma_go_no_code,
    lemma_ints_index, lemma_slots_index, lit_prefix, no_code, slots_l,
};
use crate::argv::{ArgvResult, Parse, Slot, long_is, parse_argv, parts_view, short_is, word_view};
use crate::ast::{Opaque, Part, Script, Simple, Word};
use crate::bytes::{DOT, SLASH, bytes_eq, normalize_path, starts_with};
#[cfg(creusot)]
use crate::bytes::{lemma_sub_snoc, norm_l};
#[cfg(creusot)]
use crate::catalog::Row;
use crate::catalog::{Catalog, Opt, OptName, Role};
use crate::classify::{
    Classified, SimpleClass, Witness, classify_script, classify_simple, key_match,
};
#[cfg(creusot)]
use crate::classify::{covered_script, covered_simple, key_matches, row_covers};
use crate::decision::Decision;
#[cfg(creusot)]
use crate::decision::le;
use crate::rule::{OptAlts, Outcome, Pat, PatKind, Rule, Scope};
use crate::verdict::{Addr, Reason, UnknownKind};
#[cfg(creusot)]
use crate::verdict::{simple_at_l, valid_addr};
#[cfg(creusot)]
use creusot_std::prelude::*;

// ---------------------------------------------------------------------------
// Selected row
// ---------------------------------------------------------------------------

/// `rows[j]` is the selected row of the command with words `ws`: the first
/// row that covers it.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn selected_row(rows: Seq<Row>, j: Int, ws: Seq<Word>) -> bool {
    pearlite! {
        row_covers(rows, j, ws) && forall<m> 0 <= m && m < j ==> !row_covers(rows, m, ws)
    }
}

/// There is at most one selected row.
#[cfg(creusot)]
#[logic]
#[ensures(forall<j, m> selected_row(rows, j, ws) && selected_row(rows, m, ws) ==> j == m)]
pub fn lemma_selected_unique(rows: Seq<Row>, ws: Seq<Word>) {}

// ---------------------------------------------------------------------------
// Canonical view of words and patterns
// ---------------------------------------------------------------------------

/// The index of the first part of `parts[j..]` that is not an empty `Lit`,
/// or `parts.len()`.
#[cfg(creusot)]
#[logic(open)]
#[variant(parts.len() - j)]
pub fn lead_skip(parts: Seq<Part>, j: Int) -> Int {
    pearlite! {
        if j < 0 || j >= parts.len() {
            parts.len()
        } else {
            match parts[j] {
                Part::Lit(b) => if b@.len() == 0 { lead_skip(parts, j + 1) } else { j },
                Part::Opaque(_) => j,
            }
        }
    }
}

/// `p` is a `~`.
#[cfg(creusot)]
#[logic(open)]
pub fn is_tilde(p: Part) -> bool {
    match p {
        Part::Opaque(Opaque::Tilde) => true,
        Part::Opaque(Opaque::Var(_)) | Part::Lit(_) => false,
    }
}

/// The canonical view of `parts` starts with `~`.
#[cfg(creusot)]
#[logic(open)]
pub fn path_tilde(parts: Seq<Part>) -> bool {
    pearlite! { lead_skip(parts, 0) < parts.len() && is_tilde(parts[lead_skip(parts, 0)]) }
}

/// Where the lead starts: after the leading `~`, if any.
#[cfg(creusot)]
#[logic(open)]
pub fn body_start(parts: Seq<Part>) -> Int {
    if path_tilde(parts) {
        lead_skip(parts, 0) + 1
    } else {
        0
    }
}

/// The literal bytes after the head, up to the next opaque part.
#[cfg(creusot)]
#[logic(open)]
pub fn path_lead(parts: Seq<Part>) -> Seq<u8> {
    lit_prefix(parts, body_start(parts))
}

/// An opaque part follows the lead: the word is neither fully literal nor
/// `~` followed by literal bytes.
#[cfg(creusot)]
#[logic(open)]
pub fn path_more(parts: Seq<Part>) -> bool {
    has_opaque(parts, body_start(parts))
}

/// `b` starts with `/`.
#[cfg(creusot)]
#[logic(open)]
pub fn starts_slash(b: Seq<u8>) -> bool {
    pearlite! { b.len() > 0 && b[0] == SLASH }
}

/// The lead, normalized when nothing opaque follows it and it starts with
/// `/`.
#[cfg(creusot)]
#[logic(open)]
pub fn path_norm(parts: Seq<Part>) -> Seq<u8> {
    if !path_more(parts) && starts_slash(path_lead(parts)) {
        norm_l(path_lead(parts))
    } else {
        path_lead(parts)
    }
}

/// The key a word or pattern is compared on: `path_norm`, except that a
/// bare `~` (nothing after it) has the key `/`, like `~/`.
#[cfg(creusot)]
#[logic(open)]
pub fn path_key(parts: Seq<Part>) -> Seq<u8> {
    if path_tilde(parts) && !path_more(parts) && path_lead(parts).len() == 0 {
        Seq::singleton(SLASH)
    } else {
        path_norm(parts)
    }
}

/// `q` is a byte prefix of `s`.
#[cfg(creusot)]
#[logic(open)]
pub fn is_prefix(q: Seq<u8>, s: Seq<u8>) -> bool {
    pearlite! { q.len() <= s.len() && s.subsequence(0, q.len()) == q }
}

/// `pat` matches a word whose view is head `wt`, normalized lead `wnorm`,
/// key `wkey` and trailing-opaque flag `wmore`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn pat_match_view(pat: Pat, wt: bool, wnorm: Seq<u8>, wkey: Seq<u8>, wmore: bool) -> bool {
    pearlite! {
        if path_more(pat.parts@) {
            true
        } else if path_tilde(pat.parts@) != wt {
            !path_tilde(pat.parts@) && path_lead(pat.parts@).len() == 0
                && pat.kind == PatKind::Prefix
        } else {
            match pat.kind {
                PatKind::Exact => !wmore
                    && (wnorm == path_lead(pat.parts@) || wkey == path_key(pat.parts@)),
                PatKind::Prefix => is_prefix(path_lead(pat.parts@), wnorm)
                    || is_prefix(path_key(pat.parts@), wkey),
            }
        }
    }
}

/// `pat` matches the word with parts `parts`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn pat_matches(pat: Pat, parts: Seq<Part>) -> bool {
    pat_match_view(
        pat,
        path_tilde(parts),
        path_norm(parts),
        path_key(parts),
        path_more(parts),
    )
}

/// Some pattern of `targets` matches the word with parts `parts`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn some_pat_matches(targets: Seq<Pat>, parts: Seq<Part>) -> bool {
    pearlite! { exists<t> 0 <= t && t < targets.len() && pat_matches(targets[t], parts) }
}

// ---------------------------------------------------------------------------
// Rule hits
// ---------------------------------------------------------------------------

/// `r` is the path role.
#[cfg(creusot)]
#[logic(open)]
pub fn is_path_role(r: Role) -> bool {
    match r {
        Role::Path => true,
        Role::Inert | Role::Code => false,
    }
}

/// The inline value of the option word with parts `parts`: its known bytes
/// from the offset `off` on.
#[cfg(creusot)]
#[logic(open)]
pub fn inline_value(parts: Seq<Part>, off: Int) -> Seq<u8> {
    pearlite! { lit_prefix(parts, 0).subsequence(off, lit_prefix(parts, 0).len()) }
}

/// The key an inline value is compared on: normalized when it starts with
/// `/`, like a literal path word (`path_norm` with no `~` and nothing opaque).
#[cfg(creusot)]
#[logic(open)]
pub fn inline_norm(v: Seq<u8>) -> Seq<u8> {
    if starts_slash(v) { norm_l(v) } else { v }
}

/// The inline value cannot be read: the option word is opaque or `off` is
/// outside it. `argv_spec` never builds such a slot (only a non-opaque word
/// is an option word, and the offset is at most its length), but nothing
/// proves that alignment, so a bad value fails closed: it hits every
/// pattern and fails the path check.
#[cfg(creusot)]
#[logic(open)]
pub fn inline_bad(parts: Seq<Part>, off: Int) -> bool {
    pearlite! { has_opaque(parts, 0) || off < 0 || off > lit_prefix(parts, 0).len() }
}

/// Some pattern of `targets` matches the inline value at `off` of the option
/// word with parts `parts`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn inline_path_hit(targets: Seq<Pat>, parts: Seq<Part>, off: Int) -> bool {
    pearlite! {
        inline_bad(parts, off)
            || exists<t> 0 <= t && t < targets.len()
                && pat_match_view(targets[t], false, inline_norm(inline_value(parts, off)),
                    inline_norm(inline_value(parts, off)), false)
    }
}

/// The inline value at `off` of the option word with parts `parts` fails a
/// path check; `cwd`: an earlier command changed the working directory.
#[cfg(creusot)]
#[logic(open)]
pub fn inline_path_fails(parts: Seq<Part>, off: Int, cwd: bool) -> bool {
    pearlite! {
        inline_bad(parts, off)
            || has_dotdot_l(inline_value(parts, off))
            || (cwd && !starts_slash(inline_value(parts, off)))
    }
}

/// The rule's targets hit the slot `s`, which is the word with parts `parts`:
/// a path operand or option value by `some_pat_matches`, a path value given
/// inline in an option word by `inline_path_hit`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn slot_hits(targets: Seq<Pat>, parts: Seq<Part>, s: SlotL) -> bool {
    pearlite! {
        match s {
            SlotL::Opts(Some((r, off))) => is_path_role(r) && inline_path_hit(targets, parts, off),
            SlotL::Operand(r) => is_path_role(r) && some_pat_matches(targets, parts),
            SlotL::OptValue(r) => is_path_role(r) && some_pat_matches(targets, parts),
            SlotL::Opts(None) | SlotL::DashDash => false,
        }
    }
}

/// The rule's targets hit the parse `slots` of `ws[start..]`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn targets_hit(targets: Seq<Pat>, ws: Seq<Word>, start: Int, slots: Seq<SlotL>) -> bool {
    pearlite! {
        targets.len() == 0
            || exists<k> 0 <= k && k < slots.len()
                && slot_hits(targets, ws[start + k].parts@, slots[k])
    }
}

/// The rule's option name `n` overlaps the grammar option `o`: a shared
/// short name, or long names with equal bytes.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn name_overlaps(n: OptName, o: Opt) -> bool {
    pearlite! {
        match n {
            OptName::Short(c) => has_short(o, c.byte),
            OptName::Long(l) => has_long(o, l.bytes@),
            OptName::Both(c, l) => has_short(o, c.byte) || has_long(o, l.bytes@),
        }
    }
}

/// Some option the parse saw (`seen`, indices into `gopts`) overlaps `n`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn opt_seen_l(n: OptName, gopts: Seq<Opt>, seen: Seq<Int>) -> bool {
    pearlite! {
        exists<u> 0 <= u && u < seen.len() && 0 <= seen[u] && seen[u] < gopts.len()
            && name_overlaps(n, gopts[seen[u]])
    }
}

/// Some name of the alias set `names` overlaps an option the parse saw.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn alts_seen_l(names: Seq<OptName>, gopts: Seq<Opt>, seen: Seq<Int>) -> bool {
    pearlite! {
        exists<a> 0 <= a && a < names.len() && opt_seen_l(names[a], gopts, seen)
    }
}

/// Every entry of the rule has some alternative name that overlaps an option
/// the parse saw: entries are conjoined, the names inside an entry disjoined.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn opts_hit(ropts: Seq<OptAlts>, gopts: Seq<Opt>, seen: Seq<Int>) -> bool {
    pearlite! { forall<t> 0 <= t && t < ropts.len() ==> alts_seen_l(ropts[t].names@, gopts, seen) }
}

/// `rule` hits the command with words `ws`, read by a grammar with options
/// `gopts` as the parse (`slots`, `seen`) of `ws[start..]`. `piped`: the
/// command is not the first of its pipeline.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn hit_parsed(
    rule: Rule,
    gopts: Seq<Opt>,
    ws: Seq<Word>,
    start: Int,
    slots: Seq<SlotL>,
    seen: Seq<Int>,
    piped: bool,
) -> bool {
    pearlite! {
        key_matches(rule.key@, ws)
            && opts_hit(rule.opts@, gopts, seen)
            && match rule.scope {
                Scope::Simple => targets_hit(rule.targets@, ws, start, slots),
                Scope::PipeInto => piped,
            }
    }
}

/// `rule` hits the command with words `ws` through the parse of `row`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn hit_row(rule: Rule, row: Row, ws: Seq<Word>, piped: bool) -> bool {
    pearlite! {
        match argv_spec(row.grammar, ws, row.key@.len()) {
            ArgvL::Parsed(slots, seen) =>
                hit_parsed(rule, row.grammar.opts@, ws, row.key@.len(), slots, seen, piped),
            ArgvL::Unknown(_, _) => false,
        }
    }
}

/// `rule` hits the command with words `ws` through its selected row.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn sel_hit(rows: Seq<Row>, rule: Rule, ws: Seq<Word>, piped: bool) -> bool {
    pearlite! { exists<j> selected_row(rows, j, ws) && hit_row(rule, rows[j], ws, piped) }
}

// ---------------------------------------------------------------------------
// Path checks
// ---------------------------------------------------------------------------

/// A `..` segment starts at byte `i` of `b`.
#[cfg(creusot)]
#[logic(open)]
pub fn dotdot_at(b: Seq<u8>, i: Int) -> bool {
    pearlite! {
        0 <= i && i + 1 < b.len() && b[i] == DOT && b[i + 1] == DOT
            && (i == 0 || b[i - 1] == SLASH)
            && (i + 2 == b.len() || b[i + 2] == SLASH)
    }
}

/// `b` has a `..` segment.
#[cfg(creusot)]
#[logic(open)]
pub fn has_dotdot_l(b: Seq<u8>) -> bool {
    pearlite! { exists<i> dotdot_at(b, i) }
}

/// The path word with parts `parts` fails a path check; `cwd`: an earlier
/// command changed the working directory.
#[cfg(creusot)]
#[logic(open)]
pub fn word_path_fails(parts: Seq<Part>, cwd: bool) -> bool {
    path_more(parts)
        || has_dotdot_l(path_lead(parts))
        || (cwd && !path_tilde(parts) && !starts_slash(path_lead(parts)))
}

/// The slot `s`, which is the word with parts `parts`, fails a path check:
/// a path operand or option value by `word_path_fails`, a path value given
/// inline in an option word by `inline_path_fails`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn slot_fails(parts: Seq<Part>, s: SlotL, cwd: bool) -> bool {
    pearlite! {
        match s {
            SlotL::Opts(Some((r, off))) => is_path_role(r) && inline_path_fails(parts, off, cwd),
            SlotL::Operand(r) => is_path_role(r) && word_path_fails(parts, cwd),
            SlotL::OptValue(r) => is_path_role(r) && word_path_fails(parts, cwd),
            SlotL::Opts(None) | SlotL::DashDash => false,
        }
    }
}

/// Some slot of the parse `slots` of `ws[start..]` fails a path check.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn path_fail_parsed(ws: Seq<Word>, start: Int, slots: Seq<SlotL>, cwd: bool) -> bool {
    pearlite! {
        exists<k> 0 <= k && k < slots.len() && slot_fails(ws[start + k].parts@, slots[k], cwd)
    }
}

/// The command with words `ws` fails a path check through the parse of
/// `row`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn path_fail_row(row: Row, ws: Seq<Word>, cwd: bool) -> bool {
    pearlite! {
        match argv_spec(row.grammar, ws, row.key@.len()) {
            ArgvL::Parsed(slots, _) => path_fail_parsed(ws, row.key@.len(), slots, cwd),
            ArgvL::Unknown(_, _) => false,
        }
    }
}

/// The command with words `ws` fails a path check through its selected row.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn sel_path_fail(rows: Seq<Row>, ws: Seq<Word>, cwd: bool) -> bool {
    pearlite! { exists<j> selected_row(rows, j, ws) && path_fail_row(rows[j], ws, cwd) }
}

/// The command with words `ws` is covered and its selected row changes the
/// working directory.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn sel_cwd(rows: Seq<Row>, ws: Seq<Word>) -> bool {
    pearlite! { exists<j> selected_row(rows, j, ws) && rows[j].changes_cwd }
}

/// With `rows[j]` selected, the `sel_*` predicates are those of `rows[j]`.
#[cfg(creusot)]
#[logic]
#[requires(selected_row(rows, j, ws))]
#[ensures(forall<rule: Rule, piped: bool>
    sel_hit(rows, rule, ws, piped) == hit_row(rule, rows[j], ws, piped))]
#[ensures(forall<cwd: bool> sel_path_fail(rows, ws, cwd) == path_fail_row(rows[j], ws, cwd))]
#[ensures(sel_cwd(rows, ws) == rows[j].changes_cwd)]
pub fn lemma_sel(rows: Seq<Row>, j: Int, ws: Seq<Word>) {
    lemma_selected_unique(rows, ws)
}

// ---------------------------------------------------------------------------
// Addresses and the decision
// ---------------------------------------------------------------------------

/// `b` names a command before position `(i, k, c)` (item, link, command).
#[cfg(creusot)]
#[logic(open)]
pub fn pos_before(b: Addr, i: Int, k: Int, c: Int) -> bool {
    pearlite! {
        b.item@ < i || (b.item@ == i && (b.link@ < k || (b.link@ == k && b.cmd@ < c)))
    }
}

/// Some covered command before position `(i, k, c)` has a selected row
/// that changes the working directory.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn cwd_upto(cat: Catalog, sc: Script, i: Int, k: Int, c: Int) -> bool {
    pearlite! {
        exists<b: Addr> valid_addr(sc, b) && pos_before(b, i, k, c)
            && sel_cwd(cat.rows@, simple_at_l(sc, b).words@)
    }
}

/// Some command before `a` changes the working directory.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn cwd_before(cat: Catalog, sc: Script, a: Addr) -> bool {
    pearlite! { cwd_upto(cat, sc, a.item@, a.link@, a.cmd@) }
}

/// The hit predicate: `rule` hits the command at `a`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn hits_at(cat: Catalog, rule: Rule, sc: Script, a: Addr) -> bool {
    pearlite! {
        valid_addr(sc, a) && sel_hit(cat.rows@, rule, simple_at_l(sc, a).words@, a.cmd@ > 0)
    }
}

/// The command at `a` fails a path check.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn path_fails_at(cat: Catalog, sc: Script, a: Addr) -> bool {
    pearlite! {
        valid_addr(sc, a)
            && sel_path_fail(cat.rows@, simple_at_l(sc, a).words@, cwd_before(cat, sc, a))
    }
}

/// Some rule with a Block outcome hits the command at `a`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn cmd_block(cat: Catalog, rules: Seq<Rule>, sc: Script, a: Addr) -> bool {
    pearlite! {
        exists<r> 0 <= r && r < rules.len() && rules[r].outcome == Outcome::Block
            && hits_at(cat, rules[r], sc, a)
    }
}

/// The command at `a` is uncovered, fails a path check, or is hit by a rule
/// with an Ask outcome.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn cmd_ask(cat: Catalog, rules: Seq<Rule>, sc: Script, a: Addr) -> bool {
    pearlite! {
        (valid_addr(sc, a) && !covered_simple(cat, simple_at_l(sc, a)))
            || path_fails_at(cat, sc, a)
            || exists<r> 0 <= r && r < rules.len() && rules[r].outcome == Outcome::Ask
                && hits_at(cat, rules[r], sc, a)
    }
}

/// `cmd_block` holds before position `(i, k, c)`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn block_upto(cat: Catalog, rules: Seq<Rule>, sc: Script, i: Int, k: Int, c: Int) -> bool {
    pearlite! {
        exists<b: Addr> valid_addr(sc, b) && pos_before(b, i, k, c) && cmd_block(cat, rules, sc, b)
    }
}

/// `cmd_ask` holds before position `(i, k, c)`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn ask_upto(cat: Catalog, rules: Seq<Rule>, sc: Script, i: Int, k: Int, c: Int) -> bool {
    pearlite! {
        exists<b: Addr> valid_addr(sc, b) && pos_before(b, i, k, c) && cmd_ask(cat, rules, sc, b)
    }
}

/// Some rule with a Block outcome hits somewhere in `sc`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn any_block(cat: Catalog, rules: Seq<Rule>, sc: Script) -> bool {
    pearlite! { exists<a: Addr> cmd_block(cat, rules, sc, a) }
}

/// Some command of `sc` is uncovered, fails a path check, or is hit by a
/// rule with an Ask outcome.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn any_ask(cat: Catalog, rules: Seq<Rule>, sc: Script) -> bool {
    pearlite! { exists<a: Addr> cmd_ask(cat, rules, sc, a) }
}

/// The decision for `sc`: the join of Allow, Ask when `sc` is not covered,
/// Ask when a path check fails, and the outcome of every hit of every rule.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn decision_of(cat: Catalog, rules: Seq<Rule>, sc: Script) -> Decision {
    if any_block(cat, rules, sc) {
        Decision::Block
    } else if any_ask(cat, rules, sc) {
        Decision::Ask
    } else {
        Decision::Allow
    }
}

/// No rule of `rules` hits anywhere in `sc`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn no_hits(cat: Catalog, rules: Seq<Rule>, sc: Script) -> bool {
    pearlite! {
        forall<r, a: Addr> 0 <= r && r < rules.len() ==> !hits_at(cat, rules[r], sc, a)
    }
}

/// No command of `sc` fails a path check.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn no_path_fail(cat: Catalog, sc: Script) -> bool {
    pearlite! { forall<a: Addr> !path_fails_at(cat, sc, a) }
}

/// Theorem T4: adding rules never lowers the decision.
#[cfg(creusot)]
#[logic]
#[requires(forall<i> 0 <= i && i < r.len() ==> exists<j> 0 <= j && j < r2.len() && r2[j] == r[i])]
#[ensures(le(decision_of(c, r, s), decision_of(c, r2, s)))]
pub fn lemma_decide_monotone(c: Catalog, r: Seq<Rule>, r2: Seq<Rule>, s: Script) {
    lemma_cmd_monotone(c, r, r2, s)
}

/// Adding rules keeps every per-command Block or Ask finding.
#[cfg(creusot)]
#[logic]
#[requires(forall<i> 0 <= i && i < r.len() ==> exists<j> 0 <= j && j < r2.len() && r2[j] == r[i])]
#[ensures(forall<a: Addr> cmd_block(c, r, s, a) ==> cmd_block(c, r2, s, a))]
#[ensures(forall<a: Addr> cmd_ask(c, r, s, a) ==> cmd_ask(c, r2, s, a))]
pub fn lemma_cmd_monotone(c: Catalog, r: Seq<Rule>, r2: Seq<Rule>, s: Script) {}

/// The plan's corollary: Allow means covered, no hit and no failed path
/// check (and no code position, by [`lemma_covered_no_code`]).
#[cfg(creusot)]
#[logic]
#[ensures(decision_of(c, r, s) == Decision::Allow ==> covered_script(c, s))]
#[ensures(decision_of(c, r, s) == Decision::Allow ==> no_hits(c, r, s))]
#[ensures(decision_of(c, r, s) == Decision::Allow ==> no_path_fail(c, s))]
pub fn lemma_allow_corollary(c: Catalog, r: Seq<Rule>, s: Script) {
    lemma_hit_finding(c, r, s)
}

/// Every hit is a per-command Block or Ask finding, by its outcome.
#[cfg(creusot)]
#[logic]
#[ensures(forall<x, a: Addr> 0 <= x && x < r.len() && hits_at(c, r[x], s, a)
    ==> cmd_block(c, r, s, a) || cmd_ask(c, r, s, a))]
pub fn lemma_hit_finding(c: Catalog, r: Seq<Rule>, s: Script) {}

/// A covering row's parse has no code position: `argv_spec` makes every
/// `Code` role Unknown.
#[cfg(creusot)]
#[logic]
#[requires(row_covers(rows, j, ws))]
#[ensures(match argv_spec(rows[j].grammar, ws, rows[j].key@.len()) {
    ArgvL::Parsed(slots, _) => no_code(slots),
    ArgvL::Unknown(_, _) => false,
})]
pub fn lemma_covered_no_code(rows: Seq<Row>, j: Int, ws: Seq<Word>) {
    pearlite! {
        lemma_go_no_code(rows[j].grammar, ws, rows[j].key@.len(), Phase::Options, 0,
            Seq::empty(), Seq::empty())
    }
}

/// Commands at the same position agree on every per-command predicate.
#[cfg(creusot)]
#[logic]
#[requires(valid_addr(sc, a))]
#[ensures(forall<b: Addr> valid_addr(sc, b) && b.item == a.item && b.link == a.link
    && b.cmd == a.cmd ==> simple_at_l(sc, b) == simple_at_l(sc, a)
        && cmd_block(cat, rules, sc, b) == cmd_block(cat, rules, sc, a)
        && cmd_ask(cat, rules, sc, b) == cmd_ask(cat, rules, sc, a))]
pub fn lemma_same_cmd(cat: Catalog, rules: Seq<Rule>, sc: Script, a: Addr) {}

/// Stepping over the command at `a` adds exactly its predicates.
#[cfg(creusot)]
#[logic]
#[requires(valid_addr(sc, a))]
#[ensures(block_upto(cat, rules, sc, a.item@, a.link@, a.cmd@ + 1)
    == (block_upto(cat, rules, sc, a.item@, a.link@, a.cmd@) || cmd_block(cat, rules, sc, a)))]
#[ensures(ask_upto(cat, rules, sc, a.item@, a.link@, a.cmd@ + 1)
    == (ask_upto(cat, rules, sc, a.item@, a.link@, a.cmd@) || cmd_ask(cat, rules, sc, a)))]
#[ensures(cwd_upto(cat, sc, a.item@, a.link@, a.cmd@ + 1)
    == (cwd_upto(cat, sc, a.item@, a.link@, a.cmd@)
        || sel_cwd(cat.rows@, simple_at_l(sc, a).words@)))]
pub fn lemma_upto_step(cat: Catalog, rules: Seq<Rule>, sc: Script, a: Addr) {
    lemma_same_cmd(cat, rules, sc, a)
}

/// The number of commands of the pipeline at item `i`, link `k`.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn pipe_len(sc: Script, i: Int, k: Int) -> Int {
    pearlite! {
        if k == 0 {
            sc.items@[i].first.cmds@.len()
        } else {
            sc.items@[i].rest@[k - 1].rhs.cmds@.len()
        }
    }
}

/// After the last command of a pipeline comes the next link.
#[cfg(creusot)]
#[logic]
#[requires(0 <= i && i < sc.items@.len() && 0 <= k && k <= sc.items@[i].rest@.len())]
#[ensures(block_upto(cat, rules, sc, i, k, pipe_len(sc, i, k))
    == block_upto(cat, rules, sc, i, k + 1, 0))]
#[ensures(ask_upto(cat, rules, sc, i, k, pipe_len(sc, i, k))
    == ask_upto(cat, rules, sc, i, k + 1, 0))]
#[ensures(cwd_upto(cat, sc, i, k, pipe_len(sc, i, k)) == cwd_upto(cat, sc, i, k + 1, 0))]
pub fn lemma_upto_link(cat: Catalog, rules: Seq<Rule>, sc: Script, i: Int, k: Int) {}

/// After the last link of an item comes the next item.
#[cfg(creusot)]
#[logic]
#[requires(0 <= i && i < sc.items@.len())]
#[ensures(block_upto(cat, rules, sc, i, sc.items@[i].rest@.len() + 1, 0)
    == block_upto(cat, rules, sc, i + 1, 0, 0))]
#[ensures(ask_upto(cat, rules, sc, i, sc.items@[i].rest@.len() + 1, 0)
    == ask_upto(cat, rules, sc, i + 1, 0, 0))]
#[ensures(cwd_upto(cat, sc, i, sc.items@[i].rest@.len() + 1, 0) == cwd_upto(cat, sc, i + 1, 0, 0))]
pub fn lemma_upto_item(cat: Catalog, rules: Seq<Rule>, sc: Script, i: Int) {}

/// Nothing precedes the first position; everything precedes the end.
#[cfg(creusot)]
#[logic]
#[ensures(!block_upto(cat, rules, sc, 0, 0, 0) && !ask_upto(cat, rules, sc, 0, 0, 0)
    && !cwd_upto(cat, sc, 0, 0, 0))]
#[ensures(block_upto(cat, rules, sc, sc.items@.len(), 0, 0) == any_block(cat, rules, sc))]
#[ensures(ask_upto(cat, rules, sc, sc.items@.len(), 0, 0) == any_ask(cat, rules, sc))]
pub fn lemma_upto_ends(cat: Catalog, rules: Seq<Rule>, sc: Script) {}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// Proof that a script may run without asking: only [`decide`] builds one,
/// from the [`Witness`] it obtains by classifying the script against the
/// catalog it was given (`_sealed` is private to this module and there is
/// no public constructor or conversion). The invariant ties the rules it was
/// checked against to the witness's catalog, and states the plan's
/// corollary: the script is covered, no rule hits and no path check fails.
#[cfg_attr(not(creusot), derive(Debug))]
pub struct Allowed {
    _sealed: (),
    /// The witness `decide` obtained; it owns the script.
    pub(crate) witness: Witness,
    /// The rules the script was checked against (ghost).
    #[cfg(creusot)]
    pub(crate) rules: Snapshot<Seq<Rule>>,
}

#[cfg(creusot)]
impl Invariant for Allowed {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! {
            covered_script(*self.witness.cat, self.witness.script)
                && no_hits(*self.witness.cat, *self.rules, self.witness.script)
                && no_path_fail(*self.witness.cat, self.witness.script)
        }
    }
}

impl Allowed {
    /// The allowed script.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.witness.script))]
    #[must_use]
    pub fn script(&self) -> &Script {
        self.witness.script()
    }

    /// The coverage witness.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.witness))]
    #[must_use]
    pub fn witness(&self) -> &Witness {
        &self.witness
    }
}

/// The kernel's answer for a script. Every arm owns the script (#1006).
#[cfg_attr(not(creusot), derive(Debug))]
pub enum Verdict {
    /// Run without asking.
    Allow(Allowed),
    /// Ask the user first: the script and the first Ask-level reason.
    Ask(Script, Reason),
    /// Refuse: the script and the first Block rule hit.
    Block(Script, Reason),
}

/// The decision a verdict stands for.
#[cfg(creusot)]
#[logic(open)]
pub fn verdict_decision(v: Verdict) -> Decision {
    match v {
        Verdict::Allow(_) => Decision::Allow,
        Verdict::Ask(_, _) => Decision::Ask,
        Verdict::Block(_, _) => Decision::Block,
    }
}

/// The script a verdict owns.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn verdict_script(v: Verdict) -> Script {
    match v {
        Verdict::Allow(a) => a.witness.script,
        Verdict::Ask(s, _) | Verdict::Block(s, _) => s,
    }
}

impl Verdict {
    /// The decision.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == verdict_decision(*self)))]
    #[must_use]
    pub fn decision(&self) -> Decision {
        match self {
            Verdict::Allow(_) => Decision::Allow,
            Verdict::Ask(_, _) => Decision::Ask,
            Verdict::Block(_, _) => Decision::Block,
        }
    }

    /// The script the verdict is about.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == verdict_script(*self)))]
    #[must_use]
    pub fn script(&self) -> &Script {
        match self {
            Verdict::Allow(a) => a.script(),
            Verdict::Ask(s, _) | Verdict::Block(s, _) => s,
        }
    }
}

// ---------------------------------------------------------------------------
// Program side
// ---------------------------------------------------------------------------

/// The index of the first part that is not an empty `Lit`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@ == lead_skip(parts@, 0)))]
#[cfg_attr(creusot, ensures(result@ <= parts@.len()))]
fn first_nonempty(parts: &[Part]) -> usize {
    let mut j: usize = 0;
    #[cfg_attr(creusot, variant(parts@.len() - j@))]
    #[cfg_attr(creusot, invariant(j@ <= parts@.len()))]
    #[cfg_attr(creusot, invariant(lead_skip(parts@, j@) == lead_skip(parts@, 0)))]
    while j < parts.len() {
        match &parts[j] {
            Part::Lit(b) => {
                if !<[u8]>::is_empty(b) {
                    return j;
                }
            }
            Part::Opaque(_) => return j,
        }
        j += 1;
    }
    j
}

/// The canonical view of `parts`: head is `~`, the lead, and whether an
/// opaque part follows the lead.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result.0 == path_tilde(parts@)))]
#[cfg_attr(creusot, ensures(result.1@ == path_lead(parts@)))]
#[cfg_attr(creusot, ensures(result.2 == path_more(parts@)))]
fn path_shape(parts: &[Part]) -> (bool, Vec<u8>, bool) {
    let h = first_nonempty(parts);
    let tilde = h < parts.len()
        && match &parts[h] {
            Part::Opaque(Opaque::Tilde) => true,
            Part::Opaque(Opaque::Var(_)) | Part::Lit(_) => false,
        };
    let from = if tilde { h + 1 } else { 0 };
    let (lead, more) = parts_view(parts, from);
    (tilde, lead, more)
}

/// The normalized lead (see `path_norm`).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@
    == if !more && starts_slash(lead@) { norm_l(lead@) } else { lead@ }))]
fn path_norm_of(lead: Vec<u8>, more: bool) -> Vec<u8> {
    if !more && !<[u8]>::is_empty(&lead) && lead[0] == SLASH {
        normalize_path(&lead)
    } else {
        lead
    }
}

/// The one-byte path `/`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@ == Seq::singleton(SLASH)))]
#[expect(
    clippy::vec_init_then_push,
    reason = "`vec!` would need creusot-std's own macro; `push` is already specified"
)]
fn slash() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.push(SLASH);
    #[cfg(creusot)]
    proof_assert!(v@.ext_eq(Seq::singleton(SLASH)));
    v
}

/// The program view of a word or pattern (see the logic functions named in
/// `path_view`'s contract).
struct PathView {
    tilde: bool,
    lead: Vec<u8>,
    norm: Vec<u8>,
    key: Vec<u8>,
    more: bool,
}

/// The view of `parts`: head, lead, normalized lead, key and whether an
/// opaque part follows the lead.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result.tilde == path_tilde(parts@)))]
#[cfg_attr(creusot, ensures(result.lead@ == path_lead(parts@)))]
#[cfg_attr(creusot, ensures(result.norm@ == path_norm(parts@)))]
#[cfg_attr(creusot, ensures(result.key@ == path_key(parts@)))]
#[cfg_attr(creusot, ensures(result.more == path_more(parts@)))]
fn path_view(parts: &[Part]) -> PathView {
    // Three owned copies of the lead from three calls, each carrying the
    // `path_shape` contract, instead of relying on a spec for `Vec::clone`.
    let (tilde, lead, more) = path_shape(parts);
    let (_, lead2, _) = path_shape(parts);
    let (_, lead3, _) = path_shape(parts);
    let norm = path_norm_of(lead2, more);
    // A bare `~` has the key `/`, like `~/`.
    let bare = tilde && !more && <[u8]>::is_empty(&lead);
    let key = if bare {
        slash()
    } else {
        path_norm_of(lead3, more)
    };
    PathView {
        tilde,
        lead,
        norm,
        key,
        more,
    }
}

/// `pat` matches a word with the view `w`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == pat_match_view(*pat, w.tilde, w.norm@, w.key@, w.more)))]
fn pat_match(pat: &Pat, w: &PathView) -> bool {
    let p = path_view(&pat.parts);
    if p.more {
        return true;
    }
    let prefix = match pat.kind {
        PatKind::Exact => false,
        PatKind::Prefix => true,
    };
    if p.tilde != w.tilde {
        return !p.tilde && <[u8]>::is_empty(&p.lead) && prefix;
    }
    if prefix {
        starts_with(&w.norm, &p.lead) || starts_with(&w.key, &p.key)
    } else {
        !w.more && (bytes_eq(&w.norm, &p.lead) || bytes_eq(&w.key, &p.key))
    }
}

/// Some pattern of `targets` matches `w`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == some_pat_matches(targets@, w.parts@)))]
fn any_pat_matches(targets: &[Pat], w: &Word) -> bool {
    let wv = path_view(&w.parts);
    let mut t: usize = 0;
    #[cfg_attr(creusot, variant(targets@.len() - t@))]
    #[cfg_attr(creusot, invariant(t@ <= targets@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < t@
        ==> !pat_matches(targets@[x], w.parts@)))]
    while t < targets.len() {
        if pat_match(&targets[t], &wv) {
            return true;
        }
        t += 1;
    }
    false
}

/// An owned copy of `b[off..]`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(off@ <= b@.len()))]
#[cfg_attr(creusot, ensures(result@ == b@.subsequence(off@, b@.len())))]
fn suffix_from(b: &[u8], off: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    #[cfg(creusot)]
    proof_assert! { b@.subsequence(off@, off@).ext_eq(Seq::empty()) };
    let mut j = off;
    #[cfg_attr(creusot, variant(b@.len() - j@))]
    #[cfg_attr(creusot, invariant(off@ <= j@ && j@ <= b@.len()))]
    #[cfg_attr(creusot, invariant(out@ == b@.subsequence(off@, j@)))]
    while j < b.len() {
        #[cfg(creusot)]
        proof_assert! { lemma_sub_snoc(b@, off@, j@); true };
        out.push(b[j]);
        j += 1;
    }
    out
}

/// The view of the inline value `b[off..]` of an option word: no `~`, nothing
/// opaque, and the key is the normalized lead like a literal path word's.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(off@ <= b@.len()))]
#[cfg_attr(creusot, ensures(!result.tilde && !result.more))]
#[cfg_attr(creusot, ensures(result.lead@ == b@.subsequence(off@, b@.len())))]
#[cfg_attr(creusot, ensures(result.norm@ == inline_norm(b@.subsequence(off@, b@.len()))))]
#[cfg_attr(creusot, ensures(result.key@ == inline_norm(b@.subsequence(off@, b@.len()))))]
fn inline_view(b: &[u8], off: usize) -> PathView {
    // Three owned copies, from three calls, as `path_view` does.
    let lead = suffix_from(b, off);
    let lead2 = suffix_from(b, off);
    let lead3 = suffix_from(b, off);
    let norm = path_norm_of(lead2, false);
    let key = path_norm_of(lead3, false);
    PathView {
        tilde: false,
        lead,
        norm,
        key,
        more: false,
    }
}

/// Some pattern of `targets` matches the inline value at `off` of the option
/// word `w`; true when the value cannot be read (see `inline_bad`).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == inline_path_hit(targets@, w.parts@, off@)))]
fn inline_hit(targets: &[Pat], w: &Word, off: usize) -> bool {
    let (b, opaque) = word_view(w);
    if opaque || off > b.len() {
        return true;
    }
    let wv = inline_view(&b, off);
    let mut t: usize = 0;
    #[cfg_attr(creusot, variant(targets@.len() - t@))]
    #[cfg_attr(creusot, invariant(t@ <= targets@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < t@
        ==> !pat_match_view(targets@[x], false, inline_norm(inline_value(w.parts@, off@)),
            inline_norm(inline_value(w.parts@, off@)), false)))]
    while t < targets.len() {
        if pat_match(&targets[t], &wv) {
            return true;
        }
        t += 1;
    }
    false
}

/// The targets hit the parse `slots` of `ws[start..]`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(start@ + slots@.len() == ws@.len()))]
#[cfg_attr(creusot, ensures(result == targets_hit(targets@, ws@, start@, slots_l(slots@))))]
fn targets_hit_p(targets: &[Pat], ws: &[Word], start: usize, slots: &[Slot]) -> bool {
    if <[Pat]>::is_empty(targets) {
        return true;
    }
    #[cfg(creusot)]
    proof_assert! { lemma_slots_index(slots@); true };
    let mut k: usize = 0;
    #[cfg_attr(creusot, variant(slots@.len() - k@))]
    #[cfg_attr(creusot, invariant(k@ <= slots@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < k@
        ==> !slot_hits(targets@, ws@[start@ + x].parts@, slots_l(slots@)[x])))]
    while k < slots.len() {
        match slots[k] {
            Slot::Opts(Some((Role::Path, off))) => {
                if inline_hit(targets, &ws[start + k], off) {
                    return true;
                }
            }
            Slot::Operand(Role::Path) | Slot::OptValue(Role::Path) => {
                if any_pat_matches(targets, &ws[start + k]) {
                    return true;
                }
            }
            Slot::Opts(None | Some((Role::Inert | Role::Code, _)))
            | Slot::Operand(Role::Inert | Role::Code)
            | Slot::OptValue(Role::Inert | Role::Code)
            | Slot::DashDash => {}
        }
        k += 1;
    }
    false
}

/// The rule's option name `n` overlaps the grammar option `o`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == name_overlaps(*n, *o)))]
fn overlaps(n: &OptName, o: &Opt) -> bool {
    match n {
        OptName::Short(c) => short_is(o, c.byte),
        OptName::Long(l) => long_is(o, &l.bytes),
        OptName::Both(c, l) => short_is(o, c.byte) || long_is(o, &l.bytes),
    }
}

/// Some option in `seen` (indices into `gopts`) overlaps `n`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == exists<u> 0 <= u && u < seen@.len()
    && seen@[u]@ < gopts@.len() && name_overlaps(*n, gopts@[seen@[u]@])))]
fn opt_seen(n: &OptName, gopts: &[Opt], seen: &[usize]) -> bool {
    let mut u: usize = 0;
    #[cfg_attr(creusot, variant(seen@.len() - u@))]
    #[cfg_attr(creusot, invariant(u@ <= seen@.len()))]
    #[cfg_attr(creusot, invariant(forall<v> 0 <= v && v < u@
        ==> !(seen@[v]@ < gopts@.len() && name_overlaps(*n, gopts@[seen@[v]@]))))]
    while u < seen.len() {
        let o = seen[u];
        if o < gopts.len() && overlaps(n, &gopts[o]) {
            return true;
        }
        u += 1;
    }
    false
}

/// Some name of the alias set overlaps an option in `seen`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == alts_seen_l(alts.names@, gopts@, ints(seen@))))]
fn alts_seen(alts: &OptAlts, gopts: &[Opt], seen: &[usize]) -> bool {
    let mut a: usize = 0;
    #[cfg_attr(creusot, variant(alts.names@.len() - a@))]
    #[cfg_attr(creusot, invariant(a@ <= alts.names@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < a@
        ==> !opt_seen_l(alts.names@[x], gopts@, ints(seen@))))]
    while a < alts.names.len() {
        #[cfg(creusot)]
        proof_assert! { lemma_ints_index(seen@); true };
        if opt_seen(&alts.names[a], gopts, seen) {
            return true;
        }
        a += 1;
    }
    false
}

/// Every entry of the rule has a name that overlaps an option in `seen`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == opts_hit(ropts@, gopts@, ints(seen@))))]
fn opts_present(ropts: &[OptAlts], gopts: &[Opt], seen: &[usize]) -> bool {
    let mut t: usize = 0;
    #[cfg_attr(creusot, variant(ropts@.len() - t@))]
    #[cfg_attr(creusot, invariant(t@ <= ropts@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < t@
        ==> alts_seen_l(ropts@[x].names@, gopts@, ints(seen@))))]
    while t < ropts.len() {
        if !alts_seen(&ropts[t], gopts, seen) {
            return false;
        }
        t += 1;
    }
    true
}

/// `rule` hits the command with words `ws` read as the parse `p` of
/// `ws[start..]` by a grammar with options `gopts`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(start@ + p.slots@.len() == ws@.len()))]
#[cfg_attr(creusot, ensures(result
    == hit_parsed(*rule, gopts@, ws@, start@, slots_l(p.slots@), ints(p.seen@), piped)))]
fn rule_hits(
    rule: &Rule,
    gopts: &[Opt],
    ws: &[Word],
    start: usize,
    p: &Parse,
    piped: bool,
) -> bool {
    if !key_match(&rule.key, ws) {
        return false;
    }
    if !opts_present(&rule.opts, gopts, &p.seen) {
        return false;
    }
    match rule.scope {
        Scope::Simple => targets_hit_p(&rule.targets, ws, start, &p.slots),
        Scope::PipeInto => piped,
    }
}

/// `b` has a `..` segment.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == has_dotdot_l(b@)))]
fn has_dotdot(b: &[u8]) -> bool {
    let n = b.len();
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(n@ - i@))]
    #[cfg_attr(creusot, invariant(i@ <= n@))]
    #[cfg_attr(creusot, invariant(forall<t> 0 <= t && t < i@ ==> !dotdot_at(b@, t)))]
    while i < n {
        if i + 1 < n
            && b[i] == DOT
            && b[i + 1] == DOT
            && (i == 0 || b[i - 1] == SLASH)
            && (i + 2 == n || b[i + 2] == SLASH)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// The path check of one path word, or `None` when it passes.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures((result != None) == word_path_fails(w.parts@, cwd)))]
fn word_path_check(w: &Word, cwd: bool) -> Option<UnknownKind> {
    let (tilde, lead, more) = path_shape(&w.parts);
    if more {
        return Some(UnknownKind::PathOpaque);
    }
    if has_dotdot(&lead) {
        return Some(UnknownKind::PathDotDot);
    }
    if cwd && !tilde && (<[u8]>::is_empty(&lead) || lead[0] != SLASH) {
        return Some(UnknownKind::PathAfterCd);
    }
    None
}

/// The path check of the inline value at `off` of the option word `w`, or
/// `None` when it passes. A value that cannot be read (see `inline_bad`) is
/// `PathOpaque`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures((result != None) == inline_path_fails(w.parts@, off@, cwd)))]
fn inline_path_check(w: &Word, off: usize, cwd: bool) -> Option<UnknownKind> {
    let (b, opaque) = word_view(w);
    if opaque || off > b.len() {
        return Some(UnknownKind::PathOpaque);
    }
    let v = &b[off..b.len()];
    if has_dotdot(v) {
        return Some(UnknownKind::PathDotDot);
    }
    if cwd && (<[u8]>::is_empty(v) || v[0] != SLASH) {
        return Some(UnknownKind::PathAfterCd);
    }
    None
}

/// The first failed path check of the parse `slots` of `ws[start..]`: its
/// kind and word.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(start@ + slots@.len() == ws@.len()))]
#[cfg_attr(creusot, ensures(match result {
    None => !path_fail_parsed(ws@, start@, slots_l(slots@), cwd),
    Some((_, w)) => path_fail_parsed(ws@, start@, slots_l(slots@), cwd) && w@ < ws@.len(),
}))]
fn path_check(
    ws: &[Word],
    start: usize,
    slots: &[Slot],
    cwd: bool,
) -> Option<(UnknownKind, usize)> {
    #[cfg(creusot)]
    proof_assert! { lemma_slots_index(slots@); true };
    let mut k: usize = 0;
    #[cfg_attr(creusot, variant(slots@.len() - k@))]
    #[cfg_attr(creusot, invariant(k@ <= slots@.len()))]
    #[cfg_attr(creusot, invariant(forall<x> 0 <= x && x < k@
        ==> !slot_fails(ws@[start@ + x].parts@, slots_l(slots@)[x], cwd)))]
    while k < slots.len() {
        match slots[k] {
            Slot::Opts(Some((Role::Path, off))) => {
                if let Some(u) = inline_path_check(&ws[start + k], off, cwd) {
                    return Some((u, start + k));
                }
            }
            Slot::Operand(Role::Path) | Slot::OptValue(Role::Path) => {
                if let Some(u) = word_path_check(&ws[start + k], cwd) {
                    return Some((u, start + k));
                }
            }
            Slot::Opts(None | Some((Role::Inert | Role::Code, _)))
            | Slot::Operand(Role::Inert | Role::Code)
            | Slot::OptValue(Role::Inert | Role::Code)
            | Slot::DashDash => {}
        }
        k += 1;
    }
    None
}

/// `at` with word index `w`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result.item == at.item && result.link == at.link
    && result.cmd == at.cmd && result.word == Some(w)))]
fn word_at(at: Addr, w: usize) -> Addr {
    Addr {
        item: at.item,
        link: at.link,
        cmd: at.cmd,
        word: Some(w),
    }
}

/// What the scan has found: the first Block reason, the first Ask-level
/// reason, and whether a working-directory change was seen.
struct Scan {
    block: Option<Reason>,
    ask: Option<Reason>,
    cwd: bool,
}

/// `st` is the scan state just before position `(i, k, c)`.
#[cfg(creusot)]
#[logic]
fn scan_at(st: Scan, cat: Catalog, rules: Seq<Rule>, sc: Script, i: Int, k: Int, c: Int) -> bool {
    (st.block != None) == block_upto(cat, rules, sc, i, k, c)
        && (st.ask != None) == ask_upto(cat, rules, sc, i, k, c)
        && st.cwd == cwd_upto(cat, sc, i, k, c)
}

/// Scans one simple command at `at`. `piped`: it is not the first of its
/// pipeline; `cwd`: an earlier command changed the working directory.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures((result.block != None) == exists<r> 0 <= r && r < rules@.len()
    && rules@[r].outcome == Outcome::Block && sel_hit(cat.rows@, rules@[r], s.words@, piped)))]
#[cfg_attr(creusot, ensures((result.ask != None) == (!covered_simple(*cat, *s)
    || sel_path_fail(cat.rows@, s.words@, cwd)
    || exists<r> 0 <= r && r < rules@.len() && rules@[r].outcome == Outcome::Ask
        && sel_hit(cat.rows@, rules@[r], s.words@, piped))))]
#[cfg_attr(creusot, ensures(result.cwd == sel_cwd(cat.rows@, s.words@)))]
fn scan_simple(
    cat: &Catalog,
    rules: &[Rule],
    s: &Simple,
    at: Addr,
    piped: bool,
    cwd: bool,
) -> Scan {
    let ws = &s.words;
    match classify_simple(cat, s) {
        SimpleClass::Unknown(u, w) => Scan {
            block: None,
            ask: Some(Reason::Unknown(u, word_at(at, w))),
            cwd: false,
        },
        SimpleClass::Covered { row } => {
            let r = &cat.rows[row];
            let start = r.key.len();
            #[cfg(creusot)]
            proof_assert! { lemma_sel(cat.rows@, row@, ws@); true };
            match parse_argv(&r.grammar, ws, start) {
                // Unreachable: a covering row's parse succeeds.
                ArgvResult::Unknown(_, _) => Scan {
                    block: None,
                    ask: Some(Reason::Unknown(UnknownKind::NoRow, at)),
                    cwd: false,
                },
                ArgvResult::Parsed(p) => {
                    let mut ask: Option<Reason> = None;
                    if let Some((u, w)) = path_check(ws, start, &p.slots, cwd) {
                        ask = Some(Reason::Unknown(u, word_at(at, w)));
                    }
                    let mut block: Option<Reason> = None;
                    let mut j: usize = 0;
                    #[cfg_attr(creusot, variant(rules@.len() - j@))]
                    #[cfg_attr(creusot, invariant(j@ <= rules@.len()))]
                    #[cfg_attr(creusot, invariant((block != None) == exists<x> 0 <= x && x < j@
                        && rules@[x].outcome == Outcome::Block
                        && hit_row(rules@[x], cat.rows@[row@], ws@, piped)))]
                    #[cfg_attr(creusot, invariant((ask != None)
                        == (path_fail_row(cat.rows@[row@], ws@, cwd)
                            || exists<x> 0 <= x && x < j@ && rules@[x].outcome == Outcome::Ask
                                && hit_row(rules@[x], cat.rows@[row@], ws@, piped))))]
                    while j < rules.len() {
                        let rule = &rules[j];
                        if rule_hits(rule, &r.grammar.opts, ws, start, &p, piped) {
                            let hit = Reason::Rule(rule.id, at);
                            match rule.outcome {
                                Outcome::Block => block = block.or(Some(hit)),
                                Outcome::Ask => ask = ask.or(Some(hit)),
                            }
                        }
                        j += 1;
                    }
                    Scan {
                        block,
                        ask,
                        cwd: r.changes_cwd,
                    }
                }
            }
        }
    }
}

/// Scans the pipeline at item `i`, link `link`, carrying the state `st`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(i@ < sc.items@.len() && link@ <= sc.items@[i@].rest@.len()))]
#[cfg_attr(creusot, requires(scan_at(st, *cat, rules@, *sc, i@, link@, 0)))]
#[cfg_attr(creusot, ensures(scan_at(result, *cat, rules@, *sc, i@, link@ + 1, 0)))]
fn scan_pipeline(
    cat: &Catalog,
    rules: &[Rule],
    sc: &Script,
    i: usize,
    link: usize,
    mut st: Scan,
) -> Scan {
    let ao = &sc.items[i];
    let cmds = if link == 0 {
        &ao.first.cmds
    } else {
        &ao.rest[link - 1].rhs.cmds
    };
    #[cfg(creusot)]
    proof_assert! { cmds@.len() == pipe_len(*sc, i@, link@) };
    let mut c: usize = 0;
    #[cfg_attr(creusot, variant(cmds@.len() - c@))]
    #[cfg_attr(creusot, invariant(c@ <= cmds@.len()))]
    #[cfg_attr(creusot, invariant(scan_at(st, *cat, rules@, *sc, i@, link@, c@)))]
    while c < cmds.len() {
        let at = Addr {
            item: i,
            link,
            cmd: c,
            word: None,
        };
        #[cfg(creusot)]
        proof_assert! { valid_addr(*sc, at) && simple_at_l(*sc, at) == cmds@[c@] };
        #[cfg(creusot)]
        proof_assert! { lemma_upto_step(*cat, rules@, *sc, at); true };
        let r = scan_simple(cat, rules, &cmds[c], at, c > 0, st.cwd);
        st = Scan {
            block: st.block.or(r.block),
            ask: st.ask.or(r.ask),
            cwd: st.cwd || r.cwd,
        };
        c += 1;
    }
    #[cfg(creusot)]
    proof_assert! { lemma_upto_link(*cat, rules@, *sc, i@, link@); true };
    st
}

/// Decides a script against a catalog and rules (theorem T3): the verdict's
/// decision is `decision_of`, and every arm returns the script unchanged.
///
/// Block carries the first Block rule hit in address order. Ask carries the
/// first Ask-level reason in address order (an uncovered command's reason,
/// then a failed path check, then an Ask rule hit). Allow carries an
/// [`Allowed`] built from the witness of `classify_script(cat, ..)`.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(verdict_decision(result) == decision_of(*cat, rules@, sc)))]
#[cfg_attr(creusot, ensures(verdict_script(result) == sc))]
#[cfg_attr(creusot, ensures(match result {
    Verdict::Allow(a) => *a.witness.cat == *cat && *a.rules == rules@,
    Verdict::Ask(_, _) => true,
    Verdict::Block(_, _) => true,
}))]
#[must_use]
pub fn decide(cat: &Catalog, rules: &[Rule], sc: Script) -> Verdict {
    let mut st = Scan {
        block: None,
        ask: None,
        cwd: false,
    };
    #[cfg(creusot)]
    proof_assert! { lemma_upto_ends(*cat, rules@, sc); true };
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(sc.items@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= sc.items@.len()))]
    #[cfg_attr(creusot, invariant(scan_at(st, *cat, rules@, sc, i@, 0, 0)))]
    while i < sc.items.len() {
        st = scan_pipeline(cat, rules, &sc, i, 0, st);
        let mut k: usize = 0;
        #[cfg_attr(creusot, variant(sc.items@[i@].rest@.len() - k@))]
        #[cfg_attr(creusot, invariant(k@ <= sc.items@[i@].rest@.len()))]
        #[cfg_attr(creusot, invariant(scan_at(st, *cat, rules@, sc, i@, k@ + 1, 0)))]
        while k < sc.items[i].rest.len() {
            st = scan_pipeline(cat, rules, &sc, i, k + 1, st);
            k += 1;
        }
        #[cfg(creusot)]
        proof_assert! { lemma_upto_item(*cat, rules@, sc, i@); true };
        i += 1;
    }
    #[cfg(creusot)]
    proof_assert! { lemma_upto_ends(*cat, rules@, sc); true };
    if let Some(r) = st.block {
        return Verdict::Block(sc, r);
    }
    if let Some(r) = st.ask {
        return Verdict::Ask(sc, r);
    }
    match classify_script(cat, sc) {
        Classified::Covered(w) => Verdict::Allow(Allowed {
            _sealed: (),
            witness: w,
            #[cfg(creusot)]
            rules: snapshot!(rules@),
        }),
        // Unreachable: no Ask-level reason means every command is covered.
        Classified::Uncovered(sc, r) => Verdict::Ask(sc, r),
    }
}

#[cfg(test)]
mod tests {
    use super::{OptAlts, Verdict, decide, inline_hit, inline_path_check};
    use crate::ast::{AndOr, Connector, Link, Opaque, Part, Pipeline, Script, Simple, Word};
    use crate::catalog::{
        Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role,
        Row, RunsCode, ShortName,
    };
    use crate::decision::Decision;
    use crate::rule::{Outcome, Pat, PatKind, Rule, RuleId, Scope};
    use crate::verdict::UnknownKind;

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn key(segs: &[&str]) -> Vec<Vec<u8>> {
        segs.iter().map(|s| bytes(s)).collect()
    }

    fn flag(name: OptName) -> Opt {
        Opt::new(name, OptValue::Flag)
    }

    fn short(b: u8) -> ShortName {
        ShortName::new(b).expect("printable, not '-'")
    }

    fn long(s: &str) -> LongName {
        LongName::new(bytes(s)).expect("well-formed long name")
    }

    fn row(segs: &[&str], g: Grammar, cwd: Cwd) -> Row {
        Row::new(key(segs), g, RunsCode::No, cwd).expect("valid key")
    }

    /// GNU style: options anywhere, `--` ends them, any number of operands.
    fn gnu(opts: Vec<Opt>, rest: Role) -> Grammar {
        Grammar::new(
            opts,
            Vec::new(),
            Some(rest),
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    fn catalog() -> Catalog {
        Catalog::new(
            vec![
                row(
                    &["ls"],
                    gnu(
                        vec![
                            flag(OptName::Short(short(b'l'))),
                            flag(OptName::Short(short(b'a'))),
                        ],
                        Role::Path,
                    ),
                    Cwd::Keeps,
                ),
                row(
                    &["rm"],
                    gnu(
                        vec![
                            flag(OptName::Both(short(b'r'), long("recursive"))),
                            flag(OptName::Short(short(b'f'))),
                        ],
                        Role::Path,
                    ),
                    Cwd::Keeps,
                ),
                row(
                    &["cd"],
                    Grammar::new(
                        Vec::new(),
                        vec![Role::Path],
                        None,
                        Order::Strict,
                        DashDash::Ends,
                        PlusWords::Reject,
                    ),
                    Cwd::Changes,
                ),
                row(&["echo"], gnu(Vec::new(), Role::Inert), Cwd::Keeps),
                row(&["cat"], gnu(Vec::new(), Role::Path), Cwd::Keeps),
                row(
                    &["sh"],
                    Grammar::new(
                        Vec::new(),
                        Vec::new(),
                        None,
                        Order::Strict,
                        DashDash::Ends,
                        PlusWords::Reject,
                    ),
                    Cwd::Keeps,
                ),
            ],
            Vec::new(),
        )
    }

    fn lit(s: &str) -> Part {
        Part::Lit(bytes(s))
    }

    fn any_of(names: Vec<OptName>) -> OptAlts {
        OptAlts::new(names).expect("non-empty")
    }

    fn one(name: OptName) -> OptAlts {
        any_of(vec![name])
    }

    fn rule(id: u32, scope: Scope, k: &str, targets: Vec<Pat>) -> Rule {
        let opts = match scope {
            Scope::Simple => vec![one(OptName::Short(short(b'r')))],
            Scope::PipeInto => Vec::new(),
        };
        Rule::new(RuleId(id), scope, key(&[k]), opts, targets, Outcome::Block).expect("valid")
    }

    fn rules() -> Vec<Rule> {
        let root = Pat::new(vec![lit("/")], PatKind::Exact).expect("non-empty");
        let home = Pat::new(vec![Part::Opaque(Opaque::Tilde), lit("/")], PatKind::Prefix)
            .expect("non-empty");
        vec![
            rule(1, Scope::Simple, "rm", vec![root]),
            rule(2, Scope::Simple, "rm", vec![home]),
            rule(3, Scope::PipeInto, "sh", Vec::new()),
        ]
    }

    fn word(parts: Vec<Part>) -> Word {
        Word::new(parts).expect("non-empty")
    }

    fn simple(words: Vec<Word>) -> Simple {
        Simple::new(words, Vec::new()).expect("non-empty")
    }

    fn cmd(words: &[&str]) -> Simple {
        simple(words.iter().map(|w| word(vec![lit(w)])).collect())
    }

    fn pipe(cmds: Vec<Simple>) -> Pipeline {
        Pipeline::new(cmds).expect("non-empty")
    }

    /// Each command is its own and-or list: `a; b; ...`.
    fn seq(cmds: Vec<Simple>) -> Script {
        Script::new(
            cmds.into_iter()
                .map(|c| AndOr::new(pipe(vec![c]), Vec::new()))
                .collect(),
        )
    }

    fn check_with(rules: &[Rule], sc: Script, want: Decision) {
        let v: Verdict = decide(&catalog(), rules, sc.clone());
        assert_eq!(v.decision(), want, "{sc:?}");
        assert_eq!(*v.script(), sc, "the verdict owns the input script");
    }

    fn check(sc: Script, want: Decision) {
        check_with(&rules(), sc, want);
    }

    #[test]
    fn covered_without_hits_is_allow() {
        check(seq(vec![cmd(&["ls", "-la"])]), Decision::Allow);
    }

    #[test]
    fn uncovered_is_ask() {
        check(
            seq(vec![cmd(&["unknowntool", "rm", "-rf", "/"])]),
            Decision::Ask,
        );
    }

    #[test]
    fn rm_root_is_block() {
        check(seq(vec![cmd(&["rm", "-rf", "/"])]), Decision::Block);
    }

    #[test]
    fn targets_are_normalized() {
        check(seq(vec![cmd(&["rm", "-rf", "//"])]), Decision::Block);
        check(seq(vec![cmd(&["rm", "-rf", "/./"])]), Decision::Block);
    }

    #[test]
    fn option_names_overlap() {
        check(
            seq(vec![cmd(&["rm", "-rf", "--recursive", "/"])]),
            Decision::Block,
        );
        check(seq(vec![cmd(&["rm", "--recursive", "/"])]), Decision::Block);
        check(seq(vec![cmd(&["rm", "-f", "/"])]), Decision::Allow);
    }

    #[test]
    fn canonical_view_merges_lits() {
        // `rm -rf '/'""`
        let target = word(vec![lit("/"), lit("")]);
        let rm = simple(vec![word(vec![lit("rm")]), word(vec![lit("-rf")]), target]);
        check(seq(vec![rm]), Decision::Block);
    }

    #[test]
    fn tilde_prefix_target() {
        let rm = |dashdash: bool| {
            let mut words = vec![word(vec![lit("rm")]), word(vec![lit("-r")])];
            if dashdash {
                words.push(word(vec![lit("--")]));
            }
            words.push(word(vec![Part::Opaque(Opaque::Tilde), lit("/x")]));
            seq(vec![simple(words)])
        };
        // `rm -r -- ~/x`
        check(rm(true), Decision::Block);
        // `rm -r ~/x`: argv reads a word starting with `~` in option position
        // as opaque, so the command is uncovered: Ask, not Block.
        check(rm(false), Decision::Ask);
    }

    #[test]
    fn dotdot_is_ask() {
        check(seq(vec![cmd(&["rm", "-rf", ".."])]), Decision::Ask);
    }

    #[test]
    fn opaque_path_is_ask() {
        // `rm "$X"` and `rm -- "$X"`
        let var = || word(vec![Part::Opaque(Opaque::Var(bytes("X")))]);
        check(
            seq(vec![simple(vec![word(vec![lit("rm")]), var()])]),
            Decision::Ask,
        );
        check(
            seq(vec![simple(vec![
                word(vec![lit("rm")]),
                word(vec![lit("--")]),
                var(),
            ])]),
            Decision::Ask,
        );
    }

    #[test]
    fn relative_path_after_cd_is_ask() {
        // `cd / && rm -rf usr`
        let sc = Script::new(vec![AndOr::new(
            pipe(vec![cmd(&["cd", "/"])]),
            vec![Link::new(
                Connector::And,
                pipe(vec![cmd(&["rm", "-rf", "usr"])]),
            )],
        )]);
        check(sc, Decision::Ask);
        // Without the cd, the same rm is Allow.
        check(seq(vec![cmd(&["rm", "-rf", "usr"])]), Decision::Allow);
    }

    #[test]
    fn pipe_into_rule() {
        // `curl x | sh`
        let sc = Script::new(vec![AndOr::new(
            pipe(vec![cmd(&["curl", "x"]), cmd(&["sh"])]),
            Vec::new(),
        )]);
        check(sc, Decision::Block);
        // `sh` first in its pipeline does not read a pipe.
        check(seq(vec![cmd(&["sh"])]), Decision::Allow);
    }

    #[test]
    fn pipeline_without_rules_is_allow() {
        // `echo a | cat`
        let sc = Script::new(vec![AndOr::new(
            pipe(vec![cmd(&["echo", "a"]), cmd(&["cat"])]),
            Vec::new(),
        )]);
        check_with(&[], sc, Decision::Allow);
    }

    #[test]
    fn block_anywhere_in_the_script() {
        check(
            seq(vec![cmd(&["ls"]), cmd(&["rm", "-rf", "/"])]),
            Decision::Block,
        );
        check(
            seq(vec![cmd(&["unknowntool"]), cmd(&["rm", "-rf", "/"])]),
            Decision::Block,
        );
    }

    #[test]
    fn empty_script_is_allow() {
        check(Script::new(Vec::new()), Decision::Allow);
    }

    #[test]
    fn allow_owns_the_script() {
        let sc = seq(vec![cmd(&["ls", "-la"])]);
        let Verdict::Allow(a) = decide(&catalog(), &rules(), sc.clone()) else {
            panic!("allow");
        };
        assert_eq!(*a.script(), sc);
        assert_eq!(*a.witness().script(), sc);
    }

    fn check_in(cat: &Catalog, rules: &[Rule], sc: Script, want: Decision) {
        let v = decide(cat, rules, sc.clone());
        assert_eq!(v.decision(), want, "{sc:?}");
        assert_eq!(*v.script(), sc, "the verdict owns the input script");
    }

    fn tilde_word(rest: &str) -> Word {
        if rest.is_empty() {
            word(vec![Part::Opaque(Opaque::Tilde)])
        } else {
            word(vec![Part::Opaque(Opaque::Tilde), lit(rest)])
        }
    }

    /// `rm -r -- <target>`
    fn rm_r_dashdash(target: Word) -> Script {
        seq(vec![simple(vec![
            word(vec![lit("rm")]),
            word(vec![lit("-r")]),
            word(vec![lit("--")]),
            target,
        ])])
    }

    fn block_rule(k: &str, opts: Vec<OptAlts>, targets: Vec<Pat>) -> Rule {
        Rule::new(
            RuleId(9),
            Scope::Simple,
            key(&[k]),
            opts,
            targets,
            Outcome::Block,
        )
        .expect("valid")
    }

    #[test]
    fn bare_tilde_hits_a_tilde_prefix_target() {
        // `rm -r -- ~` under `[Tilde, Lit("/")]` Prefix.
        check(rm_r_dashdash(tilde_word("")), Decision::Block);
        check(rm_r_dashdash(tilde_word("/.")), Decision::Block);
        check(rm_r_dashdash(tilde_word("//")), Decision::Block);
    }

    #[test]
    fn bare_tilde_pattern_is_home() {
        // `[Tilde]` Exact vs `rm -r -- ~/` and `rm -r -- ~`.
        let home = Pat::new(vec![Part::Opaque(Opaque::Tilde)], PatKind::Exact).expect("non-empty");
        let r = [block_rule(
            "rm",
            vec![one(OptName::Short(short(b'r')))],
            vec![home],
        )];
        check_with(&r, rm_r_dashdash(tilde_word("/")), Decision::Block);
        check_with(&r, rm_r_dashdash(tilde_word("")), Decision::Block);
        check_with(&r, rm_r_dashdash(tilde_word("/x")), Decision::Allow);
    }

    #[test]
    fn patterns_are_normalized() {
        // `/etc/` Exact vs `rm -r /etc/` and `rm -r /etc`.
        let etc = Pat::new(vec![lit("/etc/")], PatKind::Exact).expect("non-empty");
        let r = [block_rule(
            "rm",
            vec![one(OptName::Short(short(b'r')))],
            vec![etc],
        )];
        check_with(&r, seq(vec![cmd(&["rm", "-r", "/etc/"])]), Decision::Block);
        check_with(&r, seq(vec![cmd(&["rm", "-r", "/etc"])]), Decision::Block);
        check_with(&r, seq(vec![cmd(&["rm", "-r", "/etc/x"])]), Decision::Allow);
    }

    #[test]
    fn ask_rule_is_ask() {
        let ask = Rule::new(
            RuleId(10),
            Scope::Simple,
            key(&["rm"]),
            vec![one(OptName::Short(short(b'r')))],
            Vec::new(),
            Outcome::Ask,
        )
        .expect("valid");
        check_with(&[ask], seq(vec![cmd(&["rm", "-r", "x"])]), Decision::Ask);
        check_with(&[], seq(vec![cmd(&["rm", "-r", "x"])]), Decision::Allow);
    }

    /// The test catalog plus `cp [-t DIR] [--opt[=DIR]] path...`.
    fn catalog_with_cp() -> Catalog {
        let mut cat = catalog();
        let t = Opt::new(
            OptName::Both(short(b't'), long("target-directory")),
            OptValue::Takes(Role::Path),
        );
        let o = Opt::new(OptName::Long(long("opt")), OptValue::Optional(Role::Path));
        let r = flag(OptName::Short(short(b'r')));
        cat.rows
            .push(row(&["cp"], gnu(vec![t, o, r], Role::Path), Cwd::Keeps));
        cat
    }

    #[test]
    fn inline_value_tilde_is_literal() {
        let cat = catalog_with_cp();
        // In `-t~/x` the `~` is a literal byte of the option word.
        check_in(
            &cat,
            &[],
            seq(vec![cmd(&["cp", "-t~/x", "a"])]),
            Decision::Allow,
        );
        // It is a relative path, so it fails after a `cd`.
        check_in(
            &cat,
            &[],
            seq(vec![cmd(&["cd", "/"]), cmd(&["cp", "-t~/x", "/a"])]),
            Decision::Ask,
        );
        // A `[Tilde]` Prefix target does not hit it, but hits a `~` word.
        let home = Pat::new(vec![Part::Opaque(Opaque::Tilde)], PatKind::Prefix).expect("non-empty");
        let r = [block_rule("cp", Vec::new(), vec![home])];
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["cp", "-t~/x", "a"])]),
            Decision::Allow,
        );
        let tilde_operand = simple(vec![
            word(vec![lit("cp")]),
            // After `--`: a `~` word in option position would be opaque.
            word(vec![lit("--")]),
            tilde_word("/x"),
            word(vec![lit("a")]),
        ]);
        check_in(&cat, &r, seq(vec![tilde_operand]), Decision::Block);
    }

    #[test]
    fn unreadable_inline_values_fail_closed() {
        let pat = Pat::new(vec![lit("/etc")], PatKind::Exact).expect("non-empty");
        let targets = [pat];
        // `-t$X` with the offset inside the literal prefix: the word is opaque.
        let opaque = word(vec![lit("-t"), Part::Opaque(Opaque::Var(bytes("X")))]);
        // `-t/x` with an offset far outside the word.
        let literal = word(vec![lit("-t/x")]);
        for (w, off) in [(&opaque, 2), (&literal, 99)] {
            assert!(inline_hit(&targets, w, off));
            assert_eq!(
                inline_path_check(w, off, false),
                Some(UnknownKind::PathOpaque)
            );
            assert_eq!(
                inline_path_check(w, off, true),
                Some(UnknownKind::PathOpaque)
            );
        }
        // A readable value is not a hit here.
        assert!(!inline_hit(&targets, &literal, 2));
        assert_eq!(inline_path_check(&literal, 2, false), None);
    }

    #[test]
    fn inline_value_after_clustered_flag() {
        let cat = catalog_with_cp();
        let etc = Pat::new(vec![lit("/etc")], PatKind::Prefix).expect("non-empty");
        let r = [block_rule("cp", Vec::new(), vec![etc])];
        let cp = |w: &str, want| check_in(&cat, &r, seq(vec![cmd(&["cp", w, "a"])]), want);
        // The offset follows the `-r` flag: the value is `/etc/x`, not `rt/etc/x`.
        cp("-rt/etc/x", Decision::Block);
        cp("-rt/tmp/x", Decision::Allow);
    }

    #[test]
    fn inline_path_value_is_checked_like_a_path_word() {
        let cat = catalog_with_cp();
        let ok = |w: &str, want| check_in(&cat, &[], seq(vec![cmd(&["cp", w, "a"])]), want);
        // A clean absolute or relative inline value passes, as `-t /x` does.
        ok("--target-directory=/x", Decision::Allow);
        ok("-t/x", Decision::Allow);
        ok("--target-directory=x", Decision::Allow);
        // A `..` segment in the inline value is Ask.
        ok("--target-directory=../x", Decision::Ask);
        ok("-t../x", Decision::Ask);
        ok("--opt=a/../x", Decision::Ask);
        // `cp -t /x a` still passes.
        check_in(
            &cat,
            &[],
            seq(vec![cmd(&["cp", "-t", "/x", "a"])]),
            Decision::Allow,
        );
    }

    #[test]
    fn relative_inline_value_after_cd_is_ask() {
        let cat = catalog_with_cp();
        // `cd /; cp <w> /a`: the operand is absolute, so only `w` decides.
        let after_cd = |w: &str, want| {
            check_in(
                &cat,
                &[],
                seq(vec![cmd(&["cd", "/"]), cmd(&["cp", w, "/a"])]),
                want,
            );
        };
        after_cd("--target-directory=x", Decision::Ask);
        after_cd("-tx", Decision::Ask);
        after_cd("--target-directory=", Decision::Ask);
        after_cd("--target-directory=/x", Decision::Allow);
        after_cd("-t/x", Decision::Allow);
    }

    #[test]
    fn optional_inline_path_is_checked_like_takes() {
        let cat = catalog_with_cp();
        let cp = |w: &str, want| check_in(&cat, &[], seq(vec![cmd(&["cp", w, "a"])]), want);
        cp("--opt=x", Decision::Allow);
        cp("--opt=../x", Decision::Ask);
        // An empty inline value is an empty relative path: no `..`, no cd.
        cp("--opt=", Decision::Allow);
        cp("--target-directory=", Decision::Allow);
        // Without an inline value, there is no path slot at all.
        cp("--opt", Decision::Allow);
    }

    #[test]
    fn inline_path_value_is_a_target() {
        let cat = catalog_with_cp();
        let etc = Pat::new(vec![lit("/etc")], PatKind::Prefix).expect("non-empty");
        let r = [block_rule("cp", Vec::new(), vec![etc])];
        let cp = |w: &str, want| check_in(&cat, &r, seq(vec![cmd(&["cp", w, "a"])]), want);
        cp("-t/etc/x", Decision::Block);
        cp("--target-directory=/etc/x", Decision::Block);
        // The inline value is normalized like a path word.
        cp("-t/etc/./x", Decision::Block);
        cp("-t//etc", Decision::Block);
        cp("-t/tmp/x", Decision::Allow);
        // An empty inline value is not a hit.
        cp("--target-directory=", Decision::Allow);
    }

    #[test]
    fn option_value_path_is_a_target() {
        let cat = catalog_with_cp();
        let root = Pat::new(vec![lit("/")], PatKind::Exact).expect("non-empty");
        let r = [block_rule("cp", Vec::new(), vec![root])];
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["cp", "-t", "/", "a"])]),
            Decision::Block,
        );
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["cp", "-t", "/x", "a"])]),
            Decision::Allow,
        );
    }

    #[test]
    fn relative_path_after_cd_across_connectors() {
        // `cd /; rm usr`
        check(
            seq(vec![cmd(&["cd", "/"]), cmd(&["rm", "usr"])]),
            Decision::Ask,
        );
        // `cd / || rm usr`
        let or = Script::new(vec![AndOr::new(
            pipe(vec![cmd(&["cd", "/"])]),
            vec![Link::new(Connector::Or, pipe(vec![cmd(&["rm", "usr"])]))],
        )]);
        check(or, Decision::Ask);
        // `cd / | rm usr`
        let piped = Script::new(vec![AndOr::new(
            pipe(vec![cmd(&["cd", "/"]), cmd(&["rm", "usr"])]),
            Vec::new(),
        )]);
        check(piped, Decision::Ask);
        // `rm usr; cd /`: the cd comes after.
        check(
            seq(vec![cmd(&["rm", "usr"]), cmd(&["cd", "/"])]),
            Decision::Allow,
        );
    }

    #[test]
    fn tilde_dotdot_is_ask() {
        // `rm -- ~/../x`
        let sc = seq(vec![simple(vec![
            word(vec![lit("rm")]),
            word(vec![lit("--")]),
            tilde_word("/../x"),
        ])]);
        check_with(&[], sc, Decision::Ask);
    }

    #[test]
    fn alias_set_hits_any_spelling_the_catalog_lists_separately() {
        // The catalog lists `-r`, `-R` and `--recursive` as three options.
        let rm = row(
            &["rm"],
            gnu(
                vec![
                    flag(OptName::Short(short(b'r'))),
                    flag(OptName::Short(short(b'R'))),
                    flag(OptName::Long(long("recursive"))),
                    flag(OptName::Short(short(b'f'))),
                ],
                Role::Path,
            ),
            Cwd::Keeps,
        );
        let cat = Catalog::new(vec![rm], Vec::new());
        let root = Pat::new(vec![lit("/")], PatKind::Exact).expect("non-empty");
        let r = [block_rule(
            "rm",
            vec![any_of(vec![
                OptName::Short(short(b'r')),
                OptName::Short(short(b'R')),
                OptName::Long(long("recursive")),
            ])],
            vec![root],
        )];
        for argv in [
            ["rm", "-r", "/"],
            ["rm", "-R", "/"],
            ["rm", "--recursive", "/"],
        ] {
            check_in(&cat, &r, seq(vec![cmd(&argv)]), Decision::Block);
        }
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["rm", "-f", "/"])]),
            Decision::Allow,
        );
    }

    #[test]
    fn entries_are_conjoined_and_alternatives_disjoined() {
        let rm = row(
            &["rm"],
            gnu(
                vec![
                    flag(OptName::Short(short(b'r'))),
                    flag(OptName::Short(short(b'R'))),
                    flag(OptName::Short(short(b'f'))),
                ],
                Role::Path,
            ),
            Cwd::Keeps,
        );
        let cat = Catalog::new(vec![rm], Vec::new());
        let r = [block_rule(
            "rm",
            vec![
                any_of(vec![
                    OptName::Short(short(b'r')),
                    OptName::Short(short(b'R')),
                ]),
                one(OptName::Short(short(b'f'))),
            ],
            Vec::new(),
        )];
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["rm", "-R", "-f", "x"])]),
            Decision::Block,
        );
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["rm", "-R", "x"])]),
            Decision::Allow,
        );
        check_in(
            &cat,
            &r,
            seq(vec![cmd(&["rm", "-f", "x"])]),
            Decision::Allow,
        );
    }

    #[test]
    fn rules_see_the_first_covering_row() {
        let short_only = row(
            &["rm"],
            gnu(vec![flag(OptName::Short(short(b'r')))], Role::Path),
            Cwd::Keeps,
        );
        let both = row(
            &["rm"],
            gnu(
                vec![flag(OptName::Both(short(b'r'), long("recursive")))],
                Role::Path,
            ),
            Cwd::Keeps,
        );
        // The rule names only `--recursive`, so it overlaps `both` alone.
        let r = [block_rule(
            "rm",
            vec![one(OptName::Long(long("recursive")))],
            Vec::new(),
        )];
        let sc = seq(vec![cmd(&["rm", "-r", "x"])]);
        let first_short = Catalog::new(vec![short_only.clone(), both.clone()], Vec::new());
        check_in(&first_short, &r, sc.clone(), Decision::Allow);
        let first_both = Catalog::new(vec![both, short_only], Vec::new());
        check_in(&first_both, &r, sc, Decision::Block);
    }
}
