//! Normalised word representation and stage-2 static folding.
//!
//! This module defines both the output type of stage 2 (plan.md §1.1) —
//! [`NormalizedWord`]/[`Resolution`]/[`UnresolvableKind`], fixed ahead of
//! time in A3 — and, from this issue (B2) onward, the folding logic that
//! produces those values: quote removal, ANSI-C decoding, default-`$IFS`
//! splitting, tilde textualisation, and brace alternation. Everything below
//! operates on `crate::ast` values only — never on raw strings, never on any
//! parser crate's types (`coding-guidelines/principles.md`, "dependencies
//! point inward"). [`Verdict`](crate::verdict::Verdict)'s `normalized_argv`
//! is expressed in terms of [`NormalizedWord`].
//!
//! # API
//!
//! - [`normalize_word`] folds a single [`Word`](crate::ast::Word) into zero,
//!   one, or many [`NormalizedWord`]s — brace alternation and unquoted
//!   `$IFS` splitting both multiply a word; an unquoted `$IFS`-only word
//!   vanishes.
//! - [`normalize_argv`] is the convenience B3 (rules)/B4 (structural gate)
//!   actually want: flattens a [`SimpleCommand`](crate::ast::SimpleCommand)'s
//!   words into one argv.
//! - [`normalize_assignment_value`] folds an
//!   [`Assignment`](crate::ast::Assignment)'s value the same way, except
//!   `$IFS` never splits it — bash never word-splits an assignment's RHS
//!   (see that function's docs for the one narrow, documented divergence
//!   this creates around brace alternation).
//!
//! # What this module does NOT do
//!
//! No rule matching, no env lookups (not even for `$HOME` — tilde folds to
//! its literal text), no globbing, no execution. A word whose value cannot
//! be determined from the AST alone becomes [`Resolution::Unresolvable`]
//! with a [`UnresolvableKind`] — never a guessed string, never silently
//! dropped (plan.md §1.1). `IFS=` reassignment is deliberately out of scope
//! here too — folding always uses the *default* IFS (space/tab/newline);
//! making an `$IFS`-derived word untrusted after a same-line `IFS=`
//! assignment is the structural gate's job (plan.md §4, a later issue).

/// Why a word's final value could not be statically resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvableKind {
    /// The word contains a command substitution (`$(...)` or `` `...` ``)
    /// whose runtime output cannot be known statically.
    CommandSubstitution,
    /// The word contains a parameter expansion (`$NAME`/`${NAME}`) whose
    /// runtime value cannot be known statically.
    ParameterExpansion,
    /// The word's statically-decoded value is not representable as a valid
    /// UTF-8 `String`.
    ///
    /// Bash's ANSI-C quoting (`$'...'`) decodes `\xHH` and octal `\nnn`
    /// escapes as raw 8-bit bytes, and bash strings are byte-oriented — a
    /// lone `$'\x80'` is a perfectly ordinary (if unprintable) bash string.
    /// Rust's `String` must be valid UTF-8, so a byte sequence that doesn't
    /// decode as UTF-8 has no honest `String` to hold it. Per the
    /// never-guess rule (plan.md §1.1), such a word becomes `Unresolvable`
    /// with this kind rather than silently mangling or truncating the
    /// bytes. Multi-byte escapes that *do* form valid UTF-8 together (e.g.
    /// `$'\xc3\xa9'` for `é`) decode normally and never hit this case —
    /// decoding buffers raw bytes and validates UTF-8 once at the end, not
    /// escape-by-escape.
    NonUtf8,
    /// The word's brace alternation would expand past
    /// [`MAX_BRACE_ALTERNATIVES`] concrete words.
    ///
    /// shguard folds untrusted input — a command string an agent (or an
    /// attacker steering one) chose, not one shguard's own operator wrote.
    /// Brace alternation is a cartesian product: `{a,b}` repeated N times in
    /// one word is `2^N` output words with no upper bound in bash's own
    /// grammar. Materialising that product before checking its size would
    /// let a single crafted word exhaust memory or hang the hook — a
    /// security control that can itself be turned into a denial-of-service
    /// is a vulnerability, not a mitigation. The cap is enforced *during*
    /// expansion (before the oversized `Vec` is built), and a word that
    /// would exceed it fails closed as one `Unresolvable` word rather than
    /// a truncated or partial guess — the B4 gate routes it to `Ask`.
    ExpansionLimit,
    /// The word contains an arithmetic expansion (`$((...))`, issue #75)
    /// whose runtime value cannot be known statically. Kept distinct from
    /// [`UnresolvableKind::CommandSubstitution`] (rather than folded into
    /// it) because `crate::gate` also re-scans this piece's raw text for an
    /// embedded `$(...)`/backtick substitution — a distinct reason belongs
    /// to a distinct kind so the `Ask`/`Block` reason a caller reports names
    /// the actual construct.
    ArithmeticExpansion,
    /// The word contains a process substitution (`<(...)`/`>(...)`, issue
    /// #75) whose runtime output/behavior cannot be known statically. Kept
    /// distinct from [`UnresolvableKind::CommandSubstitution`] because its
    /// AST payload is a structural `CommandLine` (`crate::ast`), not a raw
    /// string — `crate::gate` recurses it via a different code path (direct
    /// AST descent, not a re-parse), and the reported reason should say so.
    ProcessSubstitution,
    /// The word contains a structural shape this stage cannot fold without
    /// guessing, and that (per shguard's AST and the parser adapter that
    /// builds it) should not be reachable through normal parsing at all.
    ///
    /// Concretely: a [`WordPiece::BraceAlternation`] nested inside a
    /// [`WordPiece::DoubleQuoted`] sequence — bash's grammar never
    /// brace-expands inside quotes, and the selected parser crate's brace
    /// pre-pass already excludes quoted content from it
    /// (docs/adr/0001-parser-crate.md). Rather than pick one alternative
    /// and silently discard the rest (a guessed string, forbidden by
    /// plan.md §1.1's never-guess rule), such a piece makes its word
    /// `Unresolvable` with this kind — fail-closed even on a path that
    /// should be structurally impossible.
    UnsupportedStructure,
    /// A word's literal content contains an embedded NUL byte — whether
    /// from raw source text (a NUL character can reach the parser directly,
    /// e.g. via a JSON `\u0000` in `tool_input.command`) or from decoding
    /// an ANSI-C escape (`$'\0'`, `$'\x00'`, …). Checked once, uniformly,
    /// at [`chunks_to_words`] — every literal chunk converges there before
    /// becoming a `Resolved` word, regardless of which `WordPiece` produced
    /// it (issue #138).
    ///
    /// NUL is valid single-byte UTF-8, so this can't be folded into
    /// [`UnresolvableKind::NonUtf8`]'s check — it needs its own guard.
    /// Real bash does not truncate a word at an embedded NUL the way a C
    /// string would suggest: it silently drops the NUL and concatenates
    /// the surrounding text into one word (`rm$'\0'IGNOREDTAIL` decodes to
    /// `rmIGNOREDTAIL`, confirmed against real bash argv capture, issue
    /// #138) — the same "merge defeats exact-string matching" bypass shape
    /// this repo has patched before, just produced by bash's own word
    /// expansion this time rather than by shguard's folding. Reproducing
    /// that merge would only recreate the bypass under a different string,
    /// and guessing a truncated prefix instead would claim knowledge
    /// shguard's static analysis doesn't have (plan.md's never-guess
    /// rule), so the word becomes `Unresolvable` with this kind instead,
    /// the same fail-closed treatment `NonUtf8` already gets.
    EmbeddedNul,
}

/// The two states a normalised word can be in: its value was folded to a
/// concrete string, or it could not be — and if not, why.
///
/// A sum type rather than `Option<String>` plus a side channel: a word is
/// never simultaneously resolved and unresolvable, and the type makes that
/// state unrepresentable instead of relying on callers to keep two fields in
/// sync (principles.md "make invalid states unrepresentable").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The word's final value, folded statically.
    Resolved(String),
    /// The word's value could not be folded statically.
    Unresolvable(UnresolvableKind),
}

/// A normalised word: its [`Resolution`] plus provenance.
///
/// The provenance flags exist because "resolved"/"unresolvable" alone don't
/// capture everything downstream matching needs to know:
///
/// - `ifs_derived`: "resolved" and "trustworthy" are not the same claim —
///   plan.md §1.1/§4 folds `$IFS`-containing words using the *default* IFS,
///   but a same-line `IFS=` assignment can make that fold wrong. Such a word
///   is legitimately both `Resolved` *and* untrusted — the structural gate
///   (a later issue) needs to tell it apart from an ordinarily resolved word
///   (e.g. to still check it against the blocklist but never let a miss
///   fall through to `Allow`).
/// - `single_word` (issue #146's `value_flags`-on-`matches_except_flags`
///   follow-up, GitHub issue #149 tracks generalising this): "unresolvable"
///   alone doesn't say whether this word position is GUARANTEED to denote
///   exactly one runtime shell word. A quoted expansion (`"$(...)"`,
///   `"$VAR"`) is — bash never word-splits inside double quotes. An
///   *unquoted* one (`$(...)`, `$VAR`) is NOT — its unknown runtime value
///   could contain IFS whitespace and split into several argv words, one of
///   which could be something entirely different from what a caller
///   expects to find at this position. Any mechanism that treats an
///   unresolvable word as safely "just a value" at a specific position
///   (rather than merely "presence somewhere in the tail forces Ask") MUST
///   consult [`Self::is_single_word`] first — see
///   `crate::rules::value_flag_consumed`, the motivating consumer.
///
/// Wrapping `Resolution` in a struct with these flags makes each combined
/// state representable instead of forcing extra `Resolution` variants that
/// would duplicate the resolved/unresolvable string cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedWord {
    resolution: Resolution,
    ifs_derived: bool,
    single_word: bool,
}

impl NormalizedWord {
    /// A word resolved to a concrete value by ordinary static folding
    /// (quote removal, ANSI-C decoding, tilde/brace expansion — not `$IFS`
    /// folding). Always [`Self::is_single_word`]: a resolved word's text is
    /// already fully known, so any unquoted whitespace it would have
    /// word-split on has already been accounted for by this stage's own
    /// splitting logic (`chunks_to_words`) — there is no remaining count
    /// uncertainty to track.
    #[must_use]
    pub fn resolved(value: impl Into<String>) -> Self {
        Self {
            resolution: Resolution::Resolved(value.into()),
            ifs_derived: false,
            single_word: true,
        }
    }

    /// A word resolved to a concrete value via `$IFS` folding against the
    /// default IFS — "resolved but untrusted" per plan.md §4: a same-line
    /// `IFS=` assignment can make this value wrong, so it stays subject to
    /// blocklist checks but must never fall through to `Allow` on a miss.
    #[must_use]
    pub fn resolved_ifs_derived(value: impl Into<String>) -> Self {
        Self {
            resolution: Resolution::Resolved(value.into()),
            ifs_derived: true,
            single_word: true,
        }
    }

    /// A word whose value could not be resolved statically, and whose
    /// runtime word COUNT at this position is also not guaranteed to be
    /// exactly one (the fail-closed default — [`Self::is_single_word`] is
    /// `false`). Use this for anything reached through an unquoted,
    /// split-eligible context, or for a kind whose splitting behavior
    /// hasn't been specifically argued safe (see
    /// [`Self::unresolvable_single_word`]'s docs for the narrower case that
    /// isn't).
    #[must_use]
    pub fn unresolvable(kind: UnresolvableKind) -> Self {
        Self {
            resolution: Resolution::Unresolvable(kind),
            ifs_derived: false,
            single_word: false,
        }
    }

    /// A word whose value could not be resolved statically, but whose
    /// runtime word count at this position IS guaranteed to be exactly one
    /// (a quoted expansion, e.g. `"$(...)"`/`"$VAR"` — bash never
    /// word-splits inside double quotes, so whatever this expands to at
    /// runtime is, by construction, one argv word, even though its content
    /// is unknown). Only [`resolve_piece`]'s expansion arms construct this,
    /// driven by the `allow_split` context already threaded through
    /// `src/normalize.rs`'s folding — never call this directly for a kind
    /// whose splitting behavior hasn't been argued safe (e.g.
    /// `ArithmeticExpansion`/`ProcessSubstitution` stay conservatively
    /// [`Self::unresolvable`] even when quoted, deferring that narrower
    /// optimization rather than bundling an unreviewed claim into this fix
    /// — GitHub issue #149).
    #[must_use]
    pub(crate) fn unresolvable_single_word(kind: UnresolvableKind) -> Self {
        Self {
            resolution: Resolution::Unresolvable(kind),
            ifs_derived: false,
            single_word: true,
        }
    }

    /// The word's resolution state.
    #[must_use]
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    /// Whether this word's resolved value came from folding a `$IFS`
    /// expansion, and is therefore untrusted in the presence of a same-line
    /// `IFS=` reassignment (plan.md §4).
    #[must_use]
    pub fn is_ifs_derived(&self) -> bool {
        self.ifs_derived
    }

    /// Whether this word is GUARANTEED to denote exactly one runtime shell
    /// word — always `true` for a [`Resolution::Resolved`] word; for a
    /// [`Resolution::Unresolvable`] one, `true` only when every expansion
    /// contributing to it was reached through a non-splitting (quoted)
    /// context. `false` is the fail-closed default for any unresolvable
    /// word not specifically constructed via
    /// [`Self::unresolvable_single_word`] — see that constructor's docs and
    /// `crate::rules::value_flag_consumed` for why this distinction matters
    /// (issue #146/#149): treating an unquoted expansion as safely "just a
    /// value" at a specific argv position would let its unknown runtime
    /// word-split smuggle in an entirely different, dangerous word.
    #[must_use]
    pub(crate) fn is_single_word(&self) -> bool {
        self.single_word
    }
}

// ---------------------------------------------------------------------
// Stage-2 folding (B2)
// ---------------------------------------------------------------------

use crate::ast::{
    Assignment, AssignmentValue, MAX_BRACE_NESTING_DEPTH, SimpleCommand, Word, WordPiece,
};

/// The three default-IFS whitespace characters bash uses when `IFS` is
/// unset: space, tab, newline. This module never folds against any other
/// `IFS` value (module docs) — a same-line `IFS=` reassignment is the
/// structural gate's concern, not this stage's.
const DEFAULT_IFS_WHITESPACE: &str = " \t\n";

/// Folds one [`Word`] into the normalised words it denotes.
///
/// A single input word can produce zero, one, or many output words:
/// - Brace alternation (`{a,b}`) multiplies it — `pre{a,b}` → `prea`,
///   `preb` (cartesian product with the surrounding pieces, recursively for
///   nested braces). An alternative that is itself unresolvable makes only
///   that expanded word `Unresolvable` — the others still fold normally.
/// - An unquoted `$IFS` re-splits it — `rm$IFS-rf$IFS/` → `rm`, `-rf`, `/`
///   (plan.md §4, Class B) — and an unquoted `$IFS`-only word vanishes
///   entirely (zero output words), matching bash's whitespace-IFS
///   splitting: leading, trailing, and consecutive IFS never produce empty
///   fields. A `$IFS` piece inside [`WordPiece::DoubleQuoted`] never splits
///   (bash semantics) — it folds to the literal default-IFS string
///   `" \t\n"` inside the one resolved word instead. Every word whose
///   resolution involved `$IFS`, split or not, is tagged
///   [`NormalizedWord::is_ifs_derived`].
///
/// # Fold order: brace before `$IFS`
///
/// Brace alternation is expanded first, structurally, into independent
/// piece sequences; `$IFS` splitting is then resolved separately *within*
/// each resulting alternative. This mirrors bash's own expansion order
/// (brace expansion runs before word splitting in the shell's actual
/// expansion pipeline) and falls out naturally from the data model: each
/// brace alternative already denotes its own complete word, so it makes its
/// own independent splitting decision — `rm$IFS{a,b}` folds as if it were
/// two separate words `rm$IFSa` and `rm$IFSb`, each of which then resolves
/// (and potentially splits) on its own.
///
/// `analyze()` (`src/lib.rs`) calls this via `src/gate.rs` — stage 2 of the
/// pipeline (plan.md §1.1).
#[must_use]
pub(crate) fn normalize_word(word: &Word) -> Vec<NormalizedWord> {
    fold_word(&word.0, true)
}

/// Normalises every word of a [`SimpleCommand`] into one flat argv.
///
/// A convenience wrapper over [`normalize_word`] so the rules engine and
/// the structural gate don't each have to flat-map it themselves.
#[must_use]
pub(crate) fn normalize_argv(command: &SimpleCommand) -> Vec<NormalizedWord> {
    command.words.iter().flat_map(normalize_word).collect()
}

/// Folds an [`Assignment`]'s value the same way [`normalize_word`] folds an
/// ordinary word, with one difference: `$IFS` never splits it.
///
/// Bash never word-splits the right-hand side of `NAME=value` — not even
/// when it unquoted-expands to whitespace — so this always resolves `$IFS`
/// the same way a double-quoted context would (the literal default-IFS
/// string, still tagged [`NormalizedWord::is_ifs_derived`]), and the
/// returned `Vec` normally has exactly one element for any value a real
/// bash assignment could produce (e.g. `X=rm` → one `Resolved("rm")`).
///
/// # A narrow, documented divergence
///
/// Bash also never brace-*expands* an assignment's RHS at all (`X={a,b}`
/// sets `X` to the four-character literal string `{a,b}`), but
/// `src/parser.rs`'s `convert_word` runs the same brace pre-pass on every
/// word regardless of whether it ends up as an assignment value or an
/// ordinary word, and shguard's AST has no channel left to recover the
/// original `{`/`,`/`}` characters once [`WordPiece::BraceAlternation`] has
/// replaced them. If a `BraceAlternation` piece ever does reach an
/// assignment value, this function folds it the same cartesian way
/// [`normalize_word`] would, one element per alternative — including an
/// empty, unquoted alternative, since [`chunks_to_words`]'s elision is
/// scoped to splitting contexts (`allow_split = true`) and never fires for
/// an assignment's RHS — rather than guessing at the lost literal text: a
/// narrow, acknowledged divergence from bash, recorded here rather than
/// silently worked around.
///
/// Called from `src/gate.rs` to resolve same-command-line variable
/// assignments (plan.md §4's rule 2).
#[must_use]
pub(crate) fn normalize_assignment_value(assignment: &Assignment) -> Vec<NormalizedWord> {
    match &assignment.value {
        AssignmentValue::Scalar(word) => fold_word(&word.0, false),
        // Array assignments (issue #75) are not modeled for `$NAME`
        // resolution: bash aliases a bare `$NAME` to `${NAME[0]}` for an
        // indexed array, but shguard doesn't track array elements once
        // resolved. Returning zero words here (rather than guessing at
        // "the first element") never matches `apply_one`'s `[one]` case, so
        // `Env` correctly never claims a resolution it can't stand behind.
        AssignmentValue::Array(_) => Vec::new(),
    }
}

/// One fragment of a piece sequence's resolved value: literal text, a
/// point where an unquoted `$IFS` splits the word, or (issue #82) a piece
/// whose own value couldn't be folded.
///
/// `Split` is only ever produced when folding is called with
/// `allow_split = true` — see [`resolve_piece`]. `Unresolvable` makes data,
/// not control flow, out of what a piece's own resolution failure means:
/// [`resolve_pieces`] never short-circuits across piece boundaries, so an
/// unresolvable piece never discards `Chunk`s (including `Split` points)
/// already produced by earlier pieces in the same run — see
/// [`chunks_to_words`] for how a `$IFS`-delimited segment containing one of
/// these differs from a clean segment (issue #82: `rm$IFS-rf$IFS/$(true)`
/// must still recognise `rm`/`-rf` as clean, resolved segments, isolating
/// only the trailing `/$(true)` segment as opaque, rather than collapsing
/// the entire piece run to one opaque word the moment any piece anywhere in
/// it fails to fold).
enum Chunk {
    /// `bool`: whether this text came from an actual quote pair
    /// (`WordPiece::SingleQuoted`, `WordPiece::AnsiCQuoted`, or a collapsed
    /// `WordPiece::DoubleQuoted` sequence) rather than plain unquoted text —
    /// [`chunks_to_words`] keys its empty-word elision on this, not on
    /// segment count, since bash elides an empty *unquoted* result
    /// regardless of which expansion produced the emptiness (`$IFS` split
    /// or an empty brace-alternation member) but always keeps an empty
    /// *quoted* one (`''`/`""`/`$''`).
    Literal(String, bool),
    Split,
    /// `bool`: whether THIS piece's contribution is guaranteed to be part
    /// of exactly one runtime word (issue #146/#149) — `true` when it was
    /// resolved with `allow_split = false` (a quoted/non-splitting
    /// context) for a kind whose splitting behavior has been argued safe,
    /// `false` otherwise (the fail-closed default). [`chunks_to_words`]
    /// ANDs this across every `Unresolvable` chunk in a segment, since one
    /// splittable piece anywhere in an otherwise-quoted word still makes
    /// the WHOLE resulting word's runtime count uncertain.
    Unresolvable(UnresolvableKind, bool),
}

/// The shared brace-then-resolve fold for both [`normalize_word`]
/// (`allow_split = true`) and [`normalize_assignment_value`]
/// (`allow_split = false`).
fn fold_word(pieces: &[WordPiece], allow_split: bool) -> Vec<NormalizedWord> {
    let alternatives = match expand_braces(pieces, 0) {
        Ok(alternatives) => alternatives,
        // The whole word fails closed as one unresolvable word — never a
        // truncated subset of the product (see `ExpansionLimit`'s docs).
        Err(kind) => return vec![NormalizedWord::unresolvable(kind)],
    };
    let mut out = Vec::new();
    for alternative in alternatives {
        let (chunks, ifs_derived) = resolve_pieces(&alternative, allow_split);
        out.extend(chunks_to_words(chunks, ifs_derived, allow_split));
    }
    out
}

/// Splits a command-position [`Word`]'s brace-alternation structure into
/// the piece sequence that determines `argv[0]` (the first alternative
/// [`fold_word`] would fold into at least one output word — "the winning
/// alternative") and the piece sequences of every other alternative, each
/// of which resolves to an argument-position token once brace-expanded
/// rather than to any part of the command name (issue #77).
///
/// Mirrors `fold_word`'s own iteration over [`expand_braces`]'s output so
/// the two can never diverge: `crate::gate`'s rule 1 needs to know which
/// raw pieces of a command-position word actually determine `argv[0]`,
/// rather than treating a substitution found anywhere in the word's brace
/// tree as command-position-ambiguous. `rm$IFS-rf$IFS/{,$(true)}`'s
/// `$(true)` branch never stands in for `rm` — it only ever contributes a
/// trailing argument-position word once the brace is expanded — so it must
/// not float rule 1's "which command will run" ambiguity, even though it
/// does still need scanning as an argument-position substitution (rule 3's
/// job, via the returned leftover pieces).
///
/// Returns `(None, [word.0.clone()])` when brace expansion itself fails
/// ([`UnresolvableKind::ExpansionLimit`]): `fold_word`'s matching arm folds
/// the whole word to one `Unresolvable` word in that case, so there is no
/// winning alternative to hand back — the caller already floors the
/// decision on that kind through the ordinary unresolvable-`argv[0]` path.
/// The raw, un-expanded pieces still go out as the sole leftover entry,
/// though: `collect_substitutions_into`/`collect_process_substitutions_into`
/// (`crate::gate`) already walk into [`WordPiece::BraceAlternation`]
/// members directly with no expansion needed, so any substitution the word
/// contains is still found and recursed rather than silently dropped along
/// with the abandoned brace expansion.
///
/// `winning` can also come back `None` after a *successful* expansion whose
/// every alternative elides to zero words (e.g. `{,}` — both members are
/// unquoted and empty): every alternative lands in `leftover` instead, none
/// having produced a word. Callers must not reach this function with a word
/// `crate::gate`'s own `first_non_vanishing_word_idx` has already skipped as
/// vanishing — both current call sites already guard on that.
#[must_use]
pub(crate) fn split_command_position(word: &Word) -> (Option<Vec<WordPiece>>, Vec<Vec<WordPiece>>) {
    let Ok(alternatives) = expand_braces(&word.0, 0) else {
        return (None, vec![word.0.clone()]);
    };
    let mut winning = None;
    let mut leftover = Vec::new();
    for alternative in alternatives {
        // Every alternative but the first to produce a word is, by
        // definition, not the one determining `argv[0]` — no need to
        // re-resolve once `winning` is already set.
        let produces_word = winning.is_none() && {
            let (chunks, ifs_derived) = resolve_pieces(&alternative, true);
            !chunks_to_words(chunks, ifs_derived, true).is_empty()
        };
        if produces_word {
            winning = Some(alternative);
        } else {
            leftover.push(alternative);
        }
    }
    // Issue #82: the winning alternative's OWN pieces can still be
    // `$IFS`-packed (`rm$IFS-rf$IFS/$(true)`, no braces involved at all) —
    // only the piece run contributing to `argv[0]` itself (the FIRST
    // non-empty `$IFS`-delimited segment, exactly the one
    // `chunks_to_words` would pick as the first output word) actually
    // determines `argv[0]`; a substitution after that segment's boundary
    // is command-position-ambiguous only in the same sense a brace-leftover
    // substitution is (issue #77), not in the "which command will run"
    // sense rule 1 exists for. Splitting this out here — rather than as a
    // separate helper only rule 1 consults — means
    // `has_command_position_leftover_substitution`'s allowlist-eligibility
    // guard (issue #83) sees it too: that guard's own doc rests on "a
    // substitution in the winning alternative always makes `argv[0]`
    // unresolvable, so rule 1 fires and no allow entry can match" — true
    // before this change, but only because the winning alternative was
    // never split any further than this.
    let winning = winning.map(|pieces| {
        let Some((command_position, remainder)) = split_at_first_word_boundary(&pieces) else {
            return pieces;
        };
        leftover.push(remainder);
        command_position
    });
    (winning, leftover)
}

/// Splits `pieces` at the `$IFS` boundary ending the first non-empty
/// segment `chunks_to_words` would fold it into — `None` if `pieces` has no
/// such boundary at all (no top-level `$IFS` piece, or every `$IFS` piece
/// is itself leading/consecutive with nothing but empty segments before
/// it, so the whole run stays one command-position piece sequence).
///
/// Walks `pieces` and [`resolve_pieces`]'s own resolved [`Chunk`]s for them
/// in lockstep — sound only because every `WordPiece` variant folds to
/// exactly one top-level `Chunk` (`resolve_piece`'s own match: one
/// `Literal`/`Split`/`Unresolvable` per piece; a nested
/// [`WordPiece::DoubleQuoted`] sequence's own internal complexity always
/// collapses to a single outer `Chunk` too, since it's folded with
/// `allow_split = false` and can never itself produce `Chunk::Split`) — so
/// `pieces[i]` and the resolved `chunks[i]` always refer to the same piece.
///
/// A segment counts as non-empty once it has seen a non-empty `Literal`
/// chunk or an `Unresolvable` chunk (mirroring [`chunks_to_words`]'s own
/// "an unresolvable segment always produces a word, never filtered as
/// empty" rule) — a `Split` seen before that point is a leading/consecutive
/// split whose preceding segment would itself be filtered away by
/// `chunks_to_words`, so it is skipped rather than treated as the boundary
/// (`$IFSrm`'s leading `$IFS` must not truncate `argv[0]` down to nothing).
///
/// The returned remainder starts at (and includes) the boundary's own
/// `$IFS` piece, not just what follows it: a leftover whose own
/// `Vec<WordPiece>` has length 1 is exempt from
/// `evaluate_leftover_alternative_substitutions`'s floor (a lone,
/// fully-transparent substitution/process-substitution piece with nothing
/// else glued to it recurses on its own merits instead, `crate::gate`
/// docs) — keeping the triggering `$IFS` piece in the remainder keeps its
/// length at 2+, so it keeps flooring to `Ask` exactly like every other
/// multi-piece leftover, the same way a real trailing argument would.
#[must_use]
fn split_at_first_word_boundary(pieces: &[WordPiece]) -> Option<(Vec<WordPiece>, Vec<WordPiece>)> {
    let (chunks, _) = resolve_pieces(pieces, true);
    debug_assert_eq!(pieces.len(), chunks.len());
    let mut segment_nonempty = false;
    for (idx, chunk) in chunks.iter().enumerate() {
        match chunk {
            Chunk::Split if segment_nonempty => {
                return Some((pieces[..idx].to_vec(), pieces[idx..].to_vec()));
            }
            Chunk::Split => segment_nonempty = false,
            Chunk::Literal(text, quoted) => segment_nonempty |= *quoted || !text.is_empty(),
            Chunk::Unresolvable(_, _) => segment_nonempty = true,
        }
    }
    None
}

/// Cap on the cartesian product of brace alternatives one word may expand
/// to. Real agent commands rarely exceed single digits; the cap exists so a
/// crafted `{a,b}{a,b}…` word cannot blow up memory — rationale in
/// [`UnresolvableKind::ExpansionLimit`]'s docs.
const MAX_BRACE_ALTERNATIVES: usize = 64;

/// Expands every [`WordPiece::BraceAlternation`] in `pieces` into the
/// cartesian product of concrete, brace-free piece sequences — the
/// structural first pass described in [`normalize_word`]'s "fold order"
/// docs. Recurses into each alternative's own pieces so nested braces
/// (`{a,{b,c}}`) multiply correctly.
///
/// The product is bounded by [`MAX_BRACE_ALTERNATIVES`], checked while the
/// product is being built (and inside every recursion) — the oversized
/// `Vec` is never materialised.
///
/// `depth` (0 at the top call from [`fold_word`], +1 per recursion into a
/// member's own pieces) is bounded by [`MAX_BRACE_NESTING_DEPTH`] — issue
/// #52's defense-in-depth for this recursion, alongside `src/parser.rs`'s
/// raw pre-scan (the primary defense: brace nesting this deep cannot
/// actually reach this function in practice, since the parser rejects it
/// first) and its own AST-level cap in `convert_brace_segment`/
/// `convert_brace_members`. A word that exceeds the cap fails closed as one
/// `Unresolvable(ExpansionLimit)` word — the same fail-closed shape (and the
/// same `UnresolvableKind`) [`MAX_BRACE_ALTERNATIVES`]'s cap already uses,
/// since both are "this word's brace structure is too large to safely
/// expand" from the gate's point of view.
fn expand_braces(
    pieces: &[WordPiece],
    depth: usize,
) -> Result<Vec<Vec<WordPiece>>, UnresolvableKind> {
    if depth > MAX_BRACE_NESTING_DEPTH {
        return Err(UnresolvableKind::ExpansionLimit);
    }
    let mut alternatives: Vec<Vec<WordPiece>> = vec![Vec::new()];
    for piece in pieces {
        if let WordPiece::BraceAlternation(members) = piece {
            let mut next = Vec::new();
            for prefix in &alternatives {
                for member in members {
                    for suffix in expand_braces(&member.0, depth + 1)? {
                        if next.len() >= MAX_BRACE_ALTERNATIVES {
                            return Err(UnresolvableKind::ExpansionLimit);
                        }
                        let mut combined = prefix.clone();
                        combined.extend(suffix);
                        next.push(combined);
                    }
                }
            }
            alternatives = next;
        } else {
            for prefix in &mut alternatives {
                prefix.push(piece.clone());
            }
        }
    }
    Ok(alternatives)
}

/// Resolves a brace-free piece sequence into its [`Chunk`]s plus whether
/// `$IFS` was involved anywhere in it. Infallible (issue #82): every piece
/// contributes exactly one `Chunk` to the output — including a piece whose
/// own value couldn't be folded, which contributes a [`Chunk::Unresolvable`]
/// rather than aborting the whole run. This one-piece-to-one-chunk shape is
/// load-bearing, not incidental: [`split_at_first_word_boundary`] walks
/// `pieces` and this function's own resolved `chunks` in lockstep, which is
/// only sound because the correspondence holds exactly.
fn resolve_pieces(pieces: &[WordPiece], allow_split: bool) -> (Vec<Chunk>, bool) {
    let mut chunks = Vec::with_capacity(pieces.len());
    let mut ifs_derived = false;
    for piece in pieces {
        let (chunk, piece_ifs) = resolve_piece(piece, allow_split);
        chunks.push(chunk);
        ifs_derived |= piece_ifs;
    }
    (chunks, ifs_derived)
}

/// Resolves one [`WordPiece`] into a single [`Chunk`] (issue #82: never more
/// or fewer than one — see [`resolve_pieces`]'s docs on why that
/// correspondence must hold exactly).
///
/// `allow_split` distinguishes the two contexts that matter for `$IFS`
/// (plan.md §4): `true` for an ordinary unquoted top-level piece (may
/// produce [`Chunk::Split`]); `false` for anything already inside a
/// non-splitting context — [`WordPiece::DoubleQuoted`] content (bash never
/// splits inside double quotes) and assignment values (bash never
/// word-splits an assignment's RHS at all) both thread `false` down.
fn resolve_piece(piece: &WordPiece, allow_split: bool) -> (Chunk, bool) {
    match piece {
        WordPiece::Literal(text) => (Chunk::Literal(text.clone(), false), false),
        WordPiece::SingleQuoted(text) => (Chunk::Literal(text.clone(), true), false),
        // `quoted = false`: a backslash escape is never empty text (`ch` is
        // always exactly one character), so the elision-relevant flag is
        // never actually consulted for it — `false` documents that this
        // piece is not itself an elision-blocking quote pair, should a
        // future change ever let it contribute empty text.
        WordPiece::EscapeSequence(ch) => (Chunk::Literal(ch.to_string(), false), false),
        WordPiece::AnsiCQuoted(raw) => match decode_ansi_c(raw) {
            Ok(decoded) => (Chunk::Literal(decoded, true), false),
            // Not argued single-word-safe (issue #149): conservatively
            // unguaranteed even though $'...' syntax itself never splits —
            // narrowing this is deferred, not bundled into this fix.
            Err(kind) => (Chunk::Unresolvable(kind, false), false),
        },
        WordPiece::DoubleQuoted(inner) => {
            // Double-quoted content never splits, regardless of the outer
            // context, so the recursive resolve always threads
            // `allow_split = false` — no `Chunk::Split` can come back out
            // of `resolve_pieces` here, so a lone `Chunk::Unresolvable`
            // anywhere inside makes the WHOLE double-quoted sequence one
            // `Chunk::Unresolvable` too (the first KIND found; matches this
            // module's existing "one bad piece poisons its containing,
            // non-splitting run" behavior — issue #82 only changes that
            // rule at the TOP-LEVEL, `$IFS`-splittable layer, never inside
            // a quoted, non-splitting one). `ifs_derived` still propagates
            // even when the result is `Unresolvable` — a `$IFS` piece
            // folded to its literal default-whitespace text before the
            // poisoning piece was reached, so rule 7's floor (a same-line
            // `IFS=` reassignment could make that already-folded text
            // wrong) still applies.
            //
            // `single_word` (issue #149): must be ANDed across EVERY inner
            // `Unresolvable` chunk, not just the first — mirroring
            // `chunks_to_words`'s own aggregation exactly, and for the same
            // reason. Most inner pieces earn `single_word = true`
            // uniformly here (they're all resolved with `allow_split =
            // false`), EXCEPT `"$@"` (see the `ParameterExpansion` arm
            // below), which is unguaranteed regardless of quoting — so
            // `"$*$@"` (an ordinary quoted `$*` — safe alone — followed by
            // `$@` — never safe) must not let the first chunk's safety
            // mask the second chunk's danger. An early return on the FIRST
            // `Unresolvable` chunk would do exactly that: `git commit -m
            // "$*$@"` word-splits at runtime and can smuggle in a real
            // `--no-verify` after the "value," identical in kind to the bug
            // `single_word` exists to catch.
            let (inner_chunks, ifs_derived) = resolve_pieces(inner, false);
            let mut buf = String::new();
            let mut unresolvable: Option<(UnresolvableKind, bool)> = None;
            for chunk in inner_chunks {
                match chunk {
                    Chunk::Literal(text, _quoted) => {
                        if unresolvable.is_none() {
                            buf.push_str(&text);
                        }
                    }
                    Chunk::Unresolvable(kind, single_word) => {
                        unresolvable = Some(match unresolvable {
                            None => (kind, single_word),
                            Some((first_kind, guaranteed_so_far)) => {
                                (first_kind, guaranteed_so_far && single_word)
                            }
                        });
                    }
                    Chunk::Split => unreachable!(
                        "allow_split=false never produces Chunk::Split (resolve_piece's own IFS arm)"
                    ),
                }
            }
            match unresolvable {
                Some((kind, single_word)) => (Chunk::Unresolvable(kind, single_word), ifs_derived),
                // Quoted unconditionally: an empty `""` must survive
                // elision the same as a non-empty one, regardless of what
                // its (possibly zero) inner pieces produced.
                None => (Chunk::Literal(buf, true), ifs_derived),
            }
        }
        // `$IFS`/`${IFS}` (plan.md §4, Class B): unquoted and split-eligible
        // becomes a split point; otherwise (double-quoted, or an
        // assignment value) it folds to the literal default-IFS string.
        // Either way `$IFS` was "involved", so `ifs_derived` is always set.
        WordPiece::ParameterExpansion(name) if name == "IFS" => {
            if allow_split {
                (Chunk::Split, true)
            } else {
                (
                    Chunk::Literal(DEFAULT_IFS_WHITESPACE.to_string(), false),
                    true,
                )
            }
        }
        // issue #146/#149: `!allow_split` — a quoted (`"$VAR"`) reference is
        // guaranteed to be exactly one runtime word even though its value
        // is unknown; an unquoted one (`$VAR`) is NOT, since that unknown
        // value could contain IFS whitespace and word-split at runtime.
        //
        // `"$@"` is the one documented exception to "double quotes prevent
        // splitting" in the entire shell grammar: it always expands to one
        // runtime word PER POSITIONAL PARAMETER, even quoted — `set -- x
        // --no-verify; git commit -m "$@"` actually runs as `git commit -m
        // x --no-verify`, the exact same class of bypass this fix exists to
        // close, just through a special parameter instead of `$(...)`.
        // Never single-word regardless of `allow_split`. `"$*"` is NOT this
        // exception — it always joins to exactly one string under quoting
        // (only its join separator, not its word count, depends on IFS),
        // so it keeps the ordinary `!allow_split` treatment.
        WordPiece::ParameterExpansion(name) => (
            Chunk::Unresolvable(
                UnresolvableKind::ParameterExpansion,
                name != "@" && !allow_split,
            ),
            false,
        ),
        // Both forms of command substitution carry the same static
        // unknowability; `UnresolvableKind::CommandSubstitution`'s own docs
        // already cover "`$(...)` or `` `...` ``", so no separate kind is
        // needed. B4 recurses into the inner command straight from the AST
        // (`crate::ast::WordPiece::CommandSubstitution`/`BackquotedSubstitution`
        // already carry the raw inner string), so this kind does not need
        // to carry it too — duplicating it here would be a second source of
        // truth for data the AST already owns. `!allow_split`: same
        // quoted-vs-unquoted reasoning as `ParameterExpansion` above — this
        // is the exact case issue #146/#149 motivated (`git commit -m
        // "$(...)"` is single-word-safe; `git commit -m $(...)` is not).
        //
        // Issue #124: a SYNTACTICALLY empty body (`$()`, `$( )`, `` `` ``,
        // `` `  ` `` — the parser's raw inner text is empty or whitespace
        // only, checked here rather than re-deriving "empty" from a parsed
        // command list, since the AST already hands this piece the raw
        // string) is a deterministic, not runtime-dependent, empty-string
        // expansion — resolved the same way any other provably-empty piece
        // is (`Chunk::Literal(String::new(), !allow_split)`), which
        // `chunks_to_words`'s own elision rule (see its docs) then vanishes
        // when unquoted/splittable and keeps as a lone empty field when
        // quoted, exactly matching real bash's `$()` vs. `"$()"` split.
        // A body with ANY actual content — even a no-op like `:`/`true` —
        // is NOT "provably empty" in this sense (evaluating whether a real
        // command has side effects is a different, much harder problem,
        // out of scope here) and keeps the ordinary `Unresolvable` floor.
        //
        // `str::trim()` strips Rust's full Unicode `White_Space` set (e.g.
        // U+00A0 NBSP), which is broader than what bash's own tokenizer
        // treats as blank — bash would try to run a command literally
        // NAMED by such bytes rather than treating the body as empty. In
        // the overwhelmingly common case this is harmless either way (no
        // such command exists, so bash's `$()` also produces empty stdout
        // and the two agree). The one theoretical divergence — an attacker
        // who already controls `$PATH` well enough to place an executable
        // there literally named by Unicode-whitespace bytes — requires
        // filesystem/PATH control that would already grant far simpler
        // bypasses, so this is not treated as a live gap; recorded here so
        // the choice is deliberate rather than an accident of `trim()`'s
        // default character class.
        WordPiece::CommandSubstitution(text) | WordPiece::BackquotedSubstitution(text)
            if text.trim().is_empty() =>
        {
            (Chunk::Literal(String::new(), !allow_split), false)
        }
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedSubstitution(_) => (
            Chunk::Unresolvable(UnresolvableKind::CommandSubstitution, !allow_split),
            false,
        ),
        // Opaque regardless of what `crate::gate`'s raw-text rescan finds
        // inside it (issue #75) — the rescan only exists to let a `Block`
        // from an embedded `$(...)` escalate above this `Ask` floor, not to
        // resolve the expansion itself. Not argued single-word-safe even
        // when quoted (issue #149): an arithmetic result is always a
        // whitespace-free integer under the default IFS, which WOULD make
        // it safe unconditionally, but that claim is deferred to its own
        // review rather than bundled into this fix — conservatively
        // unguaranteed regardless of `allow_split`.
        WordPiece::ArithmeticExpansion(_) => (
            Chunk::Unresolvable(UnresolvableKind::ArithmeticExpansion, false),
            false,
        ),
        // Opaque regardless of what the substituted command's own recursive
        // evaluation decides (issue #75) — same "floor, not a resolution"
        // relationship as arithmetic expansion above. Conservatively
        // unguaranteed regardless of `allow_split` (issue #149) — no
        // established reasoning for why a process substitution's runtime
        // shape would be single-word-safe.
        WordPiece::ProcessSubstitution { .. } => (
            Chunk::Unresolvable(UnresolvableKind::ProcessSubstitution, false),
            false,
        ),
        // Literal textual form only (`~`, `~user`, `~+`, `~-`, …). Resolving
        // to an actual home directory would require an env lookup, which
        // this stage never performs (module docs); blocklist rules match on
        // absolute paths, so the literal text is both safe (never a guessed
        // path) and honest (never silently dropped either).
        WordPiece::Tilde(user) => {
            let text = if user.is_empty() {
                "~".to_string()
            } else {
                format!("~{user}")
            };
            (Chunk::Literal(text, false), false)
        }
        WordPiece::BraceAlternation(_) => {
            // Structurally unreachable in practice: `expand_braces` strips
            // every `BraceAlternation` (including nested ones, via its own
            // recursion into each member's pieces) out of any piece
            // sequence before it reaches `resolve_pieces`/`resolve_piece`.
            // The only way one could still appear here is nested inside a
            // `DoubleQuoted` sequence — which bash's grammar never produces
            // (brace expansion does not happen inside quotes) and which the
            // selected parser crate's brace pre-pass already excludes
            // (docs/adr/0001-parser-crate.md). Rather than panic, or fold
            // by guessing one alternative (forbidden — never a guessed
            // string), fail closed: the word becomes `Unresolvable` and the
            // gate routes it to Ask. Conservatively unguaranteed (issue
            // #149) — an unreachable-in-practice shape gets no special
            // single-word reasoning.
            (
                Chunk::Unresolvable(UnresolvableKind::UnsupportedStructure, false),
                false,
            )
        }
    }
}

/// Turns one alternative's resolved [`Chunk`]s into the [`NormalizedWord`]s
/// it denotes.
///
/// Uniformly segments `chunks` at every [`Chunk::Split`] boundary — even
/// when no split occurred at all, which is just the one-segment case — into
/// one `Result<(String, bool), (UnresolvableKind, bool)>` per segment: `Ok`
/// accumulates every [`Chunk::Literal`]'s text in the segment, OR-ing
/// together each one's own quoted flag (`true` once ANY part of the segment
/// came from an actual quote pair); a [`Chunk::Unresolvable`] anywhere in it
/// poisons the whole segment to `Err` (the first kind found) — and a
/// [`Chunk::Literal`] containing an embedded NUL byte is treated as an
/// `Unresolvable(EmbeddedNul)` chunk the same way, checked right here rather
/// than by each `Chunk::Literal` producer individually, since every literal
/// source's text converges on this one accumulation loop before it can
/// become a `Resolved` word (issue #138). The `bool` on the `Err` arm (issue
/// #146/#149) is every `Chunk::Unresolvable`'s own single-word flag ANDed
/// together across the WHOLE segment, not just the poisoning chunk's — a
/// later splittable piece in an otherwise-quoted segment (`"$(a)"$(b)`)
/// still makes the whole resulting word's runtime count uncertain, even
/// though only the first chunk's *kind* is kept for the reported reason.
/// Each segment then becomes zero or one words:
/// - `Err((kind, single_word))` ALWAYS produces exactly one
///   [`NormalizedWord::unresolvable`]/[`NormalizedWord::unresolvable_single_word`],
///   never filtered as potentially empty: an unresolvable segment's true
///   expansion length can't be known statically (this stage never executes
///   anything, module docs), so assuming it would vanish the way a resolved
///   empty segment does would be a guess, not a fold (issue #82's own
///   motivating case, `rm$IFS-rf$IFS/$(true)`, must isolate `/$(true)` as
///   exactly one opaque word, not zero).
/// - `Ok((text, quoted))` becomes [`NormalizedWord::resolved`] (or
///   [`NormalizedWord::resolved_ifs_derived`] if `ifs_derived`) UNLESS it is
///   empty AND `quoted` is `false` AND `allow_split` is `true`. Bash elides
///   an empty result only where word-splitting itself applies (an ordinary
///   unquoted top-level word) — regardless of which mechanism produced the
///   emptiness there (a real `$IFS` split, or an empty brace-alternation
///   member resolved on its own in [`fold_word`]'s per-alternative loop) —
///   but never in a non-splitting context: `allow_split = false` only ever
///   reaches this function via [`normalize_assignment_value`]'s top-level
///   [`fold_word`] call, and bash assigns `X=` the literal empty string
///   rather than vanishing the assignment. An empty *quoted* result (`''`,
///   `""`, `$''`) is kept unconditionally either way: it is `Resolved("")`
///   and must not vanish (plan.md §1.1 rule 7).
fn chunks_to_words(
    chunks: Vec<Chunk>,
    ifs_derived: bool,
    allow_split: bool,
) -> Vec<NormalizedWord> {
    let mut segments = Vec::new();
    let mut current: Result<(String, bool), (UnresolvableKind, bool)> = Ok((String::new(), false));
    for chunk in chunks {
        // issue #138: a literal chunk containing an embedded NUL byte is
        // treated exactly like an `Unresolvable(EmbeddedNul)` chunk from
        // here on — checked once, here, regardless of which `WordPiece`
        // (raw source text, ANSI-C decoding, …) the byte came from, rather
        // than at each producer individually.
        let chunk = match chunk {
            Chunk::Literal(text, _quoted) if text.contains('\0') => {
                Chunk::Unresolvable(UnresolvableKind::EmbeddedNul, false)
            }
            other => other,
        };
        match chunk {
            Chunk::Literal(text, quoted) => {
                if let Ok((buf, any_quoted)) = &mut current {
                    buf.push_str(&text);
                    *any_quoted |= quoted;
                }
            }
            Chunk::Unresolvable(kind, single_word) => {
                current = match current {
                    Ok(_) => Err((kind, single_word)),
                    // Keep the FIRST kind, but AND every chunk's
                    // single_word flag in — one splittable piece anywhere
                    // in the segment revokes the whole segment's guarantee.
                    Err((first_kind, guaranteed_so_far)) => {
                        Err((first_kind, guaranteed_so_far && single_word))
                    }
                };
            }
            Chunk::Split => {
                segments.push(std::mem::replace(&mut current, Ok((String::new(), false))));
            }
        }
    }
    segments.push(current);

    segments
        .into_iter()
        .filter_map(|segment| match segment {
            Err((kind, true)) => Some(NormalizedWord::unresolvable_single_word(kind)),
            Err((kind, false)) => Some(NormalizedWord::unresolvable(kind)),
            Ok((text, quoted)) if quoted || !text.is_empty() || !allow_split => {
                Some(if ifs_derived {
                    NormalizedWord::resolved_ifs_derived(text)
                } else {
                    NormalizedWord::resolved(text)
                })
            }
            Ok(_) => None,
        })
        .collect()
}

/// Computes bash's `\cX` control-character mapping. `c` must be ASCII
/// (checked by the caller before calling this).
///
/// `\c?` is `DEL` (`0x7F`) — the long-standing terminal convention bash
/// hardcodes rather than derives — otherwise the target is upper-cased and
/// masked with `0x1F` (`\cA`-`\cZ`/`\ca`-`\cz` → `0x01`-`0x1A`, `\c@` →
/// `0x00`, `\c[` → `0x1B`, `\c\` → `0x1C`, `\c]` → `0x1D`, `\c^` → `0x1E`,
/// `\c_` → `0x1F`).
fn control_char(c: char) -> u8 {
    if c == '?' {
        0x7F
    } else {
        (u32::from(c.to_ascii_uppercase()) as u8) & 0x1F
    }
}

/// Reads up to `max` ASCII hex digits from `chars`, consuming them.
/// Returns `None` (consuming nothing) if the next character isn't a hex
/// digit at all — the caller uses that to detect a malformed `\x`/`\u`/`\U`
/// escape with no digits following.
fn read_hex_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    max: usize,
) -> Option<u32> {
    let mut value: u32 = 0;
    let mut count = 0;
    while count < max {
        match chars.peek() {
            Some(digit) if digit.is_ascii_hexdigit() => {
                value = value * 16 + digit.to_digit(16).unwrap_or(0);
                chars.next();
                count += 1;
            }
            _ => break,
        }
    }
    if count == 0 { None } else { Some(value) }
}

/// Decodes the raw contents of an ANSI-C-quoted word piece (`$'...'`,
/// [`WordPiece::AnsiCQuoted`]'s un-decoded contents) per bash's `$'...'`
/// escape set: `\\ \' \" \? \a \b \e \E \f \n \r \t \v`, octal `\nnn`
/// (1-3 digits), hex `\xHH` (1-2 digits), unicode `\uHHHH` (1-4 digits) and
/// `\UHHHHHHHH` (1-8 digits), and control `\cX`.
///
/// # Bash-faithful choices
///
/// - An unrecognised or malformed escape (`\z`, a bare trailing `\`, or
///   `\x`/`\u`/`\U`/`\c` with no digit/target following) is kept literally
///   as `\` followed by the next character — bash's own behaviour for an
///   escape it doesn't recognise — rather than treated as an error.
/// - Octal/hex escapes decode to raw *bytes*, not Unicode scalar values
///   (bash strings are byte-oriented): they are buffered into a `Vec<u8>`
///   and the whole result is UTF-8-validated once at the end, so multi-byte
///   sequences built from consecutive escapes (`$'\xc3\xa9'` → `é`) decode
///   correctly. A byte sequence that isn't valid UTF-8 on its own (a lone
///   `$'\x80'`) becomes `Err(UnresolvableKind::NonUtf8)` — never a lossy or
///   truncated guess (see [`UnresolvableKind::NonUtf8`]'s docs).
/// - `\u`/`\U` values that are not a valid Unicode scalar value (surrogate
///   code points, or a `\U` value above `0x10FFFF`) also become
///   `Err(UnresolvableKind::NonUtf8)`: Rust's `char` cannot hold them, and
///   guessing a replacement would violate the never-guess rule.
/// - `\cX` uses [`control_char`]; a non-ASCII target (or none at all) is
///   malformed and kept literal, per the first bullet.
/// - A decoded byte sequence containing an embedded NUL byte (from octal
///   `\0`, hex `\x00`, unicode `\u`/`\U` escaping code point zero, or
///   `\c@`) decodes to an ordinary `Ok` string here — deliberately NOT
///   rejected in this function. [`UnresolvableKind::EmbeddedNul`]'s docs
///   cover why the NUL check instead lives downstream in
///   [`chunks_to_words`], where every literal source is checked uniformly
///   rather than only this one.
fn decode_ansi_c(raw: &str) -> Result<String, UnresolvableKind> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }

        let Some(&escape) = chars.peek() else {
            // Trailing lone backslash: bash keeps it literally.
            bytes.push(b'\\');
            continue;
        };

        match escape {
            '\\' => {
                chars.next();
                bytes.push(b'\\');
            }
            '\'' => {
                chars.next();
                bytes.push(b'\'');
            }
            '"' => {
                chars.next();
                bytes.push(b'"');
            }
            '?' => {
                chars.next();
                bytes.push(b'?');
            }
            'a' => {
                chars.next();
                bytes.push(0x07);
            }
            'b' => {
                chars.next();
                bytes.push(0x08);
            }
            'e' | 'E' => {
                chars.next();
                bytes.push(0x1B);
            }
            'f' => {
                chars.next();
                bytes.push(0x0C);
            }
            'n' => {
                chars.next();
                bytes.push(0x0A);
            }
            'r' => {
                chars.next();
                bytes.push(0x0D);
            }
            't' => {
                chars.next();
                bytes.push(0x09);
            }
            'v' => {
                chars.next();
                bytes.push(0x0B);
            }
            '0'..='7' => {
                chars.next();
                let mut value = escape.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.peek() {
                        Some(digit) if digit.is_digit(8) => {
                            value = value * 8 + digit.to_digit(8).unwrap_or(0);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                bytes.push((value & 0xFF) as u8);
            }
            'x' => {
                chars.next();
                match read_hex_digits(&mut chars, 2) {
                    Some(value) => bytes.push((value & 0xFF) as u8),
                    None => {
                        bytes.push(b'\\');
                        bytes.push(b'x');
                    }
                }
            }
            'u' => {
                chars.next();
                match read_hex_digits(&mut chars, 4) {
                    Some(value) => match char::from_u32(value) {
                        Some(ch) => {
                            let mut buf = [0u8; 4];
                            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        None => return Err(UnresolvableKind::NonUtf8),
                    },
                    None => {
                        bytes.push(b'\\');
                        bytes.push(b'u');
                    }
                }
            }
            'U' => {
                chars.next();
                match read_hex_digits(&mut chars, 8) {
                    Some(value) => match char::from_u32(value) {
                        Some(ch) => {
                            let mut buf = [0u8; 4];
                            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        None => return Err(UnresolvableKind::NonUtf8),
                    },
                    None => {
                        bytes.push(b'\\');
                        bytes.push(b'U');
                    }
                }
            }
            'c' => {
                chars.next();
                match chars.peek().copied() {
                    Some(target) if target.is_ascii() => {
                        chars.next();
                        bytes.push(control_char(target));
                    }
                    _ => {
                        bytes.push(b'\\');
                        bytes.push(b'c');
                    }
                }
            }
            other => {
                // Unknown/malformed escape: bash keeps it literally.
                chars.next();
                bytes.push(b'\\');
                let mut buf = [0u8; 4];
                bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }

    // An embedded NUL (e.g. from `\0`/`\x00`) is left in `bytes` uncaught
    // here: it's valid UTF-8, and every literal this decodes into is
    // checked uniformly downstream in `chunks_to_words`, alongside every
    // other literal source, not just this one (issue #138).
    String::from_utf8(bytes).map_err(|_| UnresolvableKind::NonUtf8)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ast::{Command, CommandLine};

    fn parse_ok(command: &str) -> CommandLine {
        match crate::parser::parse(command) {
            Ok(cmd) => cmd,
            Err(err) => panic!("expected {command:?} to parse, got {err:?}"),
        }
    }

    /// Unwraps a [`Command::Simple`], panicking otherwise — every fixture in
    /// this module parses to an ordinary simple command (issue #75: `Pipeline`
    /// holds `Command`, not `SimpleCommand`, directly).
    fn simple(command: &Command) -> &SimpleCommand {
        match command {
            Command::Simple(simple) => simple,
            other => panic!("expected a simple command, got {other:?}"),
        }
    }

    fn first_word_normalized(command: &str) -> Vec<NormalizedWord> {
        let cmd = parse_ok(command);
        normalize_word(&simple(&cmd.first.first).words[0])
    }

    fn argv_of(command: &str) -> Vec<NormalizedWord> {
        let cmd = parse_ok(command);
        normalize_argv(simple(&cmd.first.first))
    }

    fn resolved_strings(words: &[NormalizedWord]) -> Vec<&str> {
        words
            .iter()
            .map(|w| match w.resolution() {
                Resolution::Resolved(s) => s.as_str(),
                Resolution::Unresolvable(kind) => {
                    panic!("expected a resolved word, got Unresolvable({kind:?})")
                }
            })
            .collect()
    }

    // ==== DoD assertions (issue #10), going through parse() + normalize ====

    #[test]
    fn dod_1_adjacent_single_quote() {
        let argv = argv_of("r''m -rf /");
        assert_eq!(resolved_strings(&argv), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn dod_2_adjacent_double_quote() {
        let argv = argv_of("\"r\"m");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    #[test]
    fn dod_3_escaped_backslash() {
        let argv = argv_of("r\\m");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    #[test]
    fn dod_4_ansi_c_hex() {
        let argv = argv_of("$'\\x72\\x6d'");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    #[test]
    fn dod_5_ifs_splitting() {
        let argv = argv_of("rm$IFS-rf$IFS/");
        assert_eq!(resolved_strings(&argv), vec!["rm", "-rf", "/"]);
        assert!(
            argv.iter().all(NormalizedWord::is_ifs_derived),
            "every word of an $IFS-split word must be ifs_derived: {argv:?}"
        );
    }

    #[test]
    fn dod_6_command_substitution_is_unresolvable() {
        let words = first_word_normalized("$(date)");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::CommandSubstitution)
        );
    }

    // ==== Own unit tests ====

    // ---- ANSI-C: octal ----
    #[test]
    fn ansi_c_octal() {
        let argv = argv_of("$'\\162\\155'");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    // ---- ANSI-C: unicode ($'\uHHHH') ----
    #[test]
    fn ansi_c_unicode() {
        let argv = argv_of("$'\\u00e9'");
        assert_eq!(resolved_strings(&argv), vec!["\u{e9}"]);
    }

    // ---- ANSI-C: control ($'\cA' -> 0x01) ----
    #[test]
    fn ansi_c_control() {
        let argv = argv_of("$'\\cA'");
        let resolved = resolved_strings(&argv);
        assert_eq!(resolved, vec!["\u{1}"]);
        assert_eq!(resolved[0].as_bytes(), &[0x01]);
    }

    // ---- ANSI-C: unknown/malformed escape kept literally (backslash + char) ----
    #[test]
    fn ansi_c_unknown_escape_kept_literal() {
        let argv = argv_of("$'\\z'");
        assert_eq!(resolved_strings(&argv), vec!["\\z"]);
    }

    // ---- ANSI-C: a lone non-UTF-8-representable byte is Unresolvable(NonUtf8) ----
    #[test]
    fn ansi_c_lone_high_byte_is_non_utf8() {
        let words = first_word_normalized("$'\\x80'");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::NonUtf8)
        );
    }

    // ---- ANSI-C: a decoded embedded NUL is Unresolvable(EmbeddedNul),
    // never folded into a merged literal (issue #138) ----
    #[test]
    fn ansi_c_embedded_nul_is_unresolvable() {
        let words = first_word_normalized("rm$'\\0'IGNOREDTAIL");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::EmbeddedNul)
        );
    }

    // ---- ANSI-C: every escape form that can decode to a NUL byte hits the
    // same guard (issue #138), not just the octal one exercised above ----
    #[test]
    fn ansi_c_every_nul_producing_escape_form_is_unresolvable() {
        for command in ["$'\\00'", "$'\\x00'", "$'\\u0000'", "$'\\c@'"] {
            let words = first_word_normalized(command);
            assert_eq!(words.len(), 1, "command {command:?}");
            assert_eq!(
                *words[0].resolution(),
                Resolution::Unresolvable(UnresolvableKind::EmbeddedNul),
                "command {command:?}"
            );
        }
    }

    // ---- a raw NUL byte in the source text (never routed through
    // decode_ansi_c at all, e.g. from a JSON `\u0000` in
    // `tool_input.command`) hits the same guard as a decoded one, since
    // both converge on chunks_to_words (issue #138) ----
    #[test]
    fn raw_literal_embedded_nul_is_unresolvable() {
        let words = first_word_normalized("rm\0MID");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::EmbeddedNul)
        );
    }

    // ---- double-quoted $IFS does not split, folds to the literal default-IFS
    // string, and is still tagged ifs_derived ----
    #[test]
    fn double_quoted_ifs_does_not_split() {
        let words = first_word_normalized("\"$IFS\"");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Resolved(" \t\n".to_string())
        );
        assert!(words[0].is_ifs_derived());
    }

    // ---- brace multiplication with a surrounding prefix ----
    #[test]
    fn brace_multiplication_with_prefix() {
        let argv = argv_of("echo pre{a,b}");
        assert_eq!(resolved_strings(&argv), vec!["echo", "prea", "preb"]);
    }

    // ---- empty quoted word is kept as Resolved("") ----
    #[test]
    fn empty_quotes_kept() {
        let words = first_word_normalized("''");
        assert_eq!(words.len(), 1);
        assert_eq!(*words[0].resolution(), Resolution::Resolved(String::new()));
    }

    // ---- an unquoted, empty brace-alternation member is elided from argv
    // the way bash elides it (issue #93 fuzzer finding) — matches bash's
    // `set -- {a,}; echo "$#"` printing `1`, not `2` ----
    #[test]
    fn unquoted_empty_brace_member_is_elided() {
        let argv = argv_of("echo {a,}");
        assert_eq!(resolved_strings(&argv), vec!["echo", "a"]);
    }

    // ---- a quoted empty word survives elision even after an $IFS split
    // elsewhere in the same alternative (the `chunks_to_words` fix keys
    // elision on quotedness, not segment count, so a quoted-empty segment
    // must stay kept regardless of how many other segments the split
    // produced) ----
    #[test]
    fn quoted_empty_word_still_kept_after_ifs_split() {
        let argv = argv_of("''${IFS}rm");
        assert_eq!(resolved_strings(&argv), vec!["", "rm"]);
    }

    // ---- an unquoted $IFS-only word vanishes (zero output words) ----
    #[test]
    fn ifs_only_word_vanishes() {
        let words = first_word_normalized("$IFS");
        assert!(words.is_empty(), "expected zero words, got {words:?}");
    }

    // ==== issue #124: a syntactically empty (no command content at all)
    // $()/backtick body is a deterministic, not runtime-dependent,
    // empty-string expansion — vanishes unquoted (zero output words, same
    // elision as an unquoted $IFS-only word above), stays as one empty
    // field when quoted, exactly matching real bash's $() vs. "$()". ====

    #[test]
    fn unquoted_empty_command_substitution_vanishes() {
        let words = first_word_normalized("$()");
        assert!(words.is_empty(), "expected zero words, got {words:?}");
    }

    #[test]
    fn unquoted_empty_backquoted_substitution_vanishes() {
        let words = first_word_normalized("``");
        assert!(words.is_empty(), "expected zero words, got {words:?}");
    }

    #[test]
    fn unquoted_whitespace_only_command_substitution_vanishes() {
        let words = first_word_normalized("$(   )");
        assert!(words.is_empty(), "expected zero words, got {words:?}");
    }

    #[test]
    fn quoted_empty_command_substitution_stays_one_empty_field() {
        // Parity control: quoting prevents word-splitting, so an empty
        // "$()" must survive as a single Resolved("") word, NOT vanish —
        // this is the exact distinction that makes `"$()" rm -rf /` an
        // empty-string argv[0] in real bash (command not found), utterly
        // different from unquoted `$() rm -rf /` (which really does
        // dispatch plain `rm -rf /`).
        let words = first_word_normalized(r#""$()""#);
        assert_eq!(words.len(), 1);
        assert_eq!(*words[0].resolution(), Resolution::Resolved(String::new()));
    }

    #[test]
    fn command_substitution_with_real_content_stays_unresolvable() {
        // Parity control: a body with ANY actual command content — even a
        // no-op like `:`/`true` — is not "provably empty" in this sense;
        // evaluating whether a real command has side effects is a
        // different, out-of-scope problem.
        let words = first_word_normalized("$(true)");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::CommandSubstitution)
        );
    }

    #[test]
    fn nested_empty_command_substitution_stays_unresolvable() {
        // A substitution whose own raw (unparsed) inner text is `$()` —
        // not itself empty/whitespace-only as a raw string — stays
        // conservatively Unresolvable rather than recursively detecting
        // emptiness one level deeper; only the AST's own literal "nothing
        // inside" shape is treated as provably empty.
        let words = first_word_normalized("$($())");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::CommandSubstitution)
        );
    }

    // ---- non-IFS $VAR -> Unresolvable(ParameterExpansion) ----
    #[test]
    fn non_ifs_parameter_expansion_is_unresolvable() {
        let words = first_word_normalized("$FOO");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::ParameterExpansion)
        );
    }

    // ---- mixed foo$(x) -> one Unresolvable(CommandSubstitution) word,
    // word-level granularity (not dropped, not a guessed string) ----
    #[test]
    fn mixed_literal_and_command_substitution_is_unresolvable() {
        let words = first_word_normalized("foo$(x)bar");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::CommandSubstitution)
        );
    }

    // ==== single-word guarantee (issue #146/#149): a quoted expansion is
    // guaranteed to be exactly one runtime shell word even though its
    // value is unknown; an unquoted one is NOT, since word-splitting could
    // smuggle in additional words at runtime — this is what
    // `crate::rules::value_flag_consumed` must be able to tell apart. ====

    #[test]
    fn quoted_command_substitution_is_single_word() {
        let argv = argv_of(r#"true "$(date)""#);
        assert_eq!(argv.len(), 2);
        assert!(argv[1].is_single_word());
    }

    #[test]
    fn unquoted_command_substitution_is_not_single_word() {
        let argv = argv_of("true $(date)");
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn quoted_parameter_expansion_is_single_word() {
        let argv = argv_of(r#"true "$FOO""#);
        assert_eq!(argv.len(), 2);
        assert!(argv[1].is_single_word());
    }

    #[test]
    fn unquoted_parameter_expansion_is_not_single_word() {
        let argv = argv_of("true $FOO");
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    // `"$@"` (issue #146/#149) is the one exception to "double quotes
    // prevent splitting" in the shell grammar — it splits into one word per
    // positional parameter even quoted, so it must NEVER be single-word
    // regardless of `allow_split`.
    #[test]
    fn quoted_dollar_at_is_not_single_word() {
        let argv = argv_of(r#"true "$@""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn unquoted_dollar_at_is_not_single_word() {
        let argv = argv_of("true $@");
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    // `"$*"` genuinely joins to exactly one string when quoted (only its
    // separator, not its word count, depends on IFS) — it is NOT the same
    // exception `"$@"` is, and stays single-word.
    #[test]
    fn quoted_dollar_star_is_single_word() {
        let argv = argv_of(r#"true "$*""#);
        assert_eq!(argv.len(), 2);
        assert!(argv[1].is_single_word());
    }

    // ==== the DoubleQuoted arm's own aggregation trap (issue #149): a safe
    // chunk (`$*`/`$VAR`/`$(...)`) followed by `$@` inside the SAME pair of
    // double quotes must not let the first chunk's guarantee mask the
    // second chunk's danger — the same shape `chunks_to_words`'s own
    // aggregation already handles. ====

    #[test]
    fn quoted_star_then_at_is_not_single_word() {
        let argv = argv_of(r#"true "$*$@""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn quoted_var_then_at_is_not_single_word() {
        let argv = argv_of(r#"true "$VAR$@""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn quoted_command_substitution_then_at_is_not_single_word() {
        let argv = argv_of(r#"true "$(echo x)$@""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn quoted_at_then_star_is_not_single_word() {
        // Order flipped from the cases above — pins that the fix isn't
        // itself order-dependent in the other direction.
        let argv = argv_of(r#"true "$@$*""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    #[test]
    fn resolved_word_is_always_single_word() {
        let argv = argv_of("true literal");
        assert_eq!(argv.len(), 2);
        assert!(argv[1].is_single_word());
    }

    // The aggregation trap (issue #149): a quoted
    // piece followed immediately by an unquoted one, glued into ONE word
    // with no $IFS boundary between them — the segment's guarantee must be
    // the AND over every contributing chunk, not just the first (poisoning)
    // one, or this would wrongly read as single-word-safe from the quoted
    // piece alone.
    #[test]
    fn mixed_quoted_then_unquoted_substitution_is_not_single_word() {
        let argv = argv_of(r#"true "$(a)"$(b)"#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    // Same trap, opposite order: unquoted first, quoted second — the
    // unquoted piece's contribution must not be discarded just because the
    // FIRST chunk (which decides the reported `kind`) came from the quoted
    // side... here it's the other way round (unquoted first), so this also
    // pins that the AND doesn't accidentally short-circuit on the first
    // chunk's own value in either direction.
    #[test]
    fn mixed_unquoted_then_quoted_substitution_is_not_single_word() {
        let argv = argv_of(r#"true $(a)"$(b)""#);
        assert_eq!(argv.len(), 2);
        assert!(!argv[1].is_single_word());
    }

    // ---- normalize_assignment_value: the canonical B4 use case ----
    #[test]
    fn assignment_value_simple() {
        let cmd = parse_ok("X=rm");
        let words = normalize_assignment_value(&simple(&cmd.first.first).assignments[0]);
        assert_eq!(resolved_strings(&words), vec!["rm"]);
    }

    // ---- normalize_assignment_value: an empty RHS (`X=`) resolves to
    // exactly one Resolved(""), never zero words — bash assigns X the
    // literal empty string, it does not vanish the assignment the way an
    // unquoted empty word elides in a splitting context. Regression guard
    // for the fable-review finding on the elision fix above: an earlier
    // version of the `chunks_to_words` fix elided this too, which made
    // `apply_one` drop the `X -> ""` mapping and downgraded `X=; $X rm -rf
    // /` from Block to Ask. ----
    #[test]
    fn assignment_value_empty_rhs_resolves_to_one_empty_word() {
        let cmd = parse_ok("X=");
        let words = normalize_assignment_value(&simple(&cmd.first.first).assignments[0]);
        assert_eq!(words.len(), 1);
        assert_eq!(*words[0].resolution(), Resolution::Resolved(String::new()));
    }

    // ---- normalize_assignment_value: $IFS never splits an assignment's RHS,
    // even though it would split an ordinary unquoted word ----
    #[test]
    fn assignment_value_ifs_does_not_split() {
        let cmd = parse_ok("X=rm$IFS-rf");
        let words = normalize_assignment_value(&simple(&cmd.first.first).assignments[0]);
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Resolved("rm \t\n-rf".to_string())
        );
        assert!(words[0].is_ifs_derived());
    }

    // ---- tilde folds to its literal textual form, never an env lookup ----
    #[test]
    fn tilde_folds_to_literal_text() {
        let words = first_word_normalized("~/x");
        assert_eq!(resolved_strings(&words), vec!["~/x"]);
    }

    // ---- a brace product past MAX_BRACE_ALTERNATIVES fails closed as ONE
    // Unresolvable(ExpansionLimit) word, never a truncated subset ----
    #[test]
    fn brace_product_over_cap_is_expansion_limit() {
        // 2^7 = 128 > 64
        let words = first_word_normalized("a{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}");
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::ExpansionLimit)
        );
    }

    // ---- issue #52: expand_braces's own depth cap, built programmatically
    // ----
    //
    // A raw command string can never reach this path: `src/parser.rs`'s raw
    // pre-scan (`reject_excessive_raw_nesting`) and its own AST-level cap
    // (`convert_brace_segment`/`convert_brace_members`) both reject nesting
    // this deep before a `WordPiece::BraceAlternation` tree this shape
    // could ever be built by `parse()`. This test constructs the tree by
    // hand to pin `expand_braces`'s depth cap as a defense-in-depth
    // backstop in its own right, independent of the parser layer.
    #[test]
    fn programmatically_deep_brace_nesting_hits_the_depth_cap() {
        let mut pieces = vec![WordPiece::Literal("x".to_string())];
        for _ in 0..=MAX_BRACE_NESTING_DEPTH {
            pieces = vec![WordPiece::BraceAlternation(vec![Word(pieces)])];
        }
        let words = fold_word(&pieces, true);
        assert_eq!(words.len(), 1);
        assert_eq!(
            *words[0].resolution(),
            Resolution::Unresolvable(UnresolvableKind::ExpansionLimit)
        );
    }

    // ---- a multi-brace product under the cap still folds normally ----
    #[test]
    fn brace_product_under_cap_folds_normally() {
        let words = first_word_normalized("x{a,b}{c,d}");
        assert_eq!(resolved_strings(&words), vec!["xac", "xad", "xbc", "xbd"]);
    }

    // ==== split_command_position (issue #77) ====

    fn first_word(cmd: &CommandLine) -> &Word {
        &simple(&cmd.first.first).words[0]
    }

    /// Folds `pieces` as an ordinary top-level (`allow_split = true`) run —
    /// a test-only convenience wrapping [`resolve_pieces`]/[`chunks_to_words`]
    /// together, mirroring what `fold_word` does for one alternative.
    fn fold_pieces(pieces: &[WordPiece]) -> Vec<NormalizedWord> {
        let (chunks, ifs_derived) = resolve_pieces(pieces, true);
        chunks_to_words(chunks, ifs_derived, true)
    }

    fn contains_unresolvable(words: &[NormalizedWord]) -> bool {
        words
            .iter()
            .any(|w| matches!(w.resolution(), Resolution::Unresolvable(_)))
    }

    // Issue #82: the winning alternative's own `$IFS` packing is now ALSO
    // isolated (not just brace membership) — `winning` narrows to just the
    // `rm` piece run in BOTH this test and the one below, and the
    // substitution-carrying remainder becomes an ADDITIONAL leftover entry
    // rather than ever living inside `winning`. Before issue #82, this test
    // asserted `winning` resolved cleanly as a WHOLE (it happened to,
    // incidentally, since the empty brace member carries no substitution at
    // all) — post-#82 it resolves to exactly `["rm"]`, a stronger and more
    // precise claim.
    #[test]
    fn split_command_position_empty_member_wins_when_tried_first() {
        let cmd = parse_ok("rm$IFS-rf$IFS/{,$(true)}");
        let (winning, leftover) = split_command_position(first_word(&cmd));
        let winning = winning.unwrap();
        assert_eq!(resolved_strings(&fold_pieces(&winning)), vec!["rm"]);
        // One leftover from the losing brace member (issue #77), one from
        // the winning alternative's own post-`$IFS`-split remainder (issue
        // #82) — the substitution lives in the FORMER here, since the
        // winning alternative (the empty member) carries none of its own.
        assert_eq!(leftover.len(), 2);
        assert!(contains_unresolvable(&fold_pieces(&leftover[0])));
        assert!(!contains_unresolvable(&fold_pieces(&leftover[1])));
    }

    // Same word, members swapped: the substitution-carrying member is now
    // tried FIRST (mirrors `fold_word`'s left-to-right member order), so it
    // WINS the brace selection this time — but issue #82's `$IFS`-boundary
    // split still isolates `rm` alone as `winning`, moving the substitution
    // into the winning alternative's own remainder leftover instead. Before
    // issue #82, this was the genuinely-ambiguous case (the substitution
    // really did make `argv[0]` itself unresolvable, since nothing scoped
    // the winning alternative down further than brace membership) — #82
    // narrows it the same way #77 narrowed brace membership.
    #[test]
    fn split_command_position_substitution_member_wins_when_tried_first() {
        let cmd = parse_ok("rm$IFS-rf$IFS/{$(true),}");
        let (winning, leftover) = split_command_position(first_word(&cmd));
        let winning = winning.unwrap();
        assert_eq!(resolved_strings(&fold_pieces(&winning)), vec!["rm"]);
        assert_eq!(leftover.len(), 2);
        // The losing brace member (the empty one) carries no substitution;
        // the winning alternative's own `$IFS`-remainder does.
        assert!(!contains_unresolvable(&fold_pieces(&leftover[0])));
        assert!(contains_unresolvable(&fold_pieces(&leftover[1])));
    }

    // No brace alternation at all: the whole word is the winning
    // alternative, verbatim, with nothing left over.
    #[test]
    fn split_command_position_no_braces_is_the_whole_word() {
        let cmd = parse_ok("rm -rf /");
        let word = first_word(&cmd);
        let (winning, leftover) = split_command_position(word);
        assert_eq!(winning.as_deref(), Some(word.0.as_slice()));
        assert!(leftover.is_empty());
    }

    // A brace product past MAX_BRACE_ALTERNATIVES fails closed with no
    // winning alternative at all (mirrors `fold_word`'s own
    // `ExpansionLimit` fail-closed arm) — never a guessed or partial
    // winner. The raw, un-expanded pieces still come back as the sole
    // leftover entry, so a substitution elsewhere in the word is not
    // silently dropped just because the brace product itself was too large
    // to expand.
    #[test]
    fn split_command_position_expansion_limit_has_no_winner() {
        let cmd = parse_ok("a{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}$(rm -rf /)");
        let word = first_word(&cmd);
        let (winning, leftover) = split_command_position(word);
        assert!(winning.is_none());
        assert_eq!(leftover, vec![word.0.clone()]);
    }

    // Security regression (issue #93 fuzzer finding): a bare, unquoted empty
    // brace member at command position must NOT win argv[0] resolution
    // ahead of a real command listed later in the same alternation. Before
    // the `chunks_to_words` elision fix, `{,rm} -rf /` resolved `argv[0]` to
    // `""` (never matching any blocklist rule) instead of `rm`, letting the
    // command Allow through. `{rm,}` (member order swapped) was always safe,
    // since the non-empty alternative was already tried first.
    #[test]
    fn split_command_position_bare_empty_first_member_does_not_win() {
        let cmd = parse_ok("{,rm}");
        let word = first_word(&cmd);
        let (winning, _leftover) = split_command_position(word);
        let winning = winning.unwrap();
        assert_eq!(resolved_strings(&fold_pieces(&winning)), vec!["rm"]);
    }
}
