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
/// The provenance flag exists because "resolved" and "trustworthy" are not
/// the same claim: plan.md §1.1/§4 folds `$IFS`-containing words using the
/// *default* IFS, but a same-line `IFS=` assignment can make that fold
/// wrong. Such a word is legitimately both `Resolved` *and* untrusted — the
/// structural gate (a later issue) needs to tell it apart from an ordinarily
/// resolved word (e.g. to still check it against the blocklist but never let
/// a miss fall through to `Allow`). Wrapping `Resolution` in a struct with
/// an `ifs_derived` flag makes that combined state representable instead of
/// forcing a third `Resolution` variant that would duplicate the resolved
/// string case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedWord {
    resolution: Resolution,
    ifs_derived: bool,
}

impl NormalizedWord {
    /// A word resolved to a concrete value by ordinary static folding
    /// (quote removal, ANSI-C decoding, tilde/brace expansion — not `$IFS`
    /// folding).
    #[must_use]
    pub fn resolved(value: impl Into<String>) -> Self {
        Self {
            resolution: Resolution::Resolved(value.into()),
            ifs_derived: false,
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
        }
    }

    /// A word whose value could not be resolved statically.
    #[must_use]
    pub fn unresolvable(kind: UnresolvableKind) -> Self {
        Self {
            resolution: Resolution::Unresolvable(kind),
            ifs_derived: false,
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
}

// ---------------------------------------------------------------------
// Stage-2 folding (B2)
// ---------------------------------------------------------------------

use crate::ast::{Assignment, SimpleCommand, Word, WordPiece};

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
/// [`normalize_word`] would (returning more than one element) rather than
/// guessing at the lost literal text — a narrow, acknowledged divergence
/// from bash, recorded here rather than silently worked around.
///
/// Called from `src/gate.rs` to resolve same-command-line variable
/// assignments (plan.md §4's rule 2).
#[must_use]
pub(crate) fn normalize_assignment_value(assignment: &Assignment) -> Vec<NormalizedWord> {
    fold_word(&assignment.value.0, false)
}

/// One fragment of a piece sequence's resolved value: literal text, or a
/// point where an unquoted `$IFS` splits the word.
///
/// `Split` is only ever produced when folding is called with
/// `allow_split = true` — see [`resolve_piece`].
enum Chunk {
    Literal(String),
    Split,
}

/// The shared brace-then-resolve fold for both [`normalize_word`]
/// (`allow_split = true`) and [`normalize_assignment_value`]
/// (`allow_split = false`).
fn fold_word(pieces: &[WordPiece], allow_split: bool) -> Vec<NormalizedWord> {
    let alternatives = match expand_braces(pieces) {
        Ok(alternatives) => alternatives,
        // The whole word fails closed as one unresolvable word — never a
        // truncated subset of the product (see `ExpansionLimit`'s docs).
        Err(kind) => return vec![NormalizedWord::unresolvable(kind)],
    };
    let mut out = Vec::new();
    for alternative in alternatives {
        match resolve_pieces(&alternative, allow_split) {
            Err(kind) => out.push(NormalizedWord::unresolvable(kind)),
            Ok((chunks, ifs_derived)) => out.extend(chunks_to_words(chunks, ifs_derived)),
        }
    }
    out
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
fn expand_braces(pieces: &[WordPiece]) -> Result<Vec<Vec<WordPiece>>, UnresolvableKind> {
    let mut alternatives: Vec<Vec<WordPiece>> = vec![Vec::new()];
    for piece in pieces {
        if let WordPiece::BraceAlternation(members) = piece {
            let mut next = Vec::new();
            for prefix in &alternatives {
                for member in members {
                    for suffix in expand_braces(&member.0)? {
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
/// `$IFS` was involved anywhere in it. Short-circuits (word-level
/// granularity, plan.md §1.1 rule 4) the moment any piece is unresolvable —
/// `foo$(x)bar` is one `Unresolvable` word, not a partially-folded one.
fn resolve_pieces(
    pieces: &[WordPiece],
    allow_split: bool,
) -> Result<(Vec<Chunk>, bool), UnresolvableKind> {
    let mut chunks = Vec::new();
    let mut ifs_derived = false;
    for piece in pieces {
        let (piece_chunks, piece_ifs) = resolve_piece(piece, allow_split)?;
        chunks.extend(piece_chunks);
        ifs_derived |= piece_ifs;
    }
    Ok((chunks, ifs_derived))
}

/// Resolves one [`WordPiece`] into [`Chunk`]s.
///
/// `allow_split` distinguishes the two contexts that matter for `$IFS`
/// (plan.md §4): `true` for an ordinary unquoted top-level piece (may
/// produce [`Chunk::Split`]); `false` for anything already inside a
/// non-splitting context — [`WordPiece::DoubleQuoted`] content (bash never
/// splits inside double quotes) and assignment values (bash never
/// word-splits an assignment's RHS at all) both thread `false` down.
fn resolve_piece(
    piece: &WordPiece,
    allow_split: bool,
) -> Result<(Vec<Chunk>, bool), UnresolvableKind> {
    match piece {
        WordPiece::Literal(text) | WordPiece::SingleQuoted(text) => {
            Ok((vec![Chunk::Literal(text.clone())], false))
        }
        WordPiece::EscapeSequence(ch) => Ok((vec![Chunk::Literal(ch.to_string())], false)),
        WordPiece::AnsiCQuoted(raw) => {
            let decoded = decode_ansi_c(raw)?;
            Ok((vec![Chunk::Literal(decoded)], false))
        }
        WordPiece::DoubleQuoted(inner) => {
            // Double-quoted content never splits, regardless of the outer
            // context, so the recursive resolve always threads
            // `allow_split = false` — no `Chunk::Split` can come back out
            // of `resolve_pieces` here, so only `Chunk::Literal` is ever
            // seen below.
            let (inner_chunks, ifs_derived) = resolve_pieces(inner, false)?;
            let mut buf = String::new();
            for chunk in inner_chunks {
                if let Chunk::Literal(text) = chunk {
                    buf.push_str(&text);
                }
            }
            Ok((vec![Chunk::Literal(buf)], ifs_derived))
        }
        // `$IFS`/`${IFS}` (plan.md §4, Class B): unquoted and split-eligible
        // becomes a split point; otherwise (double-quoted, or an
        // assignment value) it folds to the literal default-IFS string.
        // Either way `$IFS` was "involved", so `ifs_derived` is always set.
        WordPiece::ParameterExpansion(name) if name == "IFS" => {
            if allow_split {
                Ok((vec![Chunk::Split], true))
            } else {
                Ok((
                    vec![Chunk::Literal(DEFAULT_IFS_WHITESPACE.to_string())],
                    true,
                ))
            }
        }
        WordPiece::ParameterExpansion(_) => Err(UnresolvableKind::ParameterExpansion),
        // Both forms of command substitution carry the same static
        // unknowability; `UnresolvableKind::CommandSubstitution`'s own docs
        // already cover "`$(...)` or `` `...` ``", so no separate kind is
        // needed. B4 recurses into the inner command straight from the AST
        // (`crate::ast::WordPiece::CommandSubstitution`/`BackquotedSubstitution`
        // already carry the raw inner string), so this kind does not need
        // to carry it too — duplicating it here would be a second source of
        // truth for data the AST already owns.
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedSubstitution(_) => {
            Err(UnresolvableKind::CommandSubstitution)
        }
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
            Ok((vec![Chunk::Literal(text)], false))
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
            // gate routes it to Ask.
            Err(UnresolvableKind::UnsupportedStructure)
        }
    }
}

/// Turns one alternative's resolved [`Chunk`]s into the [`NormalizedWord`]s
/// it denotes: one word if no `$IFS` split occurred (even if empty — an
/// empty quoted word like `''` is `Resolved("")` and is kept, plan.md §1.1
/// rule 7), otherwise one word per non-empty segment between split points
/// (leading/trailing/consecutive splits never produce empty segments,
/// matching bash's whitespace-IFS splitting).
fn chunks_to_words(chunks: Vec<Chunk>, ifs_derived: bool) -> Vec<NormalizedWord> {
    let split_occurred = chunks.iter().any(|chunk| matches!(chunk, Chunk::Split));

    if !split_occurred {
        let mut buf = String::new();
        for chunk in chunks {
            if let Chunk::Literal(text) = chunk {
                buf.push_str(&text);
            }
        }
        let word = if ifs_derived {
            NormalizedWord::resolved_ifs_derived(buf)
        } else {
            NormalizedWord::resolved(buf)
        };
        return vec![word];
    }

    let mut segments = Vec::new();
    let mut current = String::new();
    for chunk in chunks {
        match chunk {
            Chunk::Literal(text) => current.push_str(&text),
            Chunk::Split => segments.push(std::mem::take(&mut current)),
        }
    }
    segments.push(current);

    segments
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .map(NormalizedWord::resolved_ifs_derived)
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

    String::from_utf8(bytes).map_err(|_| UnresolvableKind::NonUtf8)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ast::CommandLine;

    fn parse_ok(command: &str) -> CommandLine {
        match crate::parser::parse(command) {
            Ok(cmd) => cmd,
            Err(err) => panic!("expected {command:?} to parse, got {err:?}"),
        }
    }

    fn first_word_normalized(command: &str) -> Vec<NormalizedWord> {
        let cmd = parse_ok(command);
        normalize_word(&cmd.first.first.words[0])
    }

    fn argv_of(command: &str) -> Vec<NormalizedWord> {
        let cmd = parse_ok(command);
        normalize_argv(&cmd.first.first)
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

    // ---- 1. r''m -rf / -> ["rm", "-rf", "/"] ----
    #[test]
    fn dod_1_adjacent_single_quote() {
        let argv = argv_of("r''m -rf /");
        assert_eq!(resolved_strings(&argv), vec!["rm", "-rf", "/"]);
    }

    // ---- 2. "r"m -> ["rm"] ----
    #[test]
    fn dod_2_adjacent_double_quote() {
        let argv = argv_of("\"r\"m");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    // ---- 3. r\m -> ["rm"] ----
    #[test]
    fn dod_3_escaped_backslash() {
        let argv = argv_of("r\\m");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    // ---- 4. $'\x72\x6d' -> ["rm"] ----
    #[test]
    fn dod_4_ansi_c_hex() {
        let argv = argv_of("$'\\x72\\x6d'");
        assert_eq!(resolved_strings(&argv), vec!["rm"]);
    }

    // ---- 5. rm$IFS-rf$IFS/ -> ["rm", "-rf", "/"], each ifs_derived ----
    #[test]
    fn dod_5_ifs_splitting() {
        let argv = argv_of("rm$IFS-rf$IFS/");
        assert_eq!(resolved_strings(&argv), vec!["rm", "-rf", "/"]);
        assert!(
            argv.iter().all(NormalizedWord::is_ifs_derived),
            "every word of an $IFS-split word must be ifs_derived: {argv:?}"
        );
    }

    // ---- 6. $(date) -> Unresolvable, not a string ----
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
        // sanity: argv carries "echo" then the two brace expansions
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

    // ---- an unquoted $IFS-only word vanishes (zero output words) ----
    #[test]
    fn ifs_only_word_vanishes() {
        let words = first_word_normalized("$IFS");
        assert!(words.is_empty(), "expected zero words, got {words:?}");
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

    // ---- normalize_assignment_value: the canonical B4 use case ----
    #[test]
    fn assignment_value_simple() {
        let cmd = parse_ok("X=rm");
        let words = normalize_assignment_value(&cmd.first.first.assignments[0]);
        assert_eq!(resolved_strings(&words), vec!["rm"]);
    }

    // ---- normalize_assignment_value: $IFS never splits an assignment's RHS,
    // even though it would split an ordinary unquoted word ----
    #[test]
    fn assignment_value_ifs_does_not_split() {
        let cmd = parse_ok("X=rm$IFS-rf");
        let words = normalize_assignment_value(&cmd.first.first.assignments[0]);
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

    // ---- a multi-brace product under the cap still folds normally ----
    #[test]
    fn brace_product_under_cap_folds_normally() {
        let words = first_word_normalized("x{a,b}{c,d}");
        assert_eq!(resolved_strings(&words), vec!["xac", "xad", "xbc", "xbd"]);
    }
}
