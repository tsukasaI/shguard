//! shguard's own AST for a parsed bash command line.
//!
//! These types are shguard's, not any parser crate's: `src/parser.rs`
//! translates the selected parser crate's output (docs/adr/0001-parser-crate.md)
//! into this shape so the rest of the pipeline never imports a type from
//! that crate (plan.md §1.1 stage 1). The shape here is sized to the
//! fixture corpus the ADR validated the selected crate against: lists joined by
//! `;`/`&&`/`||`, pipelines, simple commands (assignments + words +
//! redirections), and word pieces covering quoting, ANSI-C quoting,
//! parameter/command/backquote substitution, tilde, brace alternation, and
//! escape sequences.
//!
//! Constructed by `src/parser.rs` (the stage 1 adapter, B1). Consumed by the
//! normalise stage (`src/normalize.rs`, B2) and, for the raw substitution
//! text and command-position shape that normalisation deliberately does not
//! retain, by the structural gate (`src/gate.rs`, B4) directly.

/// Shared nesting-depth cap for brace-alternation (`{`/`}`) and
/// command-substitution (`(`/`)`) recursion, enforced independently by
/// `src/parser.rs`'s raw pre-scan and AST-level depth cap and by
/// `src/normalize.rs`'s `expand_braces` recursion (issue #52).
///
/// Placed here rather than in either consuming module because both
/// `parser` and `normalize` already depend on `ast`, and sharing one
/// constant across the two layers avoids a new `parser` -> `normalize`
/// dependency that keeping it in either module would create.
///
/// # Why 64
///
/// Real brace nesting rarely exceeds 2-3 levels; one nesting level costs
/// roughly 3KB of raw input (measured: `{a,`x3000 is the crash threshold on
/// an 8MiB main-thread stack, so ~1 level per ~3KB), so 64 levels is a ~10x
/// safety margin over the ~600-level budget `cargo test`'s 2MiB test-thread
/// stack allows — comfortably clear of both the tested-safe range and any
/// realistic legitimate nesting. This measurement is tied to `brush-parser
/// =0.4.0`'s specific recursion cost and the OS-default 8MiB main-thread
/// stack (not a Rust guarantee — `ulimit -s` or a musl target can shrink
/// it): re-measure the crash threshold before raising this cap on any
/// `brush-parser` version bump. It intentionally matches
/// `normalize::MAX_BRACE_ALTERNATIVES` (also 64) rather than
/// `gate::MAX_SUBSTITUTION_DEPTH` (8): the latter is an *analysis* recursion
/// depth (each level re-evaluates a whole pipeline through the gate), while
/// this is cheap *structural* recursion (descending into an AST/text shape).
/// A cap as tight as 8 risks a false Ask when the raw scanner over-counts
/// (e.g. `{`/`(` occurring inside a quoted string it does not parse
/// quoting out of); 64 tolerates that over-count while still capping actual
/// unbounded recursion.
///
/// # Known trade-off
///
/// The raw pre-scan in `src/parser.rs::parse` counts every `{`/`}`/`(`/`)`
/// byte in the input, including ones inside quotes (e.g. a deeply nested
/// JSON literal passed as a shell argument). Such input can hit this cap
/// and fail closed to `Ask` even though it is not itself a nesting attack —
/// an accepted false-positive cost of a scan that is deliberately linear
/// and non-recursive (the only correctness property that matters for a
/// stack-overflow defense).
pub(crate) const MAX_BRACE_NESTING_DEPTH: usize = 64;

/// Cap on the total count of reserved-word compound-command openers (`if`,
/// `while`, `until`, `for`, `case`) `src/parser.rs`'s raw pre-scan tolerates
/// in one command, enforced by [`crate::parser::reject_excessive_raw_nesting`]
/// (issue #52 follow-up: brush-parser's recursive-descent grammar recurses
/// once per nested compound command exactly as unboundedly as it does per
/// nested brace/paren, and none of these five keywords involve a `{`/`(`
/// character the existing [`MAX_BRACE_NESTING_DEPTH`] scan would catch).
///
/// Live-probed thresholds against `brush-parser =0.4.0`, on an 8MiB
/// main-thread stack: `case` aborts first at 401 levels, `for` at 420,
/// `until` at 446, `if` at 448 (`while` confirmed aborting by 2000). But
/// per-level cost here is far higher than brace/paren nesting's ~3KB
/// ([`MAX_BRACE_NESTING_DEPTH`]'s docs) — re-bisected under a 2MiB stack
/// (`ulimit -s 2048`, matching `cargo test`'s per-test thread budget, the
/// same target [`MAX_BRACE_NESTING_DEPTH`] is sized against): `case` aborts
/// there at 99 levels, `if` at 110. An earlier version of this cap (128)
/// was sized only against the 8MiB thresholds and **overflowed `cargo
/// test`'s own thread** the first time its own boundary test ran — this
/// value must clear the 2MiB budget, not just the main-thread one. 8 sits a
/// ~12x margin below the lowest 2MiB threshold found (`case`'s 99),
/// comfortably exceeding [`MAX_BRACE_NESTING_DEPTH`]'s own ~10x bar; this is
/// a *count*, not a *depth*, so 8 is also generous headroom over any
/// realistic legitimate use of these keywords — shguard's AST does not
/// model any of these five as a compound command at all, so a single
/// occurrence of any of them already always resolves to
/// `Unsupported`/`Ask` regardless of this cap, and there is no
/// false-positive cost to weigh against a tight value here. Re-measure both
/// the 8MiB and 2MiB thresholds before raising this on any `brush-parser`
/// version bump, same as [`MAX_BRACE_NESTING_DEPTH`].
///
/// `select` and `[[ … ]]` were probed too and excluded: brush-parser rejects
/// both with an immediate syntax error rather than recursing on them, so
/// they are not a stack-overflow vector at all. `function` is also excluded
/// deliberately: its body is a brace group, so its recursion is already
/// bounded by [`MAX_BRACE_NESTING_DEPTH`] and counting the keyword itself
/// would only add false positives with no additional safety.
///
/// # Why a total count, not a balanced depth like [`MAX_BRACE_NESTING_DEPTH`]
///
/// A `{`/`}`/`(`/`)` depth counter that decrements on the closing character
/// is safe because a bare closer in argument position (e.g. `echo }`) is
/// either a shell syntax error or breaks the nesting it would need to fake —
/// live-confirmed. The same is not true of keyword closers: `echo fi` and
/// `echo done` are ordinary, valid arguments (live-confirmed to resolve
/// normally), so a decrementing counter keyed on the words `fi`/`done`/`esac`
/// could be driven back down by injecting those words as arguments inside
/// genuinely-nested input that still recurses past the crash threshold —
/// live-confirmed: `("if true; then echo fi; " x 2000) + "echo done" + ("
/// fi" x 2000)` still aborts even though a naive decrementing counter reads
/// its `fi` count as balanced against its `if` count throughout. Counting
/// only openers, and never decrementing, has no closer for an attacker to
/// inject against: the count can only ever overestimate true nesting depth
/// (safe direction — an inflated count fails closed to `Ask` earlier, never
/// later), never underestimate it.
pub(crate) const MAX_KEYWORD_NESTING_COUNT: usize = 8;

/// A separator joining two [`Pipeline`]s in a [`CommandLine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Separator {
    /// `;`
    Sequence,
    /// `&&`
    And,
    /// `||`
    Or,
}

/// A full command line: one pipeline, optionally followed by more pipelines
/// joined by separators.
///
/// Modelled as `first` + `rest` (a non-empty list), not two parallel `Vec`s,
/// so "zero pipelines" and "one fewer separator than pipeline" are not
/// representable — the plain-`Vec` encoding would allow both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandLine {
    pub(crate) first: Pipeline,
    pub(crate) rest: Vec<(Separator, Pipeline)>,
}

/// A pipeline: one or more [`SimpleCommand`]s connected by `|`.
///
/// Modelled as `first` + `rest` for the same non-empty-list reason as
/// [`CommandLine`]: a pipeline can never have zero commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pipeline {
    pub(crate) first: SimpleCommand,
    pub(crate) rest: Vec<SimpleCommand>,
}

/// A single simple command: leading assignments, words (the command name and
/// its arguments), and redirections. Unlike `CommandLine`/`Pipeline`, all
/// three lists may legitimately be empty on their own (e.g. `> file` is a
/// valid simple command with zero words and zero assignments), so this stays
/// a plain struct of `Vec`s rather than a non-empty-list encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SimpleCommand {
    pub(crate) assignments: Vec<Assignment>,
    pub(crate) words: Vec<Word>,
    pub(crate) redirections: Vec<Redirection>,
}

/// A `NAME=value` assignment preceding (or standing in place of) a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assignment {
    pub(crate) name: String,
    pub(crate) value: Word,
}

/// A redirection attached to a simple command (`>`, `<`, `>>`, a heredoc, …).
///
/// A sum type rather than one struct with optional fields: a file
/// redirection has a target word and no body; a heredoc has a body and no
/// filename target. Optional fields on a single struct would make all four
/// combinations representable when only two are ever valid — the ADR's
/// heredoc fixtures (docs/adr/0001-parser-crate.md rows 7-9) specifically
/// need the body to survive into the AST, so `Redirection` must not be able
/// to hold a `HereDoc` variant with no body, the way an `Option<String>`
/// field would allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Redirection {
    /// `<`, `>`, or `>>` with a target word (a filename, itself subject to
    /// the same word-piece expansions as any other word).
    File {
        kind: FileRedirectionKind,
        target: Word,
    },
    /// `<<` (or `<<-` when `strip_leading_tabs` is set).
    ///
    /// The delimiter itself (`EOF` in `<<EOF`) has no analytical value once
    /// parsing is done — it only serves to find the terminating line — so
    /// it is dropped rather than carried in this type; only what it implies
    /// (`expand_body`) is kept.
    HereDoc {
        strip_leading_tabs: bool,
        /// `false` when the delimiter was quoted (`<<'EOF'`): bash performs
        /// no parameter/command-substitution expansion on the body in that
        /// case, so ADR row 9's `$(rm -rf /)` inside a quoted-delimiter
        /// heredoc must stay inert literal text rather than being
        /// interpreted as a substitution. `true` for an unquoted delimiter
        /// (`<<EOF`), where the body is subject to expansion.
        expand_body: bool,
        /// The heredoc body, raw and un-decoded.
        ///
        /// `String`, not `Word`: when `expand_body` is `false` the body is
        /// definitionally literal text (bash performs no expansion on it
        /// at all), so `Word`'s piece structure would model nothing that
        /// isn't already a single `Literal`. When `expand_body` is `true`
        /// the body is still multi-line raw text that gets parsed and
        /// word-split per line in the normalise stage, not as one `Word`
        /// value — the parser adapter (a later issue) re-examines this raw
        /// string then, rather than this type pre-committing to a `Word`
        /// shape that doesn't fit a multi-line body.
        body: String,
    },
}

/// The kind of a plain file redirection, per the ADR's redirection fixture
/// (row 18: `echo x > /dev/null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileRedirectionKind {
    /// `<`
    Input,
    /// `>`
    Output,
    /// `>>`
    Append,
}

/// A shell word: a sequence of [`WordPiece`]s. Kept as a sequence rather than
/// a single string so quote/expansion boundaries survive into the normalise
/// stage — the whole point of the parser-crate selection (ADR 0001):
/// `r''m` must stay `[Literal("r"), SingleQuoted(""), Literal("m")]`, never
/// pre-joined into `"rm"` before shguard's own fold decides that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word(pub(crate) Vec<WordPiece>);

/// One piece of a [`Word`], mirroring the granularity the selected parser
/// crate exposes (docs/adr/0001-parser-crate.md's evidence excerpts) —
/// expressed as shguard's own type, not that crate's `WordPiece`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WordPiece {
    /// Unquoted literal text.
    Literal(String),
    /// Single-quoted text, quotes already stripped, contents un-decoded.
    SingleQuoted(String),
    /// ANSI-C-quoted text (`$'...'`), raw un-decoded contents — hex/octal/
    /// control-escape decoding happens in the normalise stage.
    AnsiCQuoted(String),
    /// A double-quoted sequence: the pieces that appear between `"` `"`,
    /// e.g. literal text mixed with parameter expansions.
    DoubleQuoted(Vec<WordPiece>),
    /// `$NAME` / `${NAME}` — the parameter name only.
    ParameterExpansion(String),
    /// `$(...)` — the raw, unparsed inner command string.
    CommandSubstitution(String),
    /// `` `...` `` — the raw, unparsed inner command string.
    BackquotedSubstitution(String),
    /// `~` or `~user`, the raw text after `~` (empty for the current user).
    Tilde(String),
    /// `{a,b,c}` — each alternative as its own [`Word`].
    BraceAlternation(Vec<Word>),
    /// A backslash-escaped character, e.g. `\ ` inside an otherwise
    /// unquoted word.
    EscapeSequence(char),
}
