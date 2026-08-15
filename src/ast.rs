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
/// there at 99 levels, `if` at 110. This value must clear the 2MiB budget,
/// not just the main-thread one. 16 sits a
/// ~6x margin below the lowest 2MiB threshold found (`case`'s 99), still
/// comfortably exceeding [`MAX_BRACE_NESTING_DEPTH`]'s own ~10x bar; this is
/// a *count*, not a *depth*, so 16 is also generous headroom over any
/// realistic legitimate use of these keywords. Re-measure both the 8MiB and
/// 2MiB thresholds before raising this on any `brush-parser` version bump,
/// same as [`MAX_BRACE_NESTING_DEPTH`].
///
/// # Why 16, not 8 (issue #75)
///
/// `for`/`while`/`until` are now modeled as real [`Command::Compound`]
/// variants (issue #75) — a single occurrence of one of them no longer
/// automatically resolves to `Unsupported`/`Ask` regardless of this cap the
/// way it used to when this cap was first sized at 8. That earlier sizing's
/// "no false-positive cost to weigh" premise was already only true for
/// *syntactic* keyword use, though: [`crate::parser::reject_excessive_raw_nesting`]
/// counts raw bytes with no quote awareness, so a command whose *text*
/// happens to contain the words `for`/`if`/`while`/`case`/`until` several
/// times — a `git commit -m "..."` message being the clearest real example —
/// was always able to trip this cap even though nothing is actually nested.
/// Modeling `for`/`while`/`until` doesn't create that false-positive class,
/// but it does raise the stakes of it: a real, legitimate one-liner chaining
/// a couple of loops plus an `if` (still unmodeled, still hard-Asks on its
/// own first use) can now sit closer to this budget than "always Ask
/// anyway" made it matter before. Doubling to 16 keeps a healthy margin
/// under the probed 2MiB-stack abort floor (`case`'s 99) while giving that
/// realistic multi-loop one-liner — and the quoted-text false-count above —
/// more headroom than 8 did.
///
/// `select` and `[[ … ]]` were probed too and excluded: brush-parser rejects
/// both with an immediate syntax error rather than recursing on them, so
/// they are not a stack-overflow vector at all. `function` is also excluded
/// deliberately: its body is a brace group, so its recursion is already
/// bounded by [`MAX_BRACE_NESTING_DEPTH`] and counting the keyword itself
/// would only add false positives with no additional safety.
///
/// # `if` is now modeled too (issue #191)
///
/// `if`/`elif` clauses are [`Command::Compound`] variants as of issue #191,
/// the same way `for`/`while`/`until` became one under issue #75 — a single
/// `if` no longer automatically resolves to `Unsupported`/`Ask` regardless
/// of this cap either. This does not change the cap's own sizing rationale
/// above (still measured against `case`'s 99-level 2MiB-stack abort floor,
/// still a 6x margin): `case` — the tightest keyword — remains entirely
/// unmodeled (zero measured occurrences per issue #75/#191's traffic
/// samples), so it alone still keeps this cap's "no false-positive cost"
/// premise from ever mattering for that specific keyword, and 16 was
/// already sized with `if`/`while`/`until`/`for` all being real, evaluated
/// constructs in mind.
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
pub(crate) const MAX_KEYWORD_NESTING_COUNT: usize = 16;

/// A separator joining two [`Pipeline`]s in a [`CommandLine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Separator {
    /// `;`
    Sequence,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `&` (issue #191): backgrounds the pipeline to its left, but that
    /// pipeline still runs — `crate::gate::evaluate_command_line` already
    /// folds every separator identically (worst-wins across the whole
    /// line, regardless of `;`/`&&`/`||`), so `Async` needs no special
    /// handling there; it exists purely so `src/parser.rs` can stop
    /// rejecting the syntax outright.
    Async,
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

/// A pipeline: one or more [`Command`]s connected by `|`.
///
/// Modelled as `first` + `rest` for the same non-empty-list reason as
/// [`CommandLine`]: a pipeline can never have zero commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pipeline {
    pub(crate) first: Command,
    pub(crate) rest: Vec<Command>,
}

/// One command in a [`Pipeline`]: an ordinary simple command, a compound
/// command (issue #75: `for`/`while`/`until`/subshell/brace group;
/// issue #191 added `if`), a function definition (issue #75), or an
/// extended test command (issue #191: `[[ ... ]]`).
///
/// A sum type rather than folding compound commands and function
/// definitions into `SimpleCommand` itself: the four have almost nothing in
/// common structurally (a compound command has a nested [`CommandLine`]
/// body instead of `words`; a function definition has a name and a body but
/// no argv at all; an extended test has test operands that are not argv at
/// all — see [`ExtendedTest`]'s own docs), so a single struct with optional
/// fields for all four shapes would make invalid combinations (a
/// `SimpleCommand` with a `body`, a `ForClause` with `words: Vec<Word>` in
/// the argv sense) representable when they should not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Simple(SimpleCommand),
    Compound(CompoundCommand),
    FunctionDefinition(FunctionDefinition),
    ExtendedTest(ExtendedTest),
}

/// `[[ ... ]]` (issue #191): an extended test expression. shguard does not
/// model the expression's own boolean structure (`&&`/`||`/`!`/parens
/// inside the brackets, or which unary/binary predicate each operand pairs
/// with) — none of that changes what actually executes. It only keeps every
/// operand as a [`Word`] for `crate::gate`'s expansion-position scan
/// (`scan_word_expansions`), exactly the treatment a `for` clause's `in`
/// word list or an array assignment's elements already get (issue #75).
///
/// This is a deliberate choice, not an approximation of a fuller model:
/// `[[ ]]`'s operands are never command words — bash performs no
/// word-splitting or globbing on them (unlike a `SimpleCommand`'s `words`)
/// — so treating them as an argv the way `SimpleCommand` does would be a
/// false-positive risk with no safety benefit (`[[ -d /tmp/x ]]` is not the
/// command `-d /tmp/x`, and matching it against blocklist rules that expect
/// a real command name in position 0 would be nonsensical). But an operand
/// CAN still hide a command substitution (`[[ -n $(rm -rf /) ]]`), which is
/// exactly what the expansion scan catches; treating the whole construct as
/// opaque (skip it entirely, the pre-#191 behavior) would silently miss
/// that. brush-parser already hands operands over as structural [`Word`]s
/// (`bast::ExtendedTestExpr::UnaryTest`/`BinaryTest`), not raw strings, so
/// nothing is lost by extracting them this way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtendedTest {
    pub(crate) words: Vec<Word>,
    pub(crate) redirections: Vec<Redirection>,
}

/// A compound command (issue #75): `for`/`while`/`until`, a subshell, or a
/// brace group, each carrying its own nested [`CommandLine`] body (and, for
/// `while`/`until`, a condition `CommandLine` evaluated before each
/// iteration) plus any redirections attached to the compound command as a
/// whole (`for i in 1; do echo x; done > /dev/null` attaches the redirect to
/// the loop, not to `echo`).
///
/// `BraceGroup` and `Subshell` get identical treatment everywhere shguard's
/// gate evaluates them, with one exception (issue #103): a `BraceGroup`'s
/// folded-cwd context (`crate::gate::CwdContext`) is threaded through by
/// mutable reference, so a `cd` inside one persists into the enclosing
/// scope, while a `Subshell`'s is a throwaway clone whose mutations never
/// escape — this is the one place the difference between "runs in a
/// subshell" and "runs in the current shell" IS meaningful, since a real
/// `cd`'s effect on the working directory is exactly that distinction.
/// Otherwise the difference isn't meaningful to a static, non-executing
/// analyzer that already gives every recursed body its own fresh
/// environment (see `crate::gate`'s module docs). `BraceGroup` exists as its
/// own variant (rather than being folded into `Subshell`) only because
/// [`FunctionDefinition`]'s body is a brace group in virtually every real
/// function, and keeping the two syntactically distinct mirrors
/// brush-parser's own `CompoundCommand` shape.
///
/// Deliberately excludes `case` clauses, C-style arithmetic `for`, bare
/// `((...))` arithmetic commands, and coprocesses — none of these were
/// measured in issue #75's or #191's traffic samples, so they stay exactly
/// as unsupported (translate-error, `Ask`) as before this change. `if`
/// clauses (with `elif`/`else`) were added by issue #191, following the
/// same "measured in real traffic" bar #75 set.
///
/// `body`/`condition` are `Box<CommandLine>`, not a bare `CommandLine`:
/// `CommandLine` -> `Pipeline` -> `Command` -> `CompoundCommand` ->
/// `CommandLine` is a recursive type with no fixed size without some
/// indirection breaking the cycle, and this is the one point in it that
/// needs boxing (`Command::Compound`/`Pipeline::first` stay unboxed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompoundCommand {
    BraceGroup {
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    Subshell {
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    ForClause {
        variable: String,
        /// The `in ...` word list. `None` when the `for` clause omits the
        /// `in` entirely (bash then iterates `"$@"`) — kept distinct from
        /// `Some(vec![])` (an explicit, empty `in` list, which iterates zero
        /// times) rather than collapsing both to one representation.
        words: Option<Vec<Word>>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    WhileClause {
        condition: Box<CommandLine>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    UntilClause {
        condition: Box<CommandLine>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    /// `if COND; then BODY [elif COND; then BODY]... [else BODY] fi` (issue
    /// #191). `elifs`/`else_body` split brush-parser's own
    /// `Option<Vec<ElseClause>>` shape (each entry either an `elif` with a
    /// condition or a trailing plain `else` with none — see
    /// `src/parser.rs::convert_if_clause`'s docs) into the two forms
    /// shguard's own grammar actually has: zero or more conditional `elif`
    /// arms, followed by at most one unconditional `else`.
    ///
    /// shguard cannot know statically which branch runs, so
    /// `crate::gate::evaluate_compound_command` evaluates `condition`,
    /// `then_body`, every `elifs` condition/body, and `else_body` (when
    /// present) and folds all of them worst-wins — the same
    /// evaluate-every-branch stance already used for `WhileClause`/
    /// `UntilClause`'s condition-plus-body pair.
    IfClause {
        condition: Box<CommandLine>,
        then_body: Box<CommandLine>,
        elifs: Vec<ElifClause>,
        else_body: Option<Box<CommandLine>>,
        redirections: Vec<Redirection>,
    },
}

/// One `elif COND; then BODY` arm of an [`CompoundCommand::IfClause`] (issue
/// #191).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElifClause {
    pub(crate) condition: Box<CommandLine>,
    pub(crate) body: Box<CommandLine>,
}

/// A function definition (issue #75): `name() { ...; }` (or the `function`
/// keyword form). shguard evaluates the body eagerly at the definition site
/// and folds its verdict worst-wins into the definition's own — it does
/// **not** track the function name and inline it at call sites. Ignoring
/// the body entirely (parse the definition, evaluate nothing) would turn
/// `f() { rm -rf /; }; f` from an `Unsupported`/`Ask` line into a clean
/// `Allow` (an unknown, no-rule-match command defaults to `Allow` —
/// `crate::gate::fold_floors`), which is a deny-rule bypass, not a
/// documented gap. Eager body evaluation closes that without needing any
/// name-tracking or call-site resolution; the residual gap (a body that
/// only becomes dangerous once called with a specific argument, e.g.
/// `f() { rm -rf "$1"; }; f /`) already fails closed to `Ask` today via the
/// ordinary unresolved-argument floor, not `Allow`.
///
/// Has no `redirections` field of its own: `bast::FunctionBody`'s optional
/// redirect list (`f() { ...; } > log`) is exactly the same shape as
/// `bast::Command::Compound`'s own attached-redirect list, so
/// `src/parser.rs` folds it straight into `body`'s own `CompoundCommand`
/// variant (its `redirections` field) rather than duplicating it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionDefinition {
    pub(crate) name: Word,
    pub(crate) body: Box<CompoundCommand>,
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
    pub(crate) value: AssignmentValue,
}

/// The right-hand side of an [`Assignment`]: an ordinary scalar value, or
/// (issue #75) an array literal (`arr=(a b c)`). Kept as its own sum type
/// rather than always a `Vec<Word>` (a scalar is not "an array of one
/// element" — `NAME=` and `NAME=()` are observably different assignments in
/// bash) so the two remain distinguishable through normalisation and the
/// gate's expansion-position scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssignmentValue {
    Scalar(Word),
    Array(Vec<Word>),
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
    /// `<&` (issue #75). `target` is still a plain [`Word`] — brush-parser
    /// does not structurally distinguish a numeric fd/`-` target from a
    /// filename one here (`bast::IoFileRedirectTarget::Duplicate`'s own docs:
    /// "could be a filename, a file descriptor, or a file descriptor and a
    /// '-'"), so that distinction is made in `crate::gate` once the target
    /// has been resolved, not here.
    DuplicateInput,
    /// `>&` (issue #75). See [`FileRedirectionKind::DuplicateInput`]'s docs —
    /// same target ambiguity applies (`2>&1` vs. `>&/dev/sda`, which is a
    /// genuine file write bash treats identically to `> /dev/sda`).
    DuplicateOutput,
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
    /// `$((...))` (issue #75) — the raw, unparsed inner arithmetic text
    /// (`bword::ParameterExpr`'s `UnexpandedArithmeticExpr.value`). Raw, not
    /// a `Word`, for the same reason as [`WordPiece::CommandSubstitution`]:
    /// bash performs command substitution *inside* an arithmetic expression
    /// before evaluating it (`$(( $(rm -rf /) ))` really does run the `rm`),
    /// so `crate::gate` must re-scan this raw text for embedded `$(...)`/
    /// backtick substitutions the same way it already does for heredoc
    /// bodies, rather than treating the whole expression as inert.
    ArithmeticExpansion(String),
    /// `<(...)`/`>(...)` (issue #75) — process substitution. Unlike
    /// [`WordPiece::CommandSubstitution`], the inner command is **not** raw
    /// text: brush-parser already parses it into a structural command list
    /// (`bast::SubshellCommand`), so `body` is shguard's own already-parsed
    /// [`CommandLine`], not a string to re-parse. `Box`ed because
    /// `WordPiece` -> `CommandLine` -> ... -> `Word` -> `WordPiece` is
    /// otherwise a recursive type with no fixed size. Occupies exactly one
    /// [`Word`] position (bash expands `<(cmd)` to a single pathname-like
    /// token), so — like [`WordPiece::CommandSubstitution`] — it never needs
    /// a dedicated `SimpleCommand` field of its own: a bare process
    /// substitution argument becomes a single-piece `Word`, and one used as
    /// a redirect target becomes an ordinary [`Redirection::File`] target.
    ProcessSubstitution {
        direction: ProcessSubstitutionDirection,
        body: Box<CommandLine>,
    },
}

/// Whether a [`WordPiece::ProcessSubstitution`] reads from (`<(...)`) or
/// writes to (`>(...)`) the substituted command. Kept for fidelity/debug
/// output and future rule authoring even though it is not currently
/// security-relevant to shguard's own analysis (both directions recurse
/// through the same worst-wins evaluation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessSubstitutionDirection {
    /// `<(...)`
    Read,
    /// `>(...)`
    Write,
}
