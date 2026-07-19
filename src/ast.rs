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
