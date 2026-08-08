//! Stage 1 of the pipeline (plan.md §1.1): a thin adapter over `brush-parser`
//! 0.4.0 (docs/adr/0001-parser-crate.md), converting its output into
//! shguard's own AST (`crate::ast`).
//!
//! `brush-parser` types (`brush_parser::ast::*`, `brush_parser::word::*`, …)
//! MUST NOT appear outside this module — that is the entire point of having
//! an adapter ("dependencies point inward", `coding-guidelines/principles.md`).
//! Everything below either returns a `crate::ast` value or a [`ParseError`].
//!
//! # What does not survive the conversion
//!
//! shguard's AST (`src/ast.rs`) is deliberately narrower than bash's full
//! grammar. Anything brush-parser parses that has no shape in shguard's AST
//! comes back as [`ParseError::Unsupported`] rather than being silently
//! dropped or approximated — never a panic, never a partial result.
//! Concretely, this module maps to `Unsupported`:
//!
//! - `if`/`case` clauses, C-style arithmetic `for`, bare `((...))` arithmetic
//!   commands, and coprocesses (issue #75: zero measured occurrences in real
//!   traffic, unlike the compound commands below — see `crate::ast::CompoundCommand`'s
//!   docs)
//! - `[[ ... ]]` extended test commands
//! - `&` background jobs (`SeparatorOperator::Async`)
//! - pipeline negation (`!`)
//! - here-strings (`<<<`) and `&>`/`&>>` combined stdout/stderr redirections
//! - redirection kinds shguard's `FileRedirectionKind` has no variant for
//!   (`<>` read-and-write, `>|` clobber) and fd-number (as opposed to a
//!   resolved fd-number *word*) redirect targets — see
//!   `convert_redirect_target`'s docs on why `Fd(_)` is unreachable in
//!   practice
//! - array-element assignment *targets* (`arr[0]=x`, as opposed to an array
//!   assignment *value*, `arr=(a b c)`, which issue #75 now supports)
//! - parameter expansions beyond a bare `$NAME`/`${NAME}`, a bare positional
//!   parameter (`$1`, `$2`, …), or a bare special parameter (`$?`, `$$`,
//!   `$!`, `$#`, `$@`, `$*`, `$-`, `$0`, issue #75) — indirection,
//!   array-indexed access, defaults, substring, case transforms, … —
//!   shguard's `WordPiece::ParameterExpansion` only has room for a bare
//!   name/index/special-character "name", so anything that would silently
//!   discard expansion semantics beyond that is rejected instead
//! - brace-expansion ranges (`{1..5}`, `{a..z}`) — shguard's
//!   `WordPiece::BraceAlternation` holds literal alternatives, not a range to
//!   enumerate
//!
//! Issue #75 additionally supports, having measured them as common
//! (`crate::ast::CompoundCommand`/`FunctionDefinition`/`WordPiece`'s own docs
//! cover the safety-relevant details of each): brace groups, subshells,
//! `for`/`while`/`until` clauses, function definitions, `time`-prefixed
//! pipelines, fd-duplication redirections (`2>&1`), array assignment values,
//! bare positional/special parameters (`$1`, `$?`, …),
//! arithmetic expansion (`$((...))`), and process substitution
//! (`<(...)`/`>(...)`).

use std::io::Cursor;

use brush_parser::word::{self as bword};
use brush_parser::{Parser as BrushParser, ParserOptions as BrushParserOptions, ast as bast};

use crate::ast::{
    Assignment, AssignmentValue, Command, CommandLine, CompoundCommand, FileRedirectionKind,
    FunctionDefinition, MAX_BRACE_NESTING_DEPTH, MAX_KEYWORD_NESTING_COUNT, Pipeline,
    ProcessSubstitutionDirection, Redirection, Separator, SimpleCommand, Word, WordPiece,
};

/// Everything that can go wrong converting a raw command string into
/// shguard's AST.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseError {
    /// The input is not valid shell syntax at all — brush-parser rejected it
    /// outright, or the parsed shape was degenerate (e.g. an empty pipeline).
    #[error("syntax error: {message}")]
    Syntax {
        /// A human-readable description of what failed to parse.
        message: String,
    },
    /// The input parsed, but into a brush-parser AST node shguard's AST
    /// cannot represent. See the module docs for the full list.
    #[error("unsupported construct: {construct}")]
    Unsupported {
        /// A human-readable description of the unsupported construct.
        construct: String,
    },
}

impl ParseError {
    fn syntax(message: impl Into<String>) -> Self {
        Self::Syntax {
            message: message.into(),
        }
    }

    fn unsupported(construct: impl Into<String>) -> Self {
        Self::Unsupported {
            construct: construct.into(),
        }
    }
}

fn parser_options() -> BrushParserOptions {
    BrushParserOptions::default()
}

/// Reserved words that introduce a compound command brush-parser recurses
/// into, counted (never decremented) by [`reject_excessive_raw_nesting`] —
/// see [`MAX_KEYWORD_NESTING_COUNT`]'s docs for why a total count, and why
/// this exact set.
const NESTING_KEYWORDS: [&str; 5] = ["if", "while", "until", "for", "case"];

/// Byte values [`reject_excessive_raw_nesting`] treats as ending a keyword
/// token: whitespace and the shell metacharacters that can immediately
/// follow a reserved word without an intervening space (e.g. `if;`,
/// `for(`). Splitting on these — not only on whitespace — is what keeps the
/// keyword count from *under*-counting a keyword glued to a metacharacter;
/// under-counting is the unsafe direction (see [`MAX_KEYWORD_NESTING_COUNT`]).
/// All are single-byte ASCII, so, like the bracket scan below, no UTF-8
/// continuation byte can be mistaken for one and every split point this
/// produces is a valid `str` boundary.
fn is_token_boundary(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | b'\r' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
    )
}

/// Rejects `command` if its `{`/`}` nesting depth, its `(`/`)` nesting
/// depth, or its total count of [`NESTING_KEYWORDS`] occurrences exceeds
/// [`MAX_BRACE_NESTING_DEPTH`] / [`MAX_KEYWORD_NESTING_COUNT`], *before* any
/// recursive-descent parser (brush-parser's PEG grammar, or this module's
/// own brace/word conversion) ever sees the text.
///
/// This is the primary defense against issue #52's abort: deeply nested
/// `{`/`(` input (e.g. `{a,` repeated thousands of times, or `$(` repeated
/// thousands of times), or deeply nested `if`/`while`/`until`/`for`/`case`
/// compound commands, crash with a stack overflow *inside brush-parser's
/// own PEG grammar* — its mutually recursive descent has no depth limit of
/// its own, for either kind of nesting — before shguard's AST-level depth
/// cap (`convert_brace_segment`/`convert_brace_members` in this module,
/// `normalize::expand_braces`) ever gets a chance to run, because those
/// only see brush-parser's *output*. A crash there is an uncatchable abort
/// (`std::panic::catch_unwind` cannot intercept a stack overflow — see
/// `src/bin/shguard.rs`'s module docs), so the only effective defense is a
/// linear, non-recursive pre-scan that runs ahead of the parser and rejects
/// the input outright. All three counters are tracked in one pass (`{`/`}`
/// alone would miss a `$(`-only attack, which was independently confirmed
/// to abort even though it never touches shguard's AST-level brace cap at
/// all, and neither bracket alone catches a keyword-only attack like nested
/// `if`/`then`/`fi` with no braces or parens at all) — see
/// [`MAX_BRACE_NESTING_DEPTH`]'s and [`MAX_KEYWORD_NESTING_COUNT`]'s docs
/// for the chosen cap values and their trade-offs.
///
/// Scans bytes, not `char`s: every byte this function compares against
/// (`{`, `}`, `(`, `)`, and every [`is_token_boundary`] delimiter) is
/// single-byte ASCII, and no UTF-8 continuation byte (`0x80..=0xBF`) can
/// equal one of them, so counting and slicing on raw bytes is exact for any
/// valid UTF-8 input and avoids paying for UTF-8 decoding on a hot,
/// security-critical scan.
fn reject_excessive_raw_nesting(command: &str) -> Result<(), ParseError> {
    let mut brace_depth: usize = 0;
    let mut paren_depth: usize = 0;
    let mut keyword_count: usize = 0;
    let mut token_start: Option<usize> = None;

    let bytes = command.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => {
                brace_depth += 1;
                if brace_depth > MAX_BRACE_NESTING_DEPTH {
                    return Err(ParseError::unsupported(
                        "brace nesting exceeds the raw depth cap",
                    ));
                }
            }
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => {
                paren_depth += 1;
                if paren_depth > MAX_BRACE_NESTING_DEPTH {
                    return Err(ParseError::unsupported(
                        "parenthesis nesting exceeds the raw depth cap",
                    ));
                }
            }
            b')' => paren_depth = paren_depth.saturating_sub(1),
            _ => {}
        }

        if is_token_boundary(byte) {
            if let Some(start) = token_start.take() {
                check_keyword_token(&command[start..i], &mut keyword_count)?;
            }
        } else if token_start.is_none() {
            token_start = Some(i);
        }
    }
    if let Some(start) = token_start {
        check_keyword_token(&command[start..], &mut keyword_count)?;
    }

    Ok(())
}

/// Increments `keyword_count` if `token` is one of [`NESTING_KEYWORDS`],
/// rejecting once the running total exceeds [`MAX_KEYWORD_NESTING_COUNT`].
/// Split out of [`reject_excessive_raw_nesting`] only to run once per
/// completed token and once more for the trailing token at end-of-input,
/// without duplicating the check-and-increment logic at both call sites.
fn check_keyword_token(token: &str, keyword_count: &mut usize) -> Result<(), ParseError> {
    if NESTING_KEYWORDS.contains(&token) {
        *keyword_count += 1;
        if *keyword_count > MAX_KEYWORD_NESTING_COUNT {
            return Err(ParseError::unsupported(
                "compound-command keyword nesting exceeds the raw count cap",
            ));
        }
    }
    Ok(())
}

/// Parses a raw shell command line into shguard's AST.
///
/// # Errors
///
/// Returns [`ParseError::Syntax`] if `command` is not valid shell syntax, or
/// [`ParseError::Unsupported`] if it parses but contains a construct
/// shguard's AST cannot represent (see the module docs), including raw
/// `{`/`}`/`(`/`)` nesting past [`MAX_BRACE_NESTING_DEPTH`] or
/// [`NESTING_KEYWORDS`] nesting past [`MAX_KEYWORD_NESTING_COUNT`]
/// ([`reject_excessive_raw_nesting`]).
///
/// `analyze()` (`src/lib.rs`) calls this via `src/gate.rs` — stage 1 of the
/// pipeline (plan.md §1.1).
pub(crate) fn parse(command: &str) -> Result<CommandLine, ParseError> {
    reject_excessive_raw_nesting(command)?;

    let mut parser = BrushParser::new(Cursor::new(command.as_bytes()), &parser_options());
    let program = parser
        .parse_program()
        .map_err(|err| ParseError::syntax(err.to_string()))?;

    // brush-parser gives each newline-separated top-level command its own
    // `CompleteCommand`/`CompoundList` (verified empirically: `"a\nb"` yields
    // two `complete_commands`, `"a; b"` yields one with two items) — but
    // newline separation is semantically identical to `;` in bash, and real
    // agent commands are routinely multi-line (`cd x\ncargo test`). Rather
    // than special-case "one list" vs "many", every `CompoundListItem` from
    // every top-level list is concatenated into one logical sequence before
    // folding, so a trailing `&` is rejected wherever it appears (including
    // at a list boundary) exactly like within a single list.
    let items = program
        .complete_commands
        .iter()
        .flat_map(|complete_command| complete_command.0.iter());

    convert_compound_list(items)
}

/// Flattens a sequence of brush `CompoundListItem`s (nested as and/or-linked
/// pipelines, grouped by `;`/`&`-separated items — see [`parse`] for how
/// multiple top-level lists are concatenated into one such sequence) into
/// shguard's `CommandLine` (a flat first-pipeline-plus-separated-rest
/// sequence).
fn convert_compound_list<'a>(
    mut items: impl Iterator<Item = &'a bast::CompoundListItem>,
) -> Result<CommandLine, ParseError> {
    let first_item = items
        .next()
        .ok_or_else(|| ParseError::syntax("empty command list"))?;

    let first = convert_pipeline(&first_item.0.first)?;
    let mut rest = Vec::new();
    for and_or in &first_item.0.additional {
        rest.push(convert_and_or(and_or)?);
    }

    let mut pending_separator = convert_separator(&first_item.1)?;
    for item in items {
        let pipeline = convert_pipeline(&item.0.first)?;
        rest.push((pending_separator, pipeline));
        for and_or in &item.0.additional {
            rest.push(convert_and_or(and_or)?);
        }
        pending_separator = convert_separator(&item.1)?;
    }

    Ok(CommandLine { first, rest })
}

/// `SeparatorOperator::Async` (`&`) has no representation in shguard's
/// `Separator` — background jobs are an explicitly unsupported construct
/// (module docs).
fn convert_separator(sep: &bast::SeparatorOperator) -> Result<Separator, ParseError> {
    match sep {
        bast::SeparatorOperator::Sequence => Ok(Separator::Sequence),
        bast::SeparatorOperator::Async => Err(ParseError::unsupported("background job (&)")),
    }
}

fn convert_and_or(and_or: &bast::AndOr) -> Result<(Separator, Pipeline), ParseError> {
    match and_or {
        bast::AndOr::And(pipeline) => Ok((Separator::And, convert_pipeline(pipeline)?)),
        bast::AndOr::Or(pipeline) => Ok((Separator::Or, convert_pipeline(pipeline)?)),
    }
}

fn convert_pipeline(pipeline: &bast::Pipeline) -> Result<Pipeline, ParseError> {
    if pipeline.bang {
        return Err(ParseError::unsupported("pipeline negation (!)"));
    }
    // `time` (issue #75) only requests reporting the pipeline's execution
    // time — it changes no argv, no executed command, nothing the rule
    // engine cares about — so the flag is simply ignored rather than
    // rejected.

    let mut commands = pipeline.seq.iter();
    let first = commands
        .next()
        .ok_or_else(|| ParseError::syntax("empty pipeline"))?;
    let first = convert_command(first)?;
    let rest = commands.map(convert_command).collect::<Result<_, _>>()?;

    Ok(Pipeline { first, rest })
}

fn convert_command(command: &bast::Command) -> Result<Command, ParseError> {
    match command {
        bast::Command::Simple(simple) => Ok(Command::Simple(convert_simple_command(simple)?)),
        bast::Command::Compound(compound, redirects) => Ok(Command::Compound(
            convert_compound_command(compound, redirects)?,
        )),
        bast::Command::Function(func) => Ok(Command::FunctionDefinition(
            convert_function_definition(func)?,
        )),
        bast::Command::ExtendedTest(_, _) => {
            Err(ParseError::unsupported("extended test command ([[ ]])"))
        }
    }
}

/// Converts the subset of `bast::CompoundCommand` shguard's AST can
/// represent (module docs: brace group, subshell, `for`/`while`/`until`)
/// into shguard's own [`CompoundCommand`], attaching `redirects` (the
/// compound command's own redirect list, e.g. `for i in 1; do :; done >
/// /dev/null`) uniformly across every variant. Every other variant is
/// unsupported (module docs), via [`describe_compound`].
fn convert_compound_command(
    compound: &bast::CompoundCommand,
    redirects: &Option<bast::RedirectList>,
) -> Result<CompoundCommand, ParseError> {
    let redirections = convert_redirect_list(redirects)?;
    match compound {
        bast::CompoundCommand::BraceGroup(group) => Ok(CompoundCommand::BraceGroup {
            body: Box::new(convert_compound_list(group.list.0.iter())?),
            redirections,
        }),
        bast::CompoundCommand::Subshell(subshell) => Ok(CompoundCommand::Subshell {
            body: Box::new(convert_compound_list(subshell.list.0.iter())?),
            redirections,
        }),
        bast::CompoundCommand::ForClause(for_clause) => {
            let words = for_clause
                .values
                .as_ref()
                .map(|words| words.iter().map(convert_word).collect::<Result<_, _>>())
                .transpose()?;
            Ok(CompoundCommand::ForClause {
                variable: for_clause.variable_name.clone(),
                words,
                body: Box::new(convert_compound_list(for_clause.body.list.0.iter())?),
                redirections,
            })
        }
        bast::CompoundCommand::WhileClause(while_clause) => Ok(CompoundCommand::WhileClause {
            condition: Box::new(convert_compound_list(while_clause.0.0.iter())?),
            body: Box::new(convert_compound_list(while_clause.1.list.0.iter())?),
            redirections,
        }),
        bast::CompoundCommand::UntilClause(until_clause) => Ok(CompoundCommand::UntilClause {
            condition: Box::new(convert_compound_list(until_clause.0.0.iter())?),
            body: Box::new(convert_compound_list(until_clause.1.list.0.iter())?),
            redirections,
        }),
        bast::CompoundCommand::Arithmetic(_)
        | bast::CompoundCommand::ArithmeticForClause(_)
        | bast::CompoundCommand::CaseClause(_)
        | bast::CompoundCommand::IfClause(_)
        | bast::CompoundCommand::Coprocess(_) => {
            Err(ParseError::unsupported(describe_compound(compound)))
        }
    }
}

/// Converts a function definition (issue #75) by evaluating its body
/// eagerly rather than tracking the function's name for call-site inlining
/// — see [`FunctionDefinition`]'s docs for why eager evaluation is the
/// safety-load-bearing choice, not just a simplification.
fn convert_function_definition(
    func: &bast::FunctionDefinition,
) -> Result<FunctionDefinition, ParseError> {
    let name = convert_word(&func.fname)?;
    let body = convert_compound_command(&func.body.0, &func.body.1)?;
    Ok(FunctionDefinition {
        name,
        body: Box::new(body),
    })
}

fn convert_redirect_list(
    redirects: &Option<bast::RedirectList>,
) -> Result<Vec<Redirection>, ParseError> {
    redirects
        .iter()
        .flat_map(|list| list.0.iter())
        .map(convert_redirect)
        .collect()
}

fn describe_compound(compound: &bast::CompoundCommand) -> &'static str {
    match compound {
        bast::CompoundCommand::Arithmetic(_) => "arithmetic command ((...))",
        bast::CompoundCommand::ArithmeticForClause(_) => "arithmetic for clause",
        bast::CompoundCommand::BraceGroup(_) => "brace group ({ ... })",
        bast::CompoundCommand::Subshell(_) => "subshell ((...))",
        bast::CompoundCommand::ForClause(_) => "for clause",
        bast::CompoundCommand::CaseClause(_) => "case clause",
        bast::CompoundCommand::IfClause(_) => "if clause",
        bast::CompoundCommand::WhileClause(_) => "while clause",
        bast::CompoundCommand::UntilClause(_) => "until clause",
        bast::CompoundCommand::Coprocess(_) => "coprocess",
    }
}

fn convert_simple_command(simple: &bast::SimpleCommand) -> Result<SimpleCommand, ParseError> {
    let mut assignments = Vec::new();
    let mut words = Vec::new();
    let mut redirections = Vec::new();

    if let Some(prefix) = &simple.prefix {
        for item in &prefix.0 {
            apply_prefix_or_suffix_item(
                item,
                Position::Prefix,
                &mut assignments,
                &mut words,
                &mut redirections,
            )?;
        }
    }

    if let Some(word_or_name) = &simple.word_or_name {
        words.push(convert_word(word_or_name)?);
    }

    if let Some(suffix) = &simple.suffix {
        for item in &suffix.0 {
            apply_prefix_or_suffix_item(
                item,
                Position::Suffix,
                &mut assignments,
                &mut words,
                &mut redirections,
            )?;
        }
    }

    Ok(SimpleCommand {
        assignments,
        words,
        redirections,
    })
}

/// Whether a [`bast::CommandPrefixOrSuffixItem`] appears before or after the
/// command word — the distinction [`apply_prefix_or_suffix_item`] needs to
/// decide what an `AssignmentWord` item means (see that function's docs).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    Prefix,
    Suffix,
}

fn apply_prefix_or_suffix_item(
    item: &bast::CommandPrefixOrSuffixItem,
    position: Position,
    assignments: &mut Vec<Assignment>,
    words: &mut Vec<Word>,
    redirections: &mut Vec<Redirection>,
) -> Result<(), ParseError> {
    match item {
        bast::CommandPrefixOrSuffixItem::IoRedirect(redirect) => {
            redirections.push(convert_redirect(redirect)?);
        }
        bast::CommandPrefixOrSuffixItem::Word(word) => {
            words.push(convert_word(word)?);
        }
        // A `name=value`-shaped item is a real environment assignment only
        // in PREFIX position (`VAR=v cmd`) — bash scopes it to the command's
        // environment. The identical-looking shape in SUFFIX position
        // (`cmd VAR=v`, e.g. `dd if=x of=y` or `make foo=bar`) is an
        // ordinary argument to the command; bash never treats it as an
        // assignment there. brush-parser's grammar tags both the same way
        // (`AssignmentWord`), so the position this module already tracks is
        // what disambiguates them — routing a suffix assignment-shaped word
        // into `assignments` instead of `words` would make it vanish from
        // argv entirely (the word never reaches normalisation or the
        // blocklist), which is exactly how `dd if=/dev/zero of=/dev/sda`
        // dodged the `dd-write-device` rule before this fix. The raw word
        // (`bast::CommandPrefixOrSuffixItem::AssignmentWord`'s second field)
        // is converted the same way any other word would be.
        bast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, raw_word) => match position {
            Position::Prefix => assignments.push(convert_assignment(assignment)?),
            Position::Suffix => words.push(convert_word(raw_word)?),
        },
        bast::CommandPrefixOrSuffixItem::ProcessSubstitution(kind, subshell) => {
            words.push(convert_process_substitution(kind, subshell)?);
        }
    }
    Ok(())
}

/// Converts a process substitution (`<(cmd)`/`>(cmd)`, issue #75) into a
/// single-piece [`Word`] wrapping [`WordPiece::ProcessSubstitution`] — see
/// that variant's docs for why a single word piece is the right shape
/// (bash itself expands `<(cmd)` to exactly one argv-position token).
/// `subshell.list` is already a structural, parsed command list (not raw
/// text the way `$(...)` is), so it goes through the same
/// [`convert_compound_list`] every brace group/subshell/loop body does.
fn convert_process_substitution(
    kind: &bast::ProcessSubstitutionKind,
    subshell: &bast::SubshellCommand,
) -> Result<Word, ParseError> {
    let direction = match kind {
        bast::ProcessSubstitutionKind::Read => ProcessSubstitutionDirection::Read,
        bast::ProcessSubstitutionKind::Write => ProcessSubstitutionDirection::Write,
    };
    let body = convert_compound_list(subshell.list.0.iter())?;
    Ok(Word(vec![WordPiece::ProcessSubstitution {
        direction,
        body: Box::new(body),
    }]))
}

fn convert_assignment(assignment: &bast::Assignment) -> Result<Assignment, ParseError> {
    let name = match &assignment.name {
        bast::AssignmentName::VariableName(name) => name.clone(),
        bast::AssignmentName::ArrayElementName(..) => {
            return Err(ParseError::unsupported("array-element assignment"));
        }
    };
    let value = match &assignment.value {
        bast::AssignmentValue::Scalar(word) => AssignmentValue::Scalar(convert_word(word)?),
        bast::AssignmentValue::Array(items) => {
            // Each item is `(optional explicit index/key, value)` (issue
            // #75) — e.g. `arr=([2]=x y)` has one item with an index and
            // one without. Both the index and the value are ordinary words
            // that could themselves hide a substitution
            // (`arr[$(rm -rf /)]=x`), so both are flattened into one scan
            // list rather than only converting the value and silently
            // dropping the index — `AssignmentValue::Array` only exists for
            // `crate::gate`'s expansion-position scan, which doesn't need
            // the index/value pairing preserved, only every word present.
            let mut words = Vec::with_capacity(items.len());
            for (index, value) in items {
                if let Some(index) = index {
                    words.push(convert_word(index)?);
                }
                words.push(convert_word(value)?);
            }
            AssignmentValue::Array(words)
        }
    };
    Ok(Assignment { name, value })
}

fn convert_redirect(redirect: &bast::IoRedirect) -> Result<Redirection, ParseError> {
    match redirect {
        bast::IoRedirect::File(_fd, kind, target) => Ok(Redirection::File {
            kind: convert_file_redirect_kind(kind)?,
            target: convert_redirect_target(target)?,
        }),
        bast::IoRedirect::HereDocument(_fd, heredoc) => convert_heredoc(heredoc),
        bast::IoRedirect::HereString(_, _) => Err(ParseError::unsupported("here-string (<<<)")),
        bast::IoRedirect::OutputAndError(_, _) => Err(ParseError::unsupported(
            "combined stdout/stderr redirection (&>, &>>)",
        )),
    }
}

fn convert_file_redirect_kind(
    kind: &bast::IoFileRedirectKind,
) -> Result<FileRedirectionKind, ParseError> {
    match kind {
        bast::IoFileRedirectKind::Read => Ok(FileRedirectionKind::Input),
        bast::IoFileRedirectKind::Write => Ok(FileRedirectionKind::Output),
        bast::IoFileRedirectKind::Append => Ok(FileRedirectionKind::Append),
        bast::IoFileRedirectKind::DuplicateInput => Ok(FileRedirectionKind::DuplicateInput),
        bast::IoFileRedirectKind::DuplicateOutput => Ok(FileRedirectionKind::DuplicateOutput),
        bast::IoFileRedirectKind::ReadAndWrite | bast::IoFileRedirectKind::Clobber => Err(
            ParseError::unsupported(format!("redirection kind {kind:?}")),
        ),
    }
}

fn convert_redirect_target(target: &bast::IoFileRedirectTarget) -> Result<Word, ParseError> {
    match target {
        // `Duplicate`'s target (`2>&1`, `>&/dev/sda`) is converted exactly
        // like an ordinary filename target: brush-parser does not
        // structurally distinguish a numeric fd/`-` target from a filename
        // one here (`bast::IoFileRedirectTarget::Duplicate`'s own docs), so
        // that distinction is made in `crate::gate` once this word has been
        // resolved (issue #75).
        bast::IoFileRedirectTarget::Filename(word)
        | bast::IoFileRedirectTarget::Duplicate(word) => convert_word(word),
        // Never actually constructed by brush-parser's own grammar (no
        // production references it) — kept `Unsupported` only for
        // exhaustiveness.
        bast::IoFileRedirectTarget::Fd(_) => {
            Err(ParseError::unsupported("fd-duplication redirect target"))
        }
        bast::IoFileRedirectTarget::ProcessSubstitution(kind, subshell) => {
            convert_process_substitution(kind, subshell)
        }
    }
}

fn convert_heredoc(heredoc: &bast::IoHereDocument) -> Result<Redirection, ParseError> {
    Ok(Redirection::HereDoc {
        strip_leading_tabs: heredoc.remove_tabs,
        expand_body: heredoc.requires_expansion,
        body: heredoc.doc.value.clone(),
    })
}

/// Converts a raw brush `Word` (its source text) into shguard's `Word`,
/// splitting off brace alternations first (brush-parser exposes brace
/// expansion as a separate pre-pass, `word::parse_brace_expansions`, not as
/// a `WordPiece` variant of the ordinary word parse — see
/// docs/adr/0001-parser-crate.md's evidence for construct #15).
fn convert_word(word: &bast::Word) -> Result<Word, ParseError> {
    let raw = word.value.as_str();
    // Cheap pre-check (E2-6, issue #59): a word with no `{` at all — the
    // common case — can never contain a brace expansion, so skip the
    // brace-expansion pre-pass entirely and fall straight through to the
    // ordinary word parse below, rather than parsing the same text twice.
    // Purely a hot-path dedup: behavior for a `{`-containing word (valid
    // or malformed) is unchanged, since it still takes the exact same path
    // through `parse_brace_expansions` it always did.
    if !raw.contains('{') {
        return Ok(Word(convert_word_text(raw)?));
    }
    let brace_segments = bword::parse_brace_expansions(raw, &parser_options())
        .map_err(|err| ParseError::syntax(format!("brace-expansion parse of {raw:?}: {err}")))?;

    let has_brace_expr = brace_segments
        .as_ref()
        .is_some_and(|segments| segments.iter().any(is_brace_expr));

    if !has_brace_expr {
        return Ok(Word(convert_word_text(raw)?));
    }

    let mut pieces = Vec::new();
    for segment in brace_segments.into_iter().flatten() {
        pieces.extend(convert_brace_segment(segment, 0)?);
    }
    Ok(Word(pieces))
}

fn is_brace_expr(segment: &bword::BraceExpressionOrText) -> bool {
    matches!(segment, bword::BraceExpressionOrText::Expr(_))
}

/// Defense-in-depth companion to [`reject_excessive_raw_nesting`] (issue
/// #52): that raw pre-scan is the primary defense and already keeps `depth`
/// bounded by [`MAX_BRACE_NESTING_DEPTH`] in practice (brush-parser's own
/// brace pre-pass only ever nests as deep as the source text does), but this
/// cap is checked independently, at the point where *this module's own*
/// recursion happens, so a future change to the raw scan (or a gap in it)
/// cannot turn this mutual recursion into an unbounded one on its own.
/// `depth` starts at 0 from [`convert_word`] and increases by exactly one
/// per real nesting level: [`convert_brace_members`]'s `Child` arm is the
/// only place that increments (going one level deeper into a nested
/// brace's own segments) — the `Expr` arm below hands `depth` to
/// [`convert_brace_members`] unchanged, since unwrapping `Expr` into its
/// member list isn't itself a step deeper.
fn convert_brace_segment(
    segment: bword::BraceExpressionOrText,
    depth: usize,
) -> Result<Vec<WordPiece>, ParseError> {
    if depth > MAX_BRACE_NESTING_DEPTH {
        return Err(ParseError::unsupported(
            "brace nesting exceeds the AST depth cap",
        ));
    }
    match segment {
        bword::BraceExpressionOrText::Text(text) => convert_word_text(&text),
        // `depth`, not `depth + 1` (see this function's docs on why) —
        // incrementing here too would double-count each nesting level,
        // miscalibrating this cap to roughly half of
        // [`MAX_BRACE_NESTING_DEPTH`]'s intended 64-level threshold.
        bword::BraceExpressionOrText::Expr(members) => Ok(vec![WordPiece::BraceAlternation(
            convert_brace_members(members, depth)?,
        )]),
    }
}

/// See [`convert_brace_segment`]'s docs for why this depth cap exists
/// alongside the raw pre-scan.
fn convert_brace_members(
    members: Vec<bword::BraceExpressionMember>,
    depth: usize,
) -> Result<Vec<Word>, ParseError> {
    if depth > MAX_BRACE_NESTING_DEPTH {
        return Err(ParseError::unsupported(
            "brace nesting exceeds the AST depth cap",
        ));
    }
    members
        .into_iter()
        .map(|member| match member {
            bword::BraceExpressionMember::Child(inner) => {
                let mut pieces = Vec::new();
                for segment in inner {
                    pieces.extend(convert_brace_segment(segment, depth + 1)?);
                }
                Ok(Word(pieces))
            }
            bword::BraceExpressionMember::NumberSequence { .. }
            | bword::BraceExpressionMember::CharSequence { .. } => Err(ParseError::unsupported(
                "brace range expansion ({1..5} / {a..z})",
            )),
        })
        .collect()
}

/// Runs the ordinary (non-brace) word parse over a fragment of source text
/// and converts each resulting piece.
fn convert_word_text(text: &str) -> Result<Vec<WordPiece>, ParseError> {
    let pieces = bword::parse(text, &parser_options())
        .map_err(|err| ParseError::syntax(format!("word parse of {text:?}: {err}")))?;
    pieces
        .into_iter()
        .map(|piece| convert_word_piece(piece.piece))
        .collect()
}

fn convert_word_piece(piece: bword::WordPiece) -> Result<WordPiece, ParseError> {
    match piece {
        bword::WordPiece::Text(text) => Ok(WordPiece::Literal(text)),
        bword::WordPiece::SingleQuotedText(text) => Ok(WordPiece::SingleQuoted(text)),
        bword::WordPiece::AnsiCQuotedText(text) => Ok(WordPiece::AnsiCQuoted(text)),
        bword::WordPiece::DoubleQuotedSequence(inner)
        | bword::WordPiece::GettextDoubleQuotedSequence(inner) => {
            let pieces = inner
                .into_iter()
                .map(|p| convert_word_piece(p.piece))
                .collect::<Result<_, _>>()?;
            Ok(WordPiece::DoubleQuoted(pieces))
        }
        bword::WordPiece::TildeExpansion(tilde) => Ok(WordPiece::Tilde(convert_tilde(tilde))),
        bword::WordPiece::ParameterExpansion(expr) => convert_parameter_expansion(expr),
        bword::WordPiece::CommandSubstitution(inner) => Ok(WordPiece::CommandSubstitution(inner)),
        bword::WordPiece::BackquotedCommandSubstitution(inner) => {
            Ok(WordPiece::BackquotedSubstitution(inner))
        }
        bword::WordPiece::EscapeSequence(escape) => {
            let ch = escape
                .chars()
                .last()
                .ok_or_else(|| ParseError::syntax("empty escape sequence"))?;
            Ok(WordPiece::EscapeSequence(ch))
        }
        bword::WordPiece::ArithmeticExpression(expr) => {
            Ok(WordPiece::ArithmeticExpansion(expr.value))
        }
    }
}

fn convert_tilde(tilde: bword::TildeExpr) -> String {
    match tilde {
        bword::TildeExpr::Home => String::new(),
        bword::TildeExpr::UserHome(name) => name,
        bword::TildeExpr::WorkingDir => "+".to_string(),
        bword::TildeExpr::OldWorkingDir => "-".to_string(),
        bword::TildeExpr::NthDirFromTopOfDirStack { n, plus_used } => {
            format!("{}{n}", if plus_used { "+" } else { "" })
        }
        bword::TildeExpr::NthDirFromBottomOfDirStack { n } => format!("-{n}"),
    }
}

/// shguard's `WordPiece::ParameterExpansion` only carries the parameter
/// name (module docs) — only the plain `$NAME`/`${NAME}` form (a direct,
/// non-indirect named parameter), a bare positional parameter (`$1`, `$2`,
/// …), or a bare special parameter (`$?`, `$$`, `$!`, `$#`, `$@`, `$*`,
/// `$-`, `$0`, issue #75) maps onto it — all three are just as opaque/
/// unresolvable to this stage's static folding as a named variable is, and
/// `bword::SpecialParameter`'s own `Display` impl already produces exactly
/// the bare character (`?`, `-`, `$`, `!`, `#`, `@`, `*`, `0`) shguard wants
/// to store as the "name". Every other `ParameterExpr` shape (indirection,
/// array-indexed access, defaults, substring operations, case transforms,
/// …) would lose semantics if squeezed into a bare name, so it is rejected
/// instead.
fn convert_parameter_expansion(expr: bword::ParameterExpr) -> Result<WordPiece, ParseError> {
    match expr {
        bword::ParameterExpr::Parameter {
            parameter: bword::Parameter::Named(name),
            indirect: false,
        } => Ok(WordPiece::ParameterExpansion(name)),
        bword::ParameterExpr::Parameter {
            parameter: bword::Parameter::Positional(n),
            indirect: false,
        } => Ok(WordPiece::ParameterExpansion(n.to_string())),
        bword::ParameterExpr::Parameter {
            parameter: bword::Parameter::Special(special),
            indirect: false,
        } => Ok(WordPiece::ParameterExpansion(special.to_string())),
        other => Err(ParseError::unsupported(format!(
            "parameter expansion form {other:?}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse_ok(command: &str) -> CommandLine {
        match parse(command) {
            Ok(cmd) => cmd,
            Err(err) => panic!("expected {command:?} to parse, got {err:?}"),
        }
    }

    /// Unwraps a [`Command::Simple`], panicking otherwise — every existing
    /// fixture in this module parses to an ordinary simple command, so this
    /// keeps those assertions reading exactly as they did before `Pipeline`
    /// held `Command` instead of `SimpleCommand` directly (issue #75).
    fn simple(command: &Command) -> &SimpleCommand {
        match command {
            Command::Simple(simple) => simple,
            other => panic!("expected a simple command, got {other:?}"),
        }
    }

    fn first_word(cmd: &CommandLine) -> &Word {
        &simple(&cmd.first.first).words[0]
    }

    // ---- 1. adjacent-quote: r''m -rf / ----
    #[test]
    fn adjacent_quote_single() {
        let cmd = parse_ok("r''m -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![
                WordPiece::Literal("r".to_string()),
                WordPiece::SingleQuoted(String::new()),
                WordPiece::Literal("m".to_string()),
            ]
        );
    }

    // ---- 2. adjacent-quote: "r"m -rf / ----
    #[test]
    fn adjacent_quote_double() {
        let cmd = parse_ok("\"r\"m -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![
                WordPiece::DoubleQuoted(vec![WordPiece::Literal("r".to_string())]),
                WordPiece::Literal("m".to_string()),
            ]
        );
    }

    // ---- 3. adjacent-quote: r\m -rf / ----
    #[test]
    fn adjacent_quote_backslash() {
        let cmd = parse_ok("r\\m -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![
                WordPiece::Literal("r".to_string()),
                WordPiece::EscapeSequence('m'),
            ]
        );
    }

    // ---- 4. ANSI-C quoting, hex ----
    #[test]
    fn ansi_c_quoting_hex() {
        let cmd = parse_ok("$'\\x72\\x6d' -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::AnsiCQuoted("\\x72\\x6d".to_string())]
        );
    }

    // ---- 5. ANSI-C quoting, octal ----
    #[test]
    fn ansi_c_quoting_octal() {
        let cmd = parse_ok("$'\\162\\155' -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::AnsiCQuoted("\\162\\155".to_string())]
        );
    }

    // ---- 6. ANSI-C quoting, literal content ----
    #[test]
    fn ansi_c_quoting_literal() {
        let cmd = parse_ok("$'rm' -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::AnsiCQuoted("rm".to_string())]
        );
    }

    // ---- 7. heredoc ----
    #[test]
    fn heredoc_plain() {
        let cmd = parse_ok("cat <<EOF\nrm -rf /\nEOF\n");
        let redirections = &simple(&cmd.first.first).redirections;
        assert_eq!(redirections.len(), 1);
        match &redirections[0] {
            Redirection::HereDoc {
                strip_leading_tabs,
                expand_body,
                body,
            } => {
                assert!(!strip_leading_tabs);
                assert!(expand_body);
                assert_eq!(body.trim_end_matches('\n'), "rm -rf /");
            }
            other => panic!("expected HereDoc, got {other:?}"),
        }
    }

    // ---- 8. heredoc, tab-strip ----
    #[test]
    fn heredoc_tab_strip() {
        let cmd = parse_ok("cat <<-EOF\n\trm -rf /\nEOF\n");
        match &simple(&cmd.first.first).redirections[0] {
            Redirection::HereDoc {
                strip_leading_tabs,
                body,
                ..
            } => {
                assert!(strip_leading_tabs);
                assert_eq!(body.trim_end_matches('\n'), "rm -rf /");
            }
            other => panic!("expected HereDoc, got {other:?}"),
        }
    }

    // ---- 9. heredoc, quoted delimiter (no expansion) ----
    #[test]
    fn heredoc_quoted_delimiter_no_expansion() {
        let cmd = parse_ok("cat <<'EOF'\n$(rm -rf /)\nEOF\n");
        match &simple(&cmd.first.first).redirections[0] {
            Redirection::HereDoc {
                expand_body, body, ..
            } => {
                assert!(!expand_body);
                assert_eq!(body.trim_end_matches('\n'), "$(rm -rf /)");
            }
            other => panic!("expected HereDoc, got {other:?}"),
        }
    }

    // ---- 10. command substitution ----
    #[test]
    fn command_substitution() {
        let cmd = parse_ok("$(echo rm) -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::CommandSubstitution("echo rm".to_string())]
        );
    }

    // ---- 11. nested command substitution ----
    #[test]
    fn nested_command_substitution() {
        let cmd = parse_ok("$(echo $(echo rm)) -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::CommandSubstitution(
                "echo $(echo rm)".to_string()
            )]
        );
    }

    // ---- 12. backquoted command substitution ----
    #[test]
    fn backquoted_command_substitution() {
        let cmd = parse_ok("`echo rm` -rf /");
        assert_eq!(
            first_word(&cmd).0,
            vec![WordPiece::BackquotedSubstitution("echo rm".to_string())]
        );
    }

    // ---- 13. $IFS inside a word ----
    #[test]
    fn ifs_inside_word() {
        let cmd = parse_ok("rm$IFS-rf$IFS/");
        assert_eq!(
            first_word(&cmd).0,
            vec![
                WordPiece::Literal("rm".to_string()),
                WordPiece::ParameterExpansion("IFS".to_string()),
                WordPiece::Literal("-rf".to_string()),
                WordPiece::ParameterExpansion("IFS".to_string()),
                WordPiece::Literal("/".to_string()),
            ]
        );
    }

    // ---- 14. tilde expansion ----
    #[test]
    fn tilde_expansion() {
        let cmd = parse_ok("echo ~/x");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![
                WordPiece::Tilde(String::new()),
                WordPiece::Literal("/x".to_string())
            ]
        );
    }

    // ---- 15. brace expansion ----
    #[test]
    fn brace_expansion() {
        let cmd = parse_ok("echo {a,b}");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![WordPiece::BraceAlternation(vec![
                Word(vec![WordPiece::Literal("a".to_string())]),
                Word(vec![WordPiece::Literal("b".to_string())]),
            ])]
        );
    }

    // Regression pin for issue #59 (E2-6): see convert_word's pre-check
    // docs for why a `{`-containing word with no valid expansion still
    // parses as a literal.
    #[test]
    fn brace_like_text_without_valid_expansion_parses_as_literal() {
        let cmd = parse_ok("echo {foo");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(word.0, vec![WordPiece::Literal("{foo".to_string())]);
    }

    // ---- 16. pipeline ----
    #[test]
    fn pipeline_three_stages() {
        let cmd = parse_ok("echo x | base64 -d | sh");
        assert_eq!(cmd.first.rest.len(), 2);
    }

    // ---- 17. list: a; b && c ----
    #[test]
    fn list_sequence_and_and() {
        let cmd = parse_ok("a; b && c");
        assert_eq!(cmd.rest.len(), 2);
        assert_eq!(cmd.rest[0].0, Separator::Sequence);
        assert_eq!(cmd.rest[1].0, Separator::And);
    }

    // ---- 18. redirection ----
    #[test]
    fn file_redirection() {
        let cmd = parse_ok("echo x > /dev/null");
        let redirections = &simple(&cmd.first.first).redirections;
        assert_eq!(redirections.len(), 1);
        match &redirections[0] {
            Redirection::File { kind, target } => {
                assert_eq!(*kind, FileRedirectionKind::Output);
                assert_eq!(target.0, vec![WordPiece::Literal("/dev/null".to_string())]);
            }
            other => panic!("expected File redirection, got {other:?}"),
        }
    }

    // ---- unparseable input yields Err, not a panic ----
    #[test]
    fn unparseable_input_is_syntax_error() {
        let result = parse("((((");
        assert!(
            matches!(result, Err(ParseError::Syntax { .. })),
            "expected a syntax error, got {result:?}"
        );
    }

    // ---- parseable-but-unsupported construct yields
    // Err(ParseError::Unsupported), not a silent drop ----
    #[test]
    fn if_statement_is_unsupported() {
        let result = parse("if true; then echo x; fi");
        assert!(
            matches!(result, Err(ParseError::Unsupported { .. })),
            "expected an unsupported-construct error, got {result:?}"
        );
    }

    // ---- newline separation folds into one CommandLine exactly like `;`
    // (see parse()'s docs) ----
    #[test]
    fn newline_separated_commands_flatten_like_semicolon() {
        let cmd = parse_ok("a\nb");
        assert_eq!(
            simple(&cmd.first.first).words[0].0,
            vec![WordPiece::Literal("a".to_string())]
        );
        assert_eq!(cmd.rest.len(), 1);
        assert_eq!(cmd.rest[0].0, Separator::Sequence);
        assert_eq!(
            simple(&cmd.rest[0].1.first).words[0].0,
            vec![WordPiece::Literal("b".to_string())]
        );
    }

    #[test]
    fn realistic_multiline_agent_command_parses() {
        let cmd = parse_ok("cd /tmp\ncargo test");
        assert_eq!(cmd.rest.len(), 1);
        assert_eq!(cmd.rest[0].0, Separator::Sequence);
        assert_eq!(
            simple(&cmd.rest[0].1.first).words[0].0,
            vec![WordPiece::Literal("cargo".to_string())]
        );
    }

    #[test]
    fn background_job_on_either_line_of_a_multiline_command_is_unsupported() {
        let result = parse("sleep 1 &\necho done");
        assert!(
            matches!(result, Err(ParseError::Unsupported { .. })),
            "expected an unsupported-construct error, got {result:?}"
        );

        let result = parse("echo start\nsleep 1 &");
        assert!(
            matches!(result, Err(ParseError::Unsupported { .. })),
            "expected an unsupported-construct error, got {result:?}"
        );
    }

    // ---- a `name=value`-shaped SUFFIX item is an ordinary argument, not an
    // assignment (see apply_prefix_or_suffix_item's docs for why) ----
    #[test]
    fn suffix_assignment_shaped_word_is_an_ordinary_argument() {
        let cmd = parse_ok("dd if=/dev/zero of=/dev/sda");
        assert!(
            simple(&cmd.first.first).assignments.is_empty(),
            "a suffix name=value item must not be recorded as an assignment: {:?}",
            simple(&cmd.first.first).assignments
        );
        assert_eq!(
            simple(&cmd.first.first).words[1].0,
            vec![WordPiece::Literal("if=/dev/zero".to_string())]
        );
        assert_eq!(
            simple(&cmd.first.first).words[2].0,
            vec![WordPiece::Literal("of=/dev/sda".to_string())]
        );
    }

    // ---- a PREFIX name=value item (before the command word) is still a
    // real environment assignment (see apply_prefix_or_suffix_item's docs) ----
    #[test]
    fn prefix_assignment_is_still_recorded_as_an_assignment() {
        let cmd = parse_ok("VAR=v cmd");
        assert_eq!(simple(&cmd.first.first).assignments.len(), 1);
        assert_eq!(simple(&cmd.first.first).assignments[0].name, "VAR");
        assert_eq!(
            simple(&cmd.first.first).words[0].0,
            vec![WordPiece::Literal("cmd".to_string())]
        );
    }

    // ---- issue #52: reject_excessive_raw_nesting's exact boundary, not
    // just far-exceeding values (the existing integration tests in
    // tests/fail_closed_exit_paths.rs use 4000-8000x nesting, which proves
    // the defense works but not that the cap sits exactly where
    // MAX_BRACE_NESTING_DEPTH's docs claim) ----

    #[test]
    fn raw_brace_nesting_at_the_cap_still_parses() {
        let command = format!("echo {}a{}", "{a,".repeat(64), "}".repeat(64));
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn raw_brace_nesting_one_past_the_cap_is_rejected() {
        let command = format!("echo {}a{}", "{a,".repeat(65), "}".repeat(65));
        assert!(parse(&command).is_err());
    }

    #[test]
    fn raw_paren_nesting_at_the_cap_still_parses() {
        let command = format!("{}echo hi{}", "$(".repeat(64), ")".repeat(64));
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn raw_paren_nesting_one_past_the_cap_is_rejected() {
        let command = format!("{}echo hi{}", "$(".repeat(65), ")".repeat(65));
        assert!(parse(&command).is_err());
    }

    // ---- issue #52 follow-up: reject_excessive_raw_nesting's keyword
    // counter. shguard's AST does not model `if`/`while`/`for`/`case`
    // compound commands at all, so parse() always rejects them as an
    // unsupported construct regardless of nesting depth — these tests
    // distinguish that pre-existing "unsupported construct" rejection from
    // the new keyword-count rejection by asserting which error message
    // comes back, not just that parse() errors. ----

    fn unsupported_construct(command: &str) -> String {
        match parse(command) {
            Err(ParseError::Unsupported { construct }) => construct,
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn raw_keyword_nesting_at_the_cap_is_not_rejected_by_the_keyword_cap() {
        let command = format!(
            "{}a{}",
            "if true; then ".repeat(MAX_KEYWORD_NESTING_COUNT),
            "; fi".repeat(MAX_KEYWORD_NESTING_COUNT)
        );
        let construct = unsupported_construct(&command);
        assert!(
            !construct.contains("keyword nesting"),
            "unexpected keyword-cap rejection at the cap: {construct}"
        );
    }

    #[test]
    fn raw_keyword_nesting_one_past_the_cap_is_rejected_by_the_keyword_cap() {
        let command = format!(
            "{}a{}",
            "if true; then ".repeat(MAX_KEYWORD_NESTING_COUNT + 1),
            "; fi".repeat(MAX_KEYWORD_NESTING_COUNT + 1)
        );
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword-cap rejection, got: {construct}"
        );
    }

    /// Pins that the cap is a single total shared across all of
    /// [`NESTING_KEYWORDS`], not a separate budget per keyword: none of
    /// `if`/`for`/`while` alone reaches the cap, but their sum does.
    #[test]
    fn raw_keyword_nesting_cap_is_shared_across_keyword_kinds() {
        let third = MAX_KEYWORD_NESTING_COUNT / 3 + 1;
        let command = format!(
            "{}{}{}a{}{}{}",
            "if true; then ".repeat(third),
            "for x in y; do ".repeat(third),
            "while true; do ".repeat(third),
            "; done".repeat(third),
            "; done".repeat(third),
            "; fi".repeat(third),
        );
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword-cap rejection, got: {construct}"
        );
    }

    /// Regression pin for the reason [`MAX_KEYWORD_NESTING_COUNT`] counts
    /// openers only and never decrements: a decrementing counter keyed on
    /// closer words could be driven back down by injecting those words as
    /// ordinary arguments (`echo fi`) inside input that still recurses past
    /// brush-parser's overflow threshold. This nests `if` well past the cap
    /// (not just one over it, unlike the boundary tests above — the point
    /// here is the counting property, not the exact threshold) while
    /// interleaving `echo fi`/`echo done` arguments at every level — a naive
    /// decrementing scanner would read this as shallow; the actual,
    /// non-decrementing scanner must still reject it.
    #[test]
    fn raw_keyword_nesting_is_not_defeated_by_closer_words_in_argument_position() {
        let depth = MAX_KEYWORD_NESTING_COUNT * 5;
        let command = format!(
            "{}echo done{}",
            "if true; then echo fi; ".repeat(depth),
            " fi".repeat(depth)
        );
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword-cap rejection, got: {construct}"
        );
    }

    // ---- issue #52: convert_brace_segment's own AST-level depth cap,
    // built programmatically (the same approach normalize.rs's
    // `programmatically_deep_brace_nesting_hits_the_depth_cap` test uses for
    // its layer) — a raw command string can never reach this path in
    // practice, since reject_excessive_raw_nesting above rejects nesting
    // this deep before brush-parser ever builds a tree this shape, but this
    // pins the AST-level cap as a defense-in-depth backstop in its own
    // right, independent of the raw scan ----
    #[test]
    fn ast_level_brace_nesting_one_past_the_cap_is_rejected() {
        let mut segment = bword::BraceExpressionOrText::Text("x".to_string());
        for _ in 0..=MAX_BRACE_NESTING_DEPTH {
            segment =
                bword::BraceExpressionOrText::Expr(vec![bword::BraceExpressionMember::Child(
                    vec![segment],
                )]);
        }
        assert!(convert_brace_segment(segment, 0).is_err());
    }

    #[test]
    fn ast_level_brace_nesting_at_the_cap_still_converts() {
        let mut segment = bword::BraceExpressionOrText::Text("x".to_string());
        for _ in 0..MAX_BRACE_NESTING_DEPTH {
            segment =
                bword::BraceExpressionOrText::Expr(vec![bword::BraceExpressionMember::Child(
                    vec![segment],
                )]);
        }
        assert!(convert_brace_segment(segment, 0).is_ok());
    }

    // ==== Issue #75: translation tests for constructs newly supported ====

    /// Unwraps a [`Command::Compound`], panicking otherwise.
    fn compound(command: &Command) -> &CompoundCommand {
        match command {
            Command::Compound(compound) => compound,
            other => panic!("expected a compound command, got {other:?}"),
        }
    }

    #[test]
    fn timed_pipeline_parses_identically_to_the_untimed_pipeline() {
        let timed = parse_ok("time rm -rf /");
        let untimed = parse_ok("rm -rf /");
        assert_eq!(timed, untimed);
    }

    #[test]
    fn fd_duplication_redirect_parses_as_duplicate_output_with_numeric_target() {
        let cmd = parse_ok("rm -rf /tmp/x 2>&1");
        match &simple(&cmd.first.first).redirections[0] {
            Redirection::File { kind, target } => {
                assert_eq!(*kind, FileRedirectionKind::DuplicateOutput);
                assert_eq!(target.0, vec![WordPiece::Literal("1".to_string())]);
            }
            other => panic!("expected File redirection, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_input_redirect_parses() {
        let cmd = parse_ok("cmd 0<&3");
        match &simple(&cmd.first.first).redirections[0] {
            Redirection::File { kind, .. } => {
                assert_eq!(*kind, FileRedirectionKind::DuplicateInput);
            }
            other => panic!("expected File redirection, got {other:?}"),
        }
    }

    #[test]
    fn for_clause_parses_as_compound_command_with_words_and_body() {
        let cmd = parse_ok("for f in a b; do rm -rf \"$f\"; done");
        match compound(&cmd.first.first) {
            CompoundCommand::ForClause {
                variable,
                words,
                body,
                redirections,
            } => {
                assert_eq!(variable, "f");
                let Some(words) = words.as_ref() else {
                    panic!("expected an `in` word list");
                };
                assert_eq!(words.len(), 2);
                assert_eq!(words[0].0, vec![WordPiece::Literal("a".to_string())]);
                assert!(redirections.is_empty());
                // The body's `rm` call is what issue #75 needs the rule
                // engine to actually see.
                assert_eq!(
                    simple(&body.first.first).words[0].0,
                    vec![WordPiece::Literal("rm".to_string())]
                );
            }
            other => panic!("expected ForClause, got {other:?}"),
        }
    }

    #[test]
    fn for_clause_without_in_has_no_words() {
        let cmd = parse_ok("for f; do echo \"$f\"; done");
        match compound(&cmd.first.first) {
            CompoundCommand::ForClause { words, .. } => {
                assert!(words.is_none(), "expected no `in` word list, got {words:?}");
            }
            other => panic!("expected ForClause, got {other:?}"),
        }
    }

    #[test]
    fn while_clause_parses_condition_and_body() {
        let cmd = parse_ok("while true; do rm -rf /; done");
        match compound(&cmd.first.first) {
            CompoundCommand::WhileClause {
                condition, body, ..
            } => {
                assert_eq!(
                    simple(&condition.first.first).words[0].0,
                    vec![WordPiece::Literal("true".to_string())]
                );
                assert_eq!(
                    simple(&body.first.first).words[0].0,
                    vec![WordPiece::Literal("rm".to_string())]
                );
            }
            other => panic!("expected WhileClause, got {other:?}"),
        }
    }

    #[test]
    fn until_clause_parses_as_until_variant() {
        let cmd = parse_ok("until false; do echo x; done");
        assert!(matches!(
            compound(&cmd.first.first),
            CompoundCommand::UntilClause { .. }
        ));
    }

    #[test]
    fn subshell_parses_as_compound_command() {
        let cmd = parse_ok("(rm -rf /)");
        match compound(&cmd.first.first) {
            CompoundCommand::Subshell { body, .. } => {
                assert_eq!(
                    simple(&body.first.first).words[0].0,
                    vec![WordPiece::Literal("rm".to_string())]
                );
            }
            other => panic!("expected Subshell, got {other:?}"),
        }
    }

    #[test]
    fn function_definition_parses_with_brace_group_body() {
        let cmd = parse_ok("f() { rm -rf /; }");
        match &cmd.first.first {
            Command::FunctionDefinition(func) => {
                assert_eq!(func.name.0, vec![WordPiece::Literal("f".to_string())]);
                match func.body.as_ref() {
                    CompoundCommand::BraceGroup { body, .. } => {
                        assert_eq!(
                            simple(&body.first.first).words[0].0,
                            vec![WordPiece::Literal("rm".to_string())]
                        );
                    }
                    other => panic!("expected BraceGroup body, got {other:?}"),
                }
            }
            other => panic!("expected FunctionDefinition, got {other:?}"),
        }
    }

    #[test]
    fn array_assignment_converts_every_element() {
        let cmd = parse_ok("arr=(a b c)");
        match &simple(&cmd.first.first).assignments[0].value {
            AssignmentValue::Array(words) => {
                assert_eq!(words.len(), 3);
                assert_eq!(words[0].0, vec![WordPiece::Literal("a".to_string())]);
                assert_eq!(words[2].0, vec![WordPiece::Literal("c".to_string())]);
            }
            other => panic!("expected AssignmentValue::Array, got {other:?}"),
        }
    }

    #[test]
    fn scalar_assignment_is_unaffected_by_the_array_value_change() {
        let cmd = parse_ok("X=rm");
        match &simple(&cmd.first.first).assignments[0].value {
            AssignmentValue::Scalar(word) => {
                assert_eq!(word.0, vec![WordPiece::Literal("rm".to_string())]);
            }
            other => panic!("expected AssignmentValue::Scalar, got {other:?}"),
        }
    }

    #[test]
    fn special_parameter_last_exit_status_becomes_parameter_expansion() {
        let cmd = parse_ok("echo $?");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(word.0, vec![WordPiece::ParameterExpansion("?".to_string())]);
    }

    #[test]
    fn positional_parameter_becomes_parameter_expansion() {
        let cmd = parse_ok("echo $1");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(word.0, vec![WordPiece::ParameterExpansion("1".to_string())]);
    }

    #[test]
    fn arithmetic_expansion_keeps_raw_text_for_the_gate_to_rescan() {
        let cmd = parse_ok("echo $((1+$(rm -rf /)))");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![WordPiece::ArithmeticExpansion("1+$(rm -rf /)".to_string())]
        );
    }

    #[test]
    fn process_substitution_argument_becomes_single_piece_word() {
        let cmd = parse_ok("diff <(rm -rf /) f");
        let word = &simple(&cmd.first.first).words[1];
        match &word.0[..] {
            [WordPiece::ProcessSubstitution { direction, body }] => {
                assert_eq!(*direction, ProcessSubstitutionDirection::Read);
                assert_eq!(
                    simple(&body.first.first).words[0].0,
                    vec![WordPiece::Literal("rm".to_string())]
                );
            }
            other => panic!("expected a single ProcessSubstitution piece, got {other:?}"),
        }
    }

    #[test]
    fn process_substitution_as_redirect_target_converts() {
        let cmd = parse_ok("echo x > >(rm -rf /)");
        match &simple(&cmd.first.first).redirections[0] {
            Redirection::File { target, .. } => match &target.0[..] {
                [WordPiece::ProcessSubstitution { direction, .. }] => {
                    assert_eq!(*direction, ProcessSubstitutionDirection::Write);
                }
                other => panic!("expected a single ProcessSubstitution piece, got {other:?}"),
            },
            other => panic!("expected File redirection, got {other:?}"),
        }
    }
}
