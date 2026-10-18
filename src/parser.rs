//! Stage 1 of the pipeline (plan.md §1.1): a thin adapter over `brush-parser`
//! 0.4.0 (docs/adr/0001-parser-crate.md), converting its output into
//! shguard's own AST (`crate::ast`).
//!
//! `brush-parser` types (`brush_parser::ast::*`, `brush_parser::word::*`, …)
//! MUST NOT appear outside this module and `crate::syntax` — that is the
//! entire point of having an adapter ("dependencies point inward", `coding-guidelines/principles.md`).
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
//! - `case` clauses, C-style arithmetic `for`, bare `((...))` arithmetic
//!   commands, and coprocesses (issues #75/#191: zero measured occurrences
//!   in real traffic, unlike the compound commands below — see
//!   `crate::ast::CompoundCommand`'s docs)
//! - here-strings (`<<<`) and `&>`/`&>>` combined stdout/stderr redirections
//! - redirection kinds shguard's `FileRedirectionKind` has no variant for
//!   (`>|` clobber — issue #425 gave `<>` read-and-write its own variant,
//!   so the `/dev/tcp`/`/dev/udp` network-pseudo-device rule can see it)
//!   and fd-number (as opposed to a resolved fd-number *word*) redirect
//!   targets — see `convert_redirect_target`'s docs on why `Fd(_)` is
//!   unreachable in practice
//! - array-element assignment *targets* (`arr[0]=x`, as opposed to an array
//!   assignment *value*, `arr=(a b c)`, which issue #75 now supports)
//! - parameter expansions other than a bare `$NAME`/`${NAME}`, a bare
//!   positional parameter (`$1`, `$2`, …), a bare special parameter (`$?`,
//!   `$$`, `$!`, `$#`, `$@`, `$*`, `$-`, `$0`, issue #75), or the
//!   non-assigning modified forms of those (`${x%p}`, `${x:-w}`,
//!   `${x:o:l}`, `${#x}`, `${x/a/b}`, `${x^^}`, …, issue #580, kept as
//!   `WordPiece::ModifiedParameterExpansion`) and the literal-index
//!   `${PIPESTATUS[n]}`/`${pipestatus[n]}` (issue #578). Still rejected:
//!   indirection, every other array-indexed access, assigning forms
//!   (`${x:=w}`/`${x=w}`), `${x@op}`, a substring whose offset/length
//!   contains `$`/a backtick, a modifier operand containing a process
//!   substitution, a double quote inside a double-quoted parameter-expansion
//!   operand, and the zsh expansion-flag forms (`${(e)x}`, `${=x}`, `${~x}`,
//!   `${^x}`, `${+x}`, `${|x}`, `$=x`, `$~x`, `$^x`, `$+x`) and the
//!   `${ cmd; }` funsub in every shell, since brush would otherwise read them
//!   as literal text
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
//!
//! Issue #191 additionally supports, for the same reason (measured, common
//! real traffic — see `crate::ast::CompoundCommand::IfClause`/
//! `crate::ast::ExtendedTest`/`crate::ast::Separator::Async`'s own docs):
//! `if`/`elif`/`else` clauses, `&` background jobs, `[[ ... ]]` extended
//! test commands (operands only, not the boolean expression structure), and
//! pipeline negation (`!`, which — like `time` above — changes no argv and
//! is simply ignored rather than rejected).

use std::io::Cursor;

use brush_parser::word::{self as bword};
use brush_parser::{Parser as BrushParser, ast as bast};

use crate::ast::{
    Assignment, AssignmentValue, Command, CommandLine, CompoundCommand, ElifClause, ExtendedTest,
    FileRedirectionKind, FunctionDefinition, MAX_BRACE_NESTING_DEPTH, Pipeline,
    ProcessSubstitutionDirection, Redirection, Separator, SimpleCommand, Word, WordPiece,
};
use crate::syntax::compat::{self, catch_parser_panic};
use crate::syntax::{ParseError, parser_options};

/// Parses a raw shell command line into shguard's AST.
///
/// # Errors
///
/// Returns [`ParseError::Syntax`] if `command` is not valid shell syntax, or
/// [`ParseError::Unsupported`] if it parses but contains a construct
/// shguard's AST cannot represent (see the module docs), including raw
/// `{`/`}` nesting past [`crate::ast::MAX_RAW_BRACE_NESTING_DEPTH`] or raw `{` count
/// past [`crate::ast::MAX_RAW_BRACE_OPEN_COUNT`], `(`/`)` nesting past
/// [`crate::ast::MAX_RAW_PAREN_NESTING_DEPTH`] or raw `(` count past
/// [`crate::ast::MAX_RAW_PAREN_OPEN_COUNT`], `[` count past
/// [`crate::ast::MAX_RAW_BRACKET_OPENER_COUNT`], `$(`/`${`/`$[`/`<(`/`>(` counts past
/// their own caps (see `compat::reject_excessive_raw_nesting`), `compat::NESTING_KEYWORDS`
/// nesting past [`crate::ast::MAX_KEYWORD_NESTING_COUNT`], `[[ ... ]]` `!`/`&&`/`||`
/// operator count past [`crate::ast::MAX_RAW_EXTENDED_TEST_COUNT`]
/// (`compat::reject_excessive_raw_nesting`), or `$'...'` ANSI-C quoting combined
/// with a backslash-newline continuation anywhere in `command`
/// (`compat::reject_ansi_c_quote_with_line_continuation`, issue #444).
///
/// `analyze()` (`src/lib.rs`) calls this via `src/gate.rs` — stage 1 of the
/// pipeline (plan.md §1.1).
pub(crate) fn parse(command: &str) -> Result<CommandLine, ParseError> {
    let command = compat::prepare(command)?;
    let command = command.as_ref();

    let mut parser = BrushParser::new(Cursor::new(command.as_bytes()), &parser_options());
    let program = catch_parser_panic(|| parser.parse_program())?
        .map_err(|err| ParseError::syntax(err.to_string()))?;

    // brush-parser gives each newline-separated top-level command its own
    // `CompleteCommand`/`CompoundList` (verified empirically: `"a\nb"` yields
    // two `complete_commands`, `"a; b"` yields one with two items) — but
    // newline separation is semantically identical to `;` in bash, and real
    // agent commands are routinely multi-line (`cd x\ncargo test`). Rather
    // than special-case "one list" vs "many", every `CompoundListItem` from
    // every top-level list is concatenated into one logical sequence before
    // folding, so a trailing `&` (issue #191: now `Separator::Async`, not a
    // parse rejection) is handled identically wherever it appears (including
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

    // `pending_separator` at this point is the separator following the LAST
    // item's own (possibly `&&`/`||`-chained) pipeline — exactly the
    // trailing-terminator info `CommandLine::trailing_async` carries.
    Ok(CommandLine {
        first,
        rest,
        trailing_async: matches!(pending_separator, Separator::Async),
    })
}

/// `SeparatorOperator::Async` (`&`, issue #191) maps onto
/// [`Separator::Async`] — see that variant's docs for its cwd-isolation
/// semantics in `crate::gate::evaluate_command_line`.
fn convert_separator(sep: &bast::SeparatorOperator) -> Result<Separator, ParseError> {
    match sep {
        bast::SeparatorOperator::Sequence => Ok(Separator::Sequence),
        bast::SeparatorOperator::Async => Ok(Separator::Async),
    }
}

fn convert_and_or(and_or: &bast::AndOr) -> Result<(Separator, Pipeline), ParseError> {
    match and_or {
        bast::AndOr::And(pipeline) => Ok((Separator::And, convert_pipeline(pipeline)?)),
        bast::AndOr::Or(pipeline) => Ok((Separator::Or, convert_pipeline(pipeline)?)),
    }
}

fn convert_pipeline(pipeline: &bast::Pipeline) -> Result<Pipeline, ParseError> {
    // `time` (issue #75) only requests reporting the pipeline's execution
    // time — it changes no argv, no executed command, nothing the rule
    // engine cares about — so the flag is simply ignored rather than
    // rejected. `!` (issue #191) negates the pipeline's exit status, not
    // which commands run, so every consumer of `Command`/`SimpleCommand`
    // still ignores it — but `pipeline.bang` itself is carried through
    // (issue #353) since `crate::gate::evaluate_command_line`'s pushd-stack
    // collapse needs to know a negated pipeline's reported exit status
    // doesn't mean the pipeline actually succeeded.

    let mut commands = pipeline.seq.iter();
    let first = commands
        .next()
        .ok_or_else(|| ParseError::syntax("empty pipeline"))?;
    let rewritten = if pipeline.timed.is_some() {
        without_time_option_terminator(first)?
    } else {
        None
    };
    let first = convert_command(rewritten.as_ref().unwrap_or(first))?;
    let rest = commands.map(convert_command).collect::<Result<_, _>>()?;

    Ok(Pipeline {
        first,
        rest,
        bang: pipeline.bang,
    })
}

/// Bash's `time` reserved word accepts `-p` and `--` before the pipeline,
/// but brush strips only `-p`, leaving `--` as the command name: `time --
/// rm -rf /` would reach the rules as the command `--`. Narrow on purpose
/// (timed pipelines only): an untimed `-- rm` (e.g. `eval -- -- rm -rf /`)
/// really is the command `--`. Rewritten on brush's AST rather than
/// shguard's: brush tags everything after the fake `--` command as suffix
/// items, so `time -- FOO=bar rm` carries `FOO=bar` as a suffix word and a
/// plain drop would make it the command name. Leading assignments and
/// redirects move to the prefix and the first word becomes the command name,
/// exactly as `FOO=bar rm` parses. `None` (command left untouched) unless a
/// command word follows. A promoted name that is a bare reserved word
/// (`time -- ! rm -rf /`) is rejected: bash would parse it as grammar, not
/// as a command, and a plain simple command named `!` would hide the rest.
fn without_time_option_terminator(
    command: &bast::Command,
) -> Result<Option<bast::Command>, ParseError> {
    let bast::Command::Simple(simple) = command else {
        return Ok(None);
    };
    if simple.prefix.is_some() {
        return Ok(None);
    }
    let is_terminator = simple.word_or_name.as_ref().is_some_and(|word| {
        matches!(
            convert_word(word),
            Ok(Word(pieces)) if matches!(pieces.as_slice(), [WordPiece::Literal(text)] if text == "--")
        )
    });
    if !is_terminator {
        return Ok(None);
    }
    let Some(suffix) = simple.suffix.as_ref() else {
        return Ok(None);
    };
    let mut items = suffix.0.iter();
    let mut prefix = Vec::new();
    let mut name = None;
    for item in items.by_ref() {
        match item {
            bast::CommandPrefixOrSuffixItem::AssignmentWord(..)
            | bast::CommandPrefixOrSuffixItem::IoRedirect(_) => prefix.push(item.clone()),
            bast::CommandPrefixOrSuffixItem::Word(word) => {
                name = Some(word.clone());
                break;
            }
            bast::CommandPrefixOrSuffixItem::ProcessSubstitution(..) => return Ok(None),
        }
    }
    let Some(name) = name else {
        return Ok(None);
    };
    let Word(pieces) = convert_word(&name)?;
    if let [WordPiece::Literal(text)] = pieces.as_slice()
        && TIME_TERMINATOR_RESERVED_WORDS.contains(&text.as_str())
    {
        return Err(ParseError::syntax(format!(
            "reserved word `{text}` after `time --`"
        )));
    }
    let suffix: Vec<_> = items.cloned().collect();
    Ok(Some(bast::Command::Simple(bast::SimpleCommand {
        prefix: (!prefix.is_empty()).then_some(bast::CommandPrefix(prefix)),
        word_or_name: Some(name),
        suffix: (!suffix.is_empty()).then_some(bast::CommandSuffix(suffix)),
    })))
}

const TIME_TERMINATOR_RESERVED_WORDS: &[&str] = &[
    "!", "coproc", "{", "[[", "((", "if", "while", "until", "for", "select", "case", "function",
];

fn convert_command(command: &bast::Command) -> Result<Command, ParseError> {
    match command {
        bast::Command::Simple(simple) => Ok(Command::Simple(convert_simple_command(simple)?)),
        bast::Command::Compound(compound, redirects) => Ok(Command::Compound(
            convert_compound_command(compound, redirects)?,
        )),
        bast::Command::Function(func) => Ok(Command::FunctionDefinition(
            convert_function_definition(func)?,
        )),
        bast::Command::ExtendedTest(test, redirects) => Ok(Command::ExtendedTest(
            convert_extended_test(test, redirects)?,
        )),
    }
}

/// Converts the subset of `bast::CompoundCommand` shguard's AST can
/// represent (module docs: brace group, subshell, `for`/`while`/`until`/
/// `if`) into shguard's own [`CompoundCommand`], attaching `redirects` (the
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
        bast::CompoundCommand::IfClause(if_clause) => convert_if_clause(if_clause, redirections),
        bast::CompoundCommand::Arithmetic(_)
        | bast::CompoundCommand::ArithmeticForClause(_)
        | bast::CompoundCommand::CaseClause(_)
        | bast::CompoundCommand::Coprocess(_) => {
            Err(ParseError::unsupported(describe_compound(compound)))
        }
    }
}

/// Converts an `if`/`elif`/`else` chain (issue #191) into a
/// [`CompoundCommand::IfClause`], attaching the already-converted
/// `redirections` (matching every other [`convert_compound_command`] arm) —
/// see that variant's own docs for how brush-parser's
/// `elses: Option<Vec<bast::ElseClause>>` (each entry either a conditional
/// `elif` — `condition: Some(_)` — or a trailing unconditional `else` —
/// `condition: None`) maps onto shguard's own `elifs`/`else_body` split.
///
/// Fails closed (`Unsupported`) rather than silently dropping or merging a
/// branch if that shape is ever violated: a `None`-condition (`else`) entry
/// anywhere but the chain's last position would otherwise either lose every
/// clause after it or get silently skipped — bash's own grammar never
/// actually produces that shape (a bare `else` can only be the chain's
/// final clause), but this function does not lean on that grammar guarantee
/// holding forever; a dropped branch is a silent `Allow`, exactly the
/// failure mode issue #191 is about closing, not reproducing in the new
/// code that closes it.
fn convert_if_clause(
    if_clause: &bast::IfClauseCommand,
    redirections: Vec<Redirection>,
) -> Result<CompoundCommand, ParseError> {
    let condition = Box::new(convert_compound_list(if_clause.condition.0.iter())?);
    let then_body = Box::new(convert_compound_list(if_clause.then.0.iter())?);

    let clauses = if_clause.elses.as_deref().unwrap_or_default();
    let mut elifs = Vec::new();
    let mut else_body = None;
    for (index, clause) in clauses.iter().enumerate() {
        match &clause.condition {
            Some(condition) => elifs.push(ElifClause {
                condition: Box::new(convert_compound_list(condition.0.iter())?),
                body: Box::new(convert_compound_list(clause.body.0.iter())?),
            }),
            None if index == clauses.len() - 1 => {
                else_body = Some(Box::new(convert_compound_list(clause.body.0.iter())?));
            }
            None => {
                return Err(ParseError::unsupported(
                    "else clause not in the final position of an if/elif chain",
                ));
            }
        }
    }

    Ok(CompoundCommand::IfClause {
        condition,
        then_body,
        elifs,
        else_body,
        redirections,
    })
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

/// Converts a `[[ ... ]]` extended test (issue #191) into
/// [`crate::ast::ExtendedTest`] — see that type's own docs for why only the
/// operand words are kept, not the expression's boolean structure.
fn convert_extended_test(
    test: &bast::ExtendedTestExprCommand,
    redirects: &Option<bast::RedirectList>,
) -> Result<ExtendedTest, ParseError> {
    let mut words = Vec::new();
    collect_extended_test_words(&test.expr, &mut words, 0)?;
    Ok(ExtendedTest {
        words,
        redirections: convert_redirect_list(redirects)?,
    })
}

/// Recursively collects every operand [`Word`] out of an
/// `ExtendedTestExpr`'s boolean tree (`&&`/`||`/`!`/parens/unary/binary) —
/// see [`ExtendedTest`]'s docs for why the boolean structure itself is
/// discarded and only the operands survive.
///
/// `depth`, capped at [`MAX_BRACE_NESTING_DEPTH`]: `And`/`Or`/`Not`/
/// `Parenthesized` is itself a boxed recursive tree brush-parser already
/// fully materializes before this function ever runs (same as any other
/// AST shape this module walks), and unlike `&&`/`||` between top-level
/// pipelines (flat, not recursive — [`convert_compound_list`]), a long
/// unparenthesized chain *inside* `[[ ... ]]` (`[[ a && a && a && ... ]]`,
/// no parens at all) still builds a binary tree one level deeper per
/// operand — `compat::reject_excessive_raw_nesting`'s brace/paren/keyword
/// pre-scan cannot catch this shape (no `{`/`(`/`if`/`while`/`until`/`for`/
/// `case` byte appears), so this recursion needs its own depth cap the same
/// way [`convert_brace_segment`]'s does. Reuses
/// [`MAX_BRACE_NESTING_DEPTH`] rather than a new constant: both are cheap
/// structural AST descent (not the analysis-recursion
/// `gate::MAX_SUBSTITUTION_DEPTH` bounds), and 64 levels is already far
/// beyond any realistic `[[ ]]` operand count.
fn collect_extended_test_words(
    expr: &bast::ExtendedTestExpr,
    words: &mut Vec<Word>,
    depth: usize,
) -> Result<(), ParseError> {
    if depth > MAX_BRACE_NESTING_DEPTH {
        return Err(ParseError::unsupported(
            "extended test expression nesting exceeds the depth cap",
        ));
    }
    match expr {
        bast::ExtendedTestExpr::And(left, right) | bast::ExtendedTestExpr::Or(left, right) => {
            collect_extended_test_words(left, words, depth + 1)?;
            collect_extended_test_words(right, words, depth + 1)?;
        }
        bast::ExtendedTestExpr::Not(inner) | bast::ExtendedTestExpr::Parenthesized(inner) => {
            collect_extended_test_words(inner, words, depth + 1)?;
        }
        bast::ExtendedTestExpr::UnaryTest(_, operand) => {
            words.push(convert_word(operand)?);
        }
        bast::ExtendedTestExpr::BinaryTest(_, left, right) => {
            words.push(convert_word(left)?);
            words.push(convert_word(right)?);
        }
    }
    Ok(())
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
/// decide what an `AssignmentWord` item means (see its `AssignmentWord`
/// match arm).
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
    Ok(Assignment {
        name,
        value,
        append: assignment.append,
    })
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
        // Issue #425: `<>` (`exec 3<>/dev/tcp/host/port`) is now modeled so
        // the existing `/dev/*` dangerous-target machinery can see it, same
        // as any other write-applicable redirection. `Clobber` (`>|`)
        // stays unsupported — no rule targets it yet, out of this issue's
        // scope.
        bast::IoFileRedirectKind::ReadAndWrite => Ok(FileRedirectionKind::ReadAndWrite),
        bast::IoFileRedirectKind::Clobber => Err(ParseError::unsupported(
            "clobber redirection (>|)".to_string(),
        )),
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
    if has_pid_dollars_before_brace(raw) {
        return Err(ParseError::unsupported(
            "`$$` followed by `{` (brush reads the second `$` as a `${...}` opener, bash as the PID)",
        ));
    }
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
    // Issue #405: pre-empt, rather than let `parse_brace_expansions` panic
    // on, an unquoted `{...}` group brush-parser's `number()` rule would
    // panic evaluating (see [`brace_group_panics`] for the exact
    // precondition — not just a well-formed `{N..M}` range; any leading
    // overflowing digit run right after `{` panics, `..` or not) — routes
    // straight to the SAME rejection [`convert_brace_members`] already
    // gives every WELL-FORMED brace range regardless of overflow (its
    // `NumberSequence`/`CharSequence` arms are unconditionally
    // `Unsupported`), so this changes no decision for that shape, only
    // avoids reaching the panic. This is a narrowing, not an elimination,
    // of the panic surface — [`brace_group_panics`]'s own docs disclose
    // the residual shapes it can still miss, left to
    // [`catch_parser_panic`]'s pre-existing (also Ask-only) containment.
    if word_contains_overflowing_brace_range(raw) {
        return Err(ParseError::unsupported(
            "brace range expansion ({1..5} / {a..z})",
        ));
    }
    // Not routed through `parse_brace_expansions`: its grammar reads the `{`
    // after a `$` as a brace group and `number()` panics on
    // `${99999999999999999999}` (issue #640), degrading the whole line to Ask.
    if only_parameter_expansion_braces(raw) {
        return Ok(Word(convert_word_text(raw)?));
    }
    let brace_segments =
        catch_parser_panic(|| bword::parse_brace_expansions(raw, &parser_options()))?.map_err(
            |err| ParseError::syntax(format!("brace-expansion parse of {raw:?}: {err}")),
        )?;

    let has_brace_expr = brace_segments
        .as_ref()
        .is_some_and(|segments| segments.iter().any(is_brace_expr));

    if !has_brace_expr {
        return Ok(Word(convert_word_text(raw)?));
    }

    Ok(Word(convert_brace_segments(
        brace_segments.into_iter().flatten(),
        0,
    )?))
}

/// True if `text` has an even run (>= 2) of unescaped, unsingle-quoted `$`
/// directly before a `{` (issue #655). Double quotes are scanned like plain
/// text: bash expands `$$` there too, and rejecting is fail-closed.
fn has_pid_dollars_before_brace(text: &str) -> bool {
    let mut chars = text.chars();
    let mut run = 0usize;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '$' => {
                run += 1;
                continue;
            }
            '{' if run >= 2 && run.is_multiple_of(2) => return true,
            '\\' => {
                chars.next();
            }
            '\'' if !in_double => {
                // Not a plain skip to the next `'`: in `$'...'` a backslash
                // escapes the quote, and mis-pairing would hide a payload.
                let ansi_c = !run.is_multiple_of(2);
                while let Some(q) = chars.next() {
                    match q {
                        '\\' if ansi_c => {
                            chars.next();
                        }
                        '\'' => break,
                        _ => {}
                    }
                }
            }
            '"' => in_double = !in_double,
            _ => {}
        }
        run = 0;
    }
    false
}

/// Converts consecutive brace-pre-pass segments. A `Text` ending in an odd
/// run of `$` directly followed by an `Expr` is a `${...}` the pre-pass split
/// at a top-level comma; no shell brace-expands `${`, and the real parse
/// would never see the `${` text, so it is rejected here.
fn convert_brace_segments(
    segments: impl IntoIterator<Item = bword::BraceExpressionOrText>,
    depth: usize,
) -> Result<Vec<WordPiece>, ParseError> {
    let mut pieces = Vec::new();
    let mut after_lone_dollar = false;
    for segment in segments {
        match &segment {
            bword::BraceExpressionOrText::Expr(_) if after_lone_dollar => {
                return Err(ParseError::unsupported(
                    "unresolved `$` expansion form (a `${...}` split by a top-level comma)",
                ));
            }
            bword::BraceExpressionOrText::Text(text) => {
                let dollars = text.bytes().rev().take_while(|&b| b == b'$').count();
                let before = &text[..text.len() - dollars];
                let backslashes = before.bytes().rev().take_while(|&b| b == b'\\').count();
                // `\$` is a literal dollar, so the run's first `$` is escaped.
                let live = dollars.saturating_sub(usize::from(backslashes % 2 == 1));
                after_lone_dollar = live % 2 == 1;
            }
            bword::BraceExpressionOrText::Expr(_) => after_lone_dollar = false,
        }
        pieces.extend(convert_brace_segment(segment, depth)?);
    }
    Ok(pieces)
}

/// True if every `{` in `text` follows an odd run of `$` (`${`, not the PID
/// parameter `$$` before a real brace group). Backslash and `'` are excluded
/// because `\${a,b}` is a real bash brace expansion.
fn only_parameter_expansion_braces(text: &str) -> bool {
    let bytes = text.as_bytes();
    !text.contains(['\\', '\''])
        && bytes.iter().enumerate().all(|(i, &b)| {
            b != b'{' || bytes[..i].iter().rev().take_while(|&&c| c == b'$').count() % 2 == 1
        })
}

fn is_brace_expr(segment: &bword::BraceExpressionOrText) -> bool {
    matches!(segment, bword::BraceExpressionOrText::Expr(_))
}

/// True if `text` contains a `{` opening a brace group whose grammar rule
/// brush-parser 0.4.0 would panic evaluating — see [`brace_group_panics`]
/// for the exact precondition, derived from brush-parser's own grammar
/// (`word.rs:673-714`, reproduced in that function's docs).
///
/// Bails entirely (returns `false` — leave this word to
/// `catch_parser_panic`'s pre-existing containment) if `text` contains any
/// of `"`, `'`, `` ` ``, `$`, `\`. Pre-emption only exists to avoid the
/// panic itself (the *decision* is `Ask` either way — pre-empted via
/// `ParseError::unsupported` or contained via `catch_parser_panic`'s own
/// `ParseError::Syntax` — so under-flagging here costs nothing), except for
/// words [`only_parameter_expansion_braces`] diverts in `convert_word`. Every
/// one of these bytes can introduce quoting or a substitution, whose
/// content brush's grammar may keep live (inside `"..."`) or treat as an
/// opaque, independently-quoted sub-fragment (`$(...)`, `` `...` ``), and
/// getting that nesting wrong in either direction has repeatedly produced
/// real false-positive `Ask` downgrades across five rounds of review
/// (issue #405) — each fix for one nesting/quoting shape (quoted braces,
/// a comma hidden behind a quoted `}`, a `{` inside a live substitution,
/// a substitution nested inside another substitution's double-quoted
/// body) surfaced a new one. Since precise replication buys nothing
/// (Ask either way) but a mistake in the unsafe direction is a real
/// security regression, this bails conservatively at the word level
/// instead of trying to mirror that grammar.
fn word_contains_overflowing_brace_range(text: &str) -> bool {
    if text.contains(['"', '\'', '`', '$', '\\']) {
        return false;
    }
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'{' && brace_group_panics(&text[i + 1..]) {
            return true;
        }
    }
    false
}

/// Whether brush-parser 0.4.0 panics evaluating the `{...}` group whose
/// content starts at `after_brace` (the text immediately following the
/// `{`) — derived from its grammar (`word.rs:673-714`):
///
/// ```text
/// brace_expr_inner = brace_text_list_expr / brace_sequence_expr
/// brace_text_list_expr = brace_text_list_member **<2,> ","   // >=2 comma-separated members
/// brace_sequence_expr = number() ".." number() (".." number())?
/// number = sign? digits { digits.parse::<i64>().unwrap() }  // panics here
/// ```
///
/// PEG ordered choice tries `brace_text_list_expr` FIRST; only when that
/// fails (no top-level `,` before the matching `}`, since a single
/// non-comma-separated member can never satisfy `**<2,>`) does it fall to
/// `brace_sequence_expr`, whose `number()` panics as soon as it matches
/// ANY leading `sign? digit+` that overflows `i64` — *before* checking
/// whether `..` even follows (`{9223372036854775808b}`, no range syntax
/// at all, still panics). A top-level comma before the closing `}` of a
/// *terminated* group — even with a wildly overflowing leading digit run
/// (`{99999999999999999999,x}`) — makes the comma-list branch succeed
/// instead, so `number()` (and its panic) is never reached at all. An
/// *unterminated* group panics regardless of any comma
/// (`{99999999999999999999,` has no closing `}`, so the comma-list branch
/// can't match either, and the sequence branch's `number()` still runs).
///
/// This is therefore an UNDER-approximation by construction (matching
/// the safe direction — a case this misses is still safely contained by
/// [`catch_parser_panic`], never silently mis-parsed). Known residuals,
/// all left to that containment rather than chased further (chasing
/// residuals is the trap five review rounds already fell into on the
/// substitution side — see [`word_contains_overflowing_brace_range`]'s
/// docs): any panicking shape [`brace_group_may_avoid_the_panicking_path`]'s
/// `{`/`,` bail skips (e.g. `{N{}`, an unterminated `{N,`), and `{a..z..N}`
/// (`character() ".." character() (".." number())?` — brush's char-range
/// increment) whose overflowing `N` [`parse_brace_range_endpoint`] never
/// reaches, since it only recognizes numeric leading endpoints.
fn brace_group_panics(after_brace: &str) -> bool {
    if brace_group_may_avoid_the_panicking_path(after_brace) {
        return false;
    }
    let Some((leading_overflows, rest)) = parse_brace_range_endpoint(after_brace) else {
        return false;
    };
    if leading_overflows {
        return true;
    }
    let Some(rest) = rest.strip_prefix("..") else {
        return false;
    };
    let Some((second_overflows, rest)) = parse_brace_range_endpoint(rest) else {
        return false;
    };
    if second_overflows {
        return true;
    }
    let Some(rest) = rest.strip_prefix("..") else {
        return false;
    };
    matches!(parse_brace_range_endpoint(rest), Some((true, _)))
}

/// Whether [`brace_group_panics`] should stay silent about the brace group
/// whose content starts at `after_brace` — because a `,` appears before the
/// `}` that closes it, or because a further `{` appears first and this scan
/// can't tell whether brush's own grammar treats it as a nested brace group
/// or, when it doesn't itself resolve to a complete `brace_expr`, as
/// ordinary literal text via `non_brace_expr_text`'s `!brace_expr() "{"`
/// fallback (`word.rs:668-670`) — which shifts what this group's own
/// top-level content and closing `}` really are. `{99999999999999999999{a,b`
/// is the concrete case: brush treats the inner `{` as literal (it never
/// completes a brace_expr of its own), so the `,` IS this group's top-level
/// comma and the comma-list branch succeeds without ever reaching
/// `number()` — a naive depth count instead treats the inner `{` as truly
/// nested, misses that comma, and wrongly concludes this group panics — a
/// real Block→Ask downgrade. Bailing to "safe to skip" on the first `{`
/// this scan can't resolve, rather than
/// trying to replicate brush's own disambiguation, keeps this an
/// UNDER-approximation: on real input, "flagged" only remains true when
/// `after_brace` up to its own `}`/end contains no further `{` and no `,`
/// at all, and any group that shape describes genuinely does reach
/// `number()` and panic in brush's real grammar.
fn brace_group_may_avoid_the_panicking_path(after_brace: &str) -> bool {
    for byte in after_brace.bytes() {
        match byte {
            b'{' | b',' => return true,
            b'}' => return false,
            _ => {}
        }
    }
    false
}

/// Parses an optional `-`/`+` sign then an ASCII digit run from the start
/// of `s`, returning `(overflows_i64, remainder_after_the_digits)`.
/// `None` if `s` doesn't start with a digit (after an optional sign) at
/// all — not itself a range endpoint. Matches brush's own `number()` rule
/// exactly (`word.rs:706-710`): the sign is a separate grammar element
/// applied to the parsed value only AFTER the digit run itself parses, so
/// overflow is checked against the UNSIGNED digit string alone — `-` does
/// not widen the representable range the way naively parsing `"-<digits>"`
/// as one signed literal would (`i64::MIN`'s magnitude,
/// `9223372036854775808`, does not fit in `i64` even though `i64::MIN`
/// itself does).
fn parse_brace_range_endpoint(s: &str) -> Option<(bool, &str)> {
    let unsigned = s.strip_prefix(['-', '+']).unwrap_or(s);
    let digit_len = unsigned.bytes().take_while(u8::is_ascii_digit).count();
    if digit_len == 0 {
        return None;
    }
    let sign_len = s.len() - unsigned.len();
    let overflows = unsigned[..digit_len].parse::<i64>().is_err();
    Some((overflows, &s[sign_len + digit_len..]))
}

/// Defense-in-depth companion to `compat::reject_excessive_raw_nesting` (issue
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
                Ok(Word(convert_brace_segments(inner, depth + 1)?))
            }
            bword::BraceExpressionMember::NumberSequence { .. }
            | bword::BraceExpressionMember::CharSequence { .. } => Err(ParseError::unsupported(
                "brace range expansion ({1..5} / {a..z})",
            )),
        })
        .collect()
}

/// When `text` starts with a `~` directly followed by an optional `+`/`-`
/// sign and a decimal digit run that overflows `usize`, returns the
/// `(tilde_run, remainder)` split at the end of that digit run. This is
/// the exact shape that panics brush-parser 0.4.0's tilde-expression
/// parser: the unsigned/`+`-prefixed dir-stack form (`word.rs:909`,
/// `parse::<usize>().unwrap()`, `TildeExpr::NthDirFromTopOfDirStack`) and
/// the `-`-prefixed dir-stack form (`word.rs:911`,
/// `TildeExpr::NthDirFromBottomOfDirStack`) both parse the digit run the
/// same unchecked way — bash itself treats an out-of-range `~<uid>` or
/// `~±<n>` dir-stack reference as a literal word (no user has a UID this
/// large, and no shell has a directory stack this deep), so
/// [`convert_word_text`] pre-empts the parse for just this leading run
/// instead of letting the pinned dependency's internal overflow panic
/// take down the whole word (and, with it, any sibling word in the same
/// command sharing this call's fate — e.g. a `rm -rf /` in the same argv).
fn split_overflowing_leading_tilde(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('~')?;
    let sign_len = usize::from(rest.starts_with(['+', '-']));
    let digits_start = &rest[sign_len..];
    let digit_len = digits_start.bytes().take_while(u8::is_ascii_digit).count();
    if digit_len == 0 {
        return None;
    }
    let (digits, remainder) = digits_start.split_at(digit_len);
    digits
        .parse::<usize>()
        .is_err()
        .then(|| (&text[..1 + sign_len + digit_len], remainder))
}

/// Runs the ordinary (non-brace) word parse over a fragment of source text
/// and converts each resulting piece.
fn convert_word_text(text: &str) -> Result<Vec<WordPiece>, ParseError> {
    // Iterative, not recursive, over consecutive overflowing-tilde runs: a
    // word that is nothing but repeated runs (`~<20 digits>~<20 digits>…`)
    // would otherwise recurse once per run, and ~2 MiB of that shape — far
    // under the binary's 10 MiB stdin cap — overflows the stack, which
    // aborts (`catch_unwind` cannot intercept it, see
    // `src/bin/shguard.rs`'s module docs) and therefore fails OPEN in the
    // hook. Same threat model as `reject_excessive_raw_nesting`.
    let mut converted = Vec::new();
    let mut rest = text;
    while let Some((tilde_run, remainder)) = split_overflowing_leading_tilde(rest) {
        converted.push(WordPiece::Literal(tilde_run.to_string()));
        rest = remainder;
    }
    if !converted.is_empty() && rest.is_empty() {
        return Ok(converted);
    }
    let pieces = catch_parser_panic(|| bword::parse(rest, &parser_options()))?
        .map_err(|err| ParseError::syntax(format!("word parse of {rest:?}: {err}")))?;
    reject_unresolved_dollar_forms(pieces.iter().map(|p| &p.piece))?;
    for piece in pieces {
        converted.push(convert_word_piece(piece.piece, false)?);
    }
    Ok(converted)
}

/// Rejects, in every shell, the `$` forms brush does not parse as an
/// expansion but zsh/mksh/bash 5.3 evaluate: a literal `${` (flags
/// `${(e)x}`/`${=x}`/`${~x}`/`${^x}`, the funsub `${ cmd; }`) and the
/// unbraced `$=x`/`$~x`/`$^x`/`$+x`. brush leaves `${` in a `Text` piece only
/// when its parameter-expansion rule failed, and `$` is a lone literal only
/// when no expansion follows it, so a `Text` run containing either would
/// otherwise read as a resolved literal. Consecutive `Text` pieces are joined
/// first so the split point cannot hide the pair; a quoted or escaped `$`
/// arrives as another piece type and is not affected.
fn reject_unresolved_dollar_forms<'a>(
    pieces: impl Iterator<Item = &'a bword::WordPiece>,
) -> Result<(), ParseError> {
    let mut run = String::new();
    for piece in pieces {
        if let bword::WordPiece::Text(text) = piece {
            run.push_str(text);
        } else {
            reject_unresolved_dollar_run(&run)?;
            run.clear();
        }
    }
    reject_unresolved_dollar_run(&run)
}

/// `rest` follows a `$`. A numeric `{N}` / `{-N}` (an overflowing positional
/// parameter brush cannot parse) is only an unset parameter, not an
/// evaluated form, so it stays literal.
fn is_unresolved_brace(rest: &str) -> bool {
    let Some(body) = rest.strip_prefix('{') else {
        return false;
    };
    let digits = body.strip_prefix('-').unwrap_or(body);
    let after_digits = digits.trim_start_matches(|c: char| c.is_ascii_digit());
    let numeric = after_digits.len() < digits.len() && after_digits.starts_with('}');
    !numeric
}

fn reject_unresolved_dollar_run(run: &str) -> Result<(), ParseError> {
    let unresolved = run
        .split('$')
        .skip(1)
        .any(|rest| rest.starts_with(['=', '~', '^', '+']) || is_unresolved_brace(rest));
    if unresolved {
        return Err(ParseError::unsupported(
            "unresolved `$` expansion form (zsh flags/short forms such as ${(e)x}, ${=x}, $=x, $~x, or a ${ command; } substitution)",
        ));
    }
    Ok(())
}

fn convert_word_piece(
    piece: bword::WordPiece,
    in_double_quotes: bool,
) -> Result<WordPiece, ParseError> {
    match piece {
        bword::WordPiece::Text(text) => Ok(WordPiece::Literal(text)),
        bword::WordPiece::SingleQuotedText(text) => Ok(WordPiece::SingleQuoted(text)),
        bword::WordPiece::AnsiCQuotedText(text) => Ok(WordPiece::AnsiCQuoted(text)),
        bword::WordPiece::DoubleQuotedSequence(inner)
        | bword::WordPiece::GettextDoubleQuotedSequence(inner) => {
            reject_unresolved_dollar_forms(inner.iter().map(|p| &p.piece))?;
            let pieces = inner
                .into_iter()
                .map(|p| convert_word_piece(p.piece, true))
                .collect::<Result<_, _>>()?;
            Ok(WordPiece::DoubleQuoted(pieces))
        }
        bword::WordPiece::TildeExpansion(tilde) => Ok(WordPiece::Tilde(convert_tilde(tilde))),
        bword::WordPiece::ParameterExpansion(expr) => {
            convert_parameter_expansion(expr, in_double_quotes)
        }
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

/// A human-readable name for every [`bword::ParameterExpr`] shape this
/// module rejects, for the `deny_message` an agent sees (issue #471) — the
/// bare `{:?}` this replaced dumped brush's internal enum/field names
/// (`Parameter { parameter: NamedWithAllIndices { name: "arr", ... } }`)
/// instead of naming the actual bash construct.
fn describe_parameter_expr(expr: &bword::ParameterExpr) -> &'static str {
    match expr {
        bword::ParameterExpr::Parameter { .. } => {
            "indirect or array-indexed parameter expansion (${!x}/${arr[i]}/${arr[@]})"
        }
        bword::ParameterExpr::UseDefaultValues { .. } => "default-value expansion (${x:-d})",
        bword::ParameterExpr::AssignDefaultValues { .. } => "default-value assignment (${x:=d})",
        bword::ParameterExpr::IndicateErrorIfNullOrUnset { .. } => {
            "error-if-unset expansion (${x:?msg})"
        }
        bword::ParameterExpr::UseAlternativeValue { .. } => {
            "alternative-value expansion (${x:+alt})"
        }
        bword::ParameterExpr::ParameterLength { .. } => "parameter length (${#x})",
        bword::ParameterExpr::RemoveSmallestSuffixPattern { .. } => "suffix removal (${x%pat})",
        bword::ParameterExpr::RemoveLargestSuffixPattern { .. } => "suffix removal (${x%%pat})",
        bword::ParameterExpr::RemoveSmallestPrefixPattern { .. } => "prefix removal (${x#pat})",
        bword::ParameterExpr::RemoveLargestPrefixPattern { .. } => "prefix removal (${x##pat})",
        bword::ParameterExpr::Substring { .. } => "substring expansion (${x:off:len})",
        bword::ParameterExpr::Transform { .. } => "parameter transformation (${x@op})",
        bword::ParameterExpr::UppercaseFirstChar { .. } => "case modification (${x^})",
        bword::ParameterExpr::UppercasePattern { .. } => "case modification (${x^^})",
        bword::ParameterExpr::LowercaseFirstChar { .. } => "case modification (${x,})",
        bword::ParameterExpr::LowercasePattern { .. } => "case modification (${x,,})",
        bword::ParameterExpr::ReplaceSubstring { .. } => "pattern substitution (${x/a/b})",
        bword::ParameterExpr::VariableNames { .. } => "variable-name expansion (${!prefix*})",
        bword::ParameterExpr::MemberKeys { .. } => "array-key expansion (${!arr[@]})",
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
/// to store as the "name". Non-assigning modified forms of those become a
/// separate `WordPiece::ModifiedParameterExpansion` (never the bare variant,
/// whose same-line value gets substituted in command position), as does the
/// literal-index `PIPESTATUS`. Every other `ParameterExpr` shape
/// (indirection, other array-indexed access, assigning defaults, …) is
/// rejected instead — see [`describe_parameter_expr`] for the name attached
/// to the rejection.
fn convert_parameter_expansion(
    expr: bword::ParameterExpr,
    in_double_quotes: bool,
) -> Result<WordPiece, ParseError> {
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
        bword::ParameterExpr::Parameter {
            parameter,
            indirect: false,
        } => match pipestatus_name(&parameter) {
            Some(name) => Ok(modified(name, Vec::new())),
            None => Err(unsupported_parameter_form(
                &bword::ParameterExpr::Parameter {
                    parameter,
                    indirect: false,
                },
            )),
        },
        bword::ParameterExpr::UseDefaultValues {
            parameter,
            indirect: false,
            default_value: word,
            ..
        }
        | bword::ParameterExpr::IndicateErrorIfNullOrUnset {
            parameter,
            indirect: false,
            error_message: word,
            ..
        }
        | bword::ParameterExpr::UseAlternativeValue {
            parameter,
            indirect: false,
            alternative_value: word,
            ..
        }
        | bword::ParameterExpr::RemoveSmallestSuffixPattern {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::RemoveLargestSuffixPattern {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::RemoveSmallestPrefixPattern {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::RemoveLargestPrefixPattern {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::UppercaseFirstChar {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::UppercasePattern {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::LowercaseFirstChar {
            parameter,
            indirect: false,
            pattern: word,
        }
        | bword::ParameterExpr::LowercasePattern {
            parameter,
            indirect: false,
            pattern: word,
        } => {
            let name = modifiable_parameter_name(&parameter)?;
            Ok(modified(
                name,
                convert_operand(word.as_deref(), in_double_quotes)?,
            ))
        }
        bword::ParameterExpr::ReplaceSubstring {
            parameter,
            indirect: false,
            pattern,
            replacement,
            ..
        } => {
            let name = modifiable_parameter_name(&parameter)?;
            let mut operand = convert_operand(Some(&pattern), in_double_quotes)?;
            operand.extend(convert_operand(replacement.as_deref(), in_double_quotes)?);
            Ok(modified(name, operand))
        }
        bword::ParameterExpr::ParameterLength {
            parameter,
            indirect: false,
        } => Ok(modified(modifiable_parameter_name(&parameter)?, Vec::new())),
        bword::ParameterExpr::Substring {
            parameter,
            indirect: false,
            offset,
            length,
        } => {
            let name = modifiable_parameter_name(&parameter)?;
            let has_substitution = arithmetic_text_has_substitution(&offset.value)
                || length
                    .as_ref()
                    .is_some_and(|len| arithmetic_text_has_substitution(&len.value));
            if has_substitution {
                return Err(ParseError::unsupported(
                    "substring expansion with a substitution in its offset/length",
                ));
            }
            Ok(modified(name, Vec::new()))
        }
        other => Err(unsupported_parameter_form(&other)),
    }
}

fn modified(name: String, operand: Vec<WordPiece>) -> WordPiece {
    WordPiece::ModifiedParameterExpansion { name, operand }
}

fn unsupported_parameter_form(expr: &bword::ParameterExpr) -> ParseError {
    ParseError::unsupported(format!(
        "parameter expansion form: {}",
        describe_parameter_expr(expr)
    ))
}

/// The "name" for a named/positional/special parameter (the same ones the
/// bare arms above accept); array-indexed forms with a modifier are
/// unsupported.
fn modifiable_parameter_name(parameter: &bword::Parameter) -> Result<String, ParseError> {
    match parameter {
        bword::Parameter::Named(name) => Ok(name.clone()),
        bword::Parameter::Positional(n) => Ok(n.to_string()),
        bword::Parameter::Special(special) => Ok(special.to_string()),
        bword::Parameter::NamedWithIndex { .. } | bword::Parameter::NamedWithAllIndices { .. } => {
            Err(ParseError::unsupported(
                "array-indexed parameter expansion with a modifier (${arr[i]%p}/${arr[@]:-w})",
            ))
        }
    }
}

/// Issue #578: only `PIPESTATUS`/`pipestatus` with a decimal-literal or
/// `@`/`*` subscript. Its value is shell-controlled exit codes, never a
/// command name; anything else array-indexed stays unsupported.
fn pipestatus_name(parameter: &bword::Parameter) -> Option<String> {
    let is_pipestatus = |name: &str| name == "PIPESTATUS" || name == "pipestatus";
    match parameter {
        bword::Parameter::NamedWithIndex { name, index }
            if is_pipestatus(name)
                && !index.is_empty()
                && index.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(name.clone())
        }
        bword::Parameter::NamedWithAllIndices { name, concatenate } if is_pipestatus(name) => {
            Some(if *concatenate {
                name.clone()
            } else {
                format!("{name}[@]")
            })
        }
        _ => None,
    }
}

fn arithmetic_text_has_substitution(text: &str) -> bool {
    text.contains(['$', '`'])
}

/// Re-parses a modifier's raw word text so substitutions inside it are
/// found. A process substitution cannot be built from a word-level parse
/// (it would come back as inert text), so an operand containing `<(`/`>(`
/// stays unsupported.
///
/// brush captures the operand with its unquoted word grammar whatever the
/// context, but inside a double-quoted `${...}` bash treats `'` and `"` in
/// the operand as literal characters, so re-parsing such a slice unquoted
/// would let `'$(cmd)'` look inert while bash runs the substitution. A
/// double-quoted operand is therefore parsed inside a synthetic `"..."`
/// wrapper (where `'` is literal and `$(...)` stays live), and one that
/// contains `"` stays unsupported.
fn convert_operand(
    raw: Option<&str>,
    in_double_quotes: bool,
) -> Result<Vec<WordPiece>, ParseError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.contains("<(") || raw.contains(">(") {
        return Err(ParseError::unsupported(
            "process substitution inside a parameter-expansion operand",
        ));
    }
    if !in_double_quotes {
        return convert_word_text(raw);
    }
    if raw.contains('"') {
        return Err(ParseError::unsupported(
            "double quote inside a double-quoted parameter-expansion operand",
        ));
    }
    match convert_word_text(&format!("\"{raw}\""))?.as_slice() {
        [WordPiece::DoubleQuoted(inner)] => Ok(inner.clone()),
        _ => Err(ParseError::unsupported(
            "double-quoted parameter-expansion operand did not stay one quoted word",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ast::{
        BACKTRACK_COST_OPENER, MAX_KEYWORD_NESTING_COUNT, MAX_RAW_BACKTRACK_BUDGET,
        MAX_RAW_BRACE_NESTING_DEPTH, MAX_RAW_BRACKET_OPENER_COUNT, MAX_RAW_EXTENDED_TEST_COUNT,
        MAX_RAW_LEGACY_ARITH_COUNT, MAX_RAW_PARAM_EXPANSION_COUNT, MAX_RAW_PAREN_NESTING_DEPTH,
        MAX_RAW_PROCESS_SUBST_COUNT, MAX_RAW_STACK_BUDGET, STACK_COST_BRACE, STACK_COST_BRACKET,
        STACK_COST_EXTENDED_TEST_OP, STACK_COST_KEYWORD, STACK_COST_PAREN,
    };

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

    // crash-fuzzer finding: brush-parser 0.4.0 panics converting an
    // out-of-range `~<uid>` digit run to `u64` (`word.rs:909`,
    // `parse::<u64>().unwrap()`). Bash treats an unknown-uid tilde as a
    // literal word, so asserting the parse still *succeeds* (not merely
    // that it doesn't panic) is what keeps a sibling word's blocklist
    // match (e.g. `rm -rf /`) from downgrading to `ask`.
    #[test]
    fn tilde_expression_with_overflowing_uid_is_kept_literal_not_panicked() {
        let cmd = parse_ok("rm -rf / ~41353561361542343807");
        let word = &simple(&cmd.first.first).words[3];
        assert_eq!(
            word.0,
            vec![WordPiece::Literal("~41353561361542343807".to_string())]
        );
    }

    // Same shape, with more text after the overflowing digit run: the
    // remainder must still parse normally rather than being swallowed by
    // the tilde special-case.
    #[test]
    fn tilde_expression_with_overflowing_uid_still_parses_its_remainder() {
        let cmd = parse_ok("echo ~41353561361542343807/x");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![
                WordPiece::Literal("~41353561361542343807".to_string()),
                WordPiece::Literal("/x".to_string()),
            ]
        );
    }

    // issue #456: brush-parser 0.4.0 panics the same unchecked way for the
    // `+`-prefixed dir-stack form (`word.rs:909`,
    // `TildeExpr::NthDirFromTopOfDirStack`) as it does for the unsigned
    // UID form above.
    #[test]
    fn tilde_expression_with_overflowing_dirstack_top_is_kept_literal_not_panicked() {
        let cmd = parse_ok("rm -rf / ~+99999999999999999999");
        let word = &simple(&cmd.first.first).words[3];
        assert_eq!(
            word.0,
            vec![WordPiece::Literal("~+99999999999999999999".to_string())]
        );
    }

    // issue #456: same shape for the `-`-prefixed dir-stack form
    // (`word.rs:911`, `TildeExpr::NthDirFromBottomOfDirStack`).
    #[test]
    fn tilde_expression_with_overflowing_dirstack_bottom_is_kept_literal_not_panicked() {
        let cmd = parse_ok("rm -rf / ~-99999999999999999999");
        let word = &simple(&cmd.first.first).words[3];
        assert_eq!(
            word.0,
            vec![WordPiece::Literal("~-99999999999999999999".to_string())]
        );
    }

    // issue #456 boundary check: a genuinely small, non-overflowing
    // dir-stack reference (well within any real directory stack depth)
    // must still expand as a tilde expression, not get swallowed as
    // literal text by the overflow pre-emption above.
    #[test]
    fn tilde_expression_small_dirstack_top_is_not_treated_as_literal() {
        let cmd = parse_ok("echo ~+2/x");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![
                WordPiece::Tilde("+2".to_string()),
                WordPiece::Literal("/x".to_string()),
            ]
        );
    }

    // Same boundary check for the `-`-prefixed dir-stack form.
    #[test]
    fn tilde_expression_small_dirstack_bottom_is_not_treated_as_literal() {
        let cmd = parse_ok("echo ~-1/x");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![
                WordPiece::Tilde("-1".to_string()),
                WordPiece::Literal("/x".to_string()),
            ]
        );
    }

    // crash-fuzzer finding: brush-parser 0.4.0 panics on a `{`-adjacent
    // digit run past `i64::MAX` (`word.rs:708`, `parse::<i64>().unwrap()`).
    // Verdict impact is limited to the panic itself (a brace-range
    // expansion is already `Unsupported`/`ask` regardless), so this only
    // asserts the parse still fails cleanly — issue #405's
    // `brace_group_panics` now pre-empts this exact shape (no `..` at
    // all) rather than merely containing the panic; see the tests below
    // for cases distinguishing pre-emption from the residual
    // `catch_parser_panic` containment `brace_group_panics`'s own docs
    // disclose it doesn't fully replace.
    #[test]
    fn brace_sequence_number_overflow_is_a_parse_error_not_a_panic() {
        assert!(parse("echo a{9223372036854775808b").is_err());
    }

    // issue #405 (fable review finding): the leading endpoint's `+` sign
    // and an `i64::MIN`-magnitude endpoint under a `-` sign must both
    // still be pre-empted — brush's `number()` rule parses the UNSIGNED
    // digit run and applies the sign only afterward, so `i64::MIN`'s own
    // magnitude (`9223372036854775808`) overflows `i64` even though
    // `i64::MIN` itself does not.
    #[test]
    fn brace_sequence_plus_sign_overflow_is_pre_empted() {
        // Asserts the SPECIFIC pre-emption path (the "brace range
        // expansion" Unsupported message), not merely that the parse
        // fails somehow — `catch_parser_panic`'s pre-existing containment
        // would ALSO make this fail with a different message even if
        // pre-emption itself were disabled, so a bare `.is_err()` here
        // would not actually pin the fix.
        let construct = unsupported_construct("echo {+99999999999999999999..1}");
        assert!(
            construct.contains("brace range expansion"),
            "expected the pre-emption path's rejection, got: {construct}"
        );
    }

    #[test]
    fn brace_sequence_i64_min_magnitude_overflow_is_pre_empted() {
        let construct = unsupported_construct("echo {-9223372036854775808..1}");
        assert!(
            construct.contains("brace range expansion"),
            "expected the pre-emption path's rejection, got: {construct}"
        );
    }

    // issue #405 (fable review finding): a comma anywhere before the
    // closing `}` makes brush's comma-list branch succeed FIRST, so its
    // `number()`-panicking sequence-range branch is never reached at all
    // — a huge leading digit run here does not panic, and the pre-scan
    // must not flag it either (this would otherwise be a NEW
    // Block→Ask/Allow→Ask false-positive downgrade this fix should never
    // introduce).
    #[test]
    fn brace_group_with_a_comma_never_reaches_the_panicking_number_rule() {
        let cmd = parse_ok("echo {99999999999999999999,x}");
        let word = &simple(&cmd.first.first).words[1];
        assert_eq!(
            word.0,
            vec![WordPiece::BraceAlternation(vec![
                Word(vec![WordPiece::Literal("99999999999999999999".to_string())]),
                Word(vec![WordPiece::Literal("x".to_string())]),
            ])]
        );
    }

    // issue #405: `word_contains_overflowing_brace_range` bails (declines
    // to pre-empt) on any word containing a quote/substitution byte —
    // these shapes are then left entirely to brush-parser's own real
    // (correctly quote/substitution-aware) grammar, which handles them
    // without panicking on its own, so the parse must still succeed and
    // any sibling blocklist-worthy word must still be reachable.
    #[test]
    fn brace_ranges_behind_quoting_or_substitution_are_left_to_the_real_parser() {
        for command in [
            r#"rm -rf / "{99999999999999999999..1}""#,
            "rm -rf / '{99999999999999999999..1}'",
            r#"rm -rf / {99999999999999999999"}",x}"#,
            "rm -rf / {99999999999999999999'}',x}",
            "rm -rf / {99999999999999999999$(echo }),y}",
            "rm -rf / {99999999999999999999`echo }`,y}",
            "rm -rf / a$(b{99999999999999999999..1})c",
            "rm -rf / a`b{99999999999999999999..1}`c",
            r#"rm -rf / "$(echo "{99999999999999999999..1}")""#,
            r#"rm -rf / "`echo "{99999999999999999999..1}"`""#,
            r#"rm -rf / a$(x "$(y ")" z)" {99999999999999999999..1})b"#,
        ] {
            let cmd = parse_ok(command);
            assert_eq!(
                simple(&cmd.first.first).words[0].0,
                vec![WordPiece::Literal("rm".to_string())],
                "{command:?} must still parse with its rm -rf / prefix intact"
            );
        }
    }

    // issue #405: an unresolved `{` before a group's `,` doesn't
    // necessarily nest — brush's `non_brace_expr_text`
    // falls back to treating a `{` that never completes its OWN
    // `brace_expr` as ordinary literal text, so the group's real top-level
    // comma can be one the naive `{`/`}` depth count in
    // `brace_group_may_avoid_the_panicking_path` mistook for nested. Both
    // the digit-run word and its sibling `rm -rf /` must survive.
    #[test]
    fn a_dangling_inner_brace_that_brush_treats_as_literal_does_not_hide_the_real_comma() {
        let cmd = parse_ok("rm -rf / {99999999999999999999{a,b");
        assert_eq!(
            simple(&cmd.first.first).words[0].0,
            vec![WordPiece::Literal("rm".to_string())]
        );
    }

    // issue #405: any word containing `$` bails, so a word mixing `${...}`
    // with another brace group is never pre-empted either — this one
    // genuinely still panics in real brush, so the decision falls to
    // `catch_parser_panic`'s containment instead of the pre-emption path.
    // Specifically `Syntax` (containment), not `Unsupported` (pre-emption).
    #[test]
    fn overflowing_brace_range_beside_parameter_expansion_is_contained_not_pre_empted() {
        assert!(matches!(
            parse("echo ${x}{99999999999999999999..1}"),
            Err(ParseError::Syntax { .. })
        ));
    }

    // issue #606: zsh expansion-flag forms are rejected, not read as
    // literal text; quoted or escaped copies stay ordinary text.
    #[test]
    fn parser_rejects_zsh_expansion_flag_forms() {
        for command in [
            "echo ${(e)x}",
            "echo ${=x}",
            "echo ${~x}",
            "echo ${^x}",
            "echo \"${(e)x}\"",
            "echo ${ rm -rf ~; }",
            "echo ${\trm -rf ~; }",
            "echo ${\nrm -rf ~; }",
            "echo \"${ rm -rf ~; }\"",
            "x=rm; $=x -rf ~",
            "echo $~x",
            "echo $^x",
            "echo $+x",
            "echo \"$=x\"",
        ] {
            assert!(
                matches!(parse(command), Err(ParseError::Unsupported { .. })),
                "{command}"
            );
        }
        for command in ["echo '${(e)x}'", "a=b", "echo $", "echo 'x$=y'"] {
            assert!(parse(command).is_ok(), "{command}");
        }
    }

    // A `${...}` with a top-level comma beside a real brace group is split
    // by the brace pre-pass into `$` plus an alternation; it must still be
    // rejected.
    #[test]
    fn parser_rejects_comma_split_dollar_brace_beside_a_brace_group() {
        for command in [
            "echo ${ rm -rf ~; echo ,; }{c,d}",
            "echo {c,d}${ rm -rf ~; echo ,; }",
            "echo ${=x,y}{c,d}",
            "echo {a,{b,${ rm -rf ~; echo ,; }}}",
        ] {
            assert!(
                matches!(parse(command), Err(ParseError::Unsupported { .. })),
                "{command}: {:?}",
                parse(command)
            );
        }
    }

    // issue #640: the `\` exclusion keeps `\${a,b}` on the brace pre-pass.
    #[test]
    fn escaped_dollar_before_a_brace_group_is_still_a_brace_alternation() {
        let cmd = parse_ok("echo \\${a,b}");
        let word = &simple(&cmd.first.first).words[1];
        assert!(
            word.0
                .iter()
                .any(|p| matches!(p, WordPiece::BraceAlternation(_))),
            "{word:?}"
        );
    }

    // issue #640, #655: bash reads `$${` as the PID then `{`, brush as a
    // `${...}` opener, so the word is rejected rather than parsed.
    #[test]
    fn double_dollar_before_a_brace_is_unsupported() {
        for cmd in [
            "echo $${a,b}",
            "echo $${ x; touch /tmp/x; echo }",
            "echo $${x;touch /tmp/x;echo }",
            "echo $${ x\ntouch /tmp/x\necho }",
            "echo $$$${ x; touch /tmp/x; echo }",
            "echo \"$${ x; touch /tmp/x; echo }\"",
        ] {
            assert!(
                matches!(parse(cmd), Err(ParseError::Unsupported { .. })),
                "{cmd:?}: {:?}",
                parse(cmd)
            );
        }
    }

    #[test]
    fn dollar_runs_that_are_not_an_unquoted_even_run_before_a_brace_parse() {
        for cmd in ["echo $$", "echo '$${x}'", "echo $$${x}", "echo ${x}"] {
            assert!(parse(cmd).is_ok(), "{cmd:?}: {:?}", parse(cmd));
        }
    }

    #[test]
    fn escaped_dollar_before_a_brace_is_not_rejected_as_pid_dollars() {
        assert!(!has_pid_dollars_before_brace("\\$${a}"));
        assert!(!has_pid_dollars_before_brace("$'\\'$${x}'"));
        assert!(has_pid_dollars_before_brace("$'\\''$${x}'"));
    }

    // issue #640: a word whose only braces open `${...}` skips the brace
    // pre-pass, so an overflowing digit run inside parses as a plain
    // parameter expansion instead of panicking.
    #[test]
    fn parser_overflowing_numeric_parameter_expansion_does_not_panic() {
        assert!(parse("echo ${99999999999999999999}").is_ok());
        assert!(parse("echo ${-9223372036854775809}").is_ok());
        assert!(matches!(
            parse("echo ${99999999999999999999..1}"),
            Err(ParseError::Unsupported { .. })
        ));
    }

    // crash-fuzzer finding (issue #405): brush-parser 0.4.0 panics on a
    // redirection io-number past `i32::MAX` (`parser/peg.rs:695`,
    // `parse::<i32>().unwrap()`), which — unlike the brace-range shape
    // above — is not itself an unsupported construct, so simply
    // containing the panic would still leave an otherwise-parseable
    // command downgraded to a generic syntax-error `Ask`.
    // `neutralize_overflowing_io_redirect_numbers` inserts a space before
    // the panic-triggering digit run, so this asserts the parse actually
    // SUCCEEDS: the huge digit run survives as an ordinary literal
    // argument word, and the redirect itself parses as an unprefixed
    // (default-fd) `>` targeting `f`.
    #[test]
    fn redirection_io_number_overflow_parses_as_a_literal_argument_not_a_panic() {
        let cmd = parse_ok("echo 2147483648>f");
        let simple = simple(&cmd.first.first);
        assert_eq!(
            simple.words[1].0,
            vec![WordPiece::Literal("2147483648".to_string())]
        );
        match &simple.redirections[0] {
            Redirection::File { kind, target } => {
                assert_eq!(*kind, FileRedirectionKind::Output);
                assert_eq!(target.0, vec![WordPiece::Literal("f".to_string())]);
            }
            other => panic!("expected a File redirection, got {other:?}"),
        }
    }

    // The whole point of issue #405: appending this shape after an
    // otherwise-Block-worthy command must not downgrade the verdict —
    // pinned at the `parse()` level, since `crate::gate` is what actually
    // reaches the Block/Ask decision from this AST.
    #[test]
    fn redirection_io_number_overflow_does_not_swallow_a_sibling_word() {
        let cmd = parse_ok("rm -rf / 99999999999999999999>x");
        let words = &simple(&cmd.first.first).words;
        assert_eq!(words[0].0, vec![WordPiece::Literal("rm".to_string())]);
        assert_eq!(words[1].0, vec![WordPiece::Literal("-rf".to_string())]);
        assert_eq!(words[2].0, vec![WordPiece::Literal("/".to_string())]);
        assert_eq!(
            words[3].0,
            vec![WordPiece::Literal("99999999999999999999".to_string())]
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
    fn case_clause_is_unsupported() {
        let result = parse("case x in x) echo hi;; esac");
        assert!(
            matches!(result, Err(ParseError::Unsupported { .. })),
            "expected an unsupported-construct error, got {result:?}"
        );
    }

    // ---- issue #191: `if`/`elif`/`else` now reaches the rule engine
    // instead of an unconditional Unsupported/Ask ----
    #[test]
    fn if_statement_now_parses() {
        let cmd = parse_ok("if true; then echo x; fi");
        match &cmd.first.first {
            Command::Compound(CompoundCommand::IfClause {
                elifs, else_body, ..
            }) => {
                assert!(elifs.is_empty());
                assert!(else_body.is_none());
            }
            other => panic!("expected an IfClause, got {other:?}"),
        }
    }

    #[test]
    fn if_elif_else_statement_now_parses() {
        let cmd = parse_ok("if false; then echo a; elif false; then echo b; else echo c; fi");
        match &cmd.first.first {
            Command::Compound(CompoundCommand::IfClause {
                elifs, else_body, ..
            }) => {
                assert_eq!(elifs.len(), 1);
                assert!(else_body.is_some());
            }
            other => panic!("expected an IfClause, got {other:?}"),
        }
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

    // ---- issue #191: `&` now reaches the rule engine instead of an
    // unconditional Unsupported/Ask, on either line of a multiline command
    // ----
    #[test]
    fn background_job_on_either_line_of_a_multiline_command_now_parses() {
        let cmd = parse_ok("sleep 1 &\necho done");
        assert_eq!(cmd.rest.len(), 1);
        assert_eq!(
            simple(&cmd.rest[0].1.first).words[0].0,
            vec![WordPiece::Literal("echo".to_string())]
        );

        let cmd = parse_ok("echo start\nsleep 1 &");
        assert_eq!(cmd.rest.len(), 1);
        assert_eq!(
            simple(&cmd.rest[0].1.first).words[0].0,
            vec![WordPiece::Literal("sleep".to_string())]
        );
    }

    // ---- a `name=value`-shaped SUFFIX item is an ordinary argument, not an
    // assignment (see the `AssignmentWord` arm in
    // apply_prefix_or_suffix_item for why) ----
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
    // real environment assignment (see the `AssignmentWord` arm in
    // apply_prefix_or_suffix_item) ----
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
    // MAX_BRACE_NESTING_DEPTH's/MAX_RAW_BRACE_NESTING_DEPTH's docs claim)
    // ----

    // Uses a real, comma-containing brace alternation at every level (not
    // the comma-less `{{{x}}}` shape MAX_RAW_BRACE_NESTING_DEPTH's docs
    // measure) — parses in ~0.004s regardless of depth, per that constant's
    // own docs, so this boundary test itself stays fast.
    #[test]
    fn raw_brace_nesting_at_the_cap_still_parses() {
        let command = format!(
            "echo {}a{}",
            "{a,".repeat(MAX_RAW_BRACE_NESTING_DEPTH),
            "}".repeat(MAX_RAW_BRACE_NESTING_DEPTH)
        );
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn raw_brace_nesting_one_past_the_cap_is_rejected() {
        let command = format!(
            "echo {}a{}",
            "{a,".repeat(MAX_RAW_BRACE_NESTING_DEPTH + 1),
            "}".repeat(MAX_RAW_BRACE_NESTING_DEPTH + 1)
        );
        assert!(parse(&command).is_err());
    }

    // crash-fuzzer finding: a *comma-less* nested brace group (`{{{x}}}`,
    // no `,` at any level) makes brush-parser's PEG grammar backtrack
    // catastrophically — ~6.5x cost growth per two levels, ~7.3s at depth
    // 18, ~47s extrapolated at this test's depth 20. This asserts the raw
    // pre-scan rejects a depth the exponential path would otherwise burn
    // the better part of a minute on, proving the cap is what stops it,
    // not luck.
    #[test]
    fn raw_comma_less_brace_nesting_past_the_new_cap_is_rejected_before_the_exponential_path() {
        let depth = 20;
        let command = format!("echo {}x{}", "{".repeat(depth), "}".repeat(depth));
        assert!(parse(&command).is_err());
    }

    #[test]
    fn raw_paren_nesting_at_the_cap_still_parses() {
        // Plain subshells: `$(` openers are bounded by the tighter
        // `MAX_RAW_BACKTRACK_BUDGET` before the depth cap matters.
        let command = format!(
            "{}echo hi{}",
            "( echo; ".repeat(MAX_RAW_PAREN_NESTING_DEPTH),
            " )".repeat(MAX_RAW_PAREN_NESTING_DEPTH)
        );
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn raw_paren_nesting_one_past_the_cap_is_rejected() {
        let command = format!(
            "{}echo hi{}",
            "( echo; ".repeat(MAX_RAW_PAREN_NESTING_DEPTH + 1),
            " )".repeat(MAX_RAW_PAREN_NESTING_DEPTH + 1)
        );
        assert_eq!(
            unsupported_construct(&command),
            "parenthesis nesting exceeds the raw depth cap"
        );
    }

    #[test]
    fn raw_bracket_count_at_the_cap_still_parses() {
        let command = format!(
            "echo {}0{}",
            "a[".repeat(MAX_RAW_BRACKET_OPENER_COUNT),
            "]".repeat(MAX_RAW_BRACKET_OPENER_COUNT)
        );
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn raw_bracket_count_one_past_the_cap_is_rejected() {
        let command = format!("echo {}", "a[".repeat(MAX_RAW_BRACKET_OPENER_COUNT + 1));
        assert_eq!(
            unsupported_construct(&command),
            "bracket opener count exceeds the raw cap"
        );
    }

    #[test]
    fn raw_bracket_count_is_not_reduced_by_any_closer_shape() {
        // brush does not treat these `]` as closing the subscript, and the
        // count never decrements on `]` anyway, so each must hit the cap.
        for unit in [
            "a[\"]\"",
            "a[']'",
            "a[\\]",
            "a[$']\\']'",
            "a[`]`",
            "a[$(])",
            "a[]",
            "$[]",
        ] {
            let command = format!("echo {}", unit.repeat(MAX_RAW_BRACKET_OPENER_COUNT + 1));
            // The `$(` and `$[` units trip their own (tighter) caps first.
            let expected = if unit.contains('(') {
                "`$(` and `+(` `@(` `!(` `*(` `?(` openers plus other `(` exceed the raw backtracking budget"
            } else if unit.starts_with("$[") {
                "legacy arithmetic opener count exceeds the raw count cap"
            } else {
                "bracket opener count exceeds the raw cap"
            };
            assert_eq!(unsupported_construct(&command), expected, "{unit}");
        }
        // False-positive guard: a realistic number of sequential, properly
        // closed subscripts, up to the cap, must still parse.
        let command = format!("echo {}", "a[\"k\"] ".repeat(MAX_RAW_BRACKET_OPENER_COUNT));
        assert!(parse(&command).is_ok());
    }

    // issue #404: a leading run of unbalanced `(` (no matching `)`
    // anywhere) triggers brush-parser's subshell-vs-arithmetic PEG
    // ambiguity into the same catastrophic backtracking comma-less brace
    // nesting does — this asserts the raw pre-scan rejects a depth the
    // exponential path would otherwise spend seconds of CPU on, proving
    // the cap is what stops it, not luck. Fully unbalanced (no `)` at
    // all), unlike the `$(...)`-pair tests above, since the CPU-DoS shape
    // is specifically a leading run with nothing closing it. Depth is a
    // hardcoded literal, like the sibling comma-less-brace test above
    // (`raw_comma_less_brace_nesting_...`), not derived from
    // `MAX_RAW_PAREN_NESTING_DEPTH`: a depth derived from the cap under
    // test would still exceed a future *raised* cap and pass for the
    // wrong reason, silently stopping this test from ever catching a
    // cap raised back into the vulnerable 17-63 range. 26 is the
    // measured depth that already hits the 2s watchdog on the
    // vulnerable (pre-fix) code.
    #[test]
    fn raw_unbalanced_paren_run_past_the_cap_is_rejected_before_the_exponential_path() {
        let depth = 26;
        assert!(
            depth > MAX_RAW_PAREN_NESTING_DEPTH,
            "cap raised past this test's probe depth — re-measure and re-derive"
        );
        let command = format!("{}a", "(".repeat(depth));
        let start = std::time::Instant::now();
        assert!(parse(&command).is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "rejection took {:?}, expected well under the exponential blowup",
            start.elapsed()
        );
    }

    // ---- issue #401: reject_excessive_raw_nesting's `[[ ... ]]`
    // `!`/`&&`/`||` operator cap. A long UNPARENTHESIZED chain inside
    // `[[ ... ]]` (`[[ a && a && a && ... ]]`, or `[[ ! ! ! ... a ]]`)
    // builds a binary tree one level deeper per operand, with no
    // `{`/`(`/reserved-word byte for the raw pre-scan's other three
    // counters to catch — brush-parser's own recursive descent (or, for
    // the `&&`/`||` shape, the recursive `Drop` of the tree it already
    // built) overflows the stack before `collect_extended_test_words`'s
    // AST-level cap (below) ever gets a chance to run, so this raw count
    // is the primary defense and is boundary-tested the same way the
    // brace/paren/keyword caps above are. ----

    #[test]
    fn extended_test_and_chain_at_the_cap_still_parses() {
        let mut command = "[[ ".to_string();
        for _ in 0..MAX_RAW_EXTENDED_TEST_COUNT {
            command.push_str("-f x && ");
        }
        command.push_str("-f x ]]");
        assert!(parse(&command).is_ok());
    }

    #[test]
    fn extended_test_and_chain_past_the_cap_is_rejected() {
        let mut command = "[[ ".to_string();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT + 1) {
            command.push_str("-f x && ");
        }
        command.push_str("-f x ]]");
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn extended_test_not_chain_past_the_cap_is_rejected() {
        // issue #401's other overflow shape: a long `!`/`!`/`!`... chain,
        // not `&&`/`||`.
        let mut command = "[[ ".to_string();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT + 1) {
            command.push_str("! ");
        }
        command.push_str("-f x ]]");
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn extended_test_or_chain_past_the_cap_is_rejected() {
        let mut command = "[[ ".to_string();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT + 1) {
            command.push_str("-f x || ");
        }
        command.push_str("-f x ]]");
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn extended_test_operator_chain_outside_double_bracket_is_not_capped() {
        // Must not count `!`/`&&`/`||` outside a `[[ ]]` region: a
        // top-level chain of these between ordinary pipelines is flat,
        // not recursive, and legitimate at any length.
        let mut command = String::new();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT + 100) {
            command.push_str("true && ");
        }
        command.push_str("true");
        assert!(parse(&command).is_ok());
    }

    // Issue #489: a quoted `]]` token (`' ]] '`, which tokenizes as a
    // standalone `]]` once surrounded by spaces) must not be able to turn
    // extended-test tracking off mid-region -- brush treats it as a
    // literal, quoted string, not a real closer, so every `!`/`&&`/`||`
    // after it is still inside the same `[[ ... ]]` region and must still
    // be counted, or brush's own unary-negation recursion overflows the
    // stack uncaught once the raw pre-scan undercounts past the real cap.
    #[test]
    fn extended_test_op_count_survives_a_quoted_closer_mid_region() {
        let mut command = "[[ x == ' ]] ' && ".to_string();
        for _ in 0..MAX_RAW_EXTENDED_TEST_COUNT {
            command.push_str("! ");
        }
        command.push_str("y ]]");
        let err = parse(&command).unwrap_err();
        assert!(
            err.to_string().contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection despite the \
             quoted `]]`, got: {err}"
        );
    }

    // Issue #528: a quoted `[[` token inside an already-open real region
    // must not reset the count. Once past the cap every chunk of operators
    // is still counted, however many fake `[[` tokens separate them.
    #[test]
    fn extended_test_op_count_survives_a_quoted_opener_mid_region() {
        let chunk = format!(
            "{}' [[ ' && ",
            "a && ".repeat(MAX_RAW_EXTENDED_TEST_COUNT / 2)
        );
        let command = format!("[[ {} a ]]", chunk.repeat(4));
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection despite the \
             quoted `[[`, got: {construct}"
        );
    }

    #[test]
    fn extended_test_operator_count_sums_across_independent_double_bracket_blocks() {
        // The count is never reset (a reset would be defeatable by a quoted
        // `[[`), so independent blocks sum. Each block alone is under the
        // cap; three together are over it. Accepted over-Ask.
        let mut block = "[[ ".to_string();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT / 2) {
            block.push_str("-f x && ");
        }
        block.push_str("-f x ]]");
        assert!(parse(&block).is_ok());
        let command = format!("{block} && {block} && {block}");
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection, got: {construct}"
        );
    }

    // ---- per-opener never-decremented caps: `$(`, `${`, `$[`, `<(`/`>(`.
    // A quoted/escaped closer hides the real closer from brush while its
    // stack keeps growing, so each count must hold however its closer is
    // hidden. Boundary-tested at the cap and one past it. ----

    fn assert_cap_boundary(unit: &str, cap: usize, prefix: &str, needle: &str) {
        let at_cap = format!("{prefix}{}", unit.repeat(cap));
        assert!(
            !matches!(
                parse(&at_cap),
                Err(ParseError::Unsupported { ref construct }) if construct.contains(needle)
            ),
            "{unit:?} x{cap} must not trip the {needle} cap"
        );
        let past_cap = format!("{prefix}{}", unit.repeat(cap + 1));
        let construct = unsupported_construct(&past_cap);
        assert!(
            construct.contains(needle),
            "{unit:?} x{} expected the {needle} cap, got: {construct}",
            cap + 1
        );
    }

    #[test]
    fn command_substitution_count_is_bounded_by_the_backtrack_budget_despite_a_hidden_closer() {
        for unit in ["$( ')' ", "$( \")\" ", "$( \\) ", "$(echo ) "] {
            assert_cap_boundary(
                unit,
                MAX_RAW_BACKTRACK_BUDGET / BACKTRACK_COST_OPENER,
                "echo ",
                "backtracking budget",
            );
        }
    }

    #[test]
    fn parameter_expansion_count_cap_is_not_defeated_by_a_hidden_closer() {
        for unit in ["${x:-'}' ", "${a/b/'}'", "${x:-\\} "] {
            assert_cap_boundary(
                unit,
                MAX_RAW_PARAM_EXPANSION_COUNT,
                "echo ",
                "parameter expansion opener count",
            );
        }
    }

    #[test]
    fn legacy_arithmetic_count_cap_is_not_defeated_by_a_hidden_closer() {
        for unit in ["$[", "$[ ']' "] {
            assert_cap_boundary(
                unit,
                MAX_RAW_LEGACY_ARITH_COUNT,
                "echo ",
                "legacy arithmetic opener count",
            );
        }
    }

    #[test]
    fn process_substitution_count_cap_is_not_defeated_by_a_hidden_closer() {
        for (unit, prefix) in [
            ("<( ')' ", "cat "),
            (">( ')' ", "tee "),
            ("<( \\) ", "cat "),
        ] {
            assert_cap_boundary(
                unit,
                MAX_RAW_PROCESS_SUBST_COUNT,
                prefix,
                "process substitution opener count",
            );
        }
    }

    // Issue #553: unclosed comma-ful brace groups whose quoted `}` resets
    // the depth counter must be bounded by the never-reset open count, so
    // the summed backtracking cost cannot exceed the time budget.
    #[test]
    fn chained_unclosed_comma_brace_groups_are_rejected_by_the_count_cap() {
        let word = format!("{}'{}'", "{a,b,c,".repeat(10), "}".repeat(10));
        let command = format!("echo {}", vec![word; 8].join(" "));
        let started = std::time::Instant::now();
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("brace opener count"),
            "expected the brace open-count cap, got: {construct}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "rejection must happen in the pre-scan, not after backtracking"
        );
    }

    // Ordinary scripts must stay under every cap.
    #[test]
    fn ordinary_commands_stay_under_the_raw_caps() {
        for command in [
            "echo $(date) $(whoami) ${HOME} ${USER:-x} <(ls) >(cat)",
            "diff <(sort a) <(sort b)",
            "echo $((1 + 2)) $(echo $(echo hi))",
            "[[ -f a && -f b || ! -d c ]] && echo ok",
            "for f in a b; do echo ${f}; done",
            "echo {a,b,c} {1..3} ${x:-{y,z}}",
        ] {
            if let Err(ParseError::Unsupported { construct }) = parse(command) {
                assert!(
                    !construct.contains("exceeds the raw"),
                    "{command} must stay under the caps, got: {construct}"
                );
            }
        }
    }

    // The grammar-level recursions (bare `{` group, bare `(` subshell,
    // `if`/`case`, `<(`, `[[ !`) share one stack and their depths add, so
    // the per-opener caps alone do not compose; `MAX_RAW_STACK_BUDGET` does.
    // Payload spending exactly the budget (330 of 333): the pre-scan admits
    // it, and it is parsed on the test thread's default 2MiB stack, the
    // tighter shipped budget (an overflow aborts the whole test binary).
    fn budget_filling_payload(keyword_unit: &str) -> (String, usize) {
        let (braces, parens, procs, keywords, bangs) = (10, 8, 4, 8, 10);
        let cost = braces * STACK_COST_BRACE
            + (parens + procs) * STACK_COST_PAREN
            + keywords * STACK_COST_KEYWORD
            + 2 * STACK_COST_BRACKET
            + bangs * STACK_COST_EXTENDED_TEST_OP;
        let command = format!(
            "{}{}{}{}[[ {}x ]]",
            "{ '}'; ".repeat(braces),
            "( ')'; ".repeat(parens),
            "cat <( ')'; ".repeat(procs),
            keyword_unit.repeat(keywords),
            "! ".repeat(bangs),
        );
        (command, cost)
    }

    #[test]
    fn grammar_composed_payload_at_the_budget_is_admitted_and_does_not_overflow() {
        for keyword_unit in ["if true; then ", "case x in x) "] {
            let (command, cost) = budget_filling_payload(keyword_unit);
            assert!(cost <= MAX_RAW_STACK_BUDGET, "payload cost {cost}");
            assert!(
                cost + STACK_COST_BRACE > MAX_RAW_STACK_BUDGET,
                "not at the budget"
            );
            if let Err(ParseError::Unsupported { construct }) = parse(&command) {
                assert!(
                    !construct.contains("exceeds the raw"),
                    "the pre-scan must admit the at-budget payload, got: {construct}"
                );
            }
        }
    }

    #[test]
    fn grammar_composed_payload_one_opener_past_the_budget_is_rejected() {
        for keyword_unit in ["if true; then ", "case x in x) "] {
            let (command, _) = budget_filling_payload(keyword_unit);
            let construct = unsupported_construct(&format!("{{ '}}'; {command}"));
            assert!(
                construct.contains("raw stack budget"),
                "expected the combined stack budget, got: {construct}"
            );
        }
    }

    #[test]
    fn coproc_runs_count_toward_the_keyword_cap() {
        let construct = unsupported_construct(&"coproc ".repeat(MAX_KEYWORD_NESTING_COUNT + 1));
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword cap, got: {construct}"
        );
    }

    // `[[&&` with no space: the first `&&` is adjacent to the `[[` token,
    // which has not yet set `in_extended_test` when the `&` is scanned.
    #[test]
    fn extended_test_operator_adjacent_to_the_opener_is_counted() {
        // cost bookkeeping: stay below the combined stack budget so only the
        // operator-count cap can fire (64 ops x 5 = 320 + 2 brackets).
        let command = format!("[[&& {}", "&& ".repeat(MAX_RAW_EXTENDED_TEST_COUNT));
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "the adjacent `&&` must count, got: {construct}"
        );
        let at_cap = format!("[[&& {}", "&& ".repeat(MAX_RAW_EXTENDED_TEST_COUNT - 1));
        assert!(
            !matches!(
                parse(&at_cap),
                Err(ParseError::Unsupported { ref construct })
                    if construct.contains("extended-test operator count")
            ),
            "exactly the cap of operators, including the adjacent one, must pass"
        );
    }

    /// Constructed programmatically, bypassing the raw pre-scan
    /// entirely (unlike the brace test above, no raw command string can
    /// reach this AST shape in practice: any text deep enough to build
    /// this tree also trips `reject_excessive_raw_nesting`'s new operator
    /// count) — pins `collect_extended_test_words`'s own depth cap as a
    /// defense-in-depth backstop in its own right.
    #[test]
    fn ast_level_extended_test_nesting_one_past_the_cap_is_rejected() {
        let leaf = || {
            Box::new(bast::ExtendedTestExpr::UnaryTest(
                bast::UnaryPredicate::FileExists,
                bast::Word {
                    value: "x".to_string(),
                    loc: None,
                },
            ))
        };
        let mut expr = *leaf();
        for _ in 0..=MAX_BRACE_NESTING_DEPTH {
            expr = bast::ExtendedTestExpr::And(Box::new(expr), leaf());
        }
        let mut words = Vec::new();
        let result = collect_extended_test_words(&expr, &mut words, 0);
        assert!(
            matches!(result, Err(ParseError::Unsupported { .. })),
            "expected Unsupported, got {result:?}"
        );
    }

    // brush-parser must always see the ORIGINAL text, never the
    // continuation-stripped scan copy above -- brush ends a `#` comment at
    // the first raw newline regardless of what precedes it, so parsing the
    // stripped copy would hide an arbitrary following command behind
    // `# \<newline>`.
    #[test]
    fn a_command_hidden_behind_a_split_comment_is_not_swallowed() {
        let cmd = parse_ok("echo hi # \\\necho should_still_parse");
        assert_eq!(cmd.rest.len(), 1);
        assert_eq!(
            simple(&cmd.rest[0].1.first).words[0].0,
            vec![WordPiece::Literal("echo".to_string())]
        );
    }

    #[test]
    fn keyword_split_by_a_real_line_continuation_is_detected() {
        let command = format!(
            "{}echo hi{}",
            "i\\\nf true; then ".repeat(MAX_KEYWORD_NESTING_COUNT + 1),
            "; fi".repeat(MAX_KEYWORD_NESTING_COUNT + 1)
        );
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn keyword_split_by_an_even_backslash_run_is_still_two_real_keywords_not_a_bypass() {
        // Two backslashes before the newline: real bash keeps a literal
        // backslash and a real, uncontinued newline, so `if` on the next
        // line is a genuine keyword occurrence to brush, not a glued
        // non-token -- this must still be counted.
        let command = format!(
            "{}echo hi{}",
            "x\\\\\nif true; then ".repeat(MAX_KEYWORD_NESTING_COUNT + 1),
            "; fi".repeat(MAX_KEYWORD_NESTING_COUNT + 1)
        );
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("keyword nesting"),
            "expected the keyword raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn double_bracket_opener_split_by_a_real_line_continuation_is_detected() {
        let mut command = "[\\\n[ ".to_string();
        for _ in 0..(MAX_RAW_EXTENDED_TEST_COUNT + 1) {
            command.push_str("! ");
        }
        command.push_str("x ]]");
        let construct = unsupported_construct(&command);
        assert!(
            construct.contains("extended-test operator count"),
            "expected the extended-test raw-count-cap rejection, got: {construct}"
        );
    }

    #[test]
    fn overflowing_io_number_split_by_a_real_line_continuation_is_neutralized() {
        // Would otherwise panic in brush-parser's io-number rule once its
        // own tokenizer rejoins the split digit run; catch_parser_panic
        // would fold that into a whole-command-line syntax error.
        assert!(parse("echo 21474836\\\n48>f").is_ok());
    }

    #[test]
    fn overflowing_io_number_split_between_the_run_and_the_operator_is_neutralized() {
        assert!(parse("echo 2147483648\\\n>f").is_ok());
    }

    // ---- issue #52 follow-up: reject_excessive_raw_nesting's keyword
    // counter. shguard's AST does not model `case` compound commands at all
    // (issue #191 added `if`; #75 added `while`/`for`/`until` — `case`
    // alone remains unmodeled, module docs), so parse() always rejects a
    // `case` clause as an unsupported construct regardless of nesting depth
    // — these tests distinguish that pre-existing "unsupported construct"
    // rejection from the new keyword-count rejection by asserting which
    // error message comes back, not just that parse() errors. ----

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
            "case x in x) ".repeat(MAX_KEYWORD_NESTING_COUNT),
            ";; esac".repeat(MAX_KEYWORD_NESTING_COUNT)
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
    /// `compat::NESTING_KEYWORDS`, not a separate budget per keyword: none of
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
    fn timed_pipeline_drops_the_leading_option_terminator() {
        let untimed = parse_ok("rm -rf /");
        for command in ["time -- rm -rf /", "time -p -- rm -rf /"] {
            assert_eq!(
                parse_ok(command),
                untimed,
                "{command}: `--` must not remain as the command name"
            );
        }
    }

    #[test]
    fn timed_option_terminator_promotes_following_assignments_to_the_prefix() {
        for (timed, plain) in [
            ("time -- FOO=bar rm -rf /", "FOO=bar rm -rf /"),
            ("time -p -- FOO=bar rm -rf /", "FOO=bar rm -rf /"),
            ("time -- FOO=1 BAR=2 rm -rf /", "FOO=1 BAR=2 rm -rf /"),
            ("time -- FOO=bar sudo rm -rf /", "FOO=bar sudo rm -rf /"),
        ] {
            assert_eq!(parse_ok(timed), parse_ok(plain), "{timed}");
        }
    }

    #[test]
    fn timed_option_terminator_followed_by_a_reserved_word_is_a_parse_error() {
        for command in [
            "time -- ! rm -rf /",
            "time -p -- ! rm -rf /",
            "time -- ! sudo id",
            "time -- coproc rm -rf /",
            "time -- if true",
        ] {
            assert!(parse(command).is_err(), "{command}");
        }
    }

    #[test]
    fn untimed_or_quoted_option_terminator_is_kept_as_the_command() {
        for command in ["-- rm -rf /", r#"time "--" rm -rf /"#] {
            let parsed = parse_ok(command);
            let words = &simple(&parsed.first.first).words;
            assert_eq!(words.len(), 4, "{command}");
        }
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

    fn modified(name: &str, operand: Vec<WordPiece>) -> WordPiece {
        WordPiece::ModifiedParameterExpansion {
            name: name.to_string(),
            operand,
        }
    }

    fn arg_pieces(command: &str) -> Vec<WordPiece> {
        simple(&parse_ok(command).first.first).words[1].0.clone()
    }

    #[test]
    fn modified_expansion_operand_is_reparsed() {
        assert_eq!(
            arg_pieces("echo ${x:-$(echo })}"),
            vec![modified(
                "x",
                vec![WordPiece::CommandSubstitution("echo }".to_string())]
            )]
        );
        assert_eq!(
            arg_pieces("echo ${x:-${y:-z}}"),
            vec![modified(
                "x",
                vec![modified("y", vec![WordPiece::Literal("z".to_string())])]
            )]
        );
        assert_eq!(
            arg_pieces("echo \"${f%.ts}\""),
            vec![WordPiece::DoubleQuoted(vec![modified(
                "f",
                vec![WordPiece::Literal(".ts".to_string())]
            )])]
        );
        assert_eq!(arg_pieces("echo ${x:-}"), vec![modified("x", Vec::new())]);
        assert_eq!(arg_pieces("echo ${x%}"), vec![modified("x", Vec::new())]);
        assert_eq!(arg_pieces("echo ${x:0:3}"), vec![modified("x", Vec::new())]);
    }

    #[test]
    fn pipestatus_literal_index_is_modified_expansion() {
        assert_eq!(
            arg_pieces("echo ${PIPESTATUS[0]}"),
            vec![modified("PIPESTATUS", Vec::new())]
        );
        assert_eq!(
            arg_pieces("echo ${pipestatus[1]}"),
            vec![modified("pipestatus", Vec::new())]
        );
        assert_eq!(
            arg_pieces("echo ${PIPESTATUS[@]}"),
            vec![modified("PIPESTATUS[@]", Vec::new())]
        );
    }

    #[test]
    fn unsupported_parameter_forms_stay_rejected() {
        for command in [
            "echo ${x:$(cmd):3}",
            "echo ${x:-<(echo hi)}",
            "echo ${x:->(cat)}",
            "echo ${x[0]%y}",
            "echo ${!x%y}",
            "echo ${x:=d}",
            "echo ${x=d}",
            "echo ${x@Q}",
            "echo ${arr[0]}",
            "echo ${PIPESTATUS[$i]}",
            "echo ${PIPESTATUS[-1]}",
            "echo ${PIPESTATUS[0]:-x}",
        ] {
            assert!(
                matches!(parse(command), Err(ParseError::Unsupported { .. })),
                "{command}"
            );
        }
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
