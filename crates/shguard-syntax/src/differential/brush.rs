//! Oracle 1: `brush-parser` 0.4.0.
//!
//! Entry points: `Parser::new(reader, &options()).parse_program()` for the
//! command structure, and `brush_parser::word::parse` for the value of each
//! word. The options are the defaults (bash mode: not POSIX, not `sh`;
//! tilde expansion at the start of a word and not after a colon) with
//! extended globbing off, because non-interactive bash starts with `extglob`
//! off.

use super::{AndOrS, CPart, Conn, Shape, SimpleS, canon, corpus, fd_digits, is_name};
use brush_parser::ast::{
    AndOr, AndOrList, Command, CommandPrefixOrSuffixItem, IoFileRedirectKind, IoFileRedirectTarget,
    IoRedirect, Pipeline, SeparatorOperator, SimpleCommand, Word,
};
use brush_parser::word::{Parameter, ParameterExpr, TildeExpr, WordPiece, WordPieceWithSource};
use brush_parser::{Parser, ParserOptions};
use shguard_kernel::ast::Redir;

fn options() -> ParserOptions {
    ParserOptions {
        enable_extended_globbing: false,
        ..ParserOptions::default()
    }
}

/// Text from an `EscapeSequence` piece: `\c` gives `c`, backslash-newline
/// gives nothing.
fn escape_unquoted(raw: &str) -> Result<Vec<u8>, String> {
    let mut chars = raw.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some('\\'), Some('\n'), None) => Ok(Vec::new()),
        (Some('\\'), Some(c), None) => Ok(c.to_string().into_bytes()),
        _ => Err(format!("unexpected escape sequence {raw:?}")),
    }
}

/// Inside double quotes only `\$`, `` \` ``, `\"` and `\\` lose the
/// backslash, and backslash-newline disappears.
fn escape_double(raw: &str) -> Result<Vec<u8>, String> {
    let mut chars = raw.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some('\\'), Some('\n'), None) => Ok(Vec::new()),
        (Some('\\'), Some(c @ ('$' | '`' | '"' | '\\')), None) => Ok(c.to_string().into_bytes()),
        (Some('\\'), Some(_), None) => Ok(raw.as_bytes().to_vec()),
        _ => Err(format!("unexpected escape sequence {raw:?}")),
    }
}

fn parameter(expr: &ParameterExpr) -> Result<CPart, String> {
    if let ParameterExpr::Parameter {
        parameter: Parameter::Named(name),
        indirect: false,
    } = expr
        && is_name(name.as_bytes())
    {
        Ok(CPart::Var(name.as_bytes().to_vec()))
    } else {
        Err(format!("unmappable parameter expansion {expr:?}"))
    }
}

fn map_piece(node: &WordPiece, in_double: bool, out: &mut Vec<CPart>) -> Result<(), String> {
    match node {
        WordPiece::Text(text) | WordPiece::SingleQuotedText(text) => {
            out.push(CPart::Lit(text.as_bytes().to_vec()));
        }
        WordPiece::EscapeSequence(raw) => {
            let bytes = if in_double {
                escape_double(raw)?
            } else {
                escape_unquoted(raw)?
            };
            out.push(CPart::Lit(bytes));
        }
        WordPiece::DoubleQuotedSequence(inner) if !in_double => {
            for item in inner {
                map_piece(&item.piece, true, out)?;
            }
        }
        WordPiece::TildeExpansion(TildeExpr::Home) if !in_double => out.push(CPart::Tilde),
        WordPiece::ParameterExpansion(expr) if in_double => out.push(parameter(expr)?),
        // An unquoted expansion is outside the subset.
        WordPiece::ParameterExpansion(_)
        | WordPiece::AnsiCQuotedText(_)
        | WordPiece::DoubleQuotedSequence(_)
        | WordPiece::GettextDoubleQuotedSequence(_)
        | WordPiece::TildeExpansion(_)
        | WordPiece::CommandSubstitution(_)
        | WordPiece::BackquotedCommandSubstitution(_)
        | WordPiece::ArithmeticExpression(_) => {
            return Err(format!("unmappable word piece {node:?}"));
        }
    }
    Ok(())
}

fn word(word: &Word) -> Result<Vec<CPart>, String> {
    let pieces: Vec<WordPieceWithSource> = brush_parser::word::parse(&word.value, &options())
        .map_err(|err| format!("word parse error on {:?}: {err}", word.value))?;
    let mut out = Vec::new();
    for item in &pieces {
        map_piece(&item.piece, false, &mut out)?;
    }
    Ok(canon(out))
}

/// Parses the text of an assignment-shaped argument with tilde expansion at
/// the start and after colons, and fails if any tilde expansion comes out.
fn assignment_has_no_tilde(word: &Word) -> Result<(), String> {
    let opts = ParserOptions {
        tilde_expansion_at_word_start: true,
        tilde_expansion_after_colon: true,
        ..options()
    };
    let pieces = brush_parser::word::parse(&word.value, &opts)
        .map_err(|err| format!("word parse error on {:?}: {err}", word.value))?;
    if pieces
        .iter()
        .any(|item| matches!(item.piece, WordPiece::TildeExpansion(_)))
    {
        return Err(format!("tilde expanded inside {:?}", word.value));
    }
    Ok(())
}

fn fd_number(fd: i32) -> Result<u8, String> {
    u8::try_from(fd).map_err(|_| format!("descriptor {fd} out of range"))
}

fn redirect(redirect: &IoRedirect) -> Result<Redir, String> {
    let IoRedirect::File(fd, kind, target) = redirect else {
        return Err(format!("unmappable redirect {redirect:?}"));
    };
    let from = match fd {
        Some(fd) => fd_number(*fd)?,
        None => 1,
    };
    match (kind, target) {
        (IoFileRedirectKind::DuplicateOutput, IoFileRedirectTarget::Fd(to)) => Ok(Redir::Dup {
            from,
            to: fd_number(*to)?,
        }),
        (IoFileRedirectKind::DuplicateOutput, IoFileRedirectTarget::Duplicate(target)) => {
            let value = word(target)?;
            match value.as_slice() {
                [CPart::Lit(digits)] => {
                    let to = fd_digits(digits)
                        .ok_or_else(|| format!("duplicate target {target:?} is not a number"))?;
                    Ok(Redir::Dup { from, to })
                }
                _ => Err(format!("unmappable duplicate target {target:?}")),
            }
        }
        (IoFileRedirectKind::Write, IoFileRedirectTarget::Filename(target)) => {
            if word(target)? == [CPart::Lit(b"/dev/null".to_vec())] {
                Ok(Redir::DevNull { fd: from })
            } else {
                Err(format!("unmappable file redirect target {target:?}"))
            }
        }
        _ => Err(format!("unmappable redirect {redirect:?}")),
    }
}

fn simple(command: &SimpleCommand) -> Result<SimpleS, String> {
    let mut words = Vec::new();
    let mut redirs = Vec::new();
    // Before the command name only redirects are acceptable: an assignment
    // there is a real assignment, which the parser rejects.
    if let Some(prefix) = &command.prefix {
        for item in &prefix.0 {
            match item {
                CommandPrefixOrSuffixItem::IoRedirect(r) => redirs.push(redirect(r)?),
                CommandPrefixOrSuffixItem::Word(_)
                | CommandPrefixOrSuffixItem::AssignmentWord(..)
                | CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return Err(format!("unmappable prefix item {item:?}"));
                }
            }
        }
    }
    let name = command.word_or_name.as_ref().ok_or("no command name")?;
    words.push(word(name)?);
    if let Some(suffix) = &command.suffix {
        for item in &suffix.0 {
            match item {
                CommandPrefixOrSuffixItem::IoRedirect(r) => redirs.push(redirect(r)?),
                CommandPrefixOrSuffixItem::Word(w) => words.push(word(w)?),
                // brush-parser tags an argument like `A=b` as an assignment
                // word but keeps the argument's text in the word. After the
                // command name bash reads it as an argument, but outside
                // POSIX mode it still expands a tilde after `=` or `:`, so
                // any tilde expansion there is a disagreement.
                CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                    assignment_has_no_tilde(w)?;
                    words.push(word(w)?);
                }
                CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return Err(format!("unmappable suffix item {item:?}"));
                }
            }
        }
    }
    Ok(SimpleS { words, redirs })
}

fn pipeline(pipeline: &Pipeline) -> Result<Vec<SimpleS>, String> {
    if pipeline.bang || pipeline.timed.is_some() {
        return Err(format!("bang or time on {pipeline:?}"));
    }
    pipeline
        .seq
        .iter()
        .map(|command| match command {
            Command::Simple(s) => simple(s),
            Command::Compound(..) | Command::Function(_) | Command::ExtendedTest(..) => {
                Err(format!("unmappable command {command:?}"))
            }
        })
        .collect()
}

fn and_or(list: &AndOrList) -> Result<AndOrS, String> {
    let first = pipeline(&list.first)?;
    let mut rest = Vec::new();
    for item in &list.additional {
        rest.push(match item {
            AndOr::And(p) => (Conn::And, pipeline(p)?),
            AndOr::Or(p) => (Conn::Or, pipeline(p)?),
        });
    }
    Ok(AndOrS { first, rest })
}

fn shape(input: &str) -> Result<Shape, String> {
    let program = Parser::new(std::io::Cursor::new(input.as_bytes()), &options())
        .parse_program()
        .map_err(|err| format!("brush-parser error: {err}"))?;
    let mut out = Vec::new();
    for complete in &program.complete_commands {
        for item in &complete.0 {
            match item.1 {
                SeparatorOperator::Sequence => out.push(and_or(&item.0)?),
                SeparatorOperator::Async => return Err("background (&)".to_string()),
            }
        }
    }
    Ok(out)
}

#[test]
fn brush_parser_reads_accepted_inputs_as_we_do() {
    corpus().check("brush-parser", shape);
}
