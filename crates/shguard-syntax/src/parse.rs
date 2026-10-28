//! The parser for the v1 bash subset: lexemes to the kernel AST.
//!
//! Grammar over the lexer's tokens (`NL` is a newline):
//!
//! ```text
//! script   := NL* ( and_or ( sep and_or )* sep? )? NL* EOF
//! sep      := ';' NL* | NL+
//! and_or   := pipeline ( ('&&' | '||') NL* pipeline )*
//! pipeline := simple ( '|' NL* simple )*
//! simple   := (Word | Redir)+        -- at least one Word
//! ```
//!
//! Assumption P1 (bash reads every accepted string as the same AST) is
//! enforced here as well: when bash would reject the input as a syntax error
//! or could read a word as something other than a command name, the parser
//! reports [`Unsupported`]. Accepting is not a claim that the command is
//! safe.

#[cfg(test)]
mod tests;

use crate::lex::{
    LexPart, LexRedir, LexWord, Lexeme, Op, Quoting, Token, Unsupported, UnsupportedKind, fail,
    lex, starts_with_assignment,
};
use shguard_kernel::ast::{
    AndOr, Connector, Link, Opaque, Part, Pipeline, Redir, Script, Simple, Word,
};

/// Most words the parser accepts in one script.
const MAX_WORDS: usize = 4096;

/// Words that bash treats as reserved when they start a command. `[[`, `{`
/// and `}` never reach the parser (the lexer rejects them); they stay so the
/// list equals bash's `word_token_alist`.
const RESERVED: &[&[u8]] = &[
    b"if",
    b"then",
    b"else",
    b"elif",
    b"fi",
    b"case",
    b"esac",
    b"for",
    b"select",
    b"while",
    b"until",
    b"do",
    b"done",
    b"in",
    b"function",
    b"time",
    b"coproc",
    b"!",
    b"[[",
    b"]]",
    b"{",
    b"}",
];

/// Parses `input` into the kernel AST, or reports a construct outside the
/// subset.
///
/// The lexer runs to the end of the input first, so a lexer finding takes
/// precedence over a parser finding wherever each one sits: a reserved word
/// at byte 5 loses to a `$(` at byte 50.
///
/// # Errors
///
/// Returns [`Unsupported`] with the byte offset of the offending token (the
/// input length when the input ends too early).
pub fn parse(input: &[u8]) -> Result<Script, Unsupported> {
    let lexemes = lex(input)?;
    Parser {
        lexemes: lexemes.into_iter().peekable(),
        eof: input.len(),
        words: 0,
    }
    .script()
}

/// What ended a pipeline, other than `|`.
#[derive(Clone, Copy)]
enum AfterPipeline {
    AndIf,
    OrIf,
    Semi,
    Newline,
}

/// What ended an and-or list.
#[derive(Clone, Copy)]
enum Sep {
    Semi,
    Newline,
}

struct Parser {
    lexemes: std::iter::Peekable<std::vec::IntoIter<Lexeme>>,
    /// The input length, the offset of end-of-input errors.
    eof: usize,
    /// Words taken so far.
    words: usize,
}

impl Parser {
    fn skip_newlines(&mut self) {
        while self
            .lexemes
            .next_if(|lexeme| lexeme.token == Token::Op(Op::Newline))
            .is_some()
        {}
    }

    fn script(&mut self) -> Result<Script, Unsupported> {
        let mut items = Vec::new();
        self.skip_newlines();
        while self.lexemes.peek().is_some() {
            let (item, sep) = self.and_or()?;
            items.push(item);
            match sep {
                None => break,
                Some(Sep::Semi | Sep::Newline) => self.skip_newlines(),
            }
        }
        Ok(Script::new(items))
    }

    /// Parses an and-or list and returns the separator that ended it, or
    /// `None` at the end of the input.
    fn and_or(&mut self) -> Result<(AndOr, Option<Sep>), Unsupported> {
        let (first, mut after) = self.pipeline()?;
        let mut rest = Vec::new();
        let sep = loop {
            let connector = match after {
                Some(AfterPipeline::AndIf) => Connector::And,
                Some(AfterPipeline::OrIf) => Connector::Or,
                Some(AfterPipeline::Semi) => break Some(Sep::Semi),
                Some(AfterPipeline::Newline) => break Some(Sep::Newline),
                None => break None,
            };
            self.skip_newlines();
            let (pipeline, next) = self.pipeline()?;
            rest.push(Link::new(connector, pipeline));
            after = next;
        };
        Ok((AndOr::new(first, rest), sep))
    }

    /// Parses a pipeline and returns the operator that ended it, or `None`
    /// at the end of the input.
    fn pipeline(&mut self) -> Result<(Pipeline, Option<AfterPipeline>), Unsupported> {
        let (first, mut end) = self.simple()?;
        let mut rest = Vec::new();
        let after = loop {
            match end {
                Some(Op::Pipe) => {
                    self.skip_newlines();
                    let (simple, next) = self.simple()?;
                    rest.push(simple);
                    end = next;
                }
                Some(Op::AndIf) => break Some(AfterPipeline::AndIf),
                Some(Op::OrIf) => break Some(AfterPipeline::OrIf),
                Some(Op::Semi) => break Some(AfterPipeline::Semi),
                Some(Op::Newline) => break Some(AfterPipeline::Newline),
                None => break None,
            }
        };
        Ok((Pipeline::with_first(first, rest), after))
    }

    /// Parses a simple command and returns the operator that ended it, or
    /// `None` at the end of the input.
    fn simple(&mut self) -> Result<(Simple, Option<Op>), Unsupported> {
        let eof = self.eof;
        let start = self.lexemes.peek().map_or(eof, |lexeme| lexeme.offset);
        let mut first: Option<Word> = None;
        let mut rest = Vec::new();
        let mut redirs = Vec::new();
        // The operator that ended the command and where it stands.
        let mut end: Option<(Op, usize)> = None;
        for Lexeme { offset, token, .. } in self.lexemes.by_ref() {
            match token {
                Token::Word(lex_word) => {
                    if self.words >= MAX_WORDS {
                        return Err(fail(UnsupportedKind::TooManyWords, offset));
                    }
                    self.words += 1;
                    if first.is_none() {
                        check_command_name(&lex_word, offset)?;
                        first = Some(convert_word(lex_word));
                    } else {
                        rest.push(convert_word(lex_word));
                    }
                }
                Token::Redir(redir) => redirs.push(convert_redir(redir)),
                Token::Op(op) => {
                    end = Some((op, offset));
                    break;
                }
            }
        }
        match first {
            Some(first) => Ok((
                Simple::with_first(first, rest, redirs),
                end.map(|(op, _)| op),
            )),
            None if redirs.is_empty() => Err(missing_command(end, eof)),
            None => Err(fail(UnsupportedKind::RedirectOnly, start)),
        }
    }
}

/// The error for a command that is expected but not there, looking at the
/// operator (or the end of the input) that stands in its place. A `Newline`
/// cannot reach it, because every caller skips newlines first.
fn missing_command(end: Option<(Op, usize)>, eof: usize) -> Unsupported {
    match end {
        Some((Op::Semi, offset)) => fail(UnsupportedKind::LeadingSeparator, offset),
        Some((Op::Newline | Op::Pipe | Op::AndIf | Op::OrIf, offset)) => {
            fail(UnsupportedKind::MissingCommand, offset)
        }
        None => fail(UnsupportedKind::MissingCommand, eof),
    }
}

/// A reserved word or an assignment in command position is not a command
/// name. Bash recognises a reserved word only where a command may start, so
/// checking the first word of every simple command covers that position; the
/// only mismatch is rejecting `>/dev/null if x`, which is the safe side.
fn check_command_name(word: &LexWord, offset: usize) -> Result<(), Unsupported> {
    match word.first() {
        LexPart::Lit {
            bytes,
            quoting: Quoting::Unquoted,
        } => {
            if starts_with_assignment(bytes) {
                Err(fail(UnsupportedKind::Assignment, offset))
            } else if word.rest().is_empty() && RESERVED.contains(&bytes.as_slice()) {
                Err(fail(UnsupportedKind::ReservedWord, offset))
            } else {
                Ok(())
            }
        }
        LexPart::Lit {
            quoting: Quoting::Quoted,
            ..
        }
        | LexPart::Var(_)
        | LexPart::Tilde => Ok(()),
    }
}

fn convert_part(part: LexPart) -> Part {
    match part {
        LexPart::Lit { bytes, .. } => Part::Lit(bytes),
        LexPart::Var(name) => Part::Opaque(Opaque::Var(name)),
        LexPart::Tilde => Part::Opaque(Opaque::Tilde),
    }
}

fn convert_word(word: LexWord) -> Word {
    let (first, rest) = word.into_parts();
    Word::with_first(
        convert_part(first),
        rest.into_iter().map(convert_part).collect(),
    )
}

fn convert_redir(redir: LexRedir) -> Redir {
    match redir {
        LexRedir::Dup { from, to } => Redir::Dup { from, to },
        LexRedir::DevNull { fd } => Redir::DevNull { fd },
    }
}
