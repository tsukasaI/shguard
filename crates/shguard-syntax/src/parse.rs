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
    LexPart, LexRedir, LexWord, Lexeme, Op, Quoting, Token, Unsupported, UnsupportedKind, lex,
    starts_with_assignment,
};
use shguard_kernel::ast::{
    AndOr, Connector, Link, Opaque, Part, Pipeline, Redir, Script, Simple, Word,
};

/// Most words the parser accepts in one script.
const MAX_WORDS: usize = 4096;

/// Words that bash treats as reserved when they start a command.
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
        lexemes: lexemes.into_iter(),
        back: None,
        eof: input.len(),
        words: 0,
    }
    .script()
}

fn fail(kind: UnsupportedKind, offset: usize) -> Unsupported {
    Unsupported { kind, offset }
}

struct Parser {
    lexemes: std::vec::IntoIter<Lexeme>,
    /// One lexeme of lookahead.
    back: Option<Lexeme>,
    /// The input length, the offset of end-of-input errors.
    eof: usize,
    /// Words taken so far.
    words: usize,
}

impl Parser {
    fn next(&mut self) -> Option<Lexeme> {
        self.back.take().or_else(|| self.lexemes.next())
    }

    fn unread(&mut self, lexeme: Lexeme) {
        self.back = Some(lexeme);
    }

    fn peek(&mut self) -> Option<&Lexeme> {
        if self.back.is_none() {
            self.back = self.lexemes.next();
        }
        self.back.as_ref()
    }

    fn skip_newlines(&mut self) {
        while let Some(lexeme) = self.next() {
            if lexeme.token != Token::Op(Op::Newline) {
                self.unread(lexeme);
                return;
            }
        }
    }

    fn script(&mut self) -> Result<Script, Unsupported> {
        let mut items = Vec::new();
        self.skip_newlines();
        while self.peek().is_some() {
            items.push(self.and_or()?);
            match self.next() {
                None => break,
                Some(Lexeme {
                    token: Token::Op(Op::Semi | Op::Newline),
                    ..
                }) => self.skip_newlines(),
                Some(other) => {
                    return Err(fail(UnsupportedKind::UnexpectedToken, other.offset));
                }
            }
        }
        Ok(Script::new(items))
    }

    fn and_or(&mut self) -> Result<AndOr, Unsupported> {
        let first = self.pipeline()?;
        let mut rest = Vec::new();
        while let Some(lexeme) = self.next() {
            let op = match lexeme.token {
                Token::Op(Op::AndIf) => Connector::And,
                Token::Op(Op::OrIf) => Connector::Or,
                Token::Word(_) | Token::Redir(_) | Token::Op(_) => {
                    self.unread(lexeme);
                    break;
                }
            };
            self.skip_newlines();
            rest.push(Link::new(op, self.pipeline()?));
        }
        Ok(AndOr::new(first, rest))
    }

    fn pipeline(&mut self) -> Result<Pipeline, Unsupported> {
        let first = self.simple()?;
        let mut rest = Vec::new();
        while let Some(lexeme) = self.next() {
            if lexeme.token == Token::Op(Op::Pipe) {
                self.skip_newlines();
                rest.push(self.simple()?);
            } else {
                self.unread(lexeme);
                break;
            }
        }
        Ok(Pipeline::with_first(first, rest))
    }

    fn simple(&mut self) -> Result<Simple, Unsupported> {
        let eof = self.eof;
        let start = self.peek().map_or(eof, |lexeme| lexeme.offset);
        let mut first: Option<Word> = None;
        let mut rest = Vec::new();
        let mut redirs = Vec::new();
        while let Some(Lexeme { offset, token }) = self.next() {
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
                    self.unread(Lexeme {
                        offset,
                        token: Token::Op(op),
                    });
                    break;
                }
            }
        }
        match first {
            Some(first) => Ok(Simple::with_first(first, rest, redirs)),
            None if redirs.is_empty() => Err(self.missing_command()),
            None => Err(fail(UnsupportedKind::RedirectOnly, start)),
        }
    }

    /// The error for a command that is expected but not there, looking at
    /// what stands in its place.
    fn missing_command(&mut self) -> Unsupported {
        let eof = self.eof;
        match self.peek() {
            Some(Lexeme {
                offset,
                token: Token::Op(Op::Semi),
            }) => fail(UnsupportedKind::LeadingSeparator, *offset),
            Some(lexeme) => fail(UnsupportedKind::MissingCommand, lexeme.offset),
            None => fail(UnsupportedKind::MissingCommand, eof),
        }
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
