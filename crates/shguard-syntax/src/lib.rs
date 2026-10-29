//! The restricted-subset bash parser. It turns a command string into the
//! kernel's AST, or reports the construct outside the subset that stopped it.
//!
//! [`lex`] runs first, over the whole input, and [`parse`] builds the AST from
//! its lexemes; the lexer types stay public for differential tests. A lexer
//! finding therefore takes precedence over a parser finding wherever each one
//! sits in the input.

#[cfg(test)]
mod differential;
#[cfg(test)]
mod generate;
mod lex;
mod parse;

pub use lex::{
    LexPart, LexRedir, LexWord, Lexeme, Op, Quoting, Token, Unsupported, UnsupportedKind, lex,
};
pub use parse::parse;
