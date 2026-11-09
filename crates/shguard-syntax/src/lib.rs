//! The restricted-subset bash parser. It turns a command string into the
//! kernel's AST, or reports the construct outside the subset that stopped it.
//!
//! `lex` runs first, over the whole input, and [`parse`] builds the AST from
//! its lexemes, so a lexer finding takes precedence over a parser finding
//! wherever each one sits in the input. Of the lexer, only [`Unsupported`]
//! and [`UnsupportedKind`] are public.

#[cfg(test)]
mod differential;
#[cfg(test)]
mod generate;
mod lex;
mod parse;

pub use lex::{Unsupported, UnsupportedKind};
pub use parse::parse;
