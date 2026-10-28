//! The restricted-subset bash parser. It turns a command string into the
//! kernel's AST, or reports the first construct outside the subset.

mod lex;

pub use lex::{LexPart, LexRedir, LexWord, Op, Quoting, Token, Unsupported, UnsupportedKind, lex};
