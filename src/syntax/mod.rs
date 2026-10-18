//! Stage 4 of the pipeline (RFC #658, #662): everything that touches
//! `brush-parser` below the AST conversion.
//!
//! Together with `crate::parser`, this module is the only place
//! `brush_parser` types may appear (docs/adr/0001-parser-crate.md,
//! docs/adr/0003-brush-parser-stay-on-0.4.0.md); everything it returns is
//! shguard's own types or a [`ParseError`].
//!
//! - [`compat`]: the bash-compatibility pre-pass run on the raw command
//!   string before brush sees it (nesting caps, line-continuation
//!   handling, the io-number panic guard) and the parser panic catch.
//! - [`heredoc`]: parsing of heredoc bodies and arithmetic text through
//!   brush's own `word::parse_heredoc`.
//! - [`substitution`]: the tokenizer-derived extent of an argument-position
//!   `$(...)` that contains a heredoc.
//!
//! `crate::parser` (conversion into `crate::ast`), `crate::ast` and
//! `crate::normalize` still live outside this module; moving them in is a
//! later, purely mechanical step.

pub(crate) mod compat;
pub(crate) mod heredoc;
pub(crate) mod substitution;

use brush_parser::ParserOptions as BrushParserOptions;

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
    /// cannot represent. See `crate::parser`'s module docs for the full list.
    #[error("unsupported construct: {construct}")]
    Unsupported {
        /// A human-readable description of the unsupported construct.
        construct: String,
    },
}

impl ParseError {
    pub(crate) fn syntax(message: impl Into<String>) -> Self {
        Self::Syntax {
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(construct: impl Into<String>) -> Self {
        Self::Unsupported {
            construct: construct.into(),
        }
    }

    /// The unsupported construct's own description, for issue #471's
    /// category-specific `DenyMessage` at `crate::gate`'s top-level parse
    /// failure site — `None` for [`Self::Syntax`] (a genuine syntax error
    /// names no specific construct to point the agent at). Exposed as a
    /// method rather than a public field: `construct`/`message` stay
    /// private to this module, matching this enum's other fields.
    #[must_use]
    pub(crate) fn unsupported_construct(&self) -> Option<&str> {
        match self {
            Self::Unsupported { construct } => Some(construct),
            Self::Syntax { .. } => None,
        }
    }
}

/// The one set of brush options every parse in this crate uses.
pub(crate) fn parser_options() -> BrushParserOptions {
    BrushParserOptions::default()
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

/// Rejects a run of literal text (one brush left unexpanded) that still
/// carries a `$` form zsh/mksh/bash 5.3 evaluate: `${(e)x}`, `${=x}`,
/// `${ cmd; }`, `$=x`, `$~x`, `$^x`, `$+x`. Shared by words and expanding
/// heredoc bodies so the two cannot drift apart.
pub(crate) fn reject_unresolved_dollar_run(run: &str) -> Result<(), ParseError> {
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
