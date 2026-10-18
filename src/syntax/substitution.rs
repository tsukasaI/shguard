//! Heredoc-aware extents for argument-position `$(...)` (issue #631).
//!
//! brush's word grammar finds the end of a `$(...)` with a quote-aware but
//! heredoc-unaware scan, so a `)` or a `'...'` pair in a heredoc body ends the
//! substitution inside the body. The command tokenizer, which already
//! delimited the word, does track heredoc state. [`mask`] asks it for the real
//! extent and swaps each heredoc-bearing `$(...)` for an opaque placeholder
//! the word grammar cannot misread; [`Masked::restore`] puts the real inner
//! command back, so `gate::analyze_at_depth` parses it as a whole program.

use brush_parser::{Token, uncached_tokenize_str};

use super::compat::catch_parser_panic;
use super::{ParseError, parser_options};
use crate::ast::{Word, WordPiece};

/// Not a character the placeholder's index could collide with, and refused in
/// the input (see [`mask`]) so a literal copy cannot impersonate a placeholder.
const SENTINEL: char = '\u{1}';

/// Total bytes handed to the tokenizer while looking for the closing `)` of
/// one word. Each candidate `)` costs a tokenization of the prefix up to it,
/// so this bounds the quadratic case; past it the word keeps today's parse.
const TOKENIZE_BUDGET_BYTES: usize = 2 << 20;

/// A word whose heredoc-bearing substitutions were swapped for placeholders.
#[derive(Debug)]
pub(crate) struct Masked {
    pub(crate) text: String,
    originals: Vec<String>,
}

impl Masked {
    /// Puts each original inner command back where its placeholder was
    /// converted to a `CommandSubstitution`.
    ///
    /// # Errors
    ///
    /// A placeholder the word grammar buried anywhere else (inside an
    /// arithmetic expression, a split brace group, ...) would leave a
    /// substitution unanalysed, so any placeholder not restored is an error.
    pub(crate) fn restore(&self, word: &mut Word) -> Result<(), ParseError> {
        let mut restored = 0;
        self.restore_pieces(&mut word.0, &mut restored);
        if restored == self.originals.len() {
            Ok(())
        } else {
            Err(ParseError::unsupported(
                "heredoc command substitution inside a construct shguard cannot re-read",
            ))
        }
    }

    fn restore_pieces(&self, pieces: &mut [WordPiece], restored: &mut usize) {
        for piece in pieces {
            match piece {
                WordPiece::CommandSubstitution(inner) => {
                    if let Some(original) = self.original_for(inner) {
                        original.clone_into(inner);
                        *restored += 1;
                    }
                }
                WordPiece::DoubleQuoted(inner) => self.restore_pieces(inner, restored),
                WordPiece::ModifiedParameterExpansion { operand, .. } => {
                    self.restore_pieces(operand, restored);
                }
                WordPiece::BraceAlternation(words) => {
                    for word in words {
                        self.restore_pieces(&mut word.0, restored);
                    }
                }
                _ => {}
            }
        }
    }

    fn original_for(&self, inner: &str) -> Option<&str> {
        let index = inner
            .strip_prefix(SENTINEL)?
            .strip_suffix(SENTINEL)?
            .parse::<usize>()
            .ok()?;
        self.originals.get(index).map(String::as_str)
    }
}

/// Replaces every `$(...)` in `raw` that contains a heredoc by a placeholder
/// substitution, using the tokenizer's extent for the closing `)`.
///
/// Returns `None` when nothing is replaced — no heredoc-bearing `$(`, or an
/// extent that cannot be established within the budget — so the word keeps
/// the grammar's own reading, which floors an unparsable truncation to `Ask`.
///
/// # Errors
///
/// `raw` already contains the placeholder sentinel, or the tokenizer panics.
pub(crate) fn mask(raw: &str) -> Result<Option<Masked>, ParseError> {
    if !(raw.contains("$(") && raw.contains("<<")) {
        return Ok(None);
    }
    if raw.contains(SENTINEL) {
        return Err(ParseError::unsupported(
            "control character reserved for heredoc substitution handling",
        ));
    }

    let bytes = raw.as_bytes();
    let mut text = String::new();
    let mut originals = Vec::new();
    let mut budget = TOKENIZE_BUDGET_BYTES;
    let mut copied_to = 0;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\'' if !in_double => match closing_quote(bytes, i + 1, false) {
                Some(end) => i = end + 1,
                None => return Ok(None),
            },
            b'`' => match closing_backquote(bytes, i + 1) {
                Some(end) => i = end + 1,
                None => return Ok(None),
            },
            b'"' => {
                in_double = !in_double;
                i += 1;
            }
            b'$' => {
                let run_end = i + bytes[i..].iter().take_while(|&&b| b == b'$').count();
                let odd_run = (run_end - i) % 2 == 1;
                match bytes.get(run_end) {
                    Some(b'\'') if odd_run && !in_double => {
                        match closing_quote(bytes, run_end + 1, true) {
                            Some(end) => i = end + 1,
                            None => return Ok(None),
                        }
                    }
                    Some(b'(') if odd_run && bytes.get(run_end + 1) != Some(&b'(') => {
                        let start = run_end - 1;
                        if !raw[start..].contains("<<") {
                            i = run_end + 1;
                            continue;
                        }
                        let Some(close) = closing_paren(raw, run_end + 1, &mut budget)? else {
                            return Ok(None);
                        };
                        let span_end = close + 1;
                        if raw[start..span_end].contains("<<") {
                            text.push_str(&raw[copied_to..start]);
                            text.push_str(&format!("$({SENTINEL}{}{SENTINEL})", originals.len()));
                            originals.push(raw[run_end + 1..close].to_owned());
                            copied_to = span_end;
                        }
                        i = span_end;
                    }
                    _ => i = run_end,
                }
            }
            _ => i += 1,
        }
    }

    if originals.is_empty() {
        return Ok(None);
    }
    text.push_str(&raw[copied_to..]);
    Ok(Some(Masked { text, originals }))
}

/// Index of the `'` closing a quote whose content starts at `from`. In
/// ANSI-C quoting (`$'...'`) a backslash escapes the next byte.
fn closing_quote(bytes: &[u8], from: usize, ansi_c: bool) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if ansi_c => i += 2,
            b'\'' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn closing_backquote(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'`' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Byte index of the `)` that closes the substitution whose inner command
/// starts at `inner_start`: the first `)` such that `(` + the inner text up to
/// it tokenizes cleanly and that final `)` brings the parenthesis depth back
/// to zero. A `)` inside a heredoc body leaves the heredoc unterminated in the
/// prefix, which the tokenizer rejects, so such a candidate is skipped.
///
/// A heredoc body whose first line starts with `)` is read by the tokenizer as
/// an operator, closing the substitution early; that falls to `Ask`, a safe
/// over-ask kept rather than special-cased.
fn closing_paren(
    raw: &str,
    inner_start: usize,
    budget: &mut usize,
) -> Result<Option<usize>, ParseError> {
    let options = parser_options().tokenizer_options();
    for (offset, _) in raw[inner_start..].match_indices(')') {
        let close = inner_start + offset;
        let candidate = format!("({}", &raw[inner_start..=close]);
        let Some(left) = budget.checked_sub(candidate.len()) else {
            return Ok(None);
        };
        *budget = left;
        if let Ok(tokens) = catch_parser_panic(|| uncached_tokenize_str(&candidate, &options))?
            && closes_at_last_token(&tokens)
        {
            return Ok(Some(close));
        }
    }
    Ok(None)
}

fn closes_at_last_token(tokens: &[Token]) -> bool {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        let Token::Operator(operator, _) = token else {
            continue;
        };
        match operator.as_str() {
            "(" => depth += 1,
            ")" => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
                if depth == 0 {
                    return index + 1 == tokens.len();
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner_of(raw: &str) -> Vec<String> {
        match mask(raw) {
            Ok(Some(masked)) => masked.originals,
            other => panic!("expected {raw:?} to mask, got {other:?}"),
        }
    }

    #[test]
    fn paren_in_heredoc_body_does_not_close_the_substitution() {
        assert_eq!(
            inner_of("\"$(cat <<'EOF'\n1) first\nEOF\n)\""),
            ["cat <<'EOF'\n1) first\nEOF\n"]
        );
    }

    #[test]
    fn command_after_the_heredoc_stays_inside_the_substitution() {
        assert_eq!(
            inner_of("\"$(cat <<'EOF'\nx)\nEOF\nrm -rf /\n)\""),
            ["cat <<'EOF'\nx)\nEOF\nrm -rf /\n"]
        );
    }

    #[test]
    fn unterminated_heredoc_keeps_the_grammar_reading() {
        assert!(matches!(mask("\"$(cat <<'EOF'\nx)\n)\""), Ok(None)));
    }

    #[test]
    fn single_quoted_opener_is_not_a_substitution() {
        assert!(matches!(mask("'$(cat <<EOF)'"), Ok(None)));
    }

    #[test]
    fn command_after_the_heredoc_is_analysed_wherever_the_substitution_sits() {
        use crate::verdict::Decision;
        for (command, expected) in [
            (
                "echo {a,\"$(cat <<E\nx)\nE\nrm -rf /\n)\"}",
                Decision::Block,
            ),
            (
                "echo \"${x:-$(cat <<E\nx)\nE\nrm -rf /\n)}\"",
                Decision::Block,
            ),
            (
                "echo \"$(cat <<E\nx\nE\n# )\nrm -rf /\n)\"",
                Decision::Block,
            ),
            (
                "echo \"$(echo a; cat <<E\nx)\nE\n) $(cat <<F\ny)\nF\nrm -rf /\n)\"",
                Decision::Block,
            ),
            ("echo $(( $(cat <<E\nx)\nE\n) ))", Decision::Ask),
            (
                "echo \"$(cat <<E\nx\nE\ncase y in a) rm -rf /;; esac)\"",
                Decision::Ask,
            ),
        ] {
            assert_eq!(crate::analyze(command).decision(), expected, "{command:?}");
        }
    }

    #[test]
    fn sentinel_in_the_input_is_refused() {
        assert!(mask("$(cat <<E\n\u{1}\nE\n)").is_err());
    }
}
