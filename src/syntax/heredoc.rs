//! Heredoc-body parsing (RFC #658 stage 4, #662): finds the command and
//! backquote substitutions an unquoted-delimiter heredoc body (or the text of
//! a `$((...))`) will expand, using brush's own heredoc grammar
//! (`word::parse_heredoc`) instead of a hand-written re-lexer.

use brush_parser::word::{self as bword, WordPiece};

use super::compat::{catch_parser_panic, strip_raw_line_continuations_blind};
use super::{ParseError, parser_options};

/// The raw inner text of every top-level `$(...)` and backquote substitution
/// in `body`, in source order.
///
/// Nested substitutions stay inside their parent's text for
/// `gate::analyze_at_depth` to find on the next level. Substitutions hidden in
/// an arithmetic expression (`$(( $(cmd) ))`, `$[ $(cmd) ]`) or in a `${...}`
/// operand or subscript are extracted here, because brush hands those back as
/// opaque text; they are re-fed through the same grammar from a heap-allocated
/// worklist, so nesting depth never costs call-stack frames. Each re-fed text
/// is strictly shorter than its parent, which bounds the loop.
///
/// # Errors
///
/// Fails closed: any text brush cannot delimit comes back as a `ParseError`
/// the caller must treat as `Ask`. In particular brush reads an unterminated
/// `$(` or `$[` as literal text rather than rejecting it, so a joined run of
/// literal text still containing `$(`, `$[` or a backquote is an error.
pub(crate) fn parse_body(body: &str) -> Result<Vec<String>, ParseError> {
    let mut substitutions = Vec::new();
    let mut worklist = vec![body.to_owned()];
    while let Some(text) = worklist.pop() {
        for item in parse_text(&text)? {
            match item {
                Found::Substitution(inner) => substitutions.push(inner),
                Found::Nested(nested) => worklist.push(nested),
            }
        }
    }
    Ok(substitutions)
}

enum Found {
    Substitution(String),
    Nested(String),
}

fn parse_text(text: &str) -> Result<Vec<Found>, ParseError> {
    let options = parser_options();
    let pieces = catch_parser_panic(|| bword::parse_heredoc(text, &options))?
        .map_err(|err| ParseError::syntax(format!("heredoc body: {err}")))?;

    let mut found = Vec::new();
    let mut literal_run = String::new();
    for with_source in pieces {
        if let WordPiece::Text(literal) = &with_source.piece {
            literal_run.push_str(literal);
            continue;
        }
        reject_unterminated_opener(&literal_run)?;
        literal_run.clear();

        match with_source.piece {
            WordPiece::EscapeSequence(_) => {}
            WordPiece::CommandSubstitution(inner) => {
                reject_comment_in_substitution(&inner)?;
                found.push(Found::Substitution(inner));
            }
            WordPiece::BackquotedCommandSubstitution(inner) => {
                found.push(Found::Substitution(decode_backquote_escapes(&inner)));
            }
            WordPiece::ArithmeticExpression(expression) => {
                found.push(Found::Nested(expression.value));
            }
            WordPiece::ParameterExpansion(_) => {
                if let Some(inner) = braced_parameter_inner(
                    text.get(with_source.start_index..with_source.end_index),
                )? {
                    found.push(Found::Nested(inner.to_owned()));
                }
            }
            WordPiece::Text(_)
            | WordPiece::SingleQuotedText(_)
            | WordPiece::AnsiCQuotedText(_)
            | WordPiece::DoubleQuotedSequence(_)
            | WordPiece::GettextDoubleQuotedSequence(_)
            | WordPiece::TildeExpansion(_) => {
                return Err(ParseError::unsupported(
                    "heredoc body piece the heredoc grammar should not produce",
                ));
            }
        }
    }
    reject_unterminated_opener(&literal_run)?;
    Ok(found)
}

/// The text between the braces of a `${...}` piece, or `None` for a plain
/// `$name`/`$1`/`$$` piece, which carries no operand to scan.
fn braced_parameter_inner(source: Option<&str>) -> Result<Option<&str>, ParseError> {
    let source = source.ok_or_else(|| ParseError::syntax("heredoc body: piece span is invalid"))?;
    let Some(rest) = source.strip_prefix("${") else {
        return Ok(None);
    };
    rest.strip_suffix('}').map(Some).ok_or_else(|| {
        ParseError::unsupported("heredoc `${...}` expansion without a closing brace")
    })
}

/// Bash removes `\<newline>` from an expanding heredoc body before any
/// expansion, so `$\<newline>(cmd)` is a real substitution; brush keeps it raw.
pub(crate) fn strip_line_continuations(body: &str) -> String {
    strip_raw_line_continuations_blind(body).into_owned()
}

/// Bash decodes `\$` and `\\` (as well as `` \` ``) inside backquotes before
/// running the text; brush's `backquoted_char` decodes only `` \` ``. Left to
/// right, so `\\$` is a backslash then `$`.
pub(crate) fn decode_backquote_escapes(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && matches!(chars.peek(), Some('$' | '\\')) {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Not a comment-aware scan: brush's word-level command rule has no comment
/// concept, so a `)` after a `#` closes the substitution here while bash
/// treats it as comment text. Over-asks on any unquoted word-start `#`.
fn reject_comment_in_substitution(inner: &str) -> Result<(), ParseError> {
    let mut quote: Option<char> = None;
    let mut prev: Option<char> = None;
    for c in inner.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                } else if c == '#'
                    && prev.is_none_or(|p| p.is_whitespace() || matches!(p, ';' | '|' | '&' | '('))
                {
                    return Err(ParseError::unsupported(
                        "`#` comment inside a heredoc command substitution",
                    ));
                }
            }
        }
        prev = Some(c);
    }
    Ok(())
}

fn reject_unterminated_opener(literal: &str) -> Result<(), ParseError> {
    if literal.contains("$(") || literal.contains("$[") || literal.contains('`') {
        return Err(ParseError::unsupported(
            "heredoc body contains a `$(`, `$[` or backquote that never closes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subs(body: &str) -> Vec<String> {
        match parse_body(body) {
            Ok(found) => found,
            Err(err) => panic!("expected {body:?} to parse, got {err:?}"),
        }
    }

    fn rejected(body: &str) {
        assert!(
            parse_body(body).is_err(),
            "expected {body:?} to be rejected"
        );
    }

    #[test]
    fn comment_inside_a_substitution_is_rejected() {
        rejected("$(echo hi # )\nrm -rf /)");
        rejected("$(echo hi #)");
        rejected("$(echo hi;#x\n)");
        assert_eq!(subs("$(echo a#b \"# x\" '#')"), ["echo a#b \"# x\" '#'"]);
    }

    #[test]
    fn backquote_escapes_are_decoded() {
        assert_eq!(
            decode_backquote_escapes(r"echo \$(x) \\ \a"),
            r"echo $(x) \ \a"
        );
        assert_eq!(decode_backquote_escapes(r"\\$"), r"\$");
        assert_eq!(subs(r#"`echo "\$(rm -rf /)"`"#), [r#"echo "$(rm -rf /)""#]);
    }

    #[test]
    fn prose_has_no_substitutions() {
        assert!(subs("just some prose, no substitutions here").is_empty());
    }

    #[test]
    fn dollar_paren_is_extracted() {
        assert_eq!(subs("before $(rm -rf /) after"), ["rm -rf /"]);
    }

    #[test]
    fn backquote_is_extracted() {
        assert_eq!(subs("before `rm -rf /` after"), ["rm -rf /"]);
    }

    #[test]
    fn nested_substitution_stays_inside_the_outer_span() {
        assert_eq!(subs("$(echo $(date))"), ["echo $(date)"]);
    }

    #[test]
    fn quoted_close_paren_does_not_end_the_span() {
        assert_eq!(subs(r#"$(echo ")")"#), [r#"echo ")""#]);
    }

    // Heredoc bodies treat quotes as literal text, so a quoted substitution
    // at the body's top level still runs.
    #[test]
    fn quotes_are_inert_at_the_body_top_level() {
        assert_eq!(subs("'$(rm -rf /)'"), ["rm -rf /"]);
    }

    #[test]
    fn escaped_openers_are_inert() {
        assert!(subs(r"\$(rm -rf /) \`rm -rf /\` \\ x").is_empty());
    }

    #[test]
    fn escaped_backslash_then_substitution_still_runs() {
        assert_eq!(subs(r"\\$(rm -rf /)"), ["rm -rf /"]);
    }

    #[test]
    fn plain_arithmetic_is_not_a_substitution() {
        assert!(subs("$((x+1))").is_empty());
        assert!(subs("$[x+1]").is_empty());
    }

    #[test]
    fn substitution_nested_in_arithmetic_is_extracted() {
        assert_eq!(subs("$(($(rm -rf /)))"), ["rm -rf /"]);
        assert_eq!(subs("$[ $(rm -rf /) + 1 ]"), ["rm -rf /"]);
    }

    #[test]
    fn substitution_in_a_parameter_operand_is_extracted() {
        assert_eq!(subs("${x:-$(rm -rf /)}"), ["rm -rf /"]);
        assert_eq!(subs("${x:-${y:-$(rm -rf /)}}"), ["rm -rf /"]);
        assert_eq!(subs("${x/a/$(rm -rf /)}"), ["rm -rf /"]);
    }

    #[test]
    fn substitution_in_an_array_subscript_is_extracted() {
        assert_eq!(subs("${a[$(rm -rf /)]}"), ["rm -rf /"]);
    }

    #[test]
    fn substitution_in_a_substring_offset_is_extracted() {
        assert_eq!(subs("${x:$(rm -rf /):1}"), ["rm -rf /"]);
    }

    #[test]
    fn plain_parameters_carry_no_substitution() {
        assert!(subs("$HOME ${HOME} $1 $$ ${#x}").is_empty());
    }

    #[test]
    fn several_substitutions_are_all_found() {
        let mut found = subs("$(a) text `b` ${x:-$(c)}");
        found.sort();
        assert_eq!(found, ["a", "b", "c"]);
    }

    // Unterminated openers: brush parses them as literal text, so the
    // mandatory post-check is what keeps them fail-closed.
    #[test]
    fn unterminated_openers_are_rejected() {
        rejected("$(rm -rf /");
        rejected("`rm -rf /");
        rejected("$((x+1");
        rejected("$[x+1");
        rejected("a $(echo ok) $(rm -rf /");
        rejected("${x:-$(rm -rf /}");
    }

    #[test]
    fn unterminated_opener_inside_an_arithmetic_or_operand_is_rejected() {
        rejected("$(( $(rm ))");
        rejected("${x:-`rm}");
    }

    // Span parity with the retired hand-written scanner (issue #69).
    #[test]
    fn ansi_c_escaped_quote_does_not_end_the_string() {
        assert_eq!(
            subs(r"$(echo $'it\'s'; rm -rf /)"),
            [r"echo $'it\'s'; rm -rf /"]
        );
    }

    #[test]
    fn ansi_c_string_containing_a_literal_paren() {
        assert_eq!(subs(r"$(echo $'a)b')"), [r"echo $'a)b'"]);
    }

    #[test]
    fn escaped_paren_does_not_affect_depth() {
        assert_eq!(subs(r"$(echo \) ; rm -rf /)"), [r"echo \) ; rm -rf /"]);
    }

    #[test]
    fn escaped_paren_inside_double_quotes_still_works() {
        assert_eq!(subs(r#"$(echo "\)")"#), [r#"echo "\)""#]);
    }

    #[test]
    fn double_backslash_still_closes_on_the_following_paren() {
        assert_eq!(subs(r"$(echo \\)"), [r"echo \\"]);
    }

    #[test]
    fn plain_single_quotes_have_no_escape_processing() {
        assert_eq!(subs(r"$(echo 'a\'; rm -rf /)"), [r"echo 'a\'; rm -rf /"]);
    }

    #[test]
    fn trailing_lone_backslash_is_unterminated() {
        rejected(r"$(foo \");
    }

    #[test]
    fn unterminated_ansi_c_string_is_rejected() {
        rejected(r"$(echo $'abc");
    }

    #[test]
    fn empty_ansi_c_string_is_handled() {
        assert_eq!(subs(r"$(echo $''; rm -rf /)"), [r"echo $''; rm -rf /"]);
    }

    // `$$'\''` is the PID followed by a plain quote that closes at the first
    // `'`. Whatever brush makes of it, a capture that drops the trailing
    // `; rm -rf /` must come out unparsable downstream or be rejected here.
    #[test]
    fn dollar_dollar_ansi_c_misread_is_rejected_or_fully_captured() {
        match parse_body(r"$(echo $$'\'')'; rm -rf /)") {
            Err(_) => {}
            Ok(found) => {
                assert!(
                    found
                        .iter()
                        .all(|inner| inner.contains("rm -rf /")
                            || inner.matches('\'').count() % 2 == 1),
                    "dropped the tail without leaving an unbalanced quote: {found:?}"
                );
            }
        }
    }

    #[test]
    fn japanese_text_around_a_substitution_is_handled() {
        assert_eq!(
            subs("これは日本語のテキストです $(rm -rf /) この後にも日本語"),
            ["rm -rf /"]
        );
    }

    #[test]
    fn multibyte_text_around_a_substitution_is_handled() {
        assert_eq!(
            subs("\u{e9}\u{e9} $(date) \u{e9} ${x:-$(id)}"),
            ["date", "id"]
        );
    }
}
