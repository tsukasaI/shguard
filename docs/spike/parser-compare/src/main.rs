//! Throwaway spike harness for shguard issue #6 ("A1: Parser-crate selection
//! spike"). NOT part of the shguard crate — lives entirely under docs/ and is
//! never built by the root Cargo.toml.
//!
//! Feeds a fixture corpus covering the GuardFall-and-beyond attack constructs
//! (see plan.md §0.3/§2 step 1) to both `brush-parser` 0.4.0 and
//! `yash-syntax` 0.23.1, and prints — per construct, per crate — whether the
//! crate preserves the word-part structure we need (e.g. `r''m` must yield
//! parts equivalent to [literal "r", single-quoted "", literal "m"], NOT a
//! pre-joined "rm" and NOT an opaque blob).
//!
//! Run with: `cargo run` from this directory (docs/spike/parser-compare/).
//!
//! Pragmatic/throwaway style: `.unwrap()`/`.expect()` are used freely here,
//! this code is not shipped and is not subject to the coding-guidelines
//! unwrap ban that applies to src/.

use std::io::Cursor;
use std::str::FromStr;

use brush_parser::word::{self as bword, WordPiece};
use brush_parser::{Parser as BrushParser, ParserOptions as BrushParserOptions, ast as bast};

use yash_syntax::syntax::{self as ysyn};

/// Result of checking one crate against one construct.
struct Outcome {
    pass: bool,
    evidence: String,
}

impl Outcome {
    fn fail(msg: impl Into<String>) -> Self {
        Self {
            pass: false,
            evidence: msg.into(),
        }
    }
}

struct Row {
    n: usize,
    construct: &'static str,
    input: String,
    brush: Outcome,
    yash: Outcome,
    bash_oracle: Option<bool>,
}

fn bash_accepts(cmd: &str) -> Option<bool> {
    std::process::Command::new("bash")
        .arg("-n")
        .arg("-c")
        .arg(cmd)
        .output()
        .ok()
        .map(|o| o.status.success())
}

fn push_row(
    rows: &mut Vec<Row>,
    construct: &'static str,
    input: &str,
    brush: Outcome,
    yash: Outcome,
) {
    let n = rows.len() + 1;
    let bash_oracle = bash_accepts(input);
    println!("\n=== [{n}] {construct} ===");
    println!("input: {input:?}");
    if let Some(acc) = bash_oracle {
        println!(
            "bash -n oracle: {}",
            if acc { "accepts" } else { "rejects" }
        );
    } else {
        println!("bash -n oracle: (bash not available)");
    }
    println!(
        "brush-parser: {} — {}",
        if brush.pass { "PASS" } else { "FAIL" },
        brush.evidence
    );
    println!(
        "yash-syntax:  {} — {}",
        if yash.pass { "PASS" } else { "FAIL" },
        yash.evidence
    );
    rows.push(Row {
        n,
        construct,
        input: input.to_string(),
        brush,
        yash,
        bash_oracle,
    });
}

// ---------------------------------------------------------------------
// brush-parser helpers
// ---------------------------------------------------------------------

fn brush_word(input: &str) -> Result<Vec<WordPiece>, String> {
    bword::parse(input, &BrushParserOptions::default())
        .map(|pieces| pieces.into_iter().map(|p| p.piece).collect())
        .map_err(|e| format!("parse error: {e:?}"))
}

fn brush_brace(input: &str) -> Result<Option<Vec<bword::BraceExpressionOrText>>, String> {
    bword::parse_brace_expansions(input, &BrushParserOptions::default())
        .map_err(|e| format!("parse error: {e:?}"))
}

fn brush_program(input: &str) -> Result<bast::Program, String> {
    let mut parser = BrushParser::new(
        Cursor::new(input.as_bytes()),
        &BrushParserOptions::default(),
    );
    parser
        .parse_program()
        .map_err(|e| format!("parse error: {e:?}"))
}

/// Extracts the first `Command` of the first pipeline of the first
/// and-or-list of the first complete command. Good enough for our
/// single-simple-command fixtures.
fn brush_first_command(program: &bast::Program) -> Option<&bast::Command> {
    let complete_command = program.complete_commands.first()?;
    let item = complete_command.0.first()?;
    item.0.first.seq.first()
}

fn brush_pipeline_len(program: &bast::Program) -> Option<usize> {
    let complete_command = program.complete_commands.first()?;
    let item = complete_command.0.first()?;
    Some(item.0.first.seq.len())
}

fn brush_list_shape(program: &bast::Program) -> Option<(usize, usize)> {
    // (number of top-level ';'-separated items, number of '&&'/'||' links in the first item)
    let complete_command = program.complete_commands.first()?;
    let items = complete_command.0.len();
    let first_item = complete_command.0.first()?;
    Some((items, first_item.0.additional.len()))
}

fn brush_heredoc<'a>(sc: &'a bast::SimpleCommand) -> Option<&'a bast::IoHereDocument> {
    let suffix = sc.suffix.as_ref()?;
    suffix.0.iter().find_map(|item| match item {
        bast::CommandPrefixOrSuffixItem::IoRedirect(bast::IoRedirect::HereDocument(_, doc)) => {
            Some(doc)
        }
        _ => None,
    })
}

fn brush_file_redirect<'a>(
    sc: &'a bast::SimpleCommand,
) -> Option<(&'a bast::IoFileRedirectKind, &'a str)> {
    let suffix = sc.suffix.as_ref()?;
    suffix.0.iter().find_map(|item| match item {
        bast::CommandPrefixOrSuffixItem::IoRedirect(bast::IoRedirect::File(
            _,
            kind,
            bast::IoFileRedirectTarget::Filename(word),
        )) => Some((kind, word.value.as_str())),
        _ => None,
    })
}

// ---------------------------------------------------------------------
// yash-syntax helpers
// ---------------------------------------------------------------------

fn yash_word(input: &str) -> Result<ysyn::Word, String> {
    ysyn::Word::from_str(input).map_err(|e| format!("parse error: {e:?}"))
}

fn yash_list(input: &str) -> Result<ysyn::List, String> {
    ysyn::List::from_str(input).map_err(|e| format!("parse error: {e:?}"))
}

fn yash_pipeline_len(list: &ysyn::List) -> Option<usize> {
    let item = list.0.first()?;
    Some(item.and_or.first.commands.len())
}

fn yash_list_shape(list: &ysyn::List) -> Option<(usize, usize)> {
    let items = list.0.len();
    let first_item = list.0.first()?;
    Some((items, first_item.and_or.rest.len()))
}

// ---------------------------------------------------------------------
// main: one block per construct
// ---------------------------------------------------------------------

fn main() {
    println!("shguard spike — brush-parser 0.4.0 vs yash-syntax 0.23.1");
    println!("crate facts re-verified live on 2026-07-18 (see docs/adr/0001-parser-crate.md)");

    let mut rows: Vec<Row> = Vec::new();

    // ---- 1. adjacent-quote insertion: r''m -rf / ----
    {
        let word_fixture = "r''m";
        let full = "r''m -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let has_empty_single_quote = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::SingleQuotedText(s) if s.is_empty()));
                let merged = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::Text(t) if t.contains("rm")));
                Outcome {
                    pass: has_empty_single_quote && !merged && pieces.len() >= 2,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let has_empty_single_quote = w
                    .units
                    .iter()
                    .any(|u| matches!(u, ysyn::WordUnit::SingleQuote(s) if s.is_empty()));
                Outcome {
                    pass: has_empty_single_quote && w.units.len() >= 2,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "adjacent-quote: r''m -rf /", full, brush, yash);
    }

    // ---- 2. adjacent-quote insertion: "r"m ----
    {
        let word_fixture = "\"r\"m";
        let full = "\"r\"m -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let has_double_quote_seq = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::DoubleQuotedSequence(_)));
                let merged = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::Text(t) if t.contains("rm")));
                Outcome {
                    pass: has_double_quote_seq && !merged && pieces.len() >= 2,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let has_double_quote = w
                    .units
                    .iter()
                    .any(|u| matches!(u, ysyn::WordUnit::DoubleQuote(_)));
                Outcome {
                    pass: has_double_quote && w.units.len() >= 2,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "adjacent-quote: \"r\"m", full, brush, yash);
    }

    // ---- 3. adjacent-quote insertion via backslash escape: r\m ----
    {
        let word_fixture = "r\\m";
        let full = "r\\m -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let has_escape = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::EscapeSequence(_)));
                let merged = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::Text(t) if t.contains("rm")));
                Outcome {
                    pass: has_escape && !merged && pieces.len() >= 2,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let has_backslashed = w
                    .units
                    .iter()
                    .any(|u| matches!(u, ysyn::WordUnit::Unquoted(ysyn::TextUnit::Backslashed(_))));
                Outcome {
                    pass: has_backslashed && w.units.len() >= 2,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "adjacent-quote: r\\m (backslash)",
            full,
            brush,
            yash,
        );
    }

    // ---- 4. ANSI-C quoting, hex: $'\x72\x6d' ----
    {
        let word_fixture = "$'\\x72\\x6d'";
        let full = "$'\\x72\\x6d' -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let ansi_c = pieces.iter().find_map(|p| match p {
                    WordPiece::AnsiCQuotedText(s) => Some(s.clone()),
                    _ => None,
                });
                Outcome {
                    pass: ansi_c.as_deref() == Some("\\x72\\x6d") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let hex_escapes = w.units.iter().find_map(|u| match u {
                    ysyn::WordUnit::DollarSingleQuote(es) => Some(es.0.clone()),
                    _ => None,
                });
                let pass = matches!(
                    hex_escapes.as_deref(),
                    Some([ysyn::EscapeUnit::Hex(0x72), ysyn::EscapeUnit::Hex(0x6d)])
                );
                Outcome {
                    pass,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "ANSI-C quoting, hex: $'\\x72\\x6d'",
            full,
            brush,
            yash,
        );
    }

    // ---- 5. ANSI-C quoting, octal: $'\162\155' ----
    {
        let word_fixture = "$'\\162\\155'";
        let full = "$'\\162\\155' -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let ansi_c = pieces.iter().find_map(|p| match p {
                    WordPiece::AnsiCQuotedText(s) => Some(s.clone()),
                    _ => None,
                });
                Outcome {
                    pass: ansi_c.as_deref() == Some("\\162\\155") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let octal_escapes = w.units.iter().find_map(|u| match u {
                    ysyn::WordUnit::DollarSingleQuote(es) => Some(es.0.clone()),
                    _ => None,
                });
                let pass = matches!(
                    octal_escapes.as_deref(),
                    Some([
                        ysyn::EscapeUnit::Octal(0o162),
                        ysyn::EscapeUnit::Octal(0o155)
                    ])
                );
                Outcome {
                    pass,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "ANSI-C quoting, octal: $'\\162\\155'",
            full,
            brush,
            yash,
        );
    }

    // ---- 6. ANSI-C quoting, literal content ("unicode" fixture per issue spec): $'rm' ----
    {
        let word_fixture = "$'rm'";
        let full = "$'rm' -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let ansi_c = pieces.iter().find_map(|p| match p {
                    WordPiece::AnsiCQuotedText(s) => Some(s.clone()),
                    _ => None,
                });
                // Must be tagged AnsiCQuotedText (distinct from a plain SingleQuotedText),
                // even though this particular fixture has no escapes to decode.
                Outcome {
                    pass: ansi_c.as_deref() == Some("rm") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let is_dollar_single_quote = w
                    .units
                    .iter()
                    .any(|u| matches!(u, ysyn::WordUnit::DollarSingleQuote(_)));
                Outcome {
                    pass: is_dollar_single_quote,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "ANSI-C quoting, literal ('unicode' fixture per issue): $'rm'",
            full,
            brush,
            yash,
        );
    }

    // ---- 7. heredoc: <<EOF ----
    {
        let full = "cat <<EOF\nrm -rf /\nEOF\n";
        let brush = match brush_program(full) {
            Ok(program) => match brush_first_command(&program) {
                Some(bast::Command::Simple(sc)) => match brush_heredoc(sc) {
                    Some(doc) => Outcome {
                        pass: doc.doc.value.trim_end_matches('\n') == "rm -rf /"
                            && doc.requires_expansion,
                        evidence: format!("{doc:?}"),
                    },
                    None => Outcome::fail("no heredoc redirect found in suffix"),
                },
                other => Outcome::fail(format!("unexpected command shape: {other:?}")),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => {
                let item = list.0.first();
                let redir = item.and_then(|item| {
                    match item.and_or.first.commands.first().map(|c| c.as_ref()) {
                        Some(ysyn::Command::Simple(sc)) => {
                            sc.redirs.iter().find_map(|r| match &r.body {
                                ysyn::RedirBody::HereDoc(hd) => Some(hd.clone()),
                                _ => None,
                            })
                        }
                        _ => None,
                    }
                });
                match redir {
                    Some(hd) => {
                        let content = hd.content.get();
                        Outcome {
                            pass: content.is_some(),
                            evidence: format!(
                                "remove_tabs={:?} content={content:?}",
                                hd.remove_tabs
                            ),
                        }
                    }
                    None => Outcome::fail("no heredoc redirect found"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "heredoc: <<EOF", full, brush, yash);
    }

    // ---- 8. heredoc with tab stripping: <<-EOF ----
    {
        let full = "cat <<-EOF\n\trm -rf /\nEOF\n";
        let brush = match brush_program(full) {
            Ok(program) => match brush_first_command(&program) {
                Some(bast::Command::Simple(sc)) => match brush_heredoc(sc) {
                    Some(doc) => Outcome {
                        pass: doc.remove_tabs && doc.doc.value.trim_end_matches('\n') == "rm -rf /",
                        evidence: format!("{doc:?}"),
                    },
                    None => Outcome::fail("no heredoc redirect found in suffix"),
                },
                other => Outcome::fail(format!("unexpected command shape: {other:?}")),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => {
                let item = list.0.first();
                let redir = item.and_then(|item| {
                    match item.and_or.first.commands.first().map(|c| c.as_ref()) {
                        Some(ysyn::Command::Simple(sc)) => {
                            sc.redirs.iter().find_map(|r| match &r.body {
                                ysyn::RedirBody::HereDoc(hd) => Some(hd.clone()),
                                _ => None,
                            })
                        }
                        _ => None,
                    }
                });
                match redir {
                    Some(hd) => {
                        let content = hd.content.get();
                        Outcome {
                            pass: hd.remove_tabs && content.is_some(),
                            evidence: format!(
                                "remove_tabs={:?} content={content:?}",
                                hd.remove_tabs
                            ),
                        }
                    }
                    None => Outcome::fail("no heredoc redirect found"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "heredoc, tab-strip: <<-EOF", full, brush, yash);
    }

    // ---- 9. heredoc, quoted delimiter (no expansion): <<'EOF' ----
    {
        let full = "cat <<'EOF'\n$(rm -rf /)\nEOF\n";
        let brush = match brush_program(full) {
            Ok(program) => match brush_first_command(&program) {
                Some(bast::Command::Simple(sc)) => match brush_heredoc(sc) {
                    Some(doc) => Outcome {
                        // requires_expansion must be false: the crate must remember the
                        // delimiter was quoted so shguard's normalize stage does NOT
                        // treat the literal "$(rm -rf /)" text as a live substitution.
                        pass: !doc.requires_expansion
                            && doc.doc.value.trim_end_matches('\n') == "$(rm -rf /)",
                        evidence: format!("{doc:?}"),
                    },
                    None => Outcome::fail("no heredoc redirect found in suffix"),
                },
                other => Outcome::fail(format!("unexpected command shape: {other:?}")),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => {
                let item = list.0.first();
                let redir = item.and_then(|item| {
                    match item.and_or.first.commands.first().map(|c| c.as_ref()) {
                        Some(ysyn::Command::Simple(sc)) => {
                            sc.redirs.iter().find_map(|r| match &r.body {
                                ysyn::RedirBody::HereDoc(hd) => Some(hd.clone()),
                                _ => None,
                            })
                        }
                        _ => None,
                    }
                });
                match redir {
                    Some(hd) => {
                        let content = hd.content.get();
                        // Quoted-delimiter heredoc content must stay purely literal: no
                        // CommandSubst text unit for the embedded "$(rm -rf /)".
                        let has_command_subst = content
                            .map(|t| {
                                t.0.iter()
                                    .any(|u| matches!(u, ysyn::TextUnit::CommandSubst { .. }))
                            })
                            .unwrap_or(true);
                        Outcome {
                            pass: content.is_some() && !has_command_subst,
                            evidence: format!("content={content:?}"),
                        }
                    }
                    None => Outcome::fail("no heredoc redirect found"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "heredoc, quoted delimiter: <<'EOF'",
            full,
            brush,
            yash,
        );
    }

    // ---- 10. command substitution: $(echo rm) ----
    {
        let word_fixture = "$(echo rm)";
        let full = "$(echo rm) -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let inner = pieces.iter().find_map(|p| match p {
                    WordPiece::CommandSubstitution(s) => Some(s.clone()),
                    _ => None,
                });
                Outcome {
                    pass: inner.as_deref() == Some("echo rm") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let inner = w.units.iter().find_map(|u| match u {
                    ysyn::WordUnit::Unquoted(ysyn::TextUnit::CommandSubst { content, .. }) => {
                        Some(content.to_string())
                    }
                    _ => None,
                });
                Outcome {
                    pass: inner.as_deref() == Some("echo rm"),
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "command substitution: $(echo rm)",
            full,
            brush,
            yash,
        );
    }

    // ---- 11. nested command substitution: $(echo $(echo rm)) ----
    {
        let word_fixture = "$(echo $(echo rm))";
        let full = "$(echo $(echo rm)) -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let inner = pieces.iter().find_map(|p| match p {
                    WordPiece::CommandSubstitution(s) => Some(s.clone()),
                    _ => None,
                });
                // The outer substitution must capture the FULL nested expression,
                // not truncate at the first ')'.
                Outcome {
                    pass: inner.as_deref() == Some("echo $(echo rm)") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let inner = w.units.iter().find_map(|u| match u {
                    ysyn::WordUnit::Unquoted(ysyn::TextUnit::CommandSubst { content, .. }) => {
                        Some(content.to_string())
                    }
                    _ => None,
                });
                Outcome {
                    pass: inner.as_deref() == Some("echo $(echo rm)"),
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "nested command substitution: $(echo $(echo rm))",
            full,
            brush,
            yash,
        );
    }

    // ---- 12. backquoted command substitution: `echo rm` ----
    {
        let word_fixture = "`echo rm`";
        let full = "`echo rm` -rf /";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let inner = pieces.iter().find_map(|p| match p {
                    WordPiece::BackquotedCommandSubstitution(s) => Some(s.clone()),
                    _ => None,
                });
                Outcome {
                    pass: inner.as_deref() == Some("echo rm") && pieces.len() == 1,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let inner = w.units.iter().find_map(|u| match u {
                    ysyn::WordUnit::Unquoted(ysyn::TextUnit::Backquote { content, .. }) => Some(
                        content
                            .iter()
                            .map(|bq| match bq {
                                ysyn::BackquoteUnit::Literal(c)
                                | ysyn::BackquoteUnit::Backslashed(c) => *c,
                            })
                            .collect::<String>(),
                    ),
                    _ => None,
                });
                Outcome {
                    pass: inner.as_deref() == Some("echo rm"),
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "backquoted command substitution: `echo rm`",
            full,
            brush,
            yash,
        );
    }

    // ---- 13. $IFS inside a word: rm$IFS-rf$IFS/ ----
    {
        let word_fixture = "rm$IFS-rf$IFS/";
        let full = word_fixture;
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let ifs_count = pieces
                    .iter()
                    .filter(|p| {
                        matches!(
                            p,
                            WordPiece::ParameterExpansion(bword::ParameterExpr::Parameter {
                                parameter: bword::Parameter::Named(name),
                                ..
                            }) if name == "IFS"
                        )
                    })
                    .count();
                // $IFS must surface as its own ParameterExpansion piece(s), distinct
                // from surrounding literal text — not silently folded into it.
                Outcome {
                    pass: ifs_count == 2 && pieces.len() >= 5,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let ifs_count = w
                    .units
                    .iter()
                    .filter(|u| {
                        matches!(
                            u,
                            ysyn::WordUnit::Unquoted(ysyn::TextUnit::RawParam { param, .. })
                                if param.id == "IFS"
                        )
                    })
                    .count();
                Outcome {
                    pass: ifs_count == 2,
                    evidence: format!("{:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "$IFS inside word: rm$IFS-rf$IFS/",
            full,
            brush,
            yash,
        );
    }

    // ---- 14. tilde: ~/x ----
    {
        let word_fixture = "~/x";
        let full = "echo ~/x";
        let brush = match brush_word(word_fixture) {
            Ok(pieces) => {
                let has_tilde = pieces
                    .iter()
                    .any(|p| matches!(p, WordPiece::TildeExpansion(bword::TildeExpr::Home)));
                Outcome {
                    pass: has_tilde,
                    evidence: format!("{pieces:?}"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_word(word_fixture) {
            Ok(mut w) => {
                // Tilde recognition is an explicit, opt-in post-processing step in
                // yash-syntax (`Word::parse_tilde_front`), not automatic during
                // ordinary word parsing — this is the documented, idiomatic way to
                // invoke it (see parser/lex/tilde.rs doc examples).
                w.parse_tilde_front();
                let has_tilde = w
                    .units
                    .iter()
                    .any(|u| matches!(u, ysyn::WordUnit::Tilde { name, .. } if name.is_empty()));
                Outcome {
                    pass: has_tilde,
                    evidence: format!("after parse_tilde_front(): {:?}", w.units),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "tilde expansion: ~/x", full, brush, yash);
    }

    // ---- 15. brace expansion: {a,b} ----
    {
        let word_fixture = "{a,b}";
        let full = "echo {a,b}";
        let brush = match brush_brace(word_fixture) {
            Ok(Some(pieces)) => {
                let has_expr = pieces
                    .iter()
                    .any(|p| matches!(p, bword::BraceExpressionOrText::Expr(_)));
                Outcome {
                    pass: has_expr,
                    evidence: format!("{pieces:?}"),
                }
            }
            Ok(None) => {
                Outcome::fail("parse_brace_expansions returned None (no brace expr recognized)")
            }
            Err(e) => Outcome::fail(e),
        };
        // yash-syntax is deliberately POSIX-only and does not implement brace
        // expansion (plan.md §0.3): `{a,b}` parses as plain literal characters,
        // with no distinct expansion node — it cannot decompose this construct.
        let yash = match yash_word(word_fixture) {
            Ok(w) => {
                let all_literal = w
                    .units
                    .iter()
                    .all(|u| matches!(u, ysyn::WordUnit::Unquoted(ysyn::TextUnit::Literal(_))));
                Outcome {
                    pass: false,
                    evidence: format!(
                        "{:?} (parses, but as {} literal chars — no brace-expansion node exists in this crate)",
                        w.units, all_literal as u8
                    ),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "brace expansion: {a,b}", full, brush, yash);
    }

    // ---- 16. pipeline: echo x | base64 -d | sh ----
    {
        let full = "echo x | base64 -d | sh";
        let brush = match brush_program(full) {
            Ok(program) => match brush_pipeline_len(&program) {
                Some(len) => Outcome {
                    pass: len == 3,
                    evidence: format!("pipeline stages = {len}"),
                },
                None => Outcome::fail("could not locate pipeline"),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => match yash_pipeline_len(&list) {
                Some(len) => Outcome {
                    pass: len == 3,
                    evidence: format!("pipeline stages = {len}"),
                },
                None => Outcome::fail("could not locate pipeline"),
            },
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "pipeline: echo x | base64 -d | sh",
            full,
            brush,
            yash,
        );
    }

    // ---- 17. lists: a; b && c ----
    {
        let full = "a; b && c";
        let brush = match brush_program(full) {
            Ok(program) => match brush_list_shape(&program) {
                Some((items, links)) => Outcome {
                    pass: items == 2 && links == 0,
                    evidence: format!(
                        "top-level ';'-items = {items}, first-item '&&'/'||' links = {links}"
                    ),
                },
                None => Outcome::fail("could not locate list shape"),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => match yash_list_shape(&list) {
                Some((items, links)) => Outcome {
                    pass: items == 2 && links == 0,
                    evidence: format!(
                        "top-level ';'-items = {items}, first-item '&&'/'||' links = {links}"
                    ),
                },
                None => Outcome::fail("could not locate list shape"),
            },
            Err(e) => Outcome::fail(e),
        };
        push_row(&mut rows, "list: a; b && c", full, brush, yash);
    }

    // ---- 18. redirection: echo x > /dev/null ----
    {
        let full = "echo x > /dev/null";
        let brush = match brush_program(full) {
            Ok(program) => match brush_first_command(&program) {
                Some(bast::Command::Simple(sc)) => match brush_file_redirect(sc) {
                    Some((kind, target)) => Outcome {
                        pass: matches!(kind, bast::IoFileRedirectKind::Write)
                            && target == "/dev/null",
                        evidence: format!("kind={kind:?} target={target:?}"),
                    },
                    None => Outcome::fail("no file redirect found in suffix"),
                },
                other => Outcome::fail(format!("unexpected command shape: {other:?}")),
            },
            Err(e) => Outcome::fail(e),
        };
        let yash = match yash_list(full) {
            Ok(list) => {
                let item = list.0.first();
                let redir = item.and_then(|item| {
                    match item.and_or.first.commands.first().map(|c| c.as_ref()) {
                        Some(ysyn::Command::Simple(sc)) => sc.redirs.first().cloned(),
                        _ => None,
                    }
                });
                match redir {
                    Some(r) => match &r.body {
                        ysyn::RedirBody::Normal { operator, operand } => Outcome {
                            pass: matches!(operator, ysyn::RedirOp::FileOut)
                                && operand.to_string() == "/dev/null",
                            evidence: format!("operator={operator:?} operand={operand}"),
                        },
                        other => Outcome::fail(format!("unexpected redir body: {other:?}")),
                    },
                    None => Outcome::fail("no redirection found"),
                }
            }
            Err(e) => Outcome::fail(e),
        };
        push_row(
            &mut rows,
            "redirection: echo x > /dev/null",
            full,
            brush,
            yash,
        );
    }

    // ---- summary ----
    println!("\n\n## Summary matrix\n");
    println!("| # | Construct | Input | bash -n | brush-parser | yash-syntax |");
    println!("|---|---|---|---|---|---|");
    for r in &rows {
        let oracle = match r.bash_oracle {
            Some(true) => "accepts",
            Some(false) => "rejects",
            None => "n/a",
        };
        println!(
            "| {} | {} | `{}` | {} | {} | {} |",
            r.n,
            r.construct,
            r.input.replace('\n', "\\n").replace('|', "\\|"),
            oracle,
            if r.brush.pass { "PASS" } else { "FAIL" },
            if r.yash.pass { "PASS" } else { "FAIL" },
        );
    }

    let brush_passes = rows.iter().filter(|r| r.brush.pass).count();
    let yash_passes = rows.iter().filter(|r| r.yash.pass).count();
    println!("\nbrush-parser: {brush_passes}/{} PASS", rows.len());
    println!("yash-syntax:  {yash_passes}/{} PASS", rows.len());
}
