//! Bash-compatibility pre-pass (RFC #658 stage 4): everything that has to
//! happen to a raw command string before brush-parser may see it, so that
//! brush's panics, stack exhaustion and bash disagreements are turned into
//! an explicit `Ask` (or a harmless rewrite) instead of an abort or a silent
//! mis-parse.
//!
//! [`prepare`] is the single entry point, called first by `parser::parse`.
//!
//! - The nesting caps ([`reject_excessive_raw_nesting`]) stay byte-level on
//!   purpose: they protect brush's recursive descent from stack overflow
//!   *before* any brush code runs, and they deliberately over-count
//!   (quote-blind), which is the `Ask` direction. They always run first.
//!   Only after a cap rejects a command containing `<<` does brush's
//!   tokenizer run, and only behind [`MAX_RAW_TOKENIZER_RECURSION_OPENERS`]
//!   (the tokenizer itself recurses): it locates quoted-delimiter heredoc
//!   bodies, which bash and brush never re-parse, and the caps are re-run
//!   with those bodies blanked (issue #627).
//! - The io-number rewrite is built on brush's own `tokenize_str` spans, so a
//!   quoted digit run is never touched.

use std::borrow::Cow;

use brush_parser::{Token, uncached_tokenize_str};

use super::{ParseError, parser_options};
use crate::ast::{
    BACKTRACK_COST_OPENER, BACKTRACK_COST_PAREN, MAX_KEYWORD_NESTING_COUNT,
    MAX_RAW_BACKTRACK_BUDGET, MAX_RAW_BRACE_NESTING_DEPTH, MAX_RAW_BRACE_OPEN_COUNT,
    MAX_RAW_BRACKET_OPENER_COUNT, MAX_RAW_EXTENDED_TEST_COUNT, MAX_RAW_LEGACY_ARITH_COUNT,
    MAX_RAW_PARAM_EXPANSION_COUNT, MAX_RAW_PAREN_NESTING_DEPTH, MAX_RAW_PAREN_OPEN_COUNT,
    MAX_RAW_PROCESS_SUBST_COUNT, MAX_RAW_QUOTED_OPENER_COUNT, MAX_RAW_STACK_BUDGET,
    MAX_RAW_TOKENIZER_RECURSION_OPENERS, STACK_COST_BRACE, STACK_COST_BRACKET,
    STACK_COST_EXTENDED_TEST_OP, STACK_COST_KEYWORD, STACK_COST_LEGACY_ARITH_EXTRA,
    STACK_COST_PARAM_EXPANSION_EXTRA, STACK_COST_PAREN,
};

/// Runs every pre-parse check and rewrite on `command`.
///
/// Returns the text brush-parser must parse: `command` itself, or a copy with
/// a space inserted after each overflowing io-number (see
/// [`neutralize_overflowing_io_redirect_numbers`]).
///
/// # Errors
///
/// [`ParseError::Unsupported`] when a raw nesting cap trips or `$'...'` is
/// combined with a backslash-newline continuation, and [`ParseError::Syntax`]
/// when brush's tokenizer panics.
pub(crate) fn prepare(command: &str) -> Result<Cow<'_, str>, ParseError> {
    // Run against both the comment-aware and the blind scan copies — see
    // `strip_raw_line_continuations_blind`'s docs for why neither alone
    // suffices and why running both closes the gap.
    let blind = strip_raw_line_continuations_blind(command);
    if let Err(rejection) = reject_excessive_raw_nesting_both(command, blind.as_ref())
        && !(command.contains("<<") && passes_with_quoted_heredoc_bodies_blanked(command))
    {
        return Err(rejection);
    }
    reject_ansi_c_quote_with_line_continuation(command, blind.as_ref())?;
    neutralize_overflowing_io_redirect_numbers(command)
}

/// Runs [`reject_excessive_raw_nesting`] on both scan copies of `text`;
/// `blind` is `strip_raw_line_continuations_blind(text)`.
fn reject_excessive_raw_nesting_both(text: &str, blind: &str) -> Result<(), ParseError> {
    reject_excessive_raw_nesting(strip_raw_line_continuations(text).as_ref())?;
    reject_excessive_raw_nesting(blind)
}

/// Issue #627: whether `command` passes both raw scans once the body of every
/// quoted-delimiter heredoc is blanked. `false` on any doubt, so the caller
/// keeps the original rejection.
fn passes_with_quoted_heredoc_bodies_blanked(command: &str) -> bool {
    if count_tokenizer_recursion_openers(command) > MAX_RAW_TOKENIZER_RECURSION_OPENERS {
        return false;
    }
    let options = parser_options().tokenizer_options();
    let Ok(Ok(tokens)) = catch_parser_panic(|| uncached_tokenize_str(command, &options)) else {
        return false;
    };
    let Some(blanked) = blank_quoted_heredoc_bodies(command, &tokens) else {
        return false;
    };
    let blanked_blind = strip_raw_line_continuations_blind(&blanked);
    reject_excessive_raw_nesting_both(&blanked, blanked_blind.as_ref()).is_ok()
}

/// Quote-blind, never-decremented count of the byte pairs at which brush's
/// tokenizer recurses (`$(`, `$[`, `${`); see
/// [`MAX_RAW_TOKENIZER_RECURSION_OPENERS`].
fn count_tokenizer_recursion_openers(command: &str) -> usize {
    command
        .as_bytes()
        .windows(2)
        .filter(|pair| pair[0] == b'$' && matches!(pair[1], b'(' | b'[' | b'{'))
        .count()
}

/// Returns a copy of `command` with the body of every top-level heredoc whose
/// delimiter is quoted (the same `'`, `"`, `\` test brush uses for
/// `requires_expansion`) overwritten by spaces, newlines kept. The end-tag
/// line is left alone. `None` when the copy is not valid UTF-8.
///
/// brush emits a heredoc as `<<`/`<<-`, tag, body, zero-width end tag, in
/// that order; the body span runs from the line after the operator line
/// through the end-tag line. A candidate that does not have exactly that
/// shape (for instance a `<<` operator inside `(( ))`) is left counted. A
/// heredoc nested in `$(...)` never appears as a top-level token and is left
/// counted too.
fn blank_quoted_heredoc_bodies(command: &str, tokens: &[Token]) -> Option<String> {
    let byte_offsets = char_byte_offsets(command);
    let byte_at = |char_index: usize| -> Option<usize> {
        if char_index == byte_offsets.len() {
            Some(command.len())
        } else {
            byte_offsets.get(char_index).copied()
        }
    };
    let mut blanked: Vec<u8> = command.as_bytes().to_vec();
    for quad in tokens.windows(4) {
        let [
            Token::Operator(operator, _),
            Token::Word(tag, _),
            Token::Word(_, body_span),
            Token::Word(end_tag, end_span),
        ] = quad
        else {
            continue;
        };
        if !matches!(operator.as_str(), "<<" | "<<-")
            || !tag.contains(['\'', '"', '\\'])
            || end_span.start.index != body_span.end.index
            || end_span.end.index != body_span.end.index
        {
            continue;
        }
        let (Some(start), Some(end)) =
            (byte_at(body_span.start.index), byte_at(body_span.end.index))
        else {
            continue;
        };
        if start > end || (start > 0 && command.as_bytes()[start - 1] != b'\n') {
            continue;
        }
        let region = &command[start..end];
        let without_final_newline = region.strip_suffix('\n').unwrap_or(region);
        let end_line_start = without_final_newline.rfind('\n').map_or(0, |at| at + 1);
        if !without_final_newline[end_line_start..]
            .trim_start_matches('\t')
            .ends_with(end_tag.as_str())
        {
            continue;
        }
        for byte in &mut blanked[start..start + end_line_start] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(blanked).ok()
}

/// Byte offset of each `char` of `text`; token spans count characters.
fn char_byte_offsets(text: &str) -> Vec<usize> {
    text.char_indices().map(|(offset, _)| offset).collect()
}

/// Runs a brush-parser entry point and converts an internal panic (a
/// pinned dependency's own unchecked `unwrap()` — brush-parser 0.4.0 has
/// four known instances in its tilde (unsigned/`+`-prefixed dir-stack
/// form, `-`-prefixed dir-stack form), brace-sequence, and io-number
/// number parsing, each an `Err(ParseIntError { kind: PosOverflow })`
/// reached through an ordinary, if extreme, input) into a
/// `ParseError::Syntax`, so
/// it folds into this pipeline's documented fail-closed contract (`ask`)
/// instead of unwinding out of the public `shguard::analyze`/
/// `analyze_with_policy` API — `src/lib.rs` documents both as folding
/// every failure into a `Verdict`, which an uncaught panic here would
/// silently break for any library consumer.
///
/// `AssertUnwindSafe`: every call site either closes over an immutable
/// `&str`, or a freshly constructed, call-local parser that is never
/// observed again after a panic (it is dropped immediately on both the
/// `Ok` and caught-panic paths) — there is no shared mutable state a
/// caught panic could leave inconsistent for a later caller to observe.
pub(crate) fn catch_parser_panic<T>(f: impl FnOnce() -> T) -> Result<T, ParseError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map_err(|_| ParseError::syntax("parser panicked"))
}

/// Reserved words that introduce a compound command brush-parser recurses
/// into, counted (never decremented) by [`reject_excessive_raw_nesting`] —
/// see [`MAX_KEYWORD_NESTING_COUNT`]'s docs for why a total count, and why
/// this exact set.
const NESTING_KEYWORDS: [&str; 6] = ["if", "while", "until", "for", "case", "coproc"];

/// Byte values [`reject_excessive_raw_nesting`] treats as ending a keyword
/// token: whitespace and the shell metacharacters that can immediately
/// follow a reserved word without an intervening space (e.g. `if;`,
/// `for(`). Splitting on these — not only on whitespace — is what keeps the
/// keyword count from *under*-counting a keyword glued to a metacharacter;
/// under-counting is the unsafe direction (see [`MAX_KEYWORD_NESTING_COUNT`]).
/// All are single-byte ASCII, so, like the bracket scan below, no UTF-8
/// continuation byte can be mistaken for one and every split point this
/// produces is a valid `str` boundary.
fn is_token_boundary(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | b'\r' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
    )
}

/// Issue #405: inserts a single space between an io-redirect digit run
/// (`45>out`, `2<in`) and the `<`/`>` it precedes, wherever that digit run's
/// value overflows `i32` — the exact shape that panics brush-parser 0.4.0's
/// io-number rule (`peg.rs:695`, `parse::<i32>().unwrap()`). A panic there
/// unwinds out of the whole `parse_program`, so an attacker appending
/// `99999999999999999999>x` after an otherwise-`Block`-worthy command would
/// downgrade the verdict to `Ask`.
///
/// The rewrite mirrors brush's own io-number predicate on brush's own tokens:
/// a [`Token::Word`] made only of ASCII digits, immediately followed (span end
/// equals span start) by an operator starting with `<` or `>`. A quoted digit
/// run keeps its quotes in the token text, so it is never touched, and a
/// continuation-split run is judged by the spans brush itself reports.
/// Inserting a space makes the pair non-contiguous, so brush reads the digits
/// as an ordinary argument word; the digit text is preserved byte-for-byte.
///
/// If tokenizing fails the command is returned unchanged: `parse_program`
/// tokenizes with the same options right after, so the same error surfaces
/// there as a `Syntax` error and no rewrite is needed.
///
/// Token spans count characters, not bytes, hence the offset table.
fn neutralize_overflowing_io_redirect_numbers(command: &str) -> Result<Cow<'_, str>, ParseError> {
    let options = parser_options().tokenizer_options();
    let Ok(tokens) = catch_parser_panic(|| uncached_tokenize_str(command, &options))? else {
        return Ok(Cow::Borrowed(command));
    };

    let mut insert_at_char: Vec<usize> = Vec::new();
    for pair in tokens.windows(2) {
        if let [
            Token::Word(word, word_span),
            Token::Operator(operator, operator_span),
        ] = pair
            && operator.starts_with(['<', '>'])
            && word_span.end.index == operator_span.start.index
            && !word.is_empty()
            && word.chars().all(|c| c.is_ascii_digit())
            && word.parse::<i32>().is_err()
        {
            insert_at_char.push(word_span.end.index);
        }
    }
    if insert_at_char.is_empty() {
        return Ok(Cow::Borrowed(command));
    }

    let byte_offsets = char_byte_offsets(command);
    let mut rewritten = String::with_capacity(command.len() + insert_at_char.len());
    let mut copied = 0;
    for char_index in insert_at_char {
        let byte_offset = byte_offsets
            .get(char_index)
            .copied()
            .unwrap_or(command.len());
        rewritten.push_str(&command[copied..byte_offset]);
        rewritten.push(' ');
        copied = byte_offset;
    }
    rewritten.push_str(&command[copied..]);
    Ok(Cow::Owned(rewritten))
}
/// Builds a *scan-only* copy of `command` with every real `\`+newline
/// line-continuation pair removed, for [`reject_excessive_raw_nesting`]'s
/// keyword/`[[` scan to run on instead of the original text (issue #443):
/// brush-parser's own tokenizer strips these before recursing, so a
/// keyword or `[[` opener split across a continuation
/// (`i\<newline>f true; then ...`) rejoins into the exact shape that scan
/// exists to catch, while the *unstripped* text — the only text the scan
/// used to see — sailed through untouched, reaching brush-parser's
/// unbounded recursive descent uncapped: an uncatchable stack-overflow
/// abort (no decision reaches stdout at all, fail-open for a `PreToolUse`
/// hook).
///
/// **This output must never be fed to brush-parser itself** — only used as
/// `reject_excessive_raw_nesting`'s input. Brush-parser keeps parsing
/// `command` unmodified (`parse()` below): brush's comment handling ends a
/// `#...` comment at the first *raw* newline, continuation or not, so
/// blindly deleting a `\`+newline pair inside a comment would merge the
/// next line into that comment — hiding an arbitrary following command
/// behind `# \<newline>` (e.g. `echo hi # \<newline>rm -rf /` would let the
/// `rm -rf /` disappear entirely rather than being analyzed) if this
/// output were what brush-parser itself parsed. Keeping brush-parser on
/// the untouched original text makes that failure mode impossible: this
/// function only ever influences whether `reject_excessive_raw_nesting`
/// rejects up front, never what gets parsed.
///
/// Two properties this scan must get right to avoid *under*-counting a real
/// nesting/bracket shape relative to what brush-parser will actually see
/// (under-counting is the unsafe direction — see [`MAX_KEYWORD_NESTING_COUNT`]):
///
/// - **Backslash parity.** Real bash only collapses `X\<newline>Y` into
///   contiguous `XY` when an *odd* number of backslashes immediately
///   precedes the newline (the trailing one pairs with the newline as a
///   continuation; the rest pair up into literal backslash characters). An
///   *even* count leaves the newline un-stripped — a real, uncontinued
///   newline that separates commands (or ends a comment) exactly like `;`
///   does. A parity-blind strip that removes the last `\`+newline
///   regardless of what precedes it would, on an even count, glue a
///   following real keyword onto the preceding backslash run into a token
///   that no longer matches `if`/`while`/etc — under-counting a real,
///   brush-recognized keyword (e.g. `"x\\\\\nif true; then "` x600 — two
///   backslashes, even — is real separate `if` keywords to brush, but
///   glues to a non-matching token under parity-blind stripping).
/// - **Comments.** A `#` at the start of a word begins a comment that runs
///   to the next raw newline, continuation or not (same brush behavior
///   this function must never touch for the parser-input reason above) —
///   so a continuation *inside* a comment must not be stripped from the
///   scan copy either, or a real keyword split immediately after that
///   comment's line (`# x\<newline>i\<newline>f true; then ...`) would be
///   glued onto the comment text and miscounted as zero keywords even
///   though brush treats the second line as fresh, uncommented code.
///
/// Quote-blindness is a real, disclosed limitation for this scan copy
/// specifically (unlike for parser input): a `#` that sits at a
/// strip-perceived word boundary but is actually inside a quoted string
/// (e.g. `echo 'a #'; i\<newline>f ...`) makes this function open a comment
/// brush itself never opens, which suppresses stripping of every
/// `\`+newline pair until the next raw newline — including a real,
/// unquoted continuation later on the same perceived "comment" line. That
/// under-counts exactly the shape this function exists to catch. See
/// [`strip_raw_line_continuations_blind`], which has the complementary
/// blind spot and is run alongside this function for that reason —
/// between the two, a `\`+newline-split keyword/`[[` opener is rejoined by
/// at least one of them regardless of which side of a real-vs-quoted `#`
/// it falls on.
fn strip_raw_line_continuations(command: &str) -> std::borrow::Cow<'_, str> {
    let bytes = command.as_bytes();
    let mut rewritten: Option<String> = None;
    let mut last_copied = 0;
    let mut at_word_start = true;
    let mut in_comment = false;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];

        if in_comment {
            if byte == b'\n' {
                in_comment = false;
                at_word_start = true;
            }
            i += 1;
            continue;
        }

        if byte == b'#' && at_word_start {
            in_comment = true;
            at_word_start = false;
            i += 1;
            continue;
        }

        if byte == b'\\' {
            let run_start = i;
            let mut run_end = i;
            while run_end < bytes.len() && bytes[run_end] == b'\\' {
                run_end += 1;
            }
            let run_len = run_end - run_start;
            if run_end < bytes.len() && bytes[run_end] == b'\n' && run_len % 2 == 1 {
                // Odd run: the last backslash pairs with the newline as a
                // real continuation. Copy the other run_len - 1 backslashes
                // through unchanged; strip only the final pair. Preserves
                // `at_word_start` from before the run, since a stripped
                // continuation neither starts nor ends a word.
                let out = rewritten.get_or_insert_with(String::new);
                out.push_str(&command[last_copied..run_end - 1]);
                last_copied = run_end + 1;
                i = run_end + 1;
                continue;
            }
            // Even run, or not followed by a newline: copy through
            // unchanged. A backslash is never a token boundary.
            at_word_start = false;
            i = run_end;
            continue;
        }

        at_word_start = is_token_boundary(byte);
        i += 1;
    }

    match rewritten {
        Some(mut out) => {
            out.push_str(&command[last_copied..]);
            std::borrow::Cow::Owned(out)
        }
        None => std::borrow::Cow::Borrowed(command),
    }
}

/// Blind sibling of [`strip_raw_line_continuations`]: strips every
/// parity-valid `\`+newline pair unconditionally, with no `#`/comment
/// awareness at all — so a `#` inside a quoted string can never make it
/// wrongly suppress stripping. Its own blind spot is the opposite one:
/// stripping through a *genuine*, unquoted `#...` comment's own
/// continuation can hide a real split keyword on the fresh line right
/// after that comment (the case [`strip_raw_line_continuations`]'s
/// comment-tracking exists to catch). [`reject_excessive_raw_nesting`] is
/// run against both this and the comment-aware copy, rejecting if either
/// trips a cap: between the two, a `\`+newline-split keyword/`[[` opener
/// is rejoined by at least one of them regardless of which side of a
/// real-vs-quoted `#` it falls on.
pub(super) fn strip_raw_line_continuations_blind(command: &str) -> std::borrow::Cow<'_, str> {
    let bytes = command.as_bytes();
    let mut rewritten: Option<String> = None;
    let mut last_copied = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let run_start = i;
            let mut run_end = i;
            while run_end < bytes.len() && bytes[run_end] == b'\\' {
                run_end += 1;
            }
            let run_len = run_end - run_start;
            if run_end < bytes.len() && bytes[run_end] == b'\n' && run_len % 2 == 1 {
                let out = rewritten.get_or_insert_with(String::new);
                out.push_str(&command[last_copied..run_end - 1]);
                last_copied = run_end + 1;
                i = run_end + 1;
                continue;
            }
            i = run_end;
            continue;
        }
        i += 1;
    }

    match rewritten {
        Some(mut out) => {
            out.push_str(&command[last_copied..]);
            std::borrow::Cow::Owned(out)
        }
        None => std::borrow::Cow::Borrowed(command),
    }
}

/// The construct text [`reject_ansi_c_quote_with_line_continuation`] reports;
/// `crate::policy` matches on it to pick this construct's own rewrite hint.
pub(crate) const ANSI_C_WITH_CONTINUATION_CONSTRUCT: &str = "ANSI-C ($'...') quoting combined with a backslash-newline line continuation cannot be safely analyzed: brush and bash disagree on whether the continuation survives inside $'...', which could hide a command on the dropped line";

/// Fails closed (`Ask`) if `command` contains both a `$'...'` (ANSI-C
/// quoting) opener — checked in `command` itself and in `blind`, the
/// already-computed [`strip_raw_line_continuations_blind`] copy, since
/// bash's own input layer removes a `\`+newline pair before its tokenizer
/// even looks for the `$'` opener, so `$\<newline>'...'` forms one in real
/// bash without the literal two-byte substring `$'` ever appearing in
/// `command` — and a raw `\`+newline byte pair anywhere in `command`
/// (issue #444): inside `$'...'`, brush-parser's tokenizer strips a
/// `\`+newline pair the same way it does outside quotes, but real bash's
/// ANSI-C decoding does not treat `\`+newline as one of its recognized
/// escapes there and keeps the raw newline in the decoded value instead.
/// When that decoded value is later recursed into as a nested script
/// (e.g. `bash -c $'...'`), a `#` comment before the dropped continuation
/// swallows a line brush itself never drops, letting a real command on
/// that line go completely unanalyzed while bash still executes it.
///
/// Deliberately the "cruder fallback" from the issue's own suggested
/// fixes rather than a precise span-length comparison inside
/// `convert_word`: it does not require the two substrings to be inside
/// the same `$'...'` span, so it over-Asks on some commands where they
/// are unrelated — the safe direction here.
fn reject_ansi_c_quote_with_line_continuation(
    command: &str,
    blind: &str,
) -> Result<(), ParseError> {
    if command.contains("\\\n") && (command.contains("$'") || blind.contains("$'")) {
        return Err(ParseError::unsupported(ANSI_C_WITH_CONTINUATION_CONSTRUCT));
    }
    Ok(())
}

/// Rejects `command` if its `{`/`}` nesting depth exceeds
/// [`MAX_RAW_BRACE_NESTING_DEPTH`], its total count of raw `{` bytes exceeds
/// [`MAX_RAW_BRACE_OPEN_COUNT`], its `(`/`)` nesting depth exceeds
/// [`MAX_RAW_PAREN_NESTING_DEPTH`], its total count of raw `(` bytes exceeds
/// [`MAX_RAW_PAREN_OPEN_COUNT`], its total `[` count exceeds
/// [`MAX_RAW_BRACKET_OPENER_COUNT`], its total count of `${`, `$[` or
/// `<(`/`>(` openers exceeds [`MAX_RAW_PARAM_EXPANSION_COUNT`],
/// [`MAX_RAW_LEGACY_ARITH_COUNT`] or
/// [`MAX_RAW_PROCESS_SUBST_COUNT`] respectively, its `$(` and extglob
/// openers plus other `(` exceed [`MAX_RAW_BACKTRACK_BUDGET`], its total count of
/// [`NESTING_KEYWORDS`] occurrences exceeds [`MAX_KEYWORD_NESTING_COUNT`],
/// or its count of `!`/`&&`/`||` operators after the first `[[` exceeds
/// [`MAX_RAW_EXTENDED_TEST_COUNT`], *before*
/// any recursive-descent parser (brush-parser's PEG grammar, or this
/// module's own brace/word conversion) ever sees the text.
///
/// This is the primary defense against issue #52's abort and issue #404's
/// CPU-DoS: deeply nested `{`/`(` input (e.g. `{a,` repeated thousands of
/// times, or `$(` repeated thousands of times) can crash with a stack
/// overflow *inside brush-parser's own PEG grammar* (or, for the `&&`/`||`
/// shape below, in the recursive `Drop` of the tree it already
/// successfully built) — its mutually recursive descent has no depth limit
/// of its own — while a comma-less `{{{`-nested brace group or a leading
/// run of unbalanced `(` instead drives that same PEG grammar into
/// catastrophic backtracking, burning unbounded CPU without ever
/// overflowing the stack (issue #404 — via the CLI/hook path this only
/// stalls for the watchdog's timeout, but via the public library API the
/// detached watchdog worker thread keeps burning CPU indefinitely after
/// the caller already received its verdict). Deeply nested
/// `if`/`while`/`until`/`for`/`case` compound commands overflow the stack
/// the same uncatchable way, and a long unparenthesized `!`/`&&`/`||`
/// chain inside `[[ ... ]]` (issue #401) does too. None of these reach
/// shguard's AST-level depth caps (`convert_brace_segment`/
/// `convert_brace_members`/`collect_extended_test_words` in this module,
/// `normalize::expand_braces`) in time to matter, because those only see
/// brush-parser's *output* — a stack overflow is an uncatchable abort
/// (`std::panic::catch_unwind` cannot intercept one — see
/// `src/bin/shguard.rs`'s module docs) and unbounded backtracking simply
/// never returns control to run them, so the only effective defense
/// against either failure mode is a linear, non-recursive pre-scan that
/// runs ahead of the parser and rejects the input outright. All
/// counters are tracked in one pass (`{`/`}` alone would miss a `$(`-only
/// attack, which was independently confirmed to abort even though it never
/// touches shguard's AST-level brace cap at all; neither bracket alone
/// catches a keyword-only attack like nested `if`/`then`/`fi` with no
/// braces or parens at all; a `[[ ]]` operator chain contains no
/// `{`/`(`/`[`/keyword byte at all; and a run of `a[` openers — brush's
/// array-subscript grammar recurses once per `[` — contains no
/// `{`/`(`/keyword byte either and is unaffected by the paren/brace caps)
/// — see [`MAX_RAW_BRACE_NESTING_DEPTH`]'s, [`MAX_RAW_BRACE_OPEN_COUNT`]'s,
/// [`MAX_RAW_PAREN_NESTING_DEPTH`]'s, [`MAX_RAW_PAREN_OPEN_COUNT`]'s,
/// [`MAX_RAW_BRACKET_OPENER_COUNT`]'s, [`MAX_RAW_BACKTRACK_BUDGET`]'s,
/// [`MAX_RAW_PARAM_EXPANSION_COUNT`]'s, [`MAX_RAW_LEGACY_ARITH_COUNT`]'s,
/// [`MAX_RAW_PROCESS_SUBST_COUNT`]'s, [`MAX_KEYWORD_NESTING_COUNT`]'s, and
/// [`MAX_RAW_EXTENDED_TEST_COUNT`]'s docs for the chosen cap values, their
/// measured cost curves, and their trade-offs — the two depth counters use
/// a raw cap far tighter than [`MAX_BRACE_NESTING_DEPTH`]'s stack-depth-sized
/// 64, since PEG backtracking cost grows exponentially with nesting depth
/// while stack depth grows only linearly. The depth counters decrement on a
/// closer byte and are NOT a stack-depth guard: a quoted, backslash-escaped,
/// heredoc-body, or `#`-comment closer is not a real closer to
/// `brush-parser` but still decrements them. Every stack-depth guard here is
/// therefore a never-decremented per-opener total, and the caps are sized
/// together so that all of them filled at once still leaves a >=3x margin
/// (see [`MAX_RAW_STACK_BUDGET`]'s docs). Backtick command
/// substitution has no opener byte pair to count and was not a measured
/// overflow vector; re-check it on a `brush-parser` bump.
///
/// Scans bytes, not `char`s: every byte this function compares against
/// (`{`, `}`, `(`, `)`, `[`, `&`, `|`, and every [`is_token_boundary`]
/// delimiter) is single-byte ASCII, and no UTF-8 continuation byte
/// (`0x80..=0xBF`) can equal one of them, so counting and slicing on raw
/// bytes is exact for any valid UTF-8 input and avoids paying for UTF-8
/// decoding on a hot, security-critical scan.
fn reject_excessive_raw_nesting(command: &str) -> Result<(), ParseError> {
    let mut brace_depth: usize = 0;
    let mut brace_open_count: usize = 0;
    let mut paren_depth: usize = 0;
    let mut paren_open_count: usize = 0;
    let mut bracket_count: usize = 0;
    let mut legacy_arith_count: usize = 0;
    let mut backtrack_opener_count: usize = 0;
    let mut backtrack_paren_count: usize = 0;
    let mut param_start_depth: Option<usize> = None;
    let mut param_start_paren_depth: usize = 0;
    let mut param_dirty = false;
    let mut quote_in_param = false;
    let mut quoted_opener_count: usize = 0;
    let mut quoted_paren_count: usize = 0;
    let mut param_expansion_count: usize = 0;
    let mut process_subst_count: usize = 0;
    let mut keyword_count: usize = 0;
    let mut stack_cost: usize = 0;
    let mut token_start: Option<usize> = None;
    let mut in_extended_test = false;
    let mut extended_test_op_count: usize = 0;

    let bytes = command.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| bytes[j]);
        match byte {
            b'{' => {
                add_stack_cost(&mut stack_cost, STACK_COST_BRACE)?;
                brace_depth += 1;
                if brace_depth > MAX_RAW_BRACE_NESTING_DEPTH {
                    return Err(ParseError::unsupported(
                        "brace nesting exceeds the raw depth cap",
                    ));
                }
                // Never decremented — see `MAX_RAW_BRACE_OPEN_COUNT`'s docs
                // for why the decrementing `brace_depth` counter above
                // cannot be relied on alone: a quoted/escaped/heredoc/
                // comment `}` is not a real closer to brush-parser but
                // still decrements `brace_depth`, letting real nesting grow
                // unboundedly underneath it.
                brace_open_count += 1;
                if brace_open_count > MAX_RAW_BRACE_OPEN_COUNT {
                    return Err(ParseError::unsupported(
                        "brace opener count exceeds the raw count cap",
                    ));
                }
                // `${` parameter expansion recurses far deeper per opener
                // than a bare brace group, so it has its own, tighter
                // never-decremented cap, see `MAX_RAW_PARAM_EXPANSION_COUNT`.
                if prev == Some(b'$') {
                    add_stack_cost(&mut stack_cost, STACK_COST_PARAM_EXPANSION_EXTRA)?;
                    param_expansion_count += 1;
                    if param_expansion_count > MAX_RAW_PARAM_EXPANSION_COUNT {
                        return Err(ParseError::unsupported(
                            "parameter expansion opener count exceeds the raw count cap",
                        ));
                    }
                    if param_start_depth.is_none() {
                        param_start_depth = Some(brace_depth);
                        param_start_paren_depth = paren_depth;
                    }
                }
            }
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                // A `}` closes the body only when nothing in it could hide
                // the closer from brush (a backslash, quote, backtick or an
                // open `$(`): otherwise the body stays open to the end of the
                // command, fail-closed, see `MAX_RAW_QUOTED_OPENER_COUNT`.
                if param_start_depth.is_some_and(|start| brace_depth < start)
                    && !param_dirty
                    && paren_depth <= param_start_paren_depth
                {
                    param_start_depth = None;
                    quote_in_param = false;
                    quoted_opener_count = 0;
                    quoted_paren_count = 0;
                }
            }
            b'(' => {
                add_stack_cost(&mut stack_cost, STACK_COST_PAREN)?;
                paren_depth += 1;
                if paren_depth > MAX_RAW_PAREN_NESTING_DEPTH {
                    return Err(ParseError::unsupported(
                        "parenthesis nesting exceeds the raw depth cap",
                    ));
                }
                // Never decremented — the `(`/`)` counterpart of
                // `brace_open_count` above, see `MAX_RAW_PAREN_OPEN_COUNT`'s
                // docs.
                paren_open_count += 1;
                if paren_open_count > MAX_RAW_PAREN_OPEN_COUNT {
                    return Err(ParseError::unsupported(
                        "parenthesis opener count exceeds the raw count cap",
                    ));
                }
                // `<(`/`>(` process substitution has its own, tighter
                // never-decremented cap: a quoted/escaped `)` hides the
                // closer from brush while its stack keeps growing, see
                // `MAX_RAW_PROCESS_SUBST_COUNT`.
                if matches!(prev, Some(b'<' | b'>')) {
                    process_subst_count += 1;
                    if process_subst_count > MAX_RAW_PROCESS_SUBST_COUNT {
                        return Err(ParseError::unsupported(
                            "process substitution opener count exceeds the raw count cap",
                        ));
                    }
                }
                // `$(` and extglob openers backtrack exponentially in
                // brush's word parser and compound with every other `(`, see
                // `MAX_RAW_BACKTRACK_BUDGET`. Plain `(` only charges once an
                // exponential opener is present, so a command without one
                // keeps the depth and count caps above as its only limit.
                if matches!(prev, Some(b'$' | b'+' | b'@' | b'!' | b'*' | b'?')) {
                    backtrack_opener_count += 1;
                } else {
                    backtrack_paren_count += 1;
                }
                if backtrack_opener_count > 0
                    && backtrack_opener_count * BACKTRACK_COST_OPENER
                        + backtrack_paren_count * BACKTRACK_COST_PAREN
                        > MAX_RAW_BACKTRACK_BUDGET
                {
                    return Err(ParseError::unsupported(
                        "`$(` and `+(` `@(` `!(` `*(` `?(` openers plus other `(` exceed the raw backtracking budget",
                    ));
                }
                // After a quote inside `${...}` the same openers cost time
                // linear in the rest of the input, see
                // `MAX_RAW_QUOTED_OPENER_COUNT`.
                if quote_in_param {
                    if matches!(prev, Some(b'$' | b'+' | b'@' | b'!' | b'*' | b'?')) {
                        quoted_opener_count += 1;
                    } else {
                        quoted_paren_count += 1;
                    }
                    if quoted_opener_count > MAX_RAW_QUOTED_OPENER_COUNT
                        || (quoted_opener_count > 0 && quoted_paren_count > 0)
                    {
                        return Err(ParseError::unsupported(
                            "a quote inside a parameter expansion followed by `$(` or `+(` `@(` `!(` `*(` `?(` openers",
                        ));
                    }
                }
            }
            b'\'' if param_start_depth.is_some() => {
                quote_in_param = true;
                param_dirty = true;
            }
            b'"' | b'`' | b'\\' if param_start_depth.is_some() => param_dirty = true,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            // Counts every `[` and never decrements on `]`: brush hides a
            // closing `]` inside quotes, backticks, `$(`, `$((`, `${` and
            // `$[`, so no scan of `]` is sound, whereas its recursion depth
            // is bounded by the opener count however those are closed.
            b'[' => {
                add_stack_cost(&mut stack_cost, STACK_COST_BRACKET)?;
                bracket_count += 1;
                if bracket_count > MAX_RAW_BRACKET_OPENER_COUNT {
                    return Err(ParseError::unsupported(
                        "bracket opener count exceeds the raw cap",
                    ));
                }
                // `$[` legacy arithmetic recurses like `$(` but always
                // resolves to `Ask` anyway, so its own cap costs nothing,
                // see `MAX_RAW_LEGACY_ARITH_COUNT`.
                if prev == Some(b'$') {
                    add_stack_cost(&mut stack_cost, STACK_COST_LEGACY_ARITH_EXTRA)?;
                    legacy_arith_count += 1;
                    if legacy_arith_count > MAX_RAW_LEGACY_ARITH_COUNT {
                        return Err(ParseError::unsupported(
                            "legacy arithmetic opener count exceeds the raw count cap",
                        ));
                    }
                }
            }
            // `&&`/`||` are made entirely of `is_token_boundary` bytes, so
            // they never form a token the tokenizer below could match
            // whole — checked here, on raw adjacent bytes, instead.
            // Over-counts on a run of 3+ identical bytes (`&&&&` counts as
            // 3, not 1) and on any occurrence outside real `[[ ]]` operator
            // position (e.g. inside a quoted operand) — both fine, same
            // "can only overestimate, never underestimate" safety direction
            // as `check_keyword_token`.
            // A `[[` token still pending (`[[&&`, no space) has not yet set
            // `in_extended_test`: that happens in the token block below,
            // after this match, so look at the pending token here too.
            b'&' | b'|'
                if bytes.get(i + 1) == Some(&byte)
                    && (in_extended_test || token_start.is_some_and(|s| &bytes[s..i] == b"[[")) =>
            {
                add_stack_cost(&mut stack_cost, STACK_COST_EXTENDED_TEST_OP)?;
                check_extended_test_op_count(&mut extended_test_op_count)?;
            }
            _ => {}
        }

        if is_token_boundary(byte) {
            if let Some(start) = token_start.take() {
                let token = &command[start..i];
                check_keyword_token(token, &mut keyword_count, &mut stack_cost)?;
                match token {
                    // Issues #489/#528: tracking is never turned off by a
                    // `]]` token and the count is never reset by a `[[`
                    // token. This scan is quote-blind, so a quoted `]]` or
                    // `[[` (` ]] `/` [[ ` tokenize as standalone tokens
                    // once surrounded by spaces) is indistinguishable from
                    // a real one, and either reset or disable would let
                    // quoting drive the count back down while brush still
                    // sees one region. See `MAX_RAW_EXTENDED_TEST_COUNT`.
                    "[[" => in_extended_test = true,
                    "!" if in_extended_test => {
                        add_stack_cost(&mut stack_cost, STACK_COST_EXTENDED_TEST_OP)?;
                        check_extended_test_op_count(&mut extended_test_op_count)?;
                    }
                    _ => {}
                }
            }
        } else if token_start.is_none() {
            token_start = Some(i);
        }
    }
    if let Some(start) = token_start {
        let token = &command[start..];
        check_keyword_token(token, &mut keyword_count, &mut stack_cost)?;
        if in_extended_test && token == "!" {
            add_stack_cost(&mut stack_cost, STACK_COST_EXTENDED_TEST_OP)?;
            check_extended_test_op_count(&mut extended_test_op_count)?;
        }
    }

    Ok(())
}

/// Adds `cost` to the running combined stack-cost total, rejecting once it
/// exceeds [`MAX_RAW_STACK_BUDGET`] — see that constant's docs.
fn add_stack_cost(stack_cost: &mut usize, cost: usize) -> Result<(), ParseError> {
    *stack_cost += cost;
    if *stack_cost > MAX_RAW_STACK_BUDGET {
        return Err(ParseError::unsupported(
            "combined grammar nesting exceeds the raw stack budget",
        ));
    }
    Ok(())
}

/// Increments `keyword_count` if `token` is one of [`NESTING_KEYWORDS`],
/// rejecting once the running total exceeds [`MAX_KEYWORD_NESTING_COUNT`].
/// Split out of [`reject_excessive_raw_nesting`] only to run once per
/// completed token and once more for the trailing token at end-of-input,
/// without duplicating the check-and-increment logic at both call sites.
fn check_keyword_token(
    token: &str,
    keyword_count: &mut usize,
    stack_cost: &mut usize,
) -> Result<(), ParseError> {
    if NESTING_KEYWORDS.contains(&token) {
        add_stack_cost(stack_cost, STACK_COST_KEYWORD)?;
        *keyword_count += 1;
        if *keyword_count > MAX_KEYWORD_NESTING_COUNT {
            return Err(ParseError::unsupported(
                "compound-command keyword nesting exceeds the raw count cap",
            ));
        }
    }
    Ok(())
}

/// Increments `extended_test_op_count`, rejecting once the running total
/// exceeds [`MAX_RAW_EXTENDED_TEST_COUNT`] — see that constant's docs.
fn check_extended_test_op_count(extended_test_op_count: &mut usize) -> Result<(), ParseError> {
    *extended_test_op_count += 1;
    if *extended_test_op_count > MAX_RAW_EXTENDED_TEST_COUNT {
        return Err(ParseError::unsupported(
            "extended-test operator count exceeds the raw count cap",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neutralized(command: &str) -> String {
        match neutralize_overflowing_io_redirect_numbers(command) {
            Ok(rewritten) => rewritten.into_owned(),
            Err(err) => panic!("expected {command:?} to be prepared, got {err:?}"),
        }
    }

    // A digit run already separated from `<`/`>` by whitespace is not an
    // io-number shape in the first place (contiguity, per brush's own
    // grammar, is required) — the rewrite must not touch it.
    #[test]
    fn io_number_overflow_with_pre_existing_space_is_left_alone() {
        assert_eq!(
            neutralized("echo 99999999999999999999 >f"),
            "echo 99999999999999999999 >f"
        );
    }

    // A digit run glued to a PRECEDING word is never an io-number
    // candidate (io-number requires the whole token to be digits) — the
    // overflow-adjacent `>` here must not be touched.
    #[test]
    fn io_number_overflow_glued_to_a_preceding_word_is_left_alone() {
        assert_eq!(
            neutralized("echo abc99999999999999999999>f"),
            "echo abc99999999999999999999>f"
        );
    }

    // A digit run that fits i32 must never be rewritten, even right at
    // i32::MAX — the ordinary, non-overflowing io-number case is
    // unaffected by this pre-pass.
    #[test]
    fn io_number_at_i32_max_is_left_alone() {
        let command = format!("echo {}>f", i32::MAX);
        assert_eq!(neutralized(&command), command);
    }

    #[test]
    fn overflowing_io_number_gets_a_space_before_output_and_input_operators() {
        assert_eq!(neutralized("echo 2147483648>f"), "echo 2147483648 >f");
        assert_eq!(
            neutralized("cat 99999999999999999999<f"),
            "cat 99999999999999999999 <f"
        );
        assert_eq!(
            neutralized("echo 99999999999999999999>>f"),
            "echo 99999999999999999999 >>f"
        );
    }

    #[test]
    fn overflowing_io_number_at_the_start_of_the_command_is_rewritten() {
        assert_eq!(
            neutralized("99999999999999999999>x"),
            "99999999999999999999 >x"
        );
    }

    // The old byte-level scan was quote-blind and rewrote these; brush's own
    // tokens keep the quotes in the word text, so a quoted run is never an
    // io-number and must stay byte-identical.
    #[test]
    fn quoted_digit_run_followed_by_a_redirect_is_unchanged() {
        for command in [
            "echo '99999999999999999999'>x",
            "echo \"99999999999999999999\">x",
            "echo \"a 99999999999999999999>x\"",
            "echo 'a 99999999999999999999>x'",
        ] {
            assert_eq!(neutralized(command), command, "{command}");
        }
    }

    #[test]
    fn overflowing_io_number_split_by_a_continuation_is_still_neutralized() {
        for command in ["echo 21474836\\\n48>f", "echo 2147483648\\\n>f"] {
            let rewritten = neutralized(command);
            let Ok(tokens) =
                uncached_tokenize_str(&rewritten, &parser_options().tokenizer_options())
            else {
                panic!("rewritten command {rewritten:?} must tokenize");
            };
            let contiguous_overflow = tokens.windows(2).any(|pair| {
                matches!(
                    pair,
                    [Token::Word(w, ws), Token::Operator(_, os)]
                        if ws.end.index == os.start.index
                            && w.chars().all(|c| c.is_ascii_digit())
                            && w.parse::<i32>().is_err()
                )
            });
            assert!(!contiguous_overflow, "{command:?} -> {rewritten:?}");
        }
    }

    // Token spans count characters; the insertion must land on the right
    // byte after multi-byte text.
    #[test]
    fn overflow_rewrite_after_multibyte_text_lands_on_the_right_byte() {
        assert_eq!(
            neutralized("echo \u{e9}\u{e9}\u{e9} 99999999999999999999>f"),
            "echo \u{e9}\u{e9}\u{e9} 99999999999999999999 >f"
        );
    }

    #[test]
    fn overflow_rewrite_after_a_heredoc_body_lands_on_the_right_byte() {
        assert_eq!(
            neutralized("cat <<E\nbody \u{e9}\nE\necho 99999999999999999999>f"),
            "cat <<E\nbody \u{e9}\nE\necho 99999999999999999999 >f"
        );
    }

    #[test]
    fn untokenizable_input_is_passed_through_for_the_parser_to_reject() {
        let command = "echo 'unterminated 99999999999999999999>f";
        assert_eq!(neutralized(command), command);
    }

    // ---- issue #443: strip_raw_line_continuations and
    // neutralize_overflowing_io_redirect_numbers's continuation-transparent
    // digit-run scan ----

    #[test]
    fn strip_raw_line_continuations_is_a_no_op_with_no_backslash_newline() {
        assert!(matches!(
            strip_raw_line_continuations("echo hi"),
            std::borrow::Cow::Borrowed("echo hi")
        ));
    }

    #[test]
    fn strip_raw_line_continuations_removes_a_lone_pair() {
        assert_eq!(
            strip_raw_line_continuations("i\\\nf true").as_ref(),
            "if true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_keeps_an_even_backslash_run_and_its_newline() {
        // Two backslashes pair up into one literal backslash; the newline
        // is a real, uncontinued separator in real bash and must survive.
        assert_eq!(
            strip_raw_line_continuations("x\\\\\nif true").as_ref(),
            "x\\\\\nif true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_strips_only_the_last_of_an_odd_run() {
        // Three backslashes: the first two pair into one literal backslash
        // (kept), the third pairs with the newline (stripped).
        assert_eq!(
            strip_raw_line_continuations("x\\\\\\\nif true").as_ref(),
            "x\\\\if true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_does_not_strip_inside_a_comment() {
        // Brush ends a comment at the first raw newline regardless of a
        // preceding backslash, so this scan must not remove it either.
        assert_eq!(
            strip_raw_line_continuations("# x\\\nif true").as_ref(),
            "# x\\\nif true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_still_strips_a_real_continuation_after_a_comment_line() {
        assert_eq!(
            strip_raw_line_continuations("# comment\ni\\\nf true").as_ref(),
            "# comment\nif true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_is_fooled_by_a_quoted_hash_after_a_boundary() {
        // A `#` inside a quoted string, sitting right after a space, is
        // indistinguishable from a real comment opener to this quote-blind
        // scan: it wrongly suppresses stripping the real continuation right
        // after it. `strip_raw_line_continuations_blind` below has no such
        // gap -- `reject_excessive_raw_nesting` runs against both.
        assert_eq!(
            strip_raw_line_continuations("echo 'a #'; i\\\nf true").as_ref(),
            "echo 'a #'; i\\\nf true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_blind_ignores_a_quoted_hash() {
        assert_eq!(
            strip_raw_line_continuations_blind("echo 'a #'; i\\\nf true").as_ref(),
            "echo 'a #'; if true"
        );
    }

    #[test]
    fn strip_raw_line_continuations_blind_strips_through_a_real_comment() {
        // The blind scan's own, opposite blind spot: it has no comment
        // concept at all, so it strips a continuation inside a genuine
        // comment too -- `strip_raw_line_continuations` (comment-aware)
        // covers that shape instead.
        assert_eq!(
            strip_raw_line_continuations_blind("# x\\\nif true").as_ref(),
            "# xif true"
        );
    }

    fn reject_ansi_c(command: &str) -> Result<(), ParseError> {
        let blind = strip_raw_line_continuations_blind(command);
        reject_ansi_c_quote_with_line_continuation(command, blind.as_ref())
    }

    #[test]
    fn reject_ansi_c_quote_with_line_continuation_rejects_the_combination() {
        assert!(reject_ansi_c("bash -c $'echo x #\\\nrm -rf /'").is_err());
    }

    #[test]
    fn reject_ansi_c_quote_with_line_continuation_allows_ansi_c_alone() {
        assert!(reject_ansi_c("echo $'hello\\nworld'").is_ok());
    }

    #[test]
    fn reject_ansi_c_quote_with_line_continuation_allows_continuation_alone() {
        assert!(reject_ansi_c("echo hi\\\nthere").is_ok());
    }

    /// Bash's input layer removes a `\`+newline pair before its tokenizer
    /// looks for the `$'` opener, so `$\<newline>'...'` forms an ANSI-C
    /// opener in real bash without the literal substring `$'` ever
    /// appearing in the raw command — checking `blind` too closes this.
    #[test]
    fn reject_ansi_c_quote_with_line_continuation_rejects_a_split_opener() {
        assert!(reject_ansi_c("bash -c $\\\n'echo x #\\\nrm -rf /'").is_err());
    }

    #[test]
    fn strip_raw_line_continuations_handles_a_trailing_lone_backslash() {
        assert_eq!(
            strip_raw_line_continuations("echo x\\").as_ref(),
            "echo x\\"
        );
    }
}
