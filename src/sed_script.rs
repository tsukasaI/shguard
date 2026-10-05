//! Rule 6e (issue #584): a small, deliberately conservative `sed` script
//! lexer. `sed`'s script is interpreter code: the `w`/`W` commands and the
//! `w` flag of `s///` write to an arbitrary path (no `-i` needed), `r`/`R`
//! read one, and GNU's `e` command and `s///e` flag run a shell command.
//! None of that is visible to the argv-level blocklist rules, so
//! [`classify`] decides whether an invocation's script can be shown free of
//! all of them; anything it cannot show floors to `Ask` in `crate::gate`.
//!
//! The lexer follows sed's command grammar (addresses, `{}` blocks, `s`/`y`
//! with arbitrary delimiters, `a`/`i`/`c` text, labels), because `w` can
//! appear as data (`s/w/x/`, `s|a|b|g`) and `s` accepts any delimiter. It
//! errs toward over-reporting: any command letter it does not recognise,
//! any unresolved script word and any `-f script-file` (never read here)
//! counts as "not proven free". That includes harmless-looking cases:
//! `w /dev/stdout` and a script built from an unresolved expansion
//! (`sed "s/$a/$b/" f`) both Ask.
//!
//! GNU and BSD `sed` disagree on a few points that change where the script
//! is and how it splits, so [`classify`] analyses every combination and a
//! single dangerous reading wins. A reading is only dropped when it is a
//! definite syntax error in that dialect (real sed would refuse to run it):
//! - `-i` takes a separate suffix word on BSD only, `-l` a separate number
//!   on GNU only;
//! - GNU permutes options past operands, BSD stops at the first operand;
//! - GNU does not treat a delimiter inside a `[...]` bracket expression as
//!   literal, while BSD/POSIX do (`s/[^/]*$//`).

use crate::normalize::{NormalizedWord, Resolution};

/// Why a `sed` invocation's script is not proven free of file-write,
/// file-read and command-execution commands. Used only for the Ask
/// reason string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unproven {
    /// A `w`/`W` command or `s///w` flag.
    Write,
    /// A GNU `e` command or `s///e` flag.
    Exec,
    /// An `r`/`R` command.
    Read,
    /// `-f`/`--file`: the script file is never read.
    ScriptFile,
    /// A script or option word could not be statically resolved.
    Unresolved,
    /// The script (or option list) could not be lexed.
    Unlexable,
}

impl Unproven {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Write => "it contains a `w`/`W` file-write command or `s///w` flag",
            Self::Exec => "it contains an `e` command-execution command or `s///e` flag",
            Self::Read => "it contains an `r`/`R` file-read command",
            Self::ScriptFile => "its script comes from a `-f` file that is never read",
            Self::Unresolved => "its script or an option could not be statically resolved",
            Self::Unlexable => "its script could not be lexed with confidence",
        }
    }
}

/// What one dialect reading of the invocation concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Safe,
    Unsafe(Unproven),
    /// A definite syntax error in this reading (unterminated `s`, unknown
    /// `s` flag or command letter, missing option value, no script): the
    /// real sed would refuse to run it, so it contributes nothing unless
    /// every reading is one. Anything the lexer merely cannot classify is
    /// `Unsafe(Unproven::Unlexable)` instead, because another dialect might
    /// accept it.
    Unparseable,
}

/// `None` when every reading of `args` (the words after the `sed` command
/// name) is proven free of write/read/exec commands; otherwise the first
/// reason it is not.
pub(crate) fn classify(args: &[NormalizedWord]) -> Option<Unproven> {
    let mut any_safe = false;
    for bsd in [false, true] {
        match script_sources(args, bsd) {
            Err(Outcome::Unsafe(why)) => return Some(why),
            Err(Outcome::Unparseable) => {}
            Err(Outcome::Safe) | Ok(None) => any_safe = true,
            Ok(Some(script)) => {
                for bracket_aware in [false, true] {
                    match lex_script(&script, bracket_aware) {
                        Outcome::Unsafe(why) => return Some(why),
                        Outcome::Safe => any_safe = true,
                        Outcome::Unparseable => {}
                    }
                }
            }
        }
    }
    if any_safe {
        None
    } else {
        Some(Unproven::Unlexable)
    }
}

/// The text sed would run under one dialect reading: every `-e` value
/// joined by newlines, else the first operand. `Ok(None)` for
/// `--version`/`--help` (nothing runs). `Err(Safe)` is never produced.
fn script_sources(args: &[NormalizedWord], bsd: bool) -> Result<Option<String>, Outcome> {
    let mut expressions: Vec<String> = Vec::new();
    let mut first_operand: Option<String> = None;
    let mut options_ended = false;
    let mut info_only = false;
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        let Resolution::Resolved(text) = word.resolution() else {
            // Only past `--` (with the script already known) is an
            // unresolved word certainly a file operand; before that GNU
            // getopt may read its runtime value as an option.
            if options_ended && (first_operand.is_some() || !expressions.is_empty()) {
                continue;
            }
            return Err(Outcome::Unsafe(Unproven::Unresolved));
        };
        let text = text.as_str();
        if options_ended || !text.starts_with('-') || text == "-" {
            if bsd {
                options_ended = true;
            }
            first_operand.get_or_insert_with(|| text.to_string());
            continue;
        }
        if text == "--" {
            options_ended = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            let Some(name) = resolve_long_option(name) else {
                return Err(Outcome::Unsafe(Unproven::Unlexable));
            };
            match name {
                "expression" => match value {
                    Some(v) => expressions.push(v.to_string()),
                    None => expressions.push(take_value(args, &mut i, true)?),
                },
                "file" => return Err(Outcome::Unsafe(Unproven::ScriptFile)),
                "line-length" if value.is_none() => {
                    take_value(args, &mut i, false)?;
                }
                "in-place" | "line-length" | "quiet" | "silent" | "regexp-extended" | "posix"
                | "debug" | "sandbox" | "separate" | "unbuffered" | "null-data"
                | "zero-terminated" | "binary" | "follow-symlinks" => {}
                _ => info_only = true,
            }
            continue;
        }
        let cluster: Vec<char> = text[1..].chars().collect();
        let mut j = 0;
        while j < cluster.len() {
            let flag = cluster[j];
            j += 1;
            let glued: String = cluster[j..].iter().collect();
            match flag {
                'n' | 's' | 'E' | 'r' | 'z' | 'u' | 'b' => {}
                'a' | 'l' if bsd => {}
                'f' => return Err(Outcome::Unsafe(Unproven::ScriptFile)),
                'e' => {
                    expressions.push(if glued.is_empty() {
                        take_value(args, &mut i, true)?
                    } else {
                        glued
                    });
                    break;
                }
                'l' => {
                    if glued.is_empty() {
                        take_value(args, &mut i, false)?;
                    }
                    break;
                }
                // GNU: `-iSUFFIX` only. BSD: the suffix is a separate word.
                // `-I` exists on BSD only; read it the BSD way in both.
                'i' | 'I' => {
                    if glued.is_empty() && (bsd || flag == 'I') {
                        take_value(args, &mut i, false)?;
                    }
                    break;
                }
                _ => return Err(Outcome::Unsafe(Unproven::Unlexable)),
            }
        }
    }
    if info_only {
        return Ok(None);
    }
    if !expressions.is_empty() {
        return Ok(Some(expressions.join("\n")));
    }
    first_operand.map(Some).ok_or(Outcome::Unparseable)
}

/// GNU `sed` long options. getopt_long accepts any unambiguous prefix, so
/// `--expr=...` is `--expression=...`.
const LONG_OPTIONS: &[&str] = &[
    "expression",
    "file",
    "in-place",
    "line-length",
    "quiet",
    "silent",
    "regexp-extended",
    "posix",
    "debug",
    "sandbox",
    "separate",
    "unbuffered",
    "null-data",
    "zero-terminated",
    "binary",
    "follow-symlinks",
    "version",
    "help",
];

/// The full option name `name` selects, or `None` when it is unknown or an
/// ambiguous prefix. Both are treated as unlexable by the caller rather than
/// as a syntax error: a dialect that rejects the word as an option would
/// instead consume it as a value, hiding it from the other reading.
fn resolve_long_option(name: &str) -> Option<&'static str> {
    if let Some(exact) = LONG_OPTIONS.iter().find(|o| **o == name) {
        return Some(exact);
    }
    let mut matches = LONG_OPTIONS.iter().filter(|o| o.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// Consumes the next word as an option value. `needed` values (a script)
/// must be resolved; others (a suffix, a line length) may be anything.
fn take_value(args: &[NormalizedWord], i: &mut usize, needed: bool) -> Result<String, Outcome> {
    let word = args.get(*i).ok_or(Outcome::Unparseable)?;
    *i += 1;
    match word.resolution() {
        Resolution::Resolved(v) => Ok(v.clone()),
        Resolution::Unresolvable(_) if needed => Err(Outcome::Unsafe(Unproven::Unresolved)),
        Resolution::Unresolvable(_) => Ok(String::new()),
    }
}

fn lex_script(script: &str, bracket_aware: bool) -> Outcome {
    let mut lexer = Lexer {
        chars: script.chars().collect(),
        pos: 0,
        bracket_aware,
    };
    match lexer.commands() {
        Ok(()) => Outcome::Safe,
        Err(outcome) => outcome,
    }
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    bracket_aware: bool,
}

impl Lexer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn next_or_err(&mut self) -> Result<char, Outcome> {
        self.bump().ok_or(Outcome::Unparseable)
    }

    fn skip_while(&mut self, pred: impl Fn(char) -> bool) {
        while self.peek().is_some_and(&pred) {
            self.pos += 1;
        }
    }

    fn skip_blanks(&mut self) {
        self.skip_while(|c| c == ' ' || c == '\t');
    }

    /// Every command is followed by whatever comes next lexed as another
    /// command, never rejected for "extra characters": over-reading only
    /// ever finds more commands, never fewer.
    fn commands(&mut self) -> Result<(), Outcome> {
        loop {
            self.skip_while(|c| c.is_whitespace() || c == ';');
            if self.peek().is_none() {
                return Ok(());
            }
            if self.skip_address()? {
                self.skip_blanks();
                if self.peek() == Some(',') {
                    self.pos += 1;
                    self.skip_blanks();
                    if matches!(self.peek(), Some('+' | '~')) {
                        self.pos += 1;
                        self.skip_while(|c| c.is_ascii_digit());
                    } else if !self.skip_address()? {
                        return Err(Outcome::Unparseable);
                    }
                }
            }
            self.skip_blanks();
            while self.peek() == Some('!') {
                self.pos += 1;
                self.skip_blanks();
            }
            match self.next_or_err()? {
                '{' | '}' | '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P'
                | 'x' | 'z' | 'F' => {}
                '#' => self.skip_while(|c| c != '\n'),
                'l' | 'L' | 'q' | 'Q' => {
                    self.skip_blanks();
                    self.skip_while(|c| c.is_ascii_digit());
                }
                'a' | 'i' | 'c' => self.skip_text(),
                // GNU ends a label at `;`/whitespace; BSD reads to the end
                // of the line. Ending it early lexes more, never less.
                ':' | 'b' | 't' | 'T' | 'v' => {
                    self.skip_blanks();
                    self.skip_while(|c| !c.is_whitespace() && c != ';' && c != '}');
                }
                's' => self.substitute()?,
                'y' => self.transliterate()?,
                'w' | 'W' => return Err(Outcome::Unsafe(Unproven::Write)),
                'e' => return Err(Outcome::Unsafe(Unproven::Exec)),
                'r' | 'R' => return Err(Outcome::Unsafe(Unproven::Read)),
                _ => return Err(Outcome::Unparseable),
            }
        }
    }

    /// `a`/`i`/`c` text runs to the first unescaped newline.
    fn skip_text(&mut self) {
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    self.bump();
                }
                '\n' => return,
                _ => {}
            }
        }
    }

    /// Consumes one address if present; `Ok(false)` when none starts here.
    fn skip_address(&mut self) -> Result<bool, Outcome> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                self.skip_while(|c| c.is_ascii_digit());
                if self.peek() == Some('~') {
                    self.pos += 1;
                    self.skip_while(|c| c.is_ascii_digit());
                }
                Ok(true)
            }
            Some('$') => {
                self.pos += 1;
                Ok(true)
            }
            Some('/') => {
                self.pos += 1;
                self.address_regex('/')?;
                Ok(true)
            }
            Some('\\') => {
                self.pos += 1;
                let delim = self.next_or_err()?;
                if delim == '\\' || delim == '\n' {
                    return Err(Outcome::Unsafe(Unproven::Unlexable));
                }
                self.address_regex(delim)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn address_regex(&mut self, delim: char) -> Result<(), Outcome> {
        self.skip_delimited(delim, true)?;
        self.skip_while(|c| c == 'I' || c == 'M');
        Ok(())
    }

    /// Skips to just past the next unescaped `delim`. `regex` parts are
    /// bracket-aware in the BSD/POSIX reading.
    fn skip_delimited(&mut self, delim: char, regex: bool) -> Result<(), Outcome> {
        loop {
            let c = self.next_or_err()?;
            if c == '\\' {
                self.next_or_err()?;
            } else if c == delim {
                return Ok(());
            } else if c == '\n' {
                return Err(Outcome::Unparseable);
            } else if c == '[' && regex && self.bracket_aware {
                self.skip_bracket()?;
            }
        }
    }

    /// Past a `[`: a POSIX bracket expression (backslash is literal, a
    /// leading `]` is literal, `[:class:]` may nest).
    fn skip_bracket(&mut self) -> Result<(), Outcome> {
        if self.peek() == Some('^') {
            self.pos += 1;
        }
        if self.peek() == Some(']') {
            self.pos += 1;
        }
        loop {
            match self.next_or_err()? {
                ']' => return Ok(()),
                '[' if matches!(self.peek(), Some(':' | '.' | '=')) => {
                    let kind = self.next_or_err()?;
                    loop {
                        if self.next_or_err()? == kind && self.peek() == Some(']') {
                            self.pos += 1;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn delimiter(&mut self) -> Result<char, Outcome> {
        let delim = self.next_or_err()?;
        if delim == '\\' || delim == '\n' {
            Err(Outcome::Unsafe(Unproven::Unlexable))
        } else {
            Ok(delim)
        }
    }

    /// After an `s`/`y` command: only a command terminator may follow.
    fn require_command_end(&mut self) -> Result<(), Outcome> {
        match self.peek() {
            None => Ok(()),
            Some(c) if c.is_whitespace() || matches!(c, ';' | '}' | '#') => Ok(()),
            Some(_) => Err(Outcome::Unparseable),
        }
    }

    fn substitute(&mut self) -> Result<(), Outcome> {
        let delim = self.delimiter()?;
        self.skip_delimited(delim, true)?;
        self.skip_delimited(delim, false)?;
        loop {
            match self.peek() {
                Some('g' | 'p' | 'i' | 'I' | 'm' | 'M') => self.pos += 1,
                Some(c) if c.is_ascii_digit() => self.pos += 1,
                Some('e') => return Err(Outcome::Unsafe(Unproven::Exec)),
                Some('w') => return Err(Outcome::Unsafe(Unproven::Write)),
                _ => return self.require_command_end(),
            }
        }
    }

    fn transliterate(&mut self) -> Result<(), Outcome> {
        let delim = self.delimiter()?;
        self.skip_delimited(delim, false)?;
        self.skip_delimited(delim, false)?;
        self.require_command_end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<NormalizedWord> {
        args.iter().map(|a| NormalizedWord::resolved(*a)).collect()
    }

    fn verdict(args: &[&str]) -> Option<Unproven> {
        classify(&words(args))
    }

    #[test]
    fn ordinary_scripts_are_proven_free() {
        for args in [
            &["-n", "1,5p", "f"][..],
            &["s/a/b/g", "f"],
            &["-i", "s/x/y/", "f"],
            &["-i", "", "s/x/y/", "f"],
            &["-i.bak", "s/x/y/", "f"],
            &["-e", "s|a|b|", "f"],
            &["-ne", "/^#/d;p", "f"],
            &["--expression=s/w/x/", "f"],
            &["-n", "-e", "$p", "f"],
            &["s/w/x/g", "f"],
            &["s/\\//|/g", "f"],
            &["-E", "s/(a|b)+/c/2", "f"],
            &[":a;N;$!ba;s/\\n/ /g", "f"],
            &["$!N;P;D", "f"],
            &["1!G;h;$!d", "f"],
            &["/start/,/end/{/start/n;/end/!p}", "f"],
            &["0,/x/s//y/", "f"],
            &["y/abc/xyz/;10q", "f"],
            &["1~2d;2,+1p;3,~4p", "f"],
            &["/x/I{s/a/b/;b end;:end}", "f"],
            &["/a/a\\\nwrite w here\np", "f"],
            &["/x/c changed; w not a command", "f"],
            &["s/[^/]*$//", "f"],
            &["s/[/]/x/", "f"],
            &["-l", "5", "p", "f"],
            &["--version"],
            &["p", "--", "f"],
            &["-s", "-n", "p", "a", "b"],
        ] {
            assert_eq!(verdict(args), None, "{args:?}");
        }
    }

    #[test]
    fn write_read_and_exec_commands_are_found() {
        for (args, why) in [
            (&["-n", "w /tmp/out", "f"][..], Unproven::Write),
            (&["s/a/b/w /tmp/out", "f"], Unproven::Write),
            (&["s|a|b|gw out", "f"], Unproven::Write),
            (&["-e", "W ~/.zshrc", "f"], Unproven::Write),
            (&["p;w out", "f"], Unproven::Write),
            (&["/x/{p;w out}", "f"], Unproven::Write),
            (&["$!{w out", "}", "f"], Unproven::Write),
            (&["/a/ , /b/ ! w out", "f"], Unproven::Write),
            (&["1~2w out", "f"], Unproven::Write),
            (&["-n", "-e", "p", "-e", "w out", "f"], Unproven::Write),
            (&["--expression", "w out", "f"], Unproven::Write),
            (&["--expression=w out", "f"], Unproven::Write),
            (&["-nes/a/b/w out", "f"], Unproven::Write),
            (&["p", "-e", "w out"], Unproven::Write),
            (&["-i", "p", "-e", "w out", "f"], Unproven::Write),
            (&["a text", "-e", "w out", "f"], Unproven::Write),
            (&["e rm -rf ~", "f"], Unproven::Exec),
            (&["s/a/b/e", "f"], Unproven::Exec),
            (&["s/a/b/ge", "f"], Unproven::Exec),
            (&["1e id", "f"], Unproven::Exec),
            (&["r /etc/passwd", "f"], Unproven::Read),
            (&["/x/R /etc/passwd", "f"], Unproven::Read),
            (&["-f", "script.sed", "f"], Unproven::ScriptFile),
            (&["--file=script.sed", "f"], Unproven::ScriptFile),
            (&["-nf", "script.sed", "f"], Unproven::ScriptFile),
            // Delimiter inside a bracket: the BSD reading still finds `w`.
            (&["s/[/]/x/;w out", "f"], Unproven::Write),
            // The `:` label ends at `;` on GNU.
            (&[":a;w out", "f"], Unproven::Write),
            // After an `a` text line ends, the next line is a command.
            (&["a text\nw out", "f"], Unproven::Write),
        ] {
            assert_eq!(verdict(args), Some(why), "{args:?}");
        }
    }

    #[test]
    fn unlexable_or_unresolved_scripts_fail_closed() {
        assert_eq!(verdict(&["q;k", "f"]), Some(Unproven::Unlexable));
        assert_eq!(verdict(&["s/a/b/x", "f"]), Some(Unproven::Unlexable));
        assert_eq!(verdict(&["s/a/b", "f"]), Some(Unproven::Unlexable));
        assert_eq!(verdict(&["--expr=w out", "f"]), Some(Unproven::Write));
        assert_eq!(verdict(&["--bogus=w out", "f"]), Some(Unproven::Unlexable));
        assert_eq!(verdict(&[]), Some(Unproven::Unlexable));
        assert_eq!(verdict(&["-n"]), Some(Unproven::Unlexable));
        let unresolved =
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        assert_eq!(
            classify(std::slice::from_ref(&unresolved)),
            Some(Unproven::Unresolved)
        );
        let mut args = words(&["-n"]);
        args.push(unresolved.clone());
        args.extend(words(&["f"]));
        assert_eq!(classify(&args), Some(Unproven::Unresolved));
        let mut args = words(&["-e"]);
        args.push(unresolved);
        assert_eq!(classify(&args), Some(Unproven::Unresolved));
    }

    #[test]
    fn unresolved_word_after_the_script_is_tolerated_only_past_double_dash() {
        let quoted = NormalizedWord::unresolvable_single_word(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        );
        let mut args = words(&["-n", "1,5p"]);
        args.push(quoted.clone());
        assert_eq!(classify(&args), Some(Unproven::Unresolved));
        let mut args = words(&["-n", "--", "1,5p"]);
        args.push(quoted);
        assert_eq!(classify(&args), None);
        let unquoted =
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        let mut args = words(&["-n", "--", "1,5p"]);
        args.push(unquoted);
        assert_eq!(classify(&args), None);
    }

    #[test]
    fn gnu_valid_words_a_bsd_reading_would_swallow_are_still_found() {
        for args in [
            &["-i", "--expr=w out", "s/x/y/", "f"][..],
            &["-i", "--e=w out", "p", "f"],
            &["-i", "--fi=script.sed", "p", "f"],
            &["-i", "--fi=/dev/stdin", "p", "f"],
            &["-i", "--bogus", "p", "f"],
            &["-i", "--s", "p", "f"],
            &["-i", "s\\a\\b\\w out", "p", "f"],
            &["-i", "s\na\nb\nw out", "p", "f"],
            &["-i", "\\\\a\\\\w out", "p", "f"],
            &["-i", "b}w out", "p", "f"],
        ] {
            assert!(verdict(args).is_some(), "{args:?}");
        }
    }
}
