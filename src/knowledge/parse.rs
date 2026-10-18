//! The one option parser: getopt_long-equivalent over an [`OptionGrammar`].
//!
//! Short clusters, attached values, unique-prefix long abbreviation, `--`,
//! and the per-command ordering ([`ArgOrder`]). An option the grammar does
//! not describe makes the result `Err(Unmodeled)`. The error still carries a
//! [`ParsedArgv`] that treats each such token as a lone flag, because the
//! wrapped command must stay visible to rule matching while the caller
//! raises the floor; nothing may read that value as an Ok parse.

use super::spec::{ArgOrder, CommandSpec, OptionGrammar};
use crate::normalize::{NormalizedWord, Resolution};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionName {
    Short(char),
    Long(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OptionValue<'a> {
    Absent,
    /// Attached to the option's own token (`-uroot`, `--user=root`).
    Glued(&'a str),
    /// The next argument word.
    Separate(&'a NormalizedWord),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedOption<'a> {
    pub(crate) name: OptionName,
    pub(crate) value: OptionValue<'a>,
    /// Index of the option's own token among the parsed words.
    pub(crate) token: usize,
}

#[derive(Debug)]
pub(crate) struct ParsedArgv<'a> {
    options: Vec<ParsedOption<'a>>,
    options_end: usize,
    command_at: usize,
    applies: bool,
}

impl<'a> ParsedArgv<'a> {
    pub(crate) fn options(&self) -> &[ParsedOption<'a>] {
        &self.options
    }

    /// Index where the option region ends: the first operand, the word
    /// after `--`, or the first unresolvable word.
    pub(crate) fn options_end(&self) -> usize {
        self.options_end
    }

    /// Index of the command operand within the parsed words; equal to their
    /// length when none is left, and pointing at the word that stopped the
    /// parse when that word is unresolvable.
    pub(crate) fn command_at(&self) -> usize {
        self.command_at
    }

    /// Whether the words spell a call that runs another command: `false`
    /// when the command needs a subcommand (`poetry run`) the words lack.
    pub(crate) fn applies(&self) -> bool {
        self.applies
    }

    #[cfg(test)]
    pub(crate) fn has_option(&self, short: char, long: &'static str) -> bool {
        self.options.iter().any(|option| {
            option.name == OptionName::Short(short) || option.name == OptionName::Long(long)
        })
    }
}

/// An option the grammar does not describe: an unknown flag, an unknown or
/// ambiguous long abbreviation, or a value shape the grammar rules out.
#[derive(Debug)]
pub(crate) struct Unmodeled<'a> {
    command: &'static str,
    token: usize,
    best_effort: ParsedArgv<'a>,
}

/// What an [`Unmodeled`] parse found, without the parse itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Finding {
    command: &'static str,
    token: usize,
}

impl Finding {
    pub(crate) fn command(&self) -> &'static str {
        self.command
    }

    /// Index of the first unmodelled option token among the parsed words.
    #[cfg(test)]
    pub(crate) fn token(&self) -> usize {
        self.token
    }
}

impl<'a> Unmodeled<'a> {
    pub(crate) fn finding(&self) -> Finding {
        Finding {
            command: self.command,
            token: self.token,
        }
    }

    /// The parse with every unmodelled token consumed as a lone flag. Only
    /// for keeping the wrapped command visible; it is not an Ok result.
    pub(crate) fn into_best_effort(self) -> ParsedArgv<'a> {
        self.best_effort
    }
}

enum Flow {
    Next(usize),
    StopAt(usize),
}

enum Arity {
    Flag,
    Value,
    Glued,
    Pair,
}

enum LongLookup {
    Found(&'static str, Arity),
    Unknown,
}

impl OptionGrammar {
    fn long_names(&self) -> impl Iterator<Item = (&'static str, Arity)> {
        let flags = self.long_flags.iter().map(|name| (*name, Arity::Flag));
        let values = self.long_values.iter().map(|name| (*name, Arity::Value));
        let glued = self.long_glued.iter().map(|name| (*name, Arity::Glued));
        let pairs = self.long_pairs.iter().map(|name| (*name, Arity::Pair));
        flags.chain(values).chain(glued).chain(pairs)
    }

    /// An exact name wins over an abbreviation (`--login` over
    /// `--login-class`); otherwise a prefix must be unique.
    fn find_long(&self, name: &str) -> LongLookup {
        if let Some((full, arity)) = self.long_names().find(|(full, _)| *full == name) {
            return LongLookup::Found(full, arity);
        }
        let mut matches = self.long_names().filter(|(full, _)| full.starts_with(name));
        match (matches.next(), matches.next()) {
            (Some((full, arity)), None) => LongLookup::Found(full, arity),
            _ => LongLookup::Unknown,
        }
    }

    fn takes_short_value(&self, letter: char) -> bool {
        self.short_values.contains(letter)
            || self.short_values_unless_dash.contains(letter)
            || self.short_glued.contains(letter)
    }

    /// The canonical long name `token`'s `--name` part spells, when it is a
    /// unique abbreviation or exact match.
    pub(crate) fn canonical_long(&self, name: &str) -> Option<&'static str> {
        match self.find_long(name) {
            LongLookup::Found(full, _) => Some(full),
            LongLookup::Unknown => None,
        }
    }

    /// Where `letter`'s value lives when `token` is a short cluster in which
    /// `letter` is reached before any other value-taking or unmodelled
    /// letter; `None` otherwise.
    pub(crate) fn locate_short_value<'t>(
        &self,
        token: &'t str,
        letter: char,
    ) -> Option<ShortValue<'t>> {
        let body = token.strip_prefix('-')?;
        if body.is_empty() || body.starts_with('-') {
            return None;
        }
        for (offset, c) in body.char_indices() {
            if c == letter {
                let glued = &body[offset + c.len_utf8()..];
                return Some(if glued.is_empty() {
                    ShortValue::NextToken
                } else {
                    ShortValue::Glued(glued)
                });
            }
            if self.takes_short_value(c) || !self.short_flags.contains(c) {
                return None;
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ShortValue<'a> {
    NextToken,
    Glued(&'a str),
}

struct Parser<'a> {
    grammar: &'static OptionGrammar,
    argv: &'a [NormalizedWord],
    options: Vec<ParsedOption<'a>>,
    culprit: Option<usize>,
}

impl<'a> Parser<'a> {
    fn push(&mut self, at: usize, name: OptionName, value: OptionValue<'a>) {
        self.options.push(ParsedOption {
            name,
            value,
            token: at,
        });
    }

    fn unmodeled(&mut self, at: usize) -> Flow {
        self.culprit.get_or_insert(at);
        Flow::Next(at + 1)
    }

    /// Skips the assignments starting at `from` and returns the index of the
    /// first word that is not one. A nameless `=x` is skipped but marked
    /// unmodelled: `env` rejects it, so what follows cannot be placed.
    fn skip_assignments(&mut self, from: usize) -> usize {
        let mut idx = from;
        while let Some(Resolution::Resolved(token)) =
            self.argv.get(idx).map(NormalizedWord::resolution)
            && is_assignment(token)
        {
            if token.starts_with('=') {
                self.culprit.get_or_insert(idx);
            }
            idx += 1;
        }
        idx
    }

    /// Takes the next word as `name`'s separated value.
    fn separate_value(&mut self, name: OptionName, at: usize) -> Flow {
        match self.argv.get(at + 1) {
            None => {
                self.push(at, name, OptionValue::Absent);
                Flow::Next(at + 1)
            }
            Some(word) => {
                self.push(at, name, OptionValue::Separate(word));
                match word.resolution() {
                    Resolution::Resolved(_) => Flow::Next(at + 2),
                    // The value is unknown, so what follows cannot be
                    // placed: stop on it and let the caller fail closed.
                    Resolution::Unresolvable(_) => Flow::StopAt(at + 1),
                }
            }
        }
    }

    /// Takes the next two words as `name`'s separated values.
    fn pair_value(&mut self, name: OptionName, at: usize) -> Flow {
        let (Some(first), Some(second)) = (self.argv.get(at + 1), self.argv.get(at + 2)) else {
            self.push(at, name, OptionValue::Absent);
            return self.unmodeled(at);
        };
        self.push(at, name, OptionValue::Separate(first));
        match (first.resolution(), second.resolution()) {
            (Resolution::Resolved(_), Resolution::Resolved(_)) => Flow::Next(at + 3),
            (Resolution::Unresolvable(_), _) => Flow::StopAt(at + 1),
            (_, Resolution::Unresolvable(_)) => Flow::StopAt(at + 2),
        }
    }

    fn short_cluster(&mut self, at: usize, token: &'a str) -> Flow {
        let grammar = self.grammar;
        let body = &token[1..];
        if grammar.numeric_option && body.bytes().all(|b| b.is_ascii_digit()) {
            return Flow::Next(at + 1);
        }
        for (offset, c) in body.char_indices() {
            let rest = &body[offset + c.len_utf8()..];
            let name = OptionName::Short(c);
            if grammar.short_flags.contains(c) {
                self.push(at, name, OptionValue::Absent);
            } else if grammar.short_glued.contains(c) {
                let value = if rest.is_empty() {
                    OptionValue::Absent
                } else {
                    OptionValue::Glued(rest)
                };
                self.push(at, name, value);
                return Flow::Next(at + 1);
            } else if grammar.short_values.contains(c)
                || grammar.short_values_unless_dash.contains(c)
            {
                if !rest.is_empty() {
                    self.push(at, name, OptionValue::Glued(rest));
                    return Flow::Next(at + 1);
                }
                let next_is_dash = matches!(
                    self.argv.get(at + 1).map(NormalizedWord::resolution),
                    Some(Resolution::Resolved(word)) if word.starts_with('-')
                );
                if grammar.short_values_unless_dash.contains(c) && next_is_dash {
                    self.push(at, name, OptionValue::Absent);
                    return Flow::Next(at + 1);
                }
                return self.separate_value(name, at);
            } else {
                return self.unmodeled(at);
            }
        }
        Flow::Next(at + 1)
    }

    fn long_option(&mut self, at: usize, token: &'a str) -> Flow {
        let body = token.strip_prefix("--").unwrap_or(&token[1..]);
        let (name, attached) = match body.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (body, None),
        };
        if name.is_empty() {
            return self.unmodeled(at);
        }
        match self.grammar.find_long(name) {
            LongLookup::Found(full, Arity::Flag) => {
                if attached.is_some() {
                    return self.unmodeled(at);
                }
                self.push(at, OptionName::Long(full), OptionValue::Absent);
                Flow::Next(at + 1)
            }
            LongLookup::Found(full, Arity::Value) => match attached {
                Some(value) => {
                    self.push(at, OptionName::Long(full), OptionValue::Glued(value));
                    Flow::Next(at + 1)
                }
                None => self.separate_value(OptionName::Long(full), at),
            },
            LongLookup::Found(full, Arity::Pair) => {
                if attached.is_some() {
                    return self.unmodeled(at);
                }
                self.pair_value(OptionName::Long(full), at)
            }
            LongLookup::Found(full, Arity::Glued) => {
                let value = attached.map_or(OptionValue::Absent, OptionValue::Glued);
                self.push(at, OptionName::Long(full), value);
                Flow::Next(at + 1)
            }
            LongLookup::Unknown if self.grammar.any_long_attached => Flow::Next(at + 1),
            LongLookup::Unknown => self.unmodeled(at),
        }
    }

    fn option(&mut self, at: usize, token: &'a str) -> Flow {
        let word = &token[1..];
        let grammar = self.grammar;
        if token.starts_with("--") || grammar.single_dash_long {
            self.long_option(at, token)
        } else if let Some(name) = grammar.dash_words.iter().find(|name| **name == word) {
            self.push(at, OptionName::Long(name), OptionValue::Absent);
            Flow::Next(at + 1)
        } else if let Some(name) = grammar.dash_word_values.iter().find(|name| **name == word) {
            self.separate_value(OptionName::Long(name), at)
        } else {
            self.short_cluster(at, token)
        }
    }
}

/// Whether `token` is an argument the wrapper applies as an environment
/// assignment. Not the POSIX identifier shape: GNU and BSD `env` take any
/// argument containing `=` and `putenv` does not validate the name, so
/// `a.b=c` and `1a=b` are skipped before the command is exec'd.
fn is_assignment(token: &str) -> bool {
    token.contains('=')
}

/// The length of the first of `alternatives` that `words` start with.
fn match_subcommand(alternatives: &[&[&str]], words: &[NormalizedWord]) -> Option<usize> {
    alternatives
        .iter()
        .find(|alternative| {
            alternative.len() <= words.len()
                && alternative.iter().zip(words).all(|(want, word)| {
                    matches!(word.resolution(), Resolution::Resolved(text) if text == want)
                })
        })
        .map(|alternative| alternative.len())
}

/// The index just past the first `command_after` marker at or behind `from`,
/// unless the marker was already parsed as an option ahead of the first
/// operand (`nix develop -c cmd -c`), where the first operand is the command.
fn command_after_marker(
    grammar: &OptionGrammar,
    parsed: &[ParsedOption<'_>],
    argv: &[NormalizedWord],
    from: usize,
) -> Option<usize> {
    if grammar.command_after.is_empty() {
        return None;
    }
    let seen = parsed.iter().any(|option| match option.name {
        OptionName::Short(c) => grammar.command_after.contains(&format!("-{c}").as_str()),
        OptionName::Long(name) => grammar
            .command_after
            .contains(&format!("--{name}").as_str()),
    });
    if seen {
        return None;
    }
    argv[from..]
        .iter()
        .position(|word| {
            matches!(word.resolution(), Resolution::Resolved(text)
                if grammar.command_after.contains(&text.as_str()))
        })
        .map(|offset| from + offset + 1)
}

/// Parses `argv` (the words after the command name) against `spec`.
///
/// # Errors
///
/// `Unmodeled` when any option token is not described by the grammar.
pub(crate) fn parse<'a>(
    command: &'static str,
    spec: &'static CommandSpec,
    argv: &'a [NormalizedWord],
) -> Result<ParsedArgv<'a>, Unmodeled<'a>> {
    let grammar = &spec.options;
    let mut parser = Parser {
        grammar,
        argv,
        options: Vec::new(),
        culprit: None,
    };
    let mut remaining_operands = spec.leading_operands();
    let mut idx = 0;
    if grammar.leading_operand
        && let Some(Resolution::Resolved(first)) = argv.first().map(NormalizedWord::resolution)
        && !first.starts_with('-')
    {
        idx = 1;
    }

    let mut options_end = None;
    let mut command_at = None;
    let mut sub_pending = spec.subcommands();
    while idx < argv.len() {
        let Resolution::Resolved(token) = argv[idx].resolution() else {
            break;
        };
        if token == "--" {
            idx += 1;
            if grammar.assignments {
                idx = parser.skip_assignments(idx);
            }
            break;
        }
        if grammar.assignments && !token.starts_with('-') && is_assignment(token) {
            idx = parser.skip_assignments(idx);
            continue;
        }
        let is_option = (token.starts_with('-') && token.len() > 1)
            || (token == "-" && grammar.bare_dash_option);
        if is_option {
            match parser.option(idx, token) {
                Flow::Next(next) => idx = next,
                Flow::StopAt(stop) => {
                    idx = stop;
                    break;
                }
            }
            continue;
        }
        if let Some(alternatives) = sub_pending {
            let Some(len) = match_subcommand(alternatives, &argv[idx..]) else {
                break;
            };
            sub_pending = None;
            idx += len;
            continue;
        }
        match grammar.order {
            ArgOrder::FirstOperand => {
                if let Some(at) = command_after_marker(grammar, &parser.options, argv, idx) {
                    command_at = Some(at);
                }
                break;
            }
            ArgOrder::PermuteUntilCommand => {
                options_end.get_or_insert(idx);
                if remaining_operands == 0 {
                    command_at = Some(idx);
                    break;
                }
                remaining_operands -= 1;
                idx += 1;
            }
        }
    }
    let options_end = options_end.unwrap_or(idx);

    let command_at = match command_at {
        Some(at) => at,
        None => {
            while remaining_operands > 0
                && let Some(Resolution::Resolved(_)) = argv.get(idx).map(NormalizedWord::resolution)
            {
                idx += 1;
                remaining_operands -= 1;
            }
            // A lone `--` after the operands is never itself the command.
            if let Some(Resolution::Resolved(token)) = argv.get(idx).map(NormalizedWord::resolution)
                && token == "--"
            {
                idx += 1;
            }
            idx
        }
    };

    if grammar.dash_command_unmodeled
        && let Some(Resolution::Resolved(word)) =
            argv.get(command_at).map(NormalizedWord::resolution)
        && word.starts_with('-')
        && word.len() > 1
    {
        parser.culprit.get_or_insert(command_at);
    }

    let parsed = ParsedArgv {
        options: parser.options,
        options_end,
        command_at,
        applies: sub_pending.is_none(),
    };
    match parser.culprit {
        None => Ok(parsed),
        Some(token) => Err(Unmodeled {
            command,
            token,
            best_effort: parsed,
        }),
    }
}
