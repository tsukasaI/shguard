//! What shguard knows about how to read a command's argv (RFC #658 stage 2).
//!
//! A [`CommandSpec`] describes one command's option grammar and the roles
//! its words play (the command it runs, a shell string, operands consumed
//! before the command, a cwd effect, privilege escalation). The catalog is
//! embedded `&'static` data: no user extension, no serde, no I/O. Specs are
//! knowledge about reading an argv, not policy; what to do with a reading
//! is decided elsewhere.
//!
//! Invariant: for a catalogued command, an option the grammar does not
//! describe is [`Unmodeled`], never a guess. The only place that turns it
//! into a decision is `crate::gate`'s unmodelled-option floor.

mod catalog;
mod parse;
#[cfg(test)]
mod reference;
mod spec;

use crate::normalize::{NormalizedWord, Resolution};

pub(crate) use parse::{
    Finding, OptionName, OptionValue, ParsedArgv, ParsedOption, ShortValue, Unmodeled,
};
pub(crate) use spec::CwdEffect;
use spec::{CommandSpec, Slot};

/// A catalogued command found by name, with the name it was found under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Known {
    spec: &'static CommandSpec,
    name: &'static str,
}

/// Looks `folded` (case-folded, path-stripped) up in the catalog.
pub(crate) fn lookup(folded: &str) -> Option<Known> {
    catalog::CATALOG.iter().find_map(|spec| {
        spec.names
            .iter()
            .find(|name| **name == folded)
            .map(|name| Known { spec, name })
    })
}

/// Whether `folded` names a catalogued command that runs a command operand.
#[cfg(test)]
pub(crate) fn is_exec_wrapper(folded: &str) -> bool {
    lookup(folded).is_some_and(|known| known.runs_command())
}

/// Every name of a catalogued exec wrapper.
pub(crate) fn exec_wrapper_names() -> impl Iterator<Item = &'static str> {
    catalog::CATALOG
        .iter()
        .filter(|spec| spec.runs_command())
        .flat_map(|spec| spec.names.iter().copied())
}

/// Every name of a catalogued command that escalates privileges.
#[cfg(test)]
pub(crate) fn escalation_vectors() -> impl Iterator<Item = &'static str> {
    catalog::CATALOG
        .iter()
        .filter(|spec| spec.escalates_privileges())
        .flat_map(|spec| spec.names.iter().copied())
}

/// Where `letter`'s value lives in the short cluster `token` of the
/// catalogued command `folded`; see [`ShortValue`].
pub(crate) fn locate_short_value<'t>(
    folded: &str,
    token: &'t str,
    letter: char,
) -> Option<ShortValue<'t>> {
    lookup(folded)?
        .spec
        .options
        .locate_short_value(token, letter)
}

/// A value found for a [`Slot::ShellScript`] flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptValue<'a> {
    Text(&'a str),
    /// The flag's position or value could not be resolved, so whether a
    /// script is present is unknown.
    Unresolvable,
}

impl Known {
    /// The name the command was found under.
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn runs_command(&self) -> bool {
        self.spec.runs_command()
    }

    pub(crate) fn escalates_privileges(&self) -> bool {
        self.spec.escalates_privileges()
    }

    /// Parses `args` (the words after the command name).
    ///
    /// # Errors
    ///
    /// [`Unmodeled`] when an option is not described by the grammar.
    pub(crate) fn parse<'a>(
        &self,
        args: &'a [NormalizedWord],
    ) -> Result<ParsedArgv<'a>, Unmodeled<'a>> {
        parse::parse(self.name, self.spec, args)
    }

    /// Whether `token` may be an option that runs the command under another
    /// directory or root. Over-approximates on purpose (a short cluster
    /// containing the letter, a long name that is a prefix), because a false
    /// positive only makes a symlink exception fail closed.
    pub(crate) fn token_relocates_cwd(&self, token: &str) -> bool {
        let relocating = || {
            self.spec
                .cwd_options()
                .chain(self.spec.cwd_switches())
                .filter(|(_, _, effect)| *effect == CwdEffect::Relocates)
        };
        if let Some(long) = token.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if name.is_empty() {
                return false;
            }
            // Not a bare prefix match on a unique abbreviation: judge the
            // option the parser would read. Ambiguous or unknown names fall
            // back to any prefix, which only over-refuses an exception.
            return match self.spec.options.canonical_long(name) {
                Some(canonical) => relocating().any(|(_, full, _)| full == canonical),
                None => relocating().any(|(_, full, _)| full.starts_with(name)),
            };
        }
        if token == "-" {
            return self.spec.cwd_bare_dash() == Some(CwdEffect::Relocates);
        }
        token.starts_with('-') && relocating().any(|(letter, _, _)| token.contains(letter))
    }

    /// Every shell string passed through this command's script flag
    /// anywhere in `tail`. The scan is deliberately wider than the option
    /// region (`flock FILE -c cmd`, `script out -qc cmd`): a hit can only
    /// raise a floor. Any unresolvable word before the first hit is
    /// reported, since it might be the flag.
    pub(crate) fn shell_script_values<'a>(
        &self,
        tail: &'a [NormalizedWord],
    ) -> Vec<ScriptValue<'a>> {
        let mut values = Vec::new();
        for slot in self.spec.slots {
            let Slot::ShellScript { short, long } = slot else {
                continue;
            };
            let mut hit = false;
            let mut reported_unresolvable = false;
            for (index, word) in tail.iter().enumerate() {
                let Resolution::Resolved(token) = word.resolution() else {
                    if !hit && !reported_unresolvable {
                        values.push(ScriptValue::Unresolvable);
                        reported_unresolvable = true;
                    }
                    continue;
                };
                match self.locate_script_flag(*short, *long, token) {
                    None => {}
                    Some(ShortValue::Glued(text)) => {
                        hit = true;
                        values.push(ScriptValue::Text(text));
                    }
                    Some(ShortValue::NextToken) => {
                        hit = true;
                        match tail.get(index + 1).map(NormalizedWord::resolution) {
                            Some(Resolution::Resolved(text)) => {
                                values.push(ScriptValue::Text(text));
                            }
                            Some(Resolution::Unresolvable(_)) => {
                                values.push(ScriptValue::Unresolvable);
                            }
                            // A flag with nothing after it names no script.
                            None => {}
                        }
                    }
                }
            }
        }
        values
    }

    fn locate_script_flag<'t>(
        &self,
        short: Option<char>,
        long: Option<&'static str>,
        token: &'t str,
    ) -> Option<ShortValue<'t>> {
        if let Some(body) = token.strip_prefix("--") {
            let (name, attached) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (body, None),
            };
            let canonical = self.spec.options.canonical_long(name)?;
            return (Some(canonical) == long)
                .then(|| attached.map_or(ShortValue::NextToken, ShortValue::Glued));
        }
        self.spec.options.locate_short_value(token, short?)
    }

    /// The `(short, long)` spelling of the flag whose value is split into
    /// argv words, if the command has one.
    pub(crate) fn split_string_option(&self) -> Option<(char, &'static str)> {
        self.spec.split_string_option()
    }

    pub(crate) fn piped_output_option(&self) -> Option<(char, &'static str)> {
        self.spec.piped_output_option()
    }

    /// The exec flag that turns off running the operands as a shell string.
    pub(crate) fn operands_as_shell_script_exec_flag(&self) -> Option<(char, &'static str)> {
        self.spec.operands_as_shell_script_exec_flag()
    }
}

impl ParsedArgv<'_> {
    /// The options spelled `short` or `long`, in order of appearance.
    pub(crate) fn options_named(
        &self,
        flag: (char, &'static str),
    ) -> impl Iterator<Item = &ParsedOption<'_>> {
        self.options().iter().filter(move |option| {
            option.name == OptionName::Short(flag.0) || option.name == OptionName::Long(flag.1)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::normalize::NormalizedWord;

    fn words(tokens: &[&str]) -> Vec<NormalizedWord> {
        tokens
            .iter()
            .map(|t| NormalizedWord::resolved(*t))
            .collect()
    }

    fn command_at(name: &str, args: &[&str]) -> usize {
        let args = words(args);
        let known = lookup(name).expect("catalogued");
        match known.parse(&args) {
            Ok(parsed) => parsed.command_at(),
            Err(unmodeled) => unmodeled.into_best_effort().command_at(),
        }
    }

    #[test]
    fn every_reference_wrapper_has_an_exec_spec() {
        for name in reference::EXEC_WRAPPER_REFERENCE {
            assert!(
                is_exec_wrapper(name),
                "{name:?} is in the exec-wrapper reference list but has no exec CommandSpec"
            );
        }
    }

    #[test]
    fn every_exec_spec_name_is_in_the_reference_list() {
        // The list is the audit record: a wrapper added to the catalog
        // without being listed here would escape the pin test above.
        for name in exec_wrapper_names() {
            assert!(
                reference::EXEC_WRAPPER_REFERENCE.contains(&name),
                "{name:?} is an exec spec but missing from the reference list"
            );
        }
    }

    #[test]
    fn env_and_make_compose_their_cwd_option() {
        for name in ["env", "make"] {
            let spec = lookup(name).expect("catalogued").spec;
            let options: Vec<_> = spec.cwd_options().collect();
            assert_eq!(options.len(), 1, "{name}");
            assert_eq!((options[0].0, options[0].2), ('C', CwdEffect::Composed));
        }
    }

    #[test]
    fn reference_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in reference::EXEC_WRAPPER_REFERENCE {
            assert!(seen.insert(*name), "{name:?} is listed twice");
        }
    }

    #[test]
    fn no_name_is_claimed_by_two_specs() {
        let mut seen = std::collections::HashSet::new();
        for spec in catalog::CATALOG {
            for name in spec.names {
                assert!(seen.insert(*name), "{name:?} has two specs");
            }
        }
    }

    #[test]
    fn every_escalation_vector_is_an_exec_wrapper() {
        for name in escalation_vectors() {
            assert!(
                is_exec_wrapper(name),
                "{name:?} escalates but runs no command"
            );
        }
    }

    #[test]
    fn escalation_vectors_are_the_documented_set() {
        let mut found: Vec<_> = escalation_vectors().collect();
        found.sort_unstable();
        assert_eq!(found, ["doas", "pkexec", "run0", "runuser", "su", "sudo"]);
    }

    #[test]
    fn make_is_catalogued_but_runs_no_command() {
        assert!(lookup("make").is_some());
        assert!(!is_exec_wrapper("make"));
    }

    #[test]
    fn short_cluster_with_trailing_value_takes_the_next_word() {
        // `-iu FOO`: `u` is last, so `FOO` is its value and `rm` the command.
        assert_eq!(command_at("env", &["-iu", "FOO", "rm"]), 2);
        // `-ui FOO`: `i` is the glued value of `u`, so `FOO` is the command.
        assert_eq!(command_at("env", &["-ui", "FOO", "rm"]), 1);
    }

    #[test]
    fn attached_values_take_no_extra_word() {
        assert_eq!(command_at("sudo", &["-uroot", "rm"]), 1);
        assert_eq!(command_at("sudo", &["--user=root", "rm"]), 1);
        assert_eq!(command_at("sudo", &["--user", "root", "rm"]), 2);
    }

    #[test]
    fn long_abbreviation_resolves_when_unique() {
        assert_eq!(command_at("env", &["--uns", "FOO", "rm"]), 2);
        let args = words(&["--d", "x"]);
        let known = lookup("env").expect("catalogued");
        assert!(known.parse(&args).is_err(), "--d is ambiguous");
    }

    #[test]
    fn an_exact_long_name_wins_over_a_longer_one() {
        // `--login` is a boolean and `--login-class` takes a value.
        assert_eq!(command_at("sudo", &["--login", "rm"]), 1);
    }

    #[test]
    fn double_dash_ends_options() {
        assert_eq!(command_at("sudo", &["--", "-rf"]), 1);
        let args = words(&["--", "-x", "rm"]);
        let known = lookup("sudo").expect("catalogued");
        assert!(known.parse(&args).is_ok());
    }

    #[test]
    fn optional_values_are_attached_only() {
        // `--mount` never takes `rm` as its value.
        assert_eq!(command_at("unshare", &["--mount", "rm"]), 1);
        assert_eq!(command_at("unshare", &["--mount=/ns", "rm"]), 1);
    }

    #[test]
    fn operands_before_the_command_are_skipped() {
        assert_eq!(command_at("timeout", &["-k", "1", "5", "rm"]), 3);
        assert_eq!(command_at("timeout", &["--", "5", "rm"]), 2);
    }

    #[test]
    fn permuting_commands_accept_options_after_the_operand() {
        // `su root -c cmd`: the operand `root` is the user and the option
        // after it is still su's own.
        let args = words(&["root", "-c", "cmd"]);
        let known = lookup("su").expect("catalogued");
        let parsed = known.parse(&args).expect("modelled");
        assert_eq!(parsed.command_at(), args.len());
        assert!(parsed.has_option('c', "command"));
    }

    #[test]
    fn an_option_where_the_command_belongs_is_unmodeled_when_dialects_disagree() {
        // util-linux `script` permutes, BSD `script` runs `-qc`.
        let args = words(&["out.txt", "-qc", "echo hi"]);
        let known = lookup("script").expect("catalogued");
        let unmodeled = known.parse(&args).expect_err("flavor-dependent");
        assert_eq!(unmodeled.finding().token(), 1);
    }

    #[test]
    fn an_unknown_flag_is_unmodeled_but_keeps_the_command_visible() {
        let args = words(&["--bogus", "rm"]);
        let known = lookup("sudo").expect("catalogued");
        let unmodeled = known.parse(&args).expect_err("unknown option");
        assert_eq!(unmodeled.finding().command(), "sudo");
        assert_eq!(unmodeled.finding().token(), 0);
        assert_eq!(unmodeled.into_best_effort().command_at(), 1);
    }

    #[test]
    fn a_value_on_a_boolean_long_option_is_unmodeled() {
        let args = words(&["--help=x", "ls"]);
        let known = lookup("nohup").expect("catalogued");
        assert!(known.parse(&args).is_err());
    }

    #[test]
    fn a_leading_operand_is_skipped_only_when_it_is_not_an_option() {
        assert_eq!(command_at("setarch", &["x86_64", "-R", "ls"]), 2);
        assert_eq!(command_at("setarch", &["-R", "ls"]), 1);
    }

    #[test]
    fn numeric_options_belong_to_nice() {
        assert_eq!(command_at("nice", &["-10", "ls"]), 1);
    }

    #[test]
    fn script_t_takes_a_value_unless_the_next_word_is_an_option() {
        assert_eq!(command_at("script", &["-t", "0", "out", "ls"]), 3);
        let args = words(&["-t", "-qc", "ls"]);
        let known = lookup("script").expect("catalogued");
        let parsed = known.parse(&args).expect("modelled");
        assert_eq!(parsed.command_at(), args.len());
    }

    #[test]
    fn shell_script_values_find_every_spelling() {
        let known = lookup("script").expect("catalogued");
        let args = words(&["out", "-qc", "a", "--command=b", "--comm", "c"]);
        let found = known.shell_script_values(&args);
        assert_eq!(
            found,
            [
                ScriptValue::Text("a"),
                ScriptValue::Text("b"),
                ScriptValue::Text("c")
            ]
        );
    }

    #[test]
    fn relocating_cwd_flags_over_approximate() {
        let sudo = lookup("sudo").expect("catalogued");
        assert!(sudo.token_relocates_cwd("-D"));
        assert!(sudo.token_relocates_cwd("-uD"));
        assert!(sudo.token_relocates_cwd("--chdir=/x"));
        assert!(sudo.token_relocates_cwd("--ch"));
        // Ambiguous abbreviation: the prefix fallback refuses (fail closed).
        assert!(sudo.token_relocates_cwd("--c"));
        assert!(!sudo.token_relocates_cwd("--cl"));
        assert!(!sudo.token_relocates_cwd("-u"));
        let env = lookup("env").expect("catalogued");
        assert!(!env.token_relocates_cwd("-C"));
    }

    #[test]
    fn login_shell_and_chdir_wrappers_relocate_the_cwd() {
        let sudo = lookup("sudo").expect("catalogued");
        for token in ["-i", "-s", "-iu", "--login", "--shell", "--log", "--sh"] {
            assert!(sudo.token_relocates_cwd(token), "sudo {token}");
        }
        assert!(!sudo.token_relocates_cwd("-"));
        let su = lookup("su").expect("catalogued");
        for token in ["-", "-l", "-lm", "--login", "--log", "--l"] {
            assert!(su.token_relocates_cwd(token), "su {token}");
        }
        assert!(!su.token_relocates_cwd("-m"));
        let run0 = lookup("run0").expect("catalogued");
        for token in ["-D", "--chdir=/x", "--chdir", "--c=/x", "-u", "--us=alice"] {
            assert!(run0.token_relocates_cwd(token), "run0 {token}");
        }
        assert!(!run0.token_relocates_cwd("-g"));
    }

    #[test]
    fn locate_short_value_follows_cluster_rules() {
        assert!(matches!(
            locate_short_value("env", "-iC", 'C'),
            Some(ShortValue::NextToken)
        ));
        assert!(matches!(
            locate_short_value("env", "-iCdir", 'C'),
            Some(ShortValue::Glued("dir"))
        ));
        // A different value-taker comes first and owns the rest.
        assert!(locate_short_value("env", "-uC", 'C').is_none());
        // An unmodelled letter before it ends the cluster.
        assert!(locate_short_value("env", "-LC", 'C').is_none());
        assert!(locate_short_value("make", "-kC", 'C').is_some());
        assert!(locate_short_value("tar", "-C", 'C').is_none());
    }
}
