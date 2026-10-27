//! The typed shape of one catalogued command: its option grammar and the
//! roles its words play. Plain `&'static` data, no serde (RFC #658 stage 2):
//! `super::load` builds it from `rules/catalog.toml`.

/// How a [`CommandSpec`]'s options and operands are ordered, matching what
/// the tool's own getopt does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgOrder {
    /// POSIXLY_CORRECT / getopt `+`: option parsing ends at the first
    /// operand, so everything after it belongs to the wrapped command.
    FirstOperand,
    /// GNU permutation up to the command: options may follow the operands
    /// that precede the command (`su root -c cmd`, `script out -qc cmd`),
    /// and the first operand past [`Slot::Operands`] is the command.
    PermuteUntilCommand,
}

/// One command's option grammar. A letter or name that appears in none of
/// the lists is unmodelled, which `parse` reports as `Unmodeled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OptionGrammar {
    /// Short letters that take no value.
    pub(crate) short_flags: &'static str,
    /// Short letters whose value is the rest of the token, or the next
    /// token when nothing is glued.
    pub(crate) short_values: &'static str,
    /// Short letters whose value, if any, is glued to the letter.
    pub(crate) short_glued: &'static str,
    /// Like `short_values`, except a next token starting with `-` is not a
    /// value (BSD `script -t time` versus util-linux's glued `-t`).
    pub(crate) short_values_unless_dash: &'static str,
    /// Long names (no `--`) that take no value.
    pub(crate) long_flags: &'static [&'static str],
    /// Long names whose value is `=value` or the next token.
    pub(crate) long_values: &'static [&'static str],
    /// Long names whose value, if any, is `=value` only.
    pub(crate) long_glued: &'static [&'static str],
    /// Whole single-dash words (no `-`) that take no value (`arch -arm64`).
    pub(crate) dash_words: &'static [&'static str],
    /// Whole single-dash words whose value is the next word (`arch -arch x`).
    pub(crate) dash_word_values: &'static [&'static str],
    /// Every `--name` is a flag and every `--name=value` an attached value,
    /// with no separated values (firejail).
    pub(crate) any_long_attached: bool,
    /// A lone `-` is an option rather than an operand (`env -`, `su -`).
    pub(crate) bare_dash_option: bool,
    /// An option-shaped word where the command should be is unmodelled: the
    /// tool's dialects disagree on whether it is an option (util-linux
    /// `script out -qc cmd` permutes, BSD `script` runs `-qc`).
    pub(crate) dash_command_unmodeled: bool,
    /// `-<digits>` is an option (`nice -10`).
    pub(crate) numeric_option: bool,
    /// `NAME=value` operands before the command are skipped (`env`).
    pub(crate) assignments: bool,
    /// An optional first operand before the options (`setarch ARCH`).
    pub(crate) leading_operand: bool,
    pub(crate) order: ArgOrder,
    /// Long names (no `--`) that take two separated values (`bwrap --bind
    /// SRC DEST`); never `=`-attached.
    pub(crate) long_pairs: &'static [&'static str],
    /// A single dash also introduces a long name (`gdb -batch`).
    pub(crate) single_dash_long: bool,
    /// Tokens after which the command starts when one appears behind the
    /// first operand (`mise exec node@20 -- cmd`, `nix develop .#x -c cmd`),
    /// so the operands before it are not mistaken for the command.
    pub(crate) command_after: &'static [&'static str],
    /// A first operand spelled like one of these is skipped, not the command
    /// (`dotenv run CMD`).
    pub(crate) skip_first_operand: &'static [&'static str],
    /// A `+toolchain` word may precede the subcommand (`rustup +stable run`).
    pub(crate) plus_operand: bool,
    /// Long names whose presence makes the call unmodelled: they hand their
    /// value to an interpreter (`gdb -ex 'shell ...'`).
    pub(crate) floor_options: &'static [&'static str],
    /// Short options whose value, when it is one of these, makes the call
    /// unmodelled (`screen -X stuff`).
    pub(crate) floor_values: &'static [(char, &'static [&'static str])],
}

impl OptionGrammar {
    pub(crate) const EMPTY: Self = Self {
        short_flags: "",
        short_values: "",
        short_glued: "",
        short_values_unless_dash: "",
        long_flags: &[],
        long_values: &[],
        long_glued: &[],
        dash_words: &[],
        dash_word_values: &[],
        any_long_attached: false,
        bare_dash_option: false,
        dash_command_unmodeled: false,
        numeric_option: false,
        assignments: false,
        leading_operand: false,
        order: ArgOrder::FirstOperand,
        long_pairs: &[],
        single_dash_long: false,
        command_after: &[],
        skip_first_operand: &[],
        plus_operand: false,
        floor_options: &[],
        floor_values: &[],
    };
}

/// What a cwd-affecting option does to the paths the wrapped command names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CwdEffect {
    /// The gate composes the option's directory itself (`env -C`).
    Composed,
    /// The command runs under another directory or root that nothing
    /// composes (`sudo -D`/`-R`), so relative paths cannot be resolved.
    Relocates,
}

/// A role one part of the command line plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// A command operand follows: the command is transparent, and the word
    /// after its own arguments is what runs.
    Exec,
    /// Operands consumed before the command (`timeout DURATION`).
    Operands(usize),
    /// A flag whose value is a shell command string. Found anywhere in the
    /// command's argument tail, not only before the command: a hit can only
    /// raise a floor.
    ShellScript {
        short: Option<char>,
        long: Option<&'static str>,
    },
    /// The arguments after the user are handed to the target shell, so
    /// bash's own `-c` clusters (`-ic`, `-ec`) carry a shell command string
    /// that the command's own grammar cannot place (`su root -- -ic CMD`).
    ShellPassthrough,
    /// A flag whose value is split into argv words spliced ahead of the
    /// remaining arguments (`env -S`).
    SplitString { short: char, long: &'static str },
    /// A flag whose value names an output that the tool pipes into
    /// `sh -c` when it begins with `|` or `!` (`strace -o`).
    PipedOutput { short: char, long: &'static str },
    /// The operands, joined, run through `sh -c` unless the exec flag is
    /// present (`watch`).
    OperandsAsShellScript {
        exec_short: char,
        exec_long: &'static str,
    },
    /// The operands, joined, are always run through a shell (`ssh host CMD`,
    /// `tmux new-session CMD`).
    OperandsJoinedShellScript,
    /// The operands, joined, are recursed as a shell string when any of
    /// these switches is present (`sudo -s`/`-i`, `doas -s`); without one,
    /// the first operand is the command. An over-approximation: sudo
    /// backslash-escapes metacharacters in the joined string but leaves `$`
    /// alone, so `$IFS`/`$VAR` expansion is the real vector, and `doas -s`
    /// rejects a command outright (kept for symmetry).
    OperandsAsShellScriptWith(&'static [(char, &'static str)]),
    /// The command only wraps another when its first operands spell one of
    /// these word sequences (`poetry run`, `ip netns exec`); anything else
    /// (`poetry install`) is not a wrapper call. Options may surround it.
    Subcommands(&'static [&'static [&'static str]]),
    /// Subcommands that also make the call a wrapper but whose effect cannot
    /// be read (`tmux send-keys`): the call is unmodelled.
    UnmodeledSubcommands(&'static [&'static [&'static str]]),
    /// A repeatable `-o key=value` style option whose value for one of these
    /// keys (case-folded) is a shell command (`ssh -o ProxyCommand=...`).
    KeyedShellScript {
        short: char,
        keys: &'static [&'static str],
    },
    /// An option that changes the directory the wrapped command runs in.
    Cwd {
        short: char,
        long: &'static str,
        effect: CwdEffect,
    },
    /// A boolean switch that moves the wrapped command to another directory
    /// (`sudo -i`, a login shell in the target user's home). Unlike
    /// [`Slot::Cwd`] it takes no value.
    CwdSwitch {
        short: char,
        long: &'static str,
        effect: CwdEffect,
    },
    /// A lone `-` option that moves the wrapped command to another directory
    /// (`su -`, the same as `su -l`).
    CwdBareDash { effect: CwdEffect },
    /// The command escalates privileges.
    Privilege,
}

/// Whether a row lists every subcommand that matters. Closed is the safe
/// default; an open row says why an unlisted subcommand is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubcommandSet {
    Closed,
    Open { justification: &'static str },
}

/// One catalogued command (or a group of names sharing one grammar).
///
/// Fields after `slots` are the R1 (#837) row fields of docs/rfc-redesign.md:
/// loaded, but nothing in the gate reads them yet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommandSpec {
    pub(crate) names: &'static [&'static str],
    pub(crate) options: OptionGrammar,
    pub(crate) slots: &'static [Slot],
    /// Options whose value is code the command runs.
    pub(crate) code_options: &'static [&'static str],
    /// Subcommand paths whose operands are code the command runs.
    pub(crate) code_subcommands: &'static [&'static [&'static str]],
    /// Environment variables whose value is code the command runs.
    pub(crate) env_code: &'static [&'static str],
    /// Paths the command reads and may execute or source.
    pub(crate) reads_files: &'static [&'static str],
    /// What the command leaves behind that runs later.
    pub(crate) persists: &'static [&'static str],
    /// Relocation of the wrapped command that no option triggers.
    pub(crate) cwd_effect: Option<CwdEffect>,
    pub(crate) subcommands: SubcommandSet,
}

impl CommandSpec {
    pub(crate) fn runs_command(&self) -> bool {
        self.slots.iter().any(|slot| matches!(slot, Slot::Exec))
    }

    pub(crate) fn escalates_privileges(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(slot, Slot::Privilege))
    }

    /// Operands consumed before the command.
    pub(crate) fn leading_operands(&self) -> usize {
        self.slots
            .iter()
            .map(|slot| match slot {
                Slot::Operands(count) => *count,
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn joins_operands_as_shell_script(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(slot, Slot::OperandsJoinedShellScript))
    }

    pub(crate) fn operands_as_shell_script_switches(&self) -> &'static [(char, &'static str)] {
        self.slots
            .iter()
            .find_map(|slot| match slot {
                Slot::OperandsAsShellScriptWith(switches) => Some(*switches),
                _ => None,
            })
            .unwrap_or(&[])
    }

    pub(crate) fn subcommands(&self) -> Option<&'static [&'static [&'static str]]> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::Subcommands(alternatives) => Some(*alternatives),
            _ => None,
        })
    }

    pub(crate) fn unmodeled_subcommands(&self) -> Option<&'static [&'static [&'static str]]> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::UnmodeledSubcommands(alternatives) => Some(*alternatives),
            _ => None,
        })
    }

    pub(crate) fn keyed_shell_script(&self) -> Option<(char, &'static [&'static str])> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::KeyedShellScript { short, keys } => Some((*short, *keys)),
            _ => None,
        })
    }

    /// Whether a short flag carries a shell command string (`tmux -c`).
    pub(crate) fn script_short_flags(&self) -> impl Iterator<Item = char> {
        self.slots.iter().filter_map(|slot| match slot {
            Slot::ShellScript {
                short: Some(short), ..
            } => Some(*short),
            _ => None,
        })
    }

    pub(crate) fn cwd_options(&self) -> impl Iterator<Item = (char, &'static str, CwdEffect)> {
        self.slots.iter().filter_map(|slot| match slot {
            Slot::Cwd {
                short,
                long,
                effect,
            } => Some((*short, *long, *effect)),
            _ => None,
        })
    }
}

impl CommandSpec {
    pub(crate) fn cwd_switches(&self) -> impl Iterator<Item = (char, &'static str, CwdEffect)> {
        self.slots.iter().filter_map(|slot| match slot {
            Slot::CwdSwitch {
                short,
                long,
                effect,
            } => Some((*short, *long, *effect)),
            _ => None,
        })
    }

    pub(crate) fn cwd_bare_dash(&self) -> Option<CwdEffect> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::CwdBareDash { effect } => Some(*effect),
            _ => None,
        })
    }

    fn slot_pair(
        &self,
        pick: impl Fn(&Slot) -> Option<(char, &'static str)>,
    ) -> Option<(char, &'static str)> {
        self.slots.iter().find_map(pick)
    }

    pub(crate) fn split_string_option(&self) -> Option<(char, &'static str)> {
        self.slot_pair(|slot| match slot {
            Slot::SplitString { short, long } => Some((*short, *long)),
            _ => None,
        })
    }

    pub(crate) fn piped_output_option(&self) -> Option<(char, &'static str)> {
        self.slot_pair(|slot| match slot {
            Slot::PipedOutput { short, long } => Some((*short, *long)),
            _ => None,
        })
    }

    pub(crate) fn operands_as_shell_script_exec_flag(&self) -> Option<(char, &'static str)> {
        self.slot_pair(|slot| match slot {
            Slot::OperandsAsShellScript {
                exec_short,
                exec_long,
            } => Some((*exec_short, *exec_long)),
            _ => None,
        })
    }
}
