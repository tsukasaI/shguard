//! Same-command-line variable facts (rule 2's bare-`$VAR` resolution) and
//! the execution scope an assignment runs in.
//!
//! Substituting a binding into an unquoted word assumes the inherited-default
//! `IFS` (bash does not import `IFS` from the environment), the same
//! assumption the Block direction makes; a same-line `IFS` write disables it.

use std::collections::{HashMap, HashSet};

use super::value::{AbsValue, Write};
use crate::ast::{
    Assignment, AssignmentValue, Redirection, Separator, SimpleCommand, Word, WordPiece,
};
use crate::normalize::{self, NormalizedWord, Resolution};
use crate::rules;

/// Where a command runs relative to the shell whose variables later commands
/// see. Only [`Self::Parent`] certainly persists its assignments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ExecScope {
    /// Certainly runs in the parent shell whenever the line reaches it.
    Parent,
    /// May be skipped: an `&&`/`||` right-hand side, or a redirected group
    /// whose redirection can fail before the body runs.
    Conditional,
    /// Runs in a forked shell: a backgrounded chain or a pipeline stage.
    Forked,
}

impl ExecScope {
    /// The scope of a pipeline that follows `separator` (`None` for the
    /// first one) in a chain that is, or is not, `backgrounded`.
    pub(crate) fn after_separator(self, separator: Option<Separator>, backgrounded: bool) -> Self {
        let target = if backgrounded {
            Self::Forked
        } else if matches!(separator, Some(Separator::And | Separator::Or)) {
            Self::Conditional
        } else {
            Self::Parent
        };
        self.max(target)
    }

    /// The scope of one stage of a pipeline with `stage_count` stages: only
    /// a lone stage runs in the parent shell.
    pub(crate) fn pipeline_stage(self, stage_count: usize) -> Self {
        if stage_count > 1 {
            self.max(Self::Forked)
        } else {
            self
        }
    }

    /// The scope of a brace-group body: a failing redirection skips the
    /// body, so a redirected group never certainly persists its assignments.
    pub(crate) fn group_with_redirections(self, has_redirections: bool) -> Self {
        if has_redirections {
            self.max(Self::Conditional)
        } else {
            self
        }
    }
}

/// Everything known about one variable name on the current line.
#[derive(Debug)]
struct VarFacts {
    /// The most recent statically resolved value; cleared by an unresolvable
    /// write, because a stale current value is worse than none.
    last: Option<String>,
    /// Resolved values `$name` could still hold at a later use, oldest
    /// first: a possibly-skipped or command-scoped write leaves the earlier
    /// value reachable (issues #463, #534). Truncated by a certain
    /// overwrite that makes the earlier values unreachable.
    history: Vec<String>,
    /// A certain write of an unresolvable value happened (issue #516), so
    /// `$name` now holds something unknown that no earlier value explains.
    overwritten_by_unknown: bool,
    /// What `$name` certainly is, from literal-only writes: it starts as
    /// `Top` (the inherited environment may hold anything), and only a
    /// strong literal write makes it exact. Not a substitute for `history`:
    /// a strong write drops the earlier value, which `candidates` keeps
    /// (#463).
    value: AbsValue,
}

impl Default for VarFacts {
    fn default() -> Self {
        Self {
            last: None,
            history: Vec::new(),
            overwritten_by_unknown: false,
            value: AbsValue::top(),
        }
    }
}

/// Names whose value is not determined by the assignment that wrote them
/// (bash special variables, variables another builtin rewrites implicitly,
/// zsh's tied or read-only ones). `UID=/etc` fails and `$UID` keeps the real
/// value, so no binding of these may be substituted.
fn is_special_name(name: &str) -> bool {
    // Positional and special parameters (`1`, `@`, `?`, ...).
    !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || matches!(
            name,
            "IFS"
                | "HOME"
                | "PATH"
                | "CDPATH"
                | "ENV"
                | "RANDOM"
                | "SRANDOM"
                | "SECONDS"
                | "LINENO"
                | "UID"
                | "EUID"
                | "PPID"
                | "FUNCNAME"
                | "GROUPS"
                | "DIRSTACK"
                | "PIPESTATUS"
                | "SHELLOPTS"
                | "PWD"
                | "OLDPWD"
                | "REPLY"
                | "OPTARG"
                | "OPTIND"
                | "OPTERR"
                | "MAPFILE"
                | "SHLVL"
                | "HISTCMD"
                | "COLUMNS"
                | "LINES"
                | "TMOUT"
                | "_"
                | "path"
                | "cdpath"
                | "fpath"
                | "manpath"
                | "pipestatus"
                | "status"
                | "argv"
                | "ARGC"
        )
        || ["BASH", "EPOCH", "COMP_", "ZSH_"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Builtins and keywords after which no binding can be trusted: they run
/// code, define functions or aliases, or install handlers that later
/// commands trigger.
const POISONING_WORDS: &[&str] = &["eval", "source", ".", "trap", "alias", "coproc"];

/// Builtins that may write any variable, or one this scan cannot name.
const CLOBBERING_WORDS: &[&str] = &[
    "mapfile",
    "readarray",
    "let",
    "select",
    "vared",
    "zparseopts",
];

/// Builtins whose operands name the variables they write.
const NAME_WRITING_WORDS: &[&str] = &["read", "getopts", "unset", "export", "wait"];

/// Builtins that give their operands attributes (`-i`, `-u`, `-n`, ...) which
/// change what a later assignment stores.
const ATTRIBUTE_WORDS: &[&str] = &[
    "declare", "typeset", "local", "readonly", "integer", "float", "private",
];

/// Wrappers after which the next word is still run in the current shell.
const SHELL_KEEPING_WRAPPERS: &[&str] = &["builtin", "command", "time"];

/// Builtins that can switch `xtrace` on.
const TRACE_OPTION_WORDS: &[&str] = &["set", "shopt", "setopt", "unsetopt"];

/// Whether `operands` of `set`/`shopt`/`setopt` may switch `xtrace` on: a
/// `-x` flag cluster, an option named `xtrace` (`NO_XTRACE` too, for
/// `unsetopt`), or an operand not known statically.
fn enables_xtrace(operands: &[NormalizedWord]) -> bool {
    operands.iter().any(|operand| match operand.resolution() {
        Resolution::Unresolvable(_) => true,
        Resolution::Resolved(arg) => {
            let folded = arg.to_ascii_lowercase().replace('_', "");
            folded.contains("xtrace")
                || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('x'))
        }
    })
}

/// Whether `mapfile`/`readarray` operands may carry `-C` (the callback runs
/// arbitrary code, `readonly` included): a flag cluster containing `C`
/// before any `--`, or an operand not known statically.
fn has_callback_flag(operands: &[NormalizedWord]) -> bool {
    // Not a plain `take_while` on `--`: it can be the value of an option
    // taking an argument (`mapfile -d -- -C cb arr` still honours `-C`).
    let mut skip_next = false;
    for operand in operands {
        let arg = match operand.resolution() {
            Resolution::Unresolvable(_) => return true,
            Resolution::Resolved(arg) => arg,
        };
        if skip_next {
            skip_next = false;
        } else if arg == "--" {
            return false;
        } else if arg.starts_with('-') {
            if arg.contains('C') {
                return true;
            }
            // `d:u:n:O:tC:c:s:` — the last flag of a cluster takes the next word.
            skip_next = arg.ends_with(['d', 'u', 'n', 'O', 's', 'c']);
        }
    }
    false
}

/// Every `IFS` value the line could have split with, and the running
/// inherited-default hypothesis. Never truncated: an `IFS` overwritten by
/// an unresolvable value still leaves the earlier splitting possible for a
/// command that ran before it.
#[derive(Debug, Default)]
struct IfsHypotheses {
    seen: Vec<String>,
    /// Running "assume every same-line `IFS+=` appended onto the inherited
    /// default" hypothesis (issue #358), tracked apart from the `IFS`
    /// variable's own append chain, which starts from "unset appends onto
    /// empty": `IFS+=,; IFS+=.` must offer both `" \t\n,."` and `,.`.
    append_floor: Option<String>,
}

/// Names a readonly-ish builtin touched earlier on the line.
#[derive(Debug, Default)]
struct ReadonlyFacts {
    names: HashSet<String>,
    /// A readonly-ish builtin had an unresolvable operand: no name can be
    /// trusted to be writable.
    all: bool,
}

/// Whether a write certainly replaced the variable's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strength {
    Strong,
    Weak,
}

/// Tracks `NAME -> facts` for every assignment seen so far on the current
/// command line, in execution order.
///
/// A single flat map, not scoped per-command: a static analyzer deciding
/// whether this line is safe to run treats a prefix assignment as
/// line-scoped, which can only make resolution more available. `last` and
/// `history` only ever upgrade Ask to Block, never downgrade anything; the
/// exact values (`exact`, `substitute_literals`) are the one source of an
/// Allow, so they are kept apart and stricter.
///
/// `touched` records every name assigned at all, resolved or not: `vars`
/// forgets the current value of an unresolvable assignment (`HOME=$(evil)
/// cd`), which would otherwise hide the attacker-controlled-`HOME` case the
/// `cd`-poisoning checks exist to catch.
#[derive(Debug, Default)]
pub(crate) struct Env {
    vars: HashMap<String, VarFacts>,
    touched: HashSet<String>,
    ifs: IfsHypotheses,
    readonly: ReadonlyFacts,
    /// Names defined as functions on this line: a call may run any
    /// `readonly` its body holds.
    functions: HashSet<String>,
    /// Names whose value a builtin (or a body folded in by `absorb_body`)
    /// rewrote without a trackable assignment.
    clobbered: HashSet<String>,
    /// Some builtin may have rewritten any variable.
    clobbered_all: bool,
    /// Names given attributes that change what an assignment stores
    /// (`declare -i`, `-u`, ...): never bound.
    tainted: HashSet<String>,
    /// Code ran (`eval`, a function call, a trap, ...) that may have
    /// rewritten variables, defined aliases or installed handlers: nothing
    /// is bound from here on.
    poisoned: bool,
    /// `IFS` was, or may have been, rewritten: an unquoted expansion may
    /// split anywhere.
    ifs_changed: bool,
    /// `PS4` was, or may have been, written. With `xtrace` on, bash expands
    /// it (parameter, command and arithmetic expansion) in the current shell
    /// before each traced command, so it is a write channel no assignment
    /// scan sees.
    ps4_written: bool,
    /// `set -x` (or `-o xtrace`, `setopt xtrace`, ...) may be in effect. Never
    /// cleared: a later `set +x` does not undo an expansion already done.
    xtrace_on: bool,
}

/// Whether `value`, expanded unquoted, is certainly one word that no
/// globbing, tilde, brace or extglob expansion touches. Not just "no
/// whitespace and no `*?[`": a whitelist, because every other character is
/// either an expansion trigger or has not been argued safe.
fn is_unquoted_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-:,+@%".contains(c))
}

/// Longest run of identifier characters at the start of `operand`
/// (`X=1` -> `X`, `a[0]` -> `a`).
fn operand_name(operand: &str) -> &str {
    let end = operand
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(operand.len());
    &operand[..end]
}

/// The text of `word` when every piece is literal and expands to itself:
/// quotes only, no `$`, no tilde, no brace. `globs_expand` says whether an
/// unquoted `*?[` would expand (a word-list element) or not (an assignment
/// value).
pub(crate) fn literal_text(word: &Word, globs_expand: bool) -> Option<String> {
    let mut text = String::new();
    for piece in &word.0 {
        match piece {
            WordPiece::Literal(literal) => {
                if literal.contains('~') || (globs_expand && literal.contains(['*', '?', '['])) {
                    return None;
                }
                text.push_str(literal);
            }
            WordPiece::SingleQuoted(quoted) => text.push_str(quoted),
            WordPiece::DoubleQuoted(inner) => {
                for piece in inner {
                    let WordPiece::Literal(literal) = piece else {
                        return None;
                    };
                    text.push_str(literal);
                }
            }
            _ => return None,
        }
    }
    Some(text)
}

/// Whether expanding `word` may assign a variable: an arithmetic expansion
/// (`$((X=1))`) anywhere inside it.
pub(crate) fn word_may_write_variables(word: &Word) -> bool {
    fn piece_may_write(piece: &WordPiece) -> bool {
        match piece {
            WordPiece::ArithmeticExpansion(_) => true,
            WordPiece::DoubleQuoted(inner) => inner.iter().any(piece_may_write),
            WordPiece::ModifiedParameterExpansion { operand, .. } => {
                operand.iter().any(piece_may_write)
            }
            WordPiece::BraceAlternation(words) => words.iter().any(word_may_write_variables),
            _ => false,
        }
    }
    word.0.iter().any(piece_may_write)
}

/// Whether `redirections` may assign a variable when performed: an
/// arithmetic expansion in a target, or in an expanding heredoc body.
pub(crate) fn redirections_may_write_variables(redirections: &[Redirection]) -> bool {
    redirections.iter().any(|redirection| match redirection {
        Redirection::File { target, .. } => word_may_write_variables(target),
        Redirection::HereDoc {
            expand_body, body, ..
        } => {
            *expand_body
                && (body.contains("$((") || body.contains("$[") || {
                    body.contains("${") && body.contains('=')
                })
        }
    })
}

/// Whether performing `command`'s expansions may assign a variable.
pub(crate) fn command_may_write_variables(command: &SimpleCommand) -> bool {
    command.words.iter().any(word_may_write_variables)
        || command
            .assignments
            .iter()
            .any(|assignment| match &assignment.value {
                AssignmentValue::Scalar(word) => word_may_write_variables(word),
                AssignmentValue::Array(words) => words.iter().any(word_may_write_variables),
            })
        || redirections_may_write_variables(&command.redirections)
}

impl Env {
    /// A fresh environment for a boundary that shares nothing with the
    /// enclosing line: a subshell, loop or `if` body, a function body, a
    /// recursed payload.
    pub(crate) fn isolated() -> Self {
        Self::default()
    }

    /// A body's environment: no variable values (which branch or iteration
    /// ran is unknown), but the functions and readonly facts the enclosing
    /// line already established.
    pub(crate) fn child_of(parent: &Self) -> Self {
        Self {
            functions: parent.functions.clone(),
            readonly: ReadonlyFacts {
                names: parent.readonly.names.clone(),
                all: parent.readonly.all,
            },
            tainted: parent.tainted.clone(),
            poisoned: parent.poisoned,
            ifs_changed: parent.ifs_changed,
            ps4_written: parent.ps4_written,
            xtrace_on: parent.xtrace_on,
            ..Self::default()
        }
    }

    /// A subshell's environment: it starts from nothing assigned, but it
    /// inherits the functions, attributes and handlers its parent has, so
    /// the parent's poison and taint carry over.
    pub(crate) fn subshell_of(parent: &Self) -> Self {
        Self {
            functions: parent.functions.clone(),
            tainted: parent.tainted.clone(),
            poisoned: parent.poisoned,
            ifs_changed: parent.ifs_changed,
            ps4_written: parent.ps4_written,
            xtrace_on: parent.xtrace_on,
            ..Self::default()
        }
    }

    /// An environment that binds nothing: a function body runs when it is
    /// called, after functions defined later on the line exist, and a
    /// process substitution inherits whatever functions are defined.
    pub(crate) fn opaque() -> Self {
        Self {
            poisoned: true,
            ..Self::default()
        }
    }

    /// The one string `$name` certainly holds here, or `None`.
    pub(crate) fn exact(&self, name: &str) -> Option<&str> {
        if self.poisoned || self.tainted.contains(name) || is_special_name(name) {
            return None;
        }
        self.vars.get(name)?.value.exact()
    }

    /// Binds a `for` variable to the list word the current iteration holds.
    pub(crate) fn bind_loop_variable(&mut self, name: &str, value: &str) {
        self.touched.insert(name.to_string());
        self.ifs_changed |= name == "IFS";
        let readonly = self.is_possibly_readonly(name);
        let facts = self.vars.entry(name.to_string()).or_default();
        facts.value = if readonly {
            AbsValue::top()
        } else {
            AbsValue::strong_write(&Write::Exact(value.to_string()))
        };
    }

    /// `name` was rewritten to something this scan does not track.
    pub(crate) fn clobber(&mut self, name: &str) {
        self.clobbered.insert(name.to_string());
        self.ifs_changed |= name == "IFS";
        if name == "PS4" {
            self.note_ps4_written();
        }
        if let Some(facts) = self.vars.get_mut(name) {
            facts.value = AbsValue::top();
        }
    }

    fn note_ps4_written(&mut self) {
        self.ps4_written = true;
        // Not `poison()`: that calls `clobber_all`, which lands here.
        self.poisoned |= self.xtrace_on;
    }

    fn note_xtrace_on(&mut self) {
        self.xtrace_on = true;
        if self.ps4_written {
            self.poison();
        }
    }

    /// The `(PS4 written, xtrace on)` facts running `command` alone would
    /// establish, for a loop body whose later commands run before its
    /// earlier ones on the next iteration.
    pub(crate) fn trace_effects(&self, command: &SimpleCommand) -> (bool, bool) {
        let mut probe = Self {
            functions: self.functions.clone(),
            ..Self::default()
        };
        probe.apply_assignments(command, ExecScope::Conditional);
        probe.note_command_effects(command, &normalize::normalize_argv(command));
        (probe.ps4_written, probe.xtrace_on)
    }

    fn clobber_all(&mut self) {
        self.clobbered_all = true;
        self.ifs_changed = true;
        self.note_ps4_written();
        for facts in self.vars.values_mut() {
            facts.value = AbsValue::top();
        }
    }

    /// A construct that may rewrite any variable (an arithmetic expansion,
    /// the arithmetic operands of `[[ ]]`).
    pub(crate) fn note_arbitrary_writes(&mut self) {
        self.clobber_all();
    }

    /// Nothing is bound from here on: code ran that may have rewritten
    /// variables, defined aliases or installed handlers.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.clobber_all();
    }

    /// Whether running `command` would poison an environment that knows
    /// this one's functions.
    pub(crate) fn would_poison(&self, command: &SimpleCommand) -> bool {
        let mut probe = Self {
            functions: self.functions.clone(),
            ..Self::default()
        };
        probe.note_command_effects(command, &normalize::normalize_argv(command));
        probe.poisoned
    }

    /// Folds in what `command` does to variables when it runs, beyond its
    /// own assignments: builtins that write the variables they name, code
    /// that may write anything, and expansions that assign.
    pub(crate) fn note_command_effects(
        &mut self,
        command: &SimpleCommand,
        argv: &[NormalizedWord],
    ) {
        if command_may_write_variables(command) {
            self.clobber_all();
        }
        let Some(first) = argv.first() else {
            return;
        };
        if matches!(first.resolution(), Resolution::Unresolvable(_)) {
            self.poison();
        }
        for (index, word) in argv.iter().enumerate() {
            if let Resolution::Unresolvable(_) = word.resolution() {
                let after_wrapper = index > 0
                    && matches!(
                        argv[index - 1].resolution(),
                        Resolution::Resolved(wrapper)
                            if SHELL_KEEPING_WRAPPERS.contains(&wrapper.as_str())
                    );
                if after_wrapper {
                    self.poison();
                }
            }
        }
        // Only the word that runs as the command is a builtin: an operand
        // spelled `eval` or `export` is just an argument. When the wrapper
        // chain cannot be walked, every word counts.
        match rules::effective_command(argv) {
            Some((_, tail)) => {
                let index = argv.len() - tail.len() - 1;
                if let Resolution::Resolved(name) = argv[index].resolution() {
                    self.note_word_effects(name, tail);
                }
            }
            None => {
                for (index, word) in argv.iter().enumerate() {
                    if let Resolution::Resolved(name) = word.resolution() {
                        self.note_word_effects(name, &argv[index + 1..]);
                    }
                }
            }
        }
    }

    fn note_word_effects(&mut self, word: &str, rest: &[NormalizedWord]) {
        if POISONING_WORDS.contains(&word) || self.functions.contains(word) {
            self.poison();
        } else if CLOBBERING_WORDS.contains(&word) {
            self.clobber_all();
        } else if NAME_WRITING_WORDS.contains(&word) {
            self.clobber_operands(rest);
        } else if word == "printf" {
            let may_write_variable = rest.iter().any(|arg| match arg.resolution() {
                Resolution::Resolved(arg) => arg.starts_with("-v"),
                Resolution::Unresolvable(_) => true,
            });
            if may_write_variable {
                self.clobber_operands(rest);
            }
        } else if ATTRIBUTE_WORDS.contains(&word) {
            self.taint_operands(rest);
        } else if TRACE_OPTION_WORDS.contains(&word) && enables_xtrace(rest) {
            self.note_xtrace_on();
        }
    }

    fn clobber_operands(&mut self, operands: &[NormalizedWord]) {
        for operand in operands {
            match operand.resolution() {
                Resolution::Unresolvable(_) => self.clobber_all(),
                Resolution::Resolved(arg) if arg.starts_with('-') => {}
                Resolution::Resolved(arg) => {
                    let name = operand_name(arg);
                    if !name.is_empty() {
                        self.clobber(name);
                    }
                }
            }
        }
    }

    fn taint_operands(&mut self, operands: &[NormalizedWord]) {
        for operand in operands {
            match operand.resolution() {
                Resolution::Unresolvable(_) => self.poison(),
                Resolution::Resolved(arg) if arg.starts_with('-') => {
                    if arg.contains('n') {
                        self.poison();
                    }
                }
                Resolution::Resolved(arg) => {
                    let name = operand_name(arg);
                    if !name.is_empty() {
                        self.tainted.insert(name.to_string());
                        self.clobber(name);
                    }
                }
            }
        }
    }

    /// `command` with every plain `$NAME` / `"$NAME"` in its argument words
    /// (never the command word) replaced by `NAME`'s exact value, or `None`
    /// when nothing was replaced. Reads the bindings as they are BEFORE
    /// `command`'s own assignments apply: bash expands the words first.
    ///
    /// An unquoted use is replaced only by a value that is safe from word
    /// splitting and globbing; the replacement is single-quoted so it stays
    /// one literal word.
    ///
    /// Also returns the indices of the words that were replaced.
    pub(crate) fn substitute_literals(
        &self,
        command: &SimpleCommand,
    ) -> Option<(SimpleCommand, Vec<usize>)> {
        if self.poisoned || command.words.len() < 2 || command_may_write_variables(command) {
            return None;
        }
        let split_unsafe = self.ifs_changed || command.assignments.iter().any(|a| a.name == "IFS");
        let mut replaced = Vec::new();
        let words = command
            .words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                // Expansion results are never tilde-expanded, but how the
                // parser reads `~$X` (a tilde piece, or a literal `~`) is
                // not worth arguing about: leave the word alone.
                let has_tilde = word.0.iter().any(|piece| match piece {
                    WordPiece::Tilde(_) => true,
                    WordPiece::Literal(text) => text.contains('~'),
                    _ => false,
                });
                if index == 0 || has_tilde {
                    return word.clone();
                }
                let mut changed = false;
                let pieces = word
                    .0
                    .iter()
                    .map(|piece| self.substitute_piece(piece, split_unsafe, &mut changed))
                    .collect();
                if changed {
                    replaced.push(index);
                }
                Word(pieces)
            })
            .collect();
        (!replaced.is_empty()).then(|| {
            let substituted = SimpleCommand {
                assignments: command.assignments.clone(),
                words,
                redirections: command.redirections.clone(),
            };
            (substituted, replaced)
        })
    }

    fn substitute_piece(
        &self,
        piece: &WordPiece,
        split_unsafe: bool,
        changed: &mut bool,
    ) -> WordPiece {
        match piece {
            WordPiece::ParameterExpansion(name) => match self.exact(name) {
                Some(value) if !split_unsafe && is_unquoted_safe(value) => {
                    *changed = true;
                    WordPiece::SingleQuoted(value.to_string())
                }
                _ => piece.clone(),
            },
            WordPiece::DoubleQuoted(inner) => WordPiece::DoubleQuoted(
                inner
                    .iter()
                    .map(|piece| match piece {
                        WordPiece::ParameterExpansion(name) => match self.exact(name) {
                            Some(value) => {
                                *changed = true;
                                WordPiece::Literal(value.to_string())
                            }
                            None => piece.clone(),
                        },
                        _ => piece.clone(),
                    })
                    .collect(),
            ),
            _ => piece.clone(),
        }
    }

    /// An assignment to a possibly-readonly name may fail in the real shell,
    /// so it is never a certain overwrite.
    fn is_possibly_readonly(&self, name: &str) -> bool {
        self.readonly.all || self.readonly.names.contains(name)
    }

    /// Records that `name` is defined as a function on this line.
    pub(crate) fn note_function_defined(&mut self, name: &str) {
        self.functions.insert(name.to_string());
        // Bash calls it for every command it cannot find.
        if name == "command_not_found_handle" {
            self.poison();
        }
    }

    /// Whether `name` was defined as a function earlier on this line.
    pub(crate) fn defines_function(&self, name: &str) -> bool {
        self.functions.contains(name)
    }

    /// Folds in a body evaluated with its own [`Env::isolated`] whose effects
    /// still reach the parent shell (an `if`/loop body): its readonly facts
    /// become unknown here, since which iteration or branch ran is not known.
    pub(crate) fn absorb_body(&mut self, body: &Env) {
        // The body inherited the parent's names, so only added ones count.
        if body.readonly.all || !body.readonly.names.is_subset(&self.readonly.names) {
            self.readonly.all = true;
        }
        self.functions.extend(body.functions.iter().cloned());
        for name in body.touched.iter().chain(&body.clobbered) {
            self.clobber(name);
        }
        if body.clobbered_all {
            self.clobber_all();
        }
        self.tainted.extend(body.tainted.iter().cloned());
        if body.poisoned {
            self.poison();
        }
    }

    /// Conservatively records `readonly`-ish operands (`readonly`, or
    /// `declare`/`typeset`/`local`/`export` with an `-r`-containing flag
    /// cluster); any such appearance is enough, whether or not the builtin
    /// certainly runs.
    pub(crate) fn note_readonly_operands(&mut self, argv: &[NormalizedWord]) {
        let Some((first, rest)) = argv.split_first() else {
            return;
        };
        let Resolution::Resolved(name) = first.resolution() else {
            self.readonly.all = true;
            return;
        };
        // Wrappers and sourced code can run a `readonly` this scan cannot
        // see (`builtin readonly X`, zsh `integer -r X`), as can a call to
        // a function defined on this line.
        if matches!(
            name.as_str(),
            "builtin"
                | "command"
                | "eval"
                | "source"
                | "."
                | "integer"
                | "float"
                | "private"
                | "trap"
                | "autoload"
        ) || self.functions.contains(name.as_str())
            || (matches!(name.as_str(), "mapfile" | "readarray") && has_callback_flag(rest))
        {
            self.readonly.all = true;
        }
        let readonlyish = match name.as_str() {
            "readonly" => true,
            "declare" | "typeset" | "local" | "export" => {
                rest.iter().any(|word| match word.resolution() {
                    Resolution::Resolved(arg) => arg.starts_with('-') && arg.contains('r'),
                    Resolution::Unresolvable(_) => true,
                })
            }
            _ => false,
        };
        if !readonlyish {
            return;
        }
        for word in rest {
            match word.resolution() {
                Resolution::Resolved(arg) if arg.starts_with('-') => {}
                Resolution::Resolved(arg) => {
                    let operand = arg.split('=').next().unwrap_or(arg);
                    self.readonly.names.insert(operand.to_string());
                }
                Resolution::Unresolvable(_) => self.readonly.all = true,
            }
        }
    }

    /// The most recent statically resolved value of `name`, if any.
    pub(crate) fn current(&self, name: &str) -> Option<&str> {
        self.vars.get(name)?.last.as_deref()
    }

    /// The values `name` could still hold, oldest first, independent of
    /// what [`Self::current`] shows: a later prefix-scoped resolution
    /// updates the current value without making an earlier one unreachable.
    pub(crate) fn candidates(&self, name: &str) -> &[String] {
        self.vars.get(name).map_or(&[], |v| v.history.as_slice())
    }

    /// Every `IFS` value this line could have split with.
    pub(crate) fn ifs_hypotheses(&self) -> &[String] {
        &self.ifs.seen
    }

    /// Whether `name` was assigned anywhere on this line so far (this same
    /// command's own prefix assignments included), regardless of whether
    /// the value resolved.
    pub(crate) fn was_assigned(&self, name: &str) -> bool {
        self.touched.contains(name)
    }

    /// Folds `command`'s own assignments in. Must be called before
    /// evaluating `command` itself, so a same-command prefix assignment
    /// (`X=rm $X -rf /`) is visible to that very command, and every later
    /// command sees it too.
    ///
    /// A value that does not resolve to exactly one [`Resolution::Resolved`]
    /// word (unresolvable, or an assignment whose RHS split into more than
    /// one word) is a [`Write::Top`].
    ///
    /// An assignment is strong only when `scope` is [`ExecScope::Parent`]
    /// and `command` has no words (`X=v cmd` is scoped to `cmd`), and the
    /// name is not possibly readonly.
    pub(crate) fn apply_assignments(&mut self, command: &SimpleCommand, scope: ExecScope) {
        let persists = scope == ExecScope::Parent && command.words.is_empty();
        // A failing redirection may skip the assignment.
        let performed = persists && command.redirections.is_empty();
        for assignment in &command.assignments {
            let strength = if persists && !self.is_possibly_readonly(&assignment.name) {
                Strength::Strong
            } else {
                Strength::Weak
            };
            self.apply_one(assignment, strength, performed);
        }
    }

    fn apply_one(&mut self, assignment: &Assignment, strength: Strength, performed: bool) {
        self.touched.insert(assignment.name.clone());
        self.ifs_changed |= assignment.name == "IFS";
        if assignment.name == "PS4" {
            self.note_ps4_written();
        }
        let write = self.resolve_write(assignment);
        let literal = self.literal_write(assignment);
        let facts = self.vars.entry(assignment.name.clone()).or_default();
        match (strength, &write) {
            (Strength::Strong, Write::Top) => {
                facts.history.clear();
                facts.overwritten_by_unknown = true;
            }
            (Strength::Strong, Write::Exact(value)) => {
                // Not `clear` on an append, or with the flag clear: `X+=v`
                // after an unknown value still builds on it, and a first
                // strong write keeps the earlier entries (the #463 quirk).
                if facts.overwritten_by_unknown && !assignment.append {
                    facts.history.clear();
                }
                facts.history.push(value.clone());
            }
            (Strength::Weak, Write::Exact(value)) => facts.history.push(value.clone()),
            (Strength::Weak, Write::Top) => {}
        }
        facts.last = match &write {
            Write::Exact(value) => Some(value.clone()),
            Write::Top => None,
        };
        facts.value = match strength {
            Strength::Strong if performed => AbsValue::strong_write(&literal),
            _ => facts.value.weak_write(&literal),
        };
        if assignment.name == "IFS"
            && let Write::Exact(value) = &write
        {
            self.ifs.seen.push(value.clone());
        }
    }

    /// The write `assignment` performs as far as the exact-value domain can
    /// tell: a literal-only value, appended onto a prior exact value for
    /// `+=`; everything else is `Top`, however well `resolve_write` folds it.
    fn literal_write(&self, assignment: &Assignment) -> Write {
        let AssignmentValue::Scalar(word) = &assignment.value else {
            return Write::Top;
        };
        let Some(text) = literal_text(word, false) else {
            return Write::Top;
        };
        if !assignment.append {
            return Write::Exact(text);
        }
        match self.exact(&assignment.name) {
            Some(prior) => Write::Exact(format!("{prior}{text}")),
            None => Write::Top,
        }
    }

    /// The write `assignment` performs, recording the `IFS+=` inherited-
    /// default floor (issue #358) on the way.
    fn resolve_write(&mut self, assignment: &Assignment) -> Write {
        let words = normalize::normalize_assignment_value(assignment);
        let [one] = words.as_slice() else {
            return Write::Top;
        };
        let Resolution::Resolved(rhs) = one.resolution() else {
            return Write::Top;
        };
        if !assignment.append {
            return Write::Exact(rhs.clone());
        }
        // `NAME+=value` on a name with no same-line prior starts from the
        // empty string, exactly as plain `NAME=value` already assumes.
        if assignment.name == "IFS" {
            // `IFS+=value` could ALSO append onto the inherited default
            // (`" \t\n"`) rather than onto the tracked value: one more floor
            // candidate on EVERY append, chained.
            let base = self
                .ifs
                .append_floor
                .clone()
                .unwrap_or_else(|| normalize::DEFAULT_IFS_WHITESPACE.to_string());
            let floor = format!("{base}{rhs}");
            self.vars
                .entry(assignment.name.clone())
                .or_default()
                .history
                .push(floor.clone());
            self.ifs.seen.push(floor.clone());
            self.ifs.append_floor = Some(floor);
        }
        match self.current(&assignment.name) {
            Some(prior) => Write::Exact(format!("{prior}{rhs}")),
            None => Write::Exact(rhs.clone()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ast::Command;
    use crate::parser;

    fn simple(line: &str) -> SimpleCommand {
        let parsed = parser::parse(line).unwrap();
        match parsed.first.first {
            Command::Simple(simple) => simple,
            other => panic!("not a simple command: {other:?}"),
        }
    }

    fn apply(env: &mut Env, line: &str, scope: ExecScope) {
        env.apply_assignments(&simple(line), scope);
    }

    fn history(env: &Env, name: &str) -> Vec<String> {
        env.candidates(name).to_vec()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn strong_top_clears_history_and_sets_the_flag() {
        let mut env = Env::isolated();
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=$(e)", ExecScope::Parent);
        assert!(history(&env, "X").is_empty());
        assert!(env.vars["X"].overwritten_by_unknown);
        assert_eq!(env.current("X"), None);
        assert_eq!(env.vars["X"].value, AbsValue::strong_write(&Write::Top));
    }

    #[test]
    fn strong_exact_with_the_flag_set_clears_then_pushes() {
        let mut env = Env::isolated();
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=$(e)", ExecScope::Parent);
        apply(&mut env, "X=b", ExecScope::Conditional);
        apply(&mut env, "X=c", ExecScope::Parent);
        assert_eq!(history(&env, "X"), strings(&["c"]));
        assert!(env.vars["X"].overwritten_by_unknown);
        assert_eq!(env.current("X"), Some("c"));
    }

    #[test]
    fn strong_exact_with_the_flag_clear_only_pushes() {
        let mut env = Env::isolated();
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=b", ExecScope::Parent);
        assert_eq!(history(&env, "X"), strings(&["a", "b"]));
        assert_eq!(
            env.vars["X"].value,
            AbsValue::strong_write(&Write::Exact("b".into()))
        );
    }

    #[test]
    fn strong_append_with_the_flag_set_only_pushes() {
        let mut env = Env::isolated();
        apply(&mut env, "X=$(e)", ExecScope::Parent);
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X+=b", ExecScope::Parent);
        assert_eq!(history(&env, "X"), strings(&["a", "ab"]));
        assert_eq!(env.current("X"), Some("ab"));
    }

    #[test]
    fn weak_exact_pushes_and_keeps_the_old_possibility() {
        let mut env = Env::isolated();
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=b true", ExecScope::Parent);
        assert_eq!(history(&env, "X"), strings(&["a", "b"]));
        assert_eq!(env.current("X"), Some("b"));
        let both =
            AbsValue::strong_write(&Write::Exact("a".into())).weak_write(&Write::Exact("b".into()));
        assert_eq!(env.vars["X"].value, both);
    }

    #[test]
    fn weak_top_leaves_history_and_clears_the_current_value() {
        let mut env = Env::isolated();
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=$(e) true", ExecScope::Parent);
        assert_eq!(history(&env, "X"), strings(&["a"]));
        assert!(!env.vars["X"].overwritten_by_unknown);
        assert_eq!(env.current("X"), None);
        assert_eq!(env.vars["X"].value, AbsValue::strong_write(&Write::Top));
    }

    #[test]
    fn non_parent_scopes_and_readonly_names_write_weakly() {
        for scope in [ExecScope::Conditional, ExecScope::Forked] {
            let mut env = Env::isolated();
            apply(&mut env, "X=a", ExecScope::Parent);
            apply(&mut env, "X=$(e)", scope);
            assert!(!env.vars["X"].overwritten_by_unknown);
            assert_eq!(history(&env, "X"), strings(&["a"]));
        }
        let mut env = Env::isolated();
        env.note_readonly_operands(&parser_argv("readonly X"));
        apply(&mut env, "X=a", ExecScope::Parent);
        apply(&mut env, "X=$(e)", ExecScope::Parent);
        assert!(!env.vars["X"].overwritten_by_unknown);
        assert_eq!(history(&env, "X"), strings(&["a"]));
    }

    fn parser_argv(line: &str) -> Vec<NormalizedWord> {
        normalize::normalize_argv(&simple(line))
    }

    #[test]
    fn every_assignment_is_touched_and_ifs_hypotheses_are_never_truncated() {
        let mut env = Env::isolated();
        apply(&mut env, "IFS=,", ExecScope::Parent);
        apply(&mut env, "IFS=$(e)", ExecScope::Parent);
        apply(&mut env, "IFS+=.", ExecScope::Conditional);
        assert!(env.was_assigned("IFS"));
        assert!(!env.was_assigned("X"));
        assert_eq!(
            env.ifs_hypotheses(),
            strings(&[",", " \t\n.", "."]).as_slice()
        );
        assert_eq!(env.ifs.append_floor.as_deref(), Some(" \t\n."));
    }

    #[test]
    fn scope_constructors_reproduce_the_old_booleans() {
        use ExecScope::{Conditional, Forked, Parent};
        assert_eq!(Parent.after_separator(None, false), Parent);
        assert_eq!(
            Parent.after_separator(Some(Separator::Sequence), false),
            Parent
        );
        assert_eq!(
            Parent.after_separator(Some(Separator::And), false),
            Conditional
        );
        assert_eq!(
            Parent.after_separator(Some(Separator::Or), false),
            Conditional
        );
        assert_eq!(Parent.after_separator(Some(Separator::And), true), Forked);
        assert_eq!(Conditional.after_separator(None, false), Conditional);
        assert_eq!(Parent.pipeline_stage(1), Parent);
        assert_eq!(Parent.pipeline_stage(2), Forked);
        assert_eq!(Conditional.pipeline_stage(2), Forked);
        assert_eq!(Conditional.pipeline_stage(1), Conditional);
        assert_eq!(Forked.after_separator(Some(Separator::And), false), Forked);
        assert_eq!(Parent.group_with_redirections(false), Parent);
        assert_eq!(Parent.group_with_redirections(true), Conditional);
        assert_eq!(Forked.group_with_redirections(true), Forked);
    }

    fn run(env: &mut Env, line: &str) {
        let command = simple(line);
        env.apply_assignments(&command, ExecScope::Parent);
        env.note_command_effects(&command, &normalize::normalize_argv(&command));
    }

    #[test]
    fn a_strong_literal_assignment_is_exact_and_nothing_else_is() {
        let mut env = Env::isolated();
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X=/a");
        assert_eq!(env.exact("X"), Some("/a"));
        run(&mut env, "X+=/b");
        assert_eq!(env.exact("X"), Some("/a/b"));
        run(&mut env, "X='c d'");
        assert_eq!(env.exact("X"), Some("c d"));
        run(&mut env, "X=$(e)");
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X+=/b");
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X=~/b");
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X={a,b}");
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X=$Y");
        assert_eq!(env.exact("X"), None);
    }

    #[test]
    fn a_weak_or_unperformed_assignment_is_not_exact() {
        for scope in [ExecScope::Conditional, ExecScope::Forked] {
            let mut env = Env::isolated();
            env.apply_assignments(&simple("X=/a"), scope);
            assert_eq!(env.exact("X"), None);
        }
        let mut env = Env::isolated();
        run(&mut env, "X=/a");
        env.apply_assignments(&simple("X=/b"), ExecScope::Conditional);
        assert_eq!(env.exact("X"), None);
        env.apply_assignments(&simple("X=/a"), ExecScope::Parent);
        assert_eq!(env.exact("X"), Some("/a"));
        run(&mut env, "X=/b true");
        assert_eq!(env.exact("X"), None);
        run(&mut env, "X=/a");
        run(&mut env, "X=/b > /dev/null");
        assert_eq!(env.exact("X"), None);
        let mut env = Env::isolated();
        env.note_readonly_operands(&parser_argv("readonly X"));
        run(&mut env, "X=/a");
        assert_eq!(env.exact("X"), None);
    }

    #[test]
    fn special_names_are_never_exact() {
        let mut env = Env::isolated();
        for name in [
            "IFS",
            "HOME",
            "PATH",
            "CDPATH",
            "BASH_ENV",
            "ENV",
            "RANDOM",
            "SRANDOM",
            "SECONDS",
            "LINENO",
            "BASHPID",
            "EPOCHSECONDS",
            "EPOCHREALTIME",
            "UID",
            "EUID",
            "PPID",
            "FUNCNAME",
            "GROUPS",
            "DIRSTACK",
            "PIPESTATUS",
            "SHELLOPTS",
            "BASHOPTS",
            "BASH_VERSION",
            "PWD",
            "OLDPWD",
            "1",
            "@",
        ] {
            env.bind_loop_variable(name, "/a");
            assert_eq!(env.exact(name), None, "{name}");
        }
        env.bind_loop_variable("OTHER", "/a");
        assert_eq!(env.exact("OTHER"), Some("/a"));
    }

    #[test]
    fn builtins_that_write_a_variable_drop_its_binding_only() {
        for line in [
            "read X",
            "read -r Y X",
            "builtin read X",
            "command read X",
            "getopts ab X",
            "printf -v X %s v",
            "unset X",
            "export X=/b",
            "wait -p X",
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            env.bind_loop_variable("Y", "/a");
            run(&mut env, line);
            assert_eq!(env.exact("X"), None, "{line}");
            if !line.contains('Y') {
                assert_eq!(env.exact("Y"), Some("/a"), "{line}");
            }
        }
        let mut env = Env::isolated();
        env.bind_loop_variable("X", "/a");
        run(&mut env, "printf %s v");
        for line in ["echo read X", "git add .", "ls .", "grep -n source README"] {
            run(&mut env, line);
        }
        assert_eq!(env.exact("X"), Some("/a"), "an operand is not a builtin");
        run(&mut env, "command read X");
        assert_eq!(env.exact("X"), None);
    }

    #[test]
    fn a_trace_option_after_a_ps4_write_poisons_every_binding() {
        for lines in [
            &["PS4='${X:=/etc}'", "set -x"][..],
            &["set -x", "PS4='${X:=/etc}'"],
            &["PS4='${X:=/etc}' true", "set -ex"],
            &["export PS4=x", "set -xv"],
            &["declare PS4=x", "set -o xtrace"],
            &["read PS4", "shopt -o -s xtrace"],
            &["mapfile a", "set -x"],
            &["printf -v PS4 %s x", "builtin set -x"],
            &["PS4=x", "set $flags"],
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            for line in lines {
                run(&mut env, line);
            }
            env.bind_loop_variable("X", "/b");
            assert_eq!(env.exact("X"), None, "{lines:?}");
        }
        for lines in [
            &["PS4=x", "set -e"][..],
            &["PS4=x", "set +x"],
            &["PS4=x", "set -o pipefail"],
            &["set -x"],
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            for line in lines {
                run(&mut env, line);
            }
            assert_eq!(env.exact("X"), Some("/a"), "{lines:?}");
        }
    }

    #[test]
    fn builtins_with_unnameable_writes_drop_every_binding() {
        for line in [
            "mapfile arr",
            "readarray arr",
            "let X=5",
            "echo $((Y=5))",
            "read $name",
            "printf $f",
            "unset $name",
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            run(&mut env, line);
            assert_eq!(env.exact("X"), None, "{line}");
            env.bind_loop_variable("X", "/b");
            assert_eq!(env.exact("X"), Some("/b"), "{line}: rebinding works");
        }
    }

    #[test]
    fn attribute_builtins_taint_the_name_for_good() {
        for line in [
            "declare -i X",
            "typeset -u X",
            "local X",
            "readonly X",
            "integer X",
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            run(&mut env, line);
            env.bind_loop_variable("X", "/b");
            assert_eq!(env.exact("X"), None, "{line}");
        }
        let mut env = Env::isolated();
        run(&mut env, "declare -i X");
        env.bind_loop_variable("Y", "/a");
        assert_eq!(env.exact("Y"), Some("/a"));
    }

    #[test]
    fn code_that_may_rewrite_anything_poisons_every_later_binding() {
        for line in [
            "eval 'X=/b'",
            "source f",
            ". f",
            "trap 'X=/b' DEBUG",
            "alias a=read",
            "declare -n R=X",
            "declare -gn R=X",
            "declare $flags R",
            "$cmd",
            "builtin $cmd",
            "command $cmd",
            "time $cmd",
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "/a");
            run(&mut env, line);
            env.bind_loop_variable("X", "/b");
            assert_eq!(env.exact("X"), None, "{line}");
        }
        let mut env = Env::isolated();
        env.note_function_defined("f");
        env.bind_loop_variable("X", "/a");
        run(&mut env, "f");
        assert_eq!(env.exact("X"), None);
        let mut env = Env::isolated();
        env.note_function_defined("command_not_found_handle");
        env.bind_loop_variable("X", "/a");
        assert_eq!(env.exact("X"), None);
    }

    #[test]
    fn substitution_reads_the_bindings_before_the_commands_own_assignments() {
        let mut env = Env::isolated();
        run(&mut env, "S=/old");
        let command = simple("S=/new cat \"$S/a\" $S");
        let substituted = env.substitute_literals(&command).unwrap();
        env.apply_assignments(&command, ExecScope::Parent);
        let rendered = format!("{:?}", substituted.0.words);
        assert!(
            rendered.contains("/old") && !rendered.contains("/new"),
            "{rendered}"
        );
        assert_eq!(env.exact("S"), None);
    }

    fn substituted(env: &Env, line: &str) -> Option<String> {
        let command = simple(line);
        let (result, _) = env.substitute_literals(&command)?;
        Some(
            result
                .words
                .iter()
                .map(|word| {
                    word.0
                        .iter()
                        .map(|piece| match piece {
                            WordPiece::Literal(text) | WordPiece::SingleQuoted(text) => {
                                text.clone()
                            }
                            WordPiece::DoubleQuoted(inner) => inner
                                .iter()
                                .map(|piece| match piece {
                                    WordPiece::Literal(text) => text.clone(),
                                    other => format!("{other:?}"),
                                })
                                .collect(),
                            other => format!("{other:?}"),
                        })
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    #[test]
    fn substitution_covers_argument_words_and_never_the_command_word() {
        let mut env = Env::isolated();
        env.bind_loop_variable("S", "/x");
        env.bind_loop_variable("B", "ls");
        assert_eq!(
            substituted(&env, "cat \"$S/a\"").as_deref(),
            Some("cat /x/a")
        );
        assert_eq!(substituted(&env, "cat $S/a").as_deref(), Some("cat /x/a"));
        assert_eq!(substituted(&env, "cat ${S}").as_deref(), Some("cat /x"));
        assert_eq!(substituted(&env, "$B -la"), None);
        assert_eq!(substituted(&env, "\"$B\" -la"), None);
        assert_eq!(substituted(&env, "cat $T"), None);
        assert_eq!(substituted(&env, "cat \"${S:-y}\""), None);
        assert_eq!(substituted(&env, "cat ~$S"), None);
        assert_eq!(substituted(&env, "$S"), None);
    }

    #[test]
    fn unquoted_substitution_needs_a_value_no_expansion_can_touch() {
        let mut env = Env::isolated();
        for (name, value) in [
            ("A", "a b"),
            ("B", "a*"),
            ("C", "a?"),
            ("D", "[a]"),
            ("E", "~"),
            ("F", "{a,b}"),
            ("G", ""),
            ("H", "a\tb"),
            ("I", "a(b)"),
            ("J", "a'b"),
            ("K", "a$b"),
            ("L", "^a"),
            ("M", "=a"),
        ] {
            env.bind_loop_variable(name, value);
        }
        for name in [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        ] {
            assert_eq!(substituted(&env, &format!("cat ${name}")), None, "{name}");
        }
        assert_eq!(substituted(&env, "cat \"$A\"").as_deref(), Some("cat a b"));
        assert_eq!(substituted(&env, "cat \"$K\"").as_deref(), Some("cat a$b"));
        env.bind_loop_variable("S", "a-b_c.d/e:f,g+i@j%k");
        assert!(substituted(&env, "cat $S").is_some());
    }

    #[test]
    fn a_changed_ifs_blocks_unquoted_substitution_only() {
        for line in [
            "IFS=,",
            "read IFS",
            "unset IFS",
            "mapfile a",
            "printf -v IFS %s ,",
        ] {
            let mut env = Env::isolated();
            env.bind_loop_variable("X", "a");
            run(&mut env, line);
            env.bind_loop_variable("X", "a");
            assert_eq!(substituted(&env, "cat $X"), None, "{line}");
            assert_eq!(
                substituted(&env, "cat \"$X\"").as_deref(),
                Some("cat a"),
                "{line}"
            );
        }
        let mut env = Env::isolated();
        env.bind_loop_variable("X", "a");
        assert_eq!(substituted(&env, "IFS=, cat $X"), None);
        assert_eq!(
            substituted(&env, "IFS=, cat \"$X\"").as_deref(),
            Some("cat a")
        );
        let mut parent = Env::isolated();
        parent.bind_loop_variable("IFS", ",");
        let mut child = Env::child_of(&parent);
        child.bind_loop_variable("f", "a,b");
        assert_eq!(substituted(&child, "cat $f"), None);
    }

    #[test]
    fn nothing_is_substituted_in_a_command_that_assigns_through_an_expansion() {
        let mut env = Env::isolated();
        env.bind_loop_variable("X", "/a");
        assert_eq!(substituted(&env, "echo $X $((X=5))"), None);
        assert_eq!(substituted(&env, "echo $X > \"$((X=5))\""), None);
    }

    #[test]
    fn a_loop_variable_binds_strongly_and_a_poisoned_parent_binds_nothing() {
        let mut env = Env::isolated();
        env.bind_loop_variable("f", "a");
        assert_eq!(env.exact("f"), Some("a"));
        run(&mut env, "read f");
        assert_eq!(env.exact("f"), None);

        let mut parent = Env::isolated();
        run(&mut parent, "eval x");
        let mut child = Env::child_of(&parent);
        child.bind_loop_variable("f", "a");
        assert_eq!(child.exact("f"), None);

        let mut parent = Env::isolated();
        parent.note_readonly_operands(&parser_argv("readonly f"));
        parent.bind_loop_variable("f", "a");
        assert_eq!(parent.exact("f"), None);
    }

    #[test]
    fn absorbing_a_body_drops_what_the_body_may_have_written() {
        let mut parent = Env::isolated();
        for name in ["A", "B", "C", "D"] {
            parent.bind_loop_variable(name, "/a");
        }
        let mut child = Env::child_of(&parent);
        run(&mut child, "A=/b");
        run(&mut child, "read B");
        parent.absorb_body(&child);
        assert_eq!(parent.exact("A"), None);
        assert_eq!(parent.exact("B"), None);
        assert_eq!(parent.exact("C"), Some("/a"));

        let mut child = Env::child_of(&parent);
        run(&mut child, "mapfile x");
        parent.absorb_body(&child);
        assert_eq!(parent.exact("C"), None);

        let mut parent = Env::isolated();
        let mut child = Env::child_of(&parent);
        run(&mut child, "trap x DEBUG");
        parent.absorb_body(&child);
        parent.bind_loop_variable("X", "/a");
        assert_eq!(parent.exact("X"), None);

        let mut parent = Env::isolated();
        let mut child = Env::child_of(&parent);
        run(&mut child, "declare -i X");
        parent.absorb_body(&child);
        parent.bind_loop_variable("X", "/a");
        assert_eq!(parent.exact("X"), None);
    }

    #[test]
    fn a_subshell_inherits_poison_and_functions_but_no_values() {
        let mut parent = Env::isolated();
        parent.bind_loop_variable("X", "/a");
        parent.note_function_defined("f");
        let mut subshell = Env::subshell_of(&parent);
        assert_eq!(subshell.exact("X"), None);
        subshell.bind_loop_variable("Y", "/a");
        run(&mut subshell, "f");
        assert_eq!(subshell.exact("Y"), None);
        assert_eq!(parent.exact("X"), Some("/a"));
        assert_eq!(Env::opaque().exact("X"), None);
        let mut opaque = Env::opaque();
        opaque.bind_loop_variable("X", "/a");
        assert_eq!(opaque.exact("X"), None);
    }

    #[test]
    fn would_poison_probes_without_touching_the_environment() {
        let mut env = Env::isolated();
        env.bind_loop_variable("X", "/a");
        env.note_function_defined("f");
        assert!(env.would_poison(&simple("eval x")));
        assert!(env.would_poison(&simple("f")));
        assert!(env.would_poison(&simple("$c")));
        assert!(!env.would_poison(&simple("cat /a")));
        assert!(!env.would_poison(&simple("read X")));
        assert_eq!(env.exact("X"), Some("/a"));
    }
}
