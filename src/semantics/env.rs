//! Same-command-line variable facts (rule 2's bare-`$VAR` resolution) and
//! the execution scope an assignment runs in.

use std::collections::{HashMap, HashSet};

use super::value::{AbsValue, Write};
use crate::ast::{Assignment, Separator, SimpleCommand};
use crate::normalize::{self, NormalizedWord, Resolution};

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
#[derive(Debug, Default)]
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
    /// Not a substitute for `history`: a strong write drops the earlier
    /// value, which `candidates` keeps (#463).
    value: AbsValue,
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
/// line-scoped, which can only make resolution more available. Resolution
/// only ever upgrades Ask to Block, never downgrades anything.
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
}

impl Env {
    /// A fresh environment for a boundary that shares nothing with the
    /// enclosing line: a subshell, loop or `if` body, a function body, a
    /// recursed payload.
    pub(crate) fn isolated() -> Self {
        Self::default()
    }

    /// An assignment to a possibly-readonly name may fail in the real shell,
    /// so it is never a certain overwrite.
    fn is_possibly_readonly(&self, name: &str) -> bool {
        self.readonly.all || self.readonly.names.contains(name)
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
            return;
        };
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
        for assignment in &command.assignments {
            let strength = if persists && !self.is_possibly_readonly(&assignment.name) {
                Strength::Strong
            } else {
                Strength::Weak
            };
            self.apply_one(assignment, strength);
        }
    }

    fn apply_one(&mut self, assignment: &Assignment, strength: Strength) {
        self.touched.insert(assignment.name.clone());
        let write = self.resolve_write(assignment);
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
            Strength::Strong => AbsValue::strong_write(&write),
            Strength::Weak => facts.value.weak_write(&write),
        };
        if assignment.name == "IFS"
            && let Write::Exact(value) = &write
        {
            self.ifs.seen.push(value.clone());
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
}
