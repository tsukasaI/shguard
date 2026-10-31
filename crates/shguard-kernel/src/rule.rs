//! Rules: patterns that raise a decision for a matching simple command.
//!
//! Matching is defined in [`crate::decide`]. A rule hits a simple command when
//! the command's key matches `key`, every entry of `opts` is present (an
//! entry is a set of alias names, present when any one of them is), and any
//! target matches (an empty `targets` means any). Rules only raise the
//! verdict; user allows are catalog rows, never rules.

use crate::ast::Part;
use crate::catalog::OptName;
use crate::catalog::key_ok;
#[cfg(creusot)]
use crate::catalog::key_wf;
use crate::decision::Decision;
#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// Identifies a rule in reasons and logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
#[expect(
    clippy::module_name_repetitions,
    reason = "`Id` alone would be ambiguous outside this module"
)]
pub struct RuleId(pub u32);

/// What a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Scope {
    /// A simple command on its own.
    Simple,
    /// A command that receives a pipe.
    PipeInto,
}

/// How a pattern is compared with a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum PatKind {
    /// The whole word equals the pattern.
    Exact,
    /// The word starts with the pattern, byte for byte (`/etc` also covers
    /// `/etcfoo`).
    Prefix,
    /// The word is the pattern or a path below it: the pattern is a byte
    /// prefix that ends at a `/` of the word or at its end (`/etc` covers
    /// `/etc` and `/etc/x`, not `/etcfoo`). A pattern that ends in `/`
    /// (such as `/`) covers every word it is a byte prefix of.
    Under,
}

/// A target pattern. It reuses [`Part`], so `~/.bashrc` is
/// `[Opaque(Tilde), Lit("/.bashrc")]`.
///
/// A `/`-led pattern never covers a word that starts with `~`: to cover the
/// home directory, add a `~` `Prefix` or `Under` target as well (see
/// [`crate::decide`] for how patterns match).
///
/// A pattern with a non-ASCII byte, or an `Exact` or `Under` pattern with a
/// `..` segment, is matched like any other, but every word it matches
/// already fails a path check (`PathNonAscii`, `PathDotDot`), so the
/// command is Ask anyway: on an Ask rule such a target never changes the
/// decision, and only a Block rule can raise it. (A `Prefix` `..` also
/// matches `..x`, which passes the checks.)
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Pat {
    pub(crate) parts: Vec<Part>,
    pub(crate) kind: PatKind,
}

/// A pattern has at least one part.
#[cfg(creusot)]
#[logic(open)]
pub fn pat_wf(parts: Seq<Part>) -> bool {
    parts.len() > 0
}

#[cfg(creusot)]
impl Invariant for Pat {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { pat_wf(self.parts@) }
    }
}

impl Pat {
    /// Builds a pattern, or `None` when `parts` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(p) => p.parts@ == parts@ && p.kind == kind,
        None => !pat_wf(parts@),
    }))]
    #[must_use]
    pub fn new(parts: Vec<Part>, kind: PatKind) -> Option<Pat> {
        if <[_]>::is_empty(&parts) {
            None
        } else {
            Some(Pat { parts, kind })
        }
    }

    /// The pattern parts.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.parts@))]
    #[must_use]
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// How the pattern is compared.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.kind))]
    #[must_use]
    pub fn kind(&self) -> PatKind {
        self.kind
    }
}

/// What a rule does when it hits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Outcome {
    /// Raise the verdict to at least Ask.
    Ask,
    /// Raise the verdict to Block.
    Block,
}

/// The decision a rule outcome stands for.
#[cfg(creusot)]
#[logic(open)]
pub fn outcome_decision(o: Outcome) -> Decision {
    match o {
        Outcome::Ask => Decision::Ask,
        Outcome::Block => Decision::Block,
    }
}

/// A set of alternative option names: the rule entry holds when the command
/// uses any one of them (`-r`, `-R` or `--recursive`).
///
/// The set is non-empty. An empty set could never be seen, so a Block rule
/// holding one would be silently dead; the checked constructor refuses it.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct OptAlts {
    pub(crate) names: Vec<OptName>,
}

/// An alias set has at least one name.
#[cfg(creusot)]
#[logic(open)]
pub fn alts_wf(names: Seq<OptName>) -> bool {
    names.len() > 0
}

#[cfg(creusot)]
impl Invariant for OptAlts {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { alts_wf(self.names@) }
    }
}

impl OptAlts {
    /// Builds an alias set, or `None` when `names` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(a) => a.names@ == names@,
        None => !alts_wf(names@),
    }))]
    #[must_use]
    pub fn new(names: Vec<OptName>) -> Option<OptAlts> {
        if <[_]>::is_empty(&names) {
            None
        } else {
            Some(OptAlts { names })
        }
    }

    /// The alternative names.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.names@))]
    #[must_use]
    pub fn names(&self) -> &[OptName] {
        &self.names
    }
}

/// A rule.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Rule {
    pub(crate) id: RuleId,
    pub(crate) scope: Scope,
    pub(crate) key: Vec<Vec<u8>>,
    pub(crate) opts: Vec<OptAlts>,
    pub(crate) targets: Vec<Pat>,
    pub(crate) outcome: Outcome,
}

#[cfg(creusot)]
impl Invariant for Rule {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { key_wf(self.key@) }
    }
}

impl Rule {
    /// Builds a rule, or `None` when `key` is empty or has an empty segment.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(r) => r.id == id && r.scope == scope && r.key@ == key@ && r.opts@ == opts@
            && r.targets@ == targets@ && r.outcome == outcome,
        None => !key_wf(key@),
    }))]
    #[must_use]
    pub fn new(
        id: RuleId,
        scope: Scope,
        key: Vec<Vec<u8>>,
        opts: Vec<OptAlts>,
        targets: Vec<Pat>,
        outcome: Outcome,
    ) -> Option<Rule> {
        if key_ok(&key) {
            Some(Rule {
                id,
                scope,
                key,
                opts,
                targets,
                outcome,
            })
        } else {
            None
        }
    }

    /// The rule's id.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.id))]
    #[must_use]
    pub fn id(&self) -> RuleId {
        self.id
    }

    /// What the rule applies to.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.scope))]
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The command key the rule matches.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.key@))]
    #[must_use]
    pub fn key(&self) -> &[Vec<u8>] {
        &self.key
    }

    /// The option entries that must all hold; each holds when any one of its
    /// alternative names is present.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.opts@))]
    #[must_use]
    pub fn opts(&self) -> &[OptAlts] {
        &self.opts
    }

    /// The target patterns; empty means any.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.targets@))]
    #[must_use]
    pub fn targets(&self) -> &[Pat] {
        &self.targets
    }

    /// The rule's outcome.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.outcome))]
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The decision this rule raises the verdict to when it hits.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == outcome_decision(self.outcome)))]
    #[must_use]
    pub fn decision(&self) -> Decision {
        match self.outcome {
            Outcome::Ask => Decision::Ask,
            Outcome::Block => Decision::Block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OptAlts, Outcome, Pat, PatKind, Rule, RuleId, Scope};
    use crate::ast::{Opaque, Part};
    use crate::catalog::{OptName, ShortName};
    use crate::decision::Decision;

    fn short(b: u8) -> ShortName {
        ShortName::new(b).expect("printable, not '-'")
    }

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn alts() -> OptAlts {
        OptAlts::new(vec![
            OptName::Short(short(b'r')),
            OptName::Short(short(b'R')),
        ])
        .expect("non-empty")
    }

    #[test]
    fn opt_alts_constructor() {
        let a = alts();
        assert_eq!(
            a.names(),
            [OptName::Short(short(b'r')), OptName::Short(short(b'R'))]
        );
        assert!(OptAlts::new(Vec::new()).is_none());
    }

    fn rule(key: Vec<Vec<u8>>, outcome: Outcome) -> Option<Rule> {
        Rule::new(
            RuleId(7),
            Scope::Simple,
            key,
            vec![alts()],
            Vec::new(),
            outcome,
        )
    }

    #[test]
    fn pat_constructor() {
        let parts = vec![Part::Opaque(Opaque::Tilde), Part::Lit(bytes("/.bashrc"))];
        let pat = Pat::new(parts.clone(), PatKind::Exact).expect("non-empty");
        assert_eq!(pat.parts(), parts);
        assert_eq!(pat.kind(), PatKind::Exact);
        assert!(Pat::new(Vec::new(), PatKind::Prefix).is_none());
    }

    #[test]
    fn rule_constructor() {
        let r = rule(vec![bytes("rm")], Outcome::Block).expect("valid key");
        assert_eq!(r.id(), RuleId(7));
        assert_eq!(r.scope(), Scope::Simple);
        assert_eq!(r.key(), [bytes("rm")]);
        assert_eq!(r.opts(), [alts()]);
        assert!(r.targets().is_empty());
        assert_eq!(r.outcome(), Outcome::Block);

        assert!(rule(Vec::new(), Outcome::Ask).is_none());
        assert!(rule(vec![Vec::new()], Outcome::Ask).is_none());
        assert!(rule(vec![bytes("git"), Vec::new()], Outcome::Ask).is_none());
    }

    #[test]
    fn rule_decision() {
        let ask = rule(vec![bytes("rm")], Outcome::Ask).expect("valid key");
        let block = rule(vec![bytes("rm")], Outcome::Block).expect("valid key");
        assert_eq!(ask.decision(), Decision::Ask);
        assert_eq!(block.decision(), Decision::Block);
    }
}
