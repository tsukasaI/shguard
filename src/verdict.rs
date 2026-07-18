//! [`Decision`] and [`Verdict`] — the output contract of
//! [`crate::analyze`].

use crate::normalize::NormalizedWord;

/// The three-way decision a hook adapter acts on (plan.md §0.2).
///
/// Ordering matters: `Block > Ask > Allow`, declared in that ascending
/// order so the derived [`Ord`] gives worst-wins folding over a
/// multi-command line for free — `decisions.into_iter().max()` (plan.md §6
/// item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    Allow,
    Ask,
    Block,
}

/// A human-readable justification for a non-`Allow` verdict.
///
/// A newtype rather than a bare `String` so "mandatory reason" is a type,
/// not a convention: [`Verdict::ask`] and [`Verdict::block`] take `Reason`
/// (not `Option<Reason>`), so there is no argument you can pass to skip it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The id of a blocklist rule (`rules/blocklist.toml`, a later issue).
///
/// Newtype per C-NEWTYPE: a rule id is not an interchangeable `String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(String);

impl RuleId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The decision plus its justification. Kept out of `Verdict` itself and
/// behind private fields so the only way to obtain a `Block`/`Ask` value
/// with a reason attached is through [`Verdict::ask`]/[`Verdict::block`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum VerdictDetail {
    Allow,
    Ask {
        reason: Reason,
    },
    Block {
        reason: Reason,
        matched_rule: Option<RuleId>,
    },
}

/// The result of [`crate::analyze`]: a decision, its justification, the
/// normalised argv it was made against, and — for a rule-matched `Block` —
/// which rule matched.
///
/// Fields are private (C-STRUCT-PRIVATE); the only public constructors are
/// [`Verdict::allow`], [`Verdict::ask`], and [`Verdict::block`]. `ask` and
/// `block` require a [`Reason`] by value, not `Option<Reason>` — there is no
/// way to call either constructor without supplying one, so a reasonless
/// `Ask`/`Block` cannot be constructed through the public API, and the
/// private fields mean no other path (e.g. a struct literal) exists either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    detail: VerdictDetail,
    normalized_argv: Vec<NormalizedWord>,
}

impl Verdict {
    /// An `Allow` verdict: the command was normalised in full and every
    /// simple command cleared the blocklist.
    #[must_use]
    pub fn allow(normalized_argv: Vec<NormalizedWord>) -> Self {
        Self {
            detail: VerdictDetail::Allow,
            normalized_argv,
        }
    }

    /// An `Ask` verdict: `reason` explains what could not be statically
    /// resolved or decided, for the human the hook adapter will prompt.
    #[must_use]
    pub fn ask(reason: Reason, normalized_argv: Vec<NormalizedWord>) -> Self {
        Self {
            detail: VerdictDetail::Ask { reason },
            normalized_argv,
        }
    }

    /// A `Block` verdict: `reason` explains why, and `matched_rule` is the
    /// id of the blocklist rule that matched — `None` for a block decided
    /// structurally rather than by an exact rule match (plan.md §4, e.g. a
    /// decode-fed interpreter pipe).
    ///
    /// A `Block` without a reason cannot be constructed: `reason` is a
    /// [`Reason`], not `Option<Reason>`, so there is no argument that means
    /// "no reason" — the following fails to compile because `None` is not a
    /// `Reason`:
    ///
    /// ```compile_fail
    /// use shguard::verdict::Verdict;
    ///
    /// let _verdict = Verdict::block(None, Vec::new(), None);
    /// ```
    #[must_use]
    pub fn block(
        reason: Reason,
        normalized_argv: Vec<NormalizedWord>,
        matched_rule: Option<RuleId>,
    ) -> Self {
        Self {
            detail: VerdictDetail::Block {
                reason,
                matched_rule,
            },
            normalized_argv,
        }
    }

    /// The decision: `Allow`, `Ask`, or `Block`.
    #[must_use]
    pub fn decision(&self) -> Decision {
        match &self.detail {
            VerdictDetail::Allow => Decision::Allow,
            VerdictDetail::Ask { .. } => Decision::Ask,
            VerdictDetail::Block { .. } => Decision::Block,
        }
    }

    /// The verdict's justification. Always `Some` for `Ask`/`Block`, always
    /// `None` for `Allow` — guaranteed by construction, not checked here.
    #[must_use]
    pub fn reason(&self) -> Option<&Reason> {
        match &self.detail {
            VerdictDetail::Allow => None,
            VerdictDetail::Ask { reason } | VerdictDetail::Block { reason, .. } => Some(reason),
        }
    }

    /// The id of the blocklist rule that matched, if this `Block` came from
    /// an exact rule match rather than a structural decision.
    #[must_use]
    pub fn matched_rule(&self) -> Option<&RuleId> {
        match &self.detail {
            VerdictDetail::Block { matched_rule, .. } => matched_rule.as_ref(),
            VerdictDetail::Allow | VerdictDetail::Ask { .. } => None,
        }
    }

    /// The normalised argv the decision was made against.
    #[must_use]
    pub fn normalized_argv(&self) -> &[NormalizedWord] {
        &self.normalized_argv
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn block_outranks_ask_outranks_allow() {
        assert!(Decision::Block > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
        assert!(Decision::Block > Decision::Allow);
    }

    #[test]
    fn max_folding_over_a_line_picks_the_worst_decision() {
        let decisions = [Decision::Allow, Decision::Ask, Decision::Allow];
        assert_eq!(decisions.into_iter().max().unwrap(), Decision::Ask);

        let decisions = [Decision::Ask, Decision::Block, Decision::Allow];
        assert_eq!(decisions.into_iter().max().unwrap(), Decision::Block);

        let decisions = [Decision::Allow, Decision::Allow];
        assert_eq!(decisions.into_iter().max().unwrap(), Decision::Allow);
    }

    #[test]
    fn allow_has_no_reason_or_matched_rule() {
        let verdict = Verdict::allow(Vec::new());
        assert_eq!(verdict.decision(), Decision::Allow);
        assert!(verdict.reason().is_none());
        assert!(verdict.matched_rule().is_none());
    }

    #[test]
    fn ask_and_block_carry_their_reason() {
        let verdict = Verdict::ask(Reason::new("unresolvable construct"), Vec::new());
        assert_eq!(verdict.decision(), Decision::Ask);
        assert_eq!(verdict.reason().unwrap().as_str(), "unresolvable construct");

        let verdict = Verdict::block(
            Reason::new("matches blocklist rule rm-rf-root"),
            Vec::new(),
            Some(RuleId::new("rm-rf-root")),
        );
        assert_eq!(verdict.decision(), Decision::Block);
        assert_eq!(verdict.matched_rule().unwrap().as_str(), "rm-rf-root");
    }
}
