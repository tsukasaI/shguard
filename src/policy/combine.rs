//! The generic floor and fold combinators every gate stage builds its
//! verdicts with. They moved here from `src/gate.rs` unchanged so that the
//! rules for combining uncertainty (max-lift, worst-wins with the first
//! tie winning, allowlist downgrade) live next to [`super::decide`], the
//! single terminal decision site. `gate` keeps the `scan_*` functions that
//! produce the floors and the thin `apply_*_floor` wrappers that delegate
//! here.

use crate::rules::{Allowlist, AllowlistOutcome, CommandRule};
use crate::verdict::{Decision, DenyMessage, Reason, Verdict};

/// Applies a user-configured allowlist match to `verdict`: `Ask` -> `Allow`
/// only, via the existing Block-immune `crate::rules::apply_allowlist` — a
/// `Block` verdict is untouched by that function's own first guard clause,
/// and an `Allow` verdict has nothing to downgrade from.
pub(crate) fn apply_allowlist_downgrade(verdict: Verdict, allowlist: &Allowlist) -> Verdict {
    match crate::rules::apply_allowlist(&verdict, allowlist) {
        AllowlistOutcome::Unchanged => verdict,
        AllowlistOutcome::Downgraded {
            suppressed_by,
            reason,
        } => Verdict::allow_suppressed(verdict.normalized_argv().to_vec(), suppressed_by, reason),
    }
}

/// Applies a user-configured `ask` rule match to `verdict`: `Allow` ->
/// `Ask` only. A command that is already `Ask`/`Block` for its own reasons
/// keeps that reason — an ask-rule match never replaces it, only ever
/// raises a plain `Allow`.
pub(crate) fn apply_ask_floor(
    verdict: Verdict,
    ask_match: Option<&CommandRule>,
    hint: &str,
) -> Verdict {
    match (verdict.decision(), ask_match) {
        (Decision::Allow, Some(rule)) => Verdict::ask(
            Reason::new(format!(
                "matches user-configured ask rule {:?}: {}{hint}",
                rule.id().as_str(),
                rule.reason().as_str()
            )),
            verdict.normalized_argv().to_vec(),
        )
        .with_deny_message(rule.deny_message().cloned()),
        _ => verdict,
    }
}

/// Raises `verdict` to at least `floor_decision`, folding via
/// `decision.max(floor_decision)`, the same as `gate::fold_floors`'s own
/// handling: a verdict already at or above `floor_decision` passes through
/// completely untouched (keeping its own reason/matched-rule audit trail);
/// one below it is replaced with a new verdict at the floor's decision,
/// combining `floor_reason` with the verdict's own reason when it had one
/// (an `Allow` verdict has none to combine). `deny_message` is
/// unconditionally attached to a replacement verdict via
/// [`Verdict::with_deny_message`] — a no-op for the many callers that never
/// have one (issue #202's callers do; see
/// `gate::apply_command_ascent_descent_floor`'s docs for why those attach
/// one at all) — and left untouched (not cleared) on the pass-through path.
///
/// The shared core about a dozen otherwise-unrelated `gate::apply_*_floor`
/// helpers delegate to. [`apply_substitution_floor`] (rule 3) uses the same
/// max-lift mechanics but keeps its own inlined copy rather than delegating
/// here (see its own docs). Each wrapper keeps its own name and doc comment
/// so its call site stays self-documenting; only the mechanics live here.
pub(crate) fn apply_floor(
    verdict: Verdict,
    floor_decision: Decision,
    floor_reason: String,
    deny_message: Option<DenyMessage>,
) -> Verdict {
    if verdict.decision() >= floor_decision {
        return verdict;
    }
    let argv = verdict.normalized_argv().to_vec();
    let reason = match verdict.reason() {
        Some(existing) => format!("{}; {floor_reason}", existing.as_str()),
        None => floor_reason,
    };
    match floor_decision {
        Decision::Block => Verdict::block(Reason::new(reason), argv, None),
        Decision::Ask | Decision::Allow => Verdict::ask(Reason::new(reason), argv),
    }
    .with_deny_message(deny_message)
}

/// Applies rule 3's argument-position substitution floor to a verdict — the
/// same max-lift mechanics as [`apply_floor`]. The floor passed in is
/// `evaluate_simple_command_core`'s `substitution_result` binding, which
/// already folds together `evaluate_argument_substitutions`'s own result
/// (a `$()`/backtick/process substitution in ordinary argument position)
/// with issue #77's leftover-alternative substitution floor
/// (`evaluate_leftover_alternative_substitutions`'s result, a substitution
/// living in a brace alternative other than the one determining the
/// command name) via [`fold_optional_decision`] — the two are Allow-
/// transparent/Ask/Block-propagating in exactly the same way, so one floor
/// serves both. Unlike the other floors, this one is applied at
/// MULTIPLE call sites (rules 1/2/6a/6c/6e's early returns and the ordinary
/// blocklist match, plus `gate::fold_floors` itself) rather than just once
/// before `fold_floors` — see `evaluate_simple_command_core`'s
/// `substitution_result` binding for why (issue #445): this function has
/// several early returns that would otherwise never see an argument-
/// position substitution at all (`bash -c 'ls' $(rm -rf /)` was silently
/// Allowed before this floor existed). Reason text mirrors `fold_floors`'s
/// own `substitution_result` messaging so a floored verdict reads the same
/// regardless of which return path triggered it.
pub(crate) const SUBSTITUTION_FLOOR_BLOCK_REASON: &str = "an argument-position command/backquote or \
    process substitution recurses to a command that is itself blocked";
pub(crate) const SUBSTITUTION_FLOOR_ASK_REASON: &str = "an argument-position command/backquote or process \
    substitution's inner command could not be resolved to Allow";

pub(crate) fn apply_substitution_floor(
    verdict: Verdict,
    floor: Option<(Decision, Option<DenyMessage>)>,
) -> Verdict {
    let Some((floor_decision, floor_deny_message)) = floor else {
        return verdict;
    };
    if verdict.decision() >= floor_decision {
        return verdict;
    }
    // Issue #495 review (round 2): captured before `verdict` is consumed
    // below. Preferring the PRE-FLOOR verdict's own message when it has
    // one, falling back to the floor's own message only when it doesn't --
    // the opposite priority from an earlier round of this fix, corrected
    // after review proved it backwards: `fold_floors` (the sibling path
    // that also consumes this same substitution_result data, its own
    // `substitution_deny_message`) ranks the substitution floor's own
    // message LOWEST priority, below every other structural message, and
    // this site's STRICT-lift path (the only path where this function
    // ever actually swaps in the floor's message — see the early return
    // just above) must match that priority for the same reason. This does
    // NOT claim every apply_*_floor call site in this file shares this
    // exact contract: a same-decision TIE (`verdict.decision() ==
    // floor_decision`, returned unmodified by the early check above,
    // never reaching this line at all) is a distinct, pre-existing
    // question this fix doesn't touch. `reason` below still folds the
    // pre-floor verdict's reason text in first (`"{existing}; {floor_reason}"`), consistent
    // with the pre-floor verdict's message also taking priority: the
    // governing DECISION comes from the floor, but the more specific,
    // already-reported reason/message pair is the pre-floor verdict's own.
    let verdict_deny_message = verdict.deny_message().cloned();
    let argv = verdict.normalized_argv().to_vec();
    let floor_reason = match floor_decision {
        Decision::Block => SUBSTITUTION_FLOOR_BLOCK_REASON,
        Decision::Ask | Decision::Allow => SUBSTITUTION_FLOOR_ASK_REASON,
    };
    let reason = match verdict.reason() {
        Some(existing) => format!("{}; {floor_reason}", existing.as_str()),
        None => floor_reason.to_string(),
    };
    match floor_decision {
        Decision::Block => Verdict::block(Reason::new(reason), argv, None),
        Decision::Ask | Decision::Allow => Verdict::ask(Reason::new(reason), argv),
    }
    .with_deny_message(verdict_deny_message.or(floor_deny_message))
}

/// Combines two rule-3-shaped floors (issue #77:
/// `gate::evaluate_argument_substitutions`'s and
/// `gate::evaluate_leftover_alternative_substitutions`'s) into one, the same
/// worst-of-`Some` semantics [`fold_worst`] uses for [`Verdict`]s — `None`
/// means "nothing to recurse", not "Allow", so it must never win over a
/// `Some` from the other side, and on a same-decision tie the first
/// (`a`) wins, mirroring `fold_worst`'s own tie contract. Only `a`
/// (`evaluate_argument_substitutions`) carries a `deny_message` (issue
/// #495); `b` (`evaluate_leftover_alternative_substitutions`) is still
/// flattened to a bare `Decision` at its own call site — a separate,
/// still-open instance of `Verdict::with_deny_message`'s "Known remaining
/// gaps" — so it's paired with `None` here rather than widening this
/// fix's scope to a site issue #495 doesn't cover.
pub(crate) fn fold_optional_decision(
    a: Option<(Decision, Option<DenyMessage>)>,
    b: Option<Decision>,
) -> Option<(Decision, Option<DenyMessage>)> {
    let b = b.map(|decision| (decision, None));
    match (a, b) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(a), Some(b)) => Some(if a.0 >= b.0 { a } else { b }),
    }
}

/// Picks the worse of two [`Verdict`]s by [`Decision`] (rule: worst-wins,
/// plan.md §6 item 7). On a tie, keeps `current`'s argv/reason/deny_message —
/// the earlier-encountered simple command's, per `gate`'s documented
/// "normalized_argv = the simple command that produced the worst decision"
/// contract (first one wins a tie, not the last). A `current` with no
/// `deny_message` of its own does NOT borrow `new`'s: borrowing across two
/// verdicts risks pairing one verdict's reason/matched_rule with a
/// DIFFERENT verdict's remediation hint, which is unsafe both for
/// rule-matched Asks (no rule-origin tracking exists on `VerdictDetail::Ask`
/// to guard against it) and structural Asks (the messages describe
/// different simple commands). See issue #495's follow-up for a
/// message-preserving fix at the actual origin
/// (`evaluate_argument_substitutions`) instead of at this fold.
pub(crate) fn fold_worst(current: Verdict, new: Verdict) -> Verdict {
    match new.decision().cmp(&current.decision()) {
        std::cmp::Ordering::Greater => new,
        std::cmp::Ordering::Less => current,
        std::cmp::Ordering::Equal => current,
    }
}

/// Folds an always-`Ask` floor's reason (one of the `scan_redirect_*_floor`
/// scanners) into `worst` via [`fold_worst`]: a tie keeps `worst`'s own
/// reason rather than concatenating (unlike `gate::apply_redirect_ask_floor`),
/// matching how a compound command's attached-redirect checks have always
/// combined. A `None` floor returns `worst` untouched.
pub(crate) fn fold_ask_floor(worst: Verdict, floor_reason: Option<String>) -> Verdict {
    let Some(floor_reason) = floor_reason else {
        return worst;
    };
    let argv = worst.normalized_argv().to_vec();
    fold_worst(worst, Verdict::ask(Reason::new(floor_reason), argv))
}
