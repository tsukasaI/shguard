//! The single terminal decision site (issue #659, RFC #658 stage 1).
//!
//! Every path that ends in a [`Verdict`] builds [`Evidence`] and calls
//! [`decide`]: the structural gate's folded verdict, a parse failure, a
//! rejected hook payload, an unavailable config and every watchdog or
//! internal-failure trip. The adapters then only render the decided
//! verdict (`adapter::render`); none of them chooses a decision or writes a
//! reason itself.
//!
//! [`combine`] holds the generic floor and fold combinators the gate stages
//! build their verdicts with.

pub(crate) mod combine;
mod evidence;

pub use evidence::{Evidence, InputStage, LimitKind};

use crate::HookContext;
use crate::rules::AskOutcome;
use crate::verdict::{Decision, DenyMessage, Reason, Verdict};
use combine::fold_worst;

/// The configuration [`decide`] reads, resolved once at the composition
/// root. Fields are private so the only ways to obtain one are
/// [`PolicyConfig::none`] and `Policy::policy_config`.
#[derive(Debug, Clone, Copy)]
pub struct PolicyConfig {
    ask_outcome: AskOutcome,
    strict_config: bool,
}

impl PolicyConfig {
    /// No user config: `ask_outcome` stays `Ask` and a config failure is not
    /// strict. What the embedded-only entry points and the gate's own
    /// structural findings use.
    #[must_use]
    pub fn none() -> Self {
        Self::new(AskOutcome::default())
    }

    pub(crate) fn new(ask_outcome: AskOutcome) -> Self {
        Self {
            ask_outcome,
            strict_config: false,
        }
    }

    /// Whether an unavailable config blocks (`SHGUARD_STRICT_CONFIG`, issue
    /// #440) instead of asking.
    #[must_use]
    pub fn with_strict_config(mut self, strict_config: bool) -> Self {
        self.strict_config = strict_config;
        self
    }
}

/// Decides the final [`Verdict`] for `evidence`: each item is decided on
/// its own, then the worst decision wins and the first of equals keeps its
/// reason (`combine::fold_worst`). An empty list is itself a fail-closed
/// `Ask`, since "nothing found" is not evidence the command is safe.
///
/// - `ResourceLimit` is always `Ask`, never floored: a time or memory trip
///   is a resource-exhaustion signal, and remapping it to `Block` through
///   `ask_outcome` would misrepresent it as an ordinary policy decision and
///   corrupt the reason a caller needs to diagnose it.
/// - `ConfigUnavailable` is `Block` under strict config and `Ask`
///   otherwise; `ask_outcome` does not apply since no config was read.
/// - `InputRejected` is `Ask`; `ask_outcome`, resolved against `ctx`, turns
///   it into a `Block` with the same reason and no deny message.
/// - `ParseFailure` is `Ask` carrying the unsupported construct's guidance;
///   the terminal `ask_outcome` floor reaches it through the gate's
///   `GateVerdict`.
/// - `GateVerdict` passes through unless `ask_outcome` resolves to `Block`
///   and the verdict is an `Ask`; see [`floor_ask`].
#[must_use]
pub fn decide(evidence: &[Evidence], config: &PolicyConfig, ctx: &HookContext) -> Verdict {
    evidence
        .iter()
        .map(|item| decide_one(item, config, ctx))
        .reduce(fold_worst)
        .unwrap_or_else(|| {
            Verdict::ask(
                Reason::new("shguard: no evidence was produced for this command; refusing to decide (fail-closed)"),
                Vec::new(),
            )
        })
}

fn decide_one(evidence: &Evidence, config: &PolicyConfig, ctx: &HookContext) -> Verdict {
    match evidence {
        Evidence::GateVerdict(verdict) => {
            let ask_outcome = resolve_ask_outcome(config, ctx);
            floor_ask(verdict.clone(), ask_outcome)
        }
        Evidence::ParseFailure { message, construct } => Verdict::ask(
            Reason::new(format!("could not parse command: {message}")),
            Vec::new(),
        )
        .with_deny_message(construct.as_deref().map(deny_msg_unsupported_construct)),
        Evidence::InputRejected { stage } => {
            let reason = Reason::new(input_rejected_reason(stage));
            match resolve_ask_outcome(config, ctx) {
                Decision::Block => Verdict::block(reason, Vec::new(), None),
                Decision::Ask | Decision::Allow => Verdict::ask(reason, Vec::new()),
            }
        }
        Evidence::ConfigUnavailable { error } => {
            let reason = Reason::new(format!(
                "shguard: user config failed to load ({error}); refusing to evaluate any command \
                 until this is fixed"
            ));
            if config.strict_config {
                Verdict::block(reason, Vec::new(), None)
            } else {
                Verdict::ask(reason, Vec::new())
            }
        }
        Evidence::ResourceLimit { kind } => {
            Verdict::ask(Reason::new(resource_limit_reason(*kind)), Vec::new())
        }
    }
}

fn resolve_ask_outcome(config: &PolicyConfig, ctx: &HookContext) -> Decision {
    config
        .ask_outcome
        .resolve(ctx.permission_mode(), ctx.agent_id())
}

fn input_rejected_reason(stage: &InputStage) -> String {
    match stage {
        InputStage::MalformedJson(err) => {
            format!("shguard: could not parse PreToolUse stdin as JSON: {err}")
        }
        InputStage::MissingCommand => {
            "shguard: Bash tool_input is missing a string \"command\" field".to_string()
        }
        InputStage::StdinOverCap(cap) => {
            format!("shguard: stdin exceeds {cap} bytes; refusing to evaluate")
        }
        InputStage::StdinReadError(err) => format!("shguard: could not read stdin: {err}"),
    }
}

fn resource_limit_reason(kind: LimitKind) -> String {
    match kind {
        LimitKind::InnerTime => {
            "shguard: evaluation exceeded its time budget; refusing to evaluate (fail-closed)"
                .to_string()
        }
        LimitKind::InnerMemory(delta) => format!(
            "shguard: evaluation exceeded its memory budget ({delta} bytes RSS growth); \
             refusing to evaluate (fail-closed)"
        ),
        LimitKind::OuterTime => "shguard: evaluation exceeded its outer time budget; refusing to \
                                 evaluate (fail-closed)"
            .to_string(),
        LimitKind::OuterMemory(rss) => format!(
            "shguard: evaluation exceeded its memory budget ({rss} bytes RSS); refusing to \
             evaluate (fail-closed)"
        ),
        LimitKind::Disconnected => "shguard: evaluation worker stopped without producing a \
                                    result; refusing to evaluate (fail-closed)"
            .to_string(),
        LimitKind::SpawnFailed => {
            "shguard: could not start command evaluation; refusing to evaluate (fail-closed)"
                .to_string()
        }
        LimitKind::Panic => "shguard: internal panic while evaluating the command; refusing to \
                             evaluate (fail-closed)"
            .to_string(),
        LimitKind::RecursionDepth(cap) => format!(
            "nested substitution exceeds the recursion depth cap ({cap}); \
             refusing to keep unwinding (fail-closed denial-of-service guard, see gate.rs module docs)"
        ),
    }
}

/// Category-3 guidance (issue #471): a construct the gate cannot statically
/// resolve at all. Names the specific construct via whichever description
/// is available at the call site: the parser's unsupported-construct text,
/// or a human-readable name for an unresolvable word kind.
pub(crate) fn deny_msg_unsupported_construct(construct: &str) -> DenyMessage {
    DenyMessage::new(format!(
        "shguard cannot statically analyze this construct ({construct}); use its literal form, \
         or split the command across separate lines so each piece is inspectable."
    ))
}

/// Floors a terminal `Ask` verdict to `Block` when the user config's
/// `ask_outcome = "deny"` (issue #467) — see
/// [`crate::rules::parse_ask_outcome`] for why this key exists and what it
/// covers. Preserves the matched rule's own `deny_message` when the `Ask`
/// came from one (a user `[[ask]]` entry, or an embedded `decision =
/// "ask"` rule) and falls back to a generic rewrite-guidance message only
/// otherwise — [`Verdict::matched_rule`] returns `None` for an `Ask`
/// regardless of origin, so this function cannot itself tell "structural"
/// and "rule-authored" apart, and assuming structural would put wrong
/// guidance (e.g. "rewrite the `$VAR`") on a verdict that never had one.
///
/// `matched_rule_id` is deliberately left `null` on the returned `Block` —
/// unlike an ordinary rule-matched `Block`, this one names no specific
/// rule, whether the original `Ask` came from a structural gate decision
/// or a rule-table `[[ask]]`/embedded `decision = "ask"` match. This alone
/// does not isolate a floored `Ask` in a `decision_log_path` log, though:
/// several pre-existing structural `Block`s (`src/gate.rs`) also carry a
/// `null` rule id. Filter on the reason instead —
/// `jq 'select(.reason | contains("ask_outcome = \"deny\""))'` — which only
/// ever appears on a verdict this function produced.
///
/// # Why this is a single terminal remap, not a per-command floor
///
/// `combine::fold_worst` keeps the earlier verdict on a decision tie, so
/// remapping each simple command's `Ask` to `Block` independently, as
/// `gate.rs` evaluates each one, would let `ask-cmd; rm -rf /` lose the
/// real `rm` rule's id and `deny_message` to whichever `Ask`-turned-`Block`
/// folded in first. Running this fold exactly once, over the whole line's
/// already-resolved final verdict, avoids that.
///
/// # Why a watchdog trip is never floored
///
/// [`crate::analyze_with_policy`] calls [`decide`] on the gate's result
/// INSIDE `watchdog::bounded`'s closure, not on whatever `bounded` returns:
/// the watchdog's own fail-closed `Ask` is a `ResourceLimit` decided
/// outside the gate, a resource-exhaustion signal rather than a structural
/// can't-resolve-this-statically one. Remapping it to `Block` would
/// misrepresent a trip as an ordinary policy decision and corrupt the
/// accurate "time/memory budget exceeded" reason a caller needs to diagnose
/// it. Keeping the floor inside the closure leaves a trip untouched by
/// construction, rather than excluding it after the fact by matching
/// against the watchdog's own reason strings.
///
/// `combine::apply_allowlist_downgrade` still runs first, at every
/// recursion level, inside the gate itself — this function only ever sees
/// whatever the gate already decided, so an `[[allow]]` entry that would
/// have downgraded an `Ask` to `Allow` still does, unaffected by
/// `ask_outcome`.
fn floor_ask(verdict: Verdict, ask_outcome: Decision) -> Verdict {
    if ask_outcome != Decision::Block || verdict.decision() != Decision::Ask {
        return verdict;
    }

    // `Ask` always carries a reason by construction (`Verdict::ask` takes a
    // `Reason`, not `Option<Reason>`) — `map_or` with an unreachable default
    // rather than `.expect()`, matching `crate::adapter::render`'s own
    // style for the same guarantee.
    let original_reason = verdict.reason().map_or("", |reason| reason.as_str());
    let reason = Reason::new(format!(
        "{original_reason}; ask_outcome = \"deny\": this Ask has been floored to a deny \
         because an unresolved Ask cannot be acted on by an autonomous session, and Ask is \
         not a reliable control under bypassPermissions (anthropics/claude-code#37420)"
    ));
    // Preserve a rule-authored deny_message when there is one (see this
    // function's own doc comment); the generic fallback below is only for
    // a genuinely structural Ask.
    let deny_message = verdict.deny_message().cloned().unwrap_or_else(|| {
        DenyMessage::new(
            "shguard could not statically resolve this command, and this config's ask_outcome \
             = \"deny\" turns every such Ask into a deny: if it involves an unresolved \
             $VAR/$(...), rewrite it with a literal path; if it involves inline interpreter \
             code, move it to a file and run that file; otherwise split a compound line into \
             separate commands or run this one manually",
        )
    });

    Verdict::block(reason, verdict.normalized_argv().to_vec(), None)
        .with_deny_message(Some(deny_message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide_one_item(evidence: Evidence, config: &PolicyConfig) -> Verdict {
        decide(&[evidence], config, &HookContext::none())
    }

    fn deny_config() -> PolicyConfig {
        PolicyConfig::new(AskOutcome::Global(Decision::Block))
    }

    #[test]
    fn empty_evidence_fails_closed_to_ask() {
        let verdict = decide(&[], &PolicyConfig::none(), &HookContext::none());
        assert_eq!(verdict.decision(), Decision::Ask);
    }

    #[test]
    fn resource_limit_is_never_floored_by_ask_outcome() {
        let verdict = decide_one_item(
            Evidence::ResourceLimit {
                kind: LimitKind::InnerTime,
            },
            &deny_config(),
        );
        assert_eq!(verdict.decision(), Decision::Ask);
    }

    #[test]
    fn input_rejected_follows_ask_outcome_without_a_deny_message() {
        let evidence = Evidence::InputRejected {
            stage: InputStage::MissingCommand,
        };
        let asked = decide_one_item(evidence.clone(), &PolicyConfig::none());
        let blocked = decide_one_item(evidence, &deny_config());
        assert_eq!(asked.decision(), Decision::Ask);
        assert_eq!(blocked.decision(), Decision::Block);
        assert_eq!(asked.reason(), blocked.reason());
        assert!(blocked.deny_message().is_none());
    }

    #[test]
    fn config_unavailable_blocks_only_under_strict_config() {
        let evidence = Evidence::ConfigUnavailable {
            error: "boom".to_string(),
        };
        let lenient = decide_one_item(evidence.clone(), &PolicyConfig::none());
        let strict = decide_one_item(evidence, &PolicyConfig::none().with_strict_config(true));
        assert_eq!(lenient.decision(), Decision::Ask);
        assert_eq!(strict.decision(), Decision::Block);
        assert_eq!(lenient.reason(), strict.reason());
    }

    #[test]
    fn config_unavailable_ignores_ask_outcome() {
        let verdict = decide_one_item(
            Evidence::ConfigUnavailable {
                error: "boom".to_string(),
            },
            &deny_config(),
        );
        assert_eq!(verdict.decision(), Decision::Ask);
    }

    #[test]
    fn gate_ask_is_floored_only_when_ask_outcome_blocks() {
        let ask = Verdict::ask(Reason::new("because"), Vec::new());
        let kept = decide_one_item(Evidence::GateVerdict(ask.clone()), &PolicyConfig::none());
        let floored = decide_one_item(Evidence::GateVerdict(ask.clone()), &deny_config());
        assert_eq!(kept, ask);
        assert_eq!(floored.decision(), Decision::Block);
        assert!(floored.matched_rule().is_none());
        assert!(floored.deny_message().is_some());
    }

    #[test]
    fn worst_decision_wins_and_the_first_of_equals_is_kept() {
        let first = Evidence::ResourceLimit {
            kind: LimitKind::Panic,
        };
        let second = Evidence::ResourceLimit {
            kind: LimitKind::Disconnected,
        };
        let block = Evidence::GateVerdict(Verdict::block(Reason::new("rule"), Vec::new(), None));
        let ctx = HookContext::none();
        let config = PolicyConfig::none();
        let tied = decide(&[first.clone(), second.clone()], &config, &ctx);
        assert_eq!(tied, decide_one(&first, &config, &ctx));
        let worst = decide(&[first, block, second], &config, &ctx);
        assert_eq!(worst.decision(), Decision::Block);
    }
}
