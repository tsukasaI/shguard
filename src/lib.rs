//! shguard: a parse-then-decide PreToolUse hook that blocks dangerous shell
//! commands for AI coding agents.
//!
//! Design: `plan.md` at the repository root. Implementation tracked in
//! GitHub issues (tsukasaI/shguard).

pub mod adapter;
mod ast;
pub mod config;
mod decision_log;
mod gate;
pub mod normalize;
mod parser;
mod rules;
pub mod verdict;
mod watchdog;

use std::path::Path;

pub use decision_log::FileDecisionLog;
use verdict::{Decision, DenyMessage, Reason, Verdict};

/// Port [`analyze_with_policy`] appends one JSONL decision-log line
/// through, per issue #108 (`coding-guidelines/principles.md`: "ports MUST
/// be defined next to the code that consumes them" — this is that code).
/// [`FileDecisionLog`] (`src/decision_log.rs`) is the only implementation
/// today; the composition root (`src/bin/shguard.rs`) constructs it and
/// passes it in, so this module never names a concrete filesystem writer
/// itself (`coding-guidelines/principles.md`, "composition root": "code
/// outside the composition root MUST NOT know which concrete adapter it is
/// using").
pub trait DecisionLogSink {
    /// Appends one line describing `verdict` for `command` to `path`. See
    /// [`FileDecisionLog`]'s docs for the concrete format and fail-open
    /// posture.
    fn append(&self, path: &Path, command: &str, verdict: &Verdict);
}

/// Analyzes a raw shell command line and returns the [`Verdict`] the hook
/// adapter should act on.
///
/// # Error posture
///
/// This function returns [`Verdict`], not `Result<Verdict, _>`. Every
/// failure mode internal to the pipeline — a parse error, an unrecognised
/// construct, anything the parse/normalise/rules/gate stages (plan.md §1.1)
/// cannot resolve statically — folds into a fail-closed `Ask` verdict
/// *inside* `analyze`, carrying a human-readable [`verdict::Reason`], rather
/// than propagating outward as an `Err` the caller has to remember to
/// handle.
///
/// Why: the hook adapter (`src/bin/shguard.rs`) sits on Claude Code's
/// PreToolUse stdin→stdout contract (plan.md §0.2) and must satisfy two
/// constraints at once — never crash (a panic there fails *open*, since the
/// tool call proceeds unguarded when the hook produces no decision) and
/// never silently allow (mapping an unhandled `Err` to `Allow` anywhere in
/// the adapter would be the same failure in the opposite direction).
/// Returning `Verdict` unconditionally, with every internal failure folded
/// to `Ask` at this one point, means there is exactly one place that has to
/// get the fail-closed mapping right (plan.md §1.2's "single fold point"),
/// and the adapter's job becomes trivial and impossible to get wrong: call
/// `analyze`, always get a `Verdict`, always emit a `permissionDecision`.
///
/// The pipeline itself — parse (`src/parser.rs`) → normalise
/// (`src/normalize.rs`) → rules (`src/rules.rs`) → structural gate
/// (`src/gate.rs`) → worst-decision-wins fold — is composed in
/// [`gate::analyze`]; see that module's docs for the full Block/Ask/Allow
/// rule set.
///
/// # Bounded evaluation (issue #319)
///
/// Runs on its own thread, bounded by wall-clock time everywhere and, on
/// Linux/macOS, memory growth too (`src/watchdog.rs`; other platforms have
/// no RSS-reading implementation there yet and rely on the wall-clock
/// bound alone) — a pathological input that would otherwise hang or grow
/// memory unboundedly (crash-fuzzer finding #315) instead makes this
/// call itself return a fail-closed `Ask` within a couple of seconds. This
/// is a real, documented limitation, not a full guarantee: a trip leaves
/// the runaway worker thread detached rather than terminating it (Rust has
/// no safe thread-cancel primitive), so for a non-terminating input like
/// #315's, that thread keeps allocating in the background afterward and
/// the host process can still run out of memory eventually — just later,
/// and outside this call, rather than during it. See `src/watchdog.rs`'s
/// module docs for the full reasoning. A caller evaluating untrusted or
/// adversarial input, where the difference between "delayed" and
/// "prevented" matters, should run this behind a subprocess instead, so
/// the runaway dies with it.
#[must_use]
pub fn analyze(command: &str) -> Verdict {
    let command = command.to_string();
    watchdog::bounded(move || gate::analyze(&command))
}

/// Config-aware sibling of [`analyze`]: same pipeline, the same
/// error/fail-closed posture, and the same bounded-evaluation guarantee
/// (see [`analyze`]'s "Bounded evaluation" section), but `policy` (loaded
/// once at the composition root via [`config::Policy::load`]) supplies the
/// rules and allowlist instead of the embedded defaults alone. [`analyze`]'s
/// own behavior and signature are untouched — this is an additional entry
/// point, not a replacement.
///
/// # Structured decision-output logging (issue #108)
///
/// When `policy` carries a `decision_log_path` (set via the user config's
/// `decision_log_path` key, off by default), one JSONL line describing the
/// resulting verdict is appended to that path via `sink` (see
/// [`DecisionLogSink`]) — the composition root (`src/bin/shguard.rs`)
/// constructs the concrete [`FileDecisionLog`] and passes it to both the
/// real hook path (`src/adapter.rs`) and the `shguard check` CLI (issue
/// #109), so a logged line can never diverge from what either caller
/// actually saw, and it logs the verdict [`watchdog::bounded`] actually
/// returned — including its own fail-closed `Ask` on a timeout — never a
/// verdict a detached, still-running worker computed after the fact.
///
/// The write happens AFTER [`watchdog::bounded`] returns, deliberately
/// outside *this* wall-clock bound: logging inside the bounded closure was
/// tried first and rejected — a log target that blocks (a FIFO with no
/// reader, a hung network mount) would trip the watchdog's timeout and
/// silently replace an already-computed, correct `Allow`/`Ask`/`Block`
/// with a fail-closed `Ask`, corrupting the real decision to paper over a
/// logging-only problem. [`config::Policy::load`] rejects any
/// `decision_log_path` that already names a FIFO/device/socket/directory
/// at load time (`src/config.rs`), closing the detectable case.
///
/// This module-level bound is not the only watchdog a caller may sit
/// behind, though: `src/bin/shguard.rs`'s PreToolUse hook path (`run`) also
/// wraps this ENTIRE call — decision plus log write — in its own, separate
/// `EVALUATION_TIMEOUT` watchdog, since `run` itself must never hang
/// regardless of where the hang comes from. A log target that starts
/// blocking only *after* config load (a network mount that hangs
/// mid-session, not a FIFO caught at load time) can therefore still trip
/// that OUTER watchdog and yield the same fail-closed-`Ask`-instead-of-the-
/// real-decision outcome for a hook invocation specifically — a residual,
/// disclosed risk (see the README), not one this function's own bound can
/// close, since it has no visibility into whatever bound a caller wraps it
/// in. `shguard check` (issue #109) wraps this whole call in the same
/// `EVALUATION_TIMEOUT` bound for the same reason (`src/bin/shguard.rs`'s
/// `evaluate_with_timeout`); a direct library caller has no such outer
/// watchdog of its own, so for one this function's own bound is the whole
/// story.
///
/// # `ask_outcome` terminal remap (issue #467)
///
/// When `policy` carries `ask_outcome = "deny"` (top-level user-config key,
/// default `"ask"`), a *final* `Decision::Ask` — the one [`watchdog::bounded`]
/// actually returns for this whole command line — is remapped to
/// `Decision::Block` via [`remap_ask_to_block`] before logging, so an
/// autonomous session never stalls on any of the three ways a hook
/// invocation reaches `Ask` today: a structural fallback (unresolved
/// `$VAR`/`$(...)`, an inline-interpreter one-liner, an unsupported
/// construct), an embedded `decision = "ask"` blocklist rule match (e.g.
/// `rules/blocklist.toml`'s `tar-directory-root-or-home`), or a user
/// `[[ask]]` rule match.
///
/// This is a remap of the whole-line fold result, not a per-command floor
/// applied inside `gate::analyze_with_policy` itself: `gate::fold_worst`
/// already keeps the worst `Decision` across every simple command on the
/// line, so a compound line like `ask-cmd; rm -rf /` already resolves to
/// `Decision::Block` from the real `rm` rule (`Decision::Block >
/// Decision::Ask`) by the time this function sees it — remapping only a
/// verdict that is STILL `Ask` here can never touch that case, so the real
/// rule's id/reason/deny_message are never lost to this remap. Applied
/// after [`watchdog::bounded`] returns (a watchdog-timeout `Ask` is remapped
/// too — same posture: autonomous sessions should not stall on that either)
/// and before `sink.append`, so what's logged always matches what the
/// caller actually saw. `[[allow]]` downgrades already ran, at every
/// recursion level, inside `gate::analyze_with_policy` itself
/// (`gate::apply_allowlist_downgrade`) — by construction, this remap can
/// never see a verdict an allow entry would have rescued.
#[must_use]
pub fn analyze_with_policy(
    command: &str,
    policy: &config::Policy,
    sink: &dyn DecisionLogSink,
) -> Verdict {
    let command_owned = command.to_string();
    let policy_owned = policy.clone();
    let verdict = watchdog::bounded(move || {
        gate::analyze_with_policy(&command_owned, &policy_owned.rules, &policy_owned.allowlist)
    });
    let verdict = if policy.ask_outcome == Decision::Block {
        remap_ask_to_block(verdict)
    } else {
        verdict
    };
    if let Some(path) = &policy.decision_log_path {
        sink.append(path, command, &verdict);
    }
    verdict
}

/// Remaps a final `Decision::Ask` verdict to `Decision::Block` for
/// `ask_outcome = "deny"` (see [`analyze_with_policy`]'s own docs) —
/// a no-op on `Allow`/`AllowSuppressed`/`Block`. `matched_rule` stays
/// `None`: this is never itself a rule match. That alone does not isolate a
/// remapped verdict in a `decision_log_path` line, though — several
/// structural `Block`s in `gate.rs` also carry `matched_rule: None` — so the
/// combined reason text below (which always contains the literal
/// `ask_outcome = "deny"` marker) is what a caller should filter on
/// instead, e.g. `jq 'select(.reason | contains("ask_outcome"))'`.
fn remap_ask_to_block(verdict: Verdict) -> Verdict {
    if verdict.decision() != Decision::Ask {
        return verdict;
    }
    let original_reason = verdict
        .reason()
        .map_or("ask verdict carried no reason", Reason::as_str)
        .to_string();
    let deny_message = verdict.deny_message().cloned();
    Verdict::block(
        Reason::new(format!(
            "{original_reason}; ask_outcome = \"deny\" remapped this Ask to Block"
        )),
        verdict.normalized_argv().to_vec(),
        None,
    )
    .with_deny_message(deny_message.or_else(|| {
        Some(DenyMessage::new(
            "ask_outcome = \"deny\" turned this Ask into a Block; see the reason for what \
             was undecidable, and run the command manually if it is genuinely intended",
        ))
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::verdict::RuleId;

    /// Discards every logged line — these tests only care about the
    /// returned `Verdict`, not `decision_log_path` behavior (covered
    /// separately by `tests/decision_log.rs`).
    struct NoopSink;
    impl DecisionLogSink for NoopSink {
        fn append(&self, _path: &Path, _command: &str, _verdict: &Verdict) {}
    }

    /// Merges `user_toml`'s `[[deny]]`/`[[ask]]`/`[[allow]]`/`ask_outcome`
    /// onto the embedded blocklist/allowlist, mirroring `src/gate.rs`'s own
    /// `policy_from_config` test helper but returning a full
    /// `config::Policy` — this module's `analyze_with_policy` needs one to
    /// read `ask_outcome` off, unlike `gate::analyze_with_policy`, which
    /// never reads it at all (this crate's whole reason for keeping the
    /// remap here rather than in `gate.rs`).
    fn policy_from_config(user_toml: &str) -> config::Policy {
        let blocklist = rules::Rules::embedded().unwrap();
        let allowlist = rules::Allowlist::embedded().unwrap();
        let user_config = rules::UserConfig::parse(user_toml).unwrap();
        let ask_outcome = user_config.ask_outcome();
        let (rules, allowlist) =
            rules::merge_user_config(blocklist, allowlist, user_config).unwrap();
        config::Policy {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path: None,
            ask_outcome,
        }
    }

    #[test]
    fn ask_outcome_deny_remaps_a_structural_ask_to_block() {
        // rule 4's except-target refinement: an unresolved `$VAR` in
        // argument position against `rm -rf` is a genuine structural Ask
        // with no rule match at all.
        let policy = policy_from_config(r#"ask_outcome = "deny""#);
        let verdict = analyze_with_policy("rm -rf $DIR", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert!(verdict.matched_rule().is_none());
        assert!(verdict.reason().unwrap().as_str().contains("ask_outcome"));
    }

    #[test]
    fn ask_outcome_default_leaves_a_structural_ask_as_ask() {
        let policy = policy_from_config("");
        let verdict = analyze_with_policy("rm -rf $DIR", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Ask);
    }

    #[test]
    fn ask_outcome_deny_remaps_an_embedded_ask_rule_to_block() {
        // The embedded blocklist's `tar-directory-root-or-home` rule
        // (decision = "ask").
        let policy = policy_from_config(r#"ask_outcome = "deny""#);
        let verdict = analyze_with_policy("tar -C / -f a.tar", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert!(verdict.matched_rule().is_none());
    }

    #[test]
    fn ask_outcome_deny_remaps_a_user_ask_rule_to_block() {
        let policy = policy_from_config(
            r#"
            ask_outcome = "deny"

            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
        "#,
        );
        let verdict = analyze_with_policy("gh pr view", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert!(verdict.matched_rule().is_none());
    }

    #[test]
    fn ask_outcome_deny_preserves_a_matched_rules_own_deny_message() {
        // A matched `[[ask]]` rule's own `deny_message` must survive the
        // remap untouched — the generic fallback guidance only applies
        // when the original Ask verdict carried none.
        let policy = policy_from_config(
            r#"
            ask_outcome = "deny"

            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
            deny_message = "use the gh MCP tool instead"
        "#,
        );
        let verdict = analyze_with_policy("gh pr view", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert_eq!(
            verdict.deny_message().map(DenyMessage::as_str),
            Some("use the gh MCP tool instead")
        );
    }

    #[test]
    fn ask_outcome_deny_leaves_a_real_block_rule_untouched() {
        let policy = policy_from_config(r#"ask_outcome = "deny""#);
        let verdict = analyze_with_policy("rm -rf /", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert_eq!(
            verdict.matched_rule().map(RuleId::as_str),
            Some("rm-recursive-force-dangerous-target")
        );
    }

    #[test]
    fn ask_outcome_deny_leaves_allow_untouched() {
        let policy = policy_from_config(r#"ask_outcome = "deny""#);
        let verdict = analyze_with_policy("echo hello", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Allow);
    }

    #[test]
    fn allowlist_downgrade_still_wins_over_the_ask_outcome_remap() {
        // `apply_allowlist_downgrade` runs inside `gate::analyze_with_policy`
        // itself, before this module's remap ever sees the verdict — an
        // `[[allow]]` entry that would have rescued a structural Ask to
        // Allow must still do so, `ask_outcome = "deny"` notwithstanding.
        let policy = policy_from_config(
            r#"
            ask_outcome = "deny"

            [[allow]]
            id = "user-allow-rm"
            reason = "trust me"
            command = "rm"
        "#,
        );
        let verdict = analyze_with_policy("rm -rf $HOME", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Allow);
    }

    #[test]
    fn ask_outcome_deny_does_not_disturb_fold_worst_tie_breaking() {
        // `gate::fold_worst` already resolves this compound line to
        // `Decision::Block` from the real user `[[deny]]` rule (a rule that
        // also declares its own `deny_message`) before this module's remap
        // ever runs (`Decision::Block > Decision::Ask`) — the remap only
        // ever touches a verdict that is STILL `Ask` by the time
        // `watchdog::bounded` returns, so the real rule's own id AND
        // deny_message must survive untouched, not the remap's generic
        // guidance text.
        let policy = policy_from_config(
            r#"
            ask_outcome = "deny"

            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"

            [[deny]]
            id = "user-deny-mytool-force"
            reason = "mytool --force is destructive"
            command = "mytool"
            required_flags = ["f|--force"]
            deny_message = "use --force-with-lease instead"
        "#,
        );
        let verdict = analyze_with_policy("gh pr view; mytool --force", &policy, &NoopSink);
        assert_eq!(verdict.decision(), Decision::Block);
        assert_eq!(
            verdict.matched_rule().map(RuleId::as_str),
            Some("user-deny-mytool-force")
        );
        assert_eq!(
            verdict.deny_message().map(DenyMessage::as_str),
            Some("use --force-with-lease instead")
        );
    }
}
