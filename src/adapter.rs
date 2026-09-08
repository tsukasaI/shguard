//! Claude Code PreToolUse hook adapter (issue #13, plan.md §1.2's "hook
//! adapter" contract) — the boundary between the Claude Code hook's
//! stdin→stdout JSON and [`crate::analyze`].
//!
//! This module owns every Claude-Code-specific field name (`tool_name`,
//! `tool_input.command`, `hookSpecificOutput`, …). The composition root
//! (`src/bin/shguard.rs`) calls only [`handle`]; nothing else in the crate
//! depends on this module, and this module never depends on anything in
//! `src/bin/`. A future Codex/Cursor adapter is a sibling module with its
//! own `handle`-shaped entry point, not a change here (plan.md's "dependencies
//! point inward").
//!
//! # Verified stdin/stdout schema
//!
//! Re-verified against code.claude.com/docs/en/hooks on 2026-09-07 (plan.md
//! §0.2's "adapter issue re-fetches the doc before implementation") —
//! `PreToolUse`'s valid `permissionDecision` values are still
//! `"allow"`/`"deny"`/`"ask"` as of this date, and `permission_mode`/
//! `agent_id`/`agent_type` (issue #468) are now read into
//! [`crate::HookContext`] for the decision log (see that type's docs):
//!
//! - **stdin**: a JSON object. `tool_name: string`; when `tool_name ==
//!   "Bash"`, `tool_input.command: string` holds the raw shell command
//!   line. `permission_mode: string` (one of `"default"`, `"plan"`,
//!   `"acceptEdits"`, `"auto"`, `"dontAsk"`, `"bypassPermissions"`, parsed
//!   into [`crate::PermissionMode`], with any other value preserved as
//!   `Unknown`), and `agent_id`/`agent_type: string` (present only inside a
//!   subagent call), may be present. A present, wrong-JSON-type
//!   `permission_mode`/`agent_type` is treated the same as absent, not a
//!   parse failure of the whole payload; `agent_id` differs — any present,
//!   non-`null` value (not only a string) counts as present, since issue
//!   #469's `subagent` `ask_outcome` override keys on that presence alone
//!   (see [`crate::HookContext`]). Other context fields (`session_id`,
//!   `cwd`, `hook_event_name`) may be present and are ignored here.
//! - **stdout**: exit 0, plus
//!   ```json
//!   {
//!     "hookSpecificOutput": {
//!       "hookEventName": "PreToolUse",
//!       "permissionDecision": "allow" | "deny" | "ask",
//!       "permissionDecisionReason": "…",
//!       "additionalContext": "…"
//!     }
//!   }
//!   ```
//!   `permissionDecision` maps directly from [`crate::verdict::Decision`]:
//!   `Allow` → `"allow"`, `Ask` → `"ask"`, `Block` → `"deny"`.
//!   `additionalContext` is omitted entirely (not emitted as `null`/`""`)
//!   unless the matched rule declared a `deny_message` (issue #99,
//!   `crate::verdict::Verdict::deny_message`) — it carries guidance for the
//!   *agent*, distinct from `permissionDecisionReason`'s "why" explanation.
//!
//! # Fail-closed posture
//!
//! - Malformed/missing stdin JSON, or a `tool_name == "Bash"` payload whose
//!   `tool_input.command` is missing or not a string → `ask` by default, a
//!   reason describing what could not be read attached — never a crash,
//!   never an undocumented silent allow. [`handle_with_policy`] instead
//!   emits `deny` for this same failure when its `policy`'s `ask_outcome`
//!   key resolves to `deny` for the failure's own context (issues
//!   #467/#469, see [`fail_closed_with`]); [`handle`] has no `policy` to
//!   read that key from, so it always stays `ask`.
//! - `tool_name != "Bash"` → `allow`: shguard only analyses shell commands
//!   run through the Bash tool, so a non-Bash tool call is out of scope by
//!   design — the hook defers to Claude Code's normal permission flow
//!   instead of asking on every non-shell tool call.

use serde::Deserialize;
use serde_json::Value;

use crate::verdict::Decision;
use crate::{HookContext, PermissionMode};

/// The subset of the Claude Code PreToolUse stdin payload shguard reads.
///
/// Every field but `tool_name` is kept as a raw [`Value`] rather than a
/// typed field: the hook schema is fast-moving (plan.md §0.2), so each is
/// pulled out, defensively, at the point of use (via `.as_str()`, which
/// yields `None` for a present-but-wrong-typed value, not a parse error)
/// instead of committing to a rigid shape that could start failing to
/// deserialize the *entire* payload on a spec change or a malformed value —
/// exactly the trap a typed `Option<String>` field falls into, since serde
/// still errors on a present value of the wrong type.
#[derive(Debug, Deserialize)]
struct HookInput {
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    permission_mode: Value,
    #[serde(default)]
    agent_id: Value,
    #[serde(default)]
    agent_type: Value,
}

/// The three `permissionDecision` values the hook contract defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionDecision {
    Allow,
    Deny,
    Ask,
}

impl PermissionDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        }
    }
}

impl From<Decision> for PermissionDecision {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Ask => Self::Ask,
            Decision::Block => Self::Deny,
        }
    }
}

/// `additional_context`, when present, is guidance for the *agent* that
/// issued the command (issue #99's `deny_message`) — a matched rule's own
/// actionable suggestion, distinct from `reason`'s "why" (see
/// [`crate::verdict::DenyMessage`]'s own docs). Emitted as
/// `hookSpecificOutput.additionalContext`, a field Claude Code's
/// `PreToolUse` hook contract shows to the agent alongside
/// `permissionDecisionReason` (this module's verified-schema doc).
fn output_json(
    decision: PermissionDecision,
    reason: &str,
    additional_context: Option<&str>,
) -> Value {
    let mut output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.as_str(),
            "permissionDecisionReason": reason,
        }
    });
    if let Some(context) = additional_context {
        output["hookSpecificOutput"]["additionalContext"] = Value::String(context.to_string());
    }
    output
}

/// The fail-closed `ask` output, for I/O failures the composition root
/// encounters before it even has stdin text to hand to [`handle`] (e.g. a
/// stdin read error). Never carries `additionalContext` — there is no
/// matched rule to have declared one.
#[must_use]
pub fn fail_closed(reason: &str) -> Value {
    output_json(PermissionDecision::Ask, reason, None)
}

/// The stricter fail-closed `deny` output (issue #440's `SHGUARD_STRICT_CONFIG`):
/// same shape as [`fail_closed`], used only for a config-load failure under
/// strict mode. See README's "Discovery" section for why this is opt-in
/// and scoped to config-load failure alone.
#[must_use]
pub fn fail_closed_deny(reason: &str) -> Value {
    output_json(PermissionDecision::Deny, reason, None)
}

/// Fail-closed output honoring a loaded [`crate::config::Policy`]'s
/// `ask_outcome` key resolved for the caller's context (issues #467/#469):
/// `Decision::Block` emits `deny`, anything else (`Decision::Ask`, the
/// default — `Decision::Allow` never reaches here) emits `ask`, same as
/// [`fail_closed`]. Used by every composition-root fail-closed path that
/// already has a `Policy` in hand when it hits a condition it cannot
/// evaluate a command through — malformed/oversized stdin, a missing or
/// non-string `command` field, a stdin read error — so those paths floor
/// the same way a structural `Ask` from [`crate::analyze_with_policy`]
/// itself would. Distinct from [`fail_closed_deny`]: that one is
/// `SHGUARD_STRICT_CONFIG`'s own opt-in, reachable only when config load
/// itself fails — before any `Policy` (and thus any `ask_outcome`) exists
/// to read.
#[must_use]
pub fn fail_closed_with(outcome: Decision, reason: &str) -> Value {
    let decision = if outcome == Decision::Block {
        PermissionDecision::Deny
    } else {
        PermissionDecision::Ask
    };
    output_json(decision, reason, None)
}

/// Extracts `agent_id` for [`HookContext`] from the stdin's raw JSON value,
/// treating any non-null value — not only a string — as "a subagent
/// context is present": the harness sends a string today, but a present,
/// non-string `agent_id` (a number, say) is still evidence a subagent
/// fired the hook, and issue #469's `subagent` `ask_outcome` override must
/// still apply then rather than silently treating it the same as an
/// absent field.
fn subagent_id(agent_id: &Value) -> Option<String> {
    if agent_id.is_null() {
        return None;
    }
    Some(
        agent_id
            .as_str()
            .map_or_else(|| agent_id.to_string(), str::to_string),
    )
}

/// Parses `stdin` and pulls out the Bash command to analyse plus its
/// [`HookContext`], if any — the stdin-JSON/tool-name/command-field
/// extraction shared by [`handle`] and [`handle_with_policy`] (via
/// [`respond`], which also picks which `analyze`-shaped function the
/// extracted command goes to, and — issues #467/#469 — which fail-closed
/// decision an extraction error here becomes).
///
/// `Ok(None)` means `tool_name != "Bash"` (out of scope by design, the
/// caller should emit an ordinary `allow`). `Err((reason, context))` is a
/// human-readable failure description — malformed JSON, or a `Bash`
/// payload whose `tool_input.command` is missing or not a string — left
/// for the caller to turn into a fail-closed output (issue #467; see
/// [`respond`]). `context` in the `Err` case is [`HookContext::none`] only
/// when the JSON itself failed to parse (there is nothing to read
/// `permission_mode`/`agent_id` off of yet); for the missing-`command`
/// case, whatever `permission_mode`/`agent_id`/`agent_type` the stdin JSON
/// carried — absent, present, or present but not the expected type, same
/// as [`HookInput`]'s own `#[serde(default)]` posture — was already
/// resolved into the real `context` by that point, so issue #469's
/// per-mode `ask_outcome` table resolves against it rather than
/// discarding it as if it were unreadable.
fn extract_bash_command(
    stdin: &str,
) -> Result<Option<(String, HookContext)>, (String, HookContext)> {
    let input: HookInput = serde_json::from_str(stdin).map_err(|err| {
        (
            format!("shguard: could not parse PreToolUse stdin as JSON: {err}"),
            HookContext::none(),
        )
    })?;

    if input.tool_name != "Bash" {
        return Ok(None);
    }

    let context = HookContext::new(
        input.permission_mode.as_str().map(PermissionMode::parse),
        subagent_id(&input.agent_id),
        input.agent_type.as_str().map(str::to_string),
    );

    match input.tool_input.get("command").and_then(Value::as_str) {
        Some(command) => Ok(Some((command.to_string(), context))),
        None => Err((
            "shguard: Bash tool_input is missing a string \"command\" field".to_string(),
            context,
        )),
    }
}

/// Best-effort peek at the Bash command and [`HookContext`] a stdin payload
/// carries, without making any decision (issue #459). Folds both of
/// [`extract_bash_command`]'s non-analyzable outcomes — `tool_name !=
/// "Bash"` and a malformed/incomplete payload — to `None`: both are cases
/// [`respond`] itself short-circuits to `allow`/a fail-closed decision
/// without ever calling into `analyze`, so there is no analysis pipeline
/// that could hang and nothing worth attributing a later trip to.
///
/// The composition root (`src/bin/shguard.rs`) calls this once, immediately
/// after reading stdin and *before* [`handle_with_policy`]'s own call to
/// `analyze_with_policy`, so its outer watchdog has a command and context in
/// hand for the decision log even if that analysis call itself never
/// returns — [`handle_with_policy`] performs the authoritative extraction
/// and decision-making independently; this is a read-only duplicate for
/// logging purposes alone, never itself part of the decision.
#[must_use]
pub fn peek_bash_command(stdin: &str) -> Option<(String, HookContext)> {
    extract_bash_command(stdin).ok().flatten()
}

/// Builds the `hookSpecificOutput` JSON for one stdin payload, given
/// `analyze` (either [`crate::analyze`] or a closure over
/// [`crate::analyze_with_policy`] and a policy) as the decision source.
/// Never panics: every error path (malformed JSON, missing fields, wrong
/// field types) folds to a fail-closed decision with a descriptive reason —
/// the same "single fold point, never crash, never silently allow" posture
/// `crate::analyze` documents for its own internal failure modes.
///
/// `ask_outcome` (issues #467/#469) governs which fail-closed decision
/// these adapter-level failures emit: [`handle`] always resolves to
/// `Decision::Ask` (it has no `Policy`, so no key to read), while
/// [`handle_with_policy`] resolves its `policy`'s own `ask_outcome` table
/// against whatever [`HookContext`] the failure carries (see
/// [`extract_bash_command`]'s own docs for when that is a real,
/// stdin-derived context versus [`HookContext::none`]) — the same key
/// [`crate::analyze_with_policy`] floors every terminal `Ask` verdict
/// through, applied here too so a malformed/oversized stdin payload floors
/// exactly like a structural `Ask` would.
fn respond(
    stdin: &str,
    ask_outcome: impl Fn(&HookContext) -> crate::verdict::Decision,
    analyze: impl FnOnce(&str, &HookContext) -> crate::verdict::Verdict,
) -> Value {
    let (command, context) = match extract_bash_command(stdin) {
        Ok(Some(command_and_context)) => command_and_context,
        Ok(None) => {
            return output_json(
                PermissionDecision::Allow,
                "shguard only analyses commands run through the Bash tool",
                None,
            );
        }
        Err((reason, context)) => return fail_closed_with(ask_outcome(&context), &reason),
    };

    let verdict = analyze(&command, &context);
    let decision = PermissionDecision::from(verdict.decision());
    let reason = verdict
        .reason()
        .map_or("shguard: command cleared all checks", |r| r.as_str());
    let additional_context = verdict
        .deny_message()
        .map(crate::verdict::DenyMessage::as_str);

    output_json(decision, reason, additional_context)
}

/// Reads and analyses one Claude Code PreToolUse stdin payload against the
/// embedded blocklist/allowlist only, returning the `hookSpecificOutput`
/// JSON the composition root writes to stdout.
#[must_use]
pub fn handle(stdin: &str) -> Value {
    respond(
        stdin,
        |_context| Decision::Ask,
        |command, _context| crate::analyze(command),
    )
}

/// Config-aware sibling of [`handle`]: same stdin/stdout contract, but
/// `policy` (loaded once at the composition root via
/// [`crate::config::Policy::load`]) supplies the rules and allowlist
/// instead of the embedded defaults alone. `sink` is the composition
/// root's own [`crate::DecisionLogSink`] (see that trait's docs).
#[must_use]
pub fn handle_with_policy(
    stdin: &str,
    policy: &crate::config::Policy,
    sink: &dyn crate::DecisionLogSink,
) -> Value {
    respond(
        stdin,
        |context| policy.ask_outcome(context),
        |command, context| crate::analyze_with_policy(command, policy, context, sink),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn permission_decision(output: &Value) -> &str {
        output["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap()
    }

    fn permission_reason(output: &Value) -> &str {
        output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
    }

    #[test]
    fn bash_block_command_denies_with_reason() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "deny");
        assert!(!permission_reason(&output).is_empty());
    }

    #[test]
    fn bash_ask_command_asks() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn bash_allow_command_allows() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "allow");
    }

    #[test]
    fn malformed_json_fails_closed_to_ask() {
        let output = handle("not json");
        assert_eq!(permission_decision(&output), "ask");
        assert!(!permission_reason(&output).is_empty());
    }

    #[test]
    fn empty_stdin_fails_closed_to_ask() {
        let output = handle("");
        assert_eq!(permission_decision(&output), "ask");
    }

    /// issue #138: `tool_input.command` is a JSON string, and `\u0000` is
    /// legal JSON that decodes to a raw NUL byte — never routed through
    /// `decode_ansi_c` at all, so this is a distinct entry point from the
    /// `$'\0'`-escape case `normalize.rs`'s own tests cover.
    #[test]
    fn bash_command_with_raw_json_nul_asks() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm\u0000MID -rf /"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn non_bash_tool_allows() {
        let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "allow");
    }

    #[test]
    fn bash_missing_command_field_fails_closed_to_ask() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn bash_non_string_command_fails_closed_to_ask() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":42}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
    }

    // ==== handle_with_policy ====

    fn embedded_only_policy() -> crate::config::Policy {
        crate::config::Policy {
            rules: std::sync::Arc::new(crate::rules::Rules::embedded().unwrap()),
            allowlist: std::sync::Arc::new(crate::rules::Allowlist::embedded().unwrap()),
            decision_log_path: None,
            ask_outcome: crate::rules::AskOutcome::default(),
        }
    }

    #[test]
    fn handle_with_policy_embedded_only_matches_handle() {
        let policy = embedded_only_policy();
        for stdin in [
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"echo hi"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"$(which python3)"}}"#,
        ] {
            assert_eq!(
                permission_decision(&handle(stdin)),
                permission_decision(&handle_with_policy(stdin, &policy, &crate::FileDecisionLog)),
                "{stdin:?}"
            );
        }
    }

    #[test]
    fn handle_with_policy_ask_rule_from_merged_config_asks() {
        let blocklist = crate::rules::Rules::embedded().unwrap();
        let allowlist = crate::rules::Allowlist::embedded().unwrap();
        let user_config = crate::rules::UserConfig::parse(
            r#"
            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
        "#,
        )
        .unwrap();
        let (rules, allowlist) =
            crate::rules::merge_user_config(blocklist, allowlist, user_config).unwrap();
        let policy = crate::config::Policy {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path: None,
            ask_outcome: crate::rules::AskOutcome::default(),
        };

        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"gh pr view"}}"#;
        let output = handle_with_policy(stdin, &policy, &crate::FileDecisionLog);
        assert_eq!(permission_decision(&output), "ask");
    }

    #[test]
    fn handle_with_policy_malformed_json_fails_closed_to_ask() {
        let policy = embedded_only_policy();
        let output = handle_with_policy("not json", &policy, &crate::FileDecisionLog);
        assert_eq!(permission_decision(&output), "ask");
        assert!(!permission_reason(&output).is_empty());
    }

    #[test]
    fn handle_with_policy_non_bash_tool_allows() {
        let policy = embedded_only_policy();
        let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let output = handle_with_policy(stdin, &policy, &crate::FileDecisionLog);
        assert_eq!(permission_decision(&output), "allow");
    }

    // ==== issue #99: additionalContext ====

    #[test]
    fn handle_with_policy_deny_message_surfaces_as_additional_context() {
        let blocklist = crate::rules::Rules::embedded().unwrap();
        let allowlist = crate::rules::Allowlist::embedded().unwrap();
        // A command name with no embedded blocklist rule of its own -- the
        // embedded blocklist's own git-push-force rule would otherwise
        // also match `git push --force` (both Block, so match_command's
        // worst-wins tie-break keeps whichever is declared first --
        // issue #399) and shadow this user rule's deny_message before
        // it's ever reached.
        let user_config = crate::rules::UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-mytool-force"
            reason = "mytool --force is destructive"
            command = "mytool"
            required_flags = ["f|--force"]
            deny_message = "use --force-with-lease instead"
        "#,
        )
        .unwrap();
        let (rules, allowlist) =
            crate::rules::merge_user_config(blocklist, allowlist, user_config).unwrap();
        let policy = crate::config::Policy {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path: None,
            ask_outcome: crate::rules::AskOutcome::default(),
        };

        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"mytool --force"}}"#;
        let output = handle_with_policy(stdin, &policy, &crate::FileDecisionLog);
        assert_eq!(permission_decision(&output), "deny");
        assert_eq!(
            output["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap(),
            "use --force-with-lease instead"
        );
        // permissionDecisionReason is unaffected — the two fields stay distinct.
        assert!(permission_reason(&output).contains("user-deny-mytool-force"));
        assert_ne!(permission_reason(&output), "use --force-with-lease instead");
    }

    /// `fold_worst`'s documented tie contract: the FIRST-encountered simple
    /// command's verdict wins a same-decision tie outright, including its
    /// `deny_message` (or lack of one) -- it never borrows the other side's
    /// message. A compound line with TWO different `[[deny]]`-matched
    /// Blocks tied at the same decision must resolve to the first rule's
    /// own reason and its own (absent) deny_message, never a mix of one
    /// rule's message with the other's `matched_rule_id`.
    #[test]
    fn fold_worst_tie_keeps_first_matched_rules_own_reason_and_message() {
        let blocklist = crate::rules::Rules::embedded().unwrap();
        let allowlist = crate::rules::Allowlist::embedded().unwrap();
        let user_config = crate::rules::UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-mytool-force"
            reason = "mytool --force is destructive"
            command = "mytool"
            required_flags = ["f|--force"]
            deny_message = "use --force-with-lease instead"
        "#,
        )
        .unwrap();
        let (rules, allowlist) =
            crate::rules::merge_user_config(blocklist, allowlist, user_config).unwrap();
        let policy = crate::config::Policy {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path: None,
            ask_outcome: crate::rules::AskOutcome::default(),
        };

        // `rm -rf /` (embedded rule, first simple command, no deny_message
        // of its own) and `mytool --force` (user rule, second simple
        // command, its own deny_message) are both Block -- a decision tie
        // must resolve to the FIRST simple command's own reason and its
        // own (absent) deny_message, never a mix of the two rules.
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf / ; mytool --force"}}"#;
        let output = handle_with_policy(stdin, &policy, &crate::FileDecisionLog);
        assert_eq!(permission_decision(&output), "deny");
        assert!(
            permission_reason(&output).contains("rm-recursive-force-dangerous-target"),
            "expected the first-encountered rule's own reason to win the tie, got: {}",
            permission_reason(&output)
        );
        assert_eq!(
            output["hookSpecificOutput"]["additionalContext"].as_str(),
            None,
            "the first rule's own (absent) deny_message must not be replaced by the second \
             rule's message"
        );
    }

    #[test]
    fn bash_block_command_without_deny_message_omits_additional_context_entirely() {
        // A matched rule with no deny_message must not emit
        // additionalContext at all -- not as null, not as an empty string.
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "deny");
        assert!(
            output["hookSpecificOutput"]
                .get("additionalContext")
                .is_none()
        );
    }

    // ==== issue #471: category-specific deny_message on one representative
    // command per row of the issue's guidance table, using the
    // embedded-only `handle()` path (no user config involved) so each case
    // exercises the plain structural `Ask` -- the majority path a caller
    // with no `ask_outcome` configured actually sees. NOT a claim that
    // every possible structural Ask in every category always carries a
    // message: `apply_expansion_floor`'s heredoc-floor site in particular
    // is order-dependent -- `raise_expansion_floor` keeps the FIRST reason
    // raised at a tied Ask decision, so a sibling floor (e.g. a
    // substitution in an assignment value or a redirection target) raised
    // before the non-shell-interpreter heredoc floor wins the reason text
    // and this category's deny_message never attaches, even though
    // `python3 - <<EOF` alone (no sibling floor)
    // does get it (see the test below). Disclosed rather than fixed here:
    // closing it needs the same wider `Option<DenyMessage>` threading
    // through `raise_expansion_floor`'s ~18 shared call sites that
    // `Verdict::with_deny_message`'s own "Known remaining gaps" doc
    // already declines for the same reason. ====

    fn additional_context(output: &Value) -> &str {
        output["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
    }

    #[test]
    fn bare_var_command_position_gets_expand_the_variable_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$UNSETVAR foo"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Expand the variable yourself and re-issue the command with the literal path or \
             binary name."
        );
    }

    #[test]
    fn inline_interpreter_code_gets_write_to_a_file_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"python3 -c 'print(1)'"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Write the program to a file and run that file instead (e.g. `python3 file.py`, \
             `awk -f prog.awk`) — inline interpreter code is never inspected."
        );
    }

    /// Fable-review follow-up to #471: `python3 - <<EOF ... EOF` (issue
    /// #471's own row-2 example, the largest single category) reaches the
    /// gate through the heredoc-as-stdin floor (issue #424), not the
    /// `-c`/`-e` inline-code site above -- it must get the same guidance,
    /// not a message-less generic Ask.
    #[test]
    fn heredoc_fed_to_non_shell_interpreter_gets_write_to_a_file_guidance() {
        let stdin =
            r#"{"tool_name":"Bash","tool_input":{"command":"python3 - <<EOF\nimport os\nEOF"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Write the program to a file and run that file instead (e.g. `python3 file.py`, \
             `awk -f prog.awk`) — inline interpreter code is never inspected."
        );
    }

    #[test]
    fn awk_inline_script_gets_write_to_a_file_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"awk '{print}' file"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Write the program to a file and run that file instead (e.g. `python3 file.py`, \
             `awk -f prog.awk`) — inline interpreter code is never inspected."
        );
    }

    #[test]
    fn parser_unsupported_construct_is_named_in_the_guidance() {
        // `${arr[@]}` -- an array-indexed parameter expansion --
        // `src/parser.rs`'s `convert_parameter_expansion` rejects with
        // `ParseError::Unsupported`, whose own `construct` description
        // names the rejected shape in human terms (issue #471's "name the
        // construct"), not a raw Debug dump of brush's internal
        // enum/struct fields.
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo ${arr[@]}"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "shguard cannot statically analyze this construct (parameter expansion form: \
             indirect or array-indexed parameter expansion (${!x}/${arr[i]}/${arr[@]})); use \
             its literal form, or split the command across separate lines so each piece is \
             inspectable."
        );
    }

    #[test]
    fn arithmetic_expansion_is_named_in_the_guidance() {
        // `$((...))` parses successfully (unlike `${arr[@]}`) but normalises
        // to `Unresolvable(ArithmeticExpansion)` -- a different code path
        // (`crate::gate`'s opaque-kind floor, not a `ParseError`) that must
        // still name the construct in human terms, not `ArithmeticExpansion`
        // (the bare enum variant name).
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo $((1+1))"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "shguard cannot statically analyze this construct (arithmetic expansion \
             ($((...)))); use its literal form, or split the command across separate lines so \
             each piece is inspectable."
        );
    }

    #[test]
    fn command_substitution_command_position_gets_run_first_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"$(echo ls)"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Run the substitution first, then call the resulting binary literally."
        );
    }

    #[test]
    fn unresolvable_target_gets_resolve_the_target_guidance() {
        // `rm -rf $(echo /)` matches the embedded `rm-recursive-force-\
        // dangerous-target` rule's command+flags, but its target is an
        // argument-position substitution -- the except-target floor
        // (`crate::gate::fold_floors`), not a definite rule match, and that
        // rule declares no `deny_message` of its own, so this exercises the
        // structural fallback specifically.
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf $(echo /)"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Resolve the target literally so the rule can check it."
        );
    }

    #[test]
    fn pipe_to_interpreter_gets_run_the_file_directly_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"cat x.sh | bash"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Run the file directly (e.g. `bash file.sh`) instead of piping it in, so the argv \
             is inspectable."
        );
    }

    #[test]
    fn ifs_derived_word_gets_rewrite_without_ifs_guidance() {
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"echo${IFS}hi"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Rewrite the command without `$IFS`; there is no benign interactive use for it."
        );
    }

    // ==== issue #202's regression class, applied to issue #471's new
    // category-specific messages: the message must survive a recursion/
    // re-wrap boundary, not be lost or silently replaced by a generic one ====

    #[test]
    fn bare_var_message_survives_a_bash_dash_c_rewrap() {
        // `recurse_shell_string` (rule 6a's own recursion core) maps the
        // recursed script's inner `Verdict` to an outer one carrying the
        // outer `bash -c ...` argv -- the inner `Ask`'s deny_message (here,
        // category 1's bare-`$VAR` guidance) must still be the one that
        // reaches the top-level verdict, not a generic "bash -c recurses"
        // fallback.
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"bash -c '$UNSETVAR foo'"}}"#;
        let output = handle(stdin);
        assert_eq!(permission_decision(&output), "ask");
        assert_eq!(
            additional_context(&output),
            "Expand the variable yourself and re-issue the command with the literal path or \
             binary name."
        );
        // The outer reason names the recursion, distinct from the inner
        // deny_message -- confirms this is the re-wrapped outer verdict,
        // not an accidental pass-through of the inner one's own reason.
        assert!(permission_reason(&output).contains("recurses through the full pipeline"));
    }

    // Note (issue #471 fable review): a category message does NOT currently
    // survive `evaluate_argument_substitutions`' own recursion path (e.g.
    // `echo $(python3 -c "x")` still resolves Ask with `deny_message: None`)
    // -- that function returns a bare `Option<Decision>`, not the inner
    // verdict's message, a pre-existing gap `Verdict::with_deny_message`'s
    // own "Known remaining gaps" doc already discloses. Closing it would
    // mean widening that function's return type and its callers; left as a
    // documented follow-up rather than expanding this issue's scope.
}
