# RFC #105: Codex adapter design

Design for issue #105: scoping a second hook adapter target, OpenAI's
Codex CLI, alongside the existing Claude Code adapter (`src/adapter.rs`).
Design only -- no implementation in this document. Every claim below is
sourced against a fresh clone of `openai/codex` (source paths and PR
numbers cited inline) rather than carried forward from the planning
discussion that preceded this issue, per the issue's own explicit
caution. A follow-up implementation issue (`shguard codex` subcommand)
should be filed only after this RFC is agreed.

## Decision: hook on `PreToolUse`, not `PermissionRequest` alone

shguard's own design goal is "see every command" (module docs,
`src/adapter.rs`). Two Codex hook events are candidates, and they behave
differently under Codex's own bypass-equivalent configuration:

- **`PermissionRequest` is conditional.** It only fires from inside
  `Session::request_approval` (`codex-rs/core/src/tools/approvals.rs`),
  which is itself only reached when Codex's own approval flow has
  already decided a prompt is needed
  (`ExecApprovalRequirement::NeedsApproval`,
  `codex-rs/core/src/tools/orchestrator.rs`). Under `approval_policy =
  "never"`, `codex-rs/core/src/tools/sandboxing.rs` resolves this to
  `ExecApprovalRequirement::Skip` -- `request_approval` (and therefore
  `PermissionRequest`) never runs at all for shell commands.
- **`PreToolUse` is unconditional.** Dispatch
  (`codex-rs/core/src/tools/registry.rs`) is gated only on
  `tool.pre_tool_use_payload(&invocation)` returning `Some(..)`, with no
  reference anywhere in that path to `approval_policy`, `sandbox_mode`,
  or the approval/guardian machinery. Bash/shell tools fall through to
  the default implementation, which always returns `Some` for any
  function-shaped tool call.
- **Verified under Codex's own bypass-equivalent configuration**
  (`approval_policy = "never"` combined with `sandbox_mode =
  "danger-full-access"`, both real, named config values):
  `PermissionRequest` is skipped entirely; `PreToolUse` still fires.

This is the direct Codex-side analog of the Claude Code
`bypassPermissions`-mode question the sibling permission-mode matrix
(issue #91, `docs/threat-model.md`) already answers for Claude Code:
attach to whichever event survives the host's own most-permissive
configuration. For Codex, that is `PreToolUse`. `PermissionRequest`
remains available as a secondary, richer interception point for the
interactive-approval path specifically, but is never sufficient on its
own and is out of scope for the adapter's REQUIRED coverage.

## Payload shape

`PreToolUse`'s JSON schema
(`codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json`)
requires: `cwd`, `hook_event_name`, `model`, `permission_mode`,
`session_id`, `tool_input`, `tool_name`, `tool_use_id`,
`transcript_path`, `turn_id`. For a shell command, `tool_name` is the
literal string `"Bash"` (`HookToolName::bash()`,
`codex-rs/core/src/tools/hook_names.rs`) and `tool_input.command` holds
the command string -- structurally identical to Claude Code's own
`tool_name: "Bash"` / `tool_input.command` shape shguard's adapter
already parses today. `apply_patch` calls use `tool_name:
"apply_patch"` with the same `tool_input.command`-shaped payload
(confirmed via `apply_patch_payload_command`,
`codex-rs/core/src/tools/handlers/apply_patch.rs`) rather than a
`{file_path, diff}` shape -- out of scope for this adapter (shguard
analyzes shell commands, not patch bodies), but noted since it means a
future extension to cover `apply_patch` would reuse the exact same
command-string extraction path, not a new one.

## Output contract, and where it diverges from Claude Code's

The envelope is structurally close to Claude Code's own
`hookSpecificOutput.permissionDecision` contract
(`pre-tool-use.command.output.schema.json`): `hookSpecificOutput: {
hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason,
... }`, plus a separate exit-code-2-with-stderr fallback that also
blocks (`codex-rs/hooks/src/events/pre_tool_use.rs`). Two divergences
are load-bearing for the adapter's own implementation, not just
academic:

1. **`permissionDecision: "ask"` is schema-valid but rejected at
   runtime, and fails OPEN, not closed.**
   `codex-rs/hooks/src/engine/output_parser.rs` explicitly treats `Ask`
   as `"PreToolUse hook returned unsupported permissionDecision:ask"`
   -- an `invalid_reason`, which sets the hook run's status to `Failed`
   but does NOT set `should_block`. Per
   `codex-rs/hooks/src/events/pre_tool_use.rs`, a hook run with
   `should_block == false` resolves to `PreToolUseHookResult::Continue`
   -- **the command proceeds**. Codex's hook contract has no functional
   three-way decision the way Claude Code's does; it is binary
   allow/deny only.

   **Decision for the adapter: map shguard's `Ask` to Codex's `deny`,
   with `permissionDecisionReason` explaining that Codex's own hook
   contract has no equivalent to "ask a human via this channel" and
   suggesting the command be re-run once the user has reviewed it (or
   confirmed via Codex's own approval flow, `codex-rs/core/src/tools/
   approvals.rs`, if that path is separately reachable).** This is a
   real, disclosed degradation of shguard's own precision on Codex
   specifically: a command that would surface as a human-confirmable
   Ask on Claude Code becomes a hard deny on Codex, since attempting the
   literal translation (`ask`) silently fails open instead.

2. **A `deny` with no reason silently fails open too.**
   `codex-rs/core/src/hook_runtime.rs`: if `should_block == true` but
   `block_reason` is `None`, the code falls through to
   `PreToolUseHookResult::Continue` -- a block with no reason is treated
   as "don't block", not as a maximally-strict default. **Implementation
   constraint: the adapter must always emit a non-empty
   `permissionDecisionReason` on every `deny` it produces** (shguard's
   own `Verdict::reason()` is already documented as always populated
   for a non-Allow decision, so this should hold naturally, but it needs
   an explicit test pinning it, since on Codex specifically an empty
   reason is a silent fail-open, not merely a missing nicety).

## `with_escalated_permissions` vs shguard's `escalation_floor`: not a real analog

The literal identifier `with_escalated_permissions` does not exist
anywhere in current `codex-rs` (confirmed via a full-repo search) --
this was carried forward from the planning discussion as an assumed
Claude-Code-specific field and should be treated as **falsified** for
Codex. The nearest Codex concepts are `SandboxPermissions::
RequireEscalated` (a tool-input-level flag meaning "this call wants to
run without the sandbox", driving Codex's OWN approval-requirement
escalation) and a separate `EscalationPermissions` concept in the
`shell-escalation` crate (OS-level sudo-style privilege escalation for
the sandboxed exec helper) -- neither is a hook-contract decision field,
and neither interacts with what a `PreToolUse` hook itself returns.
**Conclusion: no double-semantics conflict exists, because there is
nothing on the Codex side for shguard's own `escalation_floor` (a
purely shguard-side config concept that raises the floor of what a gate
decision can resolve to) to conflict with.** `escalation_floor` applies
exactly as it does today, entirely inside `analyze_with_policy`, before
the adapter ever translates the resulting `Decision` into Codex's
allow/deny vocabulary -- the only adapter-level interaction is the
`Ask`-has-no-Codex-equivalent mapping already covered above.

## Adapter shape

Mirrors `src/adapter.rs`'s existing structure and its own "every
Claude-Code-specific field name lives in this module" convention (per
its module doc) -- a sibling module, not a change to the shared
`analyze()`/`analyze_with_policy()` core:

- **New module `src/codex_adapter.rs`**, structured identically to
  `src/adapter.rs`: a `HookInput`-equivalent struct for Codex's
  `PreToolUse` payload shape (`tool_name`, `tool_input`, plus whatever
  of `session_id`/`cwd`/`permission_mode` a later session-state RFC
  (issue #104) ends up needing -- ignored for now, mirroring how
  `src/adapter.rs` already documents ignoring context fields it doesn't
  currently use), an `extract_bash_command`-equivalent extraction
  function scoped to `tool_name == "Bash"`, and a `handle`/
  `handle_with_policy` pair with the identical signatures
  `src/adapter.rs`'s own pair has.
- **Decision-to-output mapping is the one place this adapter's logic
  genuinely differs from Claude Code's**: `Decision::Allow ->
  "allow"`, `Decision::Block -> "deny"` (same as Claude Code), but
  `Decision::Ask -> "deny"` (NOT `"ask"`, per the fail-open finding
  above) with a Codex-specific reason string explaining the
  degradation. This mapping function is the one piece of this adapter
  that should carry a code comment citing this RFC and the specific
  Codex source finding it's working around, so a future Codex hooks
  update that adds real `ask` support is easy to find and revisit.
  Every `deny` output (including the `Ask`-mapped ones) always
  populates `permissionDecisionReason` from `Verdict::reason()`'s own
  non-empty-on-non-Allow guarantee -- this exact property needs a
  dedicated unit test given the fail-open consequence of getting it
  wrong on Codex specifically.
- **`src/bin/shguard.rs`**: a new `codex` subcommand (matching the
  existing `check`/`init` dispatch pattern) that reads Codex's own
  `PreToolUse` stdin payload and calls `codex_adapter::handle_with_policy`
  instead of `adapter::handle_with_policy` -- or, if Codex's hook
  invocation contract turns out to need a different binary entry point
  entirely (unverified in this RFC; the implementation issue should
  confirm how Codex's own hook configuration invokes an external
  command), a decision on binary/subcommand shape belongs to that
  implementation issue, not this design doc.
- **Test coverage**: extends `tests/adapter_smoke.rs`'s existing
  `TARGETS` table (issue #106) with one more `Target` entry for
  `codex`, its own payload-builder and decision-extractor functions --
  exactly the extension path issue #106 was designed to support,
  confirming that design held up under its first real second-target
  test.

## Scope explicitly deferred, not silently dropped

- **MCP tool calls** use a different, non-Bash `tool_name` shape
  (`codex-rs/core/src/tools/mcp.rs`) -- out of scope for this adapter;
  shguard analyzes shell commands, not arbitrary MCP tool invocations.
- **`apply_patch` coverage** -- structurally reachable via the same
  command-string extraction path (see "Payload shape" above), but out
  of scope for the initial Codex adapter; a natural follow-up once the
  Bash path is stable, not a blocker for this RFC's own scope.
- **The originally-planned "hooks default off" warning** -- confirmed
  unnecessary. `Feature::CodexHooks` is Stable with `default_enabled:
  true` (`codex-rs/features/src/lib.rs`), contradicting the planning
  discussion's original premise; no warning needed, and none of this
  RFC's other findings surfaced a different real footgun around the
  `hooks` config key worth warning about instead.
