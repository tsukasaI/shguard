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
- **Checked under Codex's own bypass-equivalent configuration**
  (`approval_policy = "never"` combined with `sandbox_mode =
  "danger-full-access"`, both real, named config values) -- by reading
  source, not by an empirical, running reproduction: `PermissionRequest`
  is skipped entirely (traced statically through
  `codex-rs/core/src/tools/sandboxing.rs`'s `approval_policy = "never"`
  arm); `PreToolUse`'s dispatch path has no reference to either config
  value at all. This is source-analysis confidence, not the empirical,
  logged reproduction the issue's own open question asked for --
  running Codex end-to-end under this exact config combination and
  confirming which hooks actually fire is deferred to the implementation
  issue's own test plan, same as the other source-only findings this
  RFC discloses (the `session_id` field name, the `cwd` payload
  semantics).

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
   `permissionDecisionReason` on every `deny` it produces.** `Verdict::
   reason()` (`src/verdict.rs`) guarantees `Some` for every non-Allow
   decision by construction; STRING non-emptiness isn't enforced by the
   `Reason` type itself, but holds today via config load-time validation
   (`reason must not be empty`) plus every structural reason in
   `gate.rs` being a non-empty literal format string. The dedicated
   adapter test this RFC calls for must assert the emitted
   `permissionDecisionReason` string is actually non-empty, not merely
   that a reason is present -- on Codex specifically, an empty string
   is indistinguishable from no reason at all and silently fails open.

3. **This same fail-open trap applies to every FAIL-CLOSED path the
   adapter reuses from `src/adapter.rs`/`src/bin/shguard.rs`, not only
   to translated `Verdict`s.** `adapter::fail_closed()` (malformed
   stdin, a missing/non-string `tool_input.command`) emits
   `PermissionDecision::Ask` directly -- it never goes through a
   `Decision` value at all, so the `Ask -> deny` mapping above does NOT
   cover it. The composition root
   (`src/bin/shguard.rs`) also calls this same `fail_closed()` on a
   stdin read error, an evaluation-watchdog timeout, and a memory-budget
   trip. A Codex adapter mirroring `src/adapter.rs`'s structure would
   therefore emit `"ask"` on every one of these error paths too --
   exactly the value Codex's own parser rejects and fails open on. These
   are precisely the adversarial/degraded-input cases a guard tool must
   fail CLOSED on, so this is not a corner case to patch later:
   **the Codex adapter's own `fail_closed`-equivalent, and every
   composition-root error path the `codex` subcommand reuses, must emit
   `deny` with a non-empty reason, never `ask`, from the start.** The
   `Ask -> deny` mapping and this fail-closed-path requirement are
   therefore best understood as one combined constraint on the whole
   adapter ("this adapter never emits `permissionDecision: "ask"`
   under any circumstance"), not two separate concerns.

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
purely shguard-side config concept that raises the floor specifically
for escalation-vector command chains -- `sudo`/`doas`/`su`/`pkexec`/
`run0` -- not a blanket floor over every decision) to conflict with.**
`escalation_floor` applies exactly as it does today, entirely inside
`analyze_with_policy`, before the adapter ever translates the resulting
`Decision` into Codex's allow/deny vocabulary -- the only adapter-level
interaction is the `Ask`-has-no-Codex-equivalent mapping already covered
above. One concrete, user-visible consequence worth stating plainly:
with the default `escalation_floor = Ask`, every bare `sudo
whoami`-class command becomes a hard `deny` on Codex (via the `Ask ->
deny` mapping), not a human-confirmable prompt the way it is on Claude
Code -- the single most visible effect of this adapter's precision
degradation in ordinary use, not just an edge case.

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
- **Decision-to-output mapping and fail-closed posture are the two
  places this adapter's logic genuinely differs from Claude Code's**:
  `Decision::Allow -> "allow"`, `Decision::Block -> "deny"` (same as
  Claude Code), but `Decision::Ask -> "deny"` (NOT `"ask"`, per the
  fail-open finding above) with a Codex-specific reason string
  explaining the degradation -- AND this adapter's own `fail_closed`
  equivalent (and every composition-root error path it reuses) must
  likewise emit `deny`, never `ask`, per the combined constraint above.
  Both pieces should carry a code comment citing this RFC and the
  specific Codex source finding they work around, so a future Codex
  hooks update that adds real `ask` support is easy to find and revisit.
  Every `deny` output (including the `Ask`-mapped and fail-closed ones)
  must have its `permissionDecisionReason` string asserted non-empty by
  a dedicated unit test, not merely assumed from `Verdict::reason()`'s
  own `Some`-for-non-Allow guarantee -- see the output-contract section
  above for exactly why string emptiness, not mere presence, is the
  property that matters on Codex.
- **What an out-of-scope tool call (`apply_patch`, an MCP tool) gets as
  its OWN `PreToolUse` output is a decision this RFC must make, not
  leave implicit.** `src/adapter.rs`'s own Claude Code adapter emits an
  explicit `"allow"` for any non-Bash tool, which is safe there because
  Claude Code's own hook registration is matcher-scoped to Bash calls
  only. Codex's `PreToolUse` fires for `apply_patch` and MCP tools too
  (see "Payload shape" above), and whether Codex's own hook
  registration can be similarly scoped is unverified in this RFC.
  Mirroring the explicit-`"allow"` behavior unconditionally risks
  auto-approving a tool call Codex's own approval flow would otherwise
  have prompted for -- a security downgrade relative to running no hook
  at all. **Decision: for any `tool_name` other than `"Bash"`, the
  Codex adapter emits NO decision at all (a quiet, no-op exit) rather
  than an explicit `"allow"`, so Codex falls back to whatever its own
  normal approval path would have done absent this hook** -- the
  implementation issue must first confirm this "no decision" shape is
  actually representable in Codex's own hook output contract (an empty
  `hookSpecificOutput`, or simply not registering for those tool names
  if registration can be scoped), and adjust this decision if it isn't.
- **`src/bin/shguard.rs`**: a new `codex` subcommand (matching the
  existing `check`/`--check-config` dispatch pattern -- there is no
  `init` subcommand in the current dispatch to match against) that
  reads Codex's own `PreToolUse` stdin payload and calls
  `codex_adapter::handle_with_policy` instead of
  `adapter::handle_with_policy`. Note this is an asymmetry with Claude
  Code hook mode, which is the CURRENT no-argument default rather than
  a named subcommand -- the implementation issue should decide whether
  `codex` becomes a second named mode alongside that default, or
  whether the binary needs to detect which host invoked it some other
  way. Separately, if Codex's hook invocation contract turns out to
  need a different binary entry point entirely (unverified in this
  RFC; the implementation issue should confirm how Codex's own hook
  configuration invokes an external command), that decision on
  binary/subcommand shape belongs to that implementation issue too, not
  this design doc.
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
  discussion's original premise. The issue's own named edge case (a
  user explicitly setting `hooks = false` and being surprised
  shguard-for-codex stopped firing) is real but not Codex-specific:
  it's the same silent-disable shape as a user deleting shguard's entry
  from Claude Code's own `settings.json` today, which shguard also
  doesn't warn about. No Codex-specific warning is warranted for parity
  with that existing precedent; none of this RFC's other findings
  surfaced a different, genuinely new footgun around the `hooks`
  config key worth treating differently.
