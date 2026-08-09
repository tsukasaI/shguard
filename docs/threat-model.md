# Permission-mode threat model (issue #91)

This document tables how Claude Code's `--permission-mode` values resolve
this hook's `Allow` / `Ask` / `Block` decisions, for both headless (`-p`)
and interactive (TTY) execution. It answers the load-bearing question
behind shguard's design: shguard's decisions only matter if the host CLI
actually enforces them, so this is an empirical measurement of that
enforcement, not an assumption.

**Measured on**: Claude Code `2.1.226` (pinned), macOS (Darwin 25.5.0,
arm64). Six `--permission-mode` values exist as of this version
(`claude --help`): `acceptEdits`, `auto`, `bypassPermissions`, `manual`,
`dontAsk`, `plan`. `manual` is the CLI flag spelling; the equivalent
`settings.json` `permissions.defaultMode` value is spelled `"default"` —
same mode, different spelling depending on context (confirmed via
`claude doctor`'s validation-error value list). No `settings.json`-only
mode exists beyond these six: `defaultMode`'s accepted-value list is
exactly these six, modulo the `manual`/`default` spelling difference.
These behaviours are specific to Claude Code's permission-resolution
internals and may not hold across versions — see
[Reproduction method](#reproduction-method) below to re-verify on a
version bump.

Paths of the form `evidence/…` below name this investigation's captured
artifacts (debug logs, CSV summaries, session transcripts) as they existed
on the machine that ran the issue #91 investigation — they are citations
identifying what kind of evidence backs each claim, not links to files
preserved anywhere durable; the artifacts themselves lived under an
ephemeral local path and were not retained. The
[Reproduction method](#reproduction-method) section below is the durable
record: it is written to contain enough detail for someone to regenerate
the same artifacts from scratch.

**Scope note**: issue #91's acceptance criteria name a possible follow-up
— an `ask_under_bypass` config setting that would escalate Ask to Deny
under `bypassPermissions`, contingent on `bypassPermissions` being found
to swallow Ask into an auto-approval. It was not: `bypassPermissions`
renders a genuine confirmation dialog for a hook `ask` decision and holds
it, with zero auto-resolution observed in an isolated, unattended
15-minute (900s) window. That follow-up's premise does not apply, so it
is not designed or filed here.

## Headless (`-p`, no TTY)

| Mode | Allow | Ask | Block |
|---|---|---|---|
| `acceptEdits` | Executes, 4ms | Denied, fail-closed, no prompt, 5ms | Denied, fail-closed, no prompt, <1ms |
| `auto` | Executes, 4ms | Denied, fail-closed, no prompt, 7ms | Denied, fail-closed, no prompt, 1ms |
| `bypassPermissions` | Executes, 4ms | Denied, fail-closed, no prompt, 5ms | Denied, fail-closed, no prompt, 1ms |
| `manual` | Executes, 3ms | Denied, fail-closed, no prompt, 4ms | Denied, fail-closed, no prompt, <1ms |
| `dontAsk` | Executes, 3ms | Denied, fail-closed, no prompt, 6ms | Denied, fail-closed, no prompt, 1ms |
| `plan` | Bash never dispatched (see note) | Bash never dispatched (see note) | Bash never dispatched (see note) |

All 18 cells (6 modes x 3 decisions) were run; in 15 of them a
forced-decision synthetic hook was invoked and cross-checked against
`debug.log` timestamps and `output.json`'s `permission_denials` count
(the 3 `plan` cells instead confirmed Bash is never dispatched to the
hook at all — see the `plan` row's note below).

- **Allow** executes in every mode, including `bypassPermissions`, in
  3-4ms (`Hook result has permissionBehavior=allow` immediately followed
  by `[Stall] tool_dispatch_start ... permissionDecisionMs=<3|4>`).
- **Ask and Block are indistinguishable in outcome headlessly, in every
  mode including `bypassPermissions`**: both resolve to denial, with no
  prompt (`Hook result has permissionBehavior=ask` or `=deny`,
  immediately followed by `Bash tool permission denied`). There is no TTY
  to prompt, so an Ask escalation resolves to denial rather than to
  execution — **`bypassPermissions` does not swallow a hook `ask` into an
  allow when run headlessly; it fails closed the same as every other
  mode.** Timing differs slightly between the two: Block resolves in
  0-1ms across modes, Ask in 4-7ms — both sub-10ms and immaterial to the
  fail-closed conclusion, but the numbers in the table above are each
  mode's actual measured value, not a rounded average.
- **`plan` mode**: Bash is never dispatched to the hook at all, regardless
  of what decision the hook would have returned. `Bash` is present in the
  offered tool list (`output.json`'s tool list for the turn), so this is
  the agent loop self-restricting to read-only tools before `PreToolUse`
  is ever reached — not a case of the tool being unavailable, and not a
  hook-decision outcome.

## Interactive (TTY)

| Mode | Allow | Ask | Block |
|---|---|---|---|
| `acceptEdits` | Executes immediately, no dialog | Dialog renders, holds; no auto-resolution within 300s | Denied immediately, no dialog |
| `auto` | Executes immediately, no dialog | Dialog renders, holds; no auto-resolution within 300s | Denied immediately, no dialog |
| `bypassPermissions` | Executes immediately, no dialog | Dialog renders, holds; no auto-resolution within 900s (long-horizon test) | Denied immediately, no dialog |
| `manual` | Executes immediately, no dialog | Dialog renders, holds; no auto-resolution within 300s | Denied immediately, no dialog |
| `dontAsk` | Executes immediately, no dialog | Dialog renders, holds; no auto-resolution within 300s | Denied immediately, no dialog |
| `plan` | ExitPlanMode dialog gates first (see note) | ExitPlanMode dialog gates first, then Bash-level ask dialog also holds (see note) | ExitPlanMode dialog gates first (see note) |

The interactive Allow/Block cells and the basic six Ask cells are cited
from `evidence/interactive-isolated/RESULTS.csv` (isolation-verified
re-runs — see [Investigation-integrity finding](#investigation-integrity-remote-control-contamination)
below for why the isolated re-run is the citable source rather than the
original matrix). Precisely: no auto-resolution was observed within the
tested window (300s for 5 modes, 900s for `bypassPermissions`); behaviour
beyond the tested horizon is unmeasured.

- **Allow / Block**: no dialog ever renders; the decision applies
  immediately. These cells were independently confirmed clean of
  remote-control contamination in the original run — with no dialog ever
  existing, there was nothing for a remote channel to resolve.
- **Ask, all 6 modes**: a genuine confirmation dialog renders and holds.
  For the 5 basic modes, a 300-second unattended window showed zero
  auto-resolution, zero execution, zero contamination throughout. For
  `bypassPermissions` specifically — the headline cell for this
  investigation — a 900-second (15-minute) unattended window, run under
  `caffeinate -i` to prevent system sleep, also showed zero
  auto-resolution: this is the strongest single piece of evidence that
  `bypassPermissions` does not swallow a hook's Ask into a delayed or
  immediate allow. Two "close-the-loop" cells (`bypassPermissions`,
  `manual`) confirmed that after the unattended window, a genuine
  deliberate local keystroke resolves the dialog immediately (the marker
  file is created right after) — proving the dialog is a real, live gate
  waiting on real input, not a hang or an artifact of the harness.
- **`plan` mode interactively**: the model first requests `ExitPlanMode`,
  which renders its own separate confirmation dialog with the same
  genuine-wait behaviour as the Bash-hook dialog. Only after exiting plan
  mode does the model attempt Bash, which then hits the same hook-Ask
  dialog pattern as every other mode. For the `plan` x Allow and `plan` x
  Block cells: once the ExitPlanMode gate is resolved, Bash then executes
  (Allow) or is denied (Block) the same as every other mode — but that
  ExitPlanMode-gate resolution was only observed under the
  since-diagnosed contaminated condition (see
  [Investigation-integrity finding](#investigation-integrity-remote-control-contamination)
  below) and was not independently re-run in isolation; treat those two
  cells as directionally consistent, not independently re-verified. The
  `plan` x Ask cell, by contrast, WAS re-verified clean under isolation:
  in the isolated re-run, the Bash-level ask for `plan` mode was
  confirmed to genuinely stay unresolved with zero local input for the
  remainder of the observation window
  (`evidence/interactive-isolated/RESULTS.csv`, `plan-ask` row).

## Investigation-integrity: remote-control contamination

This machine's real Claude Code configuration has
`remoteControlAtStartup: true`. That setting opens an ambient
remote-control bridge on every interactive session, independent of
whether the test harness intends to use it. Early interactive test runs
were auto-resolved through this channel: `debug.log` shows an outbound
`[remote-bridge] Sent control_request` fired in the same millisecond-scale
window as `executePermissionRequestHooks called for tool: <X>`, followed
by `[remote-bridge] Sent control_response` (and usually
`Sent control_cancel_request`) landing at the exact millisecond that
`[Stall] tool_dispatch_start ... permissionDecisionMs=<wait>` fires and
the tool actually executes — i.e., something resolved the dialog well
before any scripted local keystroke could have. This pattern was present
in every ask-type dialog in the original matrix run: Bash hook-driven
asks, `settings.json` ask-rule dialogs, and even the built-in
`ExitPlanMode` confirmation (`evidence/contamination-classification.csv`
tags each observed cell as clean or contaminated by this
exact-millisecond-coincidence signal).

Diagnosis and correction: this was root-caused to
`remoteControlAtStartup`, and the interactive matrix was re-run under
verified isolation — `claude ... --settings '{"remoteControlAtStartup":false}'`
— with each run individually confirmed to show zero remote-bridge
activity (`evidence/interactive-isolated/`). The isolated re-run
reproduced the same qualitative findings (dialogs render and hold under
every mode, including `bypassPermissions`), now with the confounding
channel provably absent.

**Methodology lesson**: environment-variable scrubbing alone is
insufficient isolation for this kind of test. A remote-control channel
gated by `settings.json`, not by an environment variable, will silently
resolve confirmation dialogs regardless of how clean the process
environment looks. Any future reproduction of this investigation — or any
investigation that depends on a Claude Code confirmation dialog staying
genuinely pending — must use settings-scope isolation
(`--settings '{"remoteControlAtStartup":false}'` or equivalent) with
per-run verification (grep the run's own `debug.log` for
`[remote-bridge]` activity correlated to the specific dialog under test,
not just an aggregate line count — ambient session-open/close bridge
chatter appears in every session and is not by itself contamination).

## Double-evaluation and the `dontAsk` asymmetry

Issue #91's scope question 3 asked whether a hook's decision and a
`settings.json`-driven permission rule are independently evaluated, and
if so, which one wins. Tested by forcing the hook to `allow` while a
`settings.json` `permissions.ask` rule (`Bash(echo:*)`) also matches the
same command:

- **In 5 of 6 modes, the `settings.json` ask rule still forces a genuine,
  independent confirmation dialog even though the hook said allow.** The
  dialog's wording is distinct from the hook's own dialog — "Permission
  rule `Bash(echo:*)` requires confirmation for this command." A hook
  `allow` does not suppress a matching `settings.json` ask rule; both
  layers are evaluated, and the more restrictive one governs. This was
  corroborated under clean isolation for the `manual` mode cell
  (`evidence/interactive-isolated/double-eval-manual`: `debug.log` shows
  `Hook result has permissionBehavior=allow` immediately followed by
  `Hook returned allow for Bash, but ask rule/safety check requires full
  permission pipeline` and a fresh `executePermissionRequestHooks` call).
  The other 4 non-`dontAsk` modes' double-eval cells are cited from the
  original matrix as directionally consistent but were not independently
  re-verified under isolation — be aware of that distinction if relying
  on this doc for those specific modes.
- **`dontAsk` is the exception**: it auto-*denies* the `settings.json`-driven
  ask instead of prompting — no dialog renders at all
  (`Hook result has permissionBehavior=allow` -> `Hook returned allow for
  Bash, but ask rule/safety check requires full permission pipeline` ->
  `Bash tool permission denied`, all within ~6ms). This cell
  (`double-eval-dontAsk`) was never contaminated in the first place — with
  no dialog rendering, there was nothing for a remote channel to resolve
  — so it stands as clean, high-confidence evidence without needing a
  separate isolated re-run.
- This makes `dontAsk` asymmetric in how it handles the two ask sources:
  a **hook**-driven ask still prompts a real dialog (see the main
  interactive matrix above), while a **`settings.json` rule**-driven ask
  auto-denies with no prompt at all.

## shguard fidelity check

Two checks tie the synthetic forced-decision hook used for the rest of
this matrix back to real shguard:

- **JSON-shape match**: a byte/structural comparison of real shguard's
  stdout for an Ask-tier command (`tar xf a.tar -C /`, matched by the
  embedded `tar-directory-root-or-home` blocklist rule) against the
  synthetic test hook's Ask output shows an identical
  `hookSpecificOutput.{hookEventName,permissionDecision,permissionDecisionReason}`
  shape — same paths, same types (`evidence/task1/structural-comparison.txt`:
  "IDENTICAL SHAPE (path+type)"). Across the matrix, the observed
  permission-resolution behaviour varied only with this JSON shape,
  supporting (though not directly proving, since Claude Code's
  implementation wasn't inspected) that real shguard's Ask output would
  be treated identically to every synthetic-hook cell in the matrix
  above.
- **Interactive fidelity run**: running real shguard as the hook for the
  `bypassPermissions` x ask cell (`evidence/interactive-shguard/bypassPermissions-ask-real-shguard`)
  also showed a real dialog rendering. This specific run was **not**
  re-verified under isolation — only the synthetic-hook version of this
  exact mode/decision combination got the clean 300s+900s re-runs above.

Taken together — the JSON-shape match plus the isolated synthetic-hook
evidence for the identical mode/decision combination — these support
extending the headline finding (`bypassPermissions` does not swallow Ask)
to real shguard. The real-shguard interactive cell itself, though, was
only observed under the since-diagnosed contaminated condition; treat
that specific cell as a residual gap, not as independently re-verified.

## Reproduction method

To reproduce or re-verify this matrix on a future Claude Code version
bump:

1. **Pin and record the version.** `claude --version` (this investigation
   used `2.1.226`). Also record `uname -a` — behaviour may vary by
   platform.
2. **Isolate the remote-control channel.** Launch with
   `--settings '{"remoteControlAtStartup":false}'` (or, for a
   project-scoped `settings.json` override, set the same key there), and
   verify per-run by grepping that run's own `--debug-file` output for
   `[remote-bridge]` lines correlated to the dialog under test — not just
   checking that the flag was passed. See
   [Investigation-integrity](#investigation-integrity-remote-control-contamination)
   for why this step is load-bearing, not optional.
3. **Use a forced-decision synthetic hook** registered as a `PreToolUse`
   hook on the `Bash` matcher, reading the desired
   `permissionDecision` (`allow`/`ask`/`deny`) from a control file so the
   same script can be reused across every cell without editing it, and
   logging each invocation to a JSONL evidence log for post-hoc
   cross-checking against `debug.log` timestamps.
4. **Headless cells**: run
   `claude -p "Run this exact command using the Bash tool: echo <MARKER>" --permission-mode <mode> --output-format json --debug-file <cell>/debug.log`
   for each of the 6 modes x 3 decisions, with a unique marker string per
   cell. Check `output.json`'s terminal result event
   (`.[-1].permission_denials` — note `--output-format json` emits an
   array of stream events, not a single object) and cross-reference
   `debug.log` for `Hook result has permissionBehavior=...` and
   `[Stall] tool_dispatch_start ... permissionDecisionMs=...` lines.
5. **Interactive cells**: drive the interactive TTY session with `expect`
   (or `tmux send-keys`, if available), scripting a bounded unattended
   window (300s for most cells; extend to 900s under
   `caffeinate -i` for the headline `bypassPermissions` x ask cell) during
   which zero local keystrokes are sent, then check for zero marker
   creation, zero `tool_dispatch_start`, and zero remote-bridge activity
   throughout the window. Follow up with a deliberate "close-the-loop"
   variant (send one genuine scripted keystroke after the window) to
   confirm the dialog is a live gate rather than a hang.
6. **Double-evaluation cells**: add a `settings.json` `permissions.ask`
   rule matching the same command the forced-decision hook returns
   `allow` for, and observe whether a second, independent confirmation
   still appears.
7. **shguard fidelity**: compare real shguard's stdout JSON shape against
   the synthetic hook's, and optionally re-run the headline interactive
   cell with real shguard substituted for the synthetic hook.
