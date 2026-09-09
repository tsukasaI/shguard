# Spike: non-empty no-decision hook output for `ask_outcome = "pass"` (#470)

## Question

Can a shguard hook emit a **non-empty** stdout shape that Claude Code still
treats as "no decision" (i.e. does not itself resolve to allow/deny), so a
future `ask_outcome = "pass"` could hand Ask-tier commands to the Auto Mode
classifier instead of denying them? Empty stdout is unusable for this: the
README wrapper deliberately maps empty stdout to `deny` (#440), so `pass`
needs a shape that is simultaneously non-empty and non-deciding.

## Method

A probe hook (`bash probe.sh`) was registered as a `PreToolUse` `Bash`
matcher via `--settings` (not the project's `.claude/settings.json`), logging
raw stdin and emitting one of the four shapes below based on a `SHAPE` env
var. Runs used `--settings '{"remoteControlAtStartup":false, ...}'` per the
isolation lesson in `docs/threat-model.md` (remote-control channels can
resolve dialogs independent of hook output, contaminating results).

Verified live in this spike: **headless (`-p`) mode only**, across
`--permission-mode auto`, `manual`, and default (no flag). Interactive
dialog-rendering (does a dialog render, does it hold) could not be observed
from this non-interactive session; that requires a real TTY, the same
constraint that produced `evidence/interactive-isolated/` in prior
investigations cited by `docs/threat-model.md`. Those cells are marked
**unverified** below, not guessed.

## Test matrix results

| Shape | Content | auto (headless) | manual (headless) | default (headless) | interactive dialog rendering |
|---|---|---|---|---|---|
| 1 (control) | empty stdout, exit 0 | call proceeds, executes | call proceeds, executes | call proceeds, executes | unverified, needs TTY |
| 2 | `{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}`, no `permissionDecision` | call proceeds, executes | call proceeds, executes | call proceeds, executes | unverified, needs TTY |
| 3 | shape 2 plus `additionalContext` only | call proceeds, executes | call proceeds, executes | call proceeds, executes | unverified, needs TTY |
| 4 | shape 2 plus `permissionDecisionReason` only | call proceeds, executes | call proceeds, executes | call proceeds, executes | unverified, needs TTY |

All four headless runs completed with `"permission_denials":[]` and the
target command's output present in `result`, for all three modes tested.
Raw JSON results and the probe's stdin log are not committed here (ephemeral
run artifacts); the table above is the extracted, load-bearing signal
(`permission_denials` and `result` fields from `--output-format json`).

### Reading the headless result

In headless mode, all four shapes, including the two "no output, but
non-empty" shapes (2, 3, 4), behaved identically to the documented
empty-stdout control (shape 1): the hook was treated as having no decision,
and the call fell through to the normal permission flow, which in this test
had no `settings.json` ask rule configured, so it proceeded. This is
consistent with the hooks doc's claim that omitting `permissionDecision`
from `hookSpecificOutput` is the "no decision" shape regardless of whether
other sibling fields (`additionalContext`, `permissionDecisionReason`) are
present. In other words, non-empty output that omits `permissionDecision`
does not trip the empty-stdout-means-deny wrapper convention, because it
isn't empty.

This headless evidence does not establish whether `additionalContext`
(shape 3) or `permissionDecisionReason` (shape 4) actually reach the Auto
Mode classifier's evaluation or a transcript. That requires either
inspecting a classifier prompt/transcript live (headless `-p` here used no
classifier-mediated ask, since nothing asked) or an interactive run with a
configured ask rule forcing the classifier to engage.

## Open items (unresolved by this spike)

1. **Interactive dialog rendering** for shapes 1-4 across `auto`,
   `default`, and `manual` (12 cells). Needs a real TTY session per
   `docs/threat-model.md`'s isolation methodology. Not run here.
2. **Does `additionalContext` / `permissionDecisionReason` actually reach
   the Auto Mode classifier's decision, or only a human-facing transcript?**
   Needs a configured `settings.json` ask rule (so the classifier is
   actually invoked) plus inspection of what text the classifier receives.
   Not observable from a headless run with no ask rule in play.
3. **`dontAsk` mode** was not tested. threat-model.md notes it auto-denies
   settings.json-driven asks with no dialog, which may interact differently
   with a no-decision hook shape.

## Provisional conclusion

The blocking open question from the issue, "is a non-empty, no-decision
shape even expressible", has a **yes** answer for the mechanism (omit
`permissionDecision`, keep other fields): headless mode treats it exactly
like empty stdout, not like a deny. Whether that mechanism actually
delivers shguard's Ask signal (`additionalContext` /
`permissionDecisionReason`) to the Auto Mode classifier in a real ask
scenario is not yet verified and blocks shipping `ask_outcome = "pass"` per
the issue's own security note. Recommend a follow-up interactive spike
scoped to open item 2 before any implementation PR.
