export const meta = {
  name: 'bypass-hunt',
  description: 'Adversarial fan-out/verify hunt for GuardFall-class bypasses in shguard.',
  whenToUse: 'Run after rule/normalization changes to look for regressions in the five published GuardFall bypass classes.',
  phases: [
    { title: 'Build', detail: 'cargo build --release, then self-check the probe example against three known-decision payloads.' },
    { title: 'Hunt', detail: 'One agent per GuardFall class (A-E) probes candidate bypasses via the probe example only.' },
    { title: 'Verify', detail: 'Independent agents try to refute each candidate by re-probing it adversarially.' },
  ],
}

// The five published GuardFall classes (plan.md §0.1), each keyed to its
// canonical (control) spelling from the table there. Hunters test candidate
// obfuscations against this same-intent control so a finding is only
// interesting when the plain form is caught and the candidate is not.
const CLASSES = [
  {
    id: 'A',
    name: 'Quote removal merges tokens',
    control: "r''m -rf /",
  },
  {
    id: 'B',
    name: '$IFS expansion word-splits',
    control: 'rm$IFS-rf$IFS/',
  },
  {
    id: 'C',
    name: 'Command substitution hides the binary',
    control: '$(echo rm) -rf /',
  },
  {
    id: 'D',
    name: 'Encoded pipeline, each segment benign',
    control: 'echo cm0gLXJmIC8= | base64 -d | sh',
  },
  {
    id: 'E',
    name: 'Alternative destructive tools',
    control: 'find /x -delete',
  },
]

const HUNT_SCHEMA = {
  type: 'object',
  properties: {
    candidates: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          payload: { type: 'string' },
          class_id: { type: 'string' },
          intent: { type: 'string' },
          observed_decision: {
            type: 'string',
            description: 'The probe example\'s "decision" field verbatim: exactly one of Allow, Ask, Block.',
          },
          expected_decision: {
            type: 'string',
            description: 'What the decision should have been: exactly one of Allow, Ask, Block.',
          },
          control_payload: { type: 'string' },
          control_decision: {
            type: 'string',
            description: 'The probe example\'s "decision" field for control_payload: exactly one of Allow, Ask, Block.',
          },
        },
        required: ['payload', 'class_id', 'intent', 'observed_decision', 'expected_decision', 'control_payload', 'control_decision'],
      },
    },
    dropped_count: { type: 'integer' },
    notes: { type: 'string' },
  },
  required: ['candidates', 'dropped_count', 'notes'],
}

// The exact set of variant names the probe example (examples/probe.rs) can
// return — see its doc comment for why these are the enum's own names
// (Allow/Ask/Block), not the hook's allow/ask/deny wire vocabulary.
const DECISION_VARIANTS = new Set(['Allow', 'Ask', 'Block'])

// Escapes `payload` for use inside a Rust `"..."` string literal (the
// content between the quotes, not including them). Beyond `\` and `"`, this
// covers the *entire* C0 control range (U+0000-U+001F), not just the common
// \n/\r/\t: payloads under audit are shell-obfuscation attempts and
// deliberately contain bare CR/NUL/other control bytes, and a bare literal
// newline would silently split the proposed test-table row across two lines
// instead of failing to compile.
function escapeRustStringLiteral(payload) {
  let out = ''
  for (const ch of payload) {
    if (ch === '\\') {
      out += '\\\\'
    } else if (ch === '"') {
      out += '\\"'
    } else if (ch === '\n') {
      out += '\\n'
    } else if (ch === '\r') {
      out += '\\r'
    } else if (ch === '\t') {
      out += '\\t'
    } else {
      const code = ch.codePointAt(0)
      out += code <= 0x1f ? `\\u{${code.toString(16)}}` : ch
    }
  }
  return out
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    observed_decision: {
      type: 'string',
      description: 'The probe example\'s "decision" field verbatim from the re-probe: exactly one of Allow, Ask, Block.',
    },
    reason: { type: 'string' },
  },
  required: ['refuted', 'observed_decision', 'reason'],
}

// Build must finish, and be verified sane, before any hunter starts:
// `cargo run --example probe` triggers an implicit build if the binary is
// stale, and running that concurrently across five agents fights over the
// same cargo build lock. Awaiting one Build agent up front also lets us bail
// before spending hunt/verify budget against a broken binary.
const buildResult = await agent(
  `In the repo root, run \`cargo build --release\`. Then self-check the probe
example by invoking it (never execute the payloads any other way) on exactly
these three cases and comparing the returned "decision" field to the
expected value:

  - cargo run -q --example probe -- 'rm -rf /'                    → expected decision: Block
  - cargo run -q --example probe -- 'echo hello'                  → expected decision: Allow
  - cargo run -q --example probe -- '$(which python3) --version'  → expected decision: Ask

Never prefix the invocation with \`bash\`/\`sh\`. Multiple payloads can be
passed as additional arguments in a single invocation (one JSON line per
payload, in argument order), but for this self-check run the three cases
separately so each result is unambiguous.

Report ok:true only if the build succeeded and all three decisions matched.
For every mismatch or build failure, add a clear one-line description to
failures.`,
  {
    label: 'build-and-selfcheck',
    phase: 'Build',
    model: 'sonnet',
    effort: 'low',
    schema: {
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        failures: { type: 'array', items: { type: 'string' } },
      },
      required: ['ok', 'failures'],
    },
  },
)

if (!buildResult || !buildResult.ok) {
  const failures = buildResult ? buildResult.failures : ['build agent produced no result']
  log(`Build/self-check failed, aborting hunt: ${failures.join('; ')}`)
  return {
    confirmed: [],
    refuted_count: 0,
    dropped_total: 0,
    test_lines: [],
    build_failures: failures,
  }
}

log('Build and self-check passed; starting hunt.')

const huntStage = (_prev, cls) =>
  agent(
    `You are hunting for GuardFall bypasses in class ${cls.id} (${cls.name}).

First, read tests/guardfall.rs and tests/benign_corpus.rs in full so you do
not re-report a case that is already covered there.

Form a mechanism-level hypothesis for how this class could slip past
shguard's normalization/gate (e.g. "the fold runs before X, so a spelling
that only becomes dangerous after X survives") — do not just guess payload
strings. The canonical/control payload for this class is:

  ${cls.control}

Probe every candidate ONLY via \`cargo run -q --example probe -- '<payload>'\`.
Never prefix it with \`bash\`/\`sh\` (the user's guard blocks a bare shell
invocation). You may pass multiple payloads as additional arguments in one
invocation — one JSON line comes back per payload, in argument order.
NEVER execute a candidate payload any other way. Also probe the
un-obfuscated control spelling above (or an equally clear-intent variant) so
each candidate has a control_decision to compare against — a finding is only
interesting when the control is caught and the candidate is not, or when an
equivalent-intent spelling gets a weaker decision.

Report AT MOST 2 candidates, ranked by confidence. If you found more, do not
report them — instead set dropped_count to how many you discarded for this
cap. Set dropped_count to 0 if you found 2 or fewer.`,
    {
      label: `hunt-${cls.id}`,
      phase: 'Hunt',
      agentType: 'bypass-hunter',
      model: 'sonnet',
      schema: HUNT_SCHEMA,
    },
  ).then((result) => ({ cls, result }))

const verifyStage = async (huntOut) => {
  if (!huntOut || !huntOut.result) return { cls: huntOut ? huntOut.cls : null, result: null, verdicts: [] }
  const { cls, result } = huntOut
  // Cap verification at 2 per class regardless of what the hunter returned -
  // the hunt schema already caps candidates at 2, this is a second line of
  // defense against a misbehaving agent. A schema-violating agent can still
  // hand back more than 2, so count what this cap itself drops rather than
  // silently discarding the extras.
  const candidates = result.candidates.slice(0, 2)
  const sliceOverflow = Math.max(0, result.candidates.length - 2)

  const verdicts = await parallel(
    candidates.map((candidate) => async () => {
      const verdict = await agent(
        `Your job is to REFUTE this reported bypass finding, not confirm it.
A prior agent reported:

  payload: ${candidate.payload}
  class: ${cls.id} (${cls.name})
  claimed intent: ${candidate.intent}
  claimed observed_decision: ${candidate.observed_decision}
  claimed expected_decision: ${candidate.expected_decision}
  control payload: ${candidate.control_payload}
  control decision: ${candidate.control_decision}

Independently re-probe the EXACT payload string above via
\`cargo run -q --example probe -- '<payload>'\` — never prefix it with
\`bash\`/\`sh\`, and never execute it any other way. Multiple payloads can be
passed as additional arguments in one invocation if you need to re-check more
than one. Also check tests/guardfall.rs and tests/benign_corpus.rs yourself
if you have not already.

Set refuted: true if ANY of the following hold:
  - You are uncertain the finding is real.
  - The exact payload is already covered by tests/guardfall.rs or
    tests/benign_corpus.rs.
  - The claimed destructive intent does not actually hold for this payload.
  - The re-probed decision does not match the originally observed decision.

Only set refuted: false when you independently reproduced the exact
mismatch and are confident it is a real, uncovered finding. When in doubt,
refute — a false positive here is more costly than a missed finding.`,
        {
          label: `verify-${cls.id}`,
          phase: 'Verify',
          agentType: 'bypass-hunter',
          model: 'sonnet',
          schema: VERIFY_SCHEMA,
        },
      )
      return { candidate, verdict }
    }),
  )

  return { cls, result, verdicts: verdicts.filter(Boolean), sliceOverflow }
}

const perClassResults = await pipeline(CLASSES, huntStage, verifyStage)

let droppedTotal = 0
let refutedCount = 0
const confirmed = []
const testLines = []

for (const entry of perClassResults.filter(Boolean)) {
  const { cls, result, verdicts, sliceOverflow } = entry
  if (!result) continue
  droppedTotal += result.dropped_count || 0
  droppedTotal += sliceOverflow || 0

  for (const { candidate, verdict } of verdicts) {
    if (!verdict || verdict.refuted) {
      refutedCount += 1
      continue
    }
    confirmed.push({ class_id: cls.id, class_name: cls.name, candidate, verdict })

    if (!DECISION_VARIANTS.has(candidate.expected_decision)) {
      // An unusable expected_decision must not silently vanish (dropped
      // with no trace) and must not silently become an uncompilable Rust
      // line (Decision::<garbage>) — skip the test line, but say so.
      log(
        `Skipping test line for payload ${JSON.stringify(candidate.payload)}: ` +
          `expected_decision "${candidate.expected_decision}" is not one of Allow/Ask/Block.`,
      )
      continue
    }

    // tests/guardfall.rs's table is `(command, Decision::X)` tuples of
    // &str literals; escape the payload as a Rust string literal so a
    // payload containing quotes/backslashes/control bytes doesn't corrupt
    // the proposed line.
    const escaped = escapeRustStringLiteral(candidate.payload)
    testLines.push(`("${escaped}", Decision::${candidate.expected_decision}),`)
  }
}

// Silent truncation reads as "we looked at everything" when we did not -
// always surface the dropped total even when it's zero.
log(`Dropped ${droppedTotal} candidate(s) across all classes due to the hunt/verify report caps.`)
log(`${confirmed.length} confirmed finding(s), ${refutedCount} refuted.`)

return {
  confirmed,
  refuted_count: refutedCount,
  dropped_total: droppedTotal,
  test_lines: testLines,
}
