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
//
// controlExpected is the decision the control payload MUST get, derived
// from plan.md §3's regression table and §4's Block/Ask boundary policy:
//   A (quote removal)         -> resolves to `rm -rf /`, blocklist hit    -> Block
//   B ($IFS splitting)        -> resolves to `rm -rf /`, blocklist hit    -> Block
//   C (command substitution)  -> substitution in COMMAND position, value
//                                 statically unknowable (§4)              -> Ask
//   D (decode-fed pipe)       -> decode stage feeding an interpreter (§4) -> Block
//   E (alternative tools)     -> `find -delete` ported blocklist rule     -> Block
// Note C is deliberately Ask, not Block: §4 draws the line on *position*,
// and a bare substitution in command position has legitimate uses
// (`$(which python3) script.py`), so the policy floors it to Ask rather
// than Block.
const CLASSES = [
  {
    id: 'A',
    name: 'Quote removal merges tokens',
    control: "r''m -rf /",
    controlExpected: 'Block',
  },
  {
    id: 'B',
    name: '$IFS expansion word-splits',
    control: 'rm$IFS-rf$IFS/',
    controlExpected: 'Block',
  },
  {
    id: 'C',
    name: 'Command substitution hides the binary',
    control: '$(echo rm) -rf /',
    controlExpected: 'Ask',
  },
  {
    id: 'D',
    name: 'Encoded pipeline, each segment benign',
    control: 'echo cm0gLXJmIC8= | base64 -d | sh',
    controlExpected: 'Block',
  },
  {
    id: 'E',
    name: 'Alternative destructive tools',
    control: 'find /x -delete',
    controlExpected: 'Block',
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
          mechanisms: {
            type: 'array',
            items: { type: 'string' },
            description:
              `The GuardFall class id(s) (e.g. ["A"] or ["A","C"]) whose techniques this payload combines. Report honestly: many real bypasses interleave two classes' techniques (e.g. a quote-split token inside a command substitution), and collapsing that to a single class id hides the composition.`,
          },
        },
        required: [
          'payload',
          'class_id',
          'intent',
          'observed_decision',
          'expected_decision',
          'control_payload',
          'control_decision',
          'mechanisms',
        ],
      },
    },
    control_decision: {
      type: 'string',
      description:
        'The probe example\'s "decision" field, verbatim (Allow/Ask/Block), for THIS CLASS\'s canonical control payload — report it even when candidates is empty, so an empty result is distinguishable from a result that never probed anything.',
    },
    hypotheses_tested: {
      type: 'array',
      items: { type: 'string' },
      description:
        'One entry per mechanism-level hypothesis you actually formed and probed for this class, in your own words (not payload strings). Required even when candidates is empty.',
    },
    controls_probed: {
      type: 'array',
      items: { type: 'string' },
      description: 'The exact control payload string(s) you actually probed via the probe example, verbatim.',
    },
    dropped_count: { type: 'integer' },
    notes: { type: 'string' },
  },
  required: ['candidates', 'control_decision', 'hypotheses_tested', 'controls_probed', 'dropped_count', 'notes'],
}

// The exact set of variant names the probe example (examples/probe.rs) can
// return — see its doc comment for why these are the enum's own names
// (Allow/Ask/Block), not the hook's allow/ask/deny wire vocabulary.
const DECISION_VARIANTS = new Set(['Allow', 'Ask', 'Block'])

// The exact set of outcomes VERIFY_SCHEMA allows. Used defensively at the
// aggregation sink: an agent-returned outcome that is missing or outside
// this set is treated as inconclusive, never silently trusted verbatim.
const VERIFY_OUTCOMES = new Set(['confirmed', 'refuted', 'inconclusive'])

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
    outcome: {
      type: 'string',
      enum: ['confirmed', 'refuted', 'inconclusive'],
      description:
        'confirmed: you independently reproduced the exact mismatch and are confident this is a real, uncovered finding. refuted: positively debunked — does not reproduce, OR the exact payload is already covered by tests/guardfall.rs or tests/benign_corpus.rs, OR the claimed destructive intent does not actually hold. inconclusive: you cannot decide either way — hand it to a human rather than guessing.',
    },
    observed_decision: {
      type: 'string',
      description: 'The probe example\'s "decision" field verbatim from the re-probe: exactly one of Allow, Ask, Block.',
    },
    reason: { type: 'string' },
  },
  required: ['outcome', 'observed_decision', 'reason'],
}

// Build must finish, and be verified sane, before any hunter starts:
// `cargo run --example probe` triggers an implicit build if the binary is
// stale, and running that concurrently across five agents fights over the
// same cargo build lock. Awaiting one Build agent up front also lets us bail
// before spending hunt/verify budget against a broken binary.
//
// agentType is set here (matching the Hunt/Verify agents) so a registry
// miss for 'bypass-hunter' surfaces at agent #1, before any hunt/verify
// budget is spent — a preflight for zero added agents. That in turn creates
// a throw path (agent() throws on an unknown agentType), so the whole call
// is wrapped in try/catch and folded into the same ok:false shape the
// self-check failure path already used, with the thrown message as the
// failure reason.
let buildResult
try {
  buildResult = await agent(
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
      agentType: 'bypass-hunter',
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
} catch (err) {
  buildResult = {
    ok: false,
    failures: [`build agent threw: ${err && err.message ? err.message : String(err)}`],
  }
}

if (!buildResult || !buildResult.ok) {
  // buildResult.failures can itself be a present-but-empty array (agent
  // reported ok:false but forgot to explain why) — `failures.join('; ')`
  // on an empty array yields '', an abort with no visible reason. Always
  // synthesise a placeholder so an abort is never reasonless.
  let failures
  if (buildResult && Array.isArray(buildResult.failures) && buildResult.failures.length > 0) {
    failures = buildResult.failures
  } else if (buildResult) {
    failures = ['build reported ok:false with no failure reasons given']
  } else {
    failures = ['build agent produced no result']
  }
  const reason = `build/self-check failed: ${failures.join('; ')}`
  log(`AUDIT INCOMPLETE: ${reason}`)
  // Returns the SAME contract as the aggregation sink below, not a shorter
  // ad-hoc shape. A consumer must be able to decide whether to trust an
  // empty `confirmed` by reading one field — `status` — on every code path.
  // A build-failure return lacking `status` would leave that check reading
  // `undefined`, which is the same absence-inferred-as-clean defect the
  // conservation laws exist to eliminate, reintroduced on the error path.
  // No class ran, so every class is censused as failed with this reason.
  return {
    status: 'incomplete',
    reason,
    confirmed: [],
    inconclusive: [],
    refuted: [],
    class_census: CLASSES.map((cls) => ({
      class_id: cls.id,
      status: 'failed',
      reason,
      control_decision: null,
      control_expected: cls.controlExpected,
      control_ok: null,
      candidates_emitted: 0,
      verified: { confirmed: 0, refuted: 0, inconclusive: 0 },
      dropped_by_cap: 0,
      dropped_self_reported: null,
      hypotheses_tested_count: 0,
      controls_probed_count: 0,
    })),
    verify_outcomes: { confirmed: 0, refuted: 0, inconclusive: 0 },
    composition_candidates: 0,
    dropped_total: 0,
    schema_violations: [],
    test_lines: [],
    build_failures: failures,
  }
}

log('Build and self-check passed; starting hunt.')

const huntStage = async (_prev, cls) => {
  try {
    const result = await agent(
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
cap. Set dropped_count to 0 if you found 2 or fewer.

You must ALSO report, at the top level, ALL of the following — including
when candidates is empty:
  - control_decision: the probed decision (Allow/Ask/Block, the probe's own
    vocabulary) of this class's canonical control payload above.
  - hypotheses_tested: one entry per mechanism-level hypothesis you actually
    formed and probed, in your own words — not payload strings.
  - controls_probed: the exact control payload string(s) you actually probed
    via the probe example, verbatim.

These exist so an empty candidates list is credible instead of ambiguous:
without control_decision/hypotheses_tested/controls_probed, "I probed five
hypotheses and found nothing" and "I barely tried" produce identical output,
and there would be no way to tell them apart.

For every candidate you DO report, also set mechanisms: the GuardFall class
id(s) (e.g. ["A"] or ["A","C"]) whose techniques that payload actually
combines. Report this honestly — a payload combining two classes'
techniques (e.g. a quote-split token used *inside* a command substitution)
is a different finding than a plain single-class payload, and collapsing it
to one id hides that composition.`,
      {
        label: `hunt-${cls.id}`,
        phase: 'Hunt',
        agentType: 'bypass-hunter',
        model: 'sonnet',
        schema: HUNT_SCHEMA,
      },
    )
    if (!result) {
      return {
        cls,
        status: 'agent_died',
        reason: `hunt agent for class ${cls.id} resolved null (agent death)`,
        result: null,
      }
    }
    return { cls, status: 'completed', reason: null, result }
  } catch (err) {
    return {
      cls,
      status: 'errored',
      reason: err && err.message ? err.message : String(err),
      result: null,
    }
  }
}

const verifyStage = async (huntOut, cls) => {
  // Defensive: huntStage above never throws and never resolves anything
  // other than a tagged {cls, status, reason, result} object, so huntOut
  // should always be that shape. But this stage must itself never let a
  // bare null propagate out of the pipeline (that would silently drop the
  // whole class from perClassResults), so every branch — including the
  // "huntOut is somehow missing" case — still returns a cls-bearing object.
  const effectiveCls = huntOut && huntOut.cls ? huntOut.cls : cls
  try {
    const huntStatus = huntOut ? huntOut.status : 'agent_died'
    const huntReason = huntOut ? huntOut.reason : 'hunt stage produced no output for this class'
    const result = huntOut ? huntOut.result : null

    if (huntStatus !== 'completed' || !result) {
      return { cls: effectiveCls, huntStatus, huntReason, result: null, verdicts: [], sliceOverflow: 0 }
    }

    // Cap verification at 2 per class regardless of what the hunter returned -
    // the hunt schema already caps candidates at 2, this is a second line of
    // defense against a misbehaving agent. A schema-violating agent can still
    // hand back more than 2, so count what this cap itself drops rather than
    // silently discarding the extras.
    const candidates = result.candidates.slice(0, 2)
    const sliceOverflow = Math.max(0, result.candidates.length - 2)

    const verdicts = await parallel(
      candidates.map((candidate) => async () => {
        try {
          const verdict = await agent(
            `Your job is to try to REFUTE this reported bypass finding, not to
rubber-stamp it. A prior agent reported:

  payload: ${candidate.payload}
  class: ${effectiveCls.id} (${effectiveCls.name})
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

Report exactly one outcome:
  - outcome: "refuted" — ONLY when you have positively debunked the finding:
    it does not reproduce, OR the exact payload is already covered by
    tests/guardfall.rs or tests/benign_corpus.rs, OR the claimed destructive
    intent does not actually hold for this payload.
  - outcome: "confirmed" — ONLY when you independently reproduced the exact
    mismatch and are confident this is a real, uncovered finding.
  - outcome: "inconclusive" — when you cannot decide either way. Use this
    for genuine uncertainty rather than forcing a confirmed/refuted call you
    are not sure of; a human reviews every inconclusive candidate, so
    uncertainty here is never silently lost.`,
            {
              label: `verify-${effectiveCls.id}`,
              phase: 'Verify',
              agentType: 'bypass-hunter',
              model: 'sonnet',
              schema: VERIFY_SCHEMA,
            },
          )
          if (!verdict) {
            return { candidate, verdict: null, error: 'verify agent resolved null (agent death)' }
          }
          return { candidate, verdict, error: null }
        } catch (err) {
          return { candidate, verdict: null, error: err && err.message ? err.message : String(err) }
        }
      }),
    )

    return { cls: effectiveCls, huntStatus: 'completed', huntReason: null, result, verdicts, sliceOverflow }
  } catch (err) {
    return {
      cls: effectiveCls,
      huntStatus: 'errored',
      huntReason: `verify stage threw: ${err && err.message ? err.message : String(err)}`,
      result: null,
      verdicts: [],
      sliceOverflow: 0,
    }
  }
}

const perClassResults = await pipeline(CLASSES, huntStage, verifyStage)

// ---------------------------------------------------------------------
// Aggregation sink. This is the ONE place that computes and asserts both
// conservation laws:
//   1. Class conservation: zero findings may only be reported when every
//      class actually completed — completedCount === CLASSES.length. (Not
//      completed + failed === CLASSES.length: classStatus only ever takes
//      the values 'completed'/'failed', and this loop pushes exactly one
//      census entry per class, so that sum is always true and can never
//      catch a partial run — see the check itself, below, for the incident
//      that motivated replacing it.)
//   2. Candidate conservation (per class): candidates_emitted ===
//      confirmed + refuted + inconclusive + dropped_by_cap.
// Every lossy boundary upstream (Build/Hunt agent() throwing or dying,
// pipeline/parallel dropping a throwing item to null) has already been
// captured as a tagged, non-null value; this loop's only job is to fold
// those tagged values into one census entry per class — by index, never by
// filtering — so a class that never produced a tagged entry still gets one
// here, synthesised as failed. It also cross-checks each entry's carried
// entry.cls against the class its index expects to catch pipeline order
// corruption, which per-entry conservation arithmetic alone cannot detect.
// ---------------------------------------------------------------------

const confirmed = []
const inconclusive = []
const refuted = []
const testLines = []
const classCensus = []
const schemaViolations = []
let compositionCandidates = 0
let droppedByCapTotal = 0
let droppedSelfReportedTotal = 0
let classOrderOk = true

for (let i = 0; i < CLASSES.length; i++) {
  const cls = CLASSES[i]
  const entry = perClassResults[i] || {
    cls,
    huntStatus: 'errored',
    huntReason: 'pipeline produced no result for this class',
    result: null,
    verdicts: [],
    sliceOverflow: 0,
  }

  // entry.cls's keep: hunt/verify thread the class object through as
  // entry.cls specifically so this index can be cross-checked against it.
  // Without this, a pipeline order bug would report class C's result under
  // class A's id — and because both conservation laws are per-entry and
  // label-independent, they'd still balance, so a mislabeled finding would
  // pass as `ok` silently.
  if (entry.cls && entry.cls.id !== cls.id) {
    classOrderOk = false
    schemaViolations.push(
      `class census index ${i}: expected class id ${cls.id} (position ${i}) but carried entry has class id ${entry.cls.id} — pipeline order was not preserved`,
    )
  }

  const huntStatus = entry.huntStatus || 'errored'
  const classStatus = huntStatus === 'completed' ? 'completed' : 'failed'
  const failReason = huntStatus === 'completed' ? null : entry.huntReason || `hunt ${huntStatus}`
  const result = huntStatus === 'completed' ? entry.result : null

  const controlDecision = result && typeof result.control_decision === 'string' ? result.control_decision : null
  const controlExpected = cls.controlExpected
  const controlOk = controlDecision != null ? controlDecision === controlExpected : null

  const candidatesEmitted = result && Array.isArray(result.candidates) ? result.candidates.length : 0
  const droppedByCap = entry.sliceOverflow || 0

  // Deliberately NOT `result.dropped_count || 0`: `|| 0` would rewrite "the
  // agent didn't say" (missing/non-integer) into "nothing was dropped",
  // which is exactly the absence-as-clean-audit defect this whole change
  // exists to eliminate. A missing/non-integer dropped_count is recorded as
  // null here and the class is flagged in schema_violations instead.
  let droppedSelfReported = null
  if (result) {
    if (typeof result.dropped_count === 'number' && Number.isInteger(result.dropped_count)) {
      droppedSelfReported = result.dropped_count
    } else {
      schemaViolations.push(`class ${cls.id}: dropped_count is missing or not an integer (got ${JSON.stringify(result.dropped_count)})`)
    }
  }

  const hypothesesTestedCount = result && Array.isArray(result.hypotheses_tested) ? result.hypotheses_tested.length : 0
  const controlsProbedCount = result && Array.isArray(result.controls_probed) ? result.controls_probed.length : 0

  // composition_candidates counts across every EMITTED candidate (i.e. all
  // of result.candidates, including any later dropped by the verify-side
  // cap) — not just the ones that got verified.
  if (result && Array.isArray(result.candidates)) {
    for (const c of result.candidates) {
      if (Array.isArray(c.mechanisms) && c.mechanisms.length > 1) compositionCandidates += 1
    }
  }

  let vConfirmed = 0
  let vRefuted = 0
  let vInconclusive = 0

  for (const v of entry.verdicts || []) {
    if (!v) {
      // parallel() can yield a bare null in place of a slot; this loop has
      // no surrounding try/catch, so `const {…} = null` below would throw
      // and take the whole aggregation sink down with it — losing the
      // census and all instrumentation for a run that otherwise completed.
      // Skip-with-accounting instead: bucket it inconclusive rather than
      // crash or silently drop it. This also keeps law 2 honest — a
      // silently dropped slot would make the verified sum fall short of
      // candidates_emitted and trip conservation law 2, but only if the
      // loop survives to compute it.
      vInconclusive += 1
      inconclusive.push({
        class_id: cls.id,
        class_name: cls.name,
        candidate: null,
        verdict: null,
        error: 'parallel yielded null verdict slot',
      })
      continue
    }
    const { candidate, verdict, error } = v
    // A missing verdict, or an outcome outside the enum, is bucketed
    // inconclusive at the sink — never refuted, never dropped. This is the
    // one place Change 5's "verdicts.filter(Boolean)" deletion matters:
    // there is no filter here, every verdict entry is bucketed somewhere.
    const outcome = verdict && VERIFY_OUTCOMES.has(verdict.outcome) ? verdict.outcome : 'inconclusive'
    const record = { class_id: cls.id, class_name: cls.name, candidate, verdict, error: error || null }

    if (outcome === 'confirmed') {
      vConfirmed += 1
      confirmed.push(record)

      if (!DECISION_VARIANTS.has(candidate.expected_decision)) {
        // An unusable expected_decision must not silently vanish (dropped
        // with no trace) and must not silently become an uncompilable Rust
        // line (Decision::<garbage>) — skip the test line, but say so.
        log(
          `Skipping test line for payload ${JSON.stringify(candidate.payload)}: ` +
            `expected_decision "${candidate.expected_decision}" is not one of Allow/Ask/Block.`,
        )
      } else {
        // tests/guardfall.rs's table is `(command, Decision::X)` tuples of
        // &str literals; escape the payload as a Rust string literal so a
        // payload containing quotes/backslashes/control bytes doesn't
        // corrupt the proposed line.
        const escaped = escapeRustStringLiteral(candidate.payload)
        testLines.push(`("${escaped}", Decision::${candidate.expected_decision}),`)
      }
    } else if (outcome === 'refuted') {
      vRefuted += 1
      refuted.push(record)
    } else {
      vInconclusive += 1
      inconclusive.push(record)
    }
  }

  droppedByCapTotal += droppedByCap
  if (droppedSelfReported !== null) droppedSelfReportedTotal += droppedSelfReported

  classCensus.push({
    class_id: cls.id,
    status: classStatus,
    reason: failReason,
    control_decision: controlDecision,
    control_expected: controlExpected,
    control_ok: controlOk,
    candidates_emitted: candidatesEmitted,
    verified: { confirmed: vConfirmed, refuted: vRefuted, inconclusive: vInconclusive },
    dropped_by_cap: droppedByCap,
    dropped_self_reported: droppedSelfReported,
    hypotheses_tested_count: hypothesesTestedCount,
    controls_probed_count: controlsProbedCount,
  })

  log(
    `Class ${cls.id} (${cls.name}): status=${classStatus}` +
      (failReason ? ` reason=${failReason}` : '') +
      ` control_decision=${controlDecision ?? 'unknown'} control_expected=${controlExpected} control_ok=${controlOk}`,
  )
  if (controlOk === false) {
    log(`  CONTROL MISMATCH for class ${cls.id}: expected ${controlExpected}, probed ${controlDecision}.`)
  }
}

// --- Conservation law 1: class conservation ---
// "Zero findings may only be reported when every class completed": checked
// directly as completedCount === CLASSES.length, not as
// `completed + failed === CLASSES.length` — classStatus only ever takes the
// values 'completed'/'failed' and the loop above pushes exactly one census
// entry per class, so that sum is always true and can never catch a partial
// run (4 classes dying and 1 completing with zero candidates used to sail
// through as `status: 'ok'`).
const completedCount = classCensus.filter((c) => c.status === 'completed').length
const failedClasses = classCensus.filter((c) => c.status === 'failed')
const classConservationOk = completedCount === CLASSES.length

// Genuine structural check (distinct from the law above, and not vacuous
// like the deleted one): guards a future loop bug where classCensus ends up
// short or long relative to CLASSES, which nothing else here would catch.
const censusLengthOk = classCensus.length === CLASSES.length

// --- Conservation law 2: candidate conservation, per class ---
const conservationViolations = []
for (const c of classCensus) {
  const sum = c.verified.confirmed + c.verified.refuted + c.verified.inconclusive + c.dropped_by_cap
  if (sum !== c.candidates_emitted) {
    conservationViolations.push(
      `class ${c.class_id}: candidates_emitted=${c.candidates_emitted} but confirmed(${c.verified.confirmed})+refuted(${c.verified.refuted})+inconclusive(${c.verified.inconclusive})+dropped_by_cap(${c.dropped_by_cap})=${sum}`,
    )
  }
}
const candidateConservationOk = conservationViolations.length === 0

const failureReasons = []
if (!classConservationOk) {
  const detail = failedClasses.map((c) => `${c.class_id} (${c.reason})`).join(', ')
  failureReasons.push(`only ${completedCount}/${CLASSES.length} classes completed` + (detail ? `: ${detail}` : ''))
}
if (!censusLengthOk) {
  failureReasons.push(`class census length mismatch: got ${classCensus.length}, expected ${CLASSES.length}`)
}
if (!classOrderOk) {
  failureReasons.push('class order mismatch: pipeline did not preserve per-class ordering (see schema_violations)')
}
if (!candidateConservationOk) {
  failureReasons.push(`candidate conservation failed: ${conservationViolations.join('; ')}`)
}

const status = failureReasons.length > 0 ? 'incomplete' : 'ok'
const reason = failureReasons.length > 0 ? failureReasons.join(' | ') : null

if (status === 'incomplete') {
  log(`AUDIT INCOMPLETE: ${reason}`)
} else {
  log('Audit complete: both conservation laws balance across all classes.')
}

// Silent truncation reads as "we looked at everything" when we did not -
// always surface the dropped total even when it's zero.
log(
  `Dropped ${droppedByCapTotal} candidate(s) to the verify-cap and ${droppedSelfReportedTotal} self-reported by hunters (unverifiable by construction) across all classes.`,
)
log(`${confirmed.length} confirmed finding(s), ${refuted.length} refuted, ${inconclusive.length} inconclusive.`)
if (schemaViolations.length > 0) {
  log(`${schemaViolations.length} schema violation(s): ${schemaViolations.join('; ')}`)
}

return {
  status,
  reason,
  confirmed,
  inconclusive,
  refuted,
  class_census: classCensus,
  verify_outcomes: { confirmed: confirmed.length, refuted: refuted.length, inconclusive: inconclusive.length },
  composition_candidates: compositionCandidates,
  // dropped_by_cap (enforced slice overflow, from candidates that WERE
  // emitted) + dropped_self_reported (the hunter's own dropped_count,
  // candidates that were NEVER emitted and are therefore unverifiable by
  // construction) — summed here for a single top-line number; the two are
  // kept separate per-class in class_census because they mean different
  // things.
  dropped_total: droppedByCapTotal + droppedSelfReportedTotal,
  schema_violations: schemaViolations,
  test_lines: testLines,
}
