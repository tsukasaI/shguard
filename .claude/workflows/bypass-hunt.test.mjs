// Mechanical test coverage for bypass-hunt.js's aggregation sink (issue #73,
// follow-up to #70). Four defects of one shape shipped there with CI green
// (`cargo fmt`/`clippy`/`test` never touches this JS file, and every one of
// the four was syntactically valid — no linter or `node --check` would have
// caught any of them): a signal was computed, censused, logged, and never
// wired into the run's overall `status` verdict.
//
// bypass-hunt.js is NOT a standalone Node module — it is source text for the
// Workflow tool's sandboxed runtime, which supplies `agent`/`pipeline`/
// `parallel`/`log` as bound names and wraps the body in its own function.
// Confirmed empirically that it cannot be loaded any other way: running it
// directly (`node bypass-hunt.mjs`) throws `SyntaxError: Illegal return
// statement`, because the top-level `export const meta = {...}` makes Node's
// module-syntax detection treat the file as an ES module, and ESM top-level
// code (unlike a function body) does not permit a bare `return`.
//
// This harness reproduces that same wrapping deliberately, via the
// AsyncFunction constructor: it takes the file's exact source text (one
// mechanical transform — `export const meta` -> `const meta`, since `export`
// itself is illegal inside a Function-constructor body, which is not a
// module) and constructs a real async function whose parameter list is
// exactly the runtime's injected names. That makes the top-level `return`
// legal again, and — critically — means these tests execute the literal code
// that ships, not a hand-copied duplicate that could silently drift from it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor

async function loadBypassHunt() {
  const url = new URL('./bypass-hunt.js', import.meta.url)
  const src = await readFile(url, 'utf8')
  const body = src.replace('export const meta', 'const meta')
  return new AsyncFunction('agent', 'pipeline', 'parallel', 'log', body)
}

// perClassResultsFixture stands in for `pipeline(CLASSES, huntStage,
// verifyStage)`'s real output — the mock below returns it verbatim, so
// huntStage/verifyStage (which need a real LLM) never run. The Build phase's
// own `agent(...)` call is mocked separately to always report success, so
// every fixture run proceeds straight past the build-failure early return
// and into the aggregation sink under test.
function makeHarness(perClassResultsFixture) {
  const logs = []
  const agent = async () => ({ ok: true, failures: [] })
  const pipeline = async () => perClassResultsFixture
  const parallel = async (thunks) => Promise.all(thunks.map((t) => t()))
  const log = (msg) => logs.push(msg)
  return { agent, pipeline, parallel, log, logs }
}

async function runAggregate(perClassResultsFixture) {
  const fn = await loadBypassHunt()
  const harness = makeHarness(perClassResultsFixture)
  const result = await fn(harness.agent, harness.pipeline, harness.parallel, harness.log)
  return { result, logs: harness.logs }
}

// bypass-hunt.js's real CLASSES array (A-E), mirrored here ONLY for the
// values needed to build valid fixtures (id, control string, expected
// decision) — the sink itself always reads controlExpected/control/name from
// the REAL CLASSES baked into the loaded source, never from these fixture
// `cls` objects. The one field the sink DOES read off a fixture's `cls` is
// `.id`, to cross-check pipeline ordering (`entry.cls.id !== CLASSES[i].id`),
// so these ids and their positions must match the real file exactly.
const CONTROL = {
  A: { control: "r''m -rf /", expected: 'Block' },
  B: { control: 'rm$IFS-rf$IFS/', expected: 'Block' },
  C: { control: '$(echo rm) -rf /', expected: 'Ask' },
  D: { control: 'echo cm0gLXJmIC8= | base64 -d | sh', expected: 'Block' },
  E: { control: 'find /x -delete', expected: 'Block' },
}
const CLASS_IDS = ['A', 'B', 'C', 'D', 'E']

function cleanEntry(id, overrides = {}) {
  const { control, expected } = CONTROL[id]
  return {
    cls: { id },
    huntStatus: 'completed',
    huntReason: null,
    result: {
      candidates: [],
      control_decision: expected,
      control_command_echoed: control,
      hypotheses_tested: [`hypothesis probed for class ${id}`],
      controls_probed: [control],
      dropped_count: 0,
      notes: '',
      ...overrides,
    },
    verdicts: [],
    sliceOverflow: 0,
    overLengthPayloads: [],
  }
}

function deadEntry(id, reason) {
  return {
    cls: { id },
    huntStatus: 'agent_died',
    huntReason: reason,
    result: null,
    verdicts: [],
    sliceOverflow: 0,
    overLengthPayloads: [],
  }
}

function allCleanFixture() {
  return CLASS_IDS.map((id) => cleanEntry(id))
}

test("issue #73's defect 1 (unaccounted agent deaths / the tautological class-conservation law it replaced): 1 completed + 4 agent_died reports incomplete, not clean", async () => {
  const fixture = [cleanEntry('A'), deadEntry('B', 'died'), deadEntry('C', 'died'), deadEntry('D', 'died'), deadEntry('E', 'died')]
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'incomplete')
  assert.match(result.reason, /1\/5 classes completed/)
  assert.equal(result.class_census.filter((c) => c.status === 'completed').length, 1)
})

test("issue #73's defect 2/3, control_ok never wired into the verdict (source's own Fix 1): a weaker-than-expected control fails the run", async () => {
  // Class A expects Block; report it as merely Ask (rank 1 < Block's rank 2)
  // -- a real bypass-side regression on the control itself. Before the fix
  // this issue is pinning, control_ok was computed and logged but never
  // added to failureReasons, so this shape alone used to still return 'ok'.
  const fixture = allCleanFixture()
  fixture[0] = cleanEntry('A', { control_decision: 'Ask' })
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'incomplete')
  assert.match(result.reason, /control regression/)
  assert.match(result.reason, /A \(expected Block, got Ask\)/)
  const censusA = result.class_census.find((c) => c.class_id === 'A')
  assert.equal(censusA.control_direction, 'weaker')
})

test('control drift (stricter than expected) is recorded but does not fail the run', async () => {
  // Only an Ask-expected class (C) can go "stronger" -- a Block-expected
  // class is already at max rank and can never drift stricter. This pins the
  // weaker/stronger asymmetry itself, not just the weaker (failing) side.
  const fixture = allCleanFixture()
  fixture[2] = cleanEntry('C', { control_decision: 'Block' })
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'ok')
  assert.equal(result.control_drift.length, 1)
  assert.equal(result.control_drift[0].class_id, 'C')
  const censusC = result.class_census.find((c) => c.class_id === 'C')
  assert.equal(censusC.control_direction, 'stronger')
})

test("issue #73's defect 4, hollow-completion half (source's own Fix 2): a completed class with no hypotheses_tested fails the run", async () => {
  const fixture = allCleanFixture()
  fixture[1] = cleanEntry('B', { hypotheses_tested: [] })
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'incomplete')
  assert.match(result.reason, /hollow class completion/)
  const censusB = result.class_census.find((c) => c.class_id === 'B')
  assert.equal(censusB.hollow, true)
})

test("issue #73's defect 4, echo-mismatch half (source's own Fix 3): a control_command_echoed that does not match the intended payload fails the run", async () => {
  // The historical shape this guards: a shell mangles a quote-containing
  // payload before the probe ever sees it (e.g. class A's own control,
  // `r''m -rf /`, naively re-quoted becomes `rm -rf /`), so control_decision
  // looks fine while testing an entirely different string.
  const fixture = allCleanFixture()
  fixture[0] = cleanEntry('A', { control_command_echoed: 'rm -rf /' })
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'incomplete')
  assert.match(result.reason, /control payload echo mismatch/)
})

test('all clean: every class completed, controls match, non-hollow, echoes match -> ok with no schema violations', async () => {
  const { result } = await runAggregate(allCleanFixture())
  assert.equal(result.status, 'ok')
  assert.equal(result.reason, null)
  assert.equal(result.schema_violations.length, 0)
  assert.equal(result.class_census.filter((c) => c.status === 'completed').length, 5)
  assert.equal(result.class_census.every((c) => !c.hollow), true)
})

test('a confirmed candidate with a valid expected_decision produces a test_lines entry', async () => {
  const fixture = allCleanFixture()
  fixture[0] = cleanEntry('A', {
    candidates: [
      {
        payload: 'r"m -rf /',
        class_id: 'A',
        intent: 'quote-split merge',
        observed_decision: 'Allow',
        expected_decision: 'Block',
        control_payload: CONTROL.A.control,
        control_decision: 'Block',
        mechanisms: ['A'],
      },
    ],
  })
  fixture[0].verdicts = [
    {
      candidate: fixture[0].result.candidates[0],
      verdict: { outcome: 'confirmed', observed_decision: 'Allow', reason: 'reproduced' },
      error: null,
    },
  ]
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'ok')
  assert.equal(result.confirmed.length, 1)
  assert.deepEqual(result.test_lines, ['("r\\"m -rf /", Decision::Block),'])
})

test('Fix 4 (over-length payload): a candidate payload over the interpolation cap is flagged in schema_violations, without failing the run', async () => {
  // This path doesn't gate `status` (only failureReasons does, and
  // schema_violations isn't wired into it) -- pinned here anyway so a
  // regression in the check itself (e.g. the length comparison or the
  // message text) doesn't ship unnoticed, even though it wouldn't flip a
  // run from 'ok' to 'incomplete'.
  const fixture = allCleanFixture()
  const oversized = 'x'.repeat(2001)
  fixture[0] = cleanEntry('A')
  fixture[0].overLengthPayloads = [oversized]
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'ok')
  assert.equal(result.schema_violations.length, 1)
  assert.match(result.schema_violations[0], /class A: candidate payload is 2001 chars, over the 2000-char verify-prompt cap/)
})

test('null verdict slot (the historical "Change 5 filter(Boolean) deletion" regression) is bucketed inconclusive, not thrown', async () => {
  // bypass-hunt.js:766-767's own comment names this as "the one place
  // Change 5's verdicts.filter(Boolean) deletion matters" -- parallel()
  // can yield a bare null in place of a slot, and the sink must survive
  // destructuring it without crashing the whole aggregation (which would
  // silently drop the census/instrumentation for a run that otherwise
  // completed).
  const fixture = allCleanFixture()
  fixture[0] = cleanEntry('A', {
    candidates: [
      {
        payload: 'whatever',
        class_id: 'A',
        intent: 'irrelevant to this test',
        observed_decision: 'Allow',
        expected_decision: 'Block',
        control_payload: CONTROL.A.control,
        control_decision: 'Block',
        mechanisms: ['A'],
      },
    ],
  })
  // Candidate conservation (candidates_emitted === confirmed+refuted+
  // inconclusive+dropped_by_cap) requires exactly one verdict slot to match
  // the one candidate above -- a null slot still counts toward that sum
  // (bucketed inconclusive), so this fixture must supply one candidate, not
  // zero, or it would trip the UNRELATED conservation-law-2 check instead of
  // isolating the null-slot behavior this test targets.
  fixture[0].verdicts = [null]
  const { result } = await runAggregate(fixture)
  assert.equal(result.status, 'ok')
  assert.equal(result.inconclusive.length, 1)
  assert.equal(result.inconclusive[0].error, 'parallel yielded null verdict slot')
})
