# Contributing

## The differential fuzzer (`tests/fuzz_differential.rs`)

shguard's whole pitch (README "What it is") is that it decides by
*interpreting what bash will actually execute* — real tokenisation and
static normalisation, not regex matching. [The regression
table](README.md#the-regression-table) pins that claim against known
bypass classes someone already thought to write down. The differential
fuzzer exists to catch the ones nobody has written down yet: it generates
candidate command strings structurally (nesting/combining the same
mechanisms the regression table's classes use — quote-splitting, ANSI-C
escaping, `$IFS` splitting, brace alternation, tilde forms, variable
indirection), computes shguard's normalised argv for each, computes bash's
*real* post-expansion argv for the same text via an actual sandboxed bash
invocation, and flags any place the two disagree.

A divergence matters most when shguard's argv is fully **resolved** (not
`Unresolvable` — an `Unresolvable` word is shguard correctly declining to
guess, never a divergence) but doesn't match what bash actually produces,
and *especially* when shguard's decision was **Allow** for that candidate:
that's the dangerous direction, where shguard let something through based
on a wrong assumption about what bash would run.

Read `tests/fuzz_differential.rs`'s own module doc before touching the
harness — it covers the sandbox's safety design (PATH-shim, static
reject-list, why the capture technique never executes a candidate as a
real command) and the pipe-stage scoping decision (per-simple-command argv
only, never full pipeline runtime) in more depth than this file repeats.

## Triaging a fuzzer-found divergence

The nightly workflow (`.github/workflows/fuzz-nightly.yaml`) auto-files a
GitHub issue labelled `fuzz-divergence` when it finds a divergence the
harness doesn't already track. The issue body has everything you need to
reproduce without re-running the fuzzer: the exact candidate string,
shguard's normalised argv, and bash's real argv.

### 1. Reproduce locally

Copy the candidate string out of the issue body and replay it directly —
`SHGUARD_FUZZ_SEED` alone won't reproduce a specific finding, since the
mutator's own template/mechanism pool can change between the run that
found it and the run reproducing it:

```bash
SHGUARD_FUZZ_REPLAY='<the exact candidate string from the issue>' \
  cargo test --test fuzz_differential differential_fuzz_shguard_vs_bash_argv -- --nocapture
```

This runs just that one candidate through the same classify → capture →
compare pipeline as the full sweep, and prints the same `DIVERGENCE`
diagnostic if it still reproduces.

### 2. Decide which bucket it falls into

- **(a) A genuine new bypass class.** shguard's normalisation or rules
  genuinely disagree with bash in a way that could let something dangerous
  through (or, conversely, block something harmless that should be
  allowed). Fixing this means changing `src/` — out of scope for the PR
  that found it (the fuzzer harness lives entirely under `tests/`/`fuzz/`;
  it never touches `src/`). File a new GitHub issue (or link the
  auto-filed one, since it's already the right shape) describing the
  candidate, the divergence, and which `src/` module looks responsible
  (usually `src/normalize.rs` for a resolution-shape bug, `src/rules.rs`
  or `src/gate.rs` for a decision-logic bug). A fable-reviewed PR fixes it
  from there, same as any other rules/normalize change per this repo's
  process.
- **(b) shguard being stricter than necessary.** The divergence is real,
  but the direction is safe (bash resolves to something LESS dangerous
  than shguard assumed, or shguard's decision was already `Ask`/`Block`
  and stays that way) — a false-positive candidate for relaxing, not a
  bypass. Same process as (a): file or link a separate issue: this repo's
  process is issue-tracked, and "loosen a rule" changes still warrant
  their own scoped PR and fable review like any other rules change.
- **(c) A harness bug.** The divergence doesn't survive scrutiny — e.g. the
  capture technique itself mis-parsed something, or a generator mechanism
  produced a malformed candidate. Fix `tests/fuzz_differential.rs` itself;
  this can be its own PR in this same repo, no `src/` change and no
  followup issue needed. `tests/fuzz_differential.rs`'s own commit history
  has real examples of this class of fix (a NUL-count-prefix rewrite of the
  argv-capture technique, after an earlier heuristic silently miscounted a
  genuinely empty trailing argument as a split artifact) — if you're
  fixing a similar counting/parsing edge case in the harness, that's this
  bucket.

### 3. Once (a) or (b) is fixed upstream: pin the case

Once the `src/` fix (or rules-config relaxation) lands, the specific
candidate that found it should become a permanent regression case so it
never regresses silently again — mirroring how `tests/guardfall.rs`'s
existing pinned cases already reference the issue number that motivated
them (e.g. "issue #65: `//dev/sda` lexically normalizes to `/dev/sda` —
the old byte-exact `prefix = "of=/dev/"` target missed it").

- If the fix is a decision change (a command that now correctly
  Blocks/Asks/Allows), add it to the relevant table in `tests/guardfall.rs`
  — a new row in an existing `cases` array if it fits an existing test's
  theme, or a new `#[test]` function (table-driven, matching that file's
  own style) if it's a new class entirely.
- If the fix is specifically about argv *shape* (an extra/missing/reordered
  word rather than the resulting decision), a normalize.rs unit test
  (`src/normalize.rs`'s own `#[cfg(test)] mod tests`) may be the more
  precise place to pin it, alongside — not instead of — a `guardfall.rs`
  end-to-end pin for the resulting decision.
- Either way, reference the issue number in a comment the same way the
  existing pins do, so a future reader can find the "why" without having
  to re-derive it from the diff alone.

## Ingesting an externally-documented bypass class

Everything above is about cases *this repo's own tooling* finds (the
differential fuzzer, `.claude/workflows/bypass-hunt.js`'s hunt/verify
agents). A distinct, second provenance channel exists for bypass techniques
documented *outside* shguard's own tooling — a published bypass catalog, a
comparable tool's writeup, a CVE against a similar command-gating control —
where the source citation is itself part of the value, not just the payload.

That channel is `tests/bypass_corpus.toml` (issue #94), not
`tests/guardfall.rs`: internally-discovered cases (this file's own fuzzer
findings, hunt-harness findings) go in `guardfall.rs`, each citing the
issue/PR that motivated it; externally-documented cases go in the corpus,
each citing its outside source. `tests/bypass_corpus.rs` asserts every
corpus entry deterministically against `shguard::analyze`, and the
bypass-hunt hunt/verify agents read the corpus alongside `guardfall.rs`/
`benign_corpus.rs` so a corpus-covered payload is never re-reported as new.

The ingestion rule, meant to be a standing contribution path rather than a
one-time sweep: **found a publicly documented bypass technique not already
covered by the GuardFall catalog or an existing case? Add one `[[case]]`
entry to `tests/bypass_corpus.toml`, citing the source** (see that file's
own header for the exact schema — `payload`/`expected`/`source` required,
`note` optional). Two outcomes are both valid, matching the triage split
above:

- **The payload is already handled correctly.** Add it with its actual
  decision as `expected` — a passing corpus entry documenting that shguard's
  existing rules already cover a real, externally-attributed bypass shape
  is a genuine deliverable, not a no-op.
- **The payload exposes a real gap.** Don't silently add a case pinning the
  wrong decision, and don't fold an `src/` fix into the same change that
  adds the corpus entry — file a separate GitHub issue for the gap (the
  same "fix upstream first, pin the regression after" split as the fuzzer
  workflow above), and either leave the payload out of the corpus until the
  fix lands, or note in the PR/issue why it was logged out of scope instead
  (e.g. it relies on session/multi-command state shguard doesn't track —
  see issue #104 — or falls outside shguard's stated destructive/
  self-protection scope entirely rather than being a fixable gap).

### Known-open findings from this harness's own default run

Two findings are already tracked directly in `tests/fuzz_differential.rs`
(bucket (a) candidates, not yet filed as their own tracked issues at the
time this file was written) — see that file's `known_gap_*` `#[ignore]`d
tests for the full reproducer and reasoning:

- An unquoted, empty brace-alternation member (`{a,}`/`{,x}`) is kept in
  shguard's normalised argv as a real `Resolved("")` word, but real bash
  elides a fully-unquoted empty word from argv regardless of which
  expansion produced the emptiness.
- An unquoted `$IFS` reference glued directly against a brace group (no
  literal text or whitespace between them, e.g. `echo$IFS{Y,}`) makes real
  bash produce a word count that a manual trace of the documented expansion
  order doesn't predict — confirmed independent of the harness's own
  capture code, but the underlying bash mechanism itself isn't diagnosed
  yet.

Run `cargo test --test fuzz_differential -- --ignored` to see both directly.
