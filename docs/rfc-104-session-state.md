# RFC #104: opt-in session state tracking

Design for issue #104: cross-invocation memory of `export`/`alias`/
function definitions, and cross-invocation `cd`-established cwd, gated
behind an opt-in config flag. This is a design writeup only -- no code
in this document; an implementation issue should be filed separately
once this design is agreed, scoped by the sections below.

## Headline contract: session state is additive-only

Every consumer of session state MUST go through the gate's existing
additive-only contracts: `Env`'s rule-2 resolutions (which "only ever
upgrade Ask to Block", per `Env::apply_one`'s own docs), and `CwdState`'s
compose-and-`fold_worst` (which never lowers a decision the uncomposed
evaluation already reached, per `CwdContext`'s own docs). Stated as a
requirement the implementation issue must carry a property test for:

> For any session state `S` and command `C`:
> `decision(C, S) >= decision(C, SessionState::empty())`.

This single invariant is both the poisoning defense (see the threat-model
pass below) and the no-regression guarantee: absent, stale, lost, or
attacker-fabricated state can only push decisions toward Ask/Block, never
toward Allow. "State missing" is never "known safe"; it is exactly
today's documented baseline.

## Storage and lifetime

shguard is a fresh one-shot process per `PreToolUse` invocation
(`src/bin/shguard.rs`'s own module docs; no daemon), so in-process state
is impossible -- state persists to disk.

- **Location**: `$XDG_STATE_HOME/shguard/sessions/<session_id>.json`
  (fallback `~/.local/state/shguard/sessions/`). Directory created
  `0700`, files `0600`. One JSON file per session (`serde_json` is
  already a dependency), carrying a `schema_version`; an unknown version
  is treated as absent.
- **Key**: the `PreToolUse` payload's `session_id` field, present today
  and deliberately ignored (`src/adapter.rs`'s "Verified stdin/stdout
  schema" doc). Sanitized before use as a filename: must match
  `[A-Za-z0-9_-]{1,128}`, else tracking is disabled for that invocation
  (today's baseline behavior, plus a stderr warning). Per plan.md
  section 0.2's own convention, the implementation issue re-verifies the
  field's exact name and semantics against the hook docs first.
- **Lifetime/eviction**: keying by the host's own `session_id` delegates
  session-boundary semantics to the host. A new, resumed, or cleared
  session gets whatever id Claude Code assigns; an id shguard has never
  seen loads `SessionState::empty()`. No boundary tracking of our own.
  Orphaned files are pruned opportunistically at load time by mtime TTL
  (a constant, e.g. 14 days). Per-file caps: a read size cap (e.g.
  1 MiB) and bounded entry counts (e.g. 512 env names, 256 functions,
  256 aliases); on overflow the store sets a `saturated` flag meaning
  "every name assigned, no values resolved" -- maximal-caution
  over-asking, never silent eviction.
- **Concurrency**: parallel Bash calls in one session mean concurrent
  read-modify-write of the same file. Atomic temp-file-plus-rename in
  the same directory; last-writer-wins. A lost update loses one
  command's severity-raising entries and degrades toward baseline,
  which the invariant makes safe. Rejected: `flock`. A hung lock would
  trip the evaluation watchdog and turn every command into fail-closed
  Ask, a worse trade than a lost update.

## What gets tracked

Recorded from the top level of every analyzed command line at
`PreToolUse` time, including commands that end up Blocked or
human-denied and never actually run: this "phantom state" can only
over-raise a later decision (the invariant makes this safe). Rejected:
recording via a `PostToolUse` hook -- a second hook registration, and it
would not fire on denial anyway.

1. **Persistent variable assignments.** Standalone `NAME=value` and
   `export NAME=value` at top level (NOT command-scoped prefix
   assignments, which do not persist in real bash either). Stored as
   `Resolved(value)` or `AssignedUnresolved`, mirroring `Env`'s own
   `map`/`assigned` split; an unresolvable RHS records the name only. On
   the next invocation these seed the fresh `Env`: a session-resolved
   `FOO=rm` upgrades a later `$FOO -rf /` from Ask to Block; a
   session-assigned `HOME`/`CDPATH` trips the existing `was_assigned`
   poisoning guards the same way a same-line assignment already does.
2. **Function definitions.** Name mapped to the body's eagerly-evaluated
   worst verdict (already computed and folded today by
   `evaluate_function_definition`, issue #75). The cross-invocation gap
   this closes: a body that Asks (unresolvable), gets human-approved,
   and is then invoked by bare name in a LATER, separate command --
   which today Allows, since an unknown, no-rule-match command defaults
   to Allow. A later top-level command whose name matches a tracked
   function floors its decision to the recorded body verdict, worst-wins
   against the baseline evaluation of that command.
3. **Aliases.** `alias name='expansion'` at top level, same
   Resolved/AssignedUnresolved shape as variables; a later matching
   command name floors worst-wins against the expansion's own
   evaluation. Non-interactive shells may never expand aliases in
   practice, but the false-positive cost of tracking one anyway lands
   only on a session that aliased a dangerous expansion in the first
   place.
4. **Cross-invocation cwd: explicitly in scope.** A `cd` on one line
   followed by a relative-path command on a LATER line falls through
   issue #103/#210's own same-line-only scope, and would otherwise fall
   through this RFC's scope too if left unaddressed -- so it is
   addressed here rather than left as an implicit gap between the two
   issues. Persisted as the end-of-line `CwdContext`
   (`Known(path)`/`Poisoned`) plus a `stack_may_be_nonempty` flag (set
   if any `pushd` was seen this session). The next invocation's
   top-level seed becomes `CwdState::seed(session.cwd)`, or
   `seed_unknown_stack` when the flag is set (honestly modeling the
   persistent shell's inherited `DIRSTACK`), instead of today's
   unconditional `seed(CwdContext::Initial)`. Missing state still seeds
   `Initial` (today's behavior, unchanged when the feature is off or the
   session is new). The `PreToolUse` payload's own `cwd` field is NOT
   built on here -- whether Claude Code updates it per persistent-shell
   `cd` is unverified; the implementation issue should verify this
   empirically and, if it turns out reliable, add it only as a
   cross-check that POISONS on mismatch, never as a resolution source on
   its own.

## Opt-in shape

One flat top-level config key, matching the existing `decision_log_path`
and `escalation_floor` schema style: `session_tracking = true` (TOML,
`~/.config/shguard/config.toml`). Default `false`. When off (the safe
default), the state code path is never entered at all: no file reads, no
writes, no directory creation; `analyze`, `analyze_with_policy`,
`handle`, `handle_with_policy`, and `shguard check` all stay
byte-for-byte today's behavior. No further knobs in v1 -- state
directory, TTL, and caps stay fixed constants rather than becoming
config surface.

## Failure modes: fail closed to baseline

Unreadable, corrupt, oversized, version-mismatched, or missing state all
load as `SessionState::empty()` plus a stderr warning; the invocation is
then evaluated exactly as it would be today. A tracked name is simply
*unresolved* in that case -- never "known safe", never "known whatever
it last was". A failed save (disk full, permissions) warns on stderr and
never alters the verdict that was already computed. State load happens
inside `run()`, inside the existing evaluation watchdog and size-capped
the same way; the save happens after the bounded analysis returns,
following `decision_log::append`'s own precedent -- including that
precedent's disclosed residual risk that a hanging write could trip the
outer hook watchdog into a fail-closed Ask.

## Threat-model pass

**Can an agent poison tracked state to launder a later dangerous command
down to Allow? No, by construction.** Every attack considered reduces to
the headline invariant above:

- `export SAFE=echo`, later `$SAFE "rm -rf /"`: a session resolution can
  only ever *upgrade* a decision; the bare-`$VAR` command-position Ask
  floor still stands regardless. There is no code path where a resolved
  value alone produces Allow -- the same contract same-line `Env`
  resolution already has today.
- Defining a benign-looking `ls() { :; }` hoping a "known-safe body"
  downgrades a later `ls` invocation: tracked functions are only ever
  worst-wins floors layered ON TOP of the baseline evaluation of the
  literal command -- they cannot suppress or override it.
- Writing the state file directly (`echo ... > ~/.local/state/shguard/...`):
  fabricated entries can only ever over-block. This is a self-inflicted
  denial of service, not a privilege escalation. (Optional hardening:
  add the session-state directory to the protected-write-path list; not
  required for soundness given the invariant above already holds.)
- Cross-session contamination or session-id forgery: the id comes from
  Claude Code's own payload, not from anything inside the analyzed
  command; filename sanitization blocks path traversal; and even a
  wrongly-matched file can only ever raise severity, never lower it.
- Phantom state recorded from a command that was denied and never ran: a
  wrong `Known` cwd or env entry can at worst cause a missed upgrade
  later, never a drop below baseline.

**New attack surface this DOES introduce: secret persistence.** `export
GITHUB_TOKEN=ghp_...` would persist that value in plaintext session
state. Mitigations: `0700`/`0600` permissions restrict read access to
the owning user; the TTL bounds how long exposure lasts; and names
matching `TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL` (case-insensitive) are
recorded as `AssignedUnresolved` with the value itself dropped, which
stays safe under the invariant (it costs only a missed future upgrade,
never a downgrade). This continues the same disclosed trade-off
`decision_log_path` already accepts (an existing opt-in feature that
writes raw commands to disk) -- README and threat-model.md should carry
a matching disclosure for this feature.

## API shape

`analyze()` itself stays pure; statefulness is threaded explicitly,
never hidden behind global mutable state, so the core stays testable.
File I/O stays at the edges (composition root and a dedicated store
module), exactly where `config.rs`'s own I/O already lives today.

- **New module `src/session.rs`**:
  - `pub struct SessionState { env, functions, aliases, cwd, saturated }`
    -- pure serde data, with `SessionState::empty()`; no I/O.
  - `pub(crate) struct Store` -- path resolution, filename sanitization,
    TTL prune-on-load, size caps, atomic save.
    `Store::load(&session_id) -> SessionState` (every failure loads
    `empty()` plus a warning) and `Store::save(&session_id,
    &SessionState)`.
- **`src/gate.rs`**: `analyze_at_depth` already threads `CwdState`
  through recursion; the TOP-LEVEL entry point additionally seeds `Env`
  from `SessionState.env` and collects the top-level effects
  (assignments, definitions, aliases, final cwd) into the returned next
  state. Recursion boundaries stay untouched -- session state enters
  only at the same top-level seed point `CwdContext::Initial` enters at
  today.
- **`src/lib.rs`**: new
  `pub fn analyze_with_session(command: &str, policy: &Policy, session:
  &SessionState) -> (Verdict, SessionState)`, taking state in and
  returning the verdict plus the complete next state (the caller just
  persists whatever it's handed back). Wrapped in the existing watchdog
  the same way its siblings are; `analyze` and `analyze_with_policy`
  stay unchanged, as an additive new entry point.
- **`src/adapter.rs`**: `HookInput` gains `session_id: Option<String>`,
  exposed via `pub fn extract_session_id(stdin: &str) -> Option<String>`
  (this module already owns every Claude-Code-specific field name per
  its own module doc), plus a `handle_with_session(stdin, &Policy,
  &SessionState) -> (Value, Option<SessionState>)` sibling to the
  existing `handle`/`handle_with_policy` functions.
- **`src/bin/shguard.rs`** (`run()`): when `policy.session_tracking` is
  set and `extract_session_id` yields a valid id, the composition root
  does `Store::load`, `handle_with_session`, `Store::save`, then emits
  as usual. Otherwise the existing path runs completely untouched.
- **`src/config.rs`**: `Policy` gains `session_tracking: bool` (default
  `false`); `UserConfigFileDto` gains the matching optional TOML key.
- **`src/watchdog.rs`**: `bounded` gains a variant taking a fallback
  next-state value; on a timeout trip the verdict is the usual
  fail-closed Ask and the returned next state is the INPUT state,
  unchanged -- a trip reveals nothing reliable about the command's real
  effects, and leaving state unchanged only risks a missed upgrade
  later, which the invariant makes safe.

Suggested implementation slicing, each phase carrying its own
`decision(C, S) >= decision(C, empty)` property test: (1) `session.rs`
plus the config key and env-only plumbing, (2) functions and aliases,
(3) cross-invocation cwd seeding.
