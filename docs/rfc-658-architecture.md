# RFC #658: architecture redesign (policy, knowledge, semantics, syntax)

Design for the tracking issue #658 and its four epics: #659 (policy),
#660 (knowledge), #661 (semantics), #662 (syntax). This is a design
writeup only. Each epic is implemented as a sequence of PRs scoped by the
sections below; none of them starts until this RFC is merged.

## Problem: fixes keep spawning follow-ups

As of 2026-10-13 the tracker holds 387 issues. Fixing one bug reliably
uncovers the next one in the same family:

- About 0.8 to 1 follow-up issue per merged PR, created in bursts by the
  review step.
- Follow-up chains run 3 to 4 deep and do not converge, e.g. #598 → #607
  → #646 → #653, #594 → #606 → #645 → #655, #623 → #625 → #654 → #656.
- High-severity fail-open finds have not slowed: #584, #585, #638 and #639
  were all filed in October.

An estimated root-cause breakdown of the full history (from titles,
labels and a sample of bodies; the counts are approximate):

| Root cause | Issues | Typical direction |
|---|---|---|
| Parser/tokeniser divergence from bash (96 of them fuzz-filed) | ~112 | either |
| Missing command knowledge (wrapper, tool or sink not modelled) | ~50 | fail-open |
| Option-parsing semantics (abbreviation, attached values, `--`, POSIXLY_CORRECT) | ~22 | fail-open |
| State/dataflow (variables, readonly, IFS, cwd) | ~28 | both |
| Path/target normalisation (tilde, glob, `..`) | ~18 | fail-open |
| Recursion into nested code (`-c`, heredoc, eval, substitution) | ~15 | fail-open |
| False positives | ~25 | over-Ask |
| Resource limits, panics, watchdog | ~22 | Block → Ask |

Of roughly 85 fail-open bugs, most sit in the knowledge, option-parsing
and path rows. Those are the rows this redesign targets first.

## Diagnosis: the domain model, not the layering

The layering in plan.md §1.3 mostly holds. `parser.rs` is the only
importer of brush types, symlink resolution is a port with a filesystem
adapter, and wiring happens in `lib.rs` and `bin/shguard.rs`. The defects
are in how the domain is modelled.

1. **The invariant is asymmetric.** plan.md §4 fails closed on what
   shguard cannot *parse*, but fails open on what it does not *know*:
   - A wrapper flag missing from its table falls through to a generic
     dash-skip.
   - An unlisted exec wrapper (`time`, `chroot`: #638) is treated as an
     ordinary command.
   - An unmodelled long-option spelling is treated as an operand (#582,
     #639).

   Each fix closes one spelling and leaves its neighbours open, which is
   exactly the follow-up chain shape above.
2. **Command knowledge is scattered.** `rules/blocklist.toml` says *what*
   is dangerous. *How* to find the real argv, script and target for each
   tool lives in 20+ hardcoded Rust tables:
   - rules.rs: `TRANSPARENT_WRAPPERS`, `ESCALATION_VECTORS`,
     `wrapper_value_flags`, `wrapper_cluster_booleans`,
     `wrapper_positional_args`, `wrapper_shell_string_scripts`,
     `sudo_flag_changes_cwd`, and the TAR and GIT tables.
   - gate.rs: `GIT_PUSH_VALUE_FLAGS`, the fish, awk and inline-interpreter
     grammars, and `OPENSSL_ENC_CIPHER_NAMES`.
   - `sed_script.rs`.

   Adding one wrapper touches about five tables, and missing one is a
   bypass. The TOML cannot be audited on its own.
3. **"Unknown" has no single representation.** Each of these encodes it in
   its own way:
   - `Resolution::Unresolvable`.
   - `Env`'s removed key, `persisting_unresolvable` cut index,
     `value_history`, `ifs_append_floor` and `readonly_unknown`.
   - `CwdContext` poison.
   - `ExceptFloors`.

   gate.rs production code has 38 `*floor*` functions and about 80
   Ask-construction sites, rules.rs has 20 more, and there are 57
   `Reason::new` call sites.
4. **There are two incompatible combining rules.**
   - `fold_worst` keeps the first verdict on a tie and never merges
     reasons.
   - `apply_floor` (gate.rs) concatenates reasons and rebuilds the verdict
     with `matched_rule: None`, dropping rule attribution and the deny
     message.
   - `verdict.rs` documents the resulting deny-message gaps.

   On top of that, `ask_outcome` is applied outside gate in three places:
   `lib.rs` `apply_ask_outcome`, `adapter.rs` `fail_closed_with`, and
   `bin/shguard.rs`.
5. **Syntax leaks into the decision layer.**
   - gate.rs re-lexes heredoc bodies with its own quote-state scanner
     (`collect_heredoc_substitutions`), although brush exposes
     `word::parse_heredoc`.
   - parser.rs carries about 11 bash-compat shims (panic catch,
     io-number neutralisation, raw nesting caps, brace-range pre-check,
     zsh/funsub dollar-form rejection, ...). Some are not quote-aware.
   - Every hand-written lexer is a separate hardening surface.

## Decision: the invariant (spec change)

**Allow requires positive understanding.** For every command in the
knowledge catalog, a command is Allow only if every safety-relevant slot
is known: the command that will execute, any script it runs, its target
paths, and the cwd those paths are composed against.

- The **knowledge catalog** is the set of commands shguard models:
  - transparent and escalating wrappers;
  - shell and inline-code interpreters;
  - every command named by an embedded or user rule.
- For a catalogued command, an option-parse result of "unmodelled" (an
  unknown flag, an unknown abbreviation, an attached value shape the
  grammar does not describe) is **Ask**. This is enforced by type, not by
  convention (see Knowledge).
- Commands outside the catalog stay Allow, as today. An allowlist-only
  product (unknown command → Ask) was considered and rejected:
  - It would close more of the "missing knowledge" row.
  - It changes what shguard is.
  - Over-Ask is already the largest denial complaint (#632 measured 16%
    of denials on one shape).
- This invariant alone does not close #638-class gaps, where a wrapper is
  not classified as a wrapper at all. Those are closed by the exhaustive
  wrapper catalog with a pin test (Knowledge).

The rest of plan.md §4 (position axis, decode-fed interpreter pipes,
`$IFS`, parse failure) is unchanged.

## Module structure

Vocabulary follows `coding-guidelines/principles.md` (domain, boundary,
port, adapter, composition root). The modules are modules of the one
crate, each with a public API and typed seams.

| Module | Owns | Moves from |
|---|---|---|
| `syntax/` | brush adapter, shguard AST, normalisation, `compat` (bash-parity pre-pass), heredoc-body parsing | parser.rs, ast.rs, normalize.rs, gate.rs heredoc scanner |
| `knowledge/` | `CommandSpec` catalog, the option parser, rule and allowlist argv matching, serde-free typed constructors | rules.rs, sed_script.rs, gate.rs git/tar/fish/awk/interpreter tables |
| `semantics/` | abstract interpretation: value, path and cwd domains, `Env` scoping, recursion into `-c` / `$()` / `eval` / `find -exec` | gate.rs traversal, `Env`, `Cwd*`; rules.rs `PathForm` |
| `policy/` | `Evidence`, `decide`, reason and deny-message rendering, `ask_outcome`, the allowlist Ask → Allow downgrade rule | verdict.rs, gate.rs floors and folds, rules.rs `AskOutcomeTable` |
| adapters | hook I/O (`adapter.rs`), config discovery (`config.rs`), serde DTOs (`config_loader.rs`), `fs_canonicalizer.rs`, `decision_log.rs`, `watchdog.rs` | unchanged |
| composition root | `lib.rs`, `bin/shguard.rs` | unchanged |

Dependency direction:

- `policy` owns `Evidence`, because the consumer owns the port. Besides
  its own types and its typed config, it may import only pure vocabulary
  types from `syntax` and `knowledge` (`RuleId`, `UnresolvableKind`,
  `CommandName`). It never imports their logic or anything that does I/O.
- `semantics` imports `syntax`, `knowledge` and policy's types, and
  produces `Evidence`.
- `knowledge` has no I/O and no serde. `config_loader.rs` stays an adapter
  that converts DTOs into knowledge types. That DTO-to-domain duplication
  is the intended boundary shape, which settles the second half of #636.

## Stage 1: Policy (#659), first

### Evidence and decide

```rust
// policy/evidence.rs (shape, not final signatures)
pub enum Evidence {
    RuleMatch { id: RuleId, source: RuleSource, decision: Decision, deny_message: Option<DenyMessage> },
    Unresolved { slot: Slot, kind: UnresolvableKind },
    PathShape { slot: Slot, shape: PathShapeKind },
    CwdUnknown,
    OpaqueConstruct { kind: OpaqueKind },
    UnmodeledOption { command: CommandName },
    EscalationWrapper { vector: Option<CommandName> },
    DecodePipeToInterpreter,
    TokenHit { id: RuleId },
    Recursed { inner: Box<Outcome> },
    ParseFailure { construct: Option<String> },          // shell syntax shguard cannot read
    InputRejected { stage: InputStage },                 // malformed hook JSON, stdin read error, stdin over the cap
    ConfigUnavailable { path: Option<PathBuf>, error: String }, // #630: the reason names the path (None: no path could be resolved)
    ResourceLimit { kind: LimitKind },
    AllowlistMatch { id: RuleId },
    UserAskMatch { id: RuleId },
}

pub fn decide(evidence: &[Evidence], config: &PolicyConfig, ctx: &HookContext) -> Outcome;
```

- **Precedence** is explicit in one match: any Block-grade evidence wins,
  then Ask-grade, and Allow only when no uncertainty evidence is present.
- **The allowlist downgrade** is one rule: `AllowlistMatch` lowers Ask to
  Allow only when there is no uncertainty evidence. Today that condition
  is spread over ten-plus `_present` booleans in `evaluate_simple_command`.
- **`ask_outcome`** is applied inside `decide`. `Outcome` keeps the
  pre-outcome decision, so the decision log can tell a floored Ask from a
  native Block.
- **Reasons and deny messages** are rendered from the evidence list at one
  site. That fixes the attribution loss in `apply_floor`, the gaps
  documented in `verdict.rs`, and the wrong or underspecified reasons in
  #630 and #633.
- **`Recursed`** carries the whole inner outcome, so recursion no longer
  flattens to a bare `Decision`.
- **Fail-closed exit paths** build evidence at the composition root and go
  through the same `decide`, so there is a single decision site rather
  than two:
  - parse failure (`ParseFailure`);
  - config-load failure (`ConfigUnavailable`);
  - malformed hook JSON, a stdin read error, or stdin over
    `MAX_STDIN_BYTES` (`InputRejected`);
  - watchdog trip (`ResourceLimit`).
- **`AnalysisCtx`** `{ rules, allowlist, depth }` (`Copy`; `cwd` and `Env`
  stay parameters because they are re-seeded or mutated per recursion)
  carries no parse function. The injected parse function (a `ParseFn` type threaded through
  38 signatures) was deleted per #636: `gate` calls `parser::parse`
  directly, and brush stays sealed inside the parser module, so the
  injection was over-abstraction. The context struct addresses #619's
  `too_many_arguments` item.

### Gate for stage 1

Stage 1 is a behaviour-preserving refactor, gated by a **golden
snapshot**:

1. First PR: record `command → (Decision, matched_rule, deny_message)`
   from `main` for every command in these corpora, under `tests/golden/`:
   - `tests/guardfall.rs`, `tests/bypass_corpus.rs` and
     `tests/benign_corpus.rs`;
   - the fuzz corpus, generated with a pinned `SHGUARD_FUZZ_SEED` so it is
     reproducible;
   - the #632 denial corpus, if it is still available.

   The recorded Decision is `analyze()`'s, which is before `ask_outcome`
   is applied. Per-permission-mode outcomes stay covered by the
   `tests/ask_outcome_per_mode.rs` fixtures.
2. Every later stage-1 PR must match the snapshot exactly on Decision.
   Changes to `matched_rule` and `deny_message` must be intentional and
   reviewed in the snapshot diff. Some are expected, because restoring the
   attribution that `apply_floor` drops is one of the stage's goals.
3. Reason-pin tests (`*_reason_is_pinned`, the JSON assertions in
   `tests/hook_io.rs` and `tests/adapter_smoke.rs`) are updated in the same
   stage, and reason-text changes are noted in the CHANGELOG.
4. `tests/fail_closed_exit_paths.rs` and `tests/ask_outcome_per_mode.rs`
   must pass unchanged in Decision.

The old and new paths are not kept side by side. The snapshot is the
oracle.

**Stage 1 reduces fail-open by zero.** It was deliberately ordered first
so that later stages add evidence variants to one decision site instead of
adding floor function number 39. The first security gain is stage 2.

## Stage 2: Knowledge (#660)

```rust
// knowledge/spec.rs (shape)
pub struct CommandSpec {
    names: &'static [&'static str],
    options: OptionGrammar,  // short, long, value arity, cluster rules, abbreviation, dialects
    slots: &'static [Slot],  // Exec, Script, Target, CwdEffect, Privilege
}
```

- **One spec per command.** The seven wrapper tables collapse into
  `CommandSpec` entries: `TRANSPARENT_WRAPPERS`, `ESCALATION_VECTORS`,
  `wrapper_value_flags`, `wrapper_cluster_booleans`,
  `wrapper_positional_args`, `wrapper_shell_string_scripts` and
  `sudo_flag_changes_cwd`. A wrapper is added in one place.
- **One option parser.** It is getopt_long-equivalent and handles:
  - short clusters and attached values;
  - unique-prefix long-option abbreviation;
  - `--`;
  - GNU permutation versus POSIXLY_CORRECT first-operand termination;
  - per-dialect differences (GNU, BSD, busybox, toybox).

  It returns `Result<ParsedArgv, Unmodeled>`, and `Unmodeled` converts
  only into `Evidence::UnmodeledOption`. Invariant B is enforced at this
  type.
- **An exec-wrapper catalog pinned against a committed reference list.**
  The list is hand-curated from the coreutils, util-linux and busybox
  commands that take a command operand, and committed as
  `rules/reference/exec-wrappers.txt`. A test fails when a listed command
  has no `CommandSpec`, which closes the #638 class for every command on
  the list. The test cannot discover new upstream wrappers, so the list is
  re-audited at each release and whenever a wrapper bypass is filed.
- **Migration order inside the stage:**
  1. wrappers;
  2. the tar and git tables;
  3. the sed CLI (the sed script lexer in `sed_script.rs` stays a
     knowledge-owned language lexer);
  4. the awk and fish CLI scanners;
  5. the inline-interpreter grammars.

### Gate for stages 2 to 4

The gate is a two-sided differential against the golden snapshot,
re-recorded at the end of stage 1:

- **Bypass side:** never more Allow than the snapshot on `guardfall.rs`,
  `bypass_corpus.rs` and the fuzz corpus.
- **Benign side:** never more Ask than the snapshot on `benign_corpus.rs`
  and the #632 denial corpus, unless each new Ask is listed in the PR and
  approved. Invariant B is expected to add some, for example obscure flags
  on `sudo` or `env`.

## Stage 3: Semantics (#661)

- **Three abstract domains**, each with a written join, documented before
  any floor function is deleted:
  - *value*: a set of known strings or Top, per variable;
  - *path*: a normalised path form, or a shape class such as ascent,
    named home, dirstack tilde or glob, or Top. rules.rs `PathForm` is the
    seed.
  - *cwd*: initial, a known anchor, or poisoned.

  The current floor families map onto these:
  - path-shape floors map to the path domain;
  - unknown-cwd and dirstack floors map to the cwd domain;
  - opaque-kind and substitution floors map to the value domain.

  A flat `Known(set) | Top` is not enough on its own. Which assignments
  reach a use depends on bash scoping, so scoping is modelled first.
- **Explicit `Env` scoping.** The scopes to model are:
  - subshell versus persisting;
  - pipeline and background boundaries;
  - function bodies;
  - `readonly`, including the forms behind `builtin`, `command` and
    `eval` (#653).

  This makes the #607 cut index a property of the model rather than a
  patch.
- **False positives expected to move Ask → Allow:** #632 (same-line
  literal bindings), #629 (a `while read` final stage) and the
  input-process-substitution half of #628. These are approved benign-side
  deltas. #628's other half goes the other way: output process
  substitution into an interpreter becomes a pipe-to-interpreter sink, so
  it can tighten.

## Stage 4: Syntax (#662); investigation runs in parallel

- **Heredoc bodies are parsed into the AST** via `word::parse_heredoc`,
  retiring gate.rs `collect_heredoc_substitutions`, `scan_paren_span` and
  `scan_backtick_span`. This addresses #631 and the heredoc half of #655.
- **The bash-compat shims move into `syntax::compat`.** They are rebuilt as
  a pre-pass over brush's `tokenize_str` spans (`Token::Word(_, span)`),
  so no shim is quote-blind. Today the byte-level io-number neutralisation
  in parser.rs is quote-blind, which is a disclosed limitation. The panic catch stays as the last line of
  defence for the panics inside brush's PEG grammar (brace sequence,
  tilde dirstack, io-number).
- **Parser strategy:** brush-parser stays pinned at `=0.4.0`, the latest
  stable version. `brush-ocap-parser 0.5.0-rc.1` is a pre-release and a fork
  is rejected for its maintenance burden; see
  [ADR 0003](adr/0003-brush-parser-stay-on-0.4.0.md) for the decision, the
  re-check triggers and the crates.io check dated 2026-10-18. The
  `src/parser.rs` fixture corpus remains the upgrade gate.
- **The differential fuzzer is extended** to heredoc bodies and compound
  commands. It already uses real bash as the oracle per simple command.
- **Issues:** #655 (double-dollar brace tokenisation; its high-severity
  item is patched individually before this stage, see Triage), #627,
  #631, #634.

## Triage rule during the redesign

- A new follow-up that is an instance of a family covered by an epic is
  added to that epic's task list instead of being fixed on its own.
- Only **critical or high fail-open** findings are patched individually
  ahead of their epic. The patch is minimal and leaves a test that the
  epic's implementation must keep green.
- Medium and low findings, false positives, and refactor or doc nits wait
  for the epic, which is expected to resolve them structurally.
- False positives carry the `false-positive` label across epics.

## Explicitly deferred, not silently dropped

- Cross-invocation session state (RFC #104) is unchanged by this RFC. The
  semantics domains are designed so that seeding from session state can
  later be expressed as a join, never a replacement, as RFC #104 requires.
- Additional agent adapters (RFC #105) are unaffected. They consume the
  same `Outcome` through the adapter layer.
- An allowlist-only mode (unknown command → Ask) is not planned. If it is
  ever wanted, it is one more `PolicyConfig` switch over the same evidence,
  not a new code path.
