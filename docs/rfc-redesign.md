# RFC: evaluation-core redesign (coverage witness, one context, policy as data)

Design for replacing the evaluation core (`src/gate.rs` and the name tables
in `src/rules.rs`) in one rewrite series. It builds on RFC #658
(`docs/rfc-658-architecture.md`) and supersedes its unfinished stages for
the gate. Open issues were triaged against this RFC on 2026-10-20; their
Triage comments name the stage (R0 to R4) that resolves them.

Status: accepted by the owner on 2026-10-20. shguard has one user today
and will be released commercially later, so a large rewrite that closes
many issues at once is preferred over incremental patches.

## Problem

About 170 bypass or over-Ask bugs have been filed, about 110 of them
fail-open (Allow on a dangerous command). Roughly 60 of the first 200
issues are titled "Follow-up from #N": a fix pins the reported spelling
and the review finds the neighbouring one. On main at 1ea7aa8, with an
empty config (`SHGUARD_CONFIG=/dev/null`), all of these are Allow:

- `unknowntool rm -rf /`, `lxc exec c -- rm -rf /`, `mosh host rm -rf /`
- `timeout 5 lxc exec c -- rm -rf /`, `echo / | xargs rm -rf`
- `cd / && git -C etc add passwd`
- `split --filter='rm -rf ~' f`, `nu -c "rm -rf /"`
- `GIT_SSH_COMMAND='rm -rf ~' git fetch`, `PROMPT_COMMAND="rm -rf /" bash -i`
- `git config alias.x '!rm -rf /'`, `tmux bind-key x run-shell 'rm -rf /'`

The code is also too large to change safely. `gate.rs` (24,367 lines) and
`rules.rs` (19,180) are 64% of `src/`. `evaluate_simple_command` and its
core are about 1,200 lines with 38 early returns. Command names are
hard-coded at about 94 sites, more than the 86 catalog entries.

## Root causes

- **RC1: Allow is the absence of a finding.** `fold_floors` starts at
  `Decision::Allow` (gate.rs:5433) and only raises. A name outside the
  catalog is an ordinary leaf (knowledge/mod.rs:36). Every check that
  gates Allow is a `bool` recogniser whose miss counts as safe
  (`is_interpreter_sink`, `is_gated_stdin_sink`, `is_stdin_alias_path`,
  the interpreter name tables). The set of tools is open, so adding names
  one at a time never converges.
- **RC2: context is re-chosen per construct.** There are 13 recursion
  entry sites and 5 separate cwd mechanisms. `AnalysisCtx` carries
  neither cwd, stdin provenance, IFS state nor user rules, so each site
  picks them again. `evaluate_dash_c_override` restarts from
  `CwdContext::Initial` (#830). A new context fact does not fail
  compilation at the sites that forget it.
- **RC3: policy lives in code position.** 36 floor functions, a 25-term
  OR-chain decides what `[[allow]]` may downgrade (gate.rs:3600-3625),
  and only `escalation_floor` and `ask_outcome` are data. Strictness
  cannot be tuned, and every structural fix is a large edit, which is why
  RC1 and RC2 were patched per spelling.
- **RC4: code that flows through a same-line file or a persisted setting
  is invisible.** `printf 'rm -rf ~' > x.sh && bash x.sh`,
  `curl -o x.sh URL && sh x.sh`, `git config alias.x '!...'`,
  `gh alias set`, `tmux bind-key ... run-shell`, `core.hooksPath`: the
  write and the run are on one line, but nothing connects them.
- **RC5: parser divergence from bash.** About 25 issues, 6 of them
  fail-open, come from shguard's own lexer disagreeing with bash. Any
  judgement over a node bash parses differently is worthless.

## Threat line

The unit of judgement is the command line. Text on the line in a
language shguard reads (bash and zsh words, `-c` strings, eval, trap,
heredocs, substitutions, catalogued inline-code options, persisted
setting values) is recursed. Text on the line that it cannot read is
Unknown. Content off the line (pre-existing files, repo config, network
bodies, built binaries, what a program does once started) is out of
scope. A path written on the line and then read as code on the same
line is Unknown (RC4).

An Allow means "every node was read and no shell re-entry was seen",
not "the command is harmless". README and `docs/threat-model.md` must
say so.

Shells: no shell detection. Every line is judged as possibly bash or
zsh, and both builtin row sets always apply (decision of 2026-10-14 in
#666). A narrowing config knob may come later.

## Design

### Coverage witness per node

The syntax layer numbers every executable node (`NodeId`): simple
commands, assignment words, redirections, substitutions, heredoc bodies,
and every argv spliced out of a wrapper, `xargs`, `find -exec` or
`env -S`. It reports the node count.

```rust
pub(crate) enum Classified { Witness(NodeId, Roles), Unknown(NodeId, UnknownKind) }
// UnknownKind: Command | Subcommand | Option | Operand | Env | Stdin | Cwd
//              | Names | PersistedCode | Parse
```

`Witness` has a private constructor in `knowledge/`. `policy::decide`
returns Allow only when the witness count equals the node count and no
Ask or Block evidence exists. `Verdict::allow` is called from `decide`
only.

Witnesses are minted only for bare names under a PATH-trust assumption
(argv0 is looked up in a PATH the line did not change). `./x`,
`/tmp/x/rm` and other path-spelled commands are `Unknown(Command)`
unless an audited path leaf matches (R4). Witnesses are minted only over
node kinds in the bash-oracle parity set; any other node is
`Unknown(Parse)` (RC5).

### Catalog as data

One `CommandSpec` row per name in `rules/catalog.toml`, loaded through
the same DTO path as `rules/blocklist.toml`. Row kinds share one schema:
wrappers and interpreters (today's 86), leaves (about 120 coreutils and
dev tools), builtins (bash and zsh: `hash -p`, `mapfile -C`,
`compgen -C`, `printf -v`, `declare -n`, `bind -x`, `complete -C`,
`enable -f`, zsh `emulate -c`, `sched`), and every command a rule names.
A rule names a dangerous shape; it is not proof that shguard understands
the tool, so rule-named commands need rows too.

Fields:

- `names`, `reads_stdin = never | data | code`,
  `produces = data | code | network | decoded`
- `options` (a grammar, or `opaque` for leaves without subcommands)
- `code_options`: `split --filter`, `sort --compress-program`,
  `fzf --preview`, `rsync -e`, `tar --to-command`, `git -c`,
  `cargo --config`, `npm --script-shell`
- `code_subcommands`: `gh alias set`, `sqlite3 .shell`, `tmux bind-key`
- `subcommands = closed` by default; `open` only on embedded rows with a
  written justification
- `global_options`: a grammar for subcommand tools, so `git -c` or
  `cargo --config` before the subcommand is read
- `env_code`: `GIT_SSH_COMMAND`, `GIT_PAGER`, `LESSOPEN`, `MANPAGER`
- `reads_files`: `make` reads `Makefile`
- `persists`: `git config alias.*|core.hooksPath|core.pager`,
  `gh alias set`, `crontab`
- `cwd_effect`, including relocations no option triggers (chroot,
  pkexec, systemd-run)

Assignment words get roles. A standalone `S=/tmp/x` is a value binding.
A command-prefix `NAME=v cmd` is `env_code` of the row (recursed), a
name in the universal poison table (`PATH`, `LD_*`, `DYLD_*`,
`BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `IFS`, `CDPATH`, `HOME`) is
`Unknown(Env)`, a name in the closed inert set (`CARGO_TARGET_DIR`,
`RUST_LOG`, `NO_COLOR`, `TMPDIR`, ...) is witnessed, and anything else
is `Unknown(Env)`.

A build test asserts that leaves do not overlap wrappers, interpreters,
rule-named commands or builtins.

### One context, one recursion entry

```rust
struct Context<'a> {
    cwd: CwdContext, stdin: StdinProvenance, names: NameTrust,
    written: WrittenPaths, env: &'a Env, ifs: IfsState,
    rules: &'a Rules, user: &'a UserRules, depth: Depth,
}
fn evaluate(code: CodePayload<'_>, ctx: Context<'_>) -> Outcome
// CodePayload::{ShellString, Argv, Stdin}
```

No field is optional, so a new fact fails compilation at every
constructor. `evaluate` is the only recursion entry and the only place
depth increases. `spec.transform(ctx)` applies the row's `cwd_effect`,
privilege change, stdin and name poisoning (`hash -p`, `enable -f`,
`PATH=`, `alias`, function definitions, `command_not_found_handle`).
Poisoned names void every later witness on the line.

- An `Exec` slot under a stdin-fed wrapper (`xargs`, `parallel`,
  `find -exec +`) appends an unresolved operand to the inner argv, so
  `echo / | xargs rm -rf` reaches the `rm` rule.
- `written` collects same-line write targets (redirects, `tee`, `-o`,
  `cp`/`mv` destinations, `curl -o`). A later node that reads a written
  path as code is `Unknown(PersistedCode)`.
- `persists` slots recurse their value now and emit `Evidence::Persists`.
  A cwd-composed rule family protects `.git/hooks`, `.git/config`,
  `.claude/settings*.json` and `~/.claude`.
- Remote-execution slots (ssh) recurse with an unknown cwd, never the
  local one.

The separate cwd mechanisms (`env_hop_cwds`, `cwd_under_env_dash_c`,
`chain_dash_c_context`, `evaluate_dash_c_override`,
`evaluate_tool_dash_c_override`) are deleted in favour of `transform`.

### Policy

`Evidence` is completed per RFC #658, and `decide` is the only place
that writes a `Decision::` literal, a reason or a deny message. The new
core has no early returns: one `Vec<Evidence>` per line, folded by
`decide`.

Profiles:

- `balanced` (default): an `Unknown(Command)` node is witnessed when all
  of its words are resolved, none is a catalogued, rule-named or
  interpreter name or a path, and its stdin is inherited. Otherwise it
  is Unknown. `unknowntool --flag value` is Allow; `unknowntool rm -rf /`
  and `lxc exec c -- rm -rf /` are not.
- `strict`: every `Unknown` stays Unknown.

The outcome of an Unknown node is
`max(unknown.<mode>, ask_outcome.<mode>, escalation_floor)`. Precedence
is Block > Ask > Unknown > Allow. `[[allow]]` downgrades Ask or Unknown,
never Block.

## Config

```toml
profile = "balanced"          # balanced (default) | strict
[unknown]                     # outcome of Unknown evidence: ask | deny ("allow" is rejected at load)
default = "ask"               # mandatory; an unlisted mode resolves to the strictest value here
dontAsk = "deny"
ask_outcome = "deny"          # unchanged
[[allow]]
id = "tokei-leaf"
reason = "LOC counter, reads files only"
kind = "leaf"                 # downgrade | leaf | alias | path-leaf
command = "tokei"
reads_stdin = "data"
[[knowledge.extend]]          # tightening only: add code options, env_code, closed subcommands
command = "ls"
code_options = ["--exec"]
```

- `[[allow]]` is the one relaxation channel. `id` and `reason` are
  mandatory, an entry naming an embedded, rule-named, interpreter or
  wrapper name is rejected at load, and the decision log records it as
  `relaxed_by`.
- `kind = "path-leaf"` (R4) allows a path-spelled project binary only
  with a prefix under the payload cwd, a basename that is not an
  interpreter or rule-named, and `reads_stdin = never`. A path written
  on the same line stays `Unknown(PersistedCode)`.
- `[[knowledge.extend]]` can only tighten; its schema has no removing
  field.
- Unknown keys fail at load (`deny_unknown_fields`). There is no
  repo-local config.
- `shguard harvest <log>` prints candidate `[[allow]]` rows from the
  decision log and never writes them.

With `ask_outcome = "deny"`, every Unknown is a deny in every mode. The
embedded leaf list is pre-seeded from the benign and denials corpora and
the decision log (names seen at least twice that are not wrappers,
interpreters or rule-named); shell history is not used. Target before
cut-over: 0 `Unknown(Command)` on the benign corpus, at most 5 on the
denials corpus, each listed.

## Plan

Each stage is a PR series. The differential compares old and new over
guardfall, fuzz, denials, benign, bypass and legacy rows, under four
configs: empty, the owner's config, `ask_outcome = "deny"`, and one with
an `[[allow]]`.

| Stage | Content | Done-check |
|---|---|---|
| R0 metrics and corpora | `scripts/metrics`; `tests/golden/must_not_allow.jsonl` seeded with every Allow payload above and in the triaged issues (no approval can override a row); gate.rs and rules.rs unit-test inputs converted to `tests/golden/legacy_units.jsonl` before anything is deleted; fuzz oracle observes builtins via `BASH_XTRACEFD` + `set -x` (#805) | metrics print in `cargo test`; must_not_allow pins its open count; legacy rows cover every extracted input |
| R1 knowledge as data | `rules/catalog.toml`, `rules/known-safe.toml`, DTO loader; roundtrip test that the TOML equals today's catalog, then `catalog.rs` deleted; builtin, leaf, rule-named and closed-subcommand rows | no `CommandSpec {` literal in `src/knowledge/`; disjointness test green; leaf rows at least 120 |
| R2 new core, unwired | node numbering, `knowledge/classify.rs`, `semantics/eval.rs`, completed `policy`; differential under the four configs; bugs found on main meanwhile are patched once in the old path and added as rows | Unsupported = 0; must_not_allow open = 0 on the new core; 0 new Allow; one `Verdict::allow(` site |
| R3 cut-over | `lib.rs` wires the new core; `src/gate.rs` deleted; `rules.rs` keeps rule matching only; `tests/architecture_invariants.rs` caps sizes | `src/gate.rs` absent; no `Decision::` or `Reason::new` outside `src/policy/`; one recursion entry; `rules.rs` at most 6k lines, `semantics/eval.rs` at most 3k |
| R4 user knowledge | `[[allow]]` kinds, `[[knowledge.extend]]`, final `[unknown]`, decision-log `relaxed_by` and `unknown.<kind>`, `shguard harvest`, pre-push guard on relaxations | user_config tests: each relaxing form rejected for embedded names, `allow` rejected in `[unknown]`, unlisted mode is strictest |

Approval files for the differential are split by direction:
`strangler_tightenings.jsonl` (old Allow, new Ask or Block; count-pinned)
and `relaxations.jsonl` (new looser than old; one enumerated line each,
refused by the pre-push hook unless the PR touches nothing in `src/`).

## Issues

- Resolved by R0: #805, #711.
- Resolved by R1: #806, #807, #808, #809, #810, #818, #819, #770, #773,
  #699, #701, #704, #666.
- Resolved by R2: #830, #817, #831, #815, #816, #822, #823, #824, #825,
  #829, #832, #746, #768, #769, #772, #774, #776, #682, #702.
- Superseded by R3: #637, #690, #691, #721, #677, #698, #715, #834.
- Independent and done first: #720, #713, #709, #799, #803, #802, #783,
  #797, #800, #717, #684; parser layer: #617, #706, #627, #634, #826.

Each issue resolved by a stage closes when its payloads are rows in
`must_not_allow.jsonl` (or `legacy_units.jsonl`) that pass on the new
core. Residual sub-items listed in an issue's Triage comment are handled
separately.

## Risks

- The witness moves bugs into data: a row that labels an executed
  operand as data still mints a witness. Mitigations: row review, the
  disjointness and code-option reference tests, and must_not_allow.
- The golden snapshot encodes today's fail-open Allows; "no new Allow"
  alone would keep them. must_not_allow is the fail-open baseline that
  no approval file can override.
- `balanced` keeps a residual: an unknown command whose words are all
  inert is Allowed. `profile = "strict"` removes it.
- Parser divergence (RC5) is bounded, not removed: witnesses cover only
  parity-verified node kinds, and the bash-oracle fuzz stays in the gate.
