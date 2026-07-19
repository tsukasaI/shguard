# shguard — Implementation Plan

A PreToolUse hook for AI coding agents that blocks dangerous shell commands by
interpreting what bash will actually execute — real tokenisation and static
normalisation, not plain-text regex matching. Single Rust binary, agent-agnostic
core.

---

## 0. Verified facts vs. assumptions

Everything below marked **[verified]** was checked against primary sources on
2026-07-18 (crates.io API, official Claude Code hooks docs, the Adversa AI
GuardFall post). Items marked **[to verify]** must be re-checked during the
issue that consumes them — do not carry them forward from this document on
trust.

### 0.1 The threat model: GuardFall catalog **[verified]**

Source: Adversa AI, "Open-source AI coding agents shell injection vulnerability"
(adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/).
11 agents surveyed, 10 bypassed. Continue was the only agent that held, via a
five-stage evaluator that tokenises like the shell before matching.

The published catalog has exactly **five classes**:

| Class | Technique | Canonical payload |
|---|---|---|
| A | Quote removal merges tokens | `r''m -rf /` → bash runs `rm -rf /` |
| B | `$IFS` expansion word-splits | `rm$IFS-rf$IFS/` → three argv words |
| C | Command substitution hides the binary | `$(echo rm) -rf /` |
| D | Encoded pipeline, each segment benign | `echo <b64> \| base64 -d \| sh` |
| E | Alternative destructive tools | `find /x -delete`, `dd of=/dev/sda`, `tar -C / -x` |

**Correction to prior assumptions:** ANSI-C quoting (`$'\x72\x6d'`), variable
indirection (`X=rm; $X`), heredoc tricks, and glob path spoofing are **not** in
the published catalog. shguard still covers them — they are the obvious next
bypasses in the same spirit — but the README must present them as *extensions
beyond the published catalog*, not as GuardFall cases. Conversely, **Class B
(`$IFS`) was missing from the original design** and is now folded into the
normalisation stage (§1.2) and the regression suite (§3).

### 0.2 Claude Code PreToolUse hook contract **[verified]**

Source: code.claude.com/docs/en/hooks (canonical redirect of
docs.anthropic.com/en/docs/claude-code/hooks).

- stdin: JSON with `tool_name: "Bash"` and the command string at
  **`tool_input.command`**. Context fields include `session_id`, `cwd`,
  `permission_mode`, `hook_event_name`.
- Decision channel: exit 0 + JSON on stdout:

  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": "…"
    }
  }
  ```

  `permissionDecision` ∈ `allow` / `deny` / **`ask`** / `defer`. `ask` escalates
  to the normal user confirmation dialog — this is what makes shguard's
  three-way `Verdict` directly representable. Exit 2 is an alternative hard
  block (stderr fed to the model, stdout ignored); shguard uses the JSON path
  exclusively so all three decisions travel one mechanism.
- Registration: `settings.json` → `hooks.PreToolUse[].matcher: "Bash"`,
  hook `type: "command"`.
- Portability **[verified, re-verify at adapter time]**: OpenAI Codex CLI has a
  near-identical `PreToolUse` hook (same `hookSpecificOutput.permissionDecision`
  shape); Cursor has `beforeShellExecution` with a different schema
  (`permission: allow/deny/ask`). A thin adapter layer per agent is the right
  shape; the decision core stays agnostic.
- The hooks spec is fast-moving (fields are version-gated). The adapter issue
  re-fetches the doc before implementation.

### 0.3 Parser crate landscape **[verified]**

All existence/version/licence data pulled live from crates.io and docs.rs.

| Crate | Status | Licence | Fit |
|---|---|---|---|
| **brush-parser** 0.4.0 (2026-05) | Active (brush shell, ~1700 bash-compat tests) | MIT | **Primary candidate.** Two-stage word model: `ast::Word` (raw) + `word::parse()` → `WordPiece` enum with `Text`, `SingleQuotedText`, `AnsiCQuotedText`, `DoubleQuotedSequence`, `TildeExpansion`, `ParameterExpansion`, `CommandSubstitution`, `BackquotedCommandSubstitution`, `EscapeSequence`. Directly represents `r''m` as `[Text("r"), SingleQuotedText(""), Text("m")]`. Covers bash extensions (ANSI-C, brace expansion, coproc). Caveats: heredoc-in-substitution bugs fixed as recently as 0.4.0; a PEG→winnow parser rewrite is in flight (breaking-change risk). |
| **yash-syntax** 0.23.1 (2026-07) | Very active | **GPL-3.0-or-later** | **Fallback.** Rigorous POSIX AST incl. `DollarSingleQuote` (ANSI-C) and a first-class `Unquote` trait. No brace expansion (deliberately POSIX-only). GPL would constrain shguard's own licence. |
| conch-parser 0.1.1 (2019) | **Dead** (repo archived 2022) | MIT/Apache | Right AST shape, no ANSI-C variant, no maintained fork. Rejected. |
| tree-sitter-bash 0.25.1 | Active | MIT | CST only — no quote removal/escape decoding; consumer reimplements bash semantics. Open correctness bugs in exactly the heredoc/backtick areas we care about. Rejected as primary; useful as a differential-testing oracle. |
| bash-ast (cv/bash-ast) | Active, tiny | GPL-3.0 | FFI into real bash's parser — zero drift, but GPL + global-state (single-threaded only). Rejected as dependency; useful as a test oracle. |
| shell-words / shellwords / shlex | — | — | Flat word splitters, not grammar parsers. Not viable. |

The selection **spike remains the first implementation task** (§2, step 1):
the table above answers "what exists"; the spike answers "which one decomposes
our actual attack corpus correctly", empirically, against fixtures.

---

## 1. Architecture

### 1.1 Four-stage pipeline

```
raw command ──▶ [1 Parse] ──▶ [2 Normalise] ──▶ [3 Danger check] ──▶ Verdict
                    │                                  ▲
                    └────────▶ [4 Structural gate] ────┘  (unresolvable constructs)
```

1. **Parse** (`src/parser.rs`) — thin adapter over the selected crate.
   Produces shguard's own AST types (§1.4), so the external crate never leaks
   past this boundary ("dependencies point inward"). Parse failure is a typed
   error, never a silent pass.
2. **Normalise** (`src/normalize.rs`) — fold only what is *statically*
   determinable, on the AST:
   - quote removal: `r''m` → `rm`, `"r"m` → `rm`, `r\m` → `rm`
   - ANSI-C quoting: `$'\x72\x6d'` → `rm` (hex, octal, unicode, control escapes)
   - `$IFS` folding *(new, closes Class B)*: a word containing `$IFS`/`${IFS}`
     is expanded with the default IFS (space/tab/newline) and re-split; policy
     for non-default IFS in §4.
   - tilde and simple brace expansion (`{a,b}` literal alternation only)
   - Output: per simple command, a concrete `Vec<NormalizedWord>` where each
     word is either `Resolved(String)` or `Unresolvable(UnresolvableKind)`.
     No environment lookups, no globbing against the filesystem, no execution.
3. **Danger check** (`src/rules.rs`) — mechanical exact-match of the resolved
   argv against `rules/blocklist.toml`: "does the token at this position match
   exactly". Ports the covered patterns from the existing bash blocklist
   (quote-insertion-resistant now for free; alternate destructive tools —
   `find -delete`, `dd`, `truncate`, `shred` — as argv shapes; `curl | sh`).
   Rule schema: command name + required flag/arg positions + target patterns.
4. **Structural gate** (`src/gate.rs`) — for constructs whose *value* cannot be
   statically resolved, route by *structure* (§4): command substitution or a
   bare `$VAR` in command position, decode-fed interpreter pipes. Never
   attempts to compute the runtime value.

Stage 3 also **recurses**: the inner command of every `$(...)`/backtick found
in *argument* position is itself run through the full pipeline (Continue's
"substitution recursion"). A destructive inner command blocks even when the
outer command is benign (`echo "$(rm -rf /)"` → Block).

### 1.2 Two contracts (fixed before any stage work)

- **Decision core API** (`src/lib.rs`, `src/verdict.rs`):

  ```rust
  pub fn analyze(command: &str) -> Verdict
  ```

  `Verdict` carries `decision: Decision` (`Allow | Block | Ask`), `reason`,
  `normalized_argv`, `matched_rule`. Exact field types are settled in the
  core-types issue — the shape above is the contract, signatures are **[to
  verify against coding-guidelines]** (e.g. whether `analyze` returns
  `Result<Verdict, AnalyzeError>` with a fail-closed mapping at the adapter, or
  folds parse failure into `Verdict::Ask` itself; the guidelines' "parse, don't
  validate" favours the former, with the adapter as the single fold point).
- **Hook adapter** (`src/bin/shguard.rs` + an `adapter` module) — reads the
  Claude Code stdin JSON, calls `analyze`, emits the `hookSpecificOutput` JSON.
  All Claude-Code-specific field names live here and only here; a future
  Codex/Cursor adapter or MCP proxy calls the same `analyze`.

### 1.3 Mapping to coding-guidelines

The `coding-guidelines/` submodule (github.com/tsukasaI/coding-guidelines) is
authoritative; `CLAUDE.md` (created in the scaffolding issue, not now) will
contain an explicit instruction: *"Before writing or reviewing code, consult
`coding-guidelines/principles.md` and `coding-guidelines/languages/rust.md`;
tooling per `coding-guidelines/patterns/tooling.md`."*

- **Parse, don't validate**: the hook adapter parses stdin JSON into a typed
  request once; `parser.rs` parses the command into a typed AST once. No stage
  re-inspects raw strings.
- **Make invalid states unrepresentable**: `Decision` is a closed enum;
  `NormalizedWord` cannot be simultaneously resolved and unresolvable; a
  `Verdict::Block` without a reason is unconstructible.
- **Dependencies point inward**: `rules`/`gate`/`normalize` depend on core AST
  types, never on the parser crate or on serde/hook JSON.
- **Wiring in one composition root**: `src/bin/shguard.rs` is the only place
  that connects stdin → adapter → `analyze` → stdout.
- **Tooling** (per `patterns/tooling.md`): rustfmt, clippy (deny warnings),
  pre-commit hooks, gitleaks — configured in the scaffolding issue.

### 1.4 Crate layout

One crate, lib + bin (per the settled distribution decision):

```
shguard/
├── CLAUDE.md                 # consult-the-submodule instruction (§1.3)
├── Cargo.toml                # lib + [[bin]] shguard
├── coding-guidelines/        # git submodule
├── src/
│   ├── lib.rs                # analyze() — public API, composition of stages
│   ├── verdict.rs            # Decision, Verdict, reason types
│   ├── parser.rs             # crate adapter → shguard AST
│   ├── normalize.rs          # static folding → NormalizedWord
│   ├── rules.rs              # TOML rule loading + argv matching
│   ├── gate.rs               # structural routing
│   ├── config.rs             # user config discovery + Policy::load (§6 item 8)
│   └── bin/shguard.rs        # composition root + Claude Code adapter
├── rules/
│   ├── blocklist.toml
│   └── allowlist.toml
├── tests/guardfall.rs        # §3
└── README.md
```

---

## 2. Implementation order

Strict dependency sequence. Each step has an explicit completion condition;
no step starts until its predecessors' conditions hold.

| # | Step | Depends on | Completion condition |
|---|---|---|---|
| 1 | **Parser-crate selection spike** — fixture corpus of the attack constructs (adjacent quotes, ANSI-C, heredoc, nested `$()`, backticks, `$IFS`-in-word, brace/tilde, pipelines, `;`-lists); run brush-parser and yash-syntax against it (tree-sitter-bash and/or `bash -n` as cross-check oracle); record per-construct pass/fail and the decision in `docs/adr/0001-parser-crate.md` | — | ADR exists with the pass/fail matrix for ≥2 crates and names the selected crate + fallback + licence implication, **including a licence-policy clause: if the outcome is yash-syntax (GPL-3.0-or-later), the ADR states explicitly whether shguard accepts GPL propagation or keeps MIT distribution by patching/supplementing brush-parser's gaps instead. Falling back is a licence-strategy change, not a drop-in swap — the call is made here, not discovered at distribution time** |
| 2 | **Repo scaffolding** — Cargo.toml, CLAUDE.md, submodule, rustfmt/clippy/pre-commit/gitleaks, CI (fmt+clippy+test on push) | — (parallel to 1; Cargo dep added after 1) | `cargo build` + `cargo clippy -- -D warnings` pass in CI; CLAUDE.md contains the submodule-consultation instruction |
| 3 | **Core types** — `Decision`, `Verdict`, shguard AST/`NormalizedWord` types, `analyze` signature (stub body) | 1, 2 | `cargo test` compiles with a stub `analyze`; invalid-state constructions rejected at compile time (doc-tests with `compile_fail`) |
| 4 | **Stage 1: parser adapter** | 3 | Fixture corpus from step 1 parses into shguard AST; parse failure returns typed error; parser crate types appear nowhere outside `parser.rs` |
| 5 | **Stage 2: normalisation** | 4 | Unit tests: `r''m`→`rm`, `"r"m`→`rm`, `r\m`→`rm`, `$'\x72\x6d'`→`rm`, `rm$IFS-rf$IFS/`→`["rm","-rf","/"]`, tilde/brace cases; unresolvable constructs surface as `Unresolvable`, never as guessed strings |
| 6 | **Stage 3: rules engine + blocklist port** | 5 | `rules/blocklist.toml` loads and validates at startup; ported patterns (rm shapes, find -delete, dd, truncate, shred, curl\|sh) match normalised argv exactly; `git commit -m 'rm -rf /'` does NOT match |
| 7 | **Stage 4: structural gate + substitution recursion** | 5, 6 | Command-position `$()`/backtick/`$VAR` → Ask; decode-fed interpreter pipe → Block; argument-position substitution recursed (inner `rm -rf /` → Block); `echo $(date)` and `cd $HOME` → Allow; same-line `IFS=` assignment makes `$IFS`-derived words untrusted — default-fold result still checked (blocklist hit → Block, miss → Ask, never Allow): `IFS=,; rm$IFS-rf$IFS/` → Block, `IFS=x; a$IFS-b` → Ask |
| 8 | **Hook adapter + composition root** | 3 (stubs ok), final wiring after 6–7 | Re-verify hook spec against live docs; `echo '<stdin json>' \| shguard` emits correct `permissionDecision` JSON for one Allow/Block/Ask case each; malformed stdin → fail-closed (`ask`) with reason on the JSON channel |
| 9 | **tests/guardfall.rs** | 6, 7 | The 7-case table (§3) asserts exactly; plus Class E rows and a benign-corpus no-false-positive section; all green in CI |
| 10 | **README + honest limits** | 9 | README opens with the §3 table (generated or copied verbatim from test expectations); contains the §5 limits section; contains install + settings.json snippet |
| 11 | **Distribution** | 8, 9 | Tagged release produces macOS (arm64/x86_64) + Linux (x86_64/arm64) binaries on GitHub Releases via CI; crates.io name published (namespace reserved with the real crate, even at 0.1.0); Homebrew tap formula and Nix flake install and run `shguard --version` |

The **vertical-slice priority** inside this order: steps 1→4→5→6→8 form a
shippable minimum (quote-removal-resistant blocklist as a working hook) before
step 7 completes — relevant to the speed risk in §6.

---

## 3. tests/guardfall.rs design

Seven headline regression cases — one per GuardFall class, plus the two
shguard extensions, plus the false-positive guard. This exact table also goes
at the top of README.md as the credibility evidence.

| # | Class | Command | Expected |
|---|---|---|---|
| 1 | A — quote removal | `r''m -rf /` | **Block** |
| 2 | A-ext — ANSI-C quoting *(beyond published catalog)* | `$'\x72\x6d' -rf /` | **Block** |
| 3 | B — `$IFS` splitting | `rm$IFS-rf$IFS/` | **Block** |
| 4 | C — command substitution | `$(echo cm0gLXJmIC8= \| base64 -d)` | **Ask** |
| 5 | C-ext — variable indirection *(beyond published catalog)* | `X=rm; $X -rf /` | **Block** |
| 6 | D — decode-fed pipe | `echo cm0gLXJmIC8= \| base64 -d \| sh` | **Block** |
| 7 | — false-positive guard | `git commit -m 'rm -rf /'` | **Allow** |

Structure: a table-driven test (`[(command, expected_decision)]` array, one
`assert_eq!` loop) so adding cases is a one-line diff. Two further sections in
the same file:

- **Class E coverage**: `find /x -delete`, `dd of=/dev/sda`, `tar -C / -x`,
  `shred /dev/sda`, `truncate -s 0 <path>` → Block (these are the ported
  blocklist, exercised through the full pipeline, not unit-tested rule calls).
- **Benign corpus**: a list of real agent commands (`cargo test`,
  `git status`, `echo $(date)`, `cd $HOME`, `grep -r "rm -rf" src/`,
  heredoc-fed `cat > file <<'EOF' …`) → Allow. False-positive regressions are
  regressions.

Why case 4 is Ask and case 6 is Block is the §4 policy, encoded here as
executable spec. Case 5 is Block only because the same-line assignment to a
blocklisted binary is statically visible; the *default* for variable
indirection is Ask (`X=ls; $X` → Ask) — indirection is a catalog-external
extension where blanket Block would false-positive.

---

## 4. Structural gate: Block vs. Ask boundary

Blanket-blocking `$()` or `$VAR` would also stop `echo $(date)` and `cd $HOME`
— unusable. The boundary is drawn on two axes: **position** (command vs.
argument) and **legitimate-use frequency**.

| Construct | Decision | Reasoning |
|---|---|---|
| `$()`/backtick in **argument** position, inner command resolves benign | **Allow** | `echo $(date)`, `git checkout $(git branch --show-current)` are everyday agent commands. Recursion (§1.1) already inspected the inner command. |
| `$()`/backtick in **argument** position, inner command matches blocklist | **Block** | `echo "$(rm -rf /)"` executes the inner command; benign outer shape is irrelevant. |
| `$()`/backtick in **command** position | **Ask** | What runs is literally the substitution's output — statically unknowable. Legitimate uses exist (`$(which python3) script.py`), so Ask, not Block: the human sees the command and the reason. |
| Bare `$VAR`/`${VAR}` in **command** position | **Ask** | Same unknowability (`X=rm; $X -rf /`). `$VAR` in argument position stays Allow (`cd $HOME`). An assignment of the same variable in the same command line to a blocklisted binary (`X=rm; $X …`) upgrades to **Block** — that much *is* statically determinable. |
| Pipeline whose sink is an interpreter (`sh`, `bash`, `zsh`, `python`, `node`, `perl`, `xargs sh`…) **with a decode/transform stage upstream** (`base64 -d`, `xxd -r`, `openssl enc -d`, `rev`, `tr` …) | **Block** | The payload is deliberately hidden from static analysis; there is no routine agent workflow that pipes decoded data into an interpreter. Near-zero false-positive cost buys a hard stop. |
| Pipeline into an interpreter **without** a decode stage (`curl … \| sh`) | **Block** (ported rule) | Established installer-pipe rule; retained. |
| Other pipe-to-interpreter (`cat script.sh \| bash`) | **Ask** | Content unknowable but shape is common in tutorials; human decides. |
| Word containing `$IFS` | Normalise with default IFS, then: blocklist hit → **Block**; no hit → **Ask** | `$IFS` in a word has essentially no legitimate interactive use; a non-default IFS (reassigned earlier in a persistent session) defeats the default-IFS fold, so the residual uncertainty goes to the human. Responsibility split: the normalisation stage folds with the **default** IFS only; a **same-line** `IFS=` assignment is the structural gate's concern — it marks every `$IFS`-derived word untrusted, so the default-fold result is still blocklist-checked (hit → Block) but a miss routes to Ask, never Allow. |
| Parse failure / unsupported construct | **Ask** (fail-closed) | Never Allow what we could not read. Ask rather than Block keeps exotic-but-legitimate commands usable. A security control holds on every path — including the error path. |

Principle: **Block** when either (a) the statically resolved argv matches a
rule, or (b) the structure has near-zero legitimate use (decode-fed
interpreter pipes). **Ask** when the structure is opaque but has real benign
uses. **Allow** requires the full pipeline to have positively resolved and
cleared every simple command, including recursed substitutions.

---

## 5. Honest-limits policy

shguard mitigates the GuardFall class of bypasses; it does not eradicate
shell-mediated destruction. README must state, verbatim in spirit:

- **In scope**: statically determinable rewriting (quote removal, ANSI-C,
  default-`$IFS`, tilde/brace), exact-argv blocklisting, structural routing of
  statically unresolvable constructs to a human.
- **Out of scope, by construction** (each listed in README):
  - Runtime state: environment variables, aliases, shell functions, `PATH`
    shadowing set in *earlier* commands of a persistent session. shguard sees
    one command string at a time.
  - Semantic destructiveness of arbitrary programs: a Python script that
    deletes files, `make clean` with a hostile Makefile, `git push --force` to
    the wrong remote. Class E is closed only for the enumerated argv shapes.
  - An agent instructed to *edit* files destructively via non-shell tools.
  - Determined multi-step attacks that stage payloads across Ask-approved
    commands — Ask surfaces them; a hurried human can still click through.
- Never the words "completely safe" / "unbypassable". The claim is: *closes
  the published GuardFall catalog (classes A–E) plus the listed extensions,
  with the regression suite as proof.*

---

## 6. Risks and open questions

1. **Parser crate risk.** brush-parser is mid-rewrite (PEG→winnow) and fixed
   heredoc-in-substitution bugs as recently as 0.4.0. Mitigations: pin the
   version; the fixture corpus from step 1 doubles as an upgrade gate; the
   `parser.rs` boundary makes swapping to yash-syntax a one-module change.
   Fallback licence implication: yash-syntax is GPL-3.0-or-later — adopting it
   forces shguard to a GPL-compatible licence. Default plan: MIT OR Apache-2.0
   with brush-parser; revisit only if the spike fails it.
2. **Spike fails both candidates.** Fallback ladder: (a) vendor/fork
   conch-parser (MIT, right AST shape, needs ANSI-C added); (b) tree-sitter-bash
   CST + hand-written quote-removal layer (most work, known heredoc bugs);
   (c) reduce v0.1 scope to constructs both candidates parse correctly and
   route the rest to Ask via a pre-parse structural scan. All three keep the
   pipeline contract intact.
3. **Speed risk.** Adversa called Continue's design "a two-day
   re-implementation" — the idea is public and simple; someone may ship first.
   Response: shguard's differentiators are things a rushed port won't have —
   agent-agnostic single binary (Claude Code + Codex hook schemas verified,
   Cursor adaptable), a real parser instead of `shell-quote` tokenising,
   substitution recursion, and the regression table as public evidence. The
   vertical slice (§2) reaches a working hook early; polish lands behind it.
4. **Persistent-session state** (Claude Code's shell keeps env across
   commands): `IFS=,` in command N defeats default-IFS folding in command N+1.
   Accepted and documented (§5); the `$IFS → Ask` residual rule bounds the
   damage. Open question for later: optional stateful mode that watches
   assignments across the session (out of v0.1 scope).
5. **Hook spec drift.** The hooks doc is explicitly version-gated and moving.
   The adapter issue re-verifies against live docs; the adapter's JSON schema
   is integration-tested with recorded fixtures, so a spec change fails loudly.
6. **`bash -c '<string>'` and interpreter-wrapped commands.** `bash -c` /
   `sh -c` argument strings should be recursed like substitutions (parse the
   inner string). Decided: in scope for the gate issue. `python -c`, `perl -e`
   are not shell — route to Ask when their code strings contain shell-out
   markers? **Open** — decide in the gate issue; default Ask is the safe
   floor.
7. **Verdict on multi-command lines.** `a; b && c`: decided — analyze every
   simple command; the worst decision wins (Block > Ask > Allow). Noted here
   so the core-types issue encodes ordering on `Decision`.
8. **Allowlist semantics.** **Resolved.** An allowlist match downgrades
   `Ask` → `Allow` only, never `Block` → `Allow` — `crate::rules::apply_allowlist`
   is structurally Block-immune (its first check rejects any non-`Ask`
   verdict before consulting the allowlist at all). The audit trail is
   `Verdict::AllowSuppressed` (`src/verdict.rs`), carrying the matched
   entry's id and reason. Extended into a full user-configurable
   deny/ask/allow policy: `~/.config/shguard/config.toml` (or
   `SHGUARD_CONFIG`), merged additively (never replace-by-id) onto the
   embedded blocklist/allowlist by `crate::rules::merge_user_config`, with
   a fixed deny→ask→allow evaluation order applied per simple command in
   `crate::gate::evaluate_simple_command`. Implementation: `src/config.rs`
   (discovery/loading), `src/rules.rs` (`UserConfig`, `merge_user_config`,
   `Rules.ask_rules`), `src/gate.rs` (`analyze_with_policy`, the
   allowlist-downgrade/ask-floor steps), `src/verdict.rs`
   (`Verdict::allow_suppressed`). See the README's "Configuration" section
   for the user-facing schema and precedence model.
