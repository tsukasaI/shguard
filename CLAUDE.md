# shguard

A `PreToolUse` hook for Claude Code that decides Allow / Ask / Block for a
Bash command. The decision logic is a small kernel proved with Creusot.

## The promise

Allow means: the parser read the whole command, every simple command in it is
covered by the closed catalog, no rule hit, and no code-running position is
present. It holds under three assumptions:

- P1: bash reads every string our parser accepts as the same AST.
- P2: each catalog row's grammar matches the real tool's argv parsing.
- P3: the environment is not hostile (PATH, `BASH_FUNC_*`, repo-local hooks).

Allow is NOT "safe". Never write docs, messages or tests that say it is.
Unknown input is Ask; the old engine's Allow-by-default is gone (legacy code is
at tag `legacy-v0.9.5`).

## Before writing or reviewing any code

Consult the `coding-guidelines/` git submodule first:

- `principles.md`: parse-don't-validate, invalid states unrepresentable,
  dependencies point inward, one composition root.
- `languages/rust.md`: Rust style and tooling.
- `patterns/tooling.md`: lint/format/pre-commit mechanism.

Precedence when guides conflict: language guide > principles. The proof-shape
ADR (confirmed Creusot 0.14 spellings) is `spikes/README.md`.

## Layout

- `crates/shguard-kernel/`: verified. Its only dependency is `creusot-std`,
  declared under `[target.'cfg(creusot)'.dependencies]`, so it exists only
  under `cargo creusot`. It is LGPL-2.1-or-later and never enters a shipped
  build. `deny.toml`'s `[graph] targets` prunes it (and every dependency
  whose `cfg` is false on all listed triples, custom cfgs included) from all
  cargo-deny checks, not only licenses;
  keep that list equal to the release triples.
- `crates/shguard-syntax/`: subset lexer/parser to the kernel AST; Kani,
  proptest and differential tests.
- `crates/shguard/`: lib + bin; hook adapter, CLI, config, TOML loader,
  decision log. `main` is the composition root (env/config read once there).
- `catalog/*.toml`: embedded default catalog and rules.
- `acceptance/`: corpora (`must_not_allow`, `guardfall`, ...). Their
  old-engine fields are not expectations.
- `spikes/`: separate workspace (Creusot experiments); not built by the root.

Recorded exceptions to `rust.md`: the workspace split (the kernel needs zero
deps besides `creusot-std` to be verifiable), and the nightly Creusot
toolchain, confined to its own CI job; production stays on stable.

## Rust style

2024 edition, stable, `unsafe_code = "forbid"`, lints in `[workspace.lints]`
(including `wildcard_enum_match_arm = "deny"`). One `thiserror` type per seam,
no `unwrap`/`expect` outside tests, no `catch_unwind`, no `OnceLock`
singletons, newtypes and enums instead of flag structs.

## Kernel rules (`shguard-kernel`)

- Bytes, not strings. No iterators, closures, `dyn`, async or traits: index
  loops with `#[invariant]`s.
- No `_` arm when matching our own enums.
- Every `pub fn` has a contract; every loop and recursion has a `#[variant]`.
- Lemmas are `lemma_*` and live next to the code they are about.
- Allow can only be built from a `Witness` bound to the input it certifies
  (#1006): the `Witness` (built only by `classify_script`) owns the
  `Script`, and its invariant is `covered_script`.
- A ghost field (`Snapshot<..>`) takes `#[cfg(creusot)]` both on the struct
  field and on the field in the struct literal
  (`#[cfg(creusot)] cat: snapshot!(*cat)`), so normal builds have neither.
- Nothing may reference `creusot-std` unconditionally, because normal builds
  do not have it. Contracts go through `cfg_attr` only
  (`#[cfg_attr(creusot, ensures(..))]`, likewise `requires`, `check`,
  `variant`, `invariant`, `derive(DeepModel)`); logic functions, lemmas,
  `proof_assert!`, `snapshot!` and the prelude import take `#[cfg(creusot)]`
  on the whole item or statement. Spec-only parameters need
  `#[cfg_attr(not(creusot), expect(unused_variables, reason = "..."))]`.
- Constants that an open logic function mentions must be `pub`: Creusot
  refuses to unfold an open function that names a less visible item.
- Data model (`ast`, `catalog`, `rule`): fields are `pub(crate)`; other crates
  build a type that carries an invariant only through its checked constructors
  (returns `Option`, contract `Some(x) ==> fields equal inputs`,
  `None ==> !wf(inputs)`), and the type has a `#[cfg(creusot)] impl Invariant`.
  Enum variants cannot be hidden, so wrap a constrained payload in a sealed
  newtype (`OptName::Long(LongName)`); `#[non_exhaustive]` does not stop
  mutation through `&mut` patterns.
  - A logic item or `Invariant` impl that reads a `pub(crate)` field must be
    `#[logic(open(crate))]`; plain `open` fails with "would call a
    less-visible item". The `wf` predicates over views stay `open`.
  - `derive(DeepModel)` (so Creusot's `PartialEq`) fails on a struct with
    `pub(crate)` fields for the same reason. Such structs derive
    `PartialEq, Eq` only under `cfg_attr(not(creusot), ..)`; logic `==` needs
    neither.
  - Likewise a logic fn over a private type (e.g. a private program enum)
    cannot be `open`, not even when the fn itself is private; give it plain
    `#[logic]`, whose body is still visible inside its own module.
  - `Vec::is_empty` is not `terminates`; write `<[_]>::is_empty(&v)`.
  - A refinement of a loop is easiest against a tail-recursive spec that
    carries the loop state as accumulators (`argv_go(.., i, ended, k,
    slots, seen)`): the invariant is `go(state) == spec(input)`, and each
    iteration unfolds `go` once. Logic fns cannot be mutually recursive,
    so per-step helpers (`word_l`, `cluster_l`) return a description of
    the step and the one recursive fn acts on it.
  - Even inside a `#[cfg(creusot)]` item, `x@` must sit in `pearlite! { .. }`
    because the item is parsed before the cfg is applied.
- Lint policy (#1007): only this crate has
  `#![expect(clippy::indexing_slicing, reason = "bounds proved by Creusot")]`;
  every other lint, `missing_docs` included, stays on.
- `verif/` and `.why3find/` are generated and gitignored (#1005): their spans
  depend on the checkout path and leak the home directory. Every gate proves
  from source with `--span-mode relative`; the proof must pass before merge.
- Lockfile policy (#1009): the committed `Cargo.lock` is the registry form
  written by stable cargo. `cargo creusot` can rewrite it to a nix-patched
  `creusot-std` (no `source`/`checksum`); that form is a local artifact and
  must never be committed. After a proof run, repair it by running any stable
  cargo command (`cargo metadata --format-version 1 > /dev/null`), then
  confirm with `cargo metadata --locked --format-version 1 > /dev/null`
  and finally `git diff --exit-code Cargo.lock`. The repair re-resolves to
  the highest compatible versions, so `--locked` alone cannot catch drift
  (e.g. a newly published creusot-std 0.14.1).

## Tests and catalog

- Tests pin only command to decision, never messages or rule ids.
- Every catalog row records its upstream source (GNU/BSD docs or source). The
  catalog loader (M12) rejects a row without one.

## Tooling facts

- lefthook + gitleaks are the mandated pre-commit stack (`lefthook.yaml`;
  `gitleaks git --staged --redact`). `pre-push` runs fmt, clippy, test,
  `cargo deny check` and the proof run.
- `git commit --no-verify` and `SKIP=` bypasses are banned except as a
  documented emergency recorded in the commit message.
- `rustfmt.toml` is intentionally absent: stable rustfmt (1.10 with rustc
  1.99 at the time of writing) rejects `hex_literal_case` as nightly-only, so
  the template cannot be used on stable. rustfmt runs at defaults. Do not add
  the file.
- Clippy levels live in `[workspace.lints]`; parameters in `clippy.toml`.
- `lefthook.yaml`, `clippy.toml`, `rustfmt.toml`, `.gitleaks.toml` and
  `.claude/skills/**` are protected from agents: draft under the scratchpad and
  the owner applies them.
- Actions in `.github/workflows` are pinned by full commit SHA with a
  `# vX.Y.Z` comment; Dependabot renews them.

## Running proofs

```
nix develop                              # stable rust + Creusot 0.14 (free build)
cd crates/shguard-kernel                 # or spikes/lattice
cargo creusot --span-mode relative       # translate + prove (the gate); writes ignored verif/
cargo creusot --span-mode relative --replay  # fast local re-check against your own verif/
cargo creusot clean                      # after renames (interactive; `echo y |`)
```

There is no `prove` subcommand and no `-p`; run from the crate directory.
`why3find.json` and the generated `verif/` live at the workspace root, which
is where `cargo creusot` looks for and writes them; proofs of the kernel are
run from `crates/shguard-kernel`.
`cargo creusot 'mod::*'` proves one module.

For agents in the sandbox: set `HOME` and `CARGO_HOME` to scratchpad
directories and put the Creusot `bin` first on `PATH`, run it in the
background, and never pipe it into `head`/`tail` (it hangs).

## Workflow

Work in a worktree (`git worktree add --no-track -b <type>/<slug> <path>
origin/main`), never in the shared checkout. One milestone per PR; branches
are `<type>/<short-slug>`; commits follow Contextual Commits (English). Verify
before pushing: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `cargo deny check`, plus the proof run for kernel
changes. Every PR runs `verify.yaml`; confirm it is green before merging.
