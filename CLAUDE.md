# shguard

## Before writing or reviewing any code

Consult the `coding-guidelines/` git submodule first:

- `coding-guidelines/principles.md` — architecture: parse-don't-validate,
  invalid states unrepresentable, dependencies point inward, one composition
  root.
- `coding-guidelines/languages/rust.md` — Rust style and tooling.
- `coding-guidelines/patterns/tooling.md` — lint/format/pre-commit mechanism.

Precedence when guides conflict: language guide > principles.

## Tooling facts

- lefthook + gitleaks are the mandated pre-commit stack (`lefthook.yml` at
  repo root; `gitleaks git --staged --redact`).
- `git commit --no-verify` and `SKIP=` bypasses are banned except as a
  documented emergency recorded in the commit message.
- `rustfmt.toml` is INTENTIONALLY ABSENT: rustfmt runs at defaults per
  `languages/rust.md` — do not add the file.
- Clippy configuration lives only in `Cargo.toml`'s `[lints.clippy]` table —
  never blanket-enable pedantic/nursery groups.

## Project references

- Design doc: `plan.md` at the repo root.
- Implementation issues: GitHub (tsukasaI/shguard).
