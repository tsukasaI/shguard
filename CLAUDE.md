# shguard

The repository is being rebuilt from zero; the previous implementation is at
the tag `legacy-v0.9.5`. The workspace, the style rules for the verified
kernel, and the verification commands arrive with the workspace scaffold.

## Before writing or reviewing any code

Consult the `coding-guidelines/` git submodule first:

- `coding-guidelines/principles.md` — architecture: parse-don't-validate,
  invalid states unrepresentable, dependencies point inward, one composition
  root.
- `coding-guidelines/languages/rust.md` — Rust style and tooling.
- `coding-guidelines/patterns/tooling.md` — lint/format/pre-commit mechanism.

Precedence when guides conflict: language guide > principles.

## Tooling facts

- lefthook + gitleaks are the mandated pre-commit stack (`lefthook.yaml` at
  repo root; `gitleaks git --staged --redact`).
- `git commit --no-verify` and `SKIP=` bypasses are banned except as a
  documented emergency recorded in the commit message.
- `rustfmt.toml` is INTENTIONALLY ABSENT: the template's
  `hex_literal_case` is nightly-only on rustfmt 1.99 and warns on every
  stable run, and rustfmt's defaults are otherwise the Google settings.
- Clippy lint levels live in the workspace `Cargo.toml`'s
  `[workspace.lints]` table, lint parameters (`disallowed-*`, test scoping)
  in `clippy.toml`.
- `lefthook.yaml`, `clippy.toml` and `.gitleaks.toml` are protected from
  agent edits; the owner applies changes to them.
