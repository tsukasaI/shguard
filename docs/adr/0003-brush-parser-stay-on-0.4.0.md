# ADR 0003: Stay on brush-parser 0.4.0 for stage 4

- Status: Accepted (owner-approved)
- Date: 2026-10-18
- Issue: tsukasaI/shguard#662 (RFC #658 stage 4, "Syntax")

## Context

RFC #658 stage 4 asks for a choice between staying on `brush-parser`
`=0.4.0`, upgrading, or forking with the panic fixes. Stage 4 moves heredoc
bodies and the bash-compat shims onto brush's own API (`word::parse_heredoc`,
`tokenize_str`), so the choice has to be made before that work lands.

## Crate facts, re-checked live on 2026-10-18

Checked with `cargo info brush-parser` and `cargo search brush-ocap-parser`
(crates.io index), not from memory:

| Crate | Version | Status |
|---|---|---|
| `brush-parser` | 0.4.0 | latest stable; MIT; rust-version 1.88.0 |
| `brush-ocap-parser` | 0.5.0-rc.1 | pre-release (rc) line |

## Decision

Stay on `brush-parser = "=0.4.0"`.

- `brush-ocap-parser 0.5.0-rc.1` is a release candidate. A fail-closed gate
  does not build on a pre-release parser whose output shape can still move.
- A fork is rejected: carrying our own parser fork is a standing
  maintenance burden out of proportion to four known panic sites.
- The panic catch (`catch_parser_panic`) stays as the last line of defence.
  It covers the known `unwrap()` sites inside brush's PEG grammar: the tilde
  directory-stack forms (unsigned/`+`-prefixed and `-`-prefixed), the brace
  sequence form, and the io-number form. A
  caught panic maps to `Ask`, never `Allow`.
- The `src/parser.rs` fixture corpus remains the upgrade gate.

## Re-check triggers

Revisit this decision when any of the following happens:

1. A stable 0.5.x release of `brush-parser` (or a stable `brush-ocap-parser`).
2. A release that fixes the known panics.
3. A `cargo deny` or RustSec advisory hit on `brush-parser`.
4. A change to brush's heredoc or span API (`parse_heredoc`, `tokenize_str`,
   `Token::Word` spans).
5. A new panic found by the corpora or the differential fuzzer.

Last crates.io re-check: 2026-10-18.
