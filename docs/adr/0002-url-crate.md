# ADR 0002: URL-parsing crate for `except_targets`' opt-in `url_host` matcher

- Status: Accepted
- Date: 2026-08-15
- Issue: tsukasaI/shguard#102 ("except_targets URL matching must agree with a
  real URL parser's host component, not string-prefix matching")

## Context

Issue #102 asks for an opt-in `except_targets` matcher that agrees with
what a real URL parser identifies as the *host* component, closing the
userinfo-spoofing gap the README already discloses as a known limitation
of string-prefix matching (`http://localhost:pw@evil.example.com` shares
a string prefix with `http://localhost:` but its real host is
`evil.example.com`). Hand-rolling a second, "stronger" ad hoc
scheme/host/port extractor for this opt-in mode would recreate the exact
bug class the issue is about — userinfo `@`-splitting, IPv6 bracket
handling, percent-encoded hosts, and case folding are each one off-by-one
away from a bypass, and `except_targets` matching suppresses a rule
(widens an allow), so a wrong host extraction here is a real security
regression, not a cosmetic one.

## Crate facts, verified live on 2026-08-15

Verified via `cargo info url` (reads the live crates.io index), not
carried over from memory:

| Crate | Version | Licence | rust-version | Source |
|---|---|---|---|---|
| **url** | 2.5.8 | MIT OR Apache-2.0 | 1.63 | github.com/servo/rust-url |

`url` matches shguard's own `MIT OR Apache-2.0` distribution commitment
exactly — no licence-compatibility work, unlike ADR 0001's `yash-syntax`
fallback discussion. It implements the WHATWG URL Standard (the same
parsing model browsers use), is maintained by the Servo project, and is a
transitive dependency of the wider Rust HTTP ecosystem (`reqwest`,
`hyper`), making it one of the most widely-exercised URL parsers in the
ecosystem.

## Decision

Add `url = "=2.5.8"` as a normal dependency, exact-pinned — the same
posture ADR 0001 takes for `brush-parser`, for the same reason: this
crate's parsing behavior is directly security-relevant (it decides
whether a rule author's `except_targets` exception widens or doesn't),
so an unreviewed transitive version bump changing host-extraction
behavior must not silently reach a released build. `tests/`'s existing
fixture-corpus convention (`tests/guardfall.rs`, `tests/bypass_corpus.rs`)
extends naturally to gate any future pin bump: the `url_host` matcher's
own regression tests (userinfo spoof, IPv6, percent-encoding, scheme-less
input) already double as that upgrade-compatibility gate — no separate
spike harness is needed the way ADR 0001's parser selection required one,
since this is a single, narrow extraction (`Url::host_str()`), not a
whole-grammar decomposition with multiple competing crates to compare.

## Known residual risk — WHATWG vs. what `curl`/the OS resolver actually does

`url` implements the WHATWG URL Standard; `curl` and most other CLI tools
follow something closer to RFC 3986 plus their own historical quirks. The
two do not always agree, and the dangerous direction is exactly one:
`url` reports a host that is *safer* than where the command actually
connects (i.e., `url` says `localhost`, the real connection goes
elsewhere). The clearest known instance is backslash handling: WHATWG
"special" schemes (`http`, `https`, `ws`, `wss`, `ftp`, `file`) treat `\`
as equivalent to `/` in some parsing states, which some other tools do
not. Mitigation shipped alongside this matcher (see `src/rules.rs`'s
`url_host` matching code): a candidate target token containing a
backslash or any byte below `0x20` is rejected *before* being handed to
`url::Url::parse` at all — fails closed (never matches, so the rule still
fires) rather than risking a parser-disagreement bypass. This narrows the
known gap; it does not claim to eliminate every possible WHATWG/RFC-3986
divergence, matching the README's existing "narrowing the gap, not
eliminating it" posture for `except_targets` generally.

## Scope note

`url` is added as a **normal** dependency (used at runtime by the
`url_host` matcher, not test-only), unlike ADR 0001's `yash-syntax` which
is explicitly kept out of the shipped binary. There is no licence
objection here — see the table above — so this doesn't need ADR 0001's
"never a runtime dependency of the shipped binary" clause.
