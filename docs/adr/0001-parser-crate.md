# ADR 0001: Parser-crate selection

- Status: Accepted
- Date: 2026-07-18
- Issue: tsukasaI/shguard#6 ("A1: Parser-crate selection spike")

## Context

shguard needs a shell parser that decomposes a bash command string into a
structure that *preserves quote/expansion boundaries*, not one that either
(a) pre-joins tokens after removing quotes, or (b) hands back an opaque
blob. Concretely: `r''m -rf /` must be representable as something
equivalent to `[literal "r", single-quoted "", literal "m"]` so that
shguard's own normalize stage (plan.md §1.1) can fold it into `rm` itself,
rather than the parser silently doing (or failing to do) that fold.

plan.md §0.3 named `brush-parser` 0.4.0 (MIT) as the primary candidate and
`yash-syntax` 0.23.1 (GPL-3.0-or-later) as the fallback, based on
crates.io/docs.rs research recorded 2026-07-18. This ADR re-verifies those
facts live and replaces the desk-research judgement with an empirical one:
a throwaway harness at `docs/spike/parser-compare/` feeds both crates a
fixture corpus of 18 attack-relevant constructs and inspects the actual
parsed structure.

## Crate facts, re-verified live on 2026-07-18

Verified via `cargo info <crate>` (downloads and reads the real
crates.io index entry) and the crates.io HTTP API
(`https://crates.io/api/v1/crates/<crate>`), not carried over from
plan.md on trust:

| Crate | Version | Licence | Published | rust-version | Source |
|---|---|---|---|---|---|
| **brush-parser** | 0.4.0 | MIT | 2026-05-03 | 1.88.0 | github.com/reubeno/brush |
| **yash-syntax** | 0.23.1 | GPL-3.0-or-later | 2026-07-12 | 1.96.0 | github.com/magicant/yash-rs |

Both are still the current `max_stable_version` / `cargo search` top hit as
of 2026-07-18 — no newer release of either crate has shipped since
plan.md's original research. `cargo search` also surfaced two other hits
worth a one-line note: `kodegen_bash_shell` (a fork of brush-shell with
cancellation support, unrelated) and `clash-brush-parser` 0.7.2 (an
unrelated third-party fork under a different name) — neither is relevant
to this decision.

## The spike

`docs/spike/parser-compare/` is a standalone, throwaway Cargo project
(its own `Cargo.toml`, pinned to `brush-parser = "=0.4.0"` and
`yash-syntax = "=0.23.1"`) — **not** a member of the root shguard package
and not built by the root `Cargo.toml`. It defines 18 fixtures covering
every construct class listed in the issue, parses each with both crates'
real public APIs (`brush_parser::word::parse`, `brush_parser::Parser::
parse_program`, `brush_parser::word::parse_brace_expansions` for brush;
`yash_syntax::syntax::Word::from_str`, `yash_syntax::syntax::List::
from_str` for yash), and for each (construct, crate) pair prints the
actual parsed `Debug` structure as evidence and a hand-checked PASS/FAIL
verdict against a construct-specific structural criterion (e.g. "contains
a `SingleQuotedText("")` piece and no merged `Text` containing `rm`").
`bash -n` is run per fixture as an independent accepts/rejects oracle.

Run it yourself:

```sh
cd docs/spike/parser-compare && cargo run
```

Both crates' real public APIs were confirmed by reading the actual crate
source under `~/.cargo/registry/src/.../brush-parser-0.4.0/src/word.rs`
and `~/.cargo/registry/src/.../yash-syntax-0.23.1/src/syntax.rs` (docs.rs
prose summaries were cross-checked against, and in one case corrected by,
this source read — see the tilde-expansion note below).

## Pass/fail matrix

18 constructs, 2 crates. `bash -n` accepted every fixture (all are valid
bash syntax), so that column is omitted below; the full output including
the oracle column is in `docs/spike/parser-compare` (`cargo run`).

| # | Construct | Input | brush-parser | yash-syntax |
|---|---|---|---|---|
| 1 | adjacent-quote: `r''m` | `r''m -rf /` | PASS | PASS |
| 2 | adjacent-quote: `"r"m` | `"r"m -rf /` | PASS | PASS |
| 3 | adjacent-quote: `r\m` | `r\m -rf /` | PASS | PASS |
| 4 | ANSI-C quoting, hex | `$'\x72\x6d' -rf /` | PASS | PASS |
| 5 | ANSI-C quoting, octal | `$'\162\155' -rf /` | PASS | PASS |
| 6 | ANSI-C quoting, literal (issue's "unicode" fixture) | `$'rm' -rf /` | PASS | PASS |
| 7 | heredoc | `cat <<EOF` / `rm -rf /` / `EOF` | PASS | PASS |
| 8 | heredoc, tab-strip | `cat <<-EOF` / `\trm -rf /` / `EOF` | PASS | PASS |
| 9 | heredoc, quoted delimiter | `cat <<'EOF'` / `$(rm -rf /)` / `EOF` | PASS | PASS |
| 10 | command substitution | `$(echo rm) -rf /` | PASS | PASS |
| 11 | nested command substitution | `$(echo $(echo rm)) -rf /` | PASS | PASS |
| 12 | backquoted command substitution | `` `echo rm` -rf / `` | PASS | PASS |
| 13 | `$IFS` inside a word | `rm$IFS-rf$IFS/` | PASS | PASS |
| 14 | tilde expansion | `echo ~/x` | PASS | PASS |
| 15 | brace expansion | `echo {a,b}` | PASS | **FAIL** |
| 16 | pipeline | `echo x \| base64 -d \| sh` | PASS | PASS |
| 17 | list (`;`, `&&`) | `a; b && c` | PASS | PASS |
| 18 | redirection | `echo x > /dev/null` | PASS | PASS |
| | **Total** | | **18/18** | **17/18** |

Full evidence (the real `Debug` output backing every verdict above) is in
the "Evidence excerpts" section below and reproducible via `cargo run`.

### Construct where both crates could plausibly fail: none

No construct in the 18-row corpus fails both crates. The single failure
(#15, brace expansion for yash-syntax) is a **deliberate scope exclusion**,
not a bug: yash-syntax targets strict POSIX shell syntax, and POSIX has no
brace expansion. Confirmed by reading `yash-syntax-0.23.1/src/syntax.rs`
in full — there is no `BraceExpr`/`BraceExpansion` type anywhere in the
crate; `{a,b}` simply parses as five literal characters
(`Unquoted(Literal('{'))`, ...), which is *correct* POSIX behaviour but
means the crate cannot decompose this construct for shguard's normalize
stage. If shguard ever needs yash-syntax as anything other than a
strictly-Ask-on-braces fallback, brace-expansion detection would need a
small pre-pass supplied by shguard itself (see "Licence-policy clause"
below for why this is a fallback-only concern).

## Evidence excerpts

```
=== [1] adjacent-quote: r''m -rf / ===
brush-parser: PASS — [Text("r"), SingleQuotedText(""), Text("m")]
yash-syntax:  PASS — [Unquoted(Literal('r')), SingleQuote(""), Unquoted(Literal('m'))]

=== [4] ANSI-C quoting, hex: $'\x72\x6d' ===
brush-parser: PASS — [AnsiCQuotedText("\\x72\\x6d")]
yash-syntax:  PASS — [DollarSingleQuote(EscapedString([Hex(114), Hex(109)]))]

=== [9] heredoc, quoted delimiter: <<'EOF' ===
brush-parser: PASS — IoHereDocument { remove_tabs: false, requires_expansion: false,
  here_end: Word { value: "'EOF'", .. }, doc: Word { value: "$(rm -rf /)\n", .. } }
yash-syntax:  PASS — content=Some(Text([Literal('$'), Literal('('), Literal('r'), Literal('m'),
  Literal(' '), Literal('-'), Literal('r'), Literal('f'), Literal(' '), Literal('/'), Literal(')'), Literal('\n')]))

=== [11] nested command substitution: $(echo $(echo rm)) ===
brush-parser: PASS — [CommandSubstitution("echo $(echo rm)")]
yash-syntax:  PASS — [Unquoted(CommandSubst { content: "echo $(echo rm)", .. })]

=== [13] $IFS inside word: rm$IFS-rf$IFS/ ===
brush-parser: PASS — [Text("rm"), ParameterExpansion(Parameter { parameter: Named("IFS"), indirect: false }),
  Text("-rf"), ParameterExpansion(Parameter { parameter: Named("IFS"), indirect: false }), Text("/")]
yash-syntax:  PASS — [Unquoted(Literal('r')), Unquoted(Literal('m')),
  Unquoted(RawParam { param: Param { id: "IFS", type: Variable }, .. }), ...]

=== [15] brace expansion: {a,b} ===
brush-parser: PASS — [Expr([Child([Text("a")]), Child([Text("b")])])]
yash-syntax:  FAIL — [Unquoted(Literal('{')), Unquoted(Literal('a')), Unquoted(Literal(',')),
  Unquoted(Literal('b')), Unquoted(Literal('}'))] (parses, but as literal chars — no
  brace-expansion node exists in this crate)
```

Full untruncated output (all 18 rows plus the `bash -n` oracle column) is
reproduced by running the harness — see "Re-running the harness" below.

### A methodology correction worth recording

Row 14 (tilde expansion) initially reported yash-syntax as FAIL: calling
`yash_syntax::syntax::Word::from_str("~/x")` alone returns
`[Unquoted(Literal('~')), Unquoted(Literal('/')), Unquoted(Literal('x'))]`
— no `Tilde` variant. Reading `yash-syntax-0.23.1/src/parser/lex/tilde.rs`
revealed this is intentional: yash-syntax treats tilde recognition as an
explicit, opt-in post-processing step (`Word::parse_tilde_front()`) rather
than something the base word parser always applies, because tilde
expansion is POSIX-defined as context-sensitive (recognized at word start
or after certain delimiters, not unconditionally). Calling
`word.parse_tilde_front()` after parsing does produce
`[Tilde { name: "", followed_by_slash: true }, ...]` — a correct PASS. The
harness was corrected to call the real, documented API rather than
mis-score the crate for a harness bug. This is the kind of API-shape risk
the issue asked us to adapt to rather than assume from prose docs.

## Decision

Decision: **brush-parser** 0.4.0 is selected as the primary parser crate,
with **yash-syntax** 0.23.1 retained as the fallback.

Rationale: brush-parser passed all 18 constructs in the corpus, including
every construct that maps directly onto a GuardFall class or a documented
shguard extension (adjacent-quote insertion, ANSI-C quoting, `$IFS`-in-word,
nested command substitution, heredocs with correct quoted/unquoted-delimiter
distinction). It is MIT-licensed, matching shguard's own `MIT OR
Apache-2.0` distribution without any licence-compatibility work. Its one
known risk (plan.md §6.1: a PEG→winnow parser rewrite in flight) is
mitigated the same way plan.md already planned — pin the version, and this
fixture corpus becomes the upgrade-compatibility gate — and the
`parser.rs` adapter boundary (plan.md §1.1) is exactly the seam that makes
swapping to yash-syntax later a one-module change if brush-parser
regresses.

yash-syntax remains the fallback: it passed 17/18 constructs (only losing
on brace expansion, a deliberate POSIX-scope exclusion rather than a
parsing defect), its word/text-unit model is at least as granular as
brush-parser's (e.g. ANSI-C escapes come pre-classified as `Hex`/`Octal`/
`Literal` `EscapeUnit`s rather than a raw undecoded string), and it is
"very active" upstream (0.23.1 shipped 2026-07-12, six days before this
ADR).

## Licence-policy clause

yash-syntax is **GPL-3.0-or-later**. This clause is included per plan.md
§2 step 1's completion condition regardless of which crate wins, because
falling back is a licence-strategy change, not a drop-in swap.

**shguard does NOT accept GPL propagation.** The project's `Cargo.toml`
already commits to `license = "MIT OR Apache-2.0"`, and that is the
intended distribution licence for the life of the project. Concretely:

- brush-parser (MIT) is the default and expected shipping configuration.
  No licence question arises for the normal build.
- If brush-parser regresses badly enough (plan.md §6.2's "spike fails both
  candidates" ladder) to force a fallback, shguard will **not** link
  yash-syntax into the distributed binary as a GPL dependency. Adopting
  yash-syntax as a compile-time default would force the whole binary to
  GPL-3.0-or-later (static linking, no LGPL-style exception in yash-syntax),
  which is incompatible with the `MIT OR Apache-2.0` commitment already
  made to users and packagers (Homebrew tap, Nix flake, crates.io — plan.md
  §2 step 11).
- The practical fallback path if brush-parser's structure ever proves
  insufficient is therefore **not** "switch the default dependency to
  yash-syntax", but plan.md §6.2's other rungs: vendor/patch brush-parser
  itself (still MIT) for the specific gap, or narrow the affected
  construct's handling to route to `Ask` via the structural gate (§1.1
  stage 4) rather than depend on a parser crate to resolve it.
- yash-syntax's role in this repo, until and unless a future ADR revisits
  this decision, is as a **local differential-testing oracle only** (like
  tree-sitter-bash and `bash -n` in plan.md §0.3's rejected-crates table)
  — e.g. an optional `dev-dependency`-gated regression check that
  cross-validates brush-parser's parse against yash-syntax's for the POSIX
  subset both crates cover. It is never a runtime dependency of the
  shipped `shguard` binary. If a future ADR proposes making yash-syntax a
  runtime dependency, that ADR must explicitly re-open the MIT/Apache-2.0
  distribution commitment — it cannot happen as a routine dependency bump.

## Re-running the harness

```sh
cd docs/spike/parser-compare && cargo run
```

The project is entirely self-contained under `docs/spike/parser-compare/`
(its own `Cargo.toml` pinned to `brush-parser = "=0.4.0"` and
`yash-syntax = "=0.23.1"`, its own `Cargo.lock`), is not a workspace
member of the root `shguard` package, and is not built by `cargo build`
run from the repo root. It builds and runs fully offline once
dependencies are fetched once.
