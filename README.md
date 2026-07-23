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
and an empty `targets` (the shape both examples above already use) —
declaring it anywhere else is a load-time error, since the field would
otherwise silently do nothing. Declaring a flag here is a trust decision
with the same weight as an `except_targets` entry itself: only declare a
flag whose value can never itself be, or point at, the thing the rule
guards against — misdeclaring one is as much a bypass as a wrong
`except_targets` pattern would be. In particular, don't declare an
*optional*-argument flag (one that may or may not take a value depending
on invocation, e.g. GNU `--color[=WHEN]`) — when such a flag appears
without its value, the *next* token is an unrelated positional, and
`value_flags` would wrongly consume it as if it were that flag's value. A
short flag is only recognised as its own standalone token (`-o`, never
glued into a cluster like `-so`), and everything after a bare `--`
end-of-options terminator is exempt from `value_flags` matching entirely
(it's an ordinary positional by shell convention from that point on, even
if its text happens to match a declared flag's name).

### Precedence: deny > ask > allow

Evaluation is fixed, regardless of which array a rule came from: a `deny`
match always wins; failing that, an `ask` match always wins over an
`allow` match for the same command. A `deny`/`ask` entry can only ever
*raise* what would otherwise be `Allow` — it can never be silently
overridden by a broader `allow` entry elsewhere in the file. An `allow`
entry can only ever *downgrade* an `Ask` that shguard's own structural
analysis produced (an unresolvable construct, for instance) — it can
**never** downgrade a `Block`, from the embedded blocklist or from your
own `deny` entries. This mirrors Claude Code's own
`permissions.{deny,ask,allow}` model.

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
(or `--in-place`)/`dd of=`/`rm`/`unlink`/`ln` writes targeting its own
resolved config path, and the literal `~/.config/shguard/` token for any
user — an agent shouldn't be able to edit its own guardrails via a shell
command. This is a partial mitigation, not a complete one:

- Bare shell redirection (`cat > path <<EOF`, see Limitations below) is not
  analyzed by design, and a `SHGUARD_CONFIG` override set via a shell
  profile is outside shguard's visibility entirely.
- A relative path after `cd`-ing into the config directory (`cd
  ~/.config/shguard && cp evil.toml config.toml`) is not caught — shguard
  never resolves argv tokens against the process's working directory.
- Other write-capable tools (`rsync`, `truncate`, `shred`, …) are not
  enumerated in this list at all.
- `cp`/`install`/`tee`/`dd`/`sed` match a file *under* the config
  directory, but not the bare directory path with no trailing slash
  (`rm`/`unlink`/`ln`/`mv` do cover this).
- Deleting or moving a *parent* of the config directory (e.g. `rm -rf
  ~/.config`) is not caught — self-protection rules only match
  `~/.config/shguard` and paths under it, not any of its ancestors.

### What's not configurable (yet)

Per-command policy is scoped to whole commands (`command`/`command_prefix`,
optionally with `required_flags`/`targets`) — there is no subcommand-level
matching (e.g. "allow `gh pr view` but ask before `gh repo delete`") in
this version; declare separate rules keyed on flags/targets if you need
finer granularity. Pipeline-shape rules (the `curl | sh` pattern and
friends) are also not user-configurable.

## Limitations

shguard mitigates the published GuardFall bypass classes plus the listed
extensions, with the regression suite above as evidence — it does not
eradicate shell-mediated destruction. Explicitly out of scope:

1. **Runtime state.** Environment variables, aliases, shell functions, and
   `PATH` shadowing set by *earlier* commands in a persistent session.
   shguard analyzes one command string at a time; it has no session memory.
2. **Semantic destructiveness of arbitrary programs.** A Python script that
   deletes files, or `make clean` with a hostile Makefile — shguard's
   blocklist covers enumerated argv shapes (including a curated set of
   dangerous `git` subcommand/flag combinations, e.g. `push --force`,
   `reset --hard`, `commit --amend`), not arbitrary program behavior.
3. **Non-shell destructive edits.** An agent instructed to edit or delete
   files destructively through its file-editing tools rather than through a
   shell command never reaches this hook.
4. **Multi-step attacks staged across Ask-approved commands.** Ask surfaces
   an unresolvable command to a human for a decision; a hurried human can
   still approve a staged payload one step at a time.
5. **Redirection targets, mostly.** Output/append redirection (`>`, `>>`)
   targets are checked against a curated dangerous-path list (raw block
   devices, `/etc/passwd`, `/etc/shadow`) — but that list doesn't include
   shguard's own config path, so `cat > file <<EOF` is still Allow when
   `file` is shguard's config file. The
   [config-file self-protection](#protecting-the-config-file-itself) rules
   only see write-capable *commands* (`tee`, `cp`, `dd`, …) in argv, not
   bare redirection, and heredoc bodies themselves are never inspected.

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
