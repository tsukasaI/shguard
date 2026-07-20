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
