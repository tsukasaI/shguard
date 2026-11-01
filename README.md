# shguard

shguard is a `PreToolUse` hook for Claude Code. It reads the Bash command the
agent wants to run and answers Allow, Ask or Block.

## The promise

Allow means exactly this: shguard's parser read the whole command, every
simple command in it is covered by a closed, sourced command catalog, no rule
hit, and no position in it runs code. That holds under three assumptions:

- **P1.** bash reads every string the parser accepts as the same syntax tree.
- **P2.** Each catalog row's grammar matches how the real tool parses its
  arguments.
- **P3.** The environment is not hostile: `PATH`, exported shell functions
  (`BASH_FUNC_*`), and the repository's own hooks, config and build scripts.

Anything shguard cannot fully read, or does not know, is Ask. Allow is not a
claim that a command is safe: it is a claim about what shguard read and
checked. [docs/threat-model.md](docs/threat-model.md) lists what lies outside
the promise.

The decision logic is a small kernel written in Rust and proved with
[Creusot](https://github.com/creusot-rs/creusot): the kernel's code is checked
against its specification of the promise above, for every input.

## Install

Download `shguard-<target>` for your platform from
[Releases](https://github.com/tsukasaI/shguard/releases), check it against
`SHA256SUMS`, make it executable (`chmod +x`), and put it on `PATH` as
`shguard`. Or, from a checkout:

```console
$ cargo install --locked --path crates/shguard
$ shguard init
```

`shguard init` writes a config to `~/.config/shguard/config.toml` (or to
`SHGUARD_CONFIG`, which must be an absolute path) with `ask_outcome = "ask"`,
and prints the hook entry to add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/shguard",
            "args": [],
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Keep `"onFailure": "block"` (Claude Code 2.1.295 or later). Without it, a
crash, a timeout or an exit status other than 0 and 2 is a non-blocking error,
and Claude Code runs the tool. `"args": []` runs shguard directly, without a
shell. `shguard init` never writes over an existing file.

## How it decides

| Answer | When |
|---|---|
| Allow | The promise above holds for the whole command. |
| Ask | The command, or part of it, is outside the parsed subset, has no catalog row, uses an option or form the row does not list, or hits an Ask rule. |
| Block | A Block rule hit (for example `rm -rf /`, `git push --force`, `gh ... -R host/o/r`). |

The parser accepts a subset of bash: simple commands, pipelines, `&&`, `||`,
`;`, newlines, quoting, `"${NAME}"`, a leading `~`, and four redirects:
`2>&1`, `>&2`, `>/dev/null` and `2>/dev/null`. Anything else (`$(...)`,
unquoted `$X`, globs, other redirects such as `> file` or `<`, subshells,
braces, assignments, `&`) is Ask, whatever the command.

The embedded catalog (`catalog/*.toml`) covers read-mostly shell tools, `fd`
(without `-x`, `-X` and `-l`), `eza`, `tree`, read commands of `git`, its
local writes `add`, `commit`, `switch` and `stash`, `fetch` and `push`, read
commands of `gh` and a GET-only `gh api`, and `cargo` build, check, test,
clippy, fmt and doc. Every row names its upstream source.

### After a `cd`

The kernel tracks commands that change the working directory (`cd`). After
one, in the same command line:

- a relative path word is Ask (`cd / && rm -rf usr`);
- a row marked `cwd_sensitive` is Ask whatever its words. Every `git`, `gh`
  and `cargo` row is marked, because those tools read configuration or code
  from the directory they run in (`.git/config`, the git remotes,
  `.cargo/config.toml`, `build.rs`): `cd /tmp/x && git status` is Ask,
  `git status` alone is Allow. The `fd` row is marked too, because it
  searches the working directory recursively (`cd /Users/me && fd -H`).

A `cd` later in the line does not reach back: `git status; cd /tmp/x` is
Allow.

## Config

```toml
ask_outcome = "ask"      # "deny" (the default) refuses every Ask
decision_log = "/home/you/.local/state/shguard/decisions.jsonl"   # optional

[[row]]    # the catalog row schema; `source` is required
[[rule]]   # the catalog rule schema; outcome "block" or "ask"
```

User rows and rules are merged with the embedded catalog and go through the
same checks. A user `[[row]]` widens what can be Allowed, and the user owns
that. A `[[rule]]` only raises a decision: `[[rule]] key = ["rm"]
outcome = "ask"` makes every `rm` an Ask. Under `ask_outcome = "ask"`, an
embedded Block still holds for the commands the catalog covers.

Some heads can never get a covering row, from any file: interpreters and
shells (`bash`, `python3`, `node`, `sed`, `awk`, ...), wrappers that run
another command (`env`, `xargs`, `sudo`, `timeout`, ...), remote sessions
(`ssh`, `docker`, ...) and tools whose option syntax the grammar cannot
express (`find`, `tar`, `ps`). A row for one of them must set
`runs_code = true`, which keeps every command under it an Ask. `fd`
(`fdfind`), `split` and `gsplit` run code only through known options
(`fd -x`/`-X`/`-l`, `split --filter`); a row for them loads only when it
leaves those options out or declares that they take a `code` value
(`value = { takes = "code" }`). The embedded `fd-ask-broad` rule (fd from
`/` or a home directory is Ask) is keyed `fd` only; a user `fdfind` row
needs its own rule with `key = ["fdfind"]`. `fd` already has an embedded
row, and a second row with the same key is a load error, so user rows are
for `fdfind`, `split` and `gsplit`.

### Rows the catalog leaves out

Some commands are left out of the embedded catalog on purpose. Each recipe
below is a user `[[row]]`: adding it widens Allow, and the risk named next
to it is yours.

- `gh pr create` and `gh issue create` write to GitHub. A `--body-file`
  option would post any file the agent names, so the recipe takes the body
  inline.
- `jq`: `--arg name value` and `--argjson` take two values, which the grammar
  cannot express, so they stay Unknown. `jq -n env` and `$ENV` print the
  environment, tokens included, and `jq . <file>` reads any file; add a
  `[[rule]]` with the credential targets of the embedded `cat` rule.
- `nix build`: it runs the flake's code (derivation builders; on macOS the
  Nix sandbox is off by default), and an installable can name a remote flake
  (`github:o/r#x`), which is code from outside the repository.
- `git checkout` and `git restore` have no recipe: a row cannot require an
  option, so a row that allows `git checkout -b x` also allows
  `git checkout f`, which throws away local changes. Use `git switch -c`.

```toml
[[row]]
key = ["gh", "pr", "create"]
source = "https://cli.github.com/manual/gh_pr_create"
cwd_sensitive = true      # required under the embedded `gh pr` row
order = "permute"
dashdash = "ends"
positionals = []
opt = [
  { short = "t", long = "title", value = { takes = "inert" } },
  { short = "b", long = "body", value = { takes = "inert" } },
  { short = "B", long = "base", value = { takes = "inert" } },
  { short = "d", long = "draft" },
]

[[row]]
key = ["jq"]
source = "https://jqlang.org/manual/"
order = "permute"
dashdash = "ends"
positionals = ["inert"]   # the filter
rest = "path"
opt = [
  { short = "r", long = "raw-output" },
  { short = "c", long = "compact-output" },
  { short = "n", long = "null-input" },
  { short = "s", long = "slurp" },
  { short = "e", long = "exit-status" },
]

# A child key needs a row for its parent key.
[[row]]
key = ["nix"]
source = "https://nix.dev/manual/nix/latest/command-ref/new-cli/nix"
cwd_sensitive = true
order = "strict"
dashdash = "ends"
positionals = []

[[row]]
key = ["nix", "build"]
source = "https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-build"
cwd_sensitive = true
order = "permute"
dashdash = "ends"
rest = "path"
opt = [{ short = "L", long = "print-build-logs" }, { long = "no-link" }]
```

The grammar has no option with more than one value and cannot require an
option (`git commit` without `-m` opens the editor and waits).

A config or catalog that fails to load makes the hook deny every Bash call,
with the first error as the reason. `shguard check <file.toml>...` checks
catalog files.

### Decision log

`decision_log` turns on an append-only JSON Lines file, one line per Bash
decision: `{"ts": <unix seconds>, "decision": "allow"|"ask"|"deny",
"reason": ..., "command": ...}`. It is off unless set. The path must be
absolute and its directory must exist; put it where the agent cannot write.
The file is kept at mode 0600, and the log is not written when the path is a
symlink, a hard link, or anything but a regular file. **Each line holds the
command text**, so the file can hold secrets that were typed on a command
line. The log is written after the answer, with a 500 ms bound; a log that
cannot be written is reported on stderr and never changes the answer.

## Migrating from 0.9

The 0.9 config schema (`[[deny]]`, `[[ask]]`, `[[allow]]`, `[[redirect]]`,
`[[pipeline]]`, `escalation_floor`, `decision_log_path`) is gone. A 0.9 config
fails to load, which denies every Bash call; the reason says so. To migrate:

1. Move the old file aside (`mv ~/.config/shguard/config.toml{,.0.9}`).
2. Run `shguard init`.
3. Re-add your own policy as `[[rule]]` entries (to raise a decision) or
   `[[row]]` entries (to allow a command the catalog does not cover).

Two changes produce no error:

- A 0.9 config of comments only (what 0.9's `init` wrote) loads, and gets the
  new default `ask_outcome = "deny"`. Add `ask_outcome = "ask"` to keep being
  asked.
- `$XDG_CONFIG_HOME` is no longer read. The config is at `SHGUARD_CONFIG` or
  `~/.config/shguard/config.toml`.

Unknown input is Ask now: 0.9 allowed what no rule matched.

## Status

0.10.0 is the first release of the rebuild (see `CHANGELOG.md`). The
previous implementation is preserved at the tag
`legacy-v0.9.5`. `acceptance/` holds command corpora carried over from it;
each row's decision fields describe the old engine, not expectations for the
new one.

## License

MIT OR Apache-2.0. The proof-only kernel dependency `creusot-std`
(LGPL-2.1-or-later) exists only under `cargo creusot` and is not part of a
build.
