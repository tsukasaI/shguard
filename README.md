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
local writes `add`, `commit`, `switch`, `stash` and `remote` (list and
`prune`), `fetch` and `push`, read commands of `gh` and a GET-only `gh api`,
and `cargo` build, check, test, clippy, fmt and doc. Every row names its
upstream source.

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
[[hint]]   # key = ["make"], text = "..." for an Unknown command under key
```

A rule may carry `reason = "..."`, which the hook appends to its reason when
the rule hits; a `[[hint]]` appends its `text` when a command under its key
is Unknown (the longest matching key wins; a hint needs no row; a key has
at most one hint among your files, and yours replaces an embedded hint with
the same key). Neither changes a decision. Each
text is at most 300 bytes, on one line, with no control, line separator,
invisible or format character, so the agent reads what you
wrote.

User rows and rules are merged with the embedded catalog and go through the
same checks. A user `[[row]]` widens what can be Allowed, and the user owns
that. A `[[rule]]` only raises a decision: `[[rule]] key = ["rm"]
outcome = "ask"` makes every `rm` an Ask. Under `ask_outcome = "ask"`, an
embedded Block still holds for the commands the catalog covers.

The embedded catalog has no covering row for some heads: interpreters and
shells (`bash`, `python3`, `node`, `sed`, `awk`, ...), wrappers that run
another command (`env`, `xargs`, `sudo`, `timeout`, ...), remote sessions
(`ssh`, `docker`, ...) and tools whose option syntax the grammar cannot
express (`find`, `tar`, `ps`). A user row for one of them that does not set
`runs_code = true` still loads, and lets shguard Allow the commands it
covers. That can break P2 above: wherever the row gives a word that the tool
runs a role other than `code`, shguard does not treat it as code, so "no
position in it runs code" no longer holds there. It also blinds the embedded
Block rules to a command wrapped by `env`, `sudo` or `xargs` under such a
row, since the rules see the wrapper's words, not the wrapped command. The
loader warns about such a row: `shguard check` and `shguard check --config`
print each warning on its own line to stderr and still exit 0, and the hook
prints none. `runs_code = true` keeps every command under the head an Ask.
An Allow that only a user `[[row]]` gives (the embedded catalog alone would
not Allow the command) says so in the hook reason, "covered by the catalog
through a user [[row]]; no rule hit", and so does its decision log line.
`fd` (`fdfind`), `split` and `gsplit` run code only through known options
(`fd -x`/`-X`/`-l`, `split --filter`); a row for them loads only when it
leaves those options out or declares that they take a `code` value
(`value = { takes = "code" }`). The embedded `fd-ask-broad` rule (fd from
`/` or a home directory is Ask) is keyed `fd` only; a user `fdfind` row
needs its own rule with `key = ["fdfind"]`. `fd` already has an embedded
row, and a second row with the same key is a load error (the duplicate
check ignores ASCII case, so `FD` collides with `fd`), so user rows are
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
- Credential rules read a search pattern as a path: `grep .ssh docs/` is
  Ask. Pass the pattern with `-e` (`grep -e .ssh docs/`) to search for the
  text.
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
with the first error as the reason. `shguard check --config [<path>]` loads a
config the way the hook does (merged with the embedded catalog, with
`ask_outcome` and `decision_log`) and prints each error; a relative `<path>`
is read from the current directory, while `SHGUARD_CONFIG` itself must be
absolute. Without a path it checks the file the hook would read with the same
`HOME` and `SHGUARD_CONFIG`, and a missing file there is fine (no config,
embedded catalog only; a line on stderr says so). For `decision_log` it only
checks that the value parses and is an absolute path, so a path the hook
cannot write (see [Decision log](#decision-log)) passes `check --config`
and fails only when the hook writes the log.
`shguard check <file.toml>...` checks standalone catalog files; write a path
that starts with `-` as `./-name`. Both exit 0 when everything loads, 1 when
something does not, and 2 on a usage error.

### Decision log

`decision_log` turns on an append-only JSON Lines file, one line per Bash
decision: `{"ts": <unix seconds>, "decision": "allow"|"ask"|"deny",
"reason": ..., "command": ..., "class": ...}`. It is off unless set. The path
must be absolute and its directory must exist; put it where the agent cannot
write.
The file is kept at mode 0600, and the log is not written when the path is a
symlink, a hard link, or anything but a regular file. **Each line holds the
command text**, so the file can hold secrets that were typed on a command
line. The log is written after the answer, with a 500 ms bound; a log that
cannot be written is reported on stderr and never changes the answer.

`class` names the path that produced the answer, from the type of the reason
and never from its text. It is not a safety grade. The names are stable:

- `allow`: the embedded catalog covers the command.
- `allow_user_row`: an Allow that needs a user `[[row]]`.
- `rule_hit`: a rule hit (an Ask or a deny).
- `unknown:<kind>`: the catalog does not cover the command. `<kind>` is one of
  `no_row`, `opaque_command_name`, `unknown_option`, `opaque_option`,
  `missing_value`, `flag_given_value`, `dash_dash_not_allowed`,
  `extra_operand`, `option_after_operand`, `plus_word`, `code_role`,
  `runs_code`, `unknown_subcommand`, `path_opaque`, `path_dot_dot`,
  `path_non_ascii`, `path_after_cd`, `sensitive_after_cd`.
- `parse_refusal:<kind>`: the command is outside the parsed subset.
  `<kind>` is the construct, such as `unquoted_dollar`, `backquote`, `glob`,
  `input_redirect` or `redirect_target` (the full list is `UnsupportedKind`
  in `shguard-syntax`, in snake case). Also `parse_refusal:empty_command` and
  `parse_refusal:malformed_input` (hook input that is not the hook contract).
- `load_error`: the config or catalog failed to load. The hook denies, and
  since the log path comes from that config, such a line is not written in
  practice.

`shguard report [--show-commands] <log>` counts a log by class. It reads the
file line by line and prints one `<count>\t<class>` line per class, most
frequent first and by name among equals, the top 20 classes, then
`<total>\ttotal`, which counts every non-empty line, listed or not. A line
without `class` (written by an earlier version) counts as `unclassified`. A
line that is not UTF-8, is not a JSON object, or is longer than 2 MiB counts
as `invalid`. **The default output has no command text.** `--show-commands`
also prints, under each listed class, its five most frequent distinct
commands as `\t<count>\t<command as a JSON string>`; that output can hold
secrets, like the log. `report` exits 0, 1 for a log it cannot read or a
report it cannot write, and 2 on a usage error.

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
