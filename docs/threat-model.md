# Threat model

shguard sits between a coding agent and bash. The agent may be mistaken or
adversarially prompted; shguard reads the command it proposes and answers
Allow, Ask or Block before Claude Code runs it.

## What Allow claims

Allow means: the parser read the whole command, every simple command in it
is covered by the closed catalog, no rule hit, and no position in it runs
code. The kernel that decides this is proved with Creusot against that
specification. Allow does not mean the command is safe, harmless or
reversible; it means the command is one the catalog describes, with no rule
against it.

## Assumptions

The claim holds under three assumptions. Outside them, Allow says nothing.

- **P1, the parser agrees with bash.** bash reads every string the parser
  accepts as the same syntax tree. This is checked by differential tests
  against bash, brush-parser and shfmt, not proved. The agreement is shown
  for the C and UTF-8 charsets only; other locales and multibyte encodings
  (SJIS, GBK) are not covered (#1065).
- **P2, each row matches its tool.** A row's grammar (which options exist,
  which take a value, whether operands are paths) matches the real tool's
  argument parsing. Rows are written from the tool's documentation or
  source and reviewed; a mismatch can hide a word from the rules. Long
  options match by their full name only, so an abbreviation the tool would
  accept is Ask.
- **P3, the environment is not hostile.** `PATH` resolves command names to
  the real tools, no exported shell function (`BASH_FUNC_*`) or alias
  replaces them, and the code and configuration the repository brings
  (git hooks, `.git/config`, `.cargo/config.toml`, `build.rs`, proc macros,
  test binaries) are trusted to the extent the user trusts the repository.

## Out of scope

- Commands run by anything other than the Bash tool, and other tools of the
  agent (file writes, web fetches).
- What an allowed command does with data it reads: printing a file is
  reading it.
- A hostile local user, or an agent that can already write outside shguard's
  view (for example to `~/.claude/settings.json` through another tool).

## Known limits

Each item is Allow today, or a gap the catalog cannot express. They are
recorded, not hidden.

- **Credentials by absolute path.** The read rules match home paths written
  with `~` (`cat ~/.ssh/id_rsa` is Ask). The same file by its absolute path
  (`cat /home/you/.ssh/id_rsa`) is Allow, and so is any other readable file
  such as `cat /etc/shadow` (the operating system still refuses it to a
  normal user).
- **Symlinks.** shguard compares words, not the file system. `rm -r link/`
  with `link` a pre-existing symlink to a directory elsewhere is Allow and
  removes the target's contents.
- **Repository code (P3).** `cargo build` and `cargo test` run the
  package's `build.rs`, proc macros, dependencies' build scripts and test
  binaries, and may download from the registry the repository's
  `.cargo/config.toml` names. Its aliases can replace `cargo fmt` and
  `cargo clippy`.
- **Repository and user config (P3).** `git` reads repo-local and user
  config (`core.pager`, `core.fsmonitor`, `diff.external`, textconv drivers)
  and runs hooks; `gh` reads the git remotes and its own config. Inside the
  repository the agent works in, that is P3.
- **After a `cd`.** `cd` into another directory would make git, gh and
  cargo read *that* directory's config and code. Every git, gh and cargo row
  is `cwd_sensitive`, so `cd /tmp/x && git status` is Ask. Only `cd` is
  tracked; `pushd`, `popd` and `env -C` have no row and are Ask.
- **Writes to `.env`.** `cp x .env` is Allow while reading `.env` is Ask
  (accepted by the owner, #1090). Writes to relative credential-shaped
  directories (`./.ssh`, `./.aws`) are Allow; the home copies are protected
  (#1092).
- **git push remotes.** Pushes to `https:`, `http:`, `ssh:`, `git:`,
  `git+ssh:`, `ssh+git:`, `file:` URLs and to absolute or `~` paths are Ask,
  and force pushes are Block. Still Allow: the scp form
  (`git push git@host:o/r main`) and other `<scheme>://` helper URLs (#1098),
  `<helper>::` remotes other than `ext::` (#1096), glob refspecs
  (`'refs/heads/*:refs/heads/*'`, #1095), `--follow-tags` (#1097), and
  relative local remotes (`git push sub/repo main`, #1100).
- **git format placeholders.** `%G?`-style placeholders in a quoted
  `--format` (`git log '--format=%G?'`) verify signatures through
  `gpg.program`, as `--show-signature` would (#1099).
- **gh.** `-R/--repo`, URL operands and every `--jq`/`-q` are Block, since
  they can send a token to another host or print gh's environment.
  `--template` is Allow; gh's template functions have no file or exec
  access.
- **Tilde words in option position.** `cd ~/x` and `ls ~/x` are Ask today
  (a fail-closed parse of the argv spec, #1038), at a usability cost.

## The hook itself

- A config or catalog that fails to load denies every Bash call. A 0.9
  config is reported as such, with how to migrate.
- A panic answers with a deny. With `"onFailure": "block"` in the hook
  entry, a crash, a timeout or an exit status other than 0 and 2 also
  blocks; without it, Claude Code runs the tool. `shguard init` prints the
  entry with it.
- The decision log is opt-in, append-only, mode 0600, and written only
  after the answer, with a bounded wait so a FIFO or a hung mount at the
  path cannot hold the answer back. It is not written through a symlink or
  a hard link at the file; a symlink higher up the path is followed, so the
  directory must be out of the agent's reach. It holds command text, so it
  can hold secrets.
- `SHGUARD_CONFIG` must be absolute. There is no project-local config: the
  repository the agent works in cannot change shguard's policy.
