# Changelog

## Unreleased

### Added

- An embedded `fd` row: names only, without `-x`/`--exec`,
  `-X`/`--exec-batch`, `-l`/`--list-details`, `-C`/`--base-directory` or
  `--ignore-file`; `fd` from `/` or a home directory is Ask, and so is `fd`
  after a `cd` (#1111).
- Embedded rows for `git add`, `git commit`, `git fetch`, `git switch`,
  `git stash` (with `list`, `show`, `pop`, `apply`), a GET-only `gh api`,
  `eza` and `tree`; `git log` takes `-<number>` (`-5`). A bare `git commit`
  is Allowed and opens the editor (#1115).
- README recipes for user rows the catalog leaves out: `gh pr create`, `jq`,
  `nix build` (#1115).
- Rule targets of kind `component` and `component_prefix`: the pattern is
  one or more whole segments anywhere in the path (`.ssh` covers
  `/Users/me/.ssh/id_rsa` and `sub/.ssh`), or starts one (`.env.` covers
  `app/.env.local`). Proved in the kernel (#1113).
- Recursive reads (`grep -r`, `rg`, `ls -R`, `fd`, `tree`, `eza`) of
  `/System` (which holds the `/System/Volumes/Data` firmlink to every
  home), `/var/root` and `/private/var/root` are Ask, like
  the other spellings of the home and root directories (#1113).
- A search pattern of `grep` or `rg` that names a credential file is a path
  word, so `grep .ssh docs/` and `grep -rn .env src/` are Ask; pass it with
  `-e PATTERN` (`grep -e .ssh docs/`) to search for the text (#1113).
- Reads and `git` operations on `.env.*` siblings such as `.env.example`
  are Ask too (`git add .env.example`, `cat .env.example`) (#1113).
- A `component` or `component_prefix` target with a `..` segment is a load
  error (#1113).

### Changed

- The embedded catalog now has rows keyed `git add`, `git commit`,
  `git fetch`, `git switch`, `git stash`, `gh api`, `eza` and `tree`. A user
  config with its own row under one of those keys fails to load (duplicate
  key, every Bash call is denied) until that row is removed (#1115).
- `fd`, `split` and `gsplit` are no longer denylisted heads. A row for one of
  them, or for `fdfind` (embedded or user), loads when it leaves out the
  options that run code (`fd -x`/`-X`/`-l`, `split --filter` and its
  abbreviations) or declares that they take a `code` value; listing one any
  other way is a load error (#1111).
- A row whose head holds a `/` (`/bin/bash`, `/opt/homebrew/bin/fd`) is a
  load error: the kernel matches heads byte for byte, so a path head skipped
  the head checks (#1111).
- The credential rules of `cat`, `head`, `tail`, `grep`, `rg`, `wc` and
  `sort` match credential names at any depth and under any spelling of the
  home directory, so `cat /Users/me/.ssh/id_rsa` and `cat sub/.env` are Ask;
  `cp`, `uniq` and `git` get the same rule, which also makes `cp x .env`
  an Ask (#1113).

## 0.10.0 - 2026-10-31

A rebuild. The 0.9 engine is preserved at the tag `legacy-v0.9.5`.

### Breaking

- **Unknown input is Ask.** 0.9 allowed what no rule matched; now Allow
  needs every simple command covered by the closed catalog, with no rule hit
  (see the promise in the README).
- **New config schema.** The 0.9 keys (`[[deny]]`, `[[ask]]`, `[[allow]]`,
  `[[redirect]]`, `[[pipeline]]`, `escalation_floor`, `decision_log_path`)
  are gone. A 0.9 config fails to load, which denies every Bash call; the
  reason names it as a 0.9 config. Move it aside, run `shguard init`, and
  re-add your policy as `[[rule]]` or `[[row]]` entries.
- **Default `ask_outcome = "deny"`.** A 0.9 config of comments only loads
  without error and now refuses every Ask; add `ask_outcome = "ask"` to be
  asked.
- **`$XDG_CONFIG_HOME` is not read.** The config is at `SHGUARD_CONFIG`
  (absolute) or `~/.config/shguard/config.toml`.
- **`decision_log` replaces `decision_log_path`.** Its directory must
  exist; each line holds the command text.
- **Library API.** `parse_config` returns a `ConfigHead` (`ask_outcome`,
  `decision_log`), and `Settings` has a `decision_log` field.

### Added

- A kernel proved with Creusot, a bash-subset parser checked against bash,
  brush-parser and shfmt, and an embedded catalog for core tools, git, gh
  and cargo.
- `shguard init`, which prints the hook entry with `"onFailure": "block"`.
- `shguard check <catalog.toml>...`.
- The loader rejects an empty rule `id`, a `~user` target, and `.` as a
  `prefix` or `under` target, none of which could locate or match anything.
- `cwd_sensitive` rows: git, gh and cargo after a `cd` are Ask.
