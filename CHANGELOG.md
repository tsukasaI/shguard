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
