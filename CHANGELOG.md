# Changelog

## Unreleased

### Changed

- A user row for a head that runs other code or has option syntax the
  grammar cannot express (an interpreter, shell, wrapper, remote session,
  `find`, `ps`, as the README lists) and that does not set `runs_code` is
  now a warning, not a load error. Such a config failed to load on 0.12.0
  and now loads, so the row can make shguard Allow commands under that head.
  `shguard check` and `shguard check --config` print each warning to stderr
  and exit 0; the hook prints none. Set `runs_code = true` to keep the head
  an Ask (#1242).
- The hook reason of an Allow that only a user `[[row]]` gives reads
  "covered by the catalog through a user [[row]]; no rule hit", and the
  decision log line carries it (#1242).

## 0.12.0 - 2026-11-10

### Added

- `shguard check --config [<path>]` checks a config file as the hook loads
  it (#1124).

### Changed

- `cargo build|check|test|clippy|doc`: option values now go through the path
  checks (a variable, `..` or non-ASCII value is asked). Any `-` value is
  asked on build, check and doc; on test and clippy a word after
  `-p`/`--bin`/`--example`/`--test`/`--bench` is read as cargo does, so a
  hidden option (`-p --config=x -p y`, `-p -m/x/Cargo.toml`) is not allowed.
  A `--fix` anywhere in a `cargo clippy` command is asked (#1225).
- tree: `-L`, `-P` and `-I` are no longer listed, so they are asked (#1224).
- `shguard check` exits 2 (usage error) when its first catalog path starts
  with `-`, so write such a path `./-name`: `shguard check -foo.toml`, which
  0.11.1 read as a file, must now be `shguard check ./-foo.toml` (#1124).
- The loader refuses more user rows that 0.11.1 accepted. A head that can
  never get a covering row (an interpreter, shell, wrapper, remote session
  or tool whose options the grammar cannot express, as the README lists)
  under another ASCII case (`Python3`, `ENV`, `SSH`), or a versioned
  `python` spelling (`python3.10`, and any `python` followed by a digit), is
  now treated like `python3` and `env`: the row must set `runs_code`. A
  parent option that spells a `runs_code` child's key and whose value is
  `{ optional = "code" }` is also refused; it must be `{ takes = "code" }`,
  since only that makes the option run its value. Such a config fails to
  load, so the hook denies every Bash call until the row is fixed (#1125).
- A head that has code-running options (`fd` with `-x`, `split` with
  `--filter`) is now recognised under any ASCII case. A row headed `SPLIT`
  that lists `--filter` as a plain flag loaded on 0.11.1 and now fails to
  load with the same error as one headed `split`, so the hook denies every
  Bash call until the row is fixed (#1138).
- `pythonw` (the framework GUI build of `python`), and `pythonw` followed by
  a digit (`pythonw3.12`), are now treated like `python3`: the row must set
  `runs_code`. A config with such a row and no `runs_code` loaded on 0.11.1
  and now fails to load, so the hook denies every Bash call until the row is
  fixed (#1139).
- `perl`, `ruby`, `php` and `lua` followed by a digit (`ruby3.1`,
  `perl5.30`) are now treated like the bare name, and `pypy`, `pypy3`,
  `ipython`, `luajit`, `tclsh`, `expect` and `pwsh` are new interpreter
  heads: the row must set `runs_code`. A config with such a row and no
  `runs_code` loaded on 0.11.1 and now fails to load, so the hook denies
  every Bash call until the row is fixed (#1140).
- A row head with a non-ASCII byte (`baſh`) is now a load error, even when
  the row sets `runs_code`. A config that loaded on 0.11.1 with one now
  fails to load, so the hook denies every Bash call until the row is fixed
  (#1141).
- Row keys that differ only in ASCII case now count as duplicates, so a
  user row keyed `FD` or `Fd` next to the embedded `fd` row, or two user rows
  that differ only in case, is a load error. Such a config loaded on 0.11.1
  and now fails to load, so the hook denies every Bash call until the row is
  fixed (#1168).
- The version suffix of an interpreter head may also start with a hyphen
  and a digit (`python-3.10`, `ruby-3.1`, `luajit-2.1.0-beta3`), and
  `luajit` and `pwsh` followed by a digit are versioned spellings too
  (#1178). So are `pypy`, `ipython` and `tclsh` followed by a digit
  (`pypy3.10`, `ipython3`, `tclsh8.6`) (#1177). A row with such a head and
  no `runs_code` loaded on 0.11.1 and now fails to load, so the hook denies
  every Bash call until the row is fixed.
- The heads `jruby`, `truffleruby`, `irb`, `erb`, `wish`, `elixir`, `iex`,
  `groovy`, `julia` and `Rscript` are now treated like `ruby` and `python3`:
  the row must set `runs_code`. A config with such a row and no `runs_code`
  loaded on 0.11.1 and now fails to load, so the hook denies every Bash call
  until the row is fixed (#1179).

## 0.11.1 - 2026-11-02

### Added

- Embedded rows for `git remote` (lists the configured remotes, `-v`) and
  `git remote prune` (`-n`): it prunes the stale remote-tracking refs of a
  configured remote. URL and `ext::` operands are asked, because git falls
  back to a URL when the operand is not a configured remote. `git fetch
  --prune` stays Ask because a refspec argument can point it at local
  branches.

## 0.11.0 - 2026-11-01

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
- An optional `reason` on `[[rule]]` and a `[[hint]] key text` table, in the
  catalog and the user config. The text is appended to the hook's reason
  when the rule hits, or when a command under the hint's key is Unknown; no
  decision changes. Embedded rules carry reasons, and `find`,
  `git checkout` and `git restore` have hints (#1112).
- `packages.default` in the flake: the `shguard` binary built with
  nixpkgs' `rustPlatform.buildRustPackage` from `Cargo.lock`, so a Nix
  configuration can install it from a pinned rev (#1114).

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
