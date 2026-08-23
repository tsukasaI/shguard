# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- Fixed a bypass of `self-protect-config-sed-tilde`: GNU `sed` permutes
  options after operands, so `sed 's/a/b/' $(echo -i ~/.config/shguard/config.toml)`
  performed an in-place edit of shguard's own config at runtime while
  `matches_except_target`'s existing all-opaque-tail relaxation stayed
  silent (one resolved token — the script — survived in the tail). Closes
  #117.

- The device-destroying command family (`dd`, `shred`, `mkswap`, `mkfs.*`,
  redirect-to-`/dev/`, `tee`-to-`/dev/`) omitted several tools with the
  same destructive effect (#123): `dcfldd` (a drop-in `dd` variant, same
  `if=`/`of=` semantics) now mirrors `dd-write-device` and
  `self-protect-config-dd-tilde`; `wipefs -a`/`-o` (erases a
  filesystem/partition-table signature) and bare `blkdiscard` (always
  discards its target, no confirmation) are now blocked. `cp` writing to a
  `/dev/` target now asks — `cp` has no `if=`/`of=` flags to disambiguate
  source from destination the way `dd`/`dcfldd` do, so this can't
  distinguish `cp /dev/sda backup.img` (reading a device) from `cp file
  /dev/sda` (writing to one) beyond checking both positions; the everyday
  `/dev/{null,zero,urandom,random}` idiom (harmless in either role) is
  carved out via `except_targets` to stay `Allow`. `dcfldd` also mirrors
  `shell-init-dd`'s persistence-path coverage, and the `cp` rule's target
  list covers `-t`/`--target-directory=` (glued, separated, and the
  bare-directory-with-no-trailing-slash form) and `--remove-destination`
  (which replaces a device node outright, not covered by the
  harmless-in-either-role carve-out).

- `rsync --delete` syncing into a dangerous local target is functionally a
  recursive wipe of the destination, the same severity class already
  blocked for `rm -rf` against one, but had no blocklist coverage (#127).
  Like `cp-write-device` above, `rsync` has no flag marking which argv
  position is the destination, so target matching can't tell `rsync
  --delete src/ /` (wiping `/`) from `rsync --delete / backup/` (reading
  `/`, a real full-system-backup idiom) apart from checking both
  positions. Split into two new rules by anchor rather than one flat rule:
  `/`, `/*`, `/dev/*`, and `find`'s own `{}` placeholder now block (rare
  and alarming in either role); `~` and `.` ask (common as a source, e.g.
  "sync my home to backup" — blocking there would over-fire on daily
  usage). Recognized spellings: `--delete`, `--delete-before/-during/
  -delay/-after/-excluded/-missing-args`, and the `--del` alias (also
  added to the pre-existing `self-protect-config-ancestor-rsync-tilde`,
  which was missing it too). Known gap: some rsync implementations (e.g.
  macOS's default openrsync) accept unambiguous long-option prefixes
  (`--delete-a` alone can trigger deletion), which no finite flag list can
  enumerate — same class as the GNU long-option-abbreviation gap already
  noted on `cp-write-device` above.

- `truncate -r`/`--reference=RFILE` sets the target's size to match
  RFILE's size instead of an explicit number — the same unrecoverable
  content-destruction effect as `truncate -s`, but `truncate-zero` only
  checked for `-s`/`--size` (#131). New `truncate-reference` rule blocks
  on `-r`/`--reference` presence alone, regardless of what RFILE actually
  is (shrinking truncates data, growing pads with NUL — both destructive).
  Known gap, same class as the two above: GNU's unambiguous long-option
  prefixes (`--ref`) aren't enumerable and bypass this rule (and
  `truncate-zero`'s own `-s`/`--size` matching has the identical gap,
  pre-existing).

- `rsync`/`mv`/`install` writing a regular file's bytes onto a `/dev/`
  device special file had zero coverage, the same destructive effect as
  the already-blocked `dd`/`tee`/redirect shapes (#136). Unlike
  `cp-write-device` (#123, `ask`): no common daily idiom reads FROM a
  device as the SOURCE for these three, so `mv-write-device`,
  `install-write-device`, and `rsync-write-device` block outright.
  `/dev/shm` (tmpfs scratch space — a real idiom, e.g. `mv build.tar
  /dev/shm/`) is carved out via `except_targets`. `mv`/`install` also
  cover `-t`/`--target-directory=`, mirroring `cp-write-device`'s full
  target list; `install` additionally excepts `/dev/stdin` (a common
  `curl ... | install /dev/stdin dest` idiom, never a disk device node
  even in the write role).

- Fixed a bypass of `except_targets` suppression affecting every rule
  that declares it (not specific to #136's new rules, though that's what
  surfaced it): `except_targets` is deliberately never normalized
  (matched against the raw resolved token — see this file's own
  `except_targets` docs for why), but `targets` itself IS normalized, so
  a `..`-path-ascent respelling of an excepted candidate (`/dev/shm/../
  sda`) could textually start with an excepted prefix (`/dev/shm/`)
  while actually resolving to a target the exception was never meant to
  cover (`/dev/sda`). `CommandRule::matches` now refuses to treat any
  `/`- or `~`-rooted candidate containing a literal `..` path segment as
  excepted, regardless of what `except_targets` says — the same
  fail-closed posture already applied to unresolvable words.

## [0.6.0] - 2026-08-19

### Security

- Fixed a normalization bug where an unquoted, empty brace-alternation
  member (e.g. `{,rm} -rf /`) could win `argv[0]` resolution ahead of the
  real command, resolving to `""` and bypassing every blocklist rule
  entirely (`Allow` instead of `Block`) — found by the nightly differential
  fuzzer (issue #93). `chunks_to_words` now elides an empty resolved
  segment based on whether it was genuinely quoted, not on whether an
  `$IFS` split happened to produce multiple segments; a quoted empty word
  (`''`, `""`, `$''`) still always survives.

- The sudo floor (rule 10, #32) generalises to a unified escalation posture
  covering `doas`, `su`, `pkexec`, and `run0` alongside `sudo` (#35, #36):
  each is now a transparent wrapper, and a command wrapped by any of the
  five floors on a blocklist miss exactly like `sudo` already did (including
  through another wrapper, and on the `bash -c` inner-command path).
- New top-level config key `escalation_floor` (default `"ask"`, `"deny"`
  allowed, `"allow"` rejected at load) raises the floor for all five vectors
  at once via `decision.max(escalation_floor)` — no sudo-specific or
  per-vector config key. This resolves the known limitation noted in 0.2.0:
  the floor itself is still not config-downgradable below its default.
- A user `[[deny]]`/`[[ask]]` rule naming one of the five commands directly
  (e.g. `command = "doas"`) is now reachable — rule matching checks every
  hop of a command's wrapper-unwrap chain, not just the fully-resolved
  effective command, so a rule for the wrapper itself and a rule for the
  wrapped command can coexist and both fire correctly.
- **Compatibility note**: `doas`/`su`/`pkexec`/`run0` joining
  `TRANSPARENT_WRAPPERS` means an existing `[[allow]]` entry that happens to
  match one of them (exactly, or via a `command_prefix` that now collides,
  e.g. `"do"` or `"run"`) is rejected at config load, where it previously
  loaded fine — this fails shguard closed for every command until the entry
  is removed or narrowed, the same load-time rejection `sudo`-matching
  `[[allow]]` entries already had.

## [0.5.0] - 2026-08-17

### Added

- Shell-init and persistence paths (`~/.bashrc`, `~/.zshrc`,
  `~/.config/fish/config.fish`, `/etc/cron.*`, LaunchAgents, systemd user
  units, `~/.ssh/authorized_keys`, `/etc/ld.so.preload`, and 30+ more) are
  protected across every write mechanism — `tee`, `cp`, `mv`, `install`,
  `sed -i`, `dd of=`, `ln`, `rm`, `unlink`, and now bare shell redirection
  (`>`/`>>`) — all at `ask` (#259, #198, #261).
- `find`'s own `{}` placeholder is recognized wherever `find` substitutes
  it, not only as a standalone token: `rm -f ./{}`, `{}/`, `x/../{}`, `/{}`
  and `~/{}` now block alongside the bare spelling (#140, #267).
- `find … | xargs rm -f` blocks, matching `find -exec rm -f {}` and
  `find -delete` — the piped form has the same delete-every-match effect
  (#268).
- New optional `sink_required_flags` on `[[pipeline]]` rules, constraining
  the resolved sink's own flags (#268).
- `eval` and `awk`'s bare-positional script route through interpreter-code
  recursion the way `sh -c` does (#255, #258).
- The parser handles `if`, background jobs (`&`), `[[ ]]`, and pipeline
  negation (#256).
- A redirect target's statically-known substitution output is checked
  against the redirect rules (`> $(echo /dev/sda)`), not only the literal
  target (#130).

### Fixed

- Wrapper flag handling no longer mistakes a flag's value for the wrapped
  command: `env`'s own value flags (#250), `stdbuf`/`xargs` (#264),
  getopt-style short-flag clusters (`env -iu FOO rm -rf /`, #265), GNU
  unambiguous long-option abbreviations (`env --uns`, `xargs --max-a`,
  `stdbuf --out`, #266), and `env -S`'s argv splicing, which is now
  reconstructed and recursed (#265).
- `fish` is modelled on its own option surface rather than POSIX `sh`'s:
  `-C`/`--init-command`, attached values (`--command=CODE`, `-cCODE`),
  repeated `-c`, and unique-prefix long options are each read as what they
  are (#269).
- `find -exec` spawning a bare shell interpreter with no `-c` no longer
  slips through (#196 follow-up, #257).
- BSD/macOS `sed -I` counts as an in-place flag everywhere `-i` does,
  including shguard's own config self-protection (#263).
- `rm -R` (uppercase) counts as recursive (#206), and an ANSI-C-decoded
  embedded NUL is treated as unresolvable rather than silently merging
  tokens (#138).
- Redirect-target decisions fold worst-wins across rules, targets, and both
  target-resolution channels, instead of taking the first match and
  short-circuiting the remaining checks (#261).

### Compatibility notes

- **`echo ... >> ~/.zshrc` now asks.** Appending to a shell-init or
  persistence path is the standard installer idiom, so it asks rather than
  blocks — but it is no longer silently allowed. `>` truncation of the same
  paths asks too, matching every other write mechanism for those targets.
- A config using `[[pipeline]]`'s new `sink_required_flags` field fails to
  load on an older shguard (unknown fields are rejected), which fails
  closed for every command until the field is removed.
- Two decisions deliberately relaxed where the previous behavior did not
  match the real tool: `fish script.fish -c '...'` allows (fish stops
  option parsing at the script operand, so `-c` is data), and
  `find -exec fish {} -c '...'` asks rather than blocks, the same demotion
  `find -exec sh {} -c` already had.

## [0.4.1] - 2026-08-15

- **Compatibility note**: a `command` value containing whitespace (issue
  #96) used to be inert — `CommandMatch::Exact` compared it against one
  whole resolved argv token, which a `command` value containing any
  whitespace (leading, trailing, or between multiple words) could never
  equal, so it silently matched nothing — and now desugars into a command name
  plus `required_tokens`, making it live. A config that harmlessly did
  nothing before an shguard upgrade can start actively matching (and, in
  an `[[allow]]` entry, downgrading `Ask` to `Allow`) after upgrading —
  audit existing configs for accidental whitespace in `command` values,
  especially in `[[allow]]` entries. As a consequence, exact-matching a
  literal command name that itself contains a space (e.g. from a quoted
  `argv[0]` like `'my prog' --arg`) is no longer possible — whitespace in
  `command` is now unconditionally the subcommand-sugar split, with no
  escape hatch; accepted as a deliberate trade-off, since no known
  real-world command has a literal space in argv[0] and no rule in this
  repo relied on the old behavior. This also means several previously-
  loading configs now fail to load instead (a multi-word `command` with a
  flag-looking extra word, e.g. `command = "rm -rf"`; whitespace in
  `command_prefix`; an `[[allow]]` entry whose sugar-derived command name
  matches a shell interpreter) — and per this project's fail-closed
  design, any user-config load error makes the hook Ask on every single
  command until the config is fixed, not silently ignore the bad entry.
- **Compatibility note**: the `required_tokens` + `except_targets`
  dead-config rejection (issue #96) is not limited to configs that use the
  new `command` sugar or that contain whitespace — it applies to any
  command rule with that shape, sugar or not. A pre-existing, hand-written,
  sugar-free rule that loaded fine before this PR — e.g. `command = "gh"`
  with `required_tokens = ["repo", "delete"]` and `except_targets = [{
  prefix = "sandbox/" }]` (`targets`/`value_flags` both empty) — now fails
  to load, because none of `except_targets`' alternatives cover the
  literal words "repo"/"delete". Same fail-closed consequence as the other
  entries above: the whole config is rejected, not just the offending
  rule.
- **Compatibility note**: a `required_tokens` entry with leading or
  trailing whitespace (e.g. `"delete "`) is now rejected at load time — it
  can never equal a resolved argv word, so it previously loaded and
  silently never matched. Internal whitespace stays legal (e.g. `"repo
  delete"` as one token, matching a quoted positional argument). Same
  fail-closed consequence as the entries above.

## [0.2.0] - 2026-07-21

- `sudo`-prefixed commands now floor to Ask on a blocklist miss instead of
  silently allowing, independent of whether the wrapped command trips its
  own rule (#32). This includes `sudo` reached through other wrappers
  (`env sudo ls`) and `sudo bash -c '<benign script>'`. The floor is not
  config-overridable: an `allow` entry for the wrapped command
  (`command = "gh"` vs `sudo gh pr view`) no longer clears it, and
  `command = "sudo"` allow entries were already rejected at load time.
- A transparent-wrapper chain whose wrapped command cannot be statically
  resolved (`env $(echo sudo) ls`, `env $SUDO ls` — at runtime these run
  whatever the substitution/variable holds, possibly `sudo`) now fails
  closed to Ask instead of allowing.
- Known limitation: a user `[[deny]] command = "sudo"` rule remains
  unreachable (rule matching resolves through `sudo` as a transparent
  wrapper), so the floor's Ask is the strictest sudo-wide posture
  expressible today; a config key to raise it to deny is tracked in
  [#35](https://github.com/tsukasaI/shguard/issues/35).

## [0.1.0] - 2026-07-20

Initial release.

- `PreToolUse` hook for AI coding agents that blocks dangerous shell
  commands via real tokenisation and static normalisation (parse →
  normalise → danger check → structural gate), not regex matching.
- Covers all GuardFall-catalog bypass classes plus two shguard-specific
  extensions (ANSI-C quoting, variable indirection); see the regression
  table in README.md.
- User-configurable command policy (deny/ask/allow) via `SHGUARD_CONFIG`.
- Ships as a single binary for macOS (aarch64, x86_64) and Linux
  (x86_64, aarch64), published via GitHub Releases and crates.io.

[0.4.1]: https://github.com/tsukasaI/shguard/releases/tag/v0.4.1
[0.2.0]: https://github.com/tsukasaI/shguard/releases/tag/v0.2.0
[0.1.0]: https://github.com/tsukasaI/shguard/releases/tag/v0.1.0
