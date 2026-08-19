# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

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
