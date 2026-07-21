# Changelog

All notable changes to this project are documented in this file.

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

[0.2.0]: https://github.com/tsukasaI/shguard/releases/tag/v0.2.0
[0.1.0]: https://github.com/tsukasaI/shguard/releases/tag/v0.1.0
