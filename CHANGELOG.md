# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

- `sudo`-prefixed commands now floor to Ask on a blocklist miss instead of
  silently allowing, independent of whether the wrapped command trips its
  own rule (#32). This includes `sudo` reached through other wrappers
  (`env sudo ls`) and `sudo bash -c '<benign script>'`. The floor is not
  config-overridable: an `allow` entry for the wrapped command
  (`command = "gh"` vs `sudo gh pr view`) no longer clears it, and
  `command = "sudo"` allow entries were already rejected at load time.

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

[0.1.0]: https://github.com/tsukasaI/shguard/releases/tag/v0.1.0
