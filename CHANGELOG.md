# Changelog

## Unreleased

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
