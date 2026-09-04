//! Composition-root-facing user config loader (plan.md §6 item 8) —
//! `crate::gate`/`crate::rules` own the *rules*, this module owns
//! *finding* them: where the user's config file lives, and the
//! fail-closed/silent-skip boundary around reading it.
//!
//! # Discovery
//!
//! `SHGUARD_CONFIG` env var (any value counts as "set", even `""`) >
//! `$XDG_CONFIG_HOME/shguard/config.toml` (an empty `XDG_CONFIG_HOME`
//! counts as unset, per the XDG spec) > `$HOME/.config/shguard/config.toml`
//! (an empty `HOME` counts as unset too, same as `XDG_CONFIG_HOME` — an
//! empty string is never treated as "search relative to the current
//! working directory", issue #59).
//! No project-local `.shguard.toml` auto-discovery: shguard's own threat
//! model includes "the agent it's guarding might be adversarially
//! prompted to defeat it," and a project-local config file sits inside
//! the same repo the agent already has Bash/Write/Edit access to — a
//! user-global path is a meaningfully higher-friction target.
//!
//! Deliberately no `directories`/`dirs` crate dependency: distribution is
//! macOS+Linux only (plan.md §2 step 11), this project has no other
//! convenience-crate dependencies (no `clap`, even for `--version`), and
//! [`Policy::resolve_config_path`] taking `Option<&str>` arguments
//! directly (rather than reading env vars itself) is easier to unit-test
//! than a crate call would be — no `std::env::set_var` (`unsafe` in
//! recent Rust editions, and unsound under parallel `cargo test`).
//!
//! # Fail-closed policy
//!
//! `SHGUARD_CONFIG` set (to anything), or a resolved config path
//! (explicit or default) existing but unreadable/unparseable/unmergeable,
//! is a hard [`ConfigError`] — [`Policy::load`]'s caller refuses to
//! evaluate any command until it's fixed, the same posture
//! `Rules::embedded`'s own load failure already has
//! (`crate::gate::analyze`). A *resolved* default path simply not
//! existing at all (`std::fs::symlink_metadata` itself returning
//! `io::ErrorKind::NotFound`) is a hard failure too, not a silent
//! embedded-only fallback (issue #433). The only case that still runs
//! embedded-only is [`Policy::resolve_config_path`] itself returning
//! `None`, meaning no config *location* is even resolvable
//! (`SHGUARD_CONFIG` unset, and neither `XDG_CONFIG_HOME` nor `HOME`
//! usable) — see that function's own docs. Anything else a resolved
//! default path could be — a dangling symlink, a directory, an unreadable
//! file, or any other `lstat` error — is a hard failure too
//! (issue #39): `symlink_metadata` (not `read_to_string`'s own error) is
//! what decides "nothing there" vs. "something's there but broken".
//!
//! # Self-protecting the config file
//!
//! [`self_protection_toml`] generates `[[deny]]` rules, at load time,
//! targeting the config directory for the full audited set of write/
//! delete-capable primitives (issue #101): `tee`, `cp`, `mv`, `install`,
//! `sed -i`, `dd`'s `of=<path>` shape, `rsync`, `rmdir`, `perl -i`,
//! `patch`, and `find` combined with `-exec`/`-execdir`/`-ok`/`-okdir`
//! (the last as `decision = "ask"`, not `"block"` — the danger lives in
//! what `find` invokes, only partially visible to a command-line-only
//! analyzer), plus one `[[redirect]]` rule (issue #100) for the same
//! directory via bare shell redirection (`>`/`>>`) — parity with the
//! write-capable commands, since a path unreachable via `tee` must also
//! be unreachable via `>`. [`ancestor_rules_toml`] adds a second,
//! `decision = "ask"` family covering `rm -r`/`mv`/`rsync --delete`
//! against an ANCESTOR of the config directory (`~/.config`, `~`, and
//! their resolved equivalents) — deleting or renaming an ancestor takes
//! the config directory with it even though the ancestor path itself
//! never appears in the direct-target list above —
//! the one place this crate builds a rule's TOML text in code rather than
//! reading it from a file, because the directory is only known once
//! `$HOME`/`$XDG_CONFIG_HOME` are read for *this* invocation; the
//! embedded blocklist is fixed at compile time and cannot know an
//! individual user's home directory. [`self_protection_directories`]
//! walks the config path's full symlink chain, hop by hop, so a config
//! deployed behind one *or more* symlinks (e.g. into a dotfiles repo
//! behind a `stow`/`home-manager`-style layer of indirection) gets
//! *every* hop's directory protected, not only the literal path and the
//! fully-resolved end — see [`self_protection_directories`]'s own docs for
//! the walk's mechanics and its fail-closed behavior on a too-long or
//! cyclic chain. `rules/blocklist.toml`
//! separately carries a *static* rule for the literal `~/.config/shguard/`
//! token — `normalize.rs` never resolves `~`/`$HOME` to an actual
//! filesystem path (no environment lookups anywhere in parse/normalise,
//! by design), so an agent that already knows its own `$HOME` (trivially
//! available via `pwd`/`echo $HOME`) could otherwise dodge a `~`-only
//! rule by writing an absolute path instead — this module's dynamically
//! resolved rule closes that gap.
//!
//! Both mechanisms are disclosed as partial, not complete, in the README:
//! bare shell redirection (`cat > path <<EOF`, rule 9's documented
//! redirection blind spot — `crate::gate` never analyses what a
//! redirection target overwrites) and any `SHGUARD_CONFIG`-via-shell-
//! profile vector are not caught by either.
//!
//! [`SELF_PROTECT_INIT_TOML`] adds a third, non-directory-scoped `[[deny]]`
//! rule against `shguard init` itself (with or without `--force`, issue
//! #435) — `Policy::init`'s own `--force` overwrite isn't a write-capable
//! *shell* primitive the rules above's target-matching can see, since the
//! target path never appears on `shguard init`'s own command line.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::rules::{Allowlist, Rules, UserConfig, merge_user_config};

/// Everything that can go wrong loading a user policy. Every variant is a
/// hard failure — [`Policy::load`] never falls back to "ignore the bad or
/// absent config and use embedded-only" once any config path was resolved,
/// explicit or default (see the module docs' fail-closed policy).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// `path` could not be read: either `SHGUARD_CONFIG` named it
    /// explicitly (including naming a missing file — the user committed
    /// to an exact location, so that case is this variant, not
    /// [`ConfigError::Missing`]), or something exists at the default
    /// location but `lstat`/read failed; see [`Policy::load`].
    #[error("could not read {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The default config path (`XDG_CONFIG_HOME`/`HOME`-derived, never an
    /// explicit `SHGUARD_CONFIG`, see [`ConfigError::Io`] above) resolved
    /// to a location where `lstat` cleanly reports nothing exists at all
    /// (issue #433). This state also suppresses every embedded and
    /// self-protection `deny` rule, not just user-declared ones — the
    /// merged policy is never built at all until a config file exists.
    #[error("no config file at {path:?}: create one at your own shell with `shguard init`")]
    Missing { path: PathBuf },
    /// The config file's contents (or the internally-generated
    /// self-protection rules, in the unlikely event their ids collide
    /// with a user-declared one) failed to parse, validate, or merge.
    /// Carries the underlying `crate::rules::RulesError`'s message as a
    /// `String` rather than the error type itself — `RulesError` is
    /// `pub(crate)`, so a public enum variant cannot name it directly.
    #[error("invalid user config: {0}")]
    InvalidConfig(String),
    /// `var` is set in the environment but its value is not valid UTF-8 —
    /// treated as a hard failure, not silently collapsed into "unset" the
    /// way `std::env::var(..).ok()` would (see [`Policy::load`]).
    #[error("{var} is set but is not valid UTF-8")]
    InvalidEnvVar { var: &'static str },
    /// `path`'s symlink chain (walked hop by hop for self-protection —
    /// see [`self_protection_directories`]) either exceeded
    /// [`MAX_SYMLINK_HOPS`] or contained a cycle. A hard failure, same
    /// posture as every other variant here (issue #44): silently
    /// protecting only a partial prefix of an unexpectedly deep or cyclic
    /// chain would be a silent security downgrade, not a graceful
    /// degradation.
    #[error("could not resolve the symlink chain for {path:?}: {reason}")]
    SymlinkChain { path: PathBuf, reason: String },
}

impl From<crate::rules::RulesError> for ConfigError {
    fn from(err: crate::rules::RulesError) -> Self {
        Self::InvalidConfig(err.to_string())
    }
}

/// A fully loaded, merged policy: the embedded blocklist/allowlist, plus
/// whatever a user config contributed, plus this invocation's
/// self-protection rules. Opaque to callers outside this crate — the only
/// public operations are [`Policy::load`], [`Policy::rules_with_mixed_except_targets`],
/// and passing a `&Policy` to [`crate::analyze_with_policy`].
///
/// `Clone` exists primarily so [`crate::analyze_with_policy`] can hand an
/// owned copy into the bounded-evaluation worker thread `src/watchdog.rs`
/// spawns (`'static` closures can't borrow the caller's `&Policy` across
/// that boundary) on every call — deriving it on a `pub` type does make it
/// part of this type's public API regardless of that original motivation,
/// so it's fine for a caller to rely on too. It's cheap either way: the
/// fields are `Arc`-wrapped, so clone is a refcount bump, not a deep copy
/// of the whole ruleset.
#[derive(Clone)]
pub struct Policy {
    pub(crate) rules: std::sync::Arc<Rules>,
    pub(crate) allowlist: std::sync::Arc<Allowlist>,
    /// Structured decision-output logging target (issue #108) — `None`
    /// (the default) unless the user's own config set `decision_log_path`.
    /// Never populated by the self-protection-only merge path below (that
    /// synthetic config text has no such key), so this is read off the
    /// real config-file parse alone, before it's moved into
    /// [`merge_user_config`].
    pub(crate) decision_log_path: Option<PathBuf>,
}

/// `(SHGUARD_CONFIG, XDG_CONFIG_HOME, HOME)`, each `None` if unset — see
/// [`Policy::read_env_paths`].
type EnvPaths = (Option<String>, Option<String>, Option<String>);

impl Policy {
    /// Reads `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME` (in that order),
    /// failing closed on a present-but-non-UTF-8 value for any of the
    /// three (issue #28 item 1) — shared by [`Self::load`] and
    /// [`Self::config_path`] so both see identical discovery behavior.
    fn read_env_paths() -> Result<EnvPaths, ConfigError> {
        // `var_os` (not `var(..).ok()`) so a *present* but non-UTF-8 value
        // is distinguishable from *absent* — `var(..).ok()` collapses both
        // into `None`, silently falling through to XDG/HOME discovery
        // instead of the hard failure the "set to anything ⇒ explicit"
        // contract (module docs) requires for `SHGUARD_CONFIG`.
        let shguard_config = match std::env::var_os("SHGUARD_CONFIG") {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| ConfigError::InvalidEnvVar {
                        var: "SHGUARD_CONFIG",
                    })?,
            ),
            None => None,
        };
        let xdg_config_home = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| ConfigError::InvalidEnvVar {
                        var: "XDG_CONFIG_HOME",
                    })?,
            ),
            None => None,
        };
        let home = match std::env::var_os("HOME") {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| ConfigError::InvalidEnvVar { var: "HOME" })?,
            ),
            None => None,
        };
        Ok((shguard_config, xdg_config_home, home))
    }

    /// The config path [`Self::load`] would discover, without loading or
    /// parsing anything at it — for `shguard init` (issue #112), which
    /// needs to know WHERE it would write before deciding whether to.
    /// `Ok(None)` is the same ordinary "never configured, no `$HOME`
    /// either" case [`Self::resolve_config_path`] documents, not a
    /// failure; `Err` only for a present-but-non-UTF-8 env var.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEnvVar`] if `SHGUARD_CONFIG`,
    /// `XDG_CONFIG_HOME`, or `HOME` is set to a non-UTF-8 value.
    pub fn config_path() -> Result<Option<PathBuf>, ConfigError> {
        let (shguard_config, xdg_config_home, home) = Self::read_env_paths()?;
        Ok(Self::resolve_config_path(
            shguard_config.as_deref(),
            xdg_config_home.as_deref(),
            home.as_deref(),
        ))
    }

    /// Pure resolution logic — see the module docs' "Discovery" section
    /// for the precedence order and the XDG empty-string convention.
    /// `None` when none of the three inputs yield a path (the ordinary
    /// "never configured, no `$HOME` either" case — see the module docs
    /// on why this is not itself a failure).
    fn resolve_config_path(
        shguard_config: Option<&str>,
        xdg_config_home: Option<&str>,
        home: Option<&str>,
    ) -> Option<PathBuf> {
        if let Some(path) = shguard_config {
            return Some(PathBuf::from(path));
        }
        if let Some(xdg) = xdg_config_home.filter(|s| !s.is_empty()) {
            return Some(Path::new(xdg).join("shguard").join("config.toml"));
        }
        home.filter(|s| !s.is_empty()).map(|home| {
            Path::new(home)
                .join(".config")
                .join("shguard")
                .join("config.toml")
        })
    }

    /// Reads `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME`, resolves the
    /// config path, and loads the merged policy — embedded blocklist and
    /// allowlist, layered with a user config if one was found, layered
    /// with this invocation's config-directory self-protection rules.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `SHGUARD_CONFIG` is set (including to a
    /// non-UTF-8 value) but the file it names cannot be read or does not
    /// exist, if the resolved default path exists but fails to read, if
    /// the resolved default path resolves to nothing at all
    /// ([`ConfigError::Missing`]), or if a found config file (explicit or
    /// default) fails to parse/validate/merge.
    pub fn load() -> Result<Self, ConfigError> {
        let (shguard_config, xdg_config_home, home) = Self::read_env_paths()?;
        let explicit = shguard_config.is_some();

        let path = Self::resolve_config_path(
            shguard_config.as_deref(),
            xdg_config_home.as_deref(),
            home.as_deref(),
        );

        let blocklist = Rules::embedded()?;
        let allowlist = Allowlist::embedded()?;

        let mut decision_log_path: Option<PathBuf> = None;
        // `symlink_metadata` (`lstat`), not `read_to_string`'s own error,
        // decides "nothing at this path" vs. "something's there but
        // broken": a dangling symlink makes `read_to_string` fail with the
        // same `NotFound` kind a genuinely absent path does, so only a
        // clean `NotFound` from `lstat` itself -- meaning there truly is no
        // file, symlink, or anything else at this path -- takes the first
        // arm below (issues #39, #433).
        let (rules, allowlist) = match &path {
            Some(path) => match std::fs::symlink_metadata(path) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound && !explicit => {
                    return Err(ConfigError::Missing { path: path.clone() });
                }
                Err(err) => {
                    return Err(ConfigError::Io {
                        path: path.clone(),
                        source: err,
                    });
                }
                Ok(_) => match std::fs::read_to_string(path) {
                    Ok(contents) => {
                        let user_config = UserConfig::parse(&contents)?;
                        // Read off the real config-file parse alone, before
                        // `user_config` moves into `merge_user_config`
                        // below — the self-protection-only merges further
                        // down never set this key, so there is nothing to
                        // fold across multiple merges the way
                        // `escalation_floor` needs `.max()` for.
                        decision_log_path = user_config.decision_log_path().map(PathBuf::from);
                        merge_user_config(blocklist, allowlist, user_config)?
                    }
                    Err(err) => {
                        return Err(ConfigError::Io {
                            path: path.clone(),
                            source: err,
                        });
                    }
                },
            },
            None => (blocklist, allowlist),
        };

        let mut rules = rules;
        let mut allowlist = allowlist;
        if let Some(path) = &path {
            for (suffix, config_dir) in self_protection_directories(path)? {
                let toml = self_protection_toml(&config_dir.to_string_lossy(), &suffix);
                let self_protection = UserConfig::parse(&toml)?;
                (rules, allowlist) = merge_user_config(rules, allowlist, self_protection)?;
            }
            // Reached only when a real config file was just read above (the
            // `NotFound` arms return early) -- so `shguard init` here would
            // always be overwriting an existing, real config, not the
            // first-run case. First-run itself never reaches this deny: it
            // hits one of the `NotFound` arms above instead, which already
            // fails the whole load closed (issue #433/#434's own posture),
            // giving every command -- `shguard init` included -- the
            // ordinary fail-closed `ask` rather than this rule's `deny`
            // (issue #435).
            let init_protection = UserConfig::parse(SELF_PROTECT_INIT_TOML)?;
            (rules, allowlist) = merge_user_config(rules, allowlist, init_protection)?;
        }

        // Caught here rather than left to `decision_log::append`'s own
        // fail-open-on-write-failure posture (issue #108): an
        // already-existing directory would otherwise mean "logging is
        // silently, permanently broken, with no error anywhere ever" --
        // the same "typo'd path defeats the whole feature invisibly" trap
        // this module already refuses for `SHGUARD_CONFIG` itself (see the
        // module docs' fail-closed policy). A FIFO, character device, or
        // socket is rejected for a sharper reason: `decision_log::append`
        // now writes outside `analyze_with_policy`'s own bounded-evaluation
        // watchdog (`src/lib.rs`), and the PreToolUse hook path additionally
        // runs the whole call inside this binary's own outer
        // `EVALUATION_TIMEOUT` watchdog (`src/bin/shguard.rs`) -- a write
        // that blocks on a target with no reader (or one that never
        // finishes) trips that outer watchdog instead, still silently
        // replacing an already-computed, correct decision with a
        // fail-closed `Ask`. Rejecting every already-existing non-regular
        // target at load time closes the case this crate can actually
        // detect; a target that hangs for a reason `metadata` can't see up
        // front (a stale network mount backing an ordinary regular file)
        // remains a disclosed, undetectable-at-load-time residual risk --
        // see the README's "Structured decision-output logging" section.
        // `std::fs::metadata` follows symlinks, so a symlink to a regular
        // file is unaffected and a symlink to a directory/FIFO/device is
        // caught the same as a direct one.
        //
        // A `NotFound` error is expected and accepted -- `decision_log`
        // creates the file on first append. Any OTHER metadata error (e.g.
        // `PermissionDenied` on the path or a parent component) is rejected
        // here too, not silently ignored: letting the config load anyway
        // would mean every subsequent `append` fails the same way, forever,
        // with logging permanently and invisibly broken -- exactly the
        // "typo'd/unreachable path defeats the feature invisibly" trap this
        // whole check exists to close.
        if let Some(log_path) = &decision_log_path {
            match std::fs::metadata(log_path) {
                Ok(meta) if !meta.is_file() => {
                    return Err(ConfigError::InvalidConfig(format!(
                        "decision_log_path {log_path:?} exists and is not a regular file"
                    )));
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(ConfigError::InvalidConfig(format!(
                        "decision_log_path {log_path:?} could not be checked: {err}"
                    )));
                }
            }
        }

        Ok(Self {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path,
        })
    }

    /// Test-only constructor for exercising `decision_log_path` targets
    /// [`Policy::load`] would reject at config-load time (a pre-existing
    /// FIFO, in particular) — used by `src/decision_log.rs`'s
    /// `a_blocked_log_target_does_not_corrupt_the_verdict` regression test,
    /// which needs a genuinely blocking write to prove a slow log target
    /// can't corrupt the verdict `analyze_with_policy` returns.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn for_test_with_decision_log_path(decision_log_path: PathBuf) -> Self {
        Self {
            rules: std::sync::Arc::new(Rules::embedded().expect("embedded rules should parse")),
            allowlist: std::sync::Arc::new(
                Allowlist::embedded().expect("embedded allowlist should parse"),
            ),
            decision_log_path: Some(decision_log_path),
        }
    }

    /// Ids of every deny/ask/allow rule in this policy whose
    /// `except_targets` mixes a `url_host` entry with an `exact`/`prefix`
    /// entry (issue #208) — a real, consequential trap (the string entry
    /// still matches whatever `url_host` was added to reject, so the rule
    /// gains no protection from adding it *alongside* rather than in
    /// place of the old entry), but not itself a config-load error
    /// (array-level "these two entries target the same host" isn't
    /// mechanically decidable without false-positive risk on a
    /// legitimate config).
    ///
    /// Not consulted by [`crate::analyze`]/[`crate::analyze_with_policy`]
    /// or the `shguard` hook at all: a per-invocation hook binary that
    /// re-loads its config on every single command has no way to warn on
    /// this once, at config-change time, without either spamming stderr
    /// on every matching command or introducing persistent state this
    /// crate otherwise has none of. `shguard --check-config`
    /// (`src/bin/shguard.rs`) is the intended caller — a human- or
    /// CI-triggered, one-shot lint pass.
    ///
    /// Scans the embedded blocklist/allowlist too, not just what a user
    /// config contributed — deliberately: no embedded rule uses `url_host`
    /// today (checked `rules/*.toml`), but if a future shipped rule ever
    /// did mix the two shapes, this repo's own CI running
    /// `shguard --check-config` against a `shguard init`-scaffolded config
    /// is exactly what should catch that regression before it ships. A rule
    /// id flagged this way isn't one a caller can act on themselves the
    /// way `--check-config`'s own "replace the old entry" remediation text
    /// assumes (a user can't edit or override an embedded rule — a
    /// same-id user rule fails closed at load time), but that's a defect
    /// in the embedded rule itself, not a false positive from this method.
    ///
    /// Scoped to `except_targets` only, per issue #208's own title —
    /// deliberately doesn't scan an allowlist entry's own `targets` for
    /// the same mixed shape (`targets = [{ prefix = "http://localhost" },
    /// { url_host = "localhost" }]`), even though the identical trap
    /// exists there too (`targets` are OR'd the same way, in the
    /// allow-widening rather than block-narrowing direction). Not
    /// implemented here; a legitimate follow-up if it turns out to matter
    /// in practice.
    #[must_use]
    pub fn rules_with_mixed_except_targets(&self) -> Vec<crate::verdict::RuleId> {
        let mut ids = self.rules.ids_with_mixed_except_targets();
        ids.extend(self.allowlist.ids_with_mixed_except_targets());
        ids
    }
}

/// Cap on symlink hops [`self_protection_directories`] walks when
/// resolving the config path's full chain (issue #44): matches the order
/// of magnitude of Linux's own `ELOOP` resolution limit (40 hops), so a
/// chain deep enough that the OS itself would still successfully resolve
/// it — and that `Policy::load`'s own `read_to_string` call would already
/// have followed, by the time this walk runs — never spuriously hits this
/// cap. Only a chain the OS itself would refuse, or one mutated between
/// that `read_to_string` call and this walk (a TOCTOU race an adversarial
/// guarded agent could attempt against its own config file), reaches it.
const MAX_SYMLINK_HOPS: usize = 40;

/// Directories to generate self-protection rules for, given the resolved
/// config `path` (see the module docs' "Self-protecting the config file"
/// section): the path's own (literal) parent directory, plus the parent
/// directory of *every* hop in `path`'s symlink chain, all the way to its
/// final, fully-resolved target — so a config deployed behind a chain of
/// two or more symlinks (e.g. a `stow`/`home-manager`/`chezmoi`-style
/// layered dotfiles setup) has every intermediate hop protected too, not
/// only the literal start and the fully-resolved end (issues #31, #44).
/// Walks `path` with `std::fs::read_link` in
/// a loop, one hop at a time, resolving a relative symlink target against
/// the *symlink's own* parent directory — normal filesystem
/// symlink-resolution semantics, not the process's current working
/// directory — and stops at the first hop that isn't itself a symlink
/// (the final real file, or a path that doesn't exist yet), protecting
/// that hop's parent directory too.
///
/// Deduplicated (an ordinary, non-symlinked config — or a chain where two
/// hops happen to share a parent — yields the same directory only once)
/// and excludes any parent that isn't an absolute, non-root directory:
/// a relative parent (`Some("")`/`Some(".")`/`Some("foo")`, from a
/// bare-filename or relative `SHGUARD_CONFIG`) can never usefully protect
/// anything, since `normalize.rs` deliberately never resolves the current
/// working directory, and would over-match unrelated, textually-similar
/// paths via `TargetMatcher::matches`'s plain `starts_with(prefix)`
/// (issue #24); a bare `/` parent (from e.g. `SHGUARD_CONFIG=/config.toml`)
/// would deny writes to almost any absolute path (issue #28 item 3).
///
/// Each returned entry is paired with a `suffix` distinguishing it in
/// [`self_protection_toml`]'s generated rule ids: `"literal"` for the
/// starting parent, `"resolved"` for the final hop's parent, and
/// `"hop-<n>"` for anything in between (issue #31), so every hop's
/// directory gets its own distinctly-id'd rule set that can be merged
/// into one without an id collision.
///
/// The walk only ever starts once the literal parent itself is
/// protectable, same invariant issue #31 established and for the same
/// reason: a relative `SHGUARD_CONFIG` (e.g. `SHGUARD_CONFIG=config.toml`
/// in a CI/test harness) still yields nothing at all (issue #24's
/// invariant), rather than silently protecting the current working
/// directory the chain would otherwise resolve into — the config file
/// itself stays dodgeable via a relative spelling regardless
/// (`cp evil.toml config.toml`), so that blanket rule would cost real
/// usability for near-zero security value.
///
/// # Errors
///
/// Fails closed with [`ConfigError::SymlinkChain`] — never silently
/// protecting only a partial prefix of the chain — if it exceeds
/// [`MAX_SYMLINK_HOPS`] or contains a cycle (a path already visited in
/// this same chain reappears). [`Policy::load`]'s caller already treats
/// *any* `ConfigError` as "refuse to evaluate any command until this is
/// fixed" (`crate::bin::shguard::run`), the same fail-closed posture every
/// other error in this module already has — strictly safer than
/// evaluating commands against a chain resolved only up to the cap.
fn self_protection_directories(path: &Path) -> Result<Vec<(String, PathBuf)>, ConfigError> {
    let is_protectable = |dir: &Path| dir.is_absolute() && dir != Path::new("/");

    let Some(literal_dir) = path.parent().filter(|dir| is_protectable(dir)) else {
        return Ok(Vec::new());
    };

    // Walk the symlink chain hop by hop, collecting each hop's parent
    // directory. `visited` starts with `path` itself so a symlink that
    // (directly or transitively) points back at its own starting path is
    // caught as a cycle rather than looping.
    let mut chain_dirs: Vec<PathBuf> = vec![literal_dir.to_path_buf()];
    let mut visited: HashSet<PathBuf> = HashSet::from([path.to_path_buf()]);
    let mut current = path.to_path_buf();
    let mut hops = 0usize;
    // Loop ends when `current` is not a symlink -- the final real file, or
    // nothing there yet.
    while let Ok(target) = std::fs::read_link(&current) {
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Err(ConfigError::SymlinkChain {
                path: path.to_path_buf(),
                reason: format!("exceeds the {MAX_SYMLINK_HOPS}-hop resolution cap"),
            });
        }
        let next = if target.is_absolute() {
            target
        } else {
            // A relative symlink target resolves against the symlink's
            // own directory, not the process's current working directory.
            current
                .parent()
                .map_or_else(|| target.clone(), |parent| parent.join(&target))
        };
        if !visited.insert(next.clone()) {
            return Err(ConfigError::SymlinkChain {
                path: path.to_path_buf(),
                reason: "contains a symlink cycle".to_string(),
            });
        }
        current = next;
        if let Some(dir) = current.parent().filter(|dir| is_protectable(dir)) {
            chain_dirs.push(dir.to_path_buf());
        }
    }

    let last_index = chain_dirs.len() - 1;
    let mut directories: Vec<(String, PathBuf)> = Vec::with_capacity(chain_dirs.len());
    for (index, dir) in chain_dirs.iter().enumerate() {
        if directories.iter().any(|(_, existing)| existing == dir) {
            continue;
        }
        let suffix = if index == 0 {
            "literal".to_string()
        } else if index == last_index {
            "resolved".to_string()
        } else {
            format!("hop-{index}")
        };
        directories.push((suffix, dir.clone()));
    }

    Ok(directories)
}

/// Denies `shguard init`, with or without `--force` (issue #435): unlike
/// the directory-scoped rules below, this one isn't tied to any particular
/// `config_dir` hop, so it's generated once rather than per-hop. No
/// `targets` — `shguard init` takes no path argument to match against; the
/// danger is the subcommand itself, since `--force` unconditionally
/// overwrites the config file with the comment-only starter template,
/// erasing every user `deny`/`ask` rule in one command.
const SELF_PROTECT_INIT_TOML: &str = r#"
[[deny]]
id = "shguard-self-protect-init"
reason = "shguard init/--force overwrites the config file, erasing every user-defined rule; run this manually if you mean it"
command = "shguard"
required_tokens = ["init"]
"#;

/// Generates `[[deny]]`-array TOML text protecting `config_dir` (and
/// everything under it) from common write-capable commands run through
/// Bash — see the module docs' "Self-protecting the config file" section
/// for why this is generated rather than read from a file. `suffix`
/// disambiguates rule ids across multiple calls (one per directory
/// returned by [`self_protection_directories`]) so they can be merged
/// into one rule set without an id collision.
fn self_protection_toml(config_dir: &str, suffix: &str) -> String {
    let quoted_dir = toml_quote(config_dir);
    let ancestor_rules = ancestor_rules_toml(config_dir, suffix);
    format!(
        r#"
[[deny]]
id = "shguard-self-protect-config-tee-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "tee"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-cp-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "cp"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-mv-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "mv"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-install-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "install"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-sed-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "sed"
required_flags = ["i|I|--in-place"]
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-dd-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "dd"
targets = [{{ strip = "of=", normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-rm-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "rm"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-unlink-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "unlink"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-ln-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "ln"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-rsync-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "rsync"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[redirect]]
id = "shguard-self-protect-config-redirect-{suffix}"
reason = "redirecting output to shguard's own config directory must never be scripted"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-rmdir-{suffix}"
reason = "deleting shguard's own config directory must never be scripted"
command = "rmdir"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-perl-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "perl"
required_flags = ["i"]
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-patch-{suffix}"
reason = "patching shguard's own config directory must never be scripted"
command = "patch"
targets = [{{ normalized_prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-find-exec-{suffix}"
decision = "ask"
reason = "find against shguard's own config directory combined with -exec/-execdir/-ok/-okdir must never be scripted"
command = "find"
required_flags = ["-exec|-execdir|-ok|-okdir"]
targets = [{{ normalized_prefix = {quoted_dir} }}]
{ancestor_rules}"#
    )
}

/// The ancestor-directory rule blocks for `config_dir` (issue #101's
/// ancestor-coverage half — see the sibling static rules in
/// `rules/blocklist.toml` for the full reasoning: `decision = "ask"`
/// because `targets` can't distinguish source/destination position, and
/// flag-scoped to the recursively-destructive form of each command).
/// Every proper ancestor of `config_dir` UP TO BUT EXCLUDING the
/// filesystem root — `/Users/foo/.config/shguard` yields
/// `/Users/foo/.config` and `/Users/foo` (and `/Users`, and so on up),
/// never bare `/` (that's the existing global `rm-recursive-force-
/// dangerous-target` rule's territory, and an over-broad target here
/// would make every one of these ancestor rules fire on essentially any
/// `rm -r`/`mv`/`rsync --delete` invocation touching the filesystem
/// root). Returns an empty string — omitting the ancestor rules
/// entirely for this `config_dir` — when there are no proper ancestors
/// short of root (e.g. `SHGUARD_CONFIG=/foo/config.toml`): an ancestor
/// rule with an EMPTY `targets` list would mean "no target constraint"
/// per this crate's own schema (`rules/blocklist.toml`'s own schema
/// comment), silently turning "ask near the config directory" into "ask
/// on every matching command anywhere" — the opposite of this rule's
/// intent.
fn ancestor_rules_toml(config_dir: &str, suffix: &str) -> String {
    let ancestors: Vec<String> = Path::new(config_dir)
        .ancestors()
        .skip(1)
        .filter(|p| p.parent().is_some())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    if ancestors.is_empty() {
        return String::new();
    }
    let targets = ancestors
        .iter()
        .map(|a| format!("{{ normalized = {} }}", toml_quote(a)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
[[deny]]
id = "shguard-self-protect-config-ancestor-rm-{suffix}"
decision = "ask"
reason = "deleting an ancestor directory of shguard's own config directory must never be scripted"
command = "rm"
required_flags = ["r|R|--recursive"]
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-config-ancestor-mv-{suffix}"
decision = "ask"
reason = "renaming an ancestor directory of shguard's own config directory must never be scripted"
command = "mv"
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-config-ancestor-rsync-{suffix}"
decision = "ask"
reason = "rsync --delete over an ancestor directory of shguard's own config directory must never be scripted"
command = "rsync"
required_flags = [
    "--delete|--delete-before|--delete-during|--delete-after|--delete-excluded|--delete-delay",
]
targets = [{targets}]
"#
    )
}

/// Serializes `value` as a quoted TOML string literal via the `toml`
/// crate's own serializer, not hand-rolled escaping
/// (`~/dotfiles/claude-code/rules/encoding.md`) — used to embed a
/// filesystem path (which may contain characters TOML basic strings must
/// escape) into [`self_protection_toml`]'s generated text.
fn toml_quote(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

/// Everything that can go wrong running `shguard init` (issue #112).
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// [`Policy::config_path`] resolved to `None` — no `SHGUARD_CONFIG`
    /// and no usable `$HOME`/`$XDG_CONFIG_HOME`, so there's nowhere to
    /// write.
    #[error(
        "could not determine a config path to write (SHGUARD_CONFIG is unset and no \
         $HOME/$XDG_CONFIG_HOME was found)"
    )]
    NoConfigPath,
    /// A `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME` value was set but not
    /// valid UTF-8 — same fail-closed posture as [`Policy::load`].
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Something already exists at the target path and `force` was not
    /// set.
    #[error("{path:?} already exists; pass --force to overwrite it")]
    AlreadyExists {
        /// The path that already has something at it.
        path: PathBuf,
    },
    /// A filesystem operation (stat, create-dir, write, rename) failed.
    #[error("{path:?}: {source}")]
    Io {
        /// The path the failing operation targeted.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

impl Policy {
    /// Writes `shguard init`'s scaffolded config to the path
    /// [`Self::config_path`] resolves (issue #112), refusing to overwrite
    /// an existing file/symlink/anything-else-at-that-path unless `force`
    /// is `true` — mirrors [`Self::load`]'s own `symlink_metadata`-based
    /// "nothing there" vs. "something's there" distinction, since a
    /// dangling symlink or an unreadable file is still something a
    /// non-`force` caller must not silently clobber.
    ///
    /// Writes via a temp file in the same directory, `fsync`, then
    /// `rename` into place, so a crash mid-write can never leave a
    /// half-written config behind.
    /// Creates the config directory (and any missing parents) first if it
    /// doesn't exist yet.
    ///
    /// # Errors
    ///
    /// See [`InitError`]'s variants.
    pub fn init(force: bool) -> Result<PathBuf, InitError> {
        let path = Self::config_path()?.ok_or(InitError::NoConfigPath)?;

        match std::fs::symlink_metadata(&path) {
            Ok(_) if force => {}
            Ok(_) => return Err(InitError::AlreadyExists { path }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(InitError::Io { path, source }),
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| InitError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        write_atomically(&path, &init_config_template()).map_err(|source| InitError::Io {
            path: path.clone(),
            source,
        })?;

        Ok(path)
    }
}

/// Writes `contents` to `path` via a temp file in the same directory,
/// `fsync`, then `rename`: never truncate-in-place, so a crash mid-write
/// leaves the original (or nothing, for a brand-new file) rather than a
/// half-written config. Best-effort removes the temp file if the write
/// OR the rename itself fails (nothing else ever reads a `.tmp-*` file,
/// so leaving one behind on error would just be silent litter, not a
/// correctness issue, but cleaning it up costs nothing).
fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let result = (|| {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// `shguard init` (issue #112) content: a header explaining the config
/// schema's additive-only relationship to the embedded blocklist, a few
/// commented-out example entries per array, then the embedded blocklist
/// re-emitted verbatim with every line `#`-prefixed as a read-only
/// reference appendix.
///
/// # Why not just dump the embedded blocklist as loadable config
///
/// `rules/blocklist.toml`'s own `[[command]]` id space is exactly the
/// `command_rules`/`ask_rules` id space [`crate::rules::merge_user_config`]
/// already checks a user config against — writing those same ids back out
/// as loadable `[[deny]]`/`[[ask]]` entries would make the very first
/// `Policy::load` after `init` fail with `DuplicateId` on every single
/// rule, the opposite of "immediately loadable". Merging is also
/// deliberately additive-only (no replace-by-id mechanism exists), so
/// even renamed copies could only ever ADD rules on top of the embedded
/// set, never edit or disable one of its rules — scaffolding the file as
/// literally loadable would misrepresent what editing it can actually do.
/// A read-only, commented-out reference instead shows the full rule set
/// (discoverable/auditable, this issue's own stated goal) without
/// implying an editable copy is possible.
fn init_config_template() -> String {
    let commented_blocklist: String = crate::rules::EMBEDDED_BLOCKLIST
        .lines()
        .map(|line| {
            if line.is_empty() {
                "#\n".to_string()
            } else {
                format!("# {line}\n")
            }
        })
        .collect();

    format!(
        r#"# shguard user config, scaffolded by `shguard init`.
#
# This file is layered ON TOP of shguard's embedded blocklist (below, for
# reference) -- it can only ADD rules, never edit or disable one already
# built in. There is no mechanism to override or remove an embedded rule
# by id; loosening one is only ever possible via a narrowly-targeted
# `[[allow]]` entry (and never for a shell interpreter, `eval`, or other
# escalation vector -- rejected at load time).
#
# Every entry needs a unique `id` (surfaced in the decision reason) and a
# `reason`, plus one of `command`/`command_prefix`, optionally narrowed
# with `required_flags`/`targets` -- the same matcher shape the embedded
# blocklist below uses. See README.md's Configuration section for the
# full schema.
#
# [[ask]] entries are checked only as a last-resort floor after every
# deny rule already missed -- `decision` doesn't need setting on them
# (membership in [[ask]] alone is what makes an entry Ask; unlike a
# [[redirect]] entry, which must omit or set decision = "block").
#
# Uncomment an example below to try it, or copy a rule from the reference
# appendix -- give the copy a NEW id first: reusing an embedded id fails
# this whole file closed with a duplicate-id error, by design (issue
# #112) -- editing this file can only add protection on top of the
# embedded set, never replace or weaken it. If the rule you're copying
# is a [[redirect]] entry with decision = "ask" (the embedded blocklist
# can use it; a user [[redirect]] entry cannot, see above), drop that
# line from your copy or it fails to load.

# [[deny]]
# id = "user-deny-scary-tool"
# reason = "never run this"
# command = "scary-tool"

# [[ask]]
# id = "user-ask-gh"
# reason = "confirm every gh invocation before it runs"
# command = "gh"

# [[allow]]
# id = "user-allow-rm"
# reason = "trust me"
# command = "rm"

# [[redirect]]
# id = "user-forbid-redirect-to-secrets"
# reason = "forbid redirecting into ~/secrets"
# targets = [{{ normalized_prefix = "~/secrets/" }}]

# ==== Embedded blocklist (read-only reference, not loaded from here) ====
#
# Every rule below already runs by default -- this is a comment-only
# copy of rules/blocklist.toml for discovery/audit, not a second copy
# shguard reads. Editing these lines has no effect; add new rules above
# instead.

{commented_blocklist}"#
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::verdict::Decision;
    use tempfile::tempdir;

    #[test]
    fn shguard_config_takes_precedence_over_everything() {
        let path =
            Policy::resolve_config_path(Some("/explicit/path.toml"), Some("/xdg"), Some("/home"));
        assert_eq!(path, Some(PathBuf::from("/explicit/path.toml")));
    }

    #[test]
    fn xdg_config_home_used_when_shguard_config_unset() {
        let path = Policy::resolve_config_path(None, Some("/xdg"), Some("/home"));
        assert_eq!(path, Some(PathBuf::from("/xdg/shguard/config.toml")));
    }

    #[test]
    fn empty_xdg_config_home_counts_as_unset() {
        let path = Policy::resolve_config_path(None, Some(""), Some("/home"));
        assert_eq!(
            path,
            Some(PathBuf::from("/home/.config/shguard/config.toml"))
        );
    }

    #[test]
    fn home_used_as_last_resort() {
        let path = Policy::resolve_config_path(None, None, Some("/home"));
        assert_eq!(
            path,
            Some(PathBuf::from("/home/.config/shguard/config.toml"))
        );
    }

    // E2-2 (issue #59): `HOME=""` must not resolve to a CWD-relative
    // `.config/shguard/config.toml` — the same "empty counts as unset"
    // treatment `empty_xdg_config_home_counts_as_unset` already pins for
    // `XDG_CONFIG_HOME`.
    #[test]
    fn empty_home_counts_as_unset() {
        let path = Policy::resolve_config_path(None, None, Some(""));
        assert_eq!(path, None);
    }

    #[test]
    fn no_inputs_resolve_to_none() {
        assert_eq!(Policy::resolve_config_path(None, None, None), None);
    }

    #[test]
    fn empty_shguard_config_still_counts_as_set() {
        // An empty string is Some("") — still "explicitly configured",
        // distinct from None (never configured at all). Whether an empty
        // path is a usable path is a question for `Policy::load`'s I/O
        // step, not this pure resolver.
        let path = Policy::resolve_config_path(Some(""), Some("/xdg"), Some("/home"));
        assert_eq!(path, Some(PathBuf::from("")));
    }

    #[test]
    fn self_protection_rules_match_expected_write_commands_under_config_dir() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml("/home/user/.config/shguard", "literal");
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        assert!(matches(&["tee", "/home/user/.config/shguard/config.toml"]));
        assert!(matches(&[
            "cp",
            "evil.toml",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "mv",
            "evil.toml",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "install",
            "evil.toml",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "sed",
            "-i",
            "s/x/y/",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "sed",
            "--in-place",
            "s/x/y/",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "sed",
            "--in-place=.bak",
            "s/x/y/",
            "/home/user/.config/shguard/config.toml"
        ]));
        // sed without -i prints to stdout rather than writing in place.
        assert!(!matches(&[
            "sed",
            "s/x/y/",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "dd",
            "if=/dev/zero",
            "of=/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&["rm", "/home/user/.config/shguard/config.toml"]));
        // rm -r on the bare directory (no trailing slash) — issue #22's core
        // scenario, deleting the whole config directory in one shot.
        assert!(matches(&["rm", "-r", "/home/user/.config/shguard"]));
        assert!(matches(&[
            "unlink",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "ln",
            "-sf",
            "/dev/null",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "rsync",
            "-a",
            "./payload/",
            "/home/user/.config/shguard/"
        ]));
        assert!(!matches(&["cp", "a.txt", "b.txt"]));
    }

    // issue #100: the generated [[redirect]] entry protects the RESOLVED
    // config path the same way the [[deny]] command entries above already
    // do — parity between `tee <path>` and `> <path>`.
    #[test]
    fn self_protection_redirect_rule_matches_resolved_config_path() {
        let toml = self_protection_toml("/home/user/.config/shguard", "literal");
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        assert!(
            rules
                .match_redirect_target("/home/user/.config/shguard/config.toml")
                .is_some()
        );
        assert!(
            rules
                .match_redirect_target("/home/user/other-file.txt")
                .is_none()
        );
    }

    // ==== issue #101 audit: additional primitives + ancestor coverage ====

    #[test]
    fn self_protection_rules_match_newly_audited_write_commands_under_config_dir() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml("/home/user/.config/shguard", "literal");
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        assert!(matches(&["rmdir", "/home/user/.config/shguard"]));
        assert!(matches(&[
            "perl",
            "-i",
            "-pe",
            "s/a/b/",
            "/home/user/.config/shguard/config.toml"
        ]));
        // perl without -i prints to stdout rather than writing in place.
        assert!(!matches(&[
            "perl",
            "-pe",
            "s/a/b/",
            "/home/user/.config/shguard/config.toml"
        ]));
        assert!(matches(&[
            "patch",
            "/home/user/.config/shguard/config.toml",
            "p.diff"
        ]));
        assert!(matches(&[
            "find",
            "/home/user/.config/shguard",
            "-exec",
            "rm",
            "{}",
            ";"
        ]));
        // find without -exec/-execdir/-ok/-okdir is a read, not a write.
        assert!(!matches(&[
            "find",
            "/home/user/.config/shguard",
            "-name",
            "config.toml"
        ]));
    }

    #[test]
    fn self_protect_init_rule_blocks_shguard_init_with_and_without_force() {
        use crate::normalize::NormalizedWord;

        let user_config = UserConfig::parse(SELF_PROTECT_INIT_TOML).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        let decision = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules
                .match_command(&words)
                .map(|rule| (rule.id().as_str(), rule.decision()))
        };

        assert_eq!(
            decision(&["shguard", "init", "--force"]),
            Some(("shguard-self-protect-init", Decision::Block))
        );
        assert_eq!(
            decision(&["shguard", "init"]),
            Some(("shguard-self-protect-init", Decision::Block))
        );
        assert_eq!(decision(&["shguard", "--version"]), None);
        assert_eq!(decision(&["shguard", "check", "init"]), None);
    }

    #[test]
    fn self_protection_ancestor_rules_match_resolved_ancestors() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml("/home/user/.config/shguard", "literal");
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        let match_decision = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules
                .match_command(&words)
                .map(crate::rules::CommandRule::decision)
        };

        assert_eq!(
            match_decision(&["rm", "-r", "/home/user/.config"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["rm", "-r", "/home/user"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["mv", "/home/user/.config", "/tmp/x"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["rsync", "-a", "--delete", "/tmp/x/", "/home/user/.config/"]),
            Some(Decision::Ask)
        );

        // False-positive guards: an unrelated ancestor-shaped operation
        // must stay untouched.
        assert_eq!(match_decision(&["cp", "notes.txt", "/home/user"]), None);
        assert_eq!(
            match_decision(&["rsync", "-a", "./src/", "/home/user/.config/other/"]),
            None
        );
        assert_eq!(
            match_decision(&["mv", "/home/user/.config/other-app", "/tmp/backup"]),
            None
        );
    }

    // Guards issue #101's own ordering trap: an ancestor Ask rule must
    // never shadow the global rm-recursive-force Block rule within
    // rules/blocklist.toml. `match_command` is worst-wins (issue #399),
    // so `rm -rf ~`/`rm -rf /` still Block regardless of declaration
    // order, with the ancestor rules present.
    #[test]
    fn ancestor_rules_do_not_shadow_the_global_rm_recursive_force_block_rule() {
        use crate::normalize::NormalizedWord;

        let rules = Rules::embedded().unwrap();
        let words: Vec<NormalizedWord> = ["rm", "-rf", "~"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        assert_eq!(
            rules
                .match_command(&words)
                .map(crate::rules::CommandRule::decision),
            Some(Decision::Block)
        );
    }

    #[test]
    fn self_protection_toml_omits_ancestor_rules_when_config_dir_has_no_proper_ancestor_short_of_root()
     {
        // SHGUARD_CONFIG=/foo/config.toml: config_dir = "/foo", whose only
        // ancestor is "/" itself, filtered out (issue #101's own
        // over-broad-empty-targets trap: an ancestor rule with an EMPTY
        // targets list would mean "no target constraint" per this
        // crate's schema, silently matching almost any rm -r/mv/rsync
        // --delete invocation).
        let toml = self_protection_toml("/foo", "literal");
        assert!(
            !toml.contains("ancestor"),
            "no ancestor rules should be generated when config_dir has no proper ancestor \
             short of root: {toml}"
        );
        // The generated TOML must still parse and merge cleanly -- this
        // is the actual behavioral guarantee, not just the string check
        // above.
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();
        // An unrelated mv/rsync --delete invocation must stay untouched --
        // proof there's no accidental "no target constraint" rule lurking.
        use crate::normalize::NormalizedWord;
        let words: Vec<NormalizedWord> = ["mv", "/some/other/dir", "/tmp/x"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        assert!(rules.match_command(&words).is_none());
    }

    #[test]
    fn root_only_parent_is_excluded_from_self_protection_directories() {
        // SHGUARD_CONFIG=/config.toml (issue #28 item 3): `Path::parent()`
        // returns `Some("/")`, which is absolute but would generate an
        // over-broad `prefix = "/"` self-protection rule denying writes to
        // almost any absolute path if not explicitly excluded.
        assert!(
            self_protection_directories(Path::new("/config.toml"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn relative_path_generates_no_self_protection_directories_even_if_it_canonicalizes() {
        // A relative `SHGUARD_CONFIG` (e.g. `config.toml` in a CI/test
        // harness) must still generate nothing, even when it canonicalizes
        // successfully (see `self_protection_directories`'s docs for why).
        // `Cargo.toml` is relative and canonicalizes (`cargo test`'s cwd is
        // the crate root), pinning this without any tempdir/cwd mutation.
        assert!(
            self_protection_directories(Path::new("Cargo.toml"))
                .unwrap()
                .is_empty()
        );
    }

    // A chain of two symlinks (issue #44): every hop's own directory --
    // literal, intermediate, and resolved -- must be protected.
    #[test]
    #[cfg(unix)]
    fn two_hop_symlink_chain_protects_every_hop() {
        let root = tempdir().unwrap();
        // Canonicalize first -- on macOS a fresh tempdir lives under
        // `/var/folders/...`, which `std::fs::canonicalize` resolves to
        // `/private/var/folders/...` (`/var` is itself a symlink) -- so the
        // directories asserted below match exactly what
        // `self_protection_directories` resolves to, mirroring
        // `tests/user_config.rs`'s
        // `write_to_symlinked_config_canonical_target_is_denied`.
        let root_canonical = root.path().canonicalize().unwrap();

        let literal_dir = root_canonical.join("literal");
        let mid_dir = root_canonical.join("mid");
        let real_dir = root_canonical.join("real");
        std::fs::create_dir_all(&literal_dir).unwrap();
        std::fs::create_dir_all(&mid_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let literal_path = literal_dir.join("config.toml");
        let mid_path = mid_dir.join("config.toml");
        let real_path = real_dir.join("config.toml");
        std::fs::write(&real_path, "").unwrap();
        std::os::unix::fs::symlink(&real_path, &mid_path).unwrap();
        std::os::unix::fs::symlink(&mid_path, &literal_path).unwrap();

        let directories = self_protection_directories(&literal_path).unwrap();
        assert_eq!(
            directories,
            vec![
                ("literal".to_string(), literal_dir),
                ("hop-1".to_string(), mid_dir),
                ("resolved".to_string(), real_dir),
            ]
        );
    }

    // A chain where two hops share the same parent directory must not
    // generate a duplicate rule id for that directory (issue #44's
    // dedup requirement) -- the intermediate hop here lives in the same
    // directory as the literal start, so it must collapse away, leaving
    // just `"literal"` and `"resolved"`, same shape as the single-hop
    // case.
    #[test]
    #[cfg(unix)]
    fn chain_with_shared_parent_directory_deduplicates_rule_ids() {
        let root = tempdir().unwrap();
        let root_canonical = root.path().canonicalize().unwrap();

        let shared_dir = root_canonical.join("shared");
        let real_dir = root_canonical.join("real");
        std::fs::create_dir_all(&shared_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let literal_path = shared_dir.join("literal.toml");
        let mid_path = shared_dir.join("mid.toml"); // same directory as literal_path
        let real_path = real_dir.join("config.toml");
        std::fs::write(&real_path, "").unwrap();
        std::os::unix::fs::symlink(&real_path, &mid_path).unwrap();
        std::os::unix::fs::symlink(&mid_path, &literal_path).unwrap();

        let directories = self_protection_directories(&literal_path).unwrap();
        assert_eq!(
            directories,
            vec![
                ("literal".to_string(), shared_dir),
                ("resolved".to_string(), real_dir),
            ]
        );
    }

    // A two-symlink cycle (a -> b -> a) must be detected and fail closed
    // rather than hang (issue #44) -- the test itself completing at all is
    // the pass condition for "doesn't loop forever".
    #[test]
    #[cfg(unix)]
    fn symlink_cycle_is_detected_and_fails_closed() {
        let root = tempdir().unwrap();
        let root_canonical = root.path().canonicalize().unwrap();
        let config_dir = root_canonical.join("config_dir");
        std::fs::create_dir_all(&config_dir).unwrap();

        let a_path = config_dir.join("a.toml");
        let b_path = config_dir.join("b.toml");
        std::os::unix::fs::symlink(&b_path, &a_path).unwrap();
        std::os::unix::fs::symlink(&a_path, &b_path).unwrap();

        let result = self_protection_directories(&a_path);
        assert!(matches!(result, Err(ConfigError::SymlinkChain { .. })));
    }

    // A chain longer than `MAX_SYMLINK_HOPS` must fail closed the same way
    // a cycle does, rather than hang or silently protect only a partial
    // prefix (issue #44).
    #[test]
    #[cfg(unix)]
    fn chain_exceeding_hop_cap_fails_closed() {
        let root = tempdir().unwrap();
        let root_canonical = root.path().canonicalize().unwrap();

        // One more hop than the cap allows, terminating in a real file --
        // so the only way this fails is the cap, never a missing target.
        let hop_count = MAX_SYMLINK_HOPS + 2;
        let paths: Vec<PathBuf> = (0..=hop_count)
            .map(|n| root_canonical.join(format!("hop-{n}.toml")))
            .collect();
        std::fs::write(paths.last().unwrap(), "").unwrap();
        for window in paths.windows(2) {
            std::os::unix::fs::symlink(&window[1], &window[0]).unwrap();
        }

        let result = self_protection_directories(&paths[0]);
        assert!(matches!(result, Err(ConfigError::SymlinkChain { .. })));
    }

    #[test]
    fn load_with_no_env_vars_falls_back_to_embedded_only() {
        // A best-effort smoke test: with no discovery inputs, resolve_config_path
        // returns None, so Policy::load's own env-reading path can't be driven
        // deterministically here without mutating process env (test-unsafe) —
        // covered end-to-end instead by tests/hook_io.rs via the real
        // binary with all three env vars stripped. This test only exercises the pure
        // resolver, already covered above; kept as a named anchor for anyone
        // looking for load()'s test coverage from this module.
        assert_eq!(Policy::resolve_config_path(None, None, None), None);
    }

    #[test]
    fn init_config_template_is_comment_only() {
        // The whole point of issue #112's reference-appendix design
        // (see `init_config_template`'s own docs): every line must be a
        // comment or blank, so the scaffolded file is immediately
        // loadable (no duplicate-id collision with the embedded
        // blocklist it quotes) while still surfacing the full rule set.
        for line in init_config_template().lines() {
            assert!(
                line.is_empty() || line.starts_with('#'),
                "every line must be a comment or blank, found: {line:?}"
            );
        }
    }

    #[test]
    fn init_config_template_contains_the_embedded_blocklist_reference() {
        // Spot-check a rule id known to exist in rules/blocklist.toml,
        // commented out, rather than asserting exact byte equality
        // against the embedded source (too brittle against unrelated
        // future rule edits).
        let template = init_config_template();
        assert!(template.contains("# id = \"rm-recursive-force-dangerous-target\""));
    }

    #[test]
    fn write_atomically_creates_a_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_atomically(&path, "hello").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn write_atomically_replaces_existing_content_rather_than_appending() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "old content, longer than the new one").unwrap();
        write_atomically(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn write_atomically_leaves_no_temp_file_behind_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_atomically(&path, "hello").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != "config.toml")
            .collect();
        assert!(
            leftovers.is_empty(),
            "unexpected leftover files: {leftovers:?}"
        );
    }

    #[test]
    fn write_atomically_leaves_no_temp_file_behind_when_rename_fails() {
        // A directory sitting at `path` makes `File::create` on the temp
        // file succeed (it's a sibling, not `path` itself) but the final
        // `rename` fail (can't rename a file onto an existing directory) —
        // this leaks the temp file if cleanup only runs on a WRITE
        // failure and not a rename failure (PR #387).
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::create_dir(&path).unwrap();
        assert!(write_atomically(&path, "hello").is_err());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != "config.toml")
            .collect();
        assert!(
            leftovers.is_empty(),
            "unexpected leftover files: {leftovers:?}"
        );
    }
}
