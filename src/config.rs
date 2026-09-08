//! Composition-root-facing user config loader (plan.md §6 item 8) —
//! `crate::gate`/`crate::rules` own the *rules*, this module owns
//! *finding* them: where the user's config file lives, and the
//! fail-closed/silent-skip boundary around reading it.
//!
//! # Discovery
//!
//! `SHGUARD_CONFIG` env var (any value counts as "set", even `""`) >
//! `$XDG_CONFIG_HOME/shguard/config.toml` (an empty or non-absolute
//! `XDG_CONFIG_HOME` counts as unset, per the XDG spec) >
//! `$HOME/.config/shguard/config.toml` (an empty `HOME` counts as unset
//! too, same as `XDG_CONFIG_HOME` — neither an empty string nor a relative
//! path is ever treated as "search relative to the current working
//! directory", issues #59 and #436).
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
//! `sed -i`, `dd`/`dcfldd`'s `of=<path>` shape (issue #450), `rsync`,
//! `rmdir`, `perl -i`, `patch`, and `find` combined with
//! `-exec`/`-execdir`/`-ok`/`-okdir`
//! (the last as `decision = "ask"`, not `"block"` — the danger lives in
//! what `find` invokes, only partially visible to a command-line-only
//! analyzer), plus one `[[redirect]]` rule (issue #100) for the same
//! directory via bare shell redirection (`>`/`>>`) — parity with the
//! write-capable commands, since a path unreachable via `tee` must also
//! be unreachable via `>`. [`ancestor_rules_toml`] adds a second,
//! `decision = "ask"` family covering `rm -r`/`mv`/`rsync --delete`
//! against an ANCESTOR of the config directory (`~/.config`, `~`, and
//! their resolved equivalents), plus (issue #450) a recursive-copy/
//! extract half — flagless `rsync`, `cp -r`/`-R`/`--recursive`,
//! `tar -x`/`--extract`/`--get` combined with `-C`/`--directory`, and
//! `unzip -d` — over the same ancestor list, since a recursive copy or
//! archive extraction whose payload happens to contain
//! `shguard/config.toml` replaces the config while only ever naming the
//! ancestor directory — deleting or renaming an ancestor takes
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
//! fully-resolved end — except the one hop whose target exists but isn't
//! an ordinary regular file (e.g. `SHGUARD_CONFIG=/dev/null`), which is
//! never a real, user-owned config location (issue #461) — plus each
//! remaining hop's `std::fs::canonicalize`d form
//! (issue #449), catching a symlinked directory *component* earlier in
//! the path (stow's default "folded" layout) that the file-symlink walk
//! alone never sees — see [`self_protection_directories`]'s own docs for
//! the walk's mechanics and its fail-closed behavior on a too-long or
//! cyclic chain. `rules/blocklist.toml`
//! separately carries a *static* rule for the literal `~/.config/shguard/`
//! token — `normalize.rs` never resolves `~`/`$HOME` to an actual
//! filesystem path (no environment lookups anywhere in parse/normalise,
//! by design), so an agent that already knows its own `$HOME` (trivially
//! available via `pwd`/`echo $HOME`) could otherwise dodge a `~`-only
//! rule by writing an absolute path instead — this module's dynamically
//! resolved rule closes that gap. That static `~`-literal rule's own
//! `normalized`/`normalized_prefix` targets carry the same
//! `case_insensitive = true` (issue #449) this module's generated ones
//! do — a re-cased `~/.CONFIG/shguard` spelling is exactly as real a
//! bypass on macOS APFS for the literal-`~` half as for the
//! dynamically-resolved half.
//!
//! Both mechanisms are disclosed as partial, not complete, in the README:
//! a `SHGUARD_CONFIG`-via-shell-profile vector is not caught by either.
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
/// [`Policy::ask_outcome`], and passing a `&Policy` to
/// [`crate::analyze_with_policy`].
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
    /// The top-level `ask_outcome` user-config key (issues #467/#469) —
    /// [`crate::rules::AskOutcome::default`] (today's unmodified behavior)
    /// unless the user's own config set it, either to #467's bare-string
    /// form or #469's per-`permission_mode` table. Read the same way
    /// `decision_log_path` is: off the real config-file parse alone, never
    /// the self-protection-only merges below. Consulted by
    /// [`crate::analyze_with_policy`] (`src/lib.rs`) to floor every
    /// terminal `Ask` verdict to `Block` for the resolved mode —
    /// `crate::gate` never reads this field itself (issue #467's design: a
    /// terminal remap, not a per-command floor threaded through gate's own
    /// recursion).
    pub(crate) ask_outcome: crate::rules::AskOutcome,
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
    /// for the precedence order and the empty-or-non-absolute convention.
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
        if let Some(xdg) = xdg_config_home.filter(|s| !s.is_empty() && Path::new(s).is_absolute()) {
            return Some(Path::new(xdg).join("shguard").join("config.toml"));
        }
        home.filter(|s| !s.is_empty() && Path::new(s).is_absolute())
            .map(|home| {
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
    /// ([`ConfigError::Missing`]), if a found config file (explicit or
    /// default) fails to parse/validate/merge, if the config path's or a
    /// configured `decision_log_path`'s symlink chain is too long or cyclic
    /// ([`ConfigError::SymlinkChain`], see [`self_protection_directories`]),
    /// or if a user config's `decision_log_path` fails any of its own
    /// validation checks
    /// ([`ConfigError::InvalidConfig`]: not an absolute path, a
    /// trailing-slash/relative-component path, a symlink, an existing
    /// non-regular file, a missing parent directory, or an unreadable
    /// `lstat`).
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
        let mut ask_outcome = crate::rules::AskOutcome::default();
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
                        ask_outcome = user_config.ask_outcome();
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
            let case_insensitive = config_dir_is_case_insensitive();
            for (suffix, config_dir) in self_protection_directories(path)? {
                let toml = self_protection_toml(
                    require_utf8_config_dir(&config_dir)?,
                    &suffix,
                    case_insensitive,
                    "config",
                    "config directory",
                    false,
                );
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
        //
        // `std::fs::symlink_metadata` (`lstat`), not `metadata`, so a
        // symlink at `decision_log_path` is inspected as a symlink rather
        // than followed (issue #458 item 1): a symlink-following check here
        // paired with `decision_log::open_log_file`'s symlink-following
        // open would let a symlink planted at this path redirect every
        // appended line into any user-writable file. `open_log_file` pairs
        // this load-time rejection with `O_NOFOLLOW` at open time, closing
        // the remaining load-to-append TOCTOU window (a symlink swapped in
        // after this check still hits `O_NOFOLLOW` and fails the append,
        // rather than being silently followed).
        //
        // A `NotFound` error is expected and accepted -- `decision_log`
        // creates the file on first append -- but only when the log path's
        // PARENT directory already exists (issue #458 item 2): a missing
        // parent means every future append fails forever, silently dropped
        // by `decision_log::append`'s own fail-open posture, which is
        // exactly the "typo'd path defeats the feature invisibly" trap this
        // whole check exists to close. Any OTHER metadata error (e.g.
        // `PermissionDenied` on the path or a parent component) is rejected
        // here too, not silently ignored, for the same reason.
        //
        // Relative paths are rejected outright (issue #458 item 3, mirroring
        // issues #436/#437's rejection of a relative `XDG_CONFIG_HOME`/
        // `HOME`): a relative `decision_log_path` would resolve against the
        // hook's per-invocation working directory -- the guarded repo, not
        // a stable location -- so it's caught before any of the checks
        // above rather than let load "succeed" with an ambiguous target.
        if let Some(log_path) = &decision_log_path {
            if !log_path.is_absolute() {
                return Err(ConfigError::InvalidConfig(format!(
                    "decision_log_path {log_path:?} must be an absolute path"
                )));
            }
            // A trailing `/` (`Path::parent()`/`components()` silently drop
            // it, unlike the raw string this checks instead) or a `.`/`..`
            // component names a directory-shaped path, not a file: the
            // parent-directory check below would see it as "parent exists,
            // file itself absent" and accept it, and every future append
            // would then fail forever with `EISDIR`/`ENOTDIR` -- exactly
            // the load-time-invisible failure fix #458 item 2 exists to
            // close, just with a different underlying OS error.
            let has_directory_shaped_component = log_path
                .to_string_lossy()
                .ends_with(std::path::MAIN_SEPARATOR)
                || log_path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                });
            if has_directory_shaped_component {
                return Err(ConfigError::InvalidConfig(format!(
                    "decision_log_path {log_path:?} must name a file directly, not a \
                     trailing-slash or relative-component path"
                )));
            }
            match std::fs::symlink_metadata(log_path) {
                Ok(meta) if meta.is_symlink() => {
                    return Err(ConfigError::InvalidConfig(format!(
                        "decision_log_path {log_path:?} is a symlink, which is not allowed"
                    )));
                }
                Ok(meta) if !meta.is_file() => {
                    return Err(ConfigError::InvalidConfig(format!(
                        "decision_log_path {log_path:?} exists and is not a regular file"
                    )));
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    let parent_exists = log_path.parent().is_some_and(|parent| parent.is_dir());
                    if !parent_exists {
                        return Err(ConfigError::InvalidConfig(format!(
                            "decision_log_path {log_path:?}'s parent directory does not exist"
                        )));
                    }
                }
                Err(err) => {
                    return Err(ConfigError::InvalidConfig(format!(
                        "decision_log_path {log_path:?} could not be checked: {err}"
                    )));
                }
            }

            // Issue #458 item 4: without this, the log path itself is the
            // audit trail's own single point of failure -- `rm`/`ln -sf`
            // against it were both `Allow`, since only `~/.bashrc`-class
            // targets are floored elsewhere. Reuses the exact mechanism
            // the config file protects itself with
            // ([`self_protection_directories`]/[`self_protection_toml`])
            // rather than inventing a second one, distinguished from the
            // config rule set by the `"decision-log"`/`"decision log
            // file"` `id_kind`/`noun` pair so ids never collide even when
            // the log lives inside the config directory itself.
            //
            // `exact_target = true`, unlike the config call site above:
            // `self_protection_directories` returns DIRECTORIES (it walks
            // `log_path`'s own symlink/canonicalization chain the same
            // way it does for the config file), but the log is one file
            // inside a directory that may hold unrelated files the user
            // never asked shguard to protect -- reconstructing the exact
            // log file path at each returned directory (same file name,
            // since `decision_log_path` is already rejected above if it
            // is itself a symlink) keeps the direct write-rules scoped to
            // that one file while `ancestor_rules_toml` still floors
            // recursive deletion/rename of the directory itself.
            let case_insensitive = config_dir_is_case_insensitive();
            let log_file_name = log_path.file_name().unwrap_or_default();
            for (suffix, log_dir) in self_protection_directories(log_path)? {
                let log_file_at_hop = log_dir.join(log_file_name);
                let toml = self_protection_toml(
                    &log_file_at_hop.to_string_lossy(),
                    &suffix,
                    case_insensitive,
                    "decision-log",
                    "decision log file",
                    true,
                );
                let self_protection = UserConfig::parse(&toml)?;
                (rules, allowlist) = merge_user_config(rules, allowlist, self_protection)?;
            }
        }

        Ok(Self {
            rules: std::sync::Arc::new(rules),
            allowlist: std::sync::Arc::new(allowlist),
            decision_log_path,
            ask_outcome,
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
            ask_outcome: crate::rules::AskOutcome::default(),
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

    /// The effective `ask_outcome` config key resolved for `context`
    /// (issues #467/#469) — see this struct's own field docs and
    /// [`crate::rules::AskOutcome::resolve`]. Public so `src/bin/shguard.rs`'s
    /// composition-root fail-closed paths (oversized/unreadable stdin, hit
    /// before any command reaches [`crate::analyze_with_policy`]) can
    /// honor the same key `adapter::fail_closed_with` applies elsewhere;
    /// those paths pass `&HookContext::none()` since none of them have a
    /// readable `permission_mode` to resolve against, which is exactly the
    /// "unreadable" fallback #469 documents (a `PerMode` table's
    /// `None`/`Unknown` handling already resolves this to `Ask` unless the
    /// bare-string `Global` form is configured).
    #[must_use]
    pub fn ask_outcome(&self, context: &crate::HookContext) -> crate::verdict::Decision {
        self.ask_outcome
            .resolve(context.permission_mode(), context.agent_id())
    }

    /// The `decision_log_path` this policy resolved, if any (issue #459).
    /// Public for the same reason [`Self::ask_outcome`] is: `src/bin/shguard.rs`'s
    /// composition root needs it outside [`crate::analyze_with_policy`]'s
    /// own call — specifically, to hand a decision-log target to its
    /// outer watchdog's trip arms, which run on a path that never reaches
    /// `analyze_with_policy` at all.
    #[must_use]
    pub fn decision_log_path(&self) -> Option<&std::path::Path> {
        self.decision_log_path.as_deref()
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
/// The final hop's directory is additionally dropped (not just excluded
/// from the dedup set above) when the fully-resolved target exists but
/// isn't an ordinary regular file (issue #461): `SHGUARD_CONFIG=/dev/null`
/// — a well-established "empty config, embedded rules only" idiom — would
/// otherwise self-protect `/dev` itself, denying every unrelated
/// `/dev/...` target (`2>/dev/null` included). A target that doesn't
/// exist yet, or a `metadata` error, is treated as protectable as
/// before — this only ever narrows the *last* hop, never an earlier one a
/// symlink chain also passes through.
///
/// Each returned entry is paired with a `suffix` distinguishing it in
/// [`self_protection_toml`]'s generated rule ids: `"literal"` for the
/// starting parent, `"resolved"` for the final hop's parent, and
/// `"hop-<n>"` for anything in between (issue #31), so every hop's
/// directory gets its own distinctly-id'd rule set that can be merged
/// into one without an id collision.
///
/// After the hop walk, every directory found so far is additionally
/// `std::fs::canonicalize`d and, if that differs from every directory
/// already collected, added under a `"canonical"`/`"canonical-<n>"`
/// suffix (issue #449): the walk above only ever follows a symlink
/// chain rooted at the config FILE itself, so a symlinked directory
/// *component* earlier in the path — e.g. stow's default "folded"
/// layout, `~/.config -> ~/dotfiles/config`, where the config file
/// itself is never a symlink — would otherwise leave the real,
/// fully-resolved directory unprotected. `canonicalize` resolves every
/// symlinked component of a path, not just a trailing one, so
/// re-resolving each already-found directory catches that gap for a
/// command spelled with the SAME degree of resolution the config path
/// itself was read with (fully literal, or fully resolved). A command
/// argument that mixes resolution — some symlinked components in its
/// spelling already resolved, others not (e.g., on macOS, a tempdir
/// under `/var/...` with only its `.config`-style component resolved,
/// leaving `/var` unresolved rather than its real `/private/var`) —
/// matches neither the literal nor the canonical rule; this is the same
/// lexical-vs-resolved boundary every self-protection rule already has,
/// not a new gap this fix introduces. A symlinked `$HOME` itself (e.g.
/// `/Users/alice -> /Volumes/Data/alice`) is a live instance of the same
/// residual: a command spelled through the literal `/Users/alice/...`
/// works (protected by `"literal"`), but a fully-resolved-except-that-hop
/// spelling doesn't. Best-effort: a directory that doesn't exist (yet)
/// simply fails `canonicalize` and contributes nothing, rather than
/// failing the whole config load — every directory found by the hop walk
/// above stays protected regardless.
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

    // Drop the final hop's directory alone when its target is non-regular
    // (issue #461, see this function's own doc comment). `chain_dirs.last()`
    // is exactly this hop's directory when one was pushed for it, since the
    // loop above only ever appends in hop order.
    if let Some(final_dir) = current.parent().filter(|dir| is_protectable(dir)) {
        let final_target_is_non_regular =
            std::fs::metadata(&current).is_ok_and(|meta| !meta.is_file());
        if final_target_is_non_regular && chain_dirs.last() == Some(&final_dir.to_path_buf()) {
            chain_dirs.pop();
        }
    }
    if chain_dirs.is_empty() {
        return Ok(Vec::new());
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

    // Directory-symlink components (issue #449): every hop above comes
    // from `read_link`ing the config FILE (or a previous hop's target)
    // itself, so a symlinked directory COMPONENT earlier in the path --
    // e.g. stow's default "folded" layout, `~/.config ->
    // ~/dotfiles/config` -- never surfaces as a hop of its own; the file
    // at the end of that path is never itself a symlink, so the walk
    // above never even starts. `std::fs::canonicalize` resolves every
    // symlinked component of a path, not just a trailing one, so
    // re-resolving each directory already found above catches exactly
    // that gap. Best-effort: a directory that doesn't exist (yet) fails
    // `canonicalize` and is silently skipped rather than failing the
    // whole config load -- every directory found above stays protected
    // either way, this only ever ADDS coverage.
    let mut canonical_additions: Vec<(String, PathBuf)> = Vec::new();
    for (_, dir) in &directories {
        let Ok(canonical) = std::fs::canonicalize(dir) else {
            continue;
        };
        if !is_protectable(&canonical)
            || directories
                .iter()
                .any(|(_, existing)| *existing == canonical)
            || canonical_additions
                .iter()
                .any(|(_, existing)| *existing == canonical)
        {
            continue;
        }
        let suffix = if canonical_additions.is_empty() {
            "canonical".to_string()
        } else {
            format!("canonical-{}", canonical_additions.len())
        };
        canonical_additions.push((suffix, canonical));
    }
    directories.extend(canonical_additions);

    Ok(directories)
}

/// `config_dir` as a UTF-8 `&str` for [`self_protection_toml`], or a
/// fail-closed [`ConfigError::InvalidConfig`] instead of the
/// `to_string_lossy` substitution this replaces (issue #465):
/// `to_string_lossy` would silently swap in U+FFFD for a non-UTF-8
/// component -- reachable only via a non-UTF-8 symlink target here (the
/// equivalent `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME` env vars are
/// already rejected by [`Policy::read_env_paths`]) -- baking a
/// self-protection rule whose target string can never match the real
/// path it was meant to protect.
fn require_utf8_config_dir(config_dir: &Path) -> Result<&str, ConfigError> {
    config_dir.to_str().ok_or_else(|| {
        ConfigError::InvalidConfig(format!(
            "config directory {config_dir:?} is not valid UTF-8"
        ))
    })
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

/// Generates `[[deny]]`-array TOML text protecting `target_path` from
/// common write-capable commands run through Bash — see the module docs'
/// "Self-protecting the config file" section for why this is generated
/// rather than read from a file. `suffix` disambiguates rule ids across
/// multiple calls (one per directory returned by
/// [`self_protection_directories`]) so they can be merged into one rule
/// set without an id collision. `case_insensitive` sets every generated
/// target's own `case_insensitive` flag (see
/// [`config_dir_is_case_insensitive`]) — see [`TargetMatcher`]
/// (`crate::rules`) for what that flag does at match time. `id_kind`/`noun`
/// parameterize what is being protected (`"config"`/`"config directory"`
/// for the config self-protection call site, `"decision-log"`/`"decision
/// log file"` for [`Policy::load`]'s decision-log self-protection — issue
/// #458 item 4) so this one mechanism generates both rule families rather
/// than a near-duplicate function.
///
/// `exact_target` chooses the target match shape: `false` (the config
/// call site) matches `target_path` as a slash-terminated `normalized_prefix`
/// plus a bare `normalized` on `target_path` itself (issue #460) — every
/// path under that directory, and the directory itself, is protected,
/// without also matching a sibling that merely shares the string prefix
/// (`~/.config/shguard-backup`), appropriate for a directory this crate
/// itself fully owns (`~/.config/shguard`). `true` (the decision-log
/// call site) matches it as an exact `normalized` path instead — a
/// prefix match here would either over-protect an arbitrary,
/// user-chosen log directory shared with unrelated files (blocking
/// ordinary writes anywhere in it) or, worse, under-protect via a
/// same-prefix collision (`normalized_prefix` is a plain string
/// `starts_with`, so it would also match `decisions.jsonl.bak`,
/// `decisions.jsonl2`, and the like — see [`self_protection_directories`]'s
/// own doc comment on this exact hazard). `ancestor_rules_toml` still
/// protects `target_path`'s ancestors (its parent directory and up) with
/// `ask`-level recursive-delete/rename rules regardless of `exact_target`,
/// since `Path::ancestors()` treats a file path and a directory path the
/// same way.
fn self_protection_toml(
    target_path: &str,
    suffix: &str,
    case_insensitive: bool,
    id_kind: &str,
    noun: &str,
    exact_target: bool,
) -> String {
    let quoted_dir = toml_quote(target_path);
    let ci_attr = case_insensitive_toml_attr(case_insensitive);
    // `!exact_target` pairs a slash-terminated `normalized_prefix` with a
    // bare `normalized` on `target_path` itself (issue #460): a bare
    // `normalized_prefix = "<dir>"` is a plain `starts_with`, so it also
    // matches a sibling that merely shares the string prefix
    // (`~/.config/shguard-backup`); the added `normalized` target covers
    // the directory named exactly, since the slash-terminated prefix is
    // longer than that token and can never match it. Mirrors the
    // already-shipped static `normalized_prefix = "~/.config/shguard/"`
    // pairing in `rules/blocklist.toml`.
    let quoted_dir_slash = toml_quote(&format!("{target_path}/"));
    let plain_targets = if exact_target {
        format!("{{ normalized = {quoted_dir}{ci_attr} }}")
    } else {
        format!(
            "{{ normalized_prefix = {quoted_dir_slash}{ci_attr} }}, \
             {{ normalized = {quoted_dir}{ci_attr} }}"
        )
    };
    let dd_targets = if exact_target {
        format!("{{ strip = \"of=\", normalized = {quoted_dir}{ci_attr} }}")
    } else {
        format!(
            "{{ strip = \"of=\", normalized_prefix = {quoted_dir_slash}{ci_attr} }}, \
             {{ strip = \"of=\", normalized = {quoted_dir}{ci_attr} }}"
        )
    };
    let ancestor_rules = ancestor_rules_toml(target_path, suffix, case_insensitive, id_kind, noun);
    format!(
        r#"
[[deny]]
id = "shguard-self-protect-{id_kind}-tee-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "tee"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-cp-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "cp"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-mv-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "mv"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-install-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "install"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-sed-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "sed"
required_flags = ["i|I|--in-place"]
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-dd-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "dd"
targets = [{dd_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-dcfldd-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "dcfldd"
targets = [{dd_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-rm-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "rm"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-unlink-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "unlink"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ln-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "ln"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-rsync-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "rsync"
targets = [{plain_targets}]

[[redirect]]
id = "shguard-self-protect-{id_kind}-redirect-{suffix}"
reason = "redirecting output to shguard's own {noun} must never be scripted"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-rmdir-{suffix}"
reason = "deleting shguard's own {noun} must never be scripted"
command = "rmdir"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-perl-{suffix}"
reason = "writing to shguard's own {noun} must never be scripted"
command = "perl"
required_flags = ["i"]
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-patch-{suffix}"
reason = "patching shguard's own {noun} must never be scripted"
command = "patch"
targets = [{plain_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-find-exec-{suffix}"
decision = "ask"
reason = "find against shguard's own {noun} combined with -exec/-execdir/-ok/-okdir must never be scripted"
command = "find"
required_flags = ["-exec|-execdir|-ok|-okdir"]
targets = [{plain_targets}]
{ancestor_rules}"#
    )
}

/// Whether generated self-protection targets should compare
/// case-insensitively (issue #449): macOS ships with case-insensitive
/// (but case-preserving) APFS/HFS+ volumes by default, so a re-cased
/// spelling of the config path (`/Users/Alice/...` vs
/// `/users/alice/...`) resolves to the exact same on-disk file — a
/// byte-exact `starts_with`/`==` comparison (`TargetMatcher::matches`,
/// `crate::rules`) would wrongly Allow a write reaching the real config
/// through such a respelling. Gated on `target_os` rather than an actual
/// filesystem probe (e.g. writing a differently-cased tempfile and
/// checking whether it collides): simpler, and correct for the default
/// volume format on every supported macOS install. A case-SENSITIVE APFS
/// volume (an explicit, non-default macOS install option) folds
/// unnecessarily conservatively rather than under-protecting — the same
/// safe-direction trade-off `crate::rules::is_home_container_dir`'s own
/// case-fold already accepts. NOT reachable on Linux (ext4 is
/// case-sensitive): a case-insensitive mount there (exFAT/NTFS) is a
/// known, disclosed residual this check does not cover.
fn config_dir_is_case_insensitive() -> bool {
    cfg!(target_os = "macos")
}

/// The `, case_insensitive = true` inline-table suffix
/// [`self_protection_toml`]/[`ancestor_rules_toml`] append to each
/// generated `normalized_prefix`/`normalized` target when
/// `case_insensitive` is set — empty otherwise, so the generated TOML is
/// byte-identical to before issue #449 on a case-sensitive filesystem.
fn case_insensitive_toml_attr(case_insensitive: bool) -> &'static str {
    if case_insensitive {
        ", case_insensitive = true"
    } else {
        ""
    }
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
///
/// Issue #450 adds a second half alongside the original delete/rename
/// family above: a recursive copy or archive extraction whose payload
/// happens to contain `shguard/config.toml` overwrites the config while
/// only ever naming the ancestor directory as its destination — flagless
/// `rsync` (recursion has too many spellings — `-a`, `-r`, `--recursive`,
/// `--archive`, or bundled into a short-flag cluster like `-rv` — to
/// enumerate via `required_flags` without leaving a bypass, the same
/// reasoning the existing direct `shguard-self-protect-config-rsync-*`
/// rule above already applies; the existing ANCESTOR rule above is
/// scoped to `--delete*` only, which is a distinct, narrower danger),
/// `cp` with `-r`/`-R`/`-a`/`--recursive`/`--archive` (GNU `-a` implies
/// `-dR --preserve=all`, BSD `-a` implies `-pPR`; both recurse the same
/// as `-r`), `tar -x`/`--extract`/`--get` combined with `-C`/`--directory`,
/// and `unzip -d`. `tar`'s targets mirror the static
/// `tar-extract-over-root-or-home` rule's shape (`rules/blocklist.toml`):
/// both a bare `normalized` target (the `-C <dir>`/`--directory <dir>`
/// separate-argument spelling) and a `strip`-based one for each of
/// `-C`/`--directory=`'s concatenated forms, since `targets` matches any
/// token, not a positional argument tied to the flag. `unzip -d <dir>`'s
/// destination may be concatenated the same way (`unzip p.zip
/// -d<dir>`, per `unzip`'s own manual page), so `cp`'s `-t`/
/// `--target-directory=` (mirroring `cp-write-device`'s own target
/// shape) and `unzip`'s `-d` all get the same bare-plus-`strip`
/// treatment as `tar`'s `-C`/`--directory=`. The new flagless
/// `shguard-self-protect-config-ancestor-rsync-copy-{suffix}` rule's
/// `targets` are a strict subset of the pre-existing
/// `shguard-self-protect-config-ancestor-rsync-{suffix}` (`--delete*`)
/// rule's own — both `ask`, so on a `--delete`-flagged command the
/// worst-wins tie is broken by *declaration order*
/// (`Rules::match_command`'s own doc), and the delete-specific rule is
/// declared first here, keeping its narrower, more specific reason as
/// the one actually reported.
fn ancestor_rules_toml(
    config_dir: &str,
    suffix: &str,
    case_insensitive: bool,
    id_kind: &str,
    noun: &str,
) -> String {
    let ancestors: Vec<String> = Path::new(config_dir)
        .ancestors()
        .skip(1)
        .filter(|p| p.parent().is_some())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    if ancestors.is_empty() {
        return String::new();
    }
    let ci_attr = case_insensitive_toml_attr(case_insensitive);
    let targets = ancestors
        .iter()
        .map(|a| format!("{{ normalized = {}{ci_attr} }}", toml_quote(a)))
        .collect::<Vec<_>>()
        .join(", ");
    let extract_targets = ancestors
        .iter()
        .map(|a| {
            let quoted = toml_quote(a);
            format!(
                "{{ normalized = {quoted}{ci_attr} }}, \
                 {{ strip = \"-C\", normalized = {quoted}{ci_attr} }}, \
                 {{ strip = \"--directory=\", normalized = {quoted}{ci_attr} }}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let unzip_targets = ancestors
        .iter()
        .map(|a| {
            let quoted = toml_quote(a);
            format!(
                "{{ normalized = {quoted}{ci_attr} }}, \
                 {{ strip = \"-d\", normalized = {quoted}{ci_attr} }}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cp_targets = ancestors
        .iter()
        .map(|a| {
            let quoted = toml_quote(a);
            format!(
                "{{ normalized = {quoted}{ci_attr} }}, \
                 {{ strip = \"--target-directory=\", normalized = {quoted}{ci_attr} }}, \
                 {{ strip = \"-t\", normalized = {quoted}{ci_attr} }}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-rm-{suffix}"
decision = "ask"
reason = "deleting an ancestor directory of shguard's own {noun} must never be scripted"
command = "rm"
required_flags = ["r|R|--recursive"]
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-mv-{suffix}"
decision = "ask"
reason = "renaming an ancestor directory of shguard's own {noun} must never be scripted"
command = "mv"
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-rsync-{suffix}"
decision = "ask"
reason = "rsync --delete over an ancestor directory of shguard's own {noun} must never be scripted"
command = "rsync"
required_flags = [
    "--delete|--delete-before|--delete-during|--delete-after|--delete-excluded|--delete-delay",
]
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-rsync-copy-{suffix}"
decision = "ask"
reason = "recursively copying into an ancestor directory of shguard's own {noun} must never be scripted"
command = "rsync"
targets = [{targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-cp-{suffix}"
decision = "ask"
reason = "recursively copying into an ancestor directory of shguard's own {noun} must never be scripted"
command = "cp"
required_flags = ["r|R|a|--recursive|--archive"]
targets = [{cp_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-tar-extract-{suffix}"
decision = "ask"
reason = "extracting an archive into an ancestor directory of shguard's own {noun} must never be scripted"
command = "tar"
required_flags = ["x|--extract|--get", "C|--directory"]
targets = [{extract_targets}]

[[deny]]
id = "shguard-self-protect-{id_kind}-ancestor-unzip-{suffix}"
decision = "ask"
reason = "extracting an archive into an ancestor directory of shguard's own {noun} must never be scripted"
command = "unzip"
required_flags = ["d"]
targets = [{unzip_targets}]
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

    // issue #465: a predictable `.{file}.tmp-{pid}` name let anything with
    // write access to the config directory pre-plant a symlink there, and
    // `File::create` (a plain `open` without `O_EXCL`) would silently
    // follow it, writing config contents through the symlink instead of
    // creating our own file. An unpredictable suffix plus `create_new`
    // (`O_EXCL`) closes both halves of that race: the name can't be
    // guessed in advance, and even a guessed/colliding name fails instead
    // of following whatever is already there. Retry a handful of times on
    // a genuine name collision (astronomically unlikely, not adversarial)
    // before giving up.
    let mut last_err = None;
    for _ in 0..8 {
        let tmp_path = parent.join(format!(
            ".{file_name}.tmp-{}-{:016x}",
            std::process::id(),
            random_u64()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(contents.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    std::fs::rename(&tmp_path, path)
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&tmp_path);
                }
                return result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::other("failed to create atomic-write temp file")))
}

/// An unpredictable `u64` for [`write_atomically`]'s temp-file suffix,
/// without pulling in a `rand` dependency: [`std::collections::hash_map::RandomState`]
/// seeds its SipHash keys from the OS's own randomness source on
/// construction, so hashing nothing still yields a value an outside
/// observer cannot predict.
fn random_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
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

    // Issue #436: a relative `XDG_CONFIG_HOME` must not resolve
    // cwd-relative — the same "unset" treatment
    // `empty_xdg_config_home_counts_as_unset` already pins for an empty
    // value, extended to any non-absolute one.
    #[test]
    fn relative_xdg_config_home_counts_as_unset() {
        let path = Policy::resolve_config_path(None, Some("relative"), Some("/home"));
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

    // Issue #436: a relative `HOME` must not resolve cwd-relative either —
    // the same extension `relative_xdg_config_home_counts_as_unset` already
    // pins for `XDG_CONFIG_HOME`.
    #[test]
    fn relative_home_counts_as_unset() {
        let path = Policy::resolve_config_path(None, None, Some("relative"));
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

        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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
        // issue #450
        assert!(matches(&[
            "dcfldd",
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

    // Issue #460: sibling directories sharing the config directory's string
    // prefix must never be denied.
    #[test]
    fn self_protection_rules_do_not_deny_sibling_directories_sharing_a_string_prefix() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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
        assert!(!matches(&["tee", "/home/user/.config/shguardX/notes.txt"]));
        assert!(!matches(&["tee", "/home/user/.config/shguard-backup/x"]));
        // `dd`'s `strip = "of="` target is built by a separate branch
        // (`dd_targets`) from the plain one above -- covered independently
        // so it can't silently regress on its own.
        assert!(!matches(&[
            "dd",
            "if=/dev/zero",
            "of=/home/user/.config/shguard-backup/x"
        ]));
        // The `[[redirect]]` rule is also built from `plain_targets`,
        // independently of `match_command` above.
        assert!(
            rules
                .match_redirect_target("/home/user/.config/shguard-backup/x")
                .is_none()
        );
    }

    // `case_insensitive` is a parse-time TOML flag, not gated on the host
    // OS running this test (only `config_dir_is_case_insensitive`'s
    // caller decides whether to set it) — so the `case_insensitive: true`
    // generation path itself (including `dd`'s combined `strip = "of=",
    // case_insensitive = true` inline table and the ancestor `normalized`
    // targets) is exercisable on any platform, including Linux CI, even
    // though no real invocation of this crate ever passes `true` there.
    // Issue #449 review follow-up: a generation typo here would otherwise
    // only surface as a `Policy::load` failure on a macOS-only path,
    // undetected by CI.
    // Issue #458 item 4: `self_protection_toml`/`ancestor_rules_toml` are
    // reused, not duplicated, to protect `decision_log_path` the same way
    // the config directory protects itself -- `id_kind`/`noun` are one
    // difference (generated ids/reasons must reflect whichever pair was
    // passed rather than always saying "config"), `exact_target` is the
    // other: the decision-log call site passes `true` and an exact FILE
    // path (not a directory) so the generated `[[deny]]` targets are
    // `normalized`, never `normalized_prefix` -- a directory-prefix match
    // here would either over-protect every unrelated file the user's
    // chosen log directory happens to hold, or under-protect via a
    // same-prefix collision with a differently-named file.
    #[test]
    fn self_protection_toml_id_kind_and_noun_parameterize_the_generated_rules() {
        let toml = self_protection_toml(
            "/home/user/.local/state/shguard/decisions.jsonl",
            "literal",
            false,
            "decision-log",
            "decision log file",
            true,
        );
        assert!(toml.contains(r#"id = "shguard-self-protect-decision-log-rm-literal""#));
        assert!(toml.contains("writing to shguard's own decision log file must never be scripted"));
        assert!(!toml.contains("shguard-self-protect-config-"));
        assert!(!toml.contains("own config directory"));
        assert!(
            toml.contains(
                r#"targets = [{ normalized = "/home/user/.local/state/shguard/decisions.jsonl" }]"#
            ),
            "exact_target = true must generate an exact `normalized` match, never \
             `normalized_prefix` (which would over- or under-match sibling files in \
             the same directory), got: {toml}"
        );
        assert!(!toml.contains("normalized_prefix ="));
    }

    #[test]
    fn self_protection_toml_case_insensitive_generation_matches_recased_commands() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml(
            "/Users/h/.config/shguard",
            "literal",
            true,
            "config",
            "config directory",
            false,
        );
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        assert!(matches(&["tee", "/USERS/H/.CONFIG/SHGUARD/config.toml"]));
        assert!(matches(&[
            "dd",
            "if=/dev/zero",
            "of=/USERS/H/.CONFIG/SHGUARD/config.toml"
        ]));
        let ancestor_decision = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules
                .match_command(&words)
                .map(crate::rules::CommandRule::decision)
        };
        assert_eq!(
            ancestor_decision(&["rm", "-r", "/USERS/H/.CONFIG"]),
            Some(Decision::Ask)
        );
    }

    // issue #100: the generated [[redirect]] entry protects the RESOLVED
    // config path the same way the [[deny]] command entries above already
    // do — parity between `tee <path>` and `> <path>`.
    #[test]
    fn self_protection_redirect_rule_matches_resolved_config_path() {
        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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

        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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

        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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

    // Issue #450's reproduction table: a recursive copy or archive
    // extraction into an ANCESTOR of the config directory (naming only
    // e.g. `~/.config`, never `~/.config/shguard` itself) can overwrite
    // `config.toml` while every existing ancestor rule (rm -r/mv/rsync
    // --delete) stays silent, since none of them covered a recursive
    // copy/extract payload.
    #[test]
    fn self_protection_ancestor_rules_cover_recursive_copy_and_extract() {
        use crate::normalize::NormalizedWord;

        let toml = self_protection_toml(
            "/home/user/.config/shguard",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
        let user_config = UserConfig::parse(&toml).unwrap();
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, user_config).unwrap();

        // Asserts the matched rule's id, not just its `Decision`, so a
        // future unrelated Ask rule on the same command can't silently
        // make this pass for the wrong reason.
        let match_id = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules
                .match_command(&words)
                .map(|rule| (rule.id().as_str().to_string(), rule.decision()))
        };

        // Previously-Allow rows from the issue's reproduction table, plus
        // cp's `-a`/`--archive`/`-t`/`--target-directory=` and tar/unzip's
        // concatenated-flag spellings.
        assert_eq!(
            match_id(&["rsync", "-a", "payload/", "/home/user/.config/"]),
            Some((
                "shguard-self-protect-config-ancestor-rsync-copy-literal".to_string(),
                Decision::Ask
            ))
        );
        for cmd in [
            vec!["cp", "-r", "payload/.", "/home/user/.config/"],
            vec!["cp", "--archive", "payload/.", "/home/user/.config/"],
            vec![
                "cp",
                "-r",
                "payload",
                "--target-directory=/home/user/.config",
            ],
            vec!["cp", "-r", "payload", "-t/home/user/.config"],
        ] {
            assert_eq!(
                match_id(&cmd),
                Some((
                    "shguard-self-protect-config-ancestor-cp-literal".to_string(),
                    Decision::Ask
                )),
                "{cmd:?}"
            );
        }
        for cmd in [
            vec!["tar", "-xf", "p.tar", "-C", "/home/user/.config"],
            vec!["tar", "-xf", "p.tar", "-C/home/user/.config"],
            vec!["tar", "-xf", "p.tar", "--directory=/home/user/.config"],
        ] {
            assert_eq!(
                match_id(&cmd),
                Some((
                    "shguard-self-protect-config-ancestor-tar-extract-literal".to_string(),
                    Decision::Ask
                )),
                "{cmd:?}"
            );
        }
        for cmd in [
            vec!["unzip", "-o", "p.zip", "-d", "/home/user/.config"],
            vec!["unzip", "-o", "p.zip", "-d/home/user/.config"],
        ] {
            assert_eq!(
                match_id(&cmd),
                Some((
                    "shguard-self-protect-config-ancestor-unzip-literal".to_string(),
                    Decision::Ask
                )),
                "{cmd:?}"
            );
        }

        // Control row: already-correct behavior must be unchanged, and
        // keeps reporting its own, more specific reason (declared before
        // the flagless copy rule above, whose targets are a superset).
        assert_eq!(
            match_id(&["rsync", "-a", "--delete", "p/", "/home/user/.config/"]),
            Some((
                "shguard-self-protect-config-ancestor-rsync-literal".to_string(),
                Decision::Ask
            ))
        );

        // False-positive guards: flagless cp / tar or unzip without an
        // ancestor destination stay untouched.
        assert_eq!(match_id(&["cp", "notes.txt", "/home/user/.config"]), None);
        assert_eq!(
            match_id(&["tar", "-cf", "out.tar", "/home/user/.config"]),
            None
        );
        assert_eq!(
            match_id(&["unzip", "-o", "p.zip", "-d", "/tmp/elsewhere"]),
            None
        );
    }

    // Issue #450's literal-`~` half: a spelling using `~` directly never
    // reaches the dynamically-generated, resolved-path rules above
    // (`normalize.rs` never expands `~`/`$HOME`), so the same coverage
    // must also exist as a static rule in the embedded blocklist -- same
    // parity `self-protect-config-ancestor-{rm,mv,rsync}-tilde` already
    // established for the delete/rename half. `Rules::embedded()` alone
    // (no generated user config) is enough to exercise these.
    #[test]
    fn self_protection_static_tilde_rules_cover_recursive_copy_and_extract() {
        use crate::normalize::NormalizedWord;

        let rules = Rules::embedded().unwrap();
        let match_decision = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules
                .match_command(&words)
                .map(crate::rules::CommandRule::decision)
        };

        assert_eq!(
            match_decision(&["rsync", "-a", "payload/", "~/.config/"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["cp", "-r", "payload/.", "~/.config/"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["tar", "-xf", "p.tar", "-C", "~/.config"]),
            Some(Decision::Ask)
        );
        assert_eq!(
            match_decision(&["unzip", "-o", "p.zip", "-d", "~/.config"]),
            Some(Decision::Ask)
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
        let toml = self_protection_toml(
            "/foo",
            "literal",
            false,
            "config",
            "config directory",
            false,
        );
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

    // A symlinked directory COMPONENT (issue #449) -- e.g. stow's default
    // "folded" layout, `~/.config -> ~/dotfiles/config` -- leaves the
    // config FILE itself an ordinary file, never a symlink, so the hop
    // walk above never even starts (`read_link` on a real file fails
    // immediately). Only canonicalizing the literal directory found above
    // surfaces the real, fully-resolved directory the symlinked component
    // actually points into.
    #[test]
    #[cfg(unix)]
    fn symlinked_directory_component_is_canonically_protected() {
        let root = tempdir().unwrap();
        let root_canonical = root.path().canonicalize().unwrap();

        let real_config_dir = root_canonical
            .join("dotfiles")
            .join("config")
            .join("shguard");
        std::fs::create_dir_all(&real_config_dir).unwrap();
        std::fs::write(real_config_dir.join("config.toml"), "").unwrap();

        let home_dir = root_canonical.join("h2");
        std::fs::create_dir_all(&home_dir).unwrap();
        std::os::unix::fs::symlink(
            root_canonical.join("dotfiles").join("config"),
            home_dir.join(".config"),
        )
        .unwrap();

        let literal_dir = home_dir.join(".config").join("shguard");
        let literal_path = literal_dir.join("config.toml");

        let directories = self_protection_directories(&literal_path).unwrap();
        assert_eq!(
            directories,
            vec![
                ("literal".to_string(), literal_dir),
                ("canonical".to_string(), real_config_dir),
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
    fn require_utf8_config_dir_accepts_a_valid_path() {
        let dir = Path::new("/home/user/.config/shguard");
        assert_eq!(
            require_utf8_config_dir(dir).unwrap(),
            "/home/user/.config/shguard"
        );
    }

    #[test]
    #[cfg(unix)]
    fn require_utf8_config_dir_fails_closed_on_non_utf8_instead_of_lossy_substitution() {
        // issue #465: this must return an error, never a lossily
        // substituted (U+FFFD) string that silently generates a
        // self-protection rule which can never match the real path.
        // Building the `PathBuf` from raw bytes is a pure, in-memory
        // operation -- unlike planting an actual non-UTF-8-named
        // directory entry on disk (the end-to-end regression test in
        // `tests/user_config.rs`), it needs no filesystem support and so
        // runs the same on every unix, including macOS's UTF-8-only APFS.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let non_utf8 = PathBuf::from(OsStr::from_bytes(&[b'/', b'x', 0xFF, 0xFE, b'y']));
        let err = require_utf8_config_dir(&non_utf8).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidConfig(_)));
        assert!(err.to_string().contains("UTF-8"));
    }

    #[test]
    #[cfg(unix)]
    fn write_atomically_ignores_a_symlink_planted_at_the_old_predictable_temp_name() {
        // issue #465: `write_atomically` used to write through
        // `.{file}.tmp-{pid}`, a name any local writer of the config
        // directory could predict and pre-plant as a symlink ahead of
        // time. Even with a symlink sitting at that exact legacy name,
        // the fix's randomized `create_new` (O_EXCL) temp name must never
        // touch it: the real config write goes through cleanly, and the
        // symlink's target is left untouched.
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let planted_target = dir.path().join("attacker-owned");
        std::fs::write(&planted_target, "attacker content").unwrap();
        let legacy_tmp_name = dir
            .path()
            .join(format!(".config.toml.tmp-{}", std::process::id()));
        std::os::unix::fs::symlink(&planted_target, &legacy_tmp_name).unwrap();

        write_atomically(&path, "real content").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "real content");
        assert_eq!(
            std::fs::read_to_string(&planted_target).unwrap(),
            "attacker content",
            "the planted symlink's target must be untouched"
        );
    }

    #[test]
    fn write_atomically_leaves_no_temp_file_behind_when_rename_fails() {
        // A directory sitting at `path` makes creating the temp file
        // succeed (it's a sibling, not `path` itself) but the final
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
