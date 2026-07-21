//! Composition-root-facing user config loader (plan.md §6 item 8) —
//! `crate::gate`/`crate::rules` own the *rules*, this module owns
//! *finding* them: where the user's config file lives, and the
//! fail-closed/silent-skip boundary around reading it.
//!
//! # Discovery
//!
//! `SHGUARD_CONFIG` env var (any value counts as "set", even `""`) >
//! `$XDG_CONFIG_HOME/shguard/config.toml` (an empty `XDG_CONFIG_HOME`
//! counts as unset, per the XDG spec) > `$HOME/.config/shguard/config.toml`.
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
//! `SHGUARD_CONFIG` set (to anything), or the default path existing but
//! unreadable/unparseable/unmergeable, is a hard [`ConfigError`] —
//! [`Policy::load`]'s caller refuses to evaluate any command until it's
//! fixed, the same posture `Rules::embedded`'s own load failure already
//! has (`crate::gate::analyze`). The default path simply not existing at
//! all — `std::fs::symlink_metadata` itself returning
//! `io::ErrorKind::NotFound`, `SHGUARD_CONFIG` unset — is the ordinary
//! "never configured" case: silently proceed embedded-only, matching
//! ripgrep's `RIPGREP_CONFIG_PATH` precedent. Anything else the default
//! path could be — a dangling symlink, a directory, an unreadable file,
//! or any other `lstat` error — is a hard failure too, not silently
//! skipped (issue #39): `symlink_metadata` (not `read_to_string`'s own
//! error) is what decides "nothing configured" vs. "something's there but
//! broken", since a dangling symlink makes `read_to_string` fail with the
//! same `NotFound` kind a genuinely absent path does.
//!
//! # Self-protecting the config file
//!
//! [`self_protection_toml`] generates `[[deny]]` rules, at load time,
//! targeting the config directory for common write-capable commands
//! (`tee`, `cp`, `mv`, `install`, `sed -i`, `dd`'s `of=<path>` shape) —
//! the one place this crate builds a rule's TOML text in code rather than
//! reading it from a file, because the directory is only known once
//! `$HOME`/`$XDG_CONFIG_HOME` are read for *this* invocation; the
//! embedded blocklist is fixed at compile time and cannot know an
//! individual user's home directory. [`self_protection_directories`]
//! `canonicalize`s the config path before generating rules, so a config
//! deployed as a symlink (e.g. into a dotfiles repo, so the policy stays
//! versioned) gets *two* directories protected — the symlink's own
//! directory and its resolved target's directory — rather than only
//! whichever one happens to be the literal path (issue #31). When the
//! path doesn't canonicalize at all (nothing there yet, or a dangling
//! symlink), only the literal directory is protected, same as before this
//! fix. `rules/blocklist.toml`
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

use std::path::{Path, PathBuf};

use crate::rules::{Allowlist, Rules, UserConfig, merge_user_config};

/// Everything that can go wrong loading a user policy. Every variant is a
/// hard failure — [`Policy::load`] never falls back to "ignore the bad
/// config and use embedded-only" once a config path was found (see the
/// module docs' fail-closed policy).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `path` exists (or was explicitly named via `SHGUARD_CONFIG`) but
    /// could not be read for a reason other than "it doesn't exist and
    /// nothing explicitly pointed at it" (see [`Policy::load`]).
    #[error("could not read {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
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
}

impl From<crate::rules::RulesError> for ConfigError {
    fn from(err: crate::rules::RulesError) -> Self {
        Self::InvalidConfig(err.to_string())
    }
}

/// A fully loaded, merged policy: the embedded blocklist/allowlist, plus
/// whatever a user config contributed, plus this invocation's
/// self-protection rules. Opaque to callers outside this crate — the only
/// public operations are [`Policy::load`] and passing a `&Policy` to
/// [`crate::analyze_with_policy`].
pub struct Policy {
    pub(crate) rules: Rules,
    pub(crate) allowlist: Allowlist,
}

impl Policy {
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
        home.map(|home| {
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
    /// non-UTF-8 value) but the file it names cannot be read, or if a found
    /// config file (explicit or default) fails to parse/validate/merge, or
    /// if the default path exists but fails to read for a reason other
    /// than "does not exist".
    pub fn load() -> Result<Self, ConfigError> {
        // `var_os` (not `var(..).ok()`) so a *present* but non-UTF-8
        // `SHGUARD_CONFIG` is distinguishable from *absent* — `var(..).ok()`
        // collapses both into `None`, silently falling through to XDG/HOME
        // discovery instead of the hard failure the "set to anything ⇒
        // explicit" contract (module docs) requires.
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
        // Same `var_os` treatment as `SHGUARD_CONFIG` above (issue #28 item
        // 1): a present-but-non-UTF-8 `HOME`/`XDG_CONFIG_HOME` must fail
        // closed too, not collapse into "unset" via `var(..).ok()` and
        // silently fall through to a different discovery source.
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
        let explicit = shguard_config.is_some();

        let path = Self::resolve_config_path(
            shguard_config.as_deref(),
            xdg_config_home.as_deref(),
            home.as_deref(),
        );

        let blocklist = Rules::embedded()?;
        let allowlist = Allowlist::embedded()?;

        let (rules, allowlist) = match &path {
            Some(path) => {
                // `symlink_metadata` (`lstat`), not `read_to_string`'s own
                // error, decides "nothing configured" vs. "something's
                // there but broken" (issue #39): a dangling symlink makes
                // `read_to_string` fail with the same `NotFound` kind a
                // genuinely absent path does, so only a clean `NotFound`
                // from `lstat` itself -- meaning there truly is no file,
                // symlink, or anything else at this path -- gets the
                // silent embedded-only fallback, and only for the
                // (non-explicit) default path.
                let lstat = std::fs::symlink_metadata(path);
                let truly_absent =
                    matches!(&lstat, Err(err) if err.kind() == std::io::ErrorKind::NotFound);
                if truly_absent && !explicit {
                    (blocklist, allowlist)
                } else if let Err(err) = lstat {
                    return Err(ConfigError::Io {
                        path: path.clone(),
                        source: err,
                    });
                } else {
                    match std::fs::read_to_string(path) {
                        Ok(contents) => {
                            let user_config = UserConfig::parse(&contents)?;
                            merge_user_config(blocklist, allowlist, user_config)?
                        }
                        Err(err) => {
                            return Err(ConfigError::Io {
                                path: path.clone(),
                                source: err,
                            });
                        }
                    }
                }
            }
            None => (blocklist, allowlist),
        };

        let (rules, allowlist) = match &path {
            Some(path) => {
                let mut rules = rules;
                let mut allowlist = allowlist;
                for (suffix, config_dir) in self_protection_directories(path) {
                    let toml = self_protection_toml(&config_dir.to_string_lossy(), suffix);
                    let self_protection = UserConfig::parse(&toml)?;
                    (rules, allowlist) = merge_user_config(rules, allowlist, self_protection)?;
                }
                (rules, allowlist)
            }
            None => (rules, allowlist),
        };

        Ok(Self { rules, allowlist })
    }
}

/// Directories to generate self-protection rules for, given the resolved
/// config `path` (see the module docs' "Self-protecting the config file"
/// section): the path's own (literal) parent directory, plus — when
/// `path` canonicalizes successfully — its resolved target's parent
/// directory too, so a symlinked config's real file is protected as well
/// as the symlink itself (issue #31). Deduplicated (an ordinary,
/// non-symlinked config yields the same directory twice from both steps)
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
/// [`self_protection_toml`]'s generated rule ids, since the literal and
/// resolved directories need distinct ids to coexist in one merged rule
/// set.
///
/// The resolved directory is only ever added *alongside* a protectable
/// literal one, never in its place: a relative `SHGUARD_CONFIG` (e.g.
/// `SHGUARD_CONFIG=config.toml` in a CI/test harness) still yields no
/// literal entry (issue #24's invariant), and canonicalizing it would
/// otherwise resolve to the current working directory — protecting an
/// entire project tree the agent can still dodge for the config file
/// itself with a relative spelling (`cp evil.toml config.toml`), so that
/// blanket rule would cost real usability for near-zero security value.
fn self_protection_directories(path: &Path) -> Vec<(&'static str, PathBuf)> {
    let is_protectable = |dir: &Path| dir.is_absolute() && dir != Path::new("/");

    let mut directories: Vec<(&'static str, PathBuf)> = Vec::new();
    if let Some(literal_dir) = path.parent().filter(|dir| is_protectable(dir)) {
        directories.push(("literal", literal_dir.to_path_buf()));
    }
    if !directories.is_empty()
        && let Ok(canonical) = std::fs::canonicalize(path)
        && let Some(resolved_dir) = canonical.parent().filter(|dir| is_protectable(dir))
        && directories.iter().all(|(_, dir)| dir != resolved_dir)
    {
        directories.push(("resolved", resolved_dir.to_path_buf()));
    }
    directories
}

/// Generates `[[deny]]`-array TOML text protecting `config_dir` (and
/// everything under it) from common write-capable commands run through
/// Bash — see the module docs' "Self-protecting the config file" section
/// for why this is generated rather than read from a file. `suffix`
/// disambiguates rule ids across multiple calls (one per directory
/// returned by [`self_protection_directories`]) so they can be merged
/// into one rule set without an id collision.
fn self_protection_toml(config_dir: &str, suffix: &str) -> String {
    let quoted_dir = toml_quote(config_dir);
    let quoted_dd_target = toml_quote(&format!("of={config_dir}"));
    format!(
        r#"
[[deny]]
id = "shguard-self-protect-config-tee-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "tee"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-cp-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "cp"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-mv-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "mv"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-install-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "install"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-sed-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "sed"
required_flags = ["i|--in-place"]
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-dd-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "dd"
targets = [{{ prefix = {quoted_dd_target} }}]

[[deny]]
id = "shguard-self-protect-config-rm-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "rm"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-unlink-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "unlink"
targets = [{{ prefix = {quoted_dir} }}]

[[deny]]
id = "shguard-self-protect-config-ln-{suffix}"
reason = "writing to shguard's own config directory must never be scripted"
command = "ln"
targets = [{{ prefix = {quoted_dir} }}]
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        assert!(!matches(&["cp", "a.txt", "b.txt"]));
    }

    #[test]
    fn root_only_parent_is_excluded_from_self_protection_directories() {
        // SHGUARD_CONFIG=/config.toml (issue #28 item 3): `Path::parent()`
        // returns `Some("/")`, which is absolute but would generate an
        // over-broad `prefix = "/"` self-protection rule denying writes to
        // almost any absolute path if not explicitly excluded.
        assert!(self_protection_directories(Path::new("/config.toml")).is_empty());
    }

    #[test]
    fn relative_path_generates_no_self_protection_directories_even_if_it_canonicalizes() {
        // A relative `SHGUARD_CONFIG` (e.g. `config.toml` in a CI/test
        // harness) must still generate nothing, even when the relative path
        // happens to exist and canonicalize successfully -- otherwise the
        // resolved directory would silently become the current working
        // directory, denying absolute-path writes across the whole project
        // for near-zero security benefit (the config file itself stays
        // writable via a relative spelling regardless). `Cargo.toml` is
        // relative and canonicalizes (`cargo test`'s cwd is the crate
        // root), pinning this without any tempdir/cwd mutation.
        assert!(self_protection_directories(Path::new("Cargo.toml")).is_empty());
    }

    #[test]
    fn load_with_no_env_vars_falls_back_to_embedded_only() {
        // A best-effort smoke test: with no discovery inputs, resolve_config_path
        // returns None, so Policy::load's own env-reading path can't be driven
        // deterministically here without mutating process env (test-unsafe) —
        // covered end-to-end instead by tests/user_config.rs via the real
        // binary with controlled env vars. This test only exercises the pure
        // resolver, already covered above; kept as a named anchor for anyone
        // looking for load()'s test coverage from this module.
        assert_eq!(Policy::resolve_config_path(None, None, None), None);
    }
}
