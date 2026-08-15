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
//! broken".
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
//! analyzer). [`ancestor_rules_toml`] adds a second, `decision = "ask"`
//! family covering `rm -r`/`mv`/`rsync --delete` against an ANCESTOR of
//! the config directory (`~/.config`, `~`, and their resolved
//! equivalents) — deleting or renaming an ancestor takes the config
//! directory with it even though the ancestor path itself never appears
//! in the direct-target list above —
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

use std::collections::HashSet;
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
        // closed too.
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
                for (suffix, config_dir) in self_protection_directories(path)? {
                    let toml = self_protection_toml(&config_dir.to_string_lossy(), &suffix);
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
required_flags = ["i|--in-place"]
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
required_flags = ["r|--recursive"]
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
    // never precede (and thereby shadow) the global rm-recursive-force
    // Block rule within rules/blocklist.toml -- first-match-wins within
    // one file. `rm -rf ~`/`rm -rf /` must still Block, not downgrade to
    // Ask, with the ancestor rules present.
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
        // covered end-to-end instead by tests/user_config.rs via the real
        // binary with controlled env vars. This test only exercises the pure
        // resolver, already covered above; kept as a named anchor for anyone
        // looking for load()'s test coverage from this module.
        assert_eq!(Policy::resolve_config_path(None, None, None), None);
    }
}
