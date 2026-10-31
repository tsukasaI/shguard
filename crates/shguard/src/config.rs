//! The user config: where it lives, and the settings built from it and the
//! embedded catalog.
//!
//! The file is TOML with `deny_unknown_fields`:
//!
//! ```toml
//! ask_outcome = "deny"   # or "ask"; default "deny"
//! decision_log = "/abs/path/decisions.jsonl"   # optional; off by default
//!
//! [[row]]    # exactly the catalog row schema; `source` is required
//! [[rule]]   # exactly the catalog rule schema; outcome "block" or "ask"
//! ```
//!
//! Rows and rules are merged with the embedded catalog through the same
//! checks as every catalog file, so a duplicate key against an embedded row
//! is a load error. A longer user key still shadows its parent for the
//! commands it matches. A user `[[row]]` widens Allow and the user owns
//! that. Under `ask_outcome = "ask"` an embedded Block holds only for
//! commands the catalog covers: an unknown option makes the command
//! uncovered, so it is an Ask. `SHGUARD_CONFIG` must be an absolute path.
//! `decision_log` must be absolute and its directory must exist; each line
//! holds the command text, so the file can hold secrets that were typed on
//! a command line. Keep the directory out of the agent's reach: a symlink
//! at the file itself is refused, one higher up is followed. A 0.9 config
//! (`[[deny]]`, `[[ask]]`, ...) is a load error that says to migrate.
//! To distrust a row, add a `[[rule]]` instead. A
//! rule with a key and no `opts` or `targets` hits every command under that
//! key, so `[[rule]] key = ["rm"] outcome = "ask"` makes every `rm` an Ask.

use std::ffi::OsString;
use std::path::PathBuf;

pub use crate::catalog::AskOutcome;
use crate::catalog::{LoadError, Loaded, Source, load_files, parse_config, parse_file};

/// What the hook runs with.
#[derive(Debug)]
pub struct Settings {
    /// What an Ask becomes.
    pub ask_outcome: AskOutcome,
    /// Where to append one JSON line per decision, if anywhere.
    pub decision_log: Option<PathBuf>,
    /// The merged catalog and rules.
    pub loaded: Loaded,
}

/// Where the config file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// No place to look: `HOME` is unset or empty and `SHGUARD_CONFIG` is
    /// not set. The defaults apply.
    Nowhere,
    /// `$HOME/.config/shguard/config.toml`. A missing file is fine.
    Default(PathBuf),
    /// `SHGUARD_CONFIG`. A missing file is a load error.
    Explicit(PathBuf),
    /// `SHGUARD_CONFIG` is not absolute: a load error, since the hook's
    /// working directory is not under the user's control.
    Relative(PathBuf),
}

/// Picks the config path from the two environment variables. An empty value
/// counts as unset.
#[must_use]
pub fn locate(shguard_config: Option<OsString>, home: Option<OsString>) -> Location {
    if let Some(p) = shguard_config.filter(|p| !p.is_empty()) {
        let path = PathBuf::from(p);
        return if path.is_absolute() {
            Location::Explicit(path)
        } else {
            Location::Relative(path)
        };
    }
    match home.filter(|h| !h.is_empty()) {
        Some(h) => Location::Default(
            PathBuf::from(h)
                .join(".config")
                .join("shguard")
                .join("config.toml"),
        ),
        None => Location::Nowhere,
    }
}

/// Builds the settings from the embedded catalog and the config file's name
/// and text, if there is one.
///
/// # Errors
///
/// Every [`LoadError`] found in the embedded files and the config.
pub fn settings(
    embedded: &[Source<'_>],
    config: Option<(&str, &str)>,
) -> Result<Settings, Vec<LoadError>> {
    let mut errs = Vec::new();
    let mut files = Vec::new();
    for src in embedded {
        match parse_file(src.name, src.text) {
            Ok(f) => files.push((src.name.to_owned(), f)),
            Err(e) => errs.push(e),
        }
    }
    let mut ask_outcome = AskOutcome::default();
    let mut decision_log = None;
    if let Some((name, text)) = config {
        match parse_config(name, text) {
            Ok((head, f)) => {
                ask_outcome = head.ask_outcome;
                decision_log = head.decision_log;
                files.push((name.to_owned(), f));
            }
            Err(e) => errs.push(e),
        }
    }
    let loaded = load_files(files, errs)?;
    Ok(Settings {
        ask_outcome,
        decision_log,
        loaded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn locates() {
        assert_eq!(
            locate(os("/c.toml"), os("/h")),
            Location::Explicit(PathBuf::from("/c.toml"))
        );
        assert_eq!(
            locate(os("rel.toml"), os("/h")),
            Location::Relative(PathBuf::from("rel.toml"))
        );
        assert_eq!(
            locate(os(""), os("/h")),
            Location::Default(PathBuf::from("/h/.config/shguard/config.toml"))
        );
        assert_eq!(
            locate(None, os("/h")),
            Location::Default(PathBuf::from("/h/.config/shguard/config.toml"))
        );
        assert_eq!(locate(None, os("")), Location::Nowhere);
        assert_eq!(locate(None, None), Location::Nowhere);
    }

    #[test]
    fn config_fields() {
        let ok = settings(&[], Some(("c", "ask_outcome = \"ask\"\n")));
        assert!(matches!(ok, Ok(s) if s.ask_outcome == AskOutcome::Ask));
        let default = settings(&[], None);
        assert!(matches!(default, Ok(s) if s.ask_outcome == AskOutcome::Deny));
        assert!(settings(&[], Some(("c", "bogus = 1\n"))).is_err());
        assert!(settings(&[], Some(("c", "ask_outcome = \"allow\"\n"))).is_err());
    }

    fn first_error(text: &str) -> LoadError {
        match settings(&[], Some(("c", text))) {
            Ok(_) => panic!("`{text}` loads"),
            Err(mut e) => e.remove(0),
        }
    }

    #[test]
    fn decision_log_must_be_absolute() {
        let ok = settings(&[], Some(("c", "decision_log = \"/var/log/d.jsonl\"\n")));
        assert!(matches!(ok, Ok(s) if s.decision_log == Some(PathBuf::from("/var/log/d.jsonl"))));
        assert!(matches!(
            first_error("decision_log = \"d.jsonl\"\n"),
            LoadError::DecisionLogNotAbsolute { .. }
        ));
    }

    #[test]
    fn a_09_config_is_reported_as_one() {
        for text in [
            "[[deny]]\nid = \"d\"\nreason = \"r\"\ncommand = \"x\"\n",
            "[[ask]]\nid = \"a\"\nreason = \"r\"\ncommand = \"gh\"\n",
            "[[allow]]\nid = \"a\"\nreason = \"r\"\ncommand = \"rm\"\n",
            "[[redirect]]\nid = \"r\"\n",
            "[[pipeline]]\nid = \"p\"\n",
            "escalation_floor = \"deny\"\n",
            "decision_log_path = \"/x\"\n",
            "ask_outcome = { default = \"ask\" }\n",
            "ask_outcome = \"ask\"\n[[deny]]\nid = \"d\"\nreason = \"r\"\ncommand = \"x\"\n",
        ] {
            assert!(
                matches!(first_error(text), LoadError::LegacyConfig { .. }),
                "{text}"
            );
        }
        // Not TOML, or an unknown key that 0.9 did not have either: a
        // plain TOML error.
        for text in ["this is = not toml [", "bogus = 1\n"] {
            assert!(
                matches!(first_error(text), LoadError::Toml { .. }),
                "{text}"
            );
        }
        // A 0.9 config of comments only (what 0.9's init wrote) loads.
        assert!(settings(&[], Some(("c", "# [[deny]]\n# id = \"x\"\n"))).is_ok());
    }
}
