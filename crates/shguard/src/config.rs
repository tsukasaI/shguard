//! The user config: where it lives, and the settings built from it and the
//! embedded catalog.
//!
//! The file is TOML with `deny_unknown_fields`:
//!
//! ```toml
//! ask_outcome = "deny"   # or "ask"; default "deny"
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
    if let Some((name, text)) = config {
        match parse_config(name, text) {
            Ok((ask, f)) => {
                ask_outcome = ask;
                files.push((name.to_owned(), f));
            }
            Err(e) => errs.push(e),
        }
    }
    let loaded = load_files(files, errs)?;
    Ok(Settings {
        ask_outcome,
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
}
