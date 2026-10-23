//! The `tests/golden/must_not_allow.jsonl` row type, its strict reader and the
//! per-row evaluation under the row's own `config`/`cwd`, shared by the
//! fail-open baseline (`tests/must_not_allow.rs`) and the R0 metrics
//! (`tests/common/metrics.rs`) so both count the same Allows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use shguard::config::Policy;
use shguard::verdict::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub command: String,
    pub status: Status,
    /// The issue number (`#836`) or RFC section the payload comes from.
    pub source: String,
    #[allow(dead_code)]
    pub note: Option<String>,
    /// A bare file name under `tests/fixtures/differential/`.
    pub config: Option<String>,
    /// The hook payload's `cwd`: an absolute path.
    pub cwd: Option<String>,
}

pub fn parse_rows(origin: &str, text: &str) -> Result<Vec<Row>, String> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = format!("{origin}:{}", index + 1);
        let row: Row =
            serde_json::from_str(line).map_err(|err| format!("{at}: malformed row: {err}"))?;
        if row.source.trim().is_empty() {
            return Err(format!("{at}: empty `source`"));
        }
        if row.command.trim().is_empty() {
            return Err(format!("{at}: empty `command`"));
        }
        if let Some(config) = &row.config
            && (config.is_empty() || config.contains(['/', '\\']) || config.starts_with('.'))
        {
            return Err(format!(
                "{at}: `config` must be a bare fixture file name, got {config:?}"
            ));
        }
        if let Some(cwd) = &row.cwd {
            if !cwd.starts_with('/') {
                return Err(format!("{at}: `cwd` must be an absolute path, got {cwd:?}"));
            }
            if row.config.is_none() {
                return Err(format!(
                    "{at}: `cwd` is only honored together with `config`"
                ));
            }
        }
        if !seen.insert(row.command.clone()) {
            return Err(format!("{at}: duplicate command {:?}", row.command));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("{origin}: no rows"));
    }
    Ok(rows)
}

/// Loads every fixture the rows name; any failure aborts the run.
pub fn load_policies(
    rows: &[Row],
    fixtures: &Path,
) -> Result<BTreeMap<String, Policy>, Vec<String>> {
    let names: BTreeSet<&str> = rows
        .iter()
        .filter_map(|row| row.config.as_deref())
        .collect();
    let mut policies = BTreeMap::new();
    let mut problems = Vec::new();
    for name in names {
        match super::policy::load_policy(&fixtures.join(name)) {
            Ok(loaded) => {
                policies.insert(name.to_string(), loaded);
            }
            Err(err) => problems.push(format!("cannot load config fixture {name:?}: {err}")),
        }
    }
    if problems.is_empty() {
        Ok(policies)
    } else {
        Err(problems)
    }
}

pub fn verdict_of(row: &Row, policies: &BTreeMap<String, Policy>) -> Result<Verdict, String> {
    match row.config.as_deref() {
        None => Ok(shguard::analyze(&row.command)),
        Some(name) => policies
            .get(name)
            .map(|loaded| {
                super::policy::analyze_under_cwd(loaded, &row.command, row.cwd.as_deref())
            })
            .ok_or_else(|| format!("config fixture {name:?} was not loaded")),
    }
}
