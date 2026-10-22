//! Loading a checked-in config fixture and analyzing a command under it,
//! shared by the differential (`tests/differential.rs`) and the fail-open
//! baseline (`tests/must_not_allow.rs`).

#![allow(dead_code)]

use std::path::Path;

use shguard::config::Policy;
use shguard::verdict::Verdict;
use shguard::{DecisionLogSink, HookContext};

/// Not `FileDecisionLog`: a test run must not write a decision log.
pub struct NoDecisionLog;

impl DecisionLogSink for NoDecisionLog {
    fn append(&self, _path: &Path, _command: &str, _verdict: &Verdict, _context: &HookContext) {}
}

/// Loads the config at `path` as the only user config.
///
/// Reads `SHGUARD_CONFIG` from the process environment, which is only safe to
/// set before any thread exists, so load every fixture before the first
/// analysis (the analysis watchdog spawns threads).
///
/// # Errors
///
/// When the file is missing or the config does not load.
pub fn load_policy(path: &Path) -> Result<Policy, String> {
    // Checked here so a renamed fixture fails naming the fixture (an explicit
    // `SHGUARD_CONFIG` that is missing would otherwise surface only as a
    // `ConfigError::Io` from `Policy::load`).
    std::fs::metadata(path).map_err(|err| format!("config fixture {}: {err}", path.display()))?;
    // SAFETY: callers run this from `main` before any thread is spawned; the
    // analysis watchdog threads start only afterwards.
    unsafe {
        std::env::set_var("SHGUARD_CONFIG", path);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
    }
    Policy::load().map_err(|err| format!("{}: {err:?}", path.display()))
}

pub fn analyze_under(policy: &Policy, command: &str) -> Verdict {
    analyze_under_cwd(policy, command, None)
}

/// Like [`analyze_under`], with the hook payload's `cwd` set to `cwd`.
pub fn analyze_under_cwd(policy: &Policy, command: &str, cwd: Option<&str>) -> Verdict {
    let context = HookContext::none().with_cwd(cwd.map(str::to_string));
    shguard::analyze_with_policy(command, policy, &context, &NoDecisionLog)
}
