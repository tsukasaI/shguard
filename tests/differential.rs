//! R2 SKELETON of the old-vs-new differential (docs/rfc-redesign.md "Plan"
//! and stage R2, issue #836). It defines the four configs and the corpora the
//! RFC names, and runs "old" against "new". Until the new core exists both
//! sides are the same entry point, so the assertion is identity; R2 replaces
//! [`new_core`] and turns identity into the approval-file comparison
//! (`strangler_tightenings.jsonl`, `relaxations.jsonl`).
//!
//! Configs (checked-in fixtures in `tests/fixtures/differential/`):
//! `empty`, `owner` (the shape of the owner's config), `ask_outcome_deny`,
//! `allow` (one `[[allow]]`).
//!
//! Corpora (`tests/golden/*.jsonl`, command column): guardfall, fuzz,
//! denials, benign, bypass, legacy units, must_not_allow.
//!
//! The full cross product is thousands of analyses per config, so a normal
//! run compares a deterministic stride sample of each corpus
//! ([`SAMPLE_PER_CORPUS`]). `SHGUARD_DIFFERENTIAL_FULL=1` compares every row.
//!
//! `harness = false`: the config loader reads `SHGUARD_CONFIG` from the
//! process environment, which is only safe to set before any thread exists.

#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::ExitCode;

use shguard::config::Policy;
use shguard::verdict::{Decision, Verdict};
use shguard::{FileDecisionLog, HookContext};

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/golden.rs"]
#[allow(dead_code)]
mod golden;

const SAMPLE_PER_CORPUS: usize = 40;

const CONFIGS: [(&str, &str); 4] = [
    ("empty", "empty.toml"),
    ("owner", "owner.toml"),
    ("ask_outcome_deny", "ask_outcome_deny.toml"),
    ("allow", "allow.toml"),
];

/// `(name, file, required)`. A required corpus that is missing fails the run;
/// an optional one is skipped with a note.
const CORPORA: [(&str, &str, bool); 7] = [
    ("guardfall", "guardfall.jsonl", true),
    ("fuzz", "fuzz.jsonl", true),
    ("denials", "denials.jsonl", true),
    ("benign", "benign_corpus.jsonl", true),
    ("bypass", "bypass_corpus.jsonl", true),
    ("must_not_allow", "must_not_allow.jsonl", true),
    // TODO(#836): make this required once the legacy_units.jsonl extraction
    // (gate.rs and rules.rs unit-test inputs) lands.
    ("legacy", "legacy_units.jsonl", false),
];

/// What the differential compares: the decision and its reason text.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    decision: Decision,
    reason: Option<String>,
}

fn outcome(verdict: &Verdict) -> Outcome {
    Outcome {
        decision: verdict.decision(),
        reason: verdict.reason().map(|reason| reason.as_str().to_string()),
    }
}

fn old_core(policy: &Policy, command: &str) -> Outcome {
    outcome(&shguard::analyze_with_policy(
        command,
        policy,
        &HookContext::none(),
        &FileDecisionLog,
    ))
}

/// R2: replace with the new evaluation core. Until then it is the old entry
/// point, which makes every comparison an identity check of the harness.
fn new_core(policy: &Policy, command: &str) -> Outcome {
    old_core(policy, command)
}

fn load_policy(path: &Path) -> Result<Policy, String> {
    // SAFETY: called from `main` before any thread is spawned; the analysis
    // watchdog threads start only afterwards.
    unsafe {
        std::env::set_var("SHGUARD_CONFIG", path);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
    }
    Policy::load().map_err(|err| format!("{}: {err:?}", path.display()))
}

fn sample(commands: Vec<String>, full: bool) -> Vec<String> {
    if full || commands.len() <= SAMPLE_PER_CORPUS {
        return commands;
    }
    let stride = commands.len().div_ceil(SAMPLE_PER_CORPUS);
    commands.into_iter().step_by(stride).collect()
}

fn run() -> Result<(), String> {
    let full = std::env::var_os("SHGUARD_DIFFERENTIAL_FULL").is_some_and(|v| v == "1");
    let root = golden::checkout_dir();
    let fixtures = root.join("tests/fixtures/differential");
    let golden_dir = root.join("tests/golden");

    let mut policies = Vec::new();
    for (name, file) in CONFIGS {
        policies.push((name, load_policy(&fixtures.join(file))?));
    }

    let mut compared = 0_usize;
    let mut mismatches = Vec::new();
    for (corpus_name, file, required) in CORPORA {
        let path = golden_dir.join(file);
        if !required && !path.exists() {
            println!("differential: skipping corpus {corpus_name}: {file} does not exist yet");
            continue;
        }
        let commands = sample(corpus::read_commands(&path)?, full);
        for (config_name, policy) in &policies {
            for command in &commands {
                let old = old_core(policy, command);
                let new = new_core(policy, command);
                compared += 1;
                if old != new {
                    mismatches.push(format!(
                        "{corpus_name}/{config_name}: old {old:?} != new {new:?} for {command:?}"
                    ));
                }
            }
        }
    }
    println!(
        "differential: R2 skeleton, {compared} comparisons over {} configs ({}), {} mismatches",
        CONFIGS.len(),
        if full { "full" } else { "sampled" },
        mismatches.len()
    );
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("differential: {err}");
            ExitCode::FAILURE
        }
    }
}
