//! R2 SKELETON of the old-vs-new differential (docs/rfc-redesign.md "Plan"
//! and stage R2, issue #836). It defines the four configs and the corpora the
//! RFC names, and runs "old" against "new". Until the new core exists both
//! sides are the same entry point, so the assertion is identity; R2 replaces
//! [`new_core`] and turns identity into the approval-file comparison
//! (`strangler_tightenings.jsonl`, `relaxations.jsonl`).
//!
//! Configs (checked-in fixtures in `tests/fixtures/differential/`):
//! `empty`, `owner` (the shape of a long-lived user config), `ask_outcome_deny`,
//! `allow` (one `[[allow]]`).
//!
//! Corpora (`tests/golden/*.jsonl`, command column): guardfall, fuzz,
//! denials, benign, bypass, legacy units (gate rows on the embedded rules only), must_not_allow; plus
//! `tests/fixtures/differential/rows.jsonl`, the rows that reach the rules the
//! config fixtures add.
//!
//! Every run loads all four configs and reads every corpus (the wiring
//! check). Rows are evaluated only when `SHGUARD_DIFFERENTIAL=1` or
//! `SHGUARD_DIFFERENTIAL_FULL=1` is set: until R2 the comparison is an
//! identity of one function with itself, and thousands of analyses per config
//! would only slow every `cargo test`.
//!
//! The full cross product is thousands of analyses per config, so an
//! evaluation compares a stride sample of each corpus
//! ([`SAMPLE_PER_CORPUS`]) at an offset derived from a seed that is printed
//! on every run; `SHGUARD_DIFFERENTIAL_SEED=<n>` replays it.
//! `SHGUARD_DIFFERENTIAL_FULL=1` compares every row.
//!
//! The config loader reads `SHGUARD_CONFIG` from the process environment,
//! which is only safe to set before any thread exists.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use shguard::config::Policy;
use shguard::verdict::{Decision, Verdict};
use shguard::{DecisionLogSink, HookContext};

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

type Reader = fn(&Path) -> Result<Vec<String>, String>;

/// `(name, path from the checkout root, reader)`. Every corpus is required: a
/// missing file fails the run.
const CORPORA: [(&str, &str, Reader); 8] = [
    (
        "guardfall",
        "tests/golden/guardfall.jsonl",
        corpus::read_commands,
    ),
    ("fuzz", "tests/golden/fuzz.jsonl", corpus::read_commands),
    (
        "denials",
        "tests/golden/denials.jsonl",
        corpus::read_commands,
    ),
    (
        "benign",
        "tests/golden/benign_corpus.jsonl",
        corpus::read_commands,
    ),
    (
        "bypass",
        "tests/golden/bypass_corpus.jsonl",
        corpus::read_commands,
    ),
    (
        "must_not_allow",
        "tests/golden/must_not_allow.jsonl",
        corpus::read_commands,
    ),
    // Reaches the rules the checked-in configs add (allow.toml, owner.toml).
    (
        "fixture_rules",
        "tests/fixtures/differential/rows.jsonl",
        corpus::read_commands,
    ),
    (
        "legacy",
        "tests/golden/legacy_units.jsonl",
        read_legacy_gate_commands,
    ),
];

/// Commands of the `kind == "gate"` rows of `legacy_units.jsonl` recorded on
/// the embedded rule set (no `config`) with no `cwd`, deduplicated: the
/// differential applies its own four configs, so a row recorded under another
/// rule set or directory would not mean what it recorded. Other kinds are
/// skipped; a malformed line or a used gate row without a string `command` fails.
fn read_legacy_gate_commands(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut commands = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = format!("{}:{}", path.display(), index + 1);
        let row: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("{at}: malformed line: {err}"))?;
        let kind = row
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{at}: missing string `kind`"))?;
        if kind != "gate" {
            continue;
        }
        if row.get("config").is_some() || row.get("cwd").is_some() {
            continue;
        }
        let command = row
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{at}: gate row missing string `command`"))?;
        if seen.insert(command.to_string()) {
            commands.push(command.to_string());
        }
    }
    if commands.is_empty() {
        return Err(format!("{}: no embedded-config gate rows", path.display()));
    }
    Ok(commands)
}

/// What the differential compares: the decision and its reason text.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    decision: Decision,
    reason: Option<String>,
}

impl Outcome {
    /// A watchdog trip is the harness running out of time, not a decision.
    fn is_watchdog_trip(&self) -> bool {
        self.reason
            .as_deref()
            .is_some_and(|reason| reason.ends_with(golden::WATCHDOG_REASON_SUFFIX))
    }
}

fn outcome(verdict: &Verdict) -> Outcome {
    Outcome {
        decision: verdict.decision(),
        reason: verdict.reason().map(|reason| reason.as_str().to_string()),
    }
}

/// Not `FileDecisionLog`: the differential must not write a decision log.
struct NoDecisionLog;

impl DecisionLogSink for NoDecisionLog {
    fn append(&self, _path: &Path, _command: &str, _verdict: &Verdict, _context: &HookContext) {}
}

fn old_core(policy: &Policy, command: &str) -> Outcome {
    outcome(&shguard::analyze_with_policy(
        command,
        policy,
        &HookContext::none(),
        &NoDecisionLog,
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

fn env_is_one(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| value == "1")
}

fn seed() -> Result<u64, String> {
    match std::env::var("SHGUARD_DIFFERENTIAL_SEED") {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|err| format!("SHGUARD_DIFFERENTIAL_SEED={text:?}: {err}")),
        Err(_) => Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())),
    }
}

fn sample(commands: Vec<String>, full: bool, seed: u64) -> Vec<String> {
    if full || commands.len() <= SAMPLE_PER_CORPUS {
        return commands;
    }
    let stride = commands.len().div_ceil(SAMPLE_PER_CORPUS);
    let offset = usize::try_from(seed % stride as u64).unwrap_or(0);
    commands.into_iter().skip(offset).step_by(stride).collect()
}

fn run() -> Result<(), String> {
    let full = env_is_one("SHGUARD_DIFFERENTIAL_FULL");
    let evaluate = full || env_is_one("SHGUARD_DIFFERENTIAL");
    let seed = seed()?;
    let root = golden::checkout_dir();
    let fixtures = root.join("tests/fixtures/differential");

    let mut policies = Vec::new();
    for (name, file) in CONFIGS {
        policies.push((name, load_policy(&fixtures.join(file))?));
    }

    let mut corpora = Vec::new();
    for (corpus_name, file, read) in CORPORA {
        corpora.push((corpus_name, read(&root.join(file))?));
    }

    if !evaluate {
        println!(
            "differential: loaded {} configs and {} corpora; evaluation skipped because both \
             sides are the same entry point until R2 (set SHGUARD_DIFFERENTIAL=1 to run it)",
            policies.len(),
            corpora.len()
        );
        return Ok(());
    }
    println!(
        "differential: {} sampling, seed {seed} (replay with SHGUARD_DIFFERENTIAL_SEED={seed})",
        if full { "no" } else { "stride" }
    );

    let mut compared = 0_usize;
    let mut problems = Vec::new();
    for (corpus_name, commands) in corpora {
        let commands = sample(commands, full, seed);
        for (config_name, policy) in &policies {
            for command in &commands {
                let old = old_core(policy, command);
                let new = new_core(policy, command);
                compared += 1;
                if old.is_watchdog_trip() || new.is_watchdog_trip() {
                    problems.push(format!(
                        "harness failure: watchdog tripped in {corpus_name}/{config_name} for \
                         {command:?}"
                    ));
                } else if old != new {
                    problems.push(format!(
                        "{corpus_name}/{config_name}: old {old:?} != new {new:?} for {command:?}"
                    ));
                }
            }
        }
    }
    println!(
        "differential: R2 skeleton, {compared} comparisons over {} configs, {} problems",
        CONFIGS.len(),
        problems.len()
    );
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
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
