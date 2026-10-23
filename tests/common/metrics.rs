//! The R0 metrics of the evaluation-core redesign (docs/rfc-redesign.md,
//! issue #836), computed once here and printed by `tests/metrics.rs`
//! (`cargo test --test metrics`, also run by `scripts/metrics`).
//!
//! Every number comes from running `shguard::analyze` (embedded rules, no
//! config, no filesystem) over the command column of a golden corpus, so it
//! is current even before a snapshot is re-blessed. The exception is
//! `must_not_allow`, whose rows run under their own `config`/`cwd`.
//!
//! # Unknown kinds
//!
//! Today's core has no `Unknown` state: a name outside the catalog is an
//! Allow, so an unknown command that was Allowed cannot be counted from the
//! outside. What can be counted is every non-Allow verdict whose reason says
//! shguard could not read part of the line. [`classify_unknown`] maps the
//! reason text to the RFC's `UnknownKind` families by the needles in
//! [`KIND_NEEDLES`], the single place to update when a reason is reworded
//! (first match wins, in that order; a verdict that names a matched
//! blocklist rule is a finding, not an Unknown).
//!
//! `unknown.<corpus>.count` sums the kinds of one corpus;
//! `unknown_command_count.<corpus>` is its `command` kind alone. Both are
//! lower bounds of what R2 will count exactly. `unknown.total` is the sum of
//! `unknown.<corpus>.count` over benign, denials and bypass.

use std::collections::BTreeMap;
use std::path::Path;

use shguard::verdict::{Decision, Verdict};

use super::corpus;
use super::golden;
use super::must_not_allow_rows::{load_policies, parse_rows, verdict_of};

/// Needles per kind, in match order.
const KIND_NEEDLES: [(&str, &[&str]); 9] = [
    ("parse", &["could not parse command"]),
    (
        "option",
        &[
            "unmodelled option",
            "option that shguard cannot place",
            "option list could not be",
        ],
    ),
    (
        "command",
        &[
            "unmodelled command name",
            "command position",
            "wrapped command could not be statically resolved",
            "shell-string flag",
        ],
    ),
    (
        "stdin",
        &[
            "reads its program from stdin",
            "no decode stage upstream",
            "decodes/transforms data upstream",
            "standard input",
            "on stdin",
        ],
    ),
    (
        "persisted",
        &[
            "whose value git runs as a shell command",
            "could name alias.",
        ],
    ),
    (
        "env",
        &["$IFS", "PATH is given", "session state could still differ"],
    ),
    (
        "cwd",
        &[
            "working directory could not be",
            "unknown anchor",
            "directory-stack",
        ],
    ),
    (
        "operand",
        &[
            "script is not proven",
            "bare positional argument",
            "inline code",
            "names its file through",
            "script operand could not",
            "payload invokes",
            "cannot be introspected",
            "could not be statically resolved",
        ],
    ),
    (
        "expansion",
        &[
            "glob in",
            "unresolvable",
            "qualifier expansion",
            "arithmetic expansion",
            "placeholder stands in",
        ],
    ),
];

/// The Unknown kind a verdict's reason falls under, if any.
#[must_use]
pub fn classify_unknown(decision: Decision, reason: Option<&str>) -> Option<&'static str> {
    let reason = reason?;
    if decision == Decision::Allow || reason.contains("matches blocklist rule") {
        return None;
    }
    KIND_NEEDLES
        .iter()
        .find(|(_, needles)| needles.iter().any(|needle| reason.contains(needle)))
        .map(|(kind, _)| *kind)
}

#[derive(Debug, Default)]
pub struct CorpusStats {
    pub total: usize,
    pub allow: usize,
    pub ask: usize,
    pub block: usize,
    pub unknown_by_kind: BTreeMap<&'static str, usize>,
}

impl CorpusStats {
    #[must_use]
    pub fn not_allow(&self) -> usize {
        self.ask + self.block
    }

    #[must_use]
    pub fn unknown_total(&self) -> usize {
        self.unknown_by_kind.values().sum()
    }
}

/// Runs `shguard::analyze` over every command of `golden/<name>.jsonl`.
///
/// # Errors
///
/// When the corpus cannot be read (see `corpus::read_commands`).
pub fn measure(golden_dir: &Path, name: &str) -> Result<CorpusStats, String> {
    let commands = corpus::read_commands(&golden_dir.join(format!("{name}.jsonl")))?;
    Ok(tally(
        commands.iter().map(|command| shguard::analyze(command)),
    ))
}

/// Evaluates every row of `golden/must_not_allow.jsonl` under its own
/// `config` and `cwd`, as `tests/must_not_allow.rs` does, so `allow` equals
/// that target's open count.
///
/// Loads the config fixtures, which sets a process environment variable, so
/// call it before the first analysis of the run.
///
/// # Errors
///
/// When the file cannot be read or parsed, or a fixture does not load.
pub fn measure_must_not_allow(golden_dir: &Path) -> Result<CorpusStats, String> {
    let path = golden_dir.join("must_not_allow.jsonl");
    let text = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let rows = parse_rows(&path.display().to_string(), &text)?;
    let fixtures = golden::checkout_dir().join("tests/fixtures/differential");
    let policies = load_policies(&rows, &fixtures).map_err(|problems| problems.join("; "))?;
    let verdicts = rows
        .iter()
        .map(|row| verdict_of(row, &policies))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tally(verdicts))
}

fn tally(verdicts: impl IntoIterator<Item = Verdict>) -> CorpusStats {
    let mut stats = CorpusStats::default();
    for verdict in verdicts {
        stats.total += 1;
        match verdict.decision() {
            Decision::Allow => stats.allow += 1,
            Decision::Ask => stats.ask += 1,
            Decision::Block => stats.block += 1,
        }
        let reason = verdict.reason().map(shguard::verdict::Reason::as_str);
        if let Some(kind) = classify_unknown(verdict.decision(), reason) {
            *stats.unknown_by_kind.entry(kind).or_insert(0) += 1;
        }
    }
    stats
}

fn percent(part: usize, whole: usize) -> String {
    // `whole` is never 0: `measure` rejects an empty corpus.
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

/// The metric lines, one `key: value` per line, stable and greppable.
///
/// # Errors
///
/// When a corpus cannot be read.
pub fn report(golden_dir: &Path) -> Result<Vec<String>, String> {
    // First: loading the must_not_allow fixtures sets a process environment
    // variable, which is only safe before the analysis watchdog spawns threads.
    let must_not_allow = measure_must_not_allow(golden_dir)?;
    let benign = measure(golden_dir, "benign_corpus")?;
    let denials = measure(golden_dir, "denials")?;
    let bypass = measure(golden_dir, "bypass_corpus")?;
    let mut lines = Vec::new();
    for (key, stats) in [("benign", &benign), ("denials", &denials)] {
        lines.push(format!(
            "{key}.over_ask_rate: {} ({}/{} Ask)",
            percent(stats.ask, stats.total),
            stats.ask,
            stats.total
        ));
        lines.push(format!(
            "{key}.not_allow_rate: {} ({}/{} not Allow: {} Ask, {} Block)",
            percent(stats.not_allow(), stats.total),
            stats.not_allow(),
            stats.total,
            stats.ask,
            stats.block
        ));
    }
    let mut total = 0;
    let mut command_counts = Vec::new();
    for (key, stats) in [
        ("benign", &benign),
        ("denials", &denials),
        ("bypass", &bypass),
    ] {
        total += stats.unknown_total();
        lines.push(format!("unknown.{key}.count: {}", stats.unknown_total()));
        for (kind, _) in KIND_NEEDLES {
            let count = stats.unknown_by_kind.get(kind).copied().unwrap_or(0);
            lines.push(format!("unknown.{key}.{kind}: {count}"));
            if kind == "command" {
                command_counts.push(format!("unknown_command_count.{key}: {count}"));
            }
        }
    }
    lines.push(format!("unknown.total: {total}"));
    lines.extend(command_counts);
    lines.push(format!(
        "bypass.allow_count: {} ({} rows)",
        bypass.allow, bypass.total
    ));
    lines.push(format!(
        "must_not_allow.allow_count: {} ({} rows)",
        must_not_allow.allow, must_not_allow.total
    ));
    Ok(lines)
}
