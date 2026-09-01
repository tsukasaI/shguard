//! shguard: a parse-then-decide PreToolUse hook that blocks dangerous shell
//! commands for AI coding agents.
//!
//! Design: `plan.md` at the repository root. Implementation tracked in
//! GitHub issues (tsukasaI/shguard).

pub mod adapter;
mod ast;
pub mod config;
mod decision_log;
mod gate;
pub mod normalize;
mod parser;
mod rules;
pub mod verdict;
mod watchdog;

use std::path::Path;

pub use decision_log::FileDecisionLog;
use verdict::Verdict;

/// Port [`analyze_with_policy`] appends one JSONL decision-log line
/// through, per issue #108 (`coding-guidelines/principles.md`: "ports MUST
/// be defined next to the code that consumes them" — this is that code).
/// [`FileDecisionLog`] (`src/decision_log.rs`) is the only implementation
/// today; the composition root (`src/bin/shguard.rs`) constructs it and
/// passes it in, so this module never names a concrete filesystem writer
/// itself (`coding-guidelines/principles.md`, "composition root": "code
/// outside the composition root MUST NOT know which concrete adapter it is
/// using").
pub trait DecisionLogSink {
    /// Appends one line describing `verdict` for `command` to `path`. See
    /// [`FileDecisionLog`]'s docs for the concrete format and fail-open
    /// posture.
    fn append(&self, path: &Path, command: &str, verdict: &Verdict);
}

/// Analyzes a raw shell command line and returns the [`Verdict`] the hook
/// adapter should act on.
///
/// # Error posture
///
/// This function returns [`Verdict`], not `Result<Verdict, _>`. Every
/// failure mode internal to the pipeline — a parse error, an unrecognised
/// construct, anything the parse/normalise/rules/gate stages (plan.md §1.1)
/// cannot resolve statically — folds into a fail-closed `Ask` verdict
/// *inside* `analyze`, carrying a human-readable [`verdict::Reason`], rather
/// than propagating outward as an `Err` the caller has to remember to
/// handle.
///
/// Why: the hook adapter (`src/bin/shguard.rs`) sits on Claude Code's
/// PreToolUse stdin→stdout contract (plan.md §0.2) and must satisfy two
/// constraints at once — never crash (a panic there fails *open*, since the
/// tool call proceeds unguarded when the hook produces no decision) and
/// never silently allow (mapping an unhandled `Err` to `Allow` anywhere in
/// the adapter would be the same failure in the opposite direction).
/// Returning `Verdict` unconditionally, with every internal failure folded
/// to `Ask` at this one point, means there is exactly one place that has to
/// get the fail-closed mapping right (plan.md §1.2's "single fold point"),
/// and the adapter's job becomes trivial and impossible to get wrong: call
/// `analyze`, always get a `Verdict`, always emit a `permissionDecision`.
///
/// The pipeline itself — parse (`src/parser.rs`) → normalise
/// (`src/normalize.rs`) → rules (`src/rules.rs`) → structural gate
/// (`src/gate.rs`) → worst-decision-wins fold — is composed in
/// [`gate::analyze`]; see that module's docs for the full Block/Ask/Allow
/// rule set.
///
/// # Bounded evaluation (issue #319)
///
/// Runs on its own thread, bounded by wall-clock time everywhere and, on
/// Linux/macOS, memory growth too (`src/watchdog.rs`; other platforms have
/// no RSS-reading implementation there yet and rely on the wall-clock
/// bound alone) — a pathological input that would otherwise hang or grow
/// memory unboundedly (crash-fuzzer finding #315) instead makes this
/// call itself return a fail-closed `Ask` within a couple of seconds. This
/// is a real, documented limitation, not a full guarantee: a trip leaves
/// the runaway worker thread detached rather than terminating it (Rust has
/// no safe thread-cancel primitive), so for a non-terminating input like
/// #315's, that thread keeps allocating in the background afterward and
/// the host process can still run out of memory eventually — just later,
/// and outside this call, rather than during it. See `src/watchdog.rs`'s
/// module docs for the full reasoning. A caller evaluating untrusted or
/// adversarial input, where the difference between "delayed" and
/// "prevented" matters, should run this behind a subprocess instead, so
/// the runaway dies with it.
#[must_use]
pub fn analyze(command: &str) -> Verdict {
    let command = command.to_string();
    watchdog::bounded(move || gate::analyze(&command))
}

/// Config-aware sibling of [`analyze`]: same pipeline, the same
/// error/fail-closed posture, and the same bounded-evaluation guarantee
/// (see [`analyze`]'s "Bounded evaluation" section), but `policy` (loaded
/// once at the composition root via [`config::Policy::load`]) supplies the
/// rules and allowlist instead of the embedded defaults alone. [`analyze`]'s
/// own behavior and signature are untouched — this is an additional entry
/// point, not a replacement.
///
/// # Structured decision-output logging (issue #108)
///
/// When `policy` carries a `decision_log_path` (set via the user config's
/// `decision_log_path` key, off by default), one JSONL line describing the
/// resulting verdict is appended to that path via `sink` (see
/// [`DecisionLogSink`]) — the composition root (`src/bin/shguard.rs`)
/// constructs the concrete [`FileDecisionLog`] and passes it to both the
/// real hook path (`src/adapter.rs`) and the `shguard check` CLI (issue
/// #109), so a logged line can never diverge from what either caller
/// actually saw, and it logs the verdict [`watchdog::bounded`] actually
/// returned — including its own fail-closed `Ask` on a timeout — never a
/// verdict a detached, still-running worker computed after the fact.
///
/// The write happens AFTER [`watchdog::bounded`] returns, deliberately
/// outside *this* wall-clock bound: logging inside the bounded closure was
/// tried first and rejected — a log target that blocks (a FIFO with no
/// reader, a hung network mount) would trip the watchdog's timeout and
/// silently replace an already-computed, correct `Allow`/`Ask`/`Block`
/// with a fail-closed `Ask`, corrupting the real decision to paper over a
/// logging-only problem. [`config::Policy::load`] rejects any
/// `decision_log_path` that already names a FIFO/device/socket/directory
/// at load time (`src/config.rs`), closing the detectable case.
///
/// This module-level bound is not the only watchdog a caller may sit
/// behind, though: `src/bin/shguard.rs`'s PreToolUse hook path (`run`) also
/// wraps this ENTIRE call — decision plus log write — in its own, separate
/// `EVALUATION_TIMEOUT` watchdog, since `run` itself must never hang
/// regardless of where the hang comes from. A log target that starts
/// blocking only *after* config load (a network mount that hangs
/// mid-session, not a FIFO caught at load time) can therefore still trip
/// that OUTER watchdog and yield the same fail-closed-`Ask`-instead-of-the-
/// real-decision outcome for a hook invocation specifically — a residual,
/// disclosed risk (see the README), not one this function's own bound can
/// close, since it has no visibility into whatever bound a caller wraps it
/// in. `shguard check` (issue #109) wraps this whole call in the same
/// `EVALUATION_TIMEOUT` bound for the same reason (`src/bin/shguard.rs`'s
/// `evaluate_with_timeout`); a direct library caller has no such outer
/// watchdog of its own, so for one this function's own bound is the whole
/// story.
#[must_use]
pub fn analyze_with_policy(
    command: &str,
    policy: &config::Policy,
    sink: &dyn DecisionLogSink,
) -> Verdict {
    let command_owned = command.to_string();
    let policy_owned = policy.clone();
    let verdict = watchdog::bounded(move || {
        gate::analyze_with_policy(&command_owned, &policy_owned.rules, &policy_owned.allowlist)
    });
    if let Some(path) = &policy.decision_log_path {
        sink.append(path, command, &verdict);
    }
    verdict
}
