//! shguard: a parse-then-decide PreToolUse hook that blocks dangerous shell
//! commands for AI coding agents.
//!
//! Design: `plan.md` at the repository root. Implementation tracked in
//! GitHub issues (tsukasaI/shguard).

pub mod adapter;
mod ast;
pub mod config;
mod gate;
pub mod normalize;
mod parser;
mod rules;
pub mod verdict;
mod watchdog;

use verdict::Verdict;

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
/// Runs on its own thread, bounded by wall-clock time and memory growth
/// (`src/watchdog.rs`) — a pathological input that would otherwise hang or
/// grow memory unboundedly (crash-fuzzer finding #315) instead makes this
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
#[must_use]
pub fn analyze_with_policy(command: &str, policy: &config::Policy) -> Verdict {
    let command = command.to_string();
    let policy = policy.clone();
    watchdog::bounded(move || gate::analyze_with_policy(&command, &policy.rules, &policy.allowlist))
}
