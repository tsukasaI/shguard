//! shguard: a parse-then-decide PreToolUse hook that blocks dangerous shell
//! commands for AI coding agents.
//!
//! Design: `plan.md` at the repository root. Implementation tracked in
//! GitHub issues (tsukasaI/shguard).

mod ast;
pub mod normalize;
mod parser;
pub mod verdict;

use verdict::{Reason, Verdict};

/// Analyzes a raw shell command line and returns the [`Verdict`] the hook
/// adapter should act on.
///
/// # Error posture
///
/// This function returns [`Verdict`], not `Result<Verdict, _>`. Every
/// failure mode internal to the pipeline — a parse error, an unrecognised
/// construct, anything the parse/normalise/rules/gate stages (plan.md §1.1)
/// cannot resolve statically — folds into a fail-closed `Ask` verdict
/// *inside* `analyze`, carrying a human-readable [`Reason`], rather than
/// propagating outward as an `Err` the caller has to remember to handle.
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
/// Currently a stub: the parse/normalise/rules/gate stages are not
/// implemented yet (tracked in later issues), so every call returns `Ask`
/// with reason "not implemented".
#[must_use]
pub fn analyze(command: &str) -> Verdict {
    let _ = command;
    Verdict::ask(Reason::new("not implemented"), Vec::new())
}
