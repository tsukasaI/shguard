//! Composition root (`coding-guidelines/languages/rust.md`'s "binaries MUST
//! stay thin"): loads the user policy once (`shguard::config::Policy::load`),
//! reads Claude Code's PreToolUse stdin JSON, hands both to
//! [`shguard::adapter::handle_with_policy`], and writes the resulting
//! `hookSpecificOutput` JSON to stdout. All decision logic lives in the
//! library crate; this file only wires config -> stdin -> adapter -> stdout.
//!
//! Never panics: every fallible step (config load, stdin read, JSON
//! serialisation) is matched explicitly and falls back to the adapter's
//! fail-closed `ask` output rather than unwinding — a panic here would fail
//! *open*, since Claude Code proceeds unguarded when the hook produces no
//! decision.

use std::io::{self, Read, Write};

/// The fail-closed output written when even producing JSON fails — a
/// hand-written literal, not `serde_json`, so it cannot itself fail to
/// serialise.
const SERIALIZATION_FAILURE_OUTPUT: &str = concat!(
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","#,
    r#""permissionDecision":"ask","#,
    r#""permissionDecisionReason":"shguard: internal error serialising output"}}"#
);

fn main() {
    let mut args = std::env::args();
    let _binary_name = args.next();
    if args.next().as_deref() == Some("--version") {
        println!("shguard {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Config read once, at the composition root, before stdin — a broken
    // user config must fail closed before any command is ever evaluated,
    // not partway through.
    let policy = match shguard::config::Policy::load() {
        Ok(policy) => policy,
        Err(err) => {
            emit(shguard::adapter::fail_closed(&format!(
                "shguard: user config failed to load ({err}); refusing to evaluate any command \
                 until this is fixed"
            )));
            return;
        }
    };

    let mut stdin = String::new();
    let output = match io::stdin().read_to_string(&mut stdin) {
        Ok(_) => shguard::adapter::handle_with_policy(&stdin, &policy),
        Err(err) => shguard::adapter::fail_closed(&format!("shguard: could not read stdin: {err}")),
    };

    emit(output);
}

/// Serialises `output` and writes it to stdout, falling back to the
/// hand-written literal if serialisation itself fails. Best-effort: if
/// stdout is broken there is nothing further to report through this
/// channel, and this composition root never panics.
fn emit(output: serde_json::Value) {
    let json =
        serde_json::to_string(&output).unwrap_or_else(|_| SERIALIZATION_FAILURE_OUTPUT.to_string());
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "{json}");
}
