//! Composition root (`coding-guidelines/languages/rust.md`'s "binaries MUST
//! stay thin"): loads the user policy once (`shguard::config::Policy::load`),
//! reads Claude Code's PreToolUse stdin JSON, hands both to
//! [`shguard::adapter::handle_with_policy`], and writes the resulting
//! `hookSpecificOutput` JSON to stdout. All decision logic lives in the
//! library crate; this file only wires config -> stdin -> adapter -> stdout.
//!
//! Never panics *observably*: every fallible step (config load, stdin read,
//! JSON serialisation) is matched explicitly and falls back to the
//! adapter's fail-closed `ask` output rather than unwinding, and [`main`]
//! additionally wraps the whole composition, including writing the
//! decision to stdout ([`run_and_emit`]), in [`std::panic::catch_unwind`]
//! as a last-resort net for a panic reached through a path this file did
//! not anticipate (e.g. inside a dependency). A panic here would otherwise
//! fail *open* — Claude Code proceeds unguarded when the hook produces no
//! decision at all — so an uncaught unwind is exactly as bad as never
//! checking in the first place.
//!
//! # `catch_unwind` is not a stack-overflow guard
//!
//! [`std::panic::catch_unwind`] can only intercept an ordinary Rust panic
//! (unwinding). It **cannot** intercept a stack overflow — that aborts the
//! process immediately (`SIGABRT` / illegal instruction), bypassing unwind
//! machinery entirely. Issue #52's original abort (deeply nested
//! `{`/`(` input driving brush-parser's recursive-descent grammar past the
//! OS stack) is that failure mode, and [`run`]'s `catch_unwind` boundary
//! below does **not** defend against it — the fix for that is
//! `src/parser.rs`'s raw nesting pre-scan (`reject_excessive_raw_nesting`),
//! which runs *before* the recursive parser and rejects oversized input
//! outright. The two are complementary, not redundant: the pre-scan cannot
//! catch an ordinary panic from unrelated code (a dependency's `unwrap()`,
//! an arithmetic overflow in a debug build, …), and `catch_unwind` cannot
//! catch a stack overflow — both defenses are required, neither backs up
//! the other.
//!
//! # `panic = "abort"` MUST NOT be added to `Cargo.toml`
//!
//! Setting the `abort` panic strategy (crate- or profile-level) would turn
//! every ordinary panic into an immediate process abort, skipping unwind
//! machinery — silently disabling the `catch_unwind` boundary below and
//! reopening the exact fail-open gap it exists to close. Do not add it,
//! now or in the future, without re-deriving this whole section.

use std::io::{self, Read, Write};

/// The fail-closed output written when even producing JSON fails — a
/// hand-written literal, not `serde_json`, so it cannot itself fail to
/// serialise.
const SERIALIZATION_FAILURE_OUTPUT: &str = concat!(
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","#,
    r#""permissionDecision":"ask","#,
    r#""permissionDecisionReason":"shguard: internal error serialising output"}}"#
);

/// Hard cap, in bytes, on how much of Claude Code's PreToolUse stdin
/// [`run`] will read before refusing to evaluate the command at all (issue
/// #52, B-2). A real hook payload — including heredoc bodies — is at most a
/// few hundred KB; 10 MiB leaves three orders of magnitude of headroom
/// while still bounding memory use against an unbounded or hung stdin
/// producer. Counted in bytes, not characters: the cap exists to bound
/// memory/CPU cost, which scales with bytes read regardless of encoding.
const MAX_STDIN_BYTES: u64 = 10 * 1024 * 1024;

fn main() {
    let mut args = std::env::args();
    let _binary_name = args.next();
    if args.next().as_deref() == Some("--version") {
        println!("shguard {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    install_panic_hook();

    if std::panic::catch_unwind(run_and_emit).is_err() {
        emit(shguard::adapter::fail_closed(
            "shguard: internal panic while evaluating the command; refusing to evaluate \
             (fail-closed)",
        ));
    }
}

/// Installs a one-line panic hook in place of the Rust default (which
/// prints a multi-line message plus a "run with `RUST_BACKTRACE=1`"
/// pointer): this is a security hook whose stderr a human is not
/// necessarily watching, so a terse breadcrumb (not complete silence —
/// a panic here is still worth being able to find in logs) is more
/// appropriate than the default's verbosity. Installed once, in `main`,
/// before the [`run`] the `catch_unwind` boundary wraps.
///
/// `RUST_BACKTRACE` is still honoured — a set operator debugging a report
/// can opt into the full backtrace the same way they would for any other
/// Rust binary — but capturing one is skipped entirely when the variable
/// is unset (or `0`), matching the standard library's own hook: capture
/// has a real cost, and this runs on every panic path in a hook meant to
/// stay fast.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("shguard: internal panic: {info}");
        if backtrace_requested() {
            eprintln!("{}", std::backtrace::Backtrace::force_capture());
        }
    }));
}

/// Whether `RUST_BACKTRACE` requests a captured backtrace — any value
/// other than unset or `"0"`, matching the standard library's own panic
/// hook convention (`RUST_BACKTRACE=1`/`full` both count).
fn backtrace_requested() -> bool {
    match std::env::var_os("RUST_BACKTRACE") {
        None => false,
        Some(value) => value != "0",
    }
}

/// The composition root's actual work — config load, stdin read, hand-off
/// to the adapter — as a plain fn item, not a closure passed to
/// [`std::panic::catch_unwind`] in [`main`]. A closure that captures
/// surrounding state can fail `UnwindSafe`'s auto-trait check (typically
/// worked around with `AssertUnwindSafe`, which is exactly the kind of
/// "trust me" the type system is otherwise enforcing here); a capture-free
/// fn item holds no state at all, so it satisfies `UnwindSafe` on its own
/// and no such escape hatch is needed.
///
/// The `catch_unwind` boundary in `main` (via [`run_and_emit`]) covers
/// everything in here, including [`shguard::config::Policy::load`] — a
/// panic inside TOML parsing is exactly as fail-open as one anywhere else
/// in this function. The `--version` branch in `main` is deliberately
/// outside the boundary: it never touches config, stdin, or command
/// evaluation, so there is nothing there for the fail-closed guarantee to
/// protect.
fn run() -> serde_json::Value {
    // Test-only panic injection (issue #52): there is no currently-known
    // reachable panic in this binary to regression-test the `catch_unwind`
    // boundary against directly, and leaving "prevents fail-open on a
    // panic" untested is a bigger risk than a debug-only env-gated panic
    // hook. `assert_cmd` (used by `tests/hook_io.rs`) runs the debug
    // binary, so this is reachable from an integration test; `#[cfg(debug_assertions)]`
    // keeps it entirely absent from release builds.
    #[cfg(debug_assertions)]
    if std::env::var_os("SHGUARD_TEST_PANIC").is_some() {
        panic!("shguard: SHGUARD_TEST_PANIC injected panic (test-only)");
    }

    // Config read once, at the composition root, before stdin — a broken
    // user config must fail closed before any command is ever evaluated,
    // not partway through.
    let policy = match shguard::config::Policy::load() {
        Ok(policy) => policy,
        Err(err) => {
            return shguard::adapter::fail_closed(&format!(
                "shguard: user config failed to load ({err}); refusing to evaluate any command \
                 until this is fixed"
            ));
        }
    };

    // B-2 (issue #52): read at most `MAX_STDIN_BYTES + 1` bytes — one byte
    // *past* the cap, not the cap itself — so an oversized input can be
    // told apart from one that lands exactly at the boundary; `Take` alone
    // would silently truncate an oversized stream to exactly `n` bytes,
    // making it indistinguishable from legitimate input of that exact
    // size. `stdin.len()` after the read is the actual byte count actually
    // read; only `> MAX_STDIN_BYTES` (not `>=`) rejects, so input of
    // exactly the cap size is still accepted.
    let mut stdin = String::new();
    match io::stdin()
        .lock()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_string(&mut stdin)
    {
        Ok(_) if stdin.len() as u64 > MAX_STDIN_BYTES => shguard::adapter::fail_closed(&format!(
            "shguard: stdin exceeds {MAX_STDIN_BYTES} bytes; refusing to evaluate"
        )),
        Ok(_) => shguard::adapter::handle_with_policy(&stdin, &policy),
        // A read error also covers the case where the input is oversized
        // *and* its true length happens to break UTF-8 exactly at the
        // `MAX_STDIN_BYTES + 1`-byte boundary `take` reads up to:
        // `read_to_string` reports that as `InvalidData` rather than
        // `Ok`, and this arm fails closed the same as any other stdin
        // read error.
        Err(err) => shguard::adapter::fail_closed(&format!("shguard: could not read stdin: {err}")),
    }
}

/// `run` followed by `emit`, as one capture-free fn item so
/// [`std::panic::catch_unwind`] in `main` covers the write to stdout as
/// well as the decision logic — `emit` is written to never panic today,
/// but the boundary should not depend on that staying true. A panic
/// mid-write here (or anywhere in `run`) leaves nothing on stdout, exactly
/// like an unhandled panic anywhere else in this fail-closed composition;
/// `main` catches it and emits the fail-closed fallback itself.
fn run_and_emit() {
    emit(run());
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
