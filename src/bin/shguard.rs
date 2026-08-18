//! Composition root (`coding-guidelines/languages/rust.md`'s "binaries MUST
//! stay thin"): loads the user policy once (`shguard::config::Policy::load`),
//! reads Claude Code's PreToolUse stdin JSON, hands both to
//! [`shguard::adapter::handle_with_policy`], and writes the resulting
//! `hookSpecificOutput` JSON to stdout. All decision logic lives in the
//! library crate; this file only wires config -> stdin -> adapter -> stdout.
//!
//! Never fails *silently* open: every fallible step (config load, stdin
//! read, JSON serialisation) is matched explicitly and falls back to the
//! adapter's fail-closed `ask` output rather than unwinding, [`main`] runs
//! the whole composition on a worker thread wrapped in
//! [`std::panic::catch_unwind`] as a last-resort net for a panic reached
//! through a path this file did not anticipate (e.g. inside a dependency),
//! and [`main`] additionally bounds that worker's wall-clock time (see
//! "The evaluation watchdog" below) so a pathological input that makes the
//! parser spin forever — instead of panicking or returning — still
//! produces a decision. A panic or a hang here would otherwise fail
//! *open* — Claude Code proceeds unguarded when the hook produces no
//! decision at all — so either is exactly as bad as never checking in the
//! first place.
//!
//! # The evaluation watchdog
//!
//! [`run`] executes on a dedicated worker thread ([`main`]) that sends its
//! result back over a channel; [`main`] blocks on that channel with a
//! bounded [`Receiver::recv_timeout`]. On timeout, `main` emits the
//! fail-closed decision itself and calls [`std::process::exit`] — the
//! runaway worker cannot be interrupted (Rust has no safe thread-cancel
//! primitive) and may still be spinning and allocating, so exiting the
//! whole process is the only way to actually stop it; leaving it running
//! detached would still eventually be reaped by the OS, but only after
//! however much memory or CPU it manages to consume in the meantime,
//! which is exactly the failure this defense exists to bound. `main` is
//! the *only* place that writes to stdout for exactly this reason: if the
//! worker happened to finish and try to emit its own decision at, say,
//! t=2.1s — just after `main`'s 2s timeout already fired — two JSON
//! decisions on stdout would corrupt Claude Code's hook protocol, which
//! expects exactly one. Splitting `run` (compute) from `emit` (the only
//! writer) makes that structurally impossible: the worker only ever sends
//! a value over the channel, it never touches stdout itself, and `main`
//! calls `emit` (via [`std::process::exit`], on the timeout path, or
//! after `recv_timeout` returns `Ok`) exactly once no matter which path
//! is taken.
//!
//! [`EVALUATION_TIMEOUT`]'s value and the measurements behind it live on
//! the constant itself.
//!
//! # `catch_unwind` is not a stack-overflow guard
//!
//! [`std::panic::catch_unwind`] can only intercept an ordinary Rust panic
//! (unwinding). It **cannot** intercept a stack overflow — that aborts the
//! process immediately (`SIGABRT` / illegal instruction), bypassing unwind
//! machinery entirely. Issue #52's original abort (deeply nested
//! `{`/`(` input driving brush-parser's recursive-descent grammar past the
//! OS stack) is that failure mode, and [`main`]'s `catch_unwind` boundary
//! does **not** defend against it — the fix for that is
//! `src/parser.rs`'s raw nesting pre-scan (`reject_excessive_raw_nesting`),
//! which runs *before* the recursive parser and rejects oversized input
//! outright. The two are complementary, not redundant: the pre-scan cannot
//! catch an ordinary panic from unrelated code (a dependency's `unwrap()`,
//! an arithmetic overflow in a debug build, …), and `catch_unwind` cannot
//! catch a stack overflow — both defenses are required, neither backs up
//! the other. Nor is the watchdog a substitute for either: a stack
//! overflow aborts before the timeout could ever fire.
//!
//! # `panic = "abort"` MUST NOT be added to `Cargo.toml`
//!
//! Setting the `abort` panic strategy (crate- or profile-level) would turn
//! every ordinary panic into an immediate process abort, skipping unwind
//! machinery — silently disabling the `catch_unwind` boundary below and
//! reopening the exact fail-open gap it exists to close. Do not add it,
//! now or in the future, without re-deriving this whole section.

use std::io::{self, Read, Write};
use std::sync::mpsc::Receiver;
use std::time::Duration;

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

/// Wall-clock budget given to one [`run`] before [`main`] gives up on it
/// and fails closed (crash-fuzzer finding: a heredoc operator whose
/// delimiter-word parsing recurses into an unterminated `$(...)` drives
/// brush-parser's tokenizer into an unbounded allocating loop — no panic,
/// no return, ~670 MB/s until the OS kills the process). 2s is ~200x the
/// measured p100 of every non-pathological input tried against this
/// pipeline (20k-stage pipelines, 200KB words, 20k heredocs all resolved
/// in <=0.25s), so it costs nothing on real hook traffic while still
/// bounding a hang to a small, fixed delay instead of unbounded memory
/// growth. Re-measure the p100 figure above before lowering this.
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    let mut args = std::env::args();
    let _binary_name = args.next();
    if args.next().as_deref() == Some("--version") {
        println!("shguard {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    install_panic_hook();

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("shguard-eval".to_string())
        .spawn(move || {
            let output = std::panic::catch_unwind(run).unwrap_or_else(|_| {
                shguard::adapter::fail_closed(
                    "shguard: internal panic while evaluating the command; refusing to \
                     evaluate (fail-closed)",
                )
            });
            // A closed receiver means `main` already timed out and moved
            // on (see below) — nothing left to send to.
            let _ = result_tx.send(output);
        });

    let Ok(worker) = worker else {
        // Thread spawn failure (e.g. the OS is out of resources) is itself
        // a reason to fail closed, not to fall through and evaluate on the
        // main thread — that would silently drop the watchdog this whole
        // boundary exists to provide.
        emit(shguard::adapter::fail_closed(
            "shguard: could not start command evaluation; refusing to evaluate (fail-closed)",
        ));
        return;
    };

    emit_first_result(&result_rx);
    // The worker already sent (or the process is about to exit on the
    // timeout path, in which case this line is never reached) — join to
    // avoid leaving a detached thread dangling off a still-running `main`.
    let _ = worker.join();
}

/// Waits up to [`EVALUATION_TIMEOUT`] for `rx` to produce a result and
/// emits it. On timeout, emits the fail-closed decision itself and exits
/// the process immediately — see the module docs' "evaluation watchdog"
/// section for why exiting, not merely returning, is required.
fn emit_first_result(rx: &Receiver<serde_json::Value>) {
    match rx.recv_timeout(EVALUATION_TIMEOUT) {
        Ok(output) => emit(output),
        Err(_) => {
            emit(shguard::adapter::fail_closed(
                "shguard: evaluation exceeded its time budget; refusing to evaluate \
                 (fail-closed)",
            ));
            std::process::exit(0);
        }
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
///
/// Writes via `writeln!` (which returns a `Result` this hook discards), not
/// `eprintln!` (which panics on a write failure): this hook itself runs
/// while `main`'s `catch_unwind` boundary is already unwinding, and a panic
/// here — e.g. from a broken stderr pipe (`EPIPE`), which Claude Code's
/// process tree can produce — would panic *during* a panic, which Rust
/// resolves by aborting the process immediately, bypassing `catch_unwind`
/// entirely and reopening the exact fail-open gap this whole boundary
/// exists to close (live-confirmed: an injected panic with stderr's read
/// end closed before the write aborts with empty stdout under `eprintln!`,
/// and correctly falls back to `ask` once the write error is discarded
/// instead).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(io::stderr(), "shguard: internal panic: {info}");
        if backtrace_requested() {
            let _ = writeln!(
                io::stderr(),
                "{}",
                std::backtrace::Backtrace::force_capture()
            );
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
/// The `catch_unwind` boundary in `main` covers everything in here,
/// including [`shguard::config::Policy::load`] — a panic inside TOML
/// parsing is exactly as fail-open as one anywhere else in this function.
/// So does the watchdog timeout: `run` executes entirely on the worker
/// thread `main` spawns, so a hang anywhere in here (stdin read, config
/// load, or command evaluation) is bounded by [`EVALUATION_TIMEOUT`] the
/// same way. The `--version` branch in `main` is deliberately outside
/// both boundaries: it never touches config, stdin, or command
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
