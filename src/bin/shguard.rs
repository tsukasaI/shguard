//! Composition root (`coding-guidelines/languages/rust.md`'s "binaries MUST
//! stay thin"): loads the user policy once (`shguard::config::Policy::load`),
//! reads Claude Code's PreToolUse stdin JSON, hands both to
//! [`shguard::adapter::handle_with_policy`], and writes the resulting
//! `hookSpecificOutput` JSON to stdout. All decision logic lives in the
//! library crate; this file only wires config -> stdin -> adapter -> stdout.
//!
//! Never fails *silently* open: every fallible step (config load, stdin
//! read, JSON serialisation) is matched explicitly and falls back to the
//! adapter's fail-closed `ask` output (or `deny`, for a config-load
//! failure under `SHGUARD_STRICT_CONFIG` — see [`strict_config_requested`])
//! rather than unwinding, [`main`] runs
//! the whole composition on a worker thread wrapped in
//! [`std::panic::catch_unwind`] as a last-resort net for a panic reached
//! through a path this file did not anticipate (e.g. inside a dependency),
//! and [`main`] additionally bounds that worker's wall-clock time *and*
//! its memory use (see "The evaluation watchdog" below) so a pathological
//! input that makes the parser spin forever — instead of panicking or
//! returning — still produces a decision. A panic or a hang here would
//! otherwise fail *open* — Claude Code proceeds unguarded when the hook
//! produces no decision at all — so either is exactly as bad as never
//! checking in the first place.
//!
//! # The evaluation watchdog
//!
//! [`run`] executes on a dedicated worker thread ([`main`]) that sends its
//! result back over a channel; [`main`] waits on that channel in a polling
//! loop ([`resolve_first_result`]), each iteration bounded by
//! [`MEMORY_POLL_INTERVAL`] (or whatever's left of [`EVALUATION_TIMEOUT`],
//! if shorter) so it can check the worker's actual memory use between
//! polls without giving up wall-clock bounding. A trip on *either* bound —
//! [`EVALUATION_TIMEOUT`] elapses, or RSS crosses [`MEMORY_LIMIT_BYTES`] —
//! checks the channel one last time (non-blocking) in case the worker's
//! real result is already there, then, only if it isn't, makes `main`
//! (via [`emit_first_result`]) emit the fail-closed decision itself and
//! call [`std::process::exit`] — the runaway worker cannot be interrupted
//! (Rust has no safe thread-cancel primitive) and may still be spinning
//! and allocating, so exiting the whole process is the only way to
//! actually stop it; leaving it running detached would still eventually
//! be reaped by the OS, but only after however much memory or CPU it
//! manages to consume in the meantime, which is exactly the failure this
//! defense exists to bound. The memory bound exists because the
//! wall-clock bound alone is not sufficient: a host or container with
//! less free memory than the runaway worker can allocate within
//! [`EVALUATION_TIMEOUT`] gets SIGKILLed by the OS before `recv_timeout`
//! ever returns — empty stdout, the exact fail-open condition this whole
//! watchdog exists to close. `main` is the *only* place that writes to
//! stdout for exactly this reason: if the worker happened to finish and
//! try to emit its own decision at, say, t=2.1s — just after `main`'s 2s
//! timeout already fired — two JSON decisions on stdout would corrupt
//! Claude Code's hook protocol, which expects exactly one. Splitting
//! `run` (compute) from `emit` (the only writer) makes that structurally
//! impossible: the worker only ever sends a value over the channel, it
//! never touches stdout itself, and `main` calls `emit` (via
//! [`std::process::exit`] on a timeout or memory-trip path with nothing
//! left in the channel, or with the worker's own result — found either by
//! the normal `recv_timeout` or by one of the trip arms' last-chance
//! `try_recv`) exactly once no matter which path is taken.
//!
//! [`EVALUATION_TIMEOUT`]'s value and the measurements behind it, and
//! [`MEMORY_LIMIT_BYTES`]'s value and the measurements behind it, live on
//! the respective constants themselves.
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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use shguard::DecisionLogSink;

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
/// no return, ~4 GB/s sustained (measured release build) until the OS
/// kills the process). 2s is ~8x the measured p100 of every
/// non-pathological input tried against this pipeline (20k-stage
/// pipelines, 200KB words, 20k heredocs all resolved in <=0.25s), so it
/// costs nothing on real hook traffic while still bounding a hang to a
/// small, fixed delay instead of unbounded memory growth. Re-measure the
/// p100 figure above before lowering this.
///
/// This bound alone is not sufficient on a memory-constrained host: at
/// ~4 GB/s, a container or box with less than ~8 GB free can be
/// SIGKILLed by the OS before this timeout ever fires — see
/// [`MEMORY_LIMIT_BYTES`] for the complementary bound that closes that
/// gap.
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(2);

/// How often [`resolve_first_result`]'s watchdog polls the worker's actual
/// memory use (via [`current_rss_bytes`]) while waiting on the result
/// channel, instead of blocking on a single [`EVALUATION_TIMEOUT`]-long
/// `recv_timeout` the way the wall-clock-only watchdog used to. Short
/// enough that the runaway-allocation repro (~4 GB/s, see
/// [`EVALUATION_TIMEOUT`]) overshoots [`MEMORY_LIMIT_BYTES`] by at most
/// ~200 MB (rate * interval) before a poll catches it; long enough that
/// polling `getrusage` costs nothing against real hook traffic, which
/// resolves in well under one interval to begin with.
const MEMORY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Hard RSS budget for the whole process, polled by [`resolve_first_result`]
/// independently of [`EVALUATION_TIMEOUT`] (follow-up to the wall-clock
/// watchdog above: the same unbounded-allocating-loop input peaks at
/// several GB RSS well within the 2s wall-clock budget, so a host or
/// container with less free memory than that gets SIGKILLed by the OS
/// before `recv_timeout` ever fires — empty stdout, the exact fail-open
/// condition the wall-clock watchdog alone does not close). 256 MiB is
/// ~10x the largest peak RSS measured for a legitimate, non-pathological
/// fixture against this pipeline (24 MB, a 20k-stage/200KB-word command),
/// and even with [`MEMORY_POLL_INTERVAL`]'s worst-case ~200 MB overshoot
/// stays comfortably under what a small container typically allots a
/// single process. There is no other documented memory budget for this
/// project to anchor against (checked README.md and docs/ before picking
/// this number). Re-measure both figures above before changing this.
const MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;

/// The command and context [`run`] sends over a dedicated channel
/// immediately after it parses the hook stdin's Bash command — before
/// handing that command to `analyze_with_policy`, which is the call that
/// can actually hang (issue #459). Lets [`emit_first_result`]'s watchdog
/// trip arms attribute a fail-closed decision to the decision log even
/// though the worker that would otherwise have logged it never gets to.
struct EarlyInfo {
    decision_log_path: Option<PathBuf>,
    command: String,
    context: shguard::HookContext,
}

/// Bound on [`log_trip_best_effort`]'s own append call, and on how long it
/// waits for a worker that got there first (see [`LogState`]) to finish its
/// own write. `decision_log_path` is validated at config-load time to be a
/// regular local file (`src/config.rs`), so a normal append finishes in low
/// single-digit milliseconds; this only matters for the one residual,
/// disclosed risk `src/lib.rs`'s own docs already carry — a target that
/// starts blocking only after that check (e.g. a network mount gone stale
/// mid-session). Reuses [`MEMORY_POLL_INTERVAL`] rather than a larger value
/// of its own: on the `MemoryTrip` arm specifically, the abandoned worker
/// may still be allocating at the multi-GB/s rate [`EVALUATION_TIMEOUT`]'s
/// own docs describe, so this bound doubles as the RSS overshoot this whole
/// watchdog already tolerates from one extra poll interval — a longer
/// bound here would let a hostile log target buy the runaway worker
/// meaningfully more headroom on exactly the memory-constrained host this
/// arm exists to protect.
const TRIP_LOG_TIMEOUT: Duration = MEMORY_POLL_INTERVAL;

/// [`LogState`]'s "nobody has touched the decision log for this invocation
/// yet" value — the only state [`AtomicU8::new`] is ever constructed with.
const LOG_UNCLAIMED: u8 = 0;
/// [`LogState`]'s "the worker's own [`DedupSink::append`] is writing (or
/// about to)" value.
const LOG_WORKER: u8 = 1;
/// [`LogState`]'s "the worker's own write finished" value.
const LOG_DONE: u8 = 2;
/// [`LogState`]'s "[`emit_first_result`]'s trip arm claimed the log for
/// itself" value.
const LOG_MAIN: u8 = 3;

/// Shared between [`DedupSink`] (on the worker thread) and
/// [`log_trip_best_effort`] (on `main`) so at most one decision-log line is
/// ever written for a single hook invocation, and — unlike a plain
/// swap-and-race flag — so the *fail-closed decision `main` is about to
/// emit to stdout* always wins ownership of the log the instant a trip
/// fires, rather than whichever side's write happens to finish first
/// (issue #459 follow-up): the `MemoryTrip` arm's outer (this binary's) and
/// inner (`analyze_with_policy`'s own `watchdog::bounded`) watchdogs poll
/// RSS on independent, phase-shifted [`MEMORY_POLL_INTERVAL`] cycles, so
/// either can cross its own threshold first. A plain "first `swap` wins"
/// flag lets the *worker* win that race after `main` has already decided
/// and emitted a *different* fail-closed reason to stdout — a duplicate at
/// best, a decision-log entry that names a reason nobody ever saw at
/// worst. `main`'s trip arm instead claims [`LOG_MAIN`] unconditionally,
/// as the very first thing it does — before `emit`, before formatting
/// anything — so the only way the worker's `DedupSink::append` still wins
/// is if it claimed [`LOG_WORKER`] microseconds earlier, in which case
/// [`log_trip_best_effort`] waits (bounded by [`TRIP_LOG_TIMEOUT`]) for it
/// to reach [`LOG_DONE`] rather than writing a second, conflicting line.
type LogState = AtomicU8;

/// Wraps [`shguard::FileDecisionLog`] so its write only happens if no trip
/// has claimed [`LOG_MAIN`] first — see [`LogState`]'s own docs for why
/// this direction (main taking priority) is the one that keeps the log
/// consistent with what stdout actually emitted.
struct DedupSink {
    state: Arc<LogState>,
}

impl shguard::DecisionLogSink for DedupSink {
    fn append(
        &self,
        path: &std::path::Path,
        command: &str,
        verdict: &shguard::verdict::Verdict,
        context: &shguard::HookContext,
    ) {
        if self
            .state
            .compare_exchange(
                LOG_UNCLAIMED,
                LOG_WORKER,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            shguard::FileDecisionLog.append(path, command, verdict, context);
            self.state.store(LOG_DONE, Ordering::SeqCst);
        }
    }
}

fn main() {
    // `args_os`, not `args`: the latter panics outright on a non-UTF-8
    // argument, which would turn a malformed-but-harmless human typo (this
    // whole block only ever runs for a human invocation — see below) into
    // an uncaught panic before `install_panic_hook`/`catch_unwind` are even
    // reachable. `to_str()` below folds a non-UTF-8 first argument to
    // `None`, which the catch-all arm treats the same as any other
    // unrecognized argument.
    let mut args = std::env::args_os();
    let _binary_name = args.next();
    let first_arg = args.next();
    let extra_arg = args.next();
    match first_arg.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("--version") if extra_arg.is_none() => {
            let _ = writeln!(io::stdout(), "shguard {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("--check-config") if extra_arg.is_none() => {
            std::process::exit(check_config());
        }
        // `check` takes a variable number of its own arguments (the command
        // string plus optional `--json`/`--permission-mode <mode>` flags),
        // unlike `--version`/`--check-config` above which take none — so it
        // can't reuse the fixed two-arg peek those use. `extra_arg` already
        // consumed the first token after "check" (if any); reassemble it
        // with the rest of the iterator so `run_check` sees the complete
        // argument list.
        Some("check") => {
            let mut check_args: Vec<std::ffi::OsString> = Vec::new();
            check_args.extend(extra_arg);
            check_args.extend(args);
            std::process::exit(run_check(&check_args));
        }
        // `init` takes only its own optional `--force` — same variable-
        // arity reassembly `check` above needs, so a stray extra argument
        // (not just `--force`) is reported precisely rather than silently
        // ignored or misrouted to hook mode.
        Some("init") => {
            let mut init_args: Vec<std::ffi::OsString> = Vec::new();
            init_args.extend(extra_arg);
            init_args.extend(args);
            std::process::exit(run_init(&init_args));
        }
        // The PreToolUse hook contract never passes shguard any arguments
        // at all (Claude Code invokes it bare, feeding the payload via
        // stdin) — `first_arg` is `None` on every real hook invocation, so
        // this arm (guarded on `first_arg.is_some()`) can never reject real
        // hook traffic, only a human's mistake: an unrecognized flag, a
        // non-flag positional, a trailing argument after a recognized
        // flag, or a non-UTF-8 argument, all of which would otherwise
        // silently fall through to hook mode below and block on stdin
        // instead of reporting the mistake. An invalid flag/argument is an
        // error, never a silent no-op — the worst failure mode a checking
        // tool can have is a typo that skips the check and exits 0 anyway.
        _ if first_arg.is_some() => {
            let rest: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
            let _ = writeln!(
                io::stderr(),
                "shguard: unrecognized arguments {rest:?} (known commands: --version, \
                 --check-config (neither taking further arguments), check <command> \
                 [--json] [--permission-mode <mode>], init [--force])"
            );
            std::process::exit(2);
        }
        _ => {}
    }

    install_panic_hook();

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let (early_tx, early_rx) = std::sync::mpsc::channel();
    // Shared with `DedupSink` (built inside `run`, on the worker thread) so
    // a watchdog trip's `log_trip_best_effort` and the worker's own
    // ordinary logging can never both write for the same invocation — see
    // `LogState`'s own docs for why a trip claims this ahead of the
    // worker, not merely before it.
    let log_state = Arc::new(LogState::new(LOG_UNCLAIMED));
    let worker_log_state = log_state.clone();
    let worker = std::thread::Builder::new()
        .name("shguard-eval".to_string())
        .spawn(move || {
            let output = std::panic::catch_unwind(move || run(&early_tx, worker_log_state))
                .unwrap_or_else(|_| {
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

    emit_first_result(&result_rx, &early_rx, &log_state);
    // The worker already sent (or the process is about to exit on a
    // watchdog-trip path — time, memory, or disconnect — in which case
    // this line is never reached) — join to avoid leaving a detached
    // thread dangling off a still-running `main`.
    let _ = worker.join();
}

/// What [`resolve_first_result`] found: either the worker's own result, or
/// a reason one of the fail-closed trips fired. Splitting the decision
/// (pure, no I/O) from emitting it and exiting the process lets
/// `resolve_first_result` be unit-tested directly — including the
/// try-the-channel-first race below — without a test ever calling
/// [`std::process::exit`] on itself.
#[derive(Debug)]
enum FirstResult {
    Output(serde_json::Value),
    MemoryTrip(String),
    TimeTrip(String),
    Disconnected(String),
}

/// Waits up to `timeout` for `rx` to produce a result, polling the
/// worker's RSS against `memory_limit` every [`MEMORY_POLL_INTERVAL`]
/// while it waits, and resolves to whichever happens first: the worker's
/// real result, a wall-clock trip, or a memory trip. The RSS check runs
/// at the *start* of each loop iteration — including the very first,
/// before ever waiting on `rx` — so a worker that has already blown the
/// memory budget by the time `main` gets here (rather than only sometime
/// while `main` is waiting) is still caught immediately rather than after
/// an extra poll interval.
///
/// Both trip arms — memory and wall-clock — check `rx` one last time
/// (`try_recv`, non-blocking) before resolving to a fail-closed trip:
/// mirrors `src/watchdog.rs::bounded_with_memory_limit`'s own
/// try-the-channel-first check (see that function's docs for the full
/// race). The worker may have already sent its real result in the gap
/// between the last poll and this one tripping — preferring that result
/// over discarding it means a verdict computed just before the deadline,
/// `Block` included, is no longer discarded except in the sub-millisecond
/// window between this `try_recv` and the process actually exiting
/// (inherent: closing that last sliver would mean blocking on the exact
/// hang this watchdog exists to bound).
fn resolve_first_result(
    rx: &Receiver<serde_json::Value>,
    memory_limit: u64,
    timeout: Duration,
) -> FirstResult {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(rss) = current_rss_bytes()
            && rss > memory_limit
        {
            if let Ok(output) = rx.try_recv() {
                return FirstResult::Output(output);
            }
            return FirstResult::MemoryTrip(format!(
                "shguard: evaluation exceeded its memory budget ({rss} bytes RSS); \
                 refusing to evaluate (fail-closed)"
            ));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if let Ok(output) = rx.try_recv() {
                return FirstResult::Output(output);
            }
            return FirstResult::TimeTrip(
                "shguard: evaluation exceeded its time budget; refusing to evaluate \
                 (fail-closed)"
                    .to_string(),
            );
        }

        match rx.recv_timeout(remaining.min(MEMORY_POLL_INTERVAL)) {
            Ok(output) => return FirstResult::Output(output),
            // Not yet past `deadline` (checked above) — loop around to
            // re-sample RSS before waiting again.
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return FirstResult::Disconnected(
                    "shguard: evaluation worker stopped without producing a result; \
                     refusing to evaluate (fail-closed)"
                        .to_string(),
                );
            }
        }
    }
}

/// The only caller of [`resolve_first_result`], invoked from [`main`]: applies
/// [`MEMORY_LIMIT_BYTES`] (or its debug-only test override) and
/// [`EVALUATION_TIMEOUT`], then emits whatever it resolved to. On either
/// trip (or a worker disconnect), emits the fail-closed decision, makes a
/// best-effort attempt to log it ([`log_trip_best_effort`], bounded by
/// [`TRIP_LOG_TIMEOUT`]), and only then exits the process — see the module
/// docs' "evaluation watchdog" section for why exiting, not merely
/// returning, is required.
fn emit_first_result(
    rx: &Receiver<serde_json::Value>,
    early_rx: &Receiver<EarlyInfo>,
    log_state: &LogState,
) {
    match resolve_first_result(rx, memory_limit_bytes(), EVALUATION_TIMEOUT) {
        FirstResult::Output(output) => emit(output),
        FirstResult::MemoryTrip(reason)
        | FirstResult::TimeTrip(reason)
        | FirstResult::Disconnected(reason) => {
            // Claimed before anything else in this arm, including `emit`
            // below — see `LogState`'s own docs for why the decision this
            // arm is about to emit must win ownership of the log ahead of
            // the worker's own, possibly different, in-flight write.
            let prior_state = log_state.swap(LOG_MAIN, Ordering::SeqCst);
            emit(shguard::adapter::fail_closed(&reason));
            // Emitted to stdout first, deliberately: the decision Claude
            // Code actually waits on must never be delayed by this
            // best-effort log write (see `log_trip_best_effort`'s own
            // docs for its bound).
            log_trip_best_effort(early_rx.try_recv().ok(), &reason, prior_state, log_state);
            std::process::exit(0);
        }
    }
}

/// Bounded, best-effort attempt to record a watchdog-trip decision in the
/// user's `decision_log_path` (issue #459) — every genuine hang the
/// PreToolUse hook's outer watchdog exists to bound previously left no
/// trace in the decision log at all, because the worker that would have
/// logged it (`crate::analyze_with_policy`'s own `sink.append` call,
/// `src/lib.rs`) is abandoned mid-evaluation and never reaches that call
/// before [`std::process::exit`] tears the whole process down.
///
/// `prior_state` is whatever [`LogState`] held immediately before
/// [`emit_first_result`] claimed [`LOG_MAIN`] — the outcome of that race
/// against the worker's own [`DedupSink::append`], already decided by the
/// time this function runs:
/// - [`LOG_WORKER`]: the worker claimed the log microseconds earlier and is
///   writing (or about to). Rather than writing a second, conflicting
///   line, this waits (bounded by [`TRIP_LOG_TIMEOUT`]) for it to reach
///   [`LOG_DONE`] and returns without writing anything itself — the one
///   remaining case where the logged reason can be the worker's own,
///   racing one rather than the reason this trip emitted to stdout, a tie
///   of the same class `resolve_first_result`'s own try-the-channel-first
///   race already accepts elsewhere in this file. If the worker doesn't
///   finish within the bound either, this invocation goes entirely
///   unlogged rather than risking a torn or duplicate write.
/// - [`LOG_DONE`]: the worker already finished; nothing left to do.
/// - [`LOG_UNCLAIMED`]: this trip arm won outright — falls through to
///   perform the write itself, below.
///
/// `early_info` is `None` when [`run`] never got as far as sending one — a
/// hang during config load or the stdin read itself, before there is any
/// command to attribute a trip to; this is a no-op in that case, same as
/// when the resolved policy has no `decision_log_path` configured at all.
///
/// Runs the actual [`shguard::DecisionLogSink::append`] call on its own
/// thread, bounded by [`TRIP_LOG_TIMEOUT`], rather than inline: an append
/// itself doing the hanging (the one residual, disclosed risk `src/lib.rs`'s
/// docs already carry for the ordinary, non-trip logging path — a network
/// mount gone stale mid-session) must not turn this best-effort log write
/// into a second hang on top of the one this watchdog already exists to
/// bound. If the write doesn't finish within the bound, it is simply
/// abandoned: `main` calls [`std::process::exit`] right after this returns
/// regardless, which tears down the spawned thread along with everything
/// else on any target where that call can actually make progress; a thread
/// genuinely stuck in an uninterruptible kernel-level write (e.g. a hard
/// NFS mount) is a pre-existing exposure this bound does not newly
/// introduce, since the abandoned evaluation worker itself carries the
/// same risk whenever it reaches `analyze_with_policy`'s own logging call.
fn log_trip_best_effort(
    early_info: Option<EarlyInfo>,
    reason: &str,
    prior_state: u8,
    log_state: &LogState,
) {
    match prior_state {
        LOG_WORKER => {
            let deadline = Instant::now() + TRIP_LOG_TIMEOUT;
            while log_state.load(Ordering::SeqCst) != LOG_DONE && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            return;
        }
        LOG_DONE => return,
        // `LOG_UNCLAIMED`: falls through to write below. `LOG_MAIN` cannot
        // appear here — `emit_first_result` is the only writer of it, and
        // runs at most once per process.
        _ => {}
    }

    let Some(early_info) = early_info else {
        return;
    };
    let Some(path) = early_info.decision_log_path else {
        return;
    };
    let verdict = shguard::verdict::Verdict::ask(shguard::verdict::Reason::new(reason), Vec::new());
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("shguard-trip-log".to_string())
        .spawn(move || {
            shguard::FileDecisionLog.append(
                &path,
                &early_info.command,
                &verdict,
                &early_info.context,
            );
            let _ = done_tx.send(());
        });
    if spawned.is_ok() {
        let _ = done_rx.recv_timeout(TRIP_LOG_TIMEOUT);
    }
}

/// Effective RSS budget used by [`resolve_first_result`] — [`MEMORY_LIMIT_BYTES`]
/// in release builds. Debug builds additionally honour
/// `SHGUARD_TEST_MEM_LIMIT_MB`, mirroring `run`'s `SHGUARD_TEST_PANIC`
/// injection pattern, so `tests/fail_closed_exit_paths.rs` can pin the
/// memory-trip path against the test process's own baseline RSS instead
/// of actually allocating hundreds of MB just to exercise it.
fn memory_limit_bytes() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os("SHGUARD_TEST_MEM_LIMIT_MB")
        && let Ok(mb) = value.to_string_lossy().parse::<u64>()
    {
        return mb.saturating_mul(1024 * 1024);
    }
    MEMORY_LIMIT_BYTES
}

/// Current process RSS in bytes via `getrusage(RUSAGE_SELF, ...)`, or
/// `None` if the call fails or this platform doesn't support it — in
/// either case [`resolve_first_result`] simply skips the memory-trip check
/// for that poll; [`EVALUATION_TIMEOUT`]'s wall-clock bound still applies
/// regardless. `ru_maxrss` reports *peak* RSS, not current — exactly what
/// a one-shot process whose memory only grows in the pathological case
/// wants to bound. Units differ by platform: bytes on macOS, kilobytes
/// everywhere else `getrusage` is available (Linux, other BSDs) — the
/// `cfg` below converts the latter to bytes so callers never see the
/// platform difference.
#[cfg(unix)]
fn current_rss_bytes() -> Option<u64> {
    // SAFETY: `usage` is a valid, zero-initialised `libc::rusage`, and its
    // address is the sole out-pointer `getrusage` writes through;
    // `RUSAGE_SELF` targets the calling process, which is always valid to
    // query.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return None;
    }
    let raw = u64::try_from(usage.ru_maxrss).ok()?;
    #[cfg(target_os = "macos")]
    {
        Some(raw)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(raw.saturating_mul(1024))
    }
}

/// Non-Unix fallback: no `getrusage`, so the memory-trip check is simply
/// unavailable and [`resolve_first_result`] relies on [`EVALUATION_TIMEOUT`]
/// alone, same as before this watchdog existed.
#[cfg(not(unix))]
fn current_rss_bytes() -> Option<u64> {
    None
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

/// Whether `SHGUARD_STRICT_CONFIG` opts `run`'s config-load failure path
/// into `deny` instead of the default `ask` (issue #440). Presence-means-on,
/// matching `SHGUARD_CONFIG` itself (module docs, `src/config.rs`) rather
/// than `RUST_BACKTRACE`'s `"0"`-means-off convention above: this is a
/// security-strictness knob, so treating any set value (including `""`) as
/// "on" is the fail-closed reading — there is no legitimate reason to set
/// this var to explicitly turn strictness off.
///
/// Scope: this only hardens the config-load-failure path inside `run`. It
/// does not change `main`'s panic/watchdog fallback paths or `run`'s own
/// stdin-read failure path, which stay `ask` regardless (including a
/// config load that itself panics or hangs) — those are a different
/// failure class this var isn't meant to cover (see README's "Discovery"
/// section, and the "Wrapping the binary to fail closed" section's
/// caller-wrapper requirement, for the PATH-miss/crash gap this can't
/// close either).
fn strict_config_requested() -> bool {
    std::env::var_os("SHGUARD_STRICT_CONFIG").is_some()
}

/// `shguard init [--force]` (issue #112): scaffolds a starter config file
/// at the same path [`shguard::config::Policy::load`] would discover, so a
/// user can see (and start extending) the full embedded rule set without
/// reading source. Deliberately outside `main`'s `catch_unwind`/watchdog
/// boundary, same reasoning as [`check_config`]: a one-shot, human- or
/// CI-triggered invocation outside the PreToolUse hook contract entirely.
///
/// Exit codes follow this repo's check/lint convention: `0` wrote the
/// file, `1` refused because something already exists at the target path
/// (a real, actionable problem: rerun with `--force`, or edit the
/// existing file directly), `2` a usage error or the target path/write
/// itself failed.
///
/// Writes via `writeln!` (discarding the write error), not
/// `println!`/`eprintln!`, for the same broken-pipe reasoning
/// [`install_panic_hook`]'s own docs give.
fn run_init(args: &[std::ffi::OsString]) -> i32 {
    let mut force = false;
    for arg in args {
        if arg == "--force" {
            force = true;
        } else {
            let _ = writeln!(
                io::stderr(),
                "shguard init: unexpected argument {arg:?} (usage: shguard init [--force])"
            );
            return 2;
        }
    }

    match shguard::config::Policy::init(force) {
        Ok(path) => {
            let _ = writeln!(io::stdout(), "shguard init: wrote {}", path.display());
            0
        }
        Err(shguard::config::InitError::AlreadyExists { path }) => {
            let _ = writeln!(
                io::stderr(),
                "shguard init: {} already exists; rerun with --force to overwrite it",
                path.display()
            );
            1
        }
        Err(err) => {
            let _ = writeln!(io::stderr(), "shguard init: {err}");
            2
        }
    }
}

/// `shguard --check-config`: a one-shot, human- or CI-triggered lint pass
/// over the resolved user config, distinct from the PreToolUse hook path
/// ([`run`]) this binary otherwise only ever runs. Exists because the hook
/// path can't safely surface issue #208's warning itself: it re-loads
/// config fresh on every single command invocation with no persistent
/// process or "config changed" signal, so a naive `eprintln!` at load time
/// would repeat on every matching command for the lifetime of a Claude
/// Code session, not once when the config actually changes — see
/// `Policy::rules_with_mixed_except_targets`'s docs for the full
/// reasoning. Exit codes follow this repo's check/lint convention: `0`
/// clean, `1` findings (a real problem to fix, not a runtime failure), `2`
/// couldn't even load the config to check it. Deliberately outside
/// `main`'s `catch_unwind`/watchdog boundary — see [`run`]'s own docs for
/// why that boundary exists; `check_config` needs neither, since it runs
/// outside the PreToolUse hook contract entirely and has none of `run`'s
/// "never hang, always emit exactly one decision" obligations.
///
/// Writes via `writeln!` (discarding the write error), not
/// `println!`/`eprintln!` (which panic on a write failure): a human piping
/// this into `head` or another pager that closes the pipe early (`EPIPE`)
/// must not turn a clean or a findings run into a panic exit code, the
/// same reasoning [`install_panic_hook`]'s own docs give for using
/// `writeln!` there.
fn check_config() -> i32 {
    let policy = match shguard::config::Policy::load() {
        Ok(policy) => policy,
        Err(err) => {
            let _ = writeln!(
                io::stderr(),
                "shguard --check-config: failed to load config: {err}"
            );
            return 2;
        }
    };

    let mixed = policy.rules_with_mixed_except_targets();
    if mixed.is_empty() {
        let _ = writeln!(io::stdout(), "shguard --check-config: no issues found");
        return 0;
    }

    for id in &mixed {
        let _ = writeln!(
            io::stderr(),
            "shguard --check-config: rule {:?} mixes a `url_host` except_targets entry with an \
             `exact`/`prefix` entry — the string-based entry still matches whatever the \
             `url_host` entry was added to reject (e.g. a userinfo-spoofed candidate), so the \
             rule gains no additional protection from adding `url_host` alongside it; replace \
             the old entry, don't add `url_host` next to it",
            id.as_str()
        );
    }
    1
}

/// Usage string shared by every `run_check` argument-error path — kept as
/// one constant so `--permission-mode`'s addition (issue #469) didn't need
/// updating at each of the several call sites separately.
const CHECK_USAGE: &str = "usage: shguard check <command> [--json] [--permission-mode <mode>]";

/// `shguard check <command> [--json] [--permission-mode <mode>]` (issue
/// #109): a dry-run mode that prints the
/// [`shguard::analyze_with_policy`] verdict for a command string given
/// directly on the command line, instead of through the PreToolUse
/// stdin contract [`run`] otherwise only ever serves. Exists so rule
/// authors can iterate on a config change and immediately see the
/// resulting decision, and so CI can assert a set of commands resolve to
/// the expected decision without an agent or hook wiring in the loop.
///
/// `--permission-mode <mode>` (issue #469) reproduces exactly what the
/// PreToolUse hook would have seen for that `permission_mode` value —
/// parsed with the same [`shguard::PermissionMode::parse`] the hook stdin
/// path uses, so a replay resolves a table-form `ask_outcome` config
/// identically to a real hook invocation carrying the same mode. Omitted,
/// this subcommand builds [`shguard::HookContext::none`] exactly as it did
/// before this flag existed — `permission_mode`/`agent_id` both absent,
/// resolving a `[ask_outcome]` table's per-mode floor the same
/// conservative way an `Unknown` mode does (`Ask`, unless the config used
/// #467's bare-string form instead).
///
/// Always evaluates through [`shguard::analyze_with_policy`] — the exact
/// same pipeline [`run`] hands a real hook payload's command to — never a
/// separate decision path, so this subcommand's output is guaranteed to
/// match what a real hook invocation would decide for the same command
/// under the same config.
///
/// Exit codes follow this repo's check/lint convention (same scheme
/// [`check_config`] already established): `0` the command Allows or Asks
/// (nothing to act on beyond what the human/CI caller already sees
/// printed), `1` the command Blocks (a real problem, not a runtime
/// failure — useful for a CI step to fail on), `2` a usage error (missing/
/// extra arguments, non-UTF-8 command), the config itself couldn't load, or
/// evaluation exceeded [`EVALUATION_TIMEOUT`] (see below). A config-load
/// failure under `--json` still emits `{"error": "..."}` on stdout (parsed
/// `json` is already known at that point). Usage errors (missing/extra
/// arguments, non-UTF-8 command) are always printed as human-readable text
/// on stderr with empty stdout, regardless of `--json` — a caller relying
/// on `--json` output should check the exit code first regardless.
///
/// Deliberately outside `main`'s `catch_unwind` boundary, exactly like
/// [`check_config`]: this is a human- or CI-triggered, one-shot invocation
/// outside the PreToolUse hook contract entirely, with none of [`run`]'s
/// "never hang, always emit exactly one decision" obligations, so a panic
/// here can simply propagate as a normal process crash rather than needing
/// to fail closed. It is NOT outside a wall-clock bound, though:
/// [`evaluate_with_timeout`] wraps the [`shguard::analyze_with_policy`] call
/// (which — issue #108 — may append to a user-configured
/// `decision_log_path` after its own internal gate-evaluation watchdog
/// already returned) in [`EVALUATION_TIMEOUT`] plus [`CHECK_TIMEOUT_GRACE`],
/// so a pathological log target (a hung network mount) fails `check` closed
/// within a bounded time instead of hanging the CI job or terminal forever —
/// matching the hook path's own bound (plus a small margin so an internal
/// timeout inside `analyze_with_policy` itself surfaces as the documented
/// `Decision: Ask`, not this outer bound's own error) instead of leaving
/// `check` as the one caller with no upper bound at all on that failure
/// mode.
///
/// Writes via `writeln!` (discarding the write error), not
/// `println!`/`eprintln!`, for the same broken-pipe reasoning
/// [`install_panic_hook`]'s own docs give.
fn run_check(args: &[std::ffi::OsString]) -> i32 {
    let mut json = false;
    let mut permission_mode: Option<&std::ffi::OsString> = None;
    let mut command: Option<&std::ffi::OsString> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // Compared against `&str` directly (not through `arg.to_str()`
        // first) so a non-UTF-8 first positional is still captured as
        // `command` below rather than silently misdiagnosed by this loop
        // as "unexpected argument" — its own UTF-8 check further down is
        // then reachable and gives the precise reason.
        if arg == "--json" {
            json = true;
        } else if arg == "--permission-mode" {
            if permission_mode.is_some() {
                let _ = writeln!(
                    io::stderr(),
                    "shguard check: --permission-mode given more than once ({CHECK_USAGE})"
                );
                return 2;
            }
            // A missing value and a flag-shaped value are rejected the same
            // way: `iter.next()` alone can't tell "no more arguments" apart
            // from "the next argument is itself a flag this loop would
            // otherwise swallow as the mode string" (e.g. `--permission-mode
            // --json` silently treating `--json` as an `Unknown` mode value
            // rather than the flag it looks like).
            let value = iter.next().filter(|v| match v.to_str() {
                Some(v) => !v.starts_with("--"),
                None => true,
            });
            let Some(value) = value else {
                let _ = writeln!(
                    io::stderr(),
                    "shguard check: --permission-mode requires a value ({CHECK_USAGE})"
                );
                return 2;
            };
            permission_mode = Some(value);
        } else if command.is_none() && arg.to_str().is_some_and(|arg| arg.starts_with("--")) {
            // A `--`-prefixed positional is a typo'd/unrecognized flag, not
            // a command: a real shell command never begins with `--`, so
            // silently accepting one here (e.g. `--permission-mode=auto`
            // typo'd without a space, or any other misspelled flag) would
            // analyze it as the literal command string, which trivially
            // resolves `Allow` — exactly the "typo skips the check and
            // exits 0 anyway" failure mode this binary exists to avoid (see
            // `main`'s own module doc).
            let _ = writeln!(
                io::stderr(),
                "shguard check: unrecognized flag {arg:?} ({CHECK_USAGE})"
            );
            return 2;
        } else if command.is_none() {
            command = Some(arg);
        } else {
            let _ = writeln!(
                io::stderr(),
                "shguard check: unexpected argument {arg:?} ({CHECK_USAGE})"
            );
            return 2;
        }
    }
    let Some(command) = command else {
        let _ = writeln!(
            io::stderr(),
            "shguard check: missing <command> ({CHECK_USAGE})"
        );
        return 2;
    };
    let Some(command) = command.to_str() else {
        let _ = writeln!(io::stderr(), "shguard check: <command> must be valid UTF-8");
        return 2;
    };
    // Reproduces exactly what the hook path would have seen for this same
    // `permission_mode` value (issue #469's own recommended design: a
    // `--permission-mode` flag over threading an `Option<PermissionMode>`
    // through `analyze_with_policy` itself), including a non-UTF-8 value —
    // `PermissionMode::parse` takes `&str`, so a non-UTF-8 flag value fails
    // closed with a precise reason rather than being silently misdiagnosed
    // as "unexpected argument" the way an unparsed positional would be.
    let permission_mode = match permission_mode {
        None => None,
        Some(value) => match value.to_str() {
            Some(value) => Some(shguard::PermissionMode::parse(value)),
            None => {
                let _ = writeln!(
                    io::stderr(),
                    "shguard check: --permission-mode value must be valid UTF-8"
                );
                return 2;
            }
        },
    };
    let context = shguard::HookContext::new(permission_mode, None, None);

    let policy = match shguard::config::Policy::load() {
        Ok(policy) => policy,
        Err(err) => {
            // `json` is already known at this point (parsed above, before
            // any analysis runs) — a `--json`-requesting caller gets valid
            // JSON here too, not empty stdout it can't parse.
            if json {
                let value = serde_json::json!({ "error": err.to_string() });
                let _ = writeln!(
                    io::stdout(),
                    "{}",
                    serde_json::to_string(&value).unwrap_or_else(|_| value.to_string())
                );
            } else {
                let _ = writeln!(io::stderr(), "shguard check: failed to load config: {err}");
            }
            return 2;
        }
    };

    let verdict = match evaluate_with_timeout(command, &policy, &context) {
        Ok(verdict) => verdict,
        Err(err) => {
            let message = match err {
                EvalTimeoutError::TimedOut => {
                    "shguard check: evaluation exceeded its time budget (possibly a hung \
                     decision_log_path target); refusing to evaluate (fail-closed)"
                }
                EvalTimeoutError::Disconnected => {
                    "shguard check: evaluation worker stopped without producing a result; \
                     refusing to evaluate (fail-closed)"
                }
            };
            if json {
                let value = serde_json::json!({ "error": message });
                let _ = writeln!(
                    io::stdout(),
                    "{}",
                    serde_json::to_string(&value).unwrap_or_else(|_| value.to_string())
                );
            } else {
                let _ = writeln!(io::stderr(), "{message}");
            }
            return 2;
        }
    };
    let decision = verdict.decision();
    let decision_name = match decision {
        shguard::verdict::Decision::Allow => "Allow",
        shguard::verdict::Decision::Ask => "Ask",
        shguard::verdict::Decision::Block => "Block",
    };
    let reason = verdict.reason().map(shguard::verdict::Reason::as_str);
    let matched_rule_id = verdict.matched_rule().map(shguard::verdict::RuleId::as_str);
    let deny_message = verdict
        .deny_message()
        .map(shguard::verdict::DenyMessage::as_str);

    if json {
        let value = serde_json::json!({
            "command": command,
            "decision": decision_name,
            "reason": reason,
            "matched_rule_id": matched_rule_id,
            "deny_message": deny_message,
        });
        let _ = writeln!(
            io::stdout(),
            "{}",
            serde_json::to_string(&value).unwrap_or_else(|_| value.to_string())
        );
    } else {
        let _ = writeln!(io::stdout(), "Decision: {decision_name}");
        if let Some(reason) = reason {
            let _ = writeln!(io::stdout(), "Reason: {reason}");
        }
        if let Some(matched_rule_id) = matched_rule_id {
            let _ = writeln!(io::stdout(), "Matched rule: {matched_rule_id}");
        }
        if let Some(deny_message) = deny_message {
            let _ = writeln!(io::stdout(), "Deny message: {deny_message}");
        }
    }

    i32::from(decision == shguard::verdict::Decision::Block)
}

/// Margin added on top of [`EVALUATION_TIMEOUT`] for
/// [`evaluate_with_timeout`]'s outer bound. `analyze_with_policy` already
/// bounds its own gate evaluation internally to `EVALUATION_TIMEOUT` (see
/// `src/watchdog.rs`) and returns its own fail-closed `Ask` verdict on that
/// internal trip — this margin must strictly exceed that internal deadline
/// so a genuine internal time-budget trip has time to be sent back over the
/// channel and reported as the documented `Decision: Ask` (with its verdict
/// still logged), rather than losing the race to this function's own outer
/// `recv_timeout` and being reported instead as `run_check`'s generic
/// "possibly a hung decision_log_path target" runtime error.
const CHECK_TIMEOUT_GRACE: Duration = Duration::from_millis(500);

/// Why [`evaluate_with_timeout`] did not produce a verdict.
enum EvalTimeoutError {
    /// The outer bound elapsed with the worker still running — most likely
    /// a blocking `decision_log_path` target, since `analyze_with_policy`'s
    /// own internal watchdog should already have returned well within
    /// [`CHECK_TIMEOUT_GRACE`] of [`EVALUATION_TIMEOUT`].
    TimedOut,
    /// The worker thread ended without sending a result — it panicked
    /// (`analyze_with_policy` itself should never panic; this is a
    /// last-resort signal for a bug reached through an unanticipated path,
    /// not a hung log target).
    Disconnected,
}

/// Runs [`shguard::analyze_with_policy`] on a worker thread bounded by
/// [`EVALUATION_TIMEOUT`] (plus [`CHECK_TIMEOUT_GRACE`]), mirroring [`run`]'s
/// own hook-path watchdog so [`run_check`] cannot hang indefinitely on a
/// pathological `decision_log_path` target — the analysis call includes
/// issue #108's log-append step, which runs after `analyze_with_policy`'s
/// own internal gate-evaluation watchdog already returned and is therefore
/// unbounded on its own. Unlike [`run`]'s watchdog, this does not also poll
/// RSS: the failure mode this closes is a blocking write, not unbounded
/// allocation, so a wall-clock bound alone is sufficient here.
///
/// If the worker thread itself can't be spawned, falls back to running
/// inline with no bound at all — strictly no worse than `check` behaved
/// before this function existed, and thread-spawn failure (OS out of
/// resources) is already a degraded environment for a one-shot CLI
/// invocation to begin with.
fn evaluate_with_timeout(
    command: &str,
    policy: &shguard::config::Policy,
    context: &shguard::HookContext,
) -> Result<shguard::verdict::Verdict, EvalTimeoutError> {
    let owned_command = command.to_string();
    let owned_policy = policy.clone();
    let owned_context = context.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("shguard-check-eval".to_string())
        .spawn(move || {
            let verdict = shguard::analyze_with_policy(
                &owned_command,
                &owned_policy,
                &owned_context,
                &shguard::FileDecisionLog,
            );
            // A closed receiver means the timeout already fired and the
            // caller moved on — nothing left to send to, and this thread
            // is about to be torn down along with the whole process once
            // `run_check` returns its exit-2 timeout path.
            let _ = tx.send(verdict);
        });
    let Ok(_worker) = spawned else {
        return Ok(shguard::analyze_with_policy(
            command,
            policy,
            context,
            &shguard::FileDecisionLog,
        ));
    };
    match rx.recv_timeout(EVALUATION_TIMEOUT + CHECK_TIMEOUT_GRACE) {
        Ok(verdict) => Ok(verdict),
        Err(RecvTimeoutError::Timeout) => Err(EvalTimeoutError::TimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(EvalTimeoutError::Disconnected),
    }
}

/// The composition root's actual work — config load, stdin read, hand-off
/// to the adapter — as a plain fn item, not a closure passed to
/// [`std::panic::catch_unwind`] in [`main`]: `main` calls it as `move ||
/// run(&early_tx, worker_log_state)`, so `catch_unwind`'s `UnwindSafe` bound
/// falls on that thin closure rather than on this function's own body,
/// which stays a capture-free fn item taking its two dependencies
/// ([`EarlyInfo`]'s sender, [`DedupSink`]'s shared [`LogState`]) as explicit
/// parameters instead of reaching for `AssertUnwindSafe` or closing over
/// shared state. Neither `Sender<EarlyInfo>` nor `Arc<LogState>` carries
/// unwind-unsafe interior state — a panic mid-`send` either lands before or
/// after the message is queued, never partway through a value the receiver
/// could observe half-mutated, and an atomic `swap`/`compare_exchange` has
/// no lock to poison — so the auto-trait check passes without an escape
/// hatch.
///
/// The `catch_unwind` boundary in `main` covers everything in here,
/// including [`shguard::config::Policy::load`] — a panic inside TOML
/// parsing is exactly as fail-open as one anywhere else in this function.
/// So does the watchdog timeout: `run` executes entirely on the worker
/// thread `main` spawns, so a hang anywhere in here (stdin read, config
/// load, or command evaluation) is bounded by [`EVALUATION_TIMEOUT`] the
/// same way. The `--version`/`--check-config` branches in `main` are
/// deliberately outside both boundaries: `--version` never touches config,
/// stdin, or command evaluation, so there is nothing there for the
/// fail-closed guarantee to protect; `--check-config` ([`check_config`])
/// does load config, but as a human- or CI-triggered, one-shot diagnostic
/// run outside the PreToolUse hook contract entirely — it has none of
/// `run`'s "never hang, always emit exactly one decision" obligations, so
/// it needs neither the panic boundary nor the watchdog.
fn run(early_tx: &Sender<EarlyInfo>, log_state: Arc<LogState>) -> serde_json::Value {
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
            let reason = format!(
                "shguard: user config failed to load ({err}); refusing to evaluate any command \
                 until this is fixed"
            );
            return if strict_config_requested() {
                shguard::adapter::fail_closed_deny(&reason)
            } else {
                shguard::adapter::fail_closed(&reason)
            };
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
        Ok(_) if stdin.len() as u64 > MAX_STDIN_BYTES => shguard::adapter::fail_closed_with(
            policy.ask_outcome(&shguard::HookContext::none()),
            &format!("shguard: stdin exceeds {MAX_STDIN_BYTES} bytes; refusing to evaluate"),
        ),
        Ok(_) => {
            // Issue #459: sent before `handle_with_policy`'s own call into
            // `analyze_with_policy` — the one call in this function that
            // can actually hang — so `main`'s outer watchdog has a command
            // and context in hand for the decision log even if that call
            // never returns. `peek_bash_command` is a read-only duplicate
            // of the extraction `handle_with_policy` performs for real
            // immediately after; it never affects the decision below, only
            // what a later watchdog trip can log.
            if let Some((command, context)) = shguard::adapter::peek_bash_command(&stdin) {
                // The receiver lives in `main`, held until after
                // `worker.join()` (well past this send), so this can only
                // fail if `main` already exited via a watchdog trip before
                // reaching that join — in which case the whole process is
                // already on its way down and there is nothing left for a
                // send failure to report.
                let _ = early_tx.send(EarlyInfo {
                    decision_log_path: policy.decision_log_path().map(std::path::Path::to_path_buf),
                    command,
                    context,
                });
            }
            let sink = DedupSink { state: log_state };
            shguard::adapter::handle_with_policy(&stdin, &policy, &sink)
        }
        // A read error also covers the case where the input is oversized
        // *and* its true length happens to break UTF-8 exactly at the
        // `MAX_STDIN_BYTES + 1`-byte boundary `take` reads up to:
        // `read_to_string` reports that as `InvalidData` rather than
        // `Ok`, and this arm fails closed the same as any other stdin
        // read error. `policy` is already loaded at this point (issue
        // #467: `ask_outcome` applies to every composition-root
        // fail-closed path that has a `Policy` in hand, not only
        // `analyze_with_policy`'s own structural `Ask`s).
        Err(err) => shguard::adapter::fail_closed_with(
            policy.ask_outcome(&shguard::HookContext::none()),
            &format!("shguard: could not read stdin: {err}"),
        ),
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

/// Issue #457: [`resolve_first_result`] is deliberately pure (no I/O, no
/// [`std::process::exit`]) so its try-the-channel-first race can be pinned
/// deterministically here, rather than only through a real subprocess and
/// real wall-clock timing (`tests/fail_closed_exit_paths.rs`, which still
/// covers the genuine-hang side end to end). Every test below sends the
/// worker's result into the channel *before* calling
/// `resolve_first_result`, then forces the trip condition it targets
/// (`memory_limit` of `0`, or a `timeout` already elapsed) — so there is no
/// timing window to race at all: either `try_recv` sees the value that is
/// already sitting there, or it doesn't, deterministically.
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Duration, FirstResult, resolve_first_result};

    fn output_value() -> serde_json::Value {
        serde_json::json!({"hookSpecificOutput": {"permissionDecision": "deny"}})
    }

    /// A worker result already sitting in the channel wins over the memory
    /// trip: `memory_limit: 0` guarantees the RSS check trips on the very
    /// first iteration (real RSS is never zero), but that must not discard
    /// the value `try_recv` finds waiting for it. `#[cfg(unix)]`: mirrors
    /// `current_rss_bytes`'s own platform gating — on any other platform
    /// there is no RSS check to trip in the first place. Paired with
    /// `memory_trip_fails_closed_when_the_channel_stays_empty` below: on its
    /// own, this test can't distinguish "the memory arm's `try_recv` won"
    /// from "the memory arm never ran and the ordinary `recv_timeout` path
    /// won instead" — the sibling test pins that the arm genuinely trips
    /// under the same `memory_limit`.
    #[cfg(unix)]
    #[test]
    fn memory_trip_prefers_a_result_already_in_the_channel() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(output_value()).expect("receiver still open");
        let resolved = resolve_first_result(&rx, 0, Duration::from_secs(30));
        match resolved {
            FirstResult::Output(value) => assert_eq!(value, output_value()),
            other => {
                panic!("expected the pre-sent result to win over the memory trip, got: {other:?}")
            }
        }
    }

    /// Same race, wall-clock side: `timeout: Duration::ZERO` means
    /// `deadline` is already in the past by the time the loop's first
    /// `Instant::now()` re-check runs, tripping the time bound on the very
    /// first iteration — again, must not discard an already-ready result.
    #[test]
    fn time_trip_prefers_a_result_already_in_the_channel() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(output_value()).expect("receiver still open");
        let resolved = resolve_first_result(&rx, u64::MAX, Duration::ZERO);
        match resolved {
            FirstResult::Output(value) => assert_eq!(value, output_value()),
            other => {
                panic!("expected the pre-sent result to win over the time trip, got: {other:?}")
            }
        }
    }

    /// Genuine fail-closed side, memory arm: with nothing ever sent, the
    /// same `memory_limit: 0` trip must still resolve to `MemoryTrip`, not
    /// hang or silently prefer an empty channel. `#[cfg(unix)]` for the same
    /// reason as the test above — without a real RSS reading, this would
    /// fall through to `TimeTrip` after the full deadline instead. A short
    /// 2s deadline (not 30s like the other tests here) bounds how long a
    /// regression that broke the memory trip would take to fail this test,
    /// rather than only surfacing after the fallback wall-clock trip fires.
    #[cfg(unix)]
    #[test]
    fn memory_trip_fails_closed_when_the_channel_stays_empty() {
        let (_tx, rx) = std::sync::mpsc::channel::<serde_json::Value>();
        let resolved = resolve_first_result(&rx, 0, Duration::from_secs(2));
        assert!(
            matches!(resolved, FirstResult::MemoryTrip(_)),
            "expected a memory trip, got: {resolved:?}"
        );
    }

    /// Genuine fail-closed side, wall-clock arm: same shape as above, for
    /// `TimeTrip`.
    #[test]
    fn time_trip_fails_closed_when_the_channel_stays_empty() {
        let (_tx, rx) = std::sync::mpsc::channel::<serde_json::Value>();
        let resolved = resolve_first_result(&rx, u64::MAX, Duration::ZERO);
        assert!(
            matches!(resolved, FirstResult::TimeTrip(_)),
            "expected a time trip, got: {resolved:?}"
        );
    }

    /// The sender dropping without ever sending (worker panicked/exited
    /// without producing a result) resolves to `Disconnected`, distinct
    /// from either trip.
    #[test]
    fn disconnected_sender_fails_closed_without_a_trip() {
        let (tx, rx) = std::sync::mpsc::channel::<serde_json::Value>();
        drop(tx);
        let resolved = resolve_first_result(&rx, u64::MAX, Duration::from_secs(30));
        assert!(
            matches!(resolved, FirstResult::Disconnected(_)),
            "expected a disconnect, got: {resolved:?}"
        );
    }

    /// The ordinary path: a result that arrives during the blocking
    /// `recv_timeout` wait (neither trip condition true) resolves to
    /// `Output` via the normal receive, not the trip arms' `try_recv`.
    #[test]
    fn result_sent_before_either_bound_trips_resolves_normally() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(output_value()).expect("receiver still open");
        let resolved = resolve_first_result(&rx, u64::MAX, Duration::from_secs(30));
        match resolved {
            FirstResult::Output(value) => assert_eq!(value, output_value()),
            _ => panic!("expected the normal receive path to win"),
        }
    }
}
