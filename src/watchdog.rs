//! A wall-clock + memory watchdog protecting the pure evaluation entry
//! points ([`crate::analyze`] / [`crate::analyze_with_policy`]) — issue
//! #319: those functions are shguard's public library API (documented on
//! crates.io), and until this module existed they had no protection
//! against the crash-fuzzer finding #315 fixed for the CLI binary — a
//! heredoc operator whose delimiter-word parsing recurses into a
//! never-closed `$(...)` drives brush-parser's tokenizer into an unbounded
//! allocating loop. A consumer calling [`crate::analyze`] directly (not
//! through the `shguard` binary) still hit that hang/OOM unprotected.
//!
//! This is a *separate* implementation from `src/bin/shguard.rs`'s own
//! watchdog, not shared code, because two of that one's assumptions don't
//! hold for a library entry point a downstream consumer can call from
//! inside an arbitrary, long-lived host process:
//!
//! - **No `std::process::exit`.** The binary's watchdog kills the whole
//!   process on a trip — safe there because a hook invocation is a
//!   disposable, short-lived process with nothing else running in it. A
//!   library call doing the same to its caller's process (a web server, a
//!   daemon, anything embedding shguard) would be a catastrophic surprise
//!   grossly out of proportion to "one command didn't parse in time." A
//!   trip here returns a fail-closed [`Verdict::ask`] instead and leaves
//!   the runaway worker thread detached: Rust has no safe thread-cancel
//!   primitive (`src/bin/shguard.rs`'s module docs cover this in full).
//!   For a non-terminating input like #315's, that thread never finishes
//!   on its own either — it keeps allocating in the background, and the
//!   host process still runs out of memory eventually, just later than an
//!   in-call hang would have. This module only buys the caller two
//!   things: the call itself returns instead of hanging, and the OOM is
//!   deferred out of the request path — it does **not** prevent the OOM.
//!   A caller evaluating untrusted or adversarial input, where that
//!   distinction matters, should run evaluation in a subprocess instead,
//!   so the runaway dies with it.
//! - **RSS delta, not absolute.** The binary's watchdog compares current
//!   RSS against an absolute cap, which is sound only because the
//!   process's own baseline footprint at that point is negligible. A
//!   library call has no such guarantee — the host process's existing
//!   memory use is unknown and unbounded from here, so an absolute cap
//!   would either trip on every call inside any host whose baseline
//!   already exceeds it, or fail to trip at all against a host whose
//!   baseline sits far below it. Measuring the *increase* in RSS from just
//!   before the worker thread is spawned isolates the memory this one
//!   evaluation is responsible for, independent of whatever else the host
//!   process is doing — which in turn requires *current*, not *peak*, RSS
//!   as the underlying measurement (see [`current_rss_bytes`]'s docs for
//!   why the binary's own `getrusage`-peak approach doesn't carry over).
//!
//! # Nesting when called through the `shguard` binary
//!
//! `src/adapter.rs` calls the public `analyze`/`analyze_with_policy`
//! functions this module wraps, so a normal hook invocation runs this
//! watchdog *inside* the binary's own — two `shguard-eval` threads, one
//! nested in the other. This is deliberate, not an oversight: the two
//! bound different scopes (this one only the evaluation pipeline; the
//! binary's also config load and stdin read) and the binary's bound is
//! always at least as strict — its wall-clock deadline starts earlier
//! (before stdin is even read) and its absolute memory cap is always `<=`
//! this module's `baseline + `[`MEMORY_LIMIT_BYTES`]` (`baseline` cannot be
//! negative) — so the binary's watchdog trips first, or the evaluation
//! finishes before either does. The extra thread-spawn is a small,
//! accepted cost, not a correctness gap.

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use crate::verdict::{Reason, Verdict};

/// Wall-clock budget given to one evaluation before it's abandoned as
/// hung. Same value as `src/bin/shguard.rs::EVALUATION_TIMEOUT`, whose
/// doc comment carries the p100 measurements this is derived from — both
/// bound the same parse/normalise/rules/gate pipeline, just entered from a
/// different caller.
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the trip-check polls RSS while waiting on the worker. Same
/// value as `src/bin/shguard.rs::MEMORY_POLL_INTERVAL`, whose doc comment
/// carries the reasoning.
const MEMORY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Budget on the *increase* in RSS since the worker thread was spawned —
/// see the module docs' "RSS delta, not absolute" for why this is a delta
/// rather than an absolute cap. Reuses `src/bin/shguard.rs::MEMORY_LIMIT_BYTES`'s
/// 256 MiB figure: the legitimate-peak-RSS measurement that value is
/// derived from (24 MB, a 20k-stage/200KB-word fixture) was itself taken
/// against a freshly-started process, so it already approximates a delta
/// from near-zero. Re-measure before changing this.
const MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;

/// Runs `pipeline` to completion on its own thread, bounded by
/// [`EVALUATION_TIMEOUT`] and [`MEMORY_LIMIT_BYTES`] — see
/// [`bounded_with_memory_limit`] for the full behavior; this is the fixed-
/// budget entry point every real caller uses.
///
/// `pipeline` must be `'static` (own everything it touches) because it
/// crosses the thread boundary — see the two call sites in `src/lib.rs`
/// for why `command`/`policy` are cloned before this is called rather than
/// borrowed.
pub(crate) fn bounded(pipeline: impl FnOnce() -> Verdict + Send + 'static) -> Verdict {
    bounded_with_memory_limit(MEMORY_LIMIT_BYTES, pipeline)
}

/// Same as [`bounded`], with the memory budget as a parameter — split out
/// so `tests` can pin the memory-trip branch deterministically with a
/// tiny limit and a small, finite allocation, instead of only reaching it
/// incidentally through a real unbounded-allocating repro (mirrors
/// `src/bin/shguard.rs`'s `SHGUARD_TEST_MEM_LIMIT_MB` injection point,
/// which exists for the same reason). Returns whatever `pipeline`
/// produces on success, or a fail-closed [`Verdict::ask`] if either bound
/// trips, the worker thread cannot be spawned, or it is lost (panics — an
/// unwind mid-closure drops the sender, which surfaces here as
/// [`RecvTimeoutError::Disconnected`] with no separate `catch_unwind`
/// needed).
fn bounded_with_memory_limit(
    memory_limit_bytes: u64,
    pipeline: impl FnOnce() -> Verdict + Send + 'static,
) -> Verdict {
    // `None` (rather than defaulting to `0`) when the platform/call can't
    // measure RSS at all — a `0` fallback would silently turn the delta
    // check into an absolute one against whatever `current_rss_bytes()`
    // next happens to return, tripping on every call in any host process
    // whose baseline already exceeds `memory_limit_bytes`.
    let baseline_rss = current_rss_bytes();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("shguard-eval".to_string())
        .spawn(move || {
            let _ = result_tx.send(pipeline());
        });

    let Ok(worker) = spawned else {
        return fail_closed(
            "shguard: could not start command evaluation; refusing to evaluate (fail-closed)",
        );
    };

    let deadline = Instant::now() + EVALUATION_TIMEOUT;
    loop {
        if let Some(baseline) = baseline_rss
            && let Some(rss) = current_rss_bytes()
        {
            let delta = rss.saturating_sub(baseline);
            if delta > memory_limit_bytes {
                // The worker may have already sent its real result in the
                // gap between the last `recv_timeout` returning and this
                // check tripping (e.g. unrelated growth elsewhere in the
                // host process pushed the delta over budget just as the
                // worker finished) — prefer that over discarding a
                // verdict the pipeline already computed, `Block` included.
                if let Ok(verdict) = result_rx.try_recv() {
                    let _ = worker.join();
                    return verdict;
                }
                // `worker` is dropped here without joining — deliberately:
                // joining would block on the exact hang this function
                // exists to bound. See the module docs' "No
                // std::process::exit" section.
                return fail_closed(&format!(
                    "shguard: evaluation exceeded its memory budget ({delta} bytes RSS \
                     growth); refusing to evaluate (fail-closed)"
                ));
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return fail_closed(
                "shguard: evaluation exceeded its time budget; refusing to evaluate \
                 (fail-closed)",
            );
        }

        match result_rx.recv_timeout(remaining.min(MEMORY_POLL_INTERVAL)) {
            Ok(verdict) => {
                let _ = worker.join();
                return verdict;
            }
            // Not yet past `deadline` (checked above) — loop around to
            // re-sample RSS before waiting again.
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return fail_closed(
                    "shguard: evaluation worker stopped without producing a result; \
                     refusing to evaluate (fail-closed)",
                );
            }
        }
    }
}

fn fail_closed(reason: &str) -> Verdict {
    Verdict::ask(Reason::new(reason), Vec::new())
}

/// Current (not peak) process RSS in bytes, or `None` if the underlying
/// call fails or this platform has no implementation here — either way
/// [`bounded_with_memory_limit`] simply skips the memory-trip check for
/// that poll; [`EVALUATION_TIMEOUT`]'s wall-clock bound still applies
/// regardless.
///
/// Deliberately *not* `src/bin/shguard.rs::current_rss_bytes`'s
/// `getrusage`/`ru_maxrss` approach, despite both living in this package
/// (bin and lib targets, not separate workspace crates) and wanting the
/// same thing: `ru_maxrss` is a *peak*, a monotonically non-decreasing
/// high-water mark for the whole process. The binary can get away with
/// that because it never takes a delta — it compares peak directly
/// against an absolute cap once, in a process that started at ~zero. This
/// module *does* take a delta (`rss - baseline_rss` in
/// [`bounded_with_memory_limit`]), and a delta of two peaks is not the
/// same thing as the memory this one call is responsible for: once
/// *anything* in the host process pushes the peak up — including a prior
/// trip of this very watchdog leaving a runaway thread allocating in the
/// background — every later call's `baseline_rss` starts at that inflated
/// peak too, so a call whose own footprint is trivial can still show a
/// large "delta" if the peak grew *between* `baseline_rss` being sampled
/// and the next poll (e.g. an unrelated host thread allocating
/// concurrently), and conversely a genuinely runaway call can show a
/// `delta` of zero if the host's historical peak already sits above
/// wherever RSS is by the time this call's polls run. Reading *current*
/// resident size instead avoids both: it only ever reflects what is
/// resident right now, so the delta is bounded by what actually happened
/// during this call's own polling window.
fn current_rss_bytes() -> Option<u64> {
    platform::current_rss_bytes()
}

#[cfg(target_os = "linux")]
mod platform {
    /// Current RSS via `/proc/self/statm`'s second field (resident pages)
    /// times the page size — the standard way to read a process's own
    /// current (not peak) resident set size on Linux; there is no
    /// dedicated syscall for it. `None` on any parse/read failure or if
    /// `sysconf` can't report a page size.
    pub(super) fn current_rss_bytes() -> Option<u64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: `sysconf` with a valid `name` argument (`_SC_PAGESIZE`
        // is always a recognised name on Linux) has no preconditions and
        // never fails destructively — a negative return means "not
        // supported", handled below via `u64::try_from`.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = u64::try_from(page_size).ok()?;
        Some(resident_pages.saturating_mul(page_size))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    /// Current RSS via `proc_pidinfo(PROC_PIDTASKINFO, ...)`'s
    /// `pti_resident_size` field — macOS's per-process current (not peak)
    /// resident size, queried for the calling process by its own pid.
    /// `None` on any call failure or short read.
    pub(super) fn current_rss_bytes() -> Option<u64> {
        // SAFETY: `info` is a valid, zero-initialised `libc::proc_taskinfo`
        // out-buffer of exactly the size `proc_pidinfo` is told it is;
        // `libc::getpid()` always returns a valid pid for the calling
        // process.
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = i32::try_from(std::mem::size_of::<libc::proc_taskinfo>()).ok()?;
        let written = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
                size,
            )
        };
        if written != size {
            return None;
        }
        Some(info.pti_resident_size)
    }
}

/// Fallback for any platform without a dedicated current-RSS
/// implementation above (any non-Linux, non-macOS target, `unix` or
/// otherwise): the memory-trip check is simply unavailable here and
/// [`bounded_with_memory_limit`] relies on [`EVALUATION_TIMEOUT`] alone,
/// same posture as `src/bin/shguard.rs::current_rss_bytes`'s own
/// non-Unix fallback.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    pub(super) fn current_rss_bytes() -> Option<u64> {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fast_pipeline_returns_its_own_verdict_unmodified() {
        let verdict = bounded(|| Verdict::allow(Vec::new()));
        assert_eq!(verdict.decision(), crate::verdict::Decision::Allow);
    }

    #[test]
    fn hung_pipeline_fails_closed_to_ask_within_timeout() {
        let started = Instant::now();
        let verdict = bounded(|| {
            std::thread::sleep(Duration::from_secs(60));
            Verdict::allow(Vec::new())
        });
        assert_eq!(verdict.decision(), crate::verdict::Decision::Ask);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "bounded() should return near EVALUATION_TIMEOUT, not wait for the worker"
        );
    }

    #[test]
    fn panicking_pipeline_fails_closed_to_ask() {
        let verdict = bounded(|| panic!("watchdog test: injected panic"));
        assert_eq!(verdict.decision(), crate::verdict::Decision::Ask);
    }

    /// Deterministic pin for the memory-trip branch itself (as opposed to
    /// only reaching it incidentally through a real unbounded-allocating
    /// repro, which may trip on time instead — see
    /// `tests/fail_closed_exit_paths.rs`'s
    /// `library_analyze_fails_closed_to_ask_on_the_same_heredoc_hang`).
    /// The pipeline allocates and touches 1 MiB — comfortably over the
    /// 64 KiB budget this test sets — then sleeps briefly before sending,
    /// giving the poll loop several 50ms iterations to observe the
    /// inflated delta before the pipeline would otherwise complete and
    /// race the memory check via the channel.
    #[test]
    fn memory_budget_trip_fails_closed_to_ask() {
        let verdict = bounded_with_memory_limit(64 * 1024, || {
            let touched = vec![1u8; 1024 * 1024];
            std::thread::sleep(Duration::from_millis(300));
            std::hint::black_box(&touched);
            Verdict::allow(Vec::new())
        });
        assert_eq!(verdict.decision(), crate::verdict::Decision::Ask);
        assert!(
            verdict
                .reason()
                .is_some_and(|r| r.as_str().contains("memory budget")),
            "expected a memory-budget fail-closed reason, got: {:?}",
            verdict.reason()
        );
    }
}
