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
//!   primitive (`src/bin/shguard.rs`'s module docs cover this in full), so
//!   the thread may keep running and allocating in the background until it
//!   finishes on its own or the host process exits. That is a known,
//!   accepted limitation of bounding *cooperative* Rust code this way, not
//!   a gap this module can close from inside itself — a caller that needs
//!   hard termination on an untrusted or adversarial input source should
//!   run evaluation in a subprocess instead.
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
//!   process is doing.

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
/// [`EVALUATION_TIMEOUT`] and [`MEMORY_LIMIT_BYTES`]; returns whatever
/// `pipeline` produces on success, or a fail-closed [`Verdict::ask`] if
/// either bound trips, the worker thread cannot be spawned, or it is lost
/// (panics — an unwind mid-closure drops the sender, which surfaces here
/// as [`RecvTimeoutError::Disconnected`] with no separate `catch_unwind`
/// needed).
///
/// `pipeline` must be `'static` (own everything it touches) because it
/// crosses the thread boundary — see the two call sites in `src/lib.rs`
/// for why `command`/`policy` are cloned before this is called rather than
/// borrowed.
pub(crate) fn bounded(pipeline: impl FnOnce() -> Verdict + Send + 'static) -> Verdict {
    let baseline_rss = current_rss_bytes().unwrap_or(0);
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
        if let Some(rss) = current_rss_bytes() {
            let delta = rss.saturating_sub(baseline_rss);
            if delta > MEMORY_LIMIT_BYTES {
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

/// Current process RSS in bytes via `getrusage(RUSAGE_SELF, ...)`, or
/// `None` if the call fails or this platform doesn't support it — either
/// way [`bounded`] simply skips the memory-trip check for that poll;
/// [`EVALUATION_TIMEOUT`]'s wall-clock bound still applies regardless.
/// `ru_maxrss` reports *peak*, not current, RSS for the whole process —
/// exactly what makes the delta in [`bounded`] meaningful: it is a
/// monotonically non-decreasing high-water mark, so `rss - baseline_rss`
/// measures how much that high-water mark has grown since the worker
/// thread was spawned. Units differ by platform: bytes on macOS,
/// kilobytes everywhere else `getrusage` is available (Linux, other
/// BSDs) — the `cfg` below converts the latter to bytes so callers never
/// see the platform difference. Duplicated from
/// `src/bin/shguard.rs::current_rss_bytes` rather than shared: the two
/// live in different crates within this workspace (bin vs. lib) with no
/// existing shared internal module to place a common helper in, and the
/// function itself is a five-line FFI call with nothing to drift.
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
/// unavailable and [`bounded`] relies on [`EVALUATION_TIMEOUT`] alone,
/// same as `src/bin/shguard.rs::current_rss_bytes`'s non-Unix fallback.
#[cfg(not(unix))]
fn current_rss_bytes() -> Option<u64> {
    None
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
}
