//! Optional structured decision-output logging (issue #108): one JSONL
//! line per [`crate::analyze_with_policy`] call, appended to the path a
//! user config's `decision_log_path` key names. Off by default —
//! [`crate::config::Policy::load`] leaves the field `None` unless the
//! user's own config sets it.
//!
//! [`FileDecisionLog`] implements [`crate::DecisionLogSink`], the port
//! [`crate::analyze_with_policy`] appends through — the composition root
//! (`src/bin/shguard.rs`) constructs one instance and passes it to both
//! `src/adapter.rs`'s hook path and the `check` subcommand (issue #408),
//! so this module's concrete writer is never named outside this file and
//! the composition root. The call itself still happens inside
//! `analyze_with_policy`, not at either caller (the exact same divergence
//! concern issue #109 closed for the decision itself: logging at the one
//! shared entry point both callers go through means the log can never
//! disagree with what either caller actually saw).

use std::io::Write;
use std::path::Path;

use crate::normalize::{NormalizedWord, Resolution};
use crate::verdict::{Decision, Verdict};

/// The only [`crate::DecisionLogSink`] implementation: appends to a real
/// file on disk. Zero-sized — construction is free, so the composition
/// root can build one wherever it needs to hand a sink to
/// [`crate::analyze_with_policy`], including inside a spawned worker
/// thread (`src/bin/shguard.rs`'s `evaluate_with_timeout`).
#[derive(Clone, Copy)]
pub struct FileDecisionLog;

impl crate::DecisionLogSink for FileDecisionLog {
    fn append(&self, path: &Path, command: &str, verdict: &Verdict) {
        append(path, command, verdict);
    }
}

/// Appends one JSONL line describing `verdict` for `command` to `path`.
///
/// Best-effort and fail-open on the logging side only: a write failure
/// (unwritable path, missing parent directory, disk full) is silently
/// dropped rather than propagated or panicking. This mirrors `analyze`'s
/// own single-fold-point posture (`src/lib.rs`) — a broken log target must
/// never turn a real Allow/Ask/Block decision into a crash or an altered
/// verdict, since logging is an observability side channel, not part of
/// the decision contract. A caller who needs to know logging itself is
/// healthy should watch the log file directly (size, mtime), not
/// shguard's return value.
fn append(path: &Path, command: &str, verdict: &Verdict) {
    let decision = match verdict.decision() {
        Decision::Allow => "Allow",
        Decision::Ask => "Ask",
        Decision::Block => "Block",
    };
    let reason = verdict.reason().map(crate::verdict::Reason::as_str);
    let matched_rule_id = verdict.matched_rule().map(crate::verdict::RuleId::as_str);
    let deny_message = verdict
        .deny_message()
        .map(crate::verdict::DenyMessage::as_str);
    let normalized_argv: Vec<String> = verdict
        .normalized_argv()
        .iter()
        .map(word_to_string)
        .collect();

    let line = serde_json::json!({
        "command": command,
        "decision": decision,
        "reason": reason,
        "matched_rule_id": matched_rule_id,
        "deny_message": deny_message,
        "normalized_argv": normalized_argv,
    });

    let Ok(mut serialized) = serde_json::to_string(&line) else {
        return;
    };
    // One `write_all` call for the whole line plus its newline, not
    // `writeln!` (which would emit the body and `"\n"` as two separate
    // `write(2)` calls on an O_APPEND fd, guaranteeing two concurrent
    // shguard invocations could interleave and corrupt a line).
    // `write_all` still loops on a partial `write(2)` (possible on a full
    // disk or a signal-interrupted call), so this makes interleaving
    // essentially never happen for a normal-sized line rather than
    // formally impossible for one of unbounded size.
    serialized.push('\n');

    let Ok(mut file) = open_log_file(path) else {
        return;
    };
    let _ = file.write_all(serialized.as_bytes());
}

/// Opens `path` for appending, creating it if absent with permissions
/// restricted to the owner (`0600`, unix only) rather than the
/// `OpenOptions` default of `0666 & !umask` (typically world-readable):
/// the log records every evaluated command verbatim, which routinely
/// contains inline secrets (`export TOKEN=...`, `curl -H "Authorization:
/// ..."`). `.mode()` only applies at creation time, so it never fights an
/// existing file's own permissions.
fn open_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Renders one normalised word for the log line: its resolved text, or a
/// `<unresolvable:...>` placeholder naming why it couldn't be folded —
/// there is no existing string form of [`Resolution`] to reuse (unlike
/// `matched_rule_id`/`reason`/`deny_message`, which already have one via
/// [`Verdict`]'s own accessors).
fn word_to_string(word: &NormalizedWord) -> String {
    match word.resolution() {
        Resolution::Resolved(value) => value.clone(),
        Resolution::Unresolvable(kind) => format!("<unresolvable:{kind:?}>"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::normalize::UnresolvableKind;
    use crate::verdict::RuleId;
    use tempfile::tempdir;

    #[test]
    fn appends_one_jsonl_line_with_expected_shape() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let verdict = Verdict::block(
            crate::verdict::Reason::new("matches blocklist rule rm-rf-root"),
            vec![
                NormalizedWord::resolved("rm"),
                NormalizedWord::resolved("-rf"),
            ],
            Some(RuleId::new("rm-recursive-force-dangerous-target")),
        );
        append(&log_path, "rm -rf /", &verdict);

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(value["command"], "rm -rf /");
        assert_eq!(value["decision"], "Block");
        assert_eq!(
            value["matched_rule_id"],
            "rm-recursive-force-dangerous-target"
        );
        assert_eq!(value["normalized_argv"], serde_json::json!(["rm", "-rf"]));
    }

    #[test]
    fn appends_across_multiple_calls_rather_than_truncating() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        append(&log_path, "echo one", &Verdict::allow(Vec::new()));
        append(&log_path, "echo two", &Verdict::allow(Vec::new()));

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    #[test]
    fn unresolvable_word_renders_as_a_placeholder_not_a_panic() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let verdict = Verdict::ask(
            crate::verdict::Reason::new("unresolvable construct"),
            vec![NormalizedWord::unresolvable(
                UnresolvableKind::ParameterExpansion,
            )],
        );
        append(&log_path, "rm $X", &verdict);

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(value["decision"], "Ask");
        assert!(
            value["normalized_argv"][0]
                .as_str()
                .unwrap()
                .starts_with("<unresolvable:")
        );
    }

    // `word_to_string`'s placeholder text is derived from `UnresolvableKind`'s
    // `Debug` output, which is not a stability contract -- a future rename
    // of a variant would silently change the persisted log format with
    // nothing else here to catch it. Pinning the exact strings for a few
    // representative variants makes such a rename a visible test failure.
    #[test]
    fn unresolvable_placeholder_text_is_pinned_for_representative_kinds() {
        assert_eq!(
            word_to_string(&NormalizedWord::unresolvable(
                UnresolvableKind::ParameterExpansion
            )),
            "<unresolvable:ParameterExpansion>"
        );
        assert_eq!(
            word_to_string(&NormalizedWord::unresolvable(
                UnresolvableKind::CommandSubstitution
            )),
            "<unresolvable:CommandSubstitution>"
        );
        assert_eq!(
            word_to_string(&NormalizedWord::unresolvable(UnresolvableKind::NonUtf8)),
            "<unresolvable:NonUtf8>"
        );
    }

    #[test]
    #[cfg(unix)]
    fn creates_the_log_file_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");
        append(&log_path, "echo hi", &Verdict::allow(Vec::new()));

        // `mode & 0o077 == 0` (no group/other bits), not an exact `0o600`
        // equality: `.mode()` is still subject to umask, so an unusual
        // umask that masks an OWNER bit (never a real-world 022/077 one --
        // those never touch owner bits, since owner bits are already the
        // minimum this call requests) could in principle make an exact
        // comparison flaky without weakening the actual security property
        // under test.
        let mode = std::fs::metadata(&log_path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the log file must not be group/other-readable (it records commands \
             verbatim, which routinely include inline secrets), got {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn a_missing_parent_directory_is_silently_dropped_not_a_panic() {
        // Fail-open on the logging side: this must not panic, and must not
        // be observable by the caller in any way other than "no line
        // appeared" -- there is no error return from `append` to check.
        let unwritable = std::path::Path::new("/nonexistent-shguard-test-dir/decisions.jsonl");
        append(unwritable, "echo hi", &Verdict::allow(Vec::new()));
    }

    /// Regression test for a HIGH bug: `crate::analyze_with_policy`
    /// (`src/lib.rs`) used to call `append` *inside*
    /// `watchdog::bounded`'s closure, so a `decision_log_path` target that
    /// blocked past the internal gate-evaluation watchdog's own timeout
    /// tripped that watchdog and silently replaced an already-computed,
    /// correct verdict with a fail-closed `Ask`. `append` now runs on the
    /// value `watchdog::bounded` already returned, so it can no longer
    /// affect the verdict at all, no matter how long it blocks.
    ///
    /// Constructs a `Policy` directly rather than through `Policy::load`:
    /// loading now rejects a `decision_log_path` that already names a FIFO
    /// at config-load time (`src/config.rs`), which is exactly the
    /// pre-existing-non-regular-target shape this test needs to force a
    /// blocking write. Direct construction is the only way left to
    /// exercise that write path at all.
    #[test]
    #[cfg(unix)]
    fn a_blocked_log_target_does_not_corrupt_the_verdict() {
        let dir = tempdir().unwrap();
        let fifo_path = dir.path().join("decisions.fifo");
        let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        // SAFETY: a valid, nul-terminated path and standard owner-only
        // permission bits; no aliasing/lifetime hazards. Same call
        // `tests/decision_log.rs`'s own FIFO test already makes.
        let rc = unsafe { libc_mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo should succeed in a fresh tempdir");

        let reader_fifo_path = fifo_path.clone();
        let reader = std::thread::spawn(move || {
            // Longer than `watchdog::bounded`'s own internal timeout
            // (`src/watchdog.rs`, 2s): the pre-fix code would already have
            // corrupted the verdict into a fail-closed `Ask` by the time
            // this reader shows up and unblocks the write.
            std::thread::sleep(std::time::Duration::from_millis(2_500));
            let mut file = std::fs::File::open(&reader_fifo_path).unwrap();
            let mut contents = String::new();
            std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
            contents
        });

        let policy = crate::config::Policy::for_test_with_decision_log_path(fifo_path);
        let verdict = crate::analyze_with_policy("rm -rf /", &policy, &FileDecisionLog);
        assert_eq!(
            verdict.decision(),
            Decision::Block,
            "a blocked log write must not corrupt the already-computed verdict into a \
             fail-closed Ask, got: {verdict:?}"
        );

        let logged = reader.join().unwrap();
        let value: serde_json::Value = serde_json::from_str(logged.trim()).unwrap();
        assert_eq!(value["decision"], "Block");
    }

    #[cfg(unix)]
    unsafe extern "C" {
        #[link_name = "mkfifo"]
        fn libc_mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    }
}
