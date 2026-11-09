//! The opt-in decision log: one JSON object per Bash decision, appended as
//! one line to the file `decision_log` names. `main` chooses the path and the
//! time; this module reads nothing from the environment.
//!
//! A line holds the command text as the hook received it, so the file can
//! hold secrets that were typed on a command line. It records what shguard
//! answered; it says nothing about whether a command is harmless.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::hook::{Response, WireDecision};

/// The log line for one answer, or `None` when there is nothing to log
/// (a non-Bash tool gets no decision). `unix_secs` is the time of the
/// answer; `command` is the Bash command, if the input had one.
#[must_use]
pub fn entry(unix_secs: u64, command: Option<&str>, response: &Response) -> Option<Value> {
    let WireDecision { word, reason } = response.decision()?;
    Some(json!({
        "ts": unix_secs,
        "decision": word,
        "reason": reason,
        "command": command,
    }))
}

/// The bytes of one log line, newline-terminated. Serializing a [`Value`]
/// cannot fail; if it somehow did, the line is dropped.
#[must_use]
pub fn line(entry: &Value) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec(entry).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

/// Appends `line` to the log at `path`. Only a regular file that is the path
/// itself (not reached through a symlink, with no other hard link) is
/// written, and a file left readable by others is made private first; the
/// directory must already exist.
///
/// # Errors
///
/// `InvalidInput` when the path is a symlink, is not a regular file, or
/// changed while it was opened; otherwise the I/O error of the open or write.
pub fn append(path: &Path, line: &[u8]) -> io::Result<()> {
    let refuse = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, why.to_owned());
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("the path is a symlink"));
    }
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK stays on the fd: clearing it needs fcntl (unsafe, forbidden
        // here) and a regular file ignores it; a FIFO with no reader fails the
        // open with ENXIO instead of blocking.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(refuse_open_error)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(refuse("the path is not a regular file"));
    }
    // O_NOFOLLOW refuses a swapped-in symlink; a regular file or hard link
    // swapped in between the check above and the open would still open: the
    // path must still name the file that was opened.
    let at_path = fs::symlink_metadata(path)?;
    if at_path.file_type().is_symlink() || !same_file(&opened, &at_path) {
        return Err(refuse("the path changed while the log was opened"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    file.write_all(line)
}

/// ELOOP (a symlink swapped in after the check) and ENXIO (a FIFO with no
/// reader) become the same refusal as the checks in [`append`].
fn refuse_open_error(e: io::Error) -> io::Error {
    #[cfg(unix)]
    {
        if e.raw_os_error() == Some(libc::ELOOP) {
            return io::Error::new(
                io::ErrorKind::InvalidInput,
                "the path is or passes through a symlink",
            );
        }
        if e.raw_os_error() == Some(libc::ENXIO) {
            return io::Error::new(
                io::ErrorKind::InvalidInput,
                "the path is not a regular file",
            );
        }
    }
    e
}

/// The opened file is the file at the path and has no other name: a hard
/// link (`ln ~/.bashrc log.jsonl`) would pass every symlink check.
#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino() && a.nlink() == 1
}

/// Best effort off unix: no file identity is compared.
#[cfg(not(unix))]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.is_file() && b.is_file() && a.len() == b.len()
}

/// Runs `write` on a helper thread and waits at most `wait`. An open that
/// blocks (a hung network mount; off unix, a FIFO with no reader) would
/// otherwise keep the hook from exiting until Claude Code's timeout, which
/// discards the answer already written.
///
/// The helper thread is detached: after `TimedOut`, `write` may still run to
/// completion. Use only in a process that exits soon after.
///
/// # Errors
///
/// `TimedOut` when `write` has not finished within `wait`; otherwise
/// `write`'s own result, or the error from spawning the thread.
pub fn log_bounded<W>(wait: Duration, write: W) -> io::Result<()>
where
    W: FnOnce() -> io::Result<()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("decision-log".to_owned())
        .spawn(move || drop(tx.send(write())))?;
    match rx.recv_timeout(wait) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the log did not open or write in time",
        )),
        Err(RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("the log writer stopped without a result"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{e:?}"),
        }
    }

    fn kind(r: io::Result<()>) -> Option<io::ErrorKind> {
        r.err().map(|e| e.kind())
    }

    #[test]
    fn append_adds_one_line_per_call() {
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("log.jsonl");
        ok(append(&log, b"{\"a\":1}\n"));
        ok(append(&log, b"{\"a\":2}\n"));
        assert_eq!(ok(fs::read_to_string(&log)), "{\"a\":1}\n{\"a\":2}\n");
    }

    #[test]
    fn a_missing_directory_is_not_created() {
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("absent").join("log.jsonl");
        assert!(append(&log, b"x\n").is_err());
        assert!(!dir.path().join("absent").exists());
    }

    #[test]
    fn a_directory_at_the_path_is_an_error() {
        let dir = ok(tempfile::tempdir());
        assert!(append(dir.path(), b"x\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_is_not_written_through() {
        let dir = ok(tempfile::tempdir());
        let target = dir.path().join("target.txt");
        ok(fs::write(&target, "keep\n"));
        let log = dir.path().join("log.jsonl");
        ok(std::os::unix::fs::symlink(&target, &log));
        assert_eq!(
            kind(append(&log, b"x\n")),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(ok(fs::read_to_string(&target)), "keep\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_linked_log_is_not_written_through() {
        let dir = ok(tempfile::tempdir());
        let target = dir.path().join("target.txt");
        ok(fs::write(&target, "keep\n"));
        let log = dir.path().join("log.jsonl");
        ok(fs::hard_link(&target, &log));
        assert_eq!(
            kind(append(&log, b"x\n")),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(ok(fs::read_to_string(&target)), "keep\n");
    }

    #[cfg(unix)]
    #[test]
    fn same_file_needs_the_same_inode_and_one_name() {
        let dir = ok(tempfile::tempdir());
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        ok(fs::write(&a, ""));
        ok(fs::write(&b, ""));
        let (ma, mb) = (ok(fs::metadata(&a)), ok(fs::metadata(&b)));
        assert!(same_file(&ma, &ma));
        // The swapped-in file (TOCTOU) is a different inode.
        assert!(!same_file(&ma, &mb));
        // A second name for the same inode is refused.
        ok(fs::hard_link(&a, dir.path().join("c")));
        let linked = ok(fs::metadata(&a));
        assert!(!same_file(&linked, &linked));
    }

    #[cfg(unix)]
    #[test]
    fn a_new_log_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("log.jsonl");
        ok(append(&log, b"x\n"));
        assert_eq!(ok(fs::metadata(&log)).permissions().mode() & 0o077, 0);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_log_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("log.jsonl");
        ok(fs::write(&log, "old\n"));
        ok(fs::set_permissions(&log, fs::Permissions::from_mode(0o644)));
        ok(append(&log, b"new\n"));
        assert_eq!(ok(fs::metadata(&log)).permissions().mode() & 0o077, 0);
        assert_eq!(ok(fs::read_to_string(&log)), "old\nnew\n");
    }

    #[test]
    fn log_bounded_returns_the_writers_result() {
        assert!(log_bounded(Duration::from_secs(30), || Ok(())).is_ok());
        let failed = log_bounded(Duration::from_secs(30), || {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert_eq!(kind(failed), Some(io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn log_bounded_times_out_on_a_writer_that_blocks() {
        let (release, blocked) = mpsc::channel::<()>();
        let result = log_bounded(Duration::from_millis(20), move || {
            let _released = blocked.recv_timeout(Duration::from_secs(30));
            Ok(())
        });
        assert_eq!(kind(result), Some(io::ErrorKind::TimedOut));
        drop(release);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_not_created_through() {
        let dir = ok(tempfile::tempdir());
        let target = dir.path().join("absent-target");
        let log = dir.path().join("log.jsonl");
        ok(std::os::unix::fs::symlink(&target, &log));
        assert_eq!(
            kind(append(&log, b"x\n")),
            Some(io::ErrorKind::InvalidInput)
        );
        assert!(!target.exists(), "the symlink was followed and created");
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_the_path_is_refused_without_writing() {
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("log.jsonl");
        let made = std::process::Command::new("mkfifo").arg(&log).status();
        assert!(matches!(made, Ok(s) if s.success()), "mkfifo: {made:?}");
        assert_eq!(
            kind(append(&log, b"x\n")),
            Some(io::ErrorKind::InvalidInput)
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_errors_for_a_symlink_or_a_fifo_are_refusals() {
        let kind_of = |errno| refuse_open_error(io::Error::from_raw_os_error(errno)).kind();
        assert_eq!(kind_of(libc::ELOOP), io::ErrorKind::InvalidInput);
        assert_eq!(kind_of(libc::ENXIO), io::ErrorKind::InvalidInput);
        assert_eq!(kind_of(libc::EACCES), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn entries_append_one_line_each_and_skip_no_decision() {
        let dir = ok(tempfile::tempdir());
        let log = dir.path().join("decisions.jsonl");
        let answers = [
            (Some("ls -la"), Response::Allow(String::new())),
            (Some("rm -rf /"), Response::Deny(String::new())),
            (None, Response::NoDecision),
            (Some("unknowntool x"), Response::Ask(String::new())),
        ];
        for (command, response) in &answers {
            let bytes = entry(1, *command, response).as_ref().and_then(line);
            if let Some(bytes) = bytes {
                ok(append(&log, &bytes));
            }
        }
        let text = ok(fs::read_to_string(&log));
        let decisions: Vec<Value> = text
            .lines()
            .map(|l| ok(serde_json::from_str::<Value>(l)))
            .collect();
        assert_eq!(decisions.len(), 3);
        assert_eq!(decisions[0]["decision"], "allow");
        assert_eq!(decisions[1]["decision"], "deny");
        assert_eq!(decisions[2]["decision"], "ask");
    }

    #[test]
    fn entries() {
        assert_eq!(entry(1, Some("ls"), &Response::NoDecision), None);
        let Some(e) = entry(7, Some("ls -l"), &Response::Allow("r".to_owned())) else {
            panic!("an Allow is logged");
        };
        assert_eq!(e["ts"], 7);
        assert_eq!(e["decision"], "allow");
        assert_eq!(e["reason"], "r");
        assert_eq!(e["command"], "ls -l");
        let Some(e) = entry(7, None, &Response::Ask("bad".to_owned())) else {
            panic!("an Ask is logged");
        };
        assert_eq!(e["decision"], "ask");
        assert!(e["command"].is_null());
        let Some(e) = entry(7, Some("rm -rf /"), &Response::Deny("no".to_owned())) else {
            panic!("a Deny is logged");
        };
        assert_eq!(e["decision"], "deny");
    }

    #[test]
    fn a_line_is_one_json_object() {
        let Some(e) = entry(1, Some("echo 'a\nb'"), &Response::Allow(String::new())) else {
            panic!("logged");
        };
        let Some(bytes) = line(&e) else {
            panic!("serializes");
        };
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
    }
}
