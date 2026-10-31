//! The `shguard` binary and its composition root: it reads argv, the
//! environment, files and stdin, calls the pure code, and writes the result.
//! Nothing below this file touches the environment.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shguard::catalog::{EMBEDDED, LoadError, Source, load};
use shguard::config::{Location, Settings, locate, settings};
use shguard::hook::{Response, panic_output, render, to_bytes};
use shguard::respond::{INPUT_CAP, answer};
use shguard::{decision_log, init};

const USAGE: &str = "\
usage: shguard                          run as a Claude Code PreToolUse hook (JSON on stdin)
       shguard check <catalog.toml>...  check catalog files
       shguard init                     write a config and print the settings.json hook entry
       shguard --help | --version
";

/// Exit status when the hook cannot write its answer, or when it is called
/// wrongly. Claude Code treats 2 as blocking.
const EXIT_BLOCK: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.split_first() {
        None => hook(),
        Some((cmd, rest)) if cmd == "check" && !rest.is_empty() => {
            let paths: Vec<PathBuf> = rest.iter().map(PathBuf::from).collect();
            check(&paths, &mut std::io::stderr().lock())
        }
        Some((cmd, [])) if cmd == "init" => init_config(),
        Some((flag, [])) if flag == "--help" || flag == "-h" => {
            drop(std::io::stdout().lock().write_all(USAGE.as_bytes()));
            ExitCode::SUCCESS
        }
        Some((flag, [])) if flag == "--version" || flag == "-V" => {
            drop(writeln!(
                std::io::stdout().lock(),
                "shguard {}",
                env!("CARGO_PKG_VERSION")
            ));
            ExitCode::SUCCESS
        }
        Some(_) => usage_error(),
    }
}

fn usage_error() -> ExitCode {
    drop(std::io::stderr().lock().write_all(USAGE.as_bytes()));
    ExitCode::from(EXIT_BLOCK)
}

/// Hook mode: exit 0 once the answer is written and flushed, 2 if it cannot
/// be written.
fn hook() -> ExitCode {
    if std::io::stdin().is_terminal() {
        return usage_error();
    }
    // A panic exits 101, which Claude Code treats as a non-blocking error and
    // runs the tool. Answer with a deny instead; the hook never returns.
    std::panic::set_hook(Box::new(|_| {
        let mut out = std::io::stdout().lock();
        let written = out
            .write_all(&panic_output())
            .and_then(|()| out.flush())
            .is_ok();
        std::process::exit(if written { 0 } else { i32::from(EXIT_BLOCK) });
    }));
    let mut input = Vec::new();
    let cap = u64::try_from(INPUT_CAP + 1).unwrap_or(u64::MAX);
    if std::io::stdin()
        .lock()
        .take(cap)
        .read_to_end(&mut input)
        .is_err()
    {
        // Whatever was read is cut off mid-stream; answer as for bad input.
        input.clear();
    }
    let loaded = load_settings();
    let (command, response) = answer(&input, loaded.as_ref().map_err(Vec::as_slice));
    let mut out = std::io::stdout().lock();
    match out
        .write_all(&to_bytes(&render(&response)))
        .and_then(|()| out.flush())
    {
        Ok(()) => {
            // The answer is out; the log can no longer change it, and a log
            // failure is only reported.
            if let Ok(Settings {
                decision_log: Some(path),
                ..
            }) = &loaded
                && let Err(e) = log_bounded(path, command, response)
            {
                drop(writeln!(
                    std::io::stderr().lock(),
                    "shguard: cannot write the decision log {}: {e}",
                    path.display()
                ));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            drop(writeln!(
                std::io::stderr().lock(),
                "shguard: cannot write the hook answer: {e}"
            ));
            ExitCode::from(EXIT_BLOCK)
        }
    }
}

/// How long the hook waits for the decision log before it exits anyway.
const LOG_WAIT: Duration = Duration::from_millis(500);

/// Writes the log line on a helper thread and waits at most [`LOG_WAIT`].
/// An open that blocks (a FIFO with no reader, a hung network mount) would
/// otherwise keep the hook from exiting until Claude Code's timeout, which
/// discards the answer already written. Returning from `main` ends the
/// helper thread.
fn log_bounded(path: &Path, command: Option<String>, response: Response) -> std::io::Result<()> {
    let (tx, rx) = mpsc::channel();
    let owned = path.to_path_buf();
    std::thread::Builder::new()
        .name("decision-log".to_owned())
        .spawn(move || drop(tx.send(append_log(&owned, command.as_deref(), &response))))?;
    match rx.recv_timeout(LOG_WAIT) {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the log did not open or write in time",
        )),
    }
}

/// Appends one line to the decision log. Only a regular file that is the
/// path itself (not reached through a symlink) is written; the directory
/// must already exist.
fn append_log(path: &Path, command: Option<&str>, response: &Response) -> std::io::Result<()> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let Some(line) = decision_log::entry(secs, command, response)
        .as_ref()
        .and_then(decision_log::line)
    else {
        return Ok(());
    };
    let refuse = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_owned());
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("the path is a symlink"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(refuse("the path is not a regular file"));
    }
    // A symlink swapped in between the check above and the open would have
    // been followed: the path must still name the file that was opened.
    let at_path = std::fs::symlink_metadata(path)?;
    if at_path.file_type().is_symlink() || !same_file(&opened, &at_path) {
        return Err(refuse("the path changed while the log was opened"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    file.write_all(&line)
}

/// The opened file is the file at the path and has no other name: a hard
/// link (`ln ~/.bashrc log.jsonl`) would pass every symlink check.
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino() && a.nlink() == 1
}

/// Best effort off unix: no file identity is compared.
#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.is_file() && b.is_file() && a.len() == b.len()
}

/// `shguard init`: writes the config to where the hook will look for it,
/// never over an existing file, and prints the settings.json hook entry.
fn init_config() -> ExitCode {
    let mut err = std::io::stderr().lock();
    let path = match locate(std::env::var_os("SHGUARD_CONFIG"), std::env::var_os("HOME")) {
        Location::Default(p) | Location::Explicit(p) => p,
        Location::Relative(p) => {
            drop(writeln!(
                err,
                "shguard init: SHGUARD_CONFIG must be an absolute path: {}",
                p.display()
            ));
            return ExitCode::FAILURE;
        }
        Location::Nowhere => {
            drop(writeln!(
                err,
                "shguard init: set HOME or SHGUARD_CONFIG to say where the config goes"
            ));
            return ExitCode::FAILURE;
        }
    };
    if std::fs::symlink_metadata(&path).is_ok() {
        drop(writeln!(
            err,
            "shguard init: {} exists; move it aside first (a shguard 0.9 config cannot be read by this version)",
            path.display()
        ));
        return ExitCode::FAILURE;
    }
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        })
        .and_then(|mut f| f.write_all(init::CONFIG_TEXT.as_bytes()));
    if let Err(e) = written {
        drop(writeln!(
            err,
            "shguard init: cannot write {}: {e}",
            path.display()
        ));
        return ExitCode::FAILURE;
    }
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| "shguard".to_owned());
    let snippet = serde_json::to_string_pretty(&init::settings_snippet(&exe)).unwrap_or_default();
    drop(writeln!(
        std::io::stdout().lock(),
        "shguard init: wrote {}\n\n\
         Add this hook to ~/.claude/settings.json (merge it into an existing \"hooks\" key).\n\
         \"onFailure\": \"block\" makes a crash or timeout refuse the call; it needs Claude Code 2.1.295 or later.\n\n\
         {snippet}",
        path.display()
    ));
    ExitCode::SUCCESS
}

/// Reads the config named by the environment and merges it with the embedded
/// catalog. Only a missing file at the default path means "no config".
fn load_settings() -> Result<Settings, Vec<LoadError>> {
    let (path, optional) =
        match locate(std::env::var_os("SHGUARD_CONFIG"), std::env::var_os("HOME")) {
            Location::Nowhere => return settings(EMBEDDED, None),
            Location::Default(p) => (p, true),
            Location::Explicit(p) => (p, false),
            Location::Relative(p) => {
                return Err(vec![LoadError::Read {
                    file: p.to_string_lossy().into_owned(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "SHGUARD_CONFIG must be an absolute path",
                    ),
                }]);
            }
        };
    let name = path.to_string_lossy().into_owned();
    match std::fs::read_to_string(&path) {
        Ok(text) => settings(EMBEDDED, Some((&name, &text))),
        Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => settings(EMBEDDED, None),
        Err(source) => Err(vec![LoadError::Read { file: name, source }]),
    }
}

/// Loads the catalog files and prints each problem on its own line. If a file
/// cannot be read the catalog is not loaded, since the missing rows would
/// only produce follow-on errors.
fn check(files: &[PathBuf], err: &mut impl Write) -> ExitCode {
    let mut texts = Vec::new();
    let mut failed = false;
    for path in files {
        let name = path.to_string_lossy().into_owned();
        match std::fs::read_to_string(path) {
            Ok(text) => texts.push((name, text)),
            Err(e) => {
                drop(writeln!(err, "{name}: {e}"));
                failed = true;
            }
        }
    }
    if !failed {
        let sources: Vec<Source<'_>> = texts
            .iter()
            .map(|(name, text)| Source { name, text })
            .collect();
        if let Err(errors) = load(&sources) {
            for e in errors {
                drop(writeln!(err, "{e}"));
            }
            failed = true;
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
