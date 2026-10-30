//! The `shguard` binary and its composition root: it reads argv, the
//! environment, files and stdin, calls the pure code, and writes the result.
//! Nothing below this file touches the environment.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use shguard::catalog::{EMBEDDED, LoadError, Source, load};
use shguard::config::{Location, Settings, locate, settings};
use shguard::hook::{panic_output, to_bytes};
use shguard::respond::{INPUT_CAP, respond};

const USAGE: &str = "\
usage: shguard                          run as a Claude Code PreToolUse hook (JSON on stdin)
       shguard check <catalog.toml>...  check catalog files
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
    let answer = respond(&input, loaded.as_ref().map_err(Vec::as_slice));
    let mut out = std::io::stdout().lock();
    match out.write_all(&to_bytes(&answer)).and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            drop(writeln!(
                std::io::stderr().lock(),
                "shguard: cannot write the hook answer: {e}"
            ));
            ExitCode::from(EXIT_BLOCK)
        }
    }
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
