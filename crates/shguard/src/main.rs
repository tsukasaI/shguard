//! The `shguard` binary and its composition root: it reads files, calls the
//! loader and renders the outcome. Nothing below this file touches the
//! environment.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use shguard::catalog::{Source, load};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut err = std::io::stderr().lock();
    match args.split_first() {
        Some((cmd, files)) if cmd == "check" && !files.is_empty() => {
            let paths: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
            check(&paths, &mut err)
        }
        _ => {
            drop(writeln!(err, "usage: shguard check <catalog.toml>..."));
            ExitCode::FAILURE
        }
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
