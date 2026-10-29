//! The `shguard` binary and its composition root: it reads files, calls the
//! loader and renders the outcome. Nothing below this file touches the
//! environment.

use std::io::Write;
use std::process::ExitCode;

use shguard::catalog::{Source, load};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut err = std::io::stderr().lock();
    match args.split_first() {
        Some((cmd, files)) if cmd == "check" && !files.is_empty() => check(files, &mut err),
        _ => {
            drop(writeln!(err, "usage: shguard check <catalog.toml>..."));
            ExitCode::FAILURE
        }
    }
}

/// Loads the catalog files and prints each problem on its own line.
fn check(files: &[String], err: &mut impl Write) -> ExitCode {
    let mut texts = Vec::new();
    let mut failed = false;
    for path in files {
        match std::fs::read_to_string(path) {
            Ok(text) => texts.push((path.as_str(), text)),
            Err(e) => {
                drop(writeln!(err, "{path}: {e}"));
                failed = true;
            }
        }
    }
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
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
