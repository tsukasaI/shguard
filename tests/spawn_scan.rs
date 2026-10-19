//! Source scan guarding the `shguard` spawn env scrub.
//!
//! `clippy.toml`'s `disallowed-methods` ban covers only assert_cmd's
//! `cargo_bin` entry points. Cargo's per-binary path env var read through
//! `env!`, or a `Command::new` fed by the program path of an existing
//! command, would reach the binary without passing through
//! `tests/common/cmd.rs::shguard()`, and so bypass its env scrub. This test
//! fails on any such occurrence in a `.rs` file under `tests/` other than
//! `tests/common/cmd.rs` itself.
//!
//! The needles are built with `concat!`, and the prose above avoids spelling
//! them, so this file does not match its own scan.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

const NEEDLES: [&str; 2] = [concat!("CARGO_BIN", "_EXE_"), concat!(".get_", "program()")];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("tests dir should be readable") {
        let entry = entry.expect("dir entry should be readable");
        let file_type = entry.file_type().expect("file type should be readable");
        let path = entry.path();
        if file_type.is_dir() {
            rust_files(&path, out);
        // Directory symlinks are not followed; file symlinks are, as cargo does.
        } else if (file_type.is_file() || (file_type.is_symlink() && path.is_file()))
            && path.extension().is_some_and(|ext| ext == "rs")
        {
            out.push(path);
        }
    }
}

#[test]
fn no_spawn_path_bypasses_the_env_scrub() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let allowed = tests_dir.join("common").join("cmd.rs");
    let mut files = Vec::new();
    rust_files(&tests_dir, &mut files);
    files.sort();

    let mut hits = Vec::new();
    for file in files.iter().filter(|f| **f != allowed) {
        let text = fs::read_to_string(file).expect("test source should be UTF-8");
        for (idx, line) in text.lines().enumerate() {
            if NEEDLES.iter().any(|needle| line.contains(needle)) {
                let rel = file.strip_prefix(&tests_dir).unwrap_or(file);
                hits.push(format!(
                    "tests/{}:{}: {}",
                    rel.display(),
                    idx + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "spawn the binary via tests/common/cmd.rs, not directly. Comments and string \
         literals count too; if a needle must be named, split it with concat!:\n{}",
        hits.join("\n")
    );
}
