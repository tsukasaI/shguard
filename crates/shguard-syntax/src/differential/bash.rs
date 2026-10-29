//! Oracle 3: `bash -n` (syntax acceptance only).
//!
//! The binary is `SHGUARD_DIFF_BASH` (default `bash` on PATH). It must be
//! bash 5 or newer: macOS `/bin/bash` is 3.2 and parses differently, so an
//! older bash fails the test instead of skipping it.

use super::{bash_program, corpus, require_bash5, run};

#[test]
#[ignore = "needs shfmt and bash 5 (nix develop)"]
fn bash_n_accepts_accepted_inputs() {
    let path = bash_program();
    require_bash5(&path);
    let program = path.to_str().expect("bash path is UTF-8");
    let corpus = corpus();
    let mut failures = Vec::new();
    for case in &corpus.cases {
        let output = run(program, &["-n"], &case.input);
        if !output.status.success() {
            failures.push(format!(
                "input: {:?}\n  bash -n exited with {}: {}",
                case.input,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    corpus.report("bash -n");
    assert!(
        failures.is_empty(),
        "{} of {} accepted inputs rejected by bash -n:\n{}",
        failures.len(),
        corpus.cases.len(),
        failures.join("\n")
    );
}
