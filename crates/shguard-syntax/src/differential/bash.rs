//! Oracle 3: `bash -n` (syntax acceptance only).
//!
//! The binary is `SHGUARD_DIFF_BASH` (default `bash` on PATH). It must be
//! bash 5 or newer: macOS `/bin/bash` is 3.2 and parses differently, so an
//! older bash fails the test instead of skipping it.

use super::{corpus, run};

fn bash_program() -> String {
    std::env::var("SHGUARD_DIFF_BASH").unwrap_or_else(|_| "bash".to_string())
}

fn require_bash5(program: &str) {
    let output = run(program, &["-c", "echo \"${BASH_VERSINFO[0]}\""], "");
    assert!(output.status.success(), "{program} -c failed");
    let major: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{program} did not print a bash major version"));
    assert!(
        major >= 5,
        "{program} is bash {major}; bash 5 or newer is required (use `nix develop`)"
    );
}

#[test]
#[ignore = "needs shfmt and bash 5 (nix develop)"]
fn bash_n_accepts_accepted_inputs() {
    let program = bash_program();
    require_bash5(&program);
    let corpus = corpus();
    let mut failures = Vec::new();
    for case in &corpus.cases {
        let output = run(&program, &["-n"], &case.input);
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
