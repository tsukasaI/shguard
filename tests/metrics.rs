//! Prints the R0 metrics of the evaluation-core redesign (docs/rfc-redesign.md,
//! issue #836) in plain `cargo test` output.
//!
//! `harness = false` (see `[[test]]` in `Cargo.toml`): libtest captures the
//! output of a passing test, so a normal test could only show the metrics
//! under `--nocapture`. This target's `main` prints them unconditionally and
//! exits nonzero when a corpus cannot be read. `scripts/metrics` runs it
//! alone. The metric definitions, including the Unknown-kind mapping, live in
//! `tests/common/metrics.rs`.

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/golden.rs"]
#[allow(dead_code)]
mod golden;
#[path = "common/metrics.rs"]
mod metrics;

fn main() {
    match metrics::report(&golden::golden_dir()) {
        Ok(lines) => {
            println!("metrics (docs/rfc-redesign.md R0, issue #836):");
            for line in lines {
                println!("metrics: {line}");
            }
        }
        Err(err) => {
            eprintln!("metrics: {err}");
            std::process::exit(1);
        }
    }
}
