//! Coverage metrics (issue #95): README publishes three coverage numbers
//! (bypass classes closed, regression test count, benign corpus size).
//! This test computes each mechanically from the actual test sources and
//! asserts they match what README.md states, so a maintainer who adds a
//! case without updating README (or vice versa) fails CI rather than
//! silently drifting -- "sourced from CI, not hand-updated" per the
//! issue's own acceptance criterion, without requiring dynamic badge
//! infrastructure this project has nowhere to host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

fn read_repo_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path:?}: {err}"))
}

/// Counts `Decision::` literal occurrences across the whole of
/// `tests/guardfall.rs`. NOT scoped to `let cases: &[...] = &[...];`
/// table literals specifically: this file genuinely mixes two testing
/// styles -- simple `(command, Decision::X)` tables (one literal per
/// pinned case) AND combinatorial loop tests that assert a single
/// `Decision::X` literal once per iteration over a cross product (e.g.
/// `guardfall_shell_init_directory_token_cases` asserts `Decision::Ask`
/// inside a nested loop over 11 directories x 2 suffixes x 4 commands =
/// 88 real assertions from ONE literal). An array-scoped count would
/// systematically miss every one of those combinatorial assertions
/// (found by fable review: an earlier, array-scoped version of this
/// function undercounted by exactly the number of such loop tests).
/// There is no purely textual way to recover the TRUE assertion count
/// for a combinatorial loop without executing it, so this function
/// reports the simpler, exactly-and-mechanically-verifiable unit
/// instead: total `Decision::` literals, which is a stable LOWER BOUND
/// on true assertion count, not an attempt at the true count itself --
/// see the README wording this backs, which describes the metric as
/// literal occurrences, not "pinned cases".
fn count_guardfall_cases() -> usize {
    let source = read_repo_file("tests/guardfall.rs");
    ["Decision::Allow", "Decision::Ask", "Decision::Block"]
        .iter()
        .map(|variant| source.matches(variant).count())
        .sum()
}

/// Counts `[[case]]` table headers in `tests/bypass_corpus.toml`.
fn count_bypass_corpus_cases() -> usize {
    read_repo_file("tests/bypass_corpus.toml")
        .lines()
        .filter(|line| line.trim() == "[[case]]")
        .count()
}

/// Counts benign-command entries in `tests/benign_corpus.rs`: every line
/// whose first non-whitespace character is `"`, but ONLY within the
/// `commands: &[&str] = &[ ... ];` array literal itself -- scoped this
/// way (not a bare whole-file scan) because the test body below the
/// array also has a `"`-first line (its `assert_eq!` format string),
/// which a whole-file scan would miscount as a 60th command when the
/// array only holds 59.
fn count_benign_corpus_commands() -> usize {
    let source = read_repo_file("tests/benign_corpus.rs");
    let mut in_array = false;
    let mut count = 0;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("let commands") {
            in_array = true;
            continue;
        }
        if in_array && trimmed == "];" {
            break;
        }
        if in_array && trimmed.starts_with('"') {
            count += 1;
        }
    }
    count
}

/// Extracts the integer immediately following `label` in `readme` (the
/// README's own published metric line, e.g. `label = "Regression test
/// count:** "` finds `305` in `"...count:** 305 ..."`). Panics with a
/// clear message if the label isn't found or isn't followed by digits --
/// a metrics section that silently fails to parse is exactly the kind of
/// staleness this test exists to catch loudly, not swallow.
fn extract_readme_metric(readme: &str, label: &str) -> usize {
    let after_label = readme
        .find(label)
        .unwrap_or_else(|| panic!("README.md coverage section is missing the {label:?} label"))
        + label.len();
    let digits: String = readme[after_label..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("no number found after {label:?} in README.md"))
}

#[test]
fn regression_test_count_matches_readme() {
    let readme = read_repo_file("README.md");
    let published = extract_readme_metric(&readme, "Regression test count:**");
    let computed = count_guardfall_cases() + count_bypass_corpus_cases();
    assert_eq!(
        computed,
        published,
        "README.md's published regression test count ({published}) doesn't match the actual \
         count ({computed} = {} guardfall.rs cases + {} bypass_corpus.toml cases) -- update \
         whichever one is stale",
        count_guardfall_cases(),
        count_bypass_corpus_cases()
    );
}

#[test]
fn benign_corpus_size_matches_readme() {
    let readme = read_repo_file("README.md");
    let published = extract_readme_metric(&readme, "Benign corpus size:**");
    let computed = count_benign_corpus_commands();
    assert_eq!(
        computed, published,
        "README.md's published benign corpus size ({published}) doesn't match \
         tests/benign_corpus.rs's actual command count ({computed}) -- update whichever one is \
         stale"
    );
}

#[test]
fn bypass_classes_closed_matches_readme() {
    // Unlike the two counts above, "which bypass class a payload belongs
    // to" is a curated classification, not something mechanically
    // derivable from source text alone -- this list is the source of
    // truth for that classification, kept here (not just in README) so
    // this test can catch drift in EITHER direction. Update both this
    // list and README's own count together when a genuinely new class
    // (not just a new payload within an existing class) is closed.
    const BYPASS_CLASSES_CLOSED: &[&str] = &[
        "A",     // quote removal
        "A-ext", // ANSI-C quoting
        "B",     // $IFS splitting
        "C",     // command substitution
        "C-ext", // variable indirection
        "D",     // decode-fed pipe
        "E",     // destructive commands outside the rm family
    ];
    let readme = read_repo_file("README.md");
    let published = extract_readme_metric(&readme, "Bypass classes closed:**");
    assert_eq!(
        BYPASS_CLASSES_CLOSED.len(),
        published,
        "README.md's published bypass-classes-closed count ({published}) doesn't match this \
         test's own curated list ({}) -- update whichever one is stale",
        BYPASS_CLASSES_CLOSED.len()
    );
}
