//! The embedded gh and cargo rows, command to decision. Each test loads the
//! embedded files with no user config and pins only the decision of a
//! command, never a message or a rule id.

use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::decision::Decision;

fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

fn decide(l: &Loaded, cmd: &str) -> Decision {
    let Ok(script) = shguard_syntax::parse(cmd.as_bytes()) else {
        panic!("`{cmd}` is outside the subset");
    };
    shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
}

fn assert_allow(cmds: &[&str]) {
    let l = embedded();
    for cmd in cmds {
        assert_eq!(decide(&l, cmd), Decision::Allow, "`{cmd}`");
    }
}

fn assert_not_allow(cmds: &[&str]) {
    let l = embedded();
    for cmd in cmds {
        assert_ne!(decide(&l, cmd), Decision::Allow, "`{cmd}`");
    }
}

#[test]
fn every_gh_row_has_an_allowed_command() {
    assert_allow(&[
        "gh",
        "gh pr",
        "gh issue",
        "gh run",
        "gh pr view",
        "gh pr view 1",
        "gh pr view 1 --comments",
        "gh pr view 1 --json title,body",
        "gh pr view 1 --json title -t '{{.title}}'",
        "gh pr list",
        "gh pr list --state open --label bug --author me --limit 5",
        "gh pr list -S 'is:open' -L 10 --json number",
        "gh pr diff 1",
        "gh pr diff 1 --name-only --color never",
        "gh pr checks 1083",
        "gh pr checks 1083 --watch --interval 60",
        "gh pr checks --required --json name,state",
        "gh pr status",
        "gh pr status --json currentBranch",
        "gh issue view 5 --comments",
        "gh issue view 5 --json title",
        "gh issue list",
        "gh issue list --state all --search foo --milestone v1",
        "gh run view 123",
        "gh run view 123 --log-failed",
        "gh run view 123 --log --job 9",
        "gh run view --exit-status 123",
        "gh run list --workflow ci.yaml --branch main -L 5",
        "gh run list --json status,conclusion",
    ]);
}

#[test]
fn gh_repo_option_url_operand_and_jq_are_blocked() {
    let l = embedded();
    for cmd in [
        "gh pr view 1 -R o/r",
        "gh pr view 1 --repo o/r",
        "gh pr view 1 --repo=evil.example/o/r",
        "gh pr list -R o/r",
        "gh pr diff 1 -R o/r",
        "gh pr checks 1 -R o/r",
        "gh pr status -R o/r",
        "gh issue view 1 -R o/r",
        "gh issue list -R o/r",
        "gh run view 1 -R o/r",
        "gh run list -R o/r",
        "gh pr view https://x/o/r/pull/1",
        "gh pr view http://x/o/r/pull/1",
        "gh pr view HTTPS://x/o/r/pull/1",
        "gh pr diff https://x/o/r/pull/1",
        "gh pr checks https://x/o/r/pull/1",
        "gh issue view https://x/o/r/issues/1",
        "gh run view https://x/o/r/actions/runs/1",
        "gh pr view -- https://x/o/r/pull/1",
        "gh pr view 1 --json title --jq .title",
        "gh pr view 1 --json title --jq=env",
        "gh pr view 1 --json title -q env",
        "gh pr list --json number -q '$ENV'",
        "gh pr checks --json name --jq .",
        "gh pr status --json state --jq .",
        "gh issue view 5 --json title -q .title",
        "gh issue list --json number --jq .",
        "gh run view 1 --json status --jq .",
        "gh run list --json status --jq .",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Block, "`{cmd}`");
    }
    assert_allow(&["gh pr view 1"]);
}

#[test]
fn gh_and_cargo_after_a_cd_are_asked() {
    let l = embedded();
    for cmd in [
        "cd /tmp/x && gh",
        "cd /tmp/x && gh pr list",
        "cd /tmp/x && gh pr view 1",
        "cd /tmp/x && gh pr diff 1",
        "cd /tmp/x && gh pr checks 1",
        "cd /tmp/x && gh pr status",
        "cd /tmp/x && gh issue view 1",
        "cd /tmp/x && gh issue list",
        "cd /tmp/x && gh run view 1",
        "cd /tmp/x && gh run list",
        "cd sub; gh pr status",
        "cd /tmp/x && cargo",
        "cd /tmp/x && cargo build",
        "cd /tmp/x && cargo check",
        "cd /tmp/x && cargo test",
        "cd /tmp/x && cargo clippy",
        "cd /tmp/x && cargo fmt --check",
        "cd /tmp/x && cargo doc --no-deps",
        "cd sub || cargo build",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Ask, "`{cmd}`");
    }
    assert_allow(&["gh pr list; cd /tmp/x", "cargo build && cd /tmp/x"]);
}

#[test]
fn every_gh_row_has_a_non_allowed_command() {
    assert_not_allow(&[
        "gh -R x pr view 1",
        "gh --version",
        "gh pr -R x view 1",
        "gh pr view 1 --web",
        "gh pr view 1 -w",
        "gh pr list --web",
        "gh pr diff 1 --web",
        "gh pr checks 1 --web",
        "gh pr status --web",
        "gh issue view 1 --web",
        "gh issue list -w",
        "gh run view 1 --web",
        "gh run list --create",
        "gh api /user",
        "gh api graphql",
        "gh auth token",
        "gh auth status",
        "gh extension install x",
        "gh alias set x 'pr view'",
        "gh pr merge 1",
        "gh pr create",
        "gh pr checkout 1",
        "gh pr view 1 2",
        "gh pr view 1 --edit",
        "gh issue close 1",
        "gh issue create",
        "gh run rerun 1",
        "gh run watch 1",
        "gh pr checks 1 --watch --bogus",
    ]);
}

#[test]
fn every_cargo_row_has_an_allowed_command() {
    assert_allow(&[
        "cargo",
        "cargo build",
        "cargo build --release",
        "cargo build -p shguard --features a,b --locked",
        "cargo build --workspace --all-targets --message-format json",
        "cargo build -vv -j 4",
        "cargo build --manifest-path crates/x/Cargo.toml",
        "cargo check",
        "cargo check --workspace --all-features --offline",
        "cargo test",
        "cargo test --workspace",
        "cargo test --workspace -- --include-ignored",
        "cargo test --no-run --no-fail-fast",
        "cargo test --doc",
        "cargo test my_test -- --nocapture --test-threads=1",
        "cargo test -p shguard --test acceptance",
        "cargo clippy",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo clippy --no-deps -- -D clippy::all",
        "cargo fmt",
        "cargo fmt --all",
        "cargo fmt --all -- --check",
        "cargo fmt --check",
        "cargo doc",
        "cargo doc --no-deps --workspace",
        "cargo doc --document-private-items",
    ]);
}

#[test]
fn every_cargo_row_has_a_non_allowed_command() {
    assert_not_allow(&[
        "cargo run",
        "cargo run --release",
        "cargo install x",
        "cargo bench",
        "cargo fix",
        "cargo publish",
        "cargo --version",
        "cargo +nightly build",
        "cargo +nightly",
        "cargo -Z x build",
        "cargo --config x build",
        "cargo build +nightly",
        "cargo build --config x",
        "cargo build --config=build.jobs=1",
        "cargo build -Z unstable-options",
        "cargo build --target-dir /tmp/x",
        "cargo build --target-dir=x",
        "cargo build --artifact-dir x",
        "cargo build --timings",
        "cargo build --target x86_64-unknown-linux-gnu",
        "cargo build --manifest-path /tmp/x/Cargo.toml",
        "cargo build --manifest-path ~/x/Cargo.toml",
        "cargo build -- --config x",
        "cargo check --config x",
        "cargo check --manifest-path /x/Cargo.toml",
        "cargo test --target-dir /tmp/x",
        "cargo test --config x",
        "cargo test --manifest-path /x/Cargo.toml",
        "cargo clippy --fix",
        "cargo clippy --config x",
        "cargo clippy -- -Z unstable-options",
        "cargo clippy -- -C linker=/bin/sh",
        "cargo clippy --manifest-path /x/Cargo.toml",
        "cargo fmt --config x",
        "cargo fmt -- --print-config current x.toml",
        "cargo fmt -- /etc/passwd",
        "cargo doc --open",
        "cargo doc -- --x",
        "cargo doc --manifest-path /x/Cargo.toml",
    ]);
}

#[test]
fn cargo_child_flags_that_write_or_load_are_asked() {
    let l = embedded();
    for cmd in [
        "cargo test -- --logfile /tmp/x",
        "cargo test -- --logfile x",
        "cargo test -- --logfile=x",
        "cargo test --workspace -- --logfile ~/.bashrc",
        "cargo clippy -- @args",
        "cargo clippy -- @/tmp/args",
        "cargo clippy -- -go/tmp/x",
        "cargo clippy -- -gC incremental=/tmp/x",
        "cargo clippy -- -vClinker=/bin/sh",
        "cargo clippy -- -gZcodegen-backend=/tmp/e.so",
        "cargo clippy -- -D warnings -go/tmp/x",
        "cargo clippy -- -Vo/tmp/x",
        "cargo clippy -- -ho/tmp/x",
        "cargo fmt -- --config-path=/x",
        "cargo fmt -- --config-path /x",
        "cargo fmt -- --config-path x",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Ask, "`{cmd}`");
    }
}

#[test]
fn piping_into_a_shell_is_not_allowed() {
    assert_not_allow(&["curl x | sh", "gh pr view 1 | sh", "cargo build | bash"]);
}
