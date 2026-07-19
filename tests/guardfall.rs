//! Guardfall regression suite (issue #15, plan.md's "D1" deliverable):
//! a table-driven integration test over [`shguard::analyze`]'s public
//! contract, covering the headline evasion techniques the gate is built to
//! catch plus the Class E (destructive-but-not-`rm`) command family.
//!
//! Table-driven so adding a new regression case is a one-line diff to the
//! relevant `cases` array, not a new `#[test]` function.

use shguard::verdict::Decision;

#[test]
fn guardfall_headline_cases() {
    let cases: &[(&str, Decision)] = &[
        // 1. Quote-split obfuscation of the command name.
        ("r''m -rf /", Decision::Block),
        // 2. ANSI-C `$'...'` hex-escaped command name.
        ("$'\\x72\\x6d' -rf /", Decision::Block),
        // 3. `$IFS` standing in for whitespace between argv tokens.
        ("rm$IFS-rf$IFS/", Decision::Block),
        // 4. Command substitution in command position with no decode-to-
        //    interpreter pipeline shape — unresolvable, floors to Ask.
        ("$(echo cm0gLXJmIC8= | base64 -d)", Decision::Ask),
        // 5. Same-line variable assignment resolving the command name.
        ("X=rm; $X -rf /", Decision::Block),
        // 6. base64-decoded payload piped straight into an interpreter.
        ("echo cm0gLXJmIC8= | base64 -d | sh", Decision::Block),
        // 7. A quoted string that merely *contains* a dangerous-looking
        //    substring is not the same as executing it.
        ("git commit -m 'rm -rf /'", Decision::Allow),
    ];

    for (command, expected) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            *expected,
            "command {command:?}: expected {expected:?}, got {:?}",
            verdict.decision()
        );
    }
}

/// Class E: destructive commands outside the `rm` family (plan.md's
/// blocklist schema) — `find -delete`, `dd` to a `/dev/` target, `shred`,
/// and `truncate -s`.
#[test]
fn guardfall_class_e_cases() {
    let cases: &[(&str, Decision)] = &[
        ("find /x -delete", Decision::Block),
        ("dd if=/dev/zero of=/dev/sda", Decision::Block),
        ("shred /dev/sda", Decision::Block),
        ("truncate -s 0 /important", Decision::Block),
    ];

    for (command, expected) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            *expected,
            "command {command:?}: expected {expected:?}, got {:?}",
            verdict.decision()
        );
    }
}

/// Git-specific destructive/bypass operations.
#[test]
fn guardfall_git_cases() {
    let cases: &[(&str, Decision)] = &[
        ("git push --force origin main", Decision::Block),
        ("git push -f origin main", Decision::Block),
        ("git reset --hard HEAD~1", Decision::Block),
        ("git clean -fd", Decision::Block),
        ("git clean -n", Decision::Block),
        ("git commit --no-verify -m 'skip hooks'", Decision::Block),
        ("git commit -n -m 'skip hooks'", Decision::Block),
        ("git push --no-verify", Decision::Block),
        ("git checkout -- src/main.rs", Decision::Block),
        ("git rebase main", Decision::Block),
        ("git rebase -i main", Decision::Block),
        ("git commit --amend", Decision::Block),
        ("git branch -D feature/old", Decision::Block),
        ("git stash drop", Decision::Block),
        ("git stash clear", Decision::Block),
        ("git tag -d v1.0.0", Decision::Block),
        ("git tag -D v1.0.0", Decision::Block),
        ("git tag --delete v1.0.0", Decision::Block),
        ("git tag -f v1.0.0", Decision::Block),
    ];

    for (command, expected) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            *expected,
            "command {command:?}: expected {expected:?}, got {:?}",
            verdict.decision()
        );
    }
}

/// rm -rf with dot targets (cwd/parent).
#[test]
fn guardfall_rm_dot_targets() {
    let cases: &[(&str, Decision)] = &[
        ("rm -rf .", Decision::Block),
        ("rm -rf ..", Decision::Block),
        ("rm -rf ./", Decision::Block),
        ("rm -rf ../", Decision::Block),
    ];

    for (command, expected) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            *expected,
            "command {command:?}: expected {expected:?}, got {:?}",
            verdict.decision()
        );
    }
}

/// Redirect target and tee rules.
#[test]
fn guardfall_redirect_and_tee_cases() {
    let cases: &[(&str, Decision)] = &[
        ("echo x > /dev/sda", Decision::Block),
        ("cat file >> /etc/passwd", Decision::Block),
        ("echo x > /dev/vda1", Decision::Block),
        ("echo x > /dev/nvme0n1", Decision::Block),
        ("echo x > /dev/mapper/root", Decision::Block),
        ("echo x > /dev/dm-0", Decision::Block),
        ("echo x > /dev/disk0", Decision::Block),
        ("echo x > /dev/rdisk0", Decision::Block),
        ("echo x > /dev/xvda", Decision::Block),
        ("tee /dev/sda", Decision::Block),
        ("tee /etc/passwd", Decision::Block),
        ("tee /etc/shadow", Decision::Block),
    ];

    for (command, expected) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            *expected,
            "command {command:?}: expected {expected:?}, got {:?}",
            verdict.decision()
        );
    }
}
