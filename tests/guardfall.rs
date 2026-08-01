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
/// `truncate -s`, and `tar` extraction with -C/--directory into / or ~.
#[test]
fn guardfall_class_e_cases() {
    let cases: &[(&str, Decision)] = &[
        ("find /x -delete", Decision::Block),
        ("dd if=/dev/zero of=/dev/sda", Decision::Block),
        // issue #65: `//dev/sda` lexically normalizes to `/dev/sda` —
        // the old byte-exact `prefix = "of=/dev/"` target missed it.
        ("dd if=/dev/zero of=//dev/sda", Decision::Block),
        ("shred /dev/sda", Decision::Block),
        ("truncate -s 0 /important", Decision::Block),
        ("tar -C / -x", Decision::Block),
        ("tar -xf evil.tar -C /", Decision::Block),
        ("tar --extract --directory=/ -f evil.tar", Decision::Block),
        ("tar xf a.tar -C /", Decision::Ask),
        // ---- pins added after a fable-model review of PR #62: all of
        // these already behaved correctly, just weren't yet asserted ----
        ("tar -C ~ -xf evil.tar", Decision::Block),
        ("tar -C~ -xf evil.tar", Decision::Allow), // literal `~`, not $HOME — see the TOML rule's docs
        ("tar -xf evil.tar -C/", Decision::Block), // attached form of -C
        ("tar -xCf evil.tar /", Decision::Block),  // dashed short-flag clustering
        ("tar -C $HOME -xf evil.tar", Decision::Ask), // unresolvable target fails closed
        // ---- issue #65: path normalization bypasses — a real shell
        // treats each of these identically to `-C /`/`-C ~`, but the old
        // pure-byte `exact`/`prefix` targets missed every one of them ----
        ("tar -xf evil.tar -C /", Decision::Block), // regression pin, unchanged
        ("tar -xf evil.tar -C //", Decision::Block), // was Allow before issue #65
        ("tar -xf evil.tar -C /.", Decision::Block), // was Allow before issue #65
        ("tar -xf evil.tar -C ~/..", Decision::Block), // was Allow before issue #65
        ("tar -xf evil.tar -C ../../../..", Decision::Block), // was Allow before issue #65
        // A dotted-but-concrete path must not false-positive against "/".
        ("tar -xf evil.tar -C /some/real/./path", Decision::Allow),
        // Deliberate behavior change (issue #65): a pure relative ascent
        // might resolve to "/" from an unknown cwd, so it now fails closed
        // to Block rather than Allow.
        ("tar -xf evil.tar -C ..", Decision::Block),
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
        // issue #65: `//` lexically normalizes to the same target `/`
        // does — the old byte-exact `exact = "/"` target missed it.
        ("rm -rf //", Decision::Block),
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

/// Issue #54: `timeout`/`ionice`/`flock` joined `TRANSPARENT_WRAPPERS`, so
/// a wrapped `rm -rf /` must reach the same rm rule a bare invocation does.
#[test]
fn guardfall_transparent_wrapper_cases() {
    let cases: &[(&str, Decision)] = &[
        ("timeout 5 rm -rf /", Decision::Block),
        ("chrt -f 99 rm -rf /", Decision::Block),
        ("taskset 0x1 rm -rf /", Decision::Block),
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

/// Issue #65: self-protection's `normalized_prefix`/`normalized` targets
/// (the literal `~/.config/shguard/` half — `src/config.rs`'s dynamically
/// generated resolved-path half is covered separately in
/// `tests/user_config.rs`, which drives the real binary with an actual
/// config path) must still catch a `.`-padded or double-slash respelling
/// of the config directory, not just the literal spelling.
#[test]
fn guardfall_self_protection_normalization_cases() {
    let cases: &[(&str, Decision)] = &[
        ("tee ~/.config/shguard/config.toml", Decision::Block), // regression pin
        ("tee ~/.config//shguard/config.toml", Decision::Block), // double slash
        ("tee ~/.config/./shguard/config.toml", Decision::Block), // dot-padded
        ("tee ~/.config/other/config.toml", Decision::Allow),   // must not over-match
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
        // Redirection-only commands (no argv) must still be caught.
        ("> /etc/passwd", Decision::Block),
        ("> /dev/sda", Decision::Block),
        (">> /etc/shadow", Decision::Block),
        // Redirect on a command with early-return path (sh -c).
        ("sh -c 'echo hi' > /dev/sda", Decision::Block),
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
