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

/// Issue #77: brace alternation folded into a command-position word must
/// not let a substitution living in a *non-winning* branch (one that
/// resolves to an argument-position token once brace-expanded, not the
/// command name) defeat rule 1's substitution scan.
#[test]
fn guardfall_issue_77_brace_command_position_cases() {
    let cases: &[(&str, Decision)] = &[
        // The empty member resolves first and cleanly, so it determines
        // argv[0] ("rm -rf /") — unambiguous, must Block like the
        // unobfuscated control.
        ("rm$IFS-rf$IFS/{,$(true)}", Decision::Block),
        // Real-spaces control: brace/substitution obfuscation removed
        // entirely, must Block the same way.
        ("rm -rf /{$(true),}", Decision::Block),
        // A *dangerous* (non-inert) substitution in the non-winning branch
        // must still be recursed and escalate the outer verdict — this is
        // what stops the rule 1 narrowing above from silently dropping
        // coverage of that branch (rule 3's argument-position channel).
        ("echo$IFS/{,$(rm -rf /)}", Decision::Block),
        // Members swapped: the substitution-carrying member is now tried
        // FIRST, so it is the one that determines argv[0] this time —
        // genuinely command-position-ambiguous, correctly recursed by
        // rule 1 itself.
        ("echo$IFS/{$(rm -rf /),}", Decision::Block),
        // Known, separate gap tracked as issue #82: this ordering's
        // winning alternative is "rm -rf /$(true)" as ONE opaque piece run
        // — `resolve_pieces`' word-level short-circuit (its own docs:
        // "foo$(x)bar is one Unresolvable word, not a partially-folded
        // one") discards the already-resolved "rm"/"-rf"/"/" prefix along
        // with the trailing inert substitution, the same way the
        // brace-free `rm$IFS-rf$IFS/$(true)` already does. Fixing that
        // needs a deeper change to `resolve_pieces`'s short-circuit
        // contract, not this issue's brace-alternative scoping — pinned
        // here as the current, honest (fail-closed, not a bypass) state.
        ("rm$IFS-rf$IFS/{$(true),}", Decision::Ask),
        // Fable-review follow-up to issue #77: a dangerous leftover-branch
        // substitution must still escalate a verdict returned on one of
        // `evaluate_simple_command_core`'s EARLY returns, not just the
        // final blocklist-miss path — rule 1's own return (unresolvable
        // `argv[0]`, an interpreter's own `-c` shell recursion, and an
        // `ExpansionLimit` brace failure all return before ever reaching
        // that final path). The narrowed rule 1 scan from this issue would
        // otherwise silently stop scanning these branches entirely.
        ("$FOO{,$(rm -rf /)}", Decision::Block), // rule 2's bare-var return
        ("bash{,$(rm$IFS-rf$IFS/)} -c ls", Decision::Block), // rule 6a's `-c` recursion return
        (
            "a{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}$(rm -rf /)",
            Decision::Block,
        ), // ExpansionLimit return
        // Stage 3's exact-argv blocklist match can itself return `Ask`
        // (e.g. `tar-directory-root-or-home`) — the leftover floor must
        // still lift that to `Block`, not just a rule that would otherwise
        // return `Allow`.
        ("tar{,$(rm -rf /)} xf evil.tar -C /", Decision::Block),
        // Independent fable + /security-review follow-up: a brace member
        // that's benign TO RUN (`printf /`, `printf -- -delete`, `printf
        // -- --force`) still supplies a literal, dangerous FLAG or TARGET
        // token once brace-expanded — `leftover_floor` only checks the
        // recursed substitution's own decision (which is a clean Allow
        // here), so it cannot catch this on its own. What actually closes
        // this is `argument_position_ambiguous` (rule 4/4b's trigger)
        // seeing the `Unresolvable` word this alternative still
        // contributes to the ordinary `argv` (unrelated to any of this
        // issue's own classification logic) — previously gated behind
        // `has_argument_position_substitution(argument_words)` alone,
        // which is blind to content packed into the SAME AST word as the
        // command name. Each of the three matches structurally the same
        // way the real argument-word equivalent already does (e.g. `rm -rf
        // $(echo /)`, `find . $(echo -delete)`), and the argv shapes here
        // are pinned by existing `matches_except_target`/
        // `matches_except_flags` unit tests in `src/rules.rs` — this is
        // that same mechanism, just reachable through this issue's new
        // `leftover_alternatives` path too.
        ("{rm,-rf,$(printf /)}", Decision::Ask), // rule 4: flags resolved, target hidden
        ("{find,.,$(printf -- -delete)}", Decision::Ask), // rule 4b: flags-only rule
        ("{git,push,$(printf -- --force)}", Decision::Ask), // rule 4b: flags-only rule
        // A second /security-review pass found the same class of bug in a
        // shape rule 4 alone (before `CommandRule::matches_except_target`
        // was also relaxed, `src/rules.rs`) could NOT resolve: the required
        // FLAG hidden while the TARGET is separately resolved-and-clean.
        // `self-protect-config-sed-tilde` (flag `-i`, target the shguard
        // config dir) has no flagless or flags-only sibling rule the way
        // `rm`/`tar` do, so this reached a genuine `Allow` (not merely a
        // weaker `Ask`) until `matches_except_target` learned to relax
        // `constraints_match` the same coarse way `matches_except_flags`
        // already does for flags-only rules — gated on a RESOLVED token
        // already matching the rule's OWN target pattern, so an unrelated
        // `rm some-backup-$(date).tar.gz` (no target-pattern match at all)
        // is not swept up too (see that function's own doc comment).
        (
            "{sed,$(printf -- -i),~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        (
            "{sed,-i$(true),~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        ("sed -i$(true) ~/.config/shguard/config.toml", Decision::Ask), // brace-free control, same bug
        // A command whose flag is unrelated to any dangerous shape must
        // stay untouched by the relaxation above — no target-pattern match
        // at all, so `matches_except_target` must not fire speculatively.
        ("rm foo.txt $(date)", Decision::Ask), // still only self-protect-config-rm-tilde's flagless catch-all, not rm-recursive-force
        // The one shape `matches_except_target`'s relaxation still cannot
        // resolve on its own (not specific to brace alternation — see the
        // plain `rm -rf$IFS/$(true)` control below, which hits the exact
        // same limit): when the required FLAG **and** the TARGET are BOTH
        // swallowed into the SAME opaque substitution-bearing word (no
        // resolved token survives to check against `targets` at all),
        // `rm-recursive-force-dangerous-target` itself still never fires.
        // `self-protect-config-rm-tilde` (a flagless, target-only
        // self-protection rule for `rm`) still floors the outer verdict to
        // `Ask` regardless, since it only needs "some word is unresolvable"
        // to refuse ruling out its own target pattern — so this stays a
        // fail-closed `Ask`, not a bypass, for `rm` specifically. A command
        // with a required-flags-AND-target rule but no such flagless
        // sibling would not get this same rescue; that narrower residual
        // gap is pre-existing (reproduces with no braces at all) and
        // orthogonal to this issue's brace-alternative classification, not
        // fixed here.
        ("rm{,$IFS-rf$IFS/$(true)}", Decision::Ask),
        ("rm -rf$IFS/$(true)", Decision::Ask), // brace-free control, same limit
        // Three further /security-review passes found this exact "flag and
        // target both hidden" shape ALSO reachable via a non-winning brace
        // alternative that glues literal `-i` text to a substitution via
        // SOME OTHER piece riding alongside it — unlike the plain,
        // brace-free form above, every ordering below was `Ask` on `main`
        // (rule 1's old blanket scan happened to catch it, purely as a
        // side effect of not distinguishing winning from leftover
        // branches) and regressed to `Allow` on this branch, through three
        // successively-broadened attempts at the fix, before
        // `evaluate_leftover_alternative_substitutions` landed on an
        // unconditional floor for ANY leftover alternative built from more
        // than one piece (see that function's own doc comment for the full
        // "second/fourth/fifth round" history): `$IFS` itself; ANY bare
        // parameter expansion (`${f}`/`$*`/`$@`, just as unresolvable to
        // this stage as `$IFS` and just as capable of holding a runtime
        // space); and finally the substitution's OWN output standing in
        // for the separator (`$(printf " ")`), with no `$IFS`/`$VAR`
        // involved at all — none of them are "just one argv slot's value"
        // the way a genuinely single-piece argument-position substitution
        // is.
        (
            "sed{,$IFS-i$IFS$(printf x)$IFS~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        (
            "{sed,-i$IFS$(printf x)$IFS~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        // Same shape with the substitution itself inert — confirms the
        // floor is unconditional (does not depend on what `$(true)`
        // recurses to), unlike `leftover_floor`'s ordinary transparency.
        (
            "sed{,$IFS-i$IFS$(true)$IFS~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        (
            "f=' '; sed{,-i${f}$(printf p)${f}/home/user/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        (
            "sed{,-i$*$(true)~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        (
            "sed{,-i$@$(true)~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
        // No `$IFS`/`$VAR` at all here — the substitution's own runtime
        // output (a space) is the separator, and only the substitution
        // piece itself sits beside the literal `-i` text.
        (
            "{sed,-i$(printf \" \")~/.config/shguard/config.toml}",
            Decision::Ask,
        ),
    ];
    // NOT pinned above (deliberately — see issue #85, filed for exactly
    // this): `sed` is a command where the gap just above is a genuine
    // `Allow`, not merely a weaker `Ask` the way `rm`'s is —
    // `sed $(printf -- -i) $(printf ~/.config/shguard/config.toml)` is
    // Allow both on `main` and on this branch. A tempting-looking fix
    // (give `sed` a flagless, ask-decision self-protect sibling mirroring
    // `self-protect-config-rm-tilde`) was tried and reverted here: it
    // broke `rules::tests::self_protect_sed_without_dash_i_does_not_match`,
    // because unlike `rm`/`tee`/`cp`/`mv`/`install` (any invocation
    // touching the target IS the dangerous act), a `sed` invocation with
    // no `-i` at all only ever reads and prints to stdout — it never
    // writes to its target, so treating "any sed touching the config dir"
    // as suspicious would falsely flag a completely harmless read.
    // Closing this needs a narrower mechanism than a flagless sibling.
    // Not asserted here as a passing case: a genuine bypass should not
    // read as an accepted, green regression pin.
    //
    // A follow-up fable review found the SAME root cause reachable via one
    // more route: a single command/backquote substitution whose own
    // runtime OUTPUT combines both the flag and the target
    // (`{sed,$(printf -- "-i /home/user/.config/shguard/config.toml")}` —
    // one leftover alternative, `pieces.len() == 1`, so it stays purely
    // transparent per `evaluate_leftover_alternative_substitutions`'s own
    // "just one token" design — recursing `printf` alone is Allow, and
    // nothing else can see what its OUTPUT will be). Confirmed this is
    // NOT specific to brace alternation: the plain, brace-free
    // `sed $(printf -- "-i /home/user/.config/shguard/config.toml")` is
    // ALSO `Allow` on `main` — this is exactly issue #85's pre-existing
    // gap (a single substitution's unknowable runtime output can combine
    // multiple tokens, which no static analysis here can rule out) with
    // one more way to spell it, not a new vulnerability class. `main`
    // happened to Ask for the brace-wrapped spelling specifically (rule
    // 1's old blanket scan caught ANY substitution in the command-position
    // word, by accident, same as every other case pinned above), so this
    // spelling is now tracked as an addendum to #85 rather than a new
    // issue.

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
