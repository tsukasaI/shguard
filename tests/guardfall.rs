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
        // Issue #115: `--directory=~` (the `=`-attached long-flag form)
        // floors to Ask, not the certain Block a separated `-C ~` gets —
        // zsh's magic_equal_subst option (off by default) is the only
        // thing that can make this expand, so shguard can only flag it.
        ("tar -x --directory=~ -f a.tar", Decision::Ask),
        // Block already outranks the floor when a DIFFERENT target on the
        // same invocation certainly matches — the floor's `decision.max`
        // must never downgrade an existing Block.
        ("tar -x -C / --directory=~ -f a.tar", Decision::Block),
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
        // issue #206: uppercase `-R` is an equally standard recursive
        // synonym in both GNU and BSD `rm` — the old `required_flags`
        // only recognized lowercase `r`, so `rm -Rf` fell through to
        // Allow (`/`, `.`) or to the weaker ancestor-rule Ask (`~`).
        ("rm -Rf /", Decision::Block),
        ("rm -Rf ~", Decision::Block),
        ("rm -Rf .", Decision::Block),
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
        // Issue #114: busybox mkswap /dev/sda1 (the issue's own repro).
        ("busybox mkswap /dev/sda1", Decision::Block),
        // Same issue, in the rm -rf / shape every sibling wrapper case
        // above uses — pins the busybox->rm resolution path specifically,
        // independent of the mkswap case above.
        ("busybox rm -rf /", Decision::Block),
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
        // Issue #82 (fixed): this ordering's winning alternative used to
        // fold to "rm -rf /$(true)" as ONE opaque piece run —
        // `resolve_pieces`'s former word-level short-circuit discarded the
        // already-resolved "rm"/"-rf"/"/" prefix along with the trailing
        // inert substitution. Now Block: `resolve_pieces`/`chunks_to_words`
        // isolate only the trailing `/$(true)` segment as opaque, and the
        // OTHER (empty) brace member's own concatenated "rm -rf /" tokens
        // land in the same `argv` regardless (real bash brace-expansion
        // semantics: a command-position word's alternatives all contribute
        // argv words to the SAME invocation, not "try member A, else B") —
        // so the literal "/" from that member hard-matches
        // `rm-recursive-force-dangerous-target` on its own merits.
        ("rm$IFS-rf$IFS/{$(true),}", Decision::Block),
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
        // Issue #85 follow-up: when the required FLAG **and** the TARGET
        // are BOTH swallowed into the SAME opaque substitution-bearing
        // word (no resolved token survives to check against `targets` at
        // all — not specific to brace alternation, see the plain `rm
        // -rf$IFS/$(true)` control below), `matches_except_target` grew a
        // third relaxation: when this rule declares a required flag/token
        // and the ENTIRE tail is unresolvable, that's still plausibly this
        // rule's own dangerous shape. So `rm-recursive-force-dangerous-target`
        // itself now fires here directly (confirmed via the probe example,
        // not merely inferred) — before issue #85, only the flagless,
        // target-only `self-protect-config-rm-tilde` sibling rescued this
        // specific case for `rm`; a required-flags-AND-target rule with no
        // such flagless sibling (`self-protect-config-sed-tilde`) had no
        // rescue at all, which is what issue #85 was filed against (see
        // the sed cases and their own comment further below).
        ("rm{,$IFS-rf$IFS/$(true)}", Decision::Ask),
        ("rm -rf$IFS/$(true)", Decision::Ask), // brace-free control, same shape
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
        //
        // Issue #82 upgrade: the two `$IFS`-separated cases below now
        // Block outright, stronger than the `Ask`-only floor they used to
        // need. `$IFS` (unlike `$*`/`$@`/`${f}`/a substitution's own
        // output) is the one separator `resolve_pieces`/`chunks_to_words`
        // treat as a genuine split point — so `-i` and the tilde-path,
        // both literal text on either side of an ACTUAL `$IFS` piece, now
        // resolve as two separate, clean argv words instead of collapsing
        // into one opaque blob alongside the substitution between them.
        // With both the required flag and the target visible as literal
        // tokens, `self-protect-config-sed-tilde` hard-matches via the
        // ordinary `Self::matches` path — no floor needed at all.
        (
            "sed{,$IFS-i$IFS$(printf x)$IFS~/.config/shguard/config.toml}",
            Decision::Block,
        ),
        (
            "{sed,-i$IFS$(printf x)$IFS~/.config/shguard/config.toml}",
            Decision::Block,
        ),
        // Same shape with the substitution itself inert — confirms the
        // upgrade to `Block` above does not depend on what `$(true)`
        // recurses to either: `-i`/the tilde-path resolve as clean words
        // regardless of the substitution's own content.
        (
            "sed{,$IFS-i$IFS$(true)$IFS~/.config/shguard/config.toml}",
            Decision::Block,
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
        // Issue #85: the required FLAG (`-i`) and the TARGET (the shguard
        // config dir) hidden together, with NO resolved token anywhere in
        // the tail to check either constraint against — `sed` has no
        // flagless self-protect sibling (unlike `rm`/`tee`/`cp`/`mv`/
        // `install`, see the "why the obvious fix is wrong" note in the
        // issue: a flagless sibling would wrongly flag a harmless
        // `sed -n '1p' ~/.config/shguard/config.toml` read), so this
        // reached a genuine `Allow`, not merely a weaker `Ask`, until
        // `CommandRule::matches_except_target` (src/rules.rs) grew a third
        // relaxation: a rule with a required flag/token whose ENTIRE tail
        // is unresolvable is still plausibly its own dangerous shape.
        // Fixed and now pinned (previously left deliberately unpinned —
        // a genuine bypass should not read as an accepted, green
        // regression pin — but now that it Asks, it belongs here like
        // every other case in this test).
        (
            "sed $(echo -i ~/.config/shguard/config.toml)",
            Decision::Ask,
        ),
        (
            "sed $(printf -- -i) $(printf ~/.config/shguard/config.toml)",
            Decision::Ask,
        ),
        // End-to-end pin (fable-review follow-up) for the exact invariant
        // issue #85's own text calls out as the reason a flagless sibling
        // rule was rejected: a resolved, no-`-i` read of the config file
        // must stay Allow. Only unit-level coverage of this existed before
        // (`self_protect_sed_without_dash_i_does_not_match`, which checks
        // `CommandRule::matches` directly) — nothing in this file, whose
        // whole purpose is pinning end-to-end gate verdicts, exercised the
        // full `shguard::analyze` path for it.
        ("sed -n '1p' ~/.config/shguard/config.toml", Decision::Allow),
        // Addendum: the SAME root cause reachable via a single
        // command/backquote substitution whose own runtime OUTPUT combines
        // both the flag and the target in one word — confirmed not
        // specific to brace alternation (the brace-free control below hits
        // the identical gap; the brace-wrapped spelling was `Ask` on old
        // `main` only because rule 1's old blanket scan caught ANY
        // substitution in the command-position word, by accident).
        (
            "{sed,$(printf -- \"-i /home/user/.config/shguard/config.toml\")}",
            Decision::Ask,
        ),
        (
            "sed $(printf -- \"-i /home/user/.config/shguard/config.toml\")",
            Decision::Ask,
        ),
    ];
    // Known residual gap (fable-review finding against issue #85's fix,
    // NOT closed here — tracked as issue #117, not pinned as a passing
    // case since a genuine bypass should not read as an accepted, green
    // regression pin): a decoy RESOLVED token elsewhere in the tail
    // still defeats the new relaxation above, even when the danger is real
    // and exploitable. GNU sed permutes options after operands (POSIX
    // getopt-style), so `sed 's/a/b/' $(echo -i ~/.config/shguard/config.toml)`
    // still performs the in-place edit at runtime, but its tail has one
    // resolved token (`'s/a/b/'`, sed's own edit script) alongside the
    // hidden flag+target substitution — the new relaxation only fires when
    // the WHOLE tail is unresolvable, so a single resolved decoy is enough
    // to keep it silent. Closing this fully needs sed-specific positional
    // semantics (which operand is the script vs. a target file), not a
    // generic flag/target check.

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
