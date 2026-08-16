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
        // 8. issue #138: an ANSI-C-decoded NUL merges the command name with
        //    trailing text ("rm" + trailing text), which used to produce a
        //    `Resolved` string byte-distinct from "rm" that no exact-string
        //    blocklist check matched.
        ("rm$'\\0'IGNOREDTAIL -rf /", Decision::Ask),
        // 9. issue #138: same bypass shape, but merging a flag instead of
        //    the command name ("--force" + trailing text).
        ("git push --force$'\\0'x origin main", Decision::Ask),
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

/// Issue #120: `eval` was never routed through interpreter-code recursion
/// at all — absent from `SHELL_INTERPRETERS`/`EXTRA_PIPELINE_INTERPRETERS`,
/// its argument fell through to the generic, transparent argument-position
/// substitution path instead of being recognised as a shell string to
/// re-parse and recurse.
#[test]
fn guardfall_eval_cases() {
    let cases: &[(&str, Decision)] = &[
        // The issue's own three repros.
        ("eval rm -rf /", Decision::Block),
        ("eval \"rm -rf /\"", Decision::Block),
        // `eval`'s single argument is a command substitution -- fails
        // closed to Ask, the same posture `bash -c "$(...)"` already takes
        // (`evaluate_dash_c`'s own `Resolution::Unresolvable` arm) rather
        // than a silent Allow.
        ("eval $(echo rm -rf /)", Decision::Ask),
        // Bare `eval` (no arguments) is a real no-op -- must stay Allow.
        ("eval", Decision::Allow),
        // An ordinary, safe eval'd command must not be over-blocked.
        ("eval ls", Decision::Allow),
        ("eval \"ls -la\"", Decision::Allow),
        // `eval eval ...` -- nested eval must compose through the same
        // recursion-depth guard as everything else, not a second mechanism.
        ("eval eval rm -rf /", Decision::Block),
        // `builtin`/`command` (issue #245's TRANSPARENT_WRAPPERS entries)
        // must resolve through to `eval` and recurse identically.
        ("builtin eval rm -rf /", Decision::Block),
        ("command eval rm -rf /", Decision::Block),
        // Real `eval` consumes a single leading `--` before joining its
        // arguments (bash's `builtins/eval.def`), so this genuinely
        // executes `rm -rf /` -- must Block, not fall through to a
        // nonexistent `--` command.
        ("eval -- rm -rf /", Decision::Block),
        // Only ONE leading `--` is consumed (matches bash's own
        // `no_options`/`loptend` semantics) -- a second `--` stays part of
        // the joined script and resolves to a nonexistent `--` command, so
        // this stays Allow like any other no-op respelling.
        ("eval -- -- rm -rf /", Decision::Allow),
        ("eval --", Decision::Allow),
        // The join reconstructs one script across quote boundaries, so a
        // dangerous command split over several quoted words must still
        // Block -- a distinct path from the space-separated form above.
        ("eval 'rm' '-rf' '/'", Decision::Block),
        ("eval \"rm -rf\" /", Decision::Block),
        // The shell-init idiom, pinned so the Ask above is understood as a
        // deliberate fail-closed posture on an unresolvable substitution,
        // not an accident of the repro's particular shape.
        ("eval \"$(ssh-agent -s)\"", Decision::Ask),
        // The outer shell removes the quotes before `eval` sees them, so
        // the joined script is `sh -c rm -rf /`: `rm` becomes `-c`'s value
        // and `-rf`/`/` become $0/$1. Genuinely harmless -- pinned so a
        // future nested-interpreter change doesn't flip it to Block on the
        // assumption that the quotes survived.
        ("eval sh -c \"rm -rf /\"", Decision::Allow),
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

/// Issue #196: `find`'s `-exec`/`-execdir`/`-ok`/`-okdir` payload already
/// recursed a `sh -c '<string>'` target (issue #72's own machinery composed
/// with rule 6a), but a payload that execs a shell interpreter directly,
/// with no `-c`, fell through both mechanisms to a silent Allow -- rule 6a
/// only fires on a `-c` flag it can find, and the recursed bare-interpreter
/// payload alone matches no blocklist rule.
#[test]
fn guardfall_find_exec_bare_interpreter_cases() {
    let cases: &[(&str, Decision)] = &[
        // The issue's own repro.
        (r"find . -exec /bin/sh \; -quit", Decision::Block),
        // Bare interpreter name, no path.
        (r"find . -exec sh \; -quit", Decision::Block),
        (r"find . -exec bash \;", Decision::Block),
        // `env`-wrapped and `+`-terminated variants must resolve the same
        // way as the `\;`-terminated bare case.
        (r"find . -exec /usr/bin/env sh \;", Decision::Block),
        (r"find . -exec bash +", Decision::Block),
        // `-execdir`/`-ok`/`-okdir` share the same `RECURSABLE_SLOTS` entry
        // shape as `-exec` -- must Block identically.
        (r"find . -execdir sh \;", Decision::Block),
        (r"find . -ok sh \;", Decision::Block),
        (r"find . -okdir sh \;", Decision::Block),
        // The found file is passed as the interpreter's own positional
        // script argument, not through `-c` -- an operand is present with
        // no `-c`, so this floors to Ask (allowlist-launderable), not the
        // unappealable Block reserved for the no-operand shape.
        (r"find . -exec sh {} \;", Decision::Ask),
        // A non-shell interpreter (not in `SHELL_INTERPRETERS`) with no
        // `-c` stays out of this fix's scope -- unchanged Allow.
        (r"find . -exec python3 \;", Decision::Allow),
        // `-c` present: rule 6a's own recursion already handles this
        // (pinned here as an over-block guard, not a new mechanism).
        (r#"find . -exec sh -c "ls" \;"#, Decision::Allow),
        (r#"find . -exec sh -c "rm -rf /" \;"#, Decision::Block),
        // A bare top-level `sh` invocation (no `find -exec` involved) is
        // unaffected -- this fix is scoped to `find`'s direct-argv payload.
        ("sh", Decision::Allow),
        // Blocker 1 (over-block): `-n`/`-x` change what the shell does with
        // the found file, not whether an operand is present -- both floor
        // to Ask, not the old unappealable Block.
        (r"find . -name '*.sh' -exec sh -n {} \;", Decision::Ask),
        (r"find . -name '*.sh' -exec sh -x {} \;", Decision::Ask),
        (r"find . -exec sh /fixed/path.sh \;", Decision::Ask),
        // Blocker 2 (under-block): a real shell's option parser stops at
        // the first operand, so `-c` (or any `c`-containing cluster) after
        // `{}` is positional to the found script, not a flag to the
        // interpreter -- must not silently reach Allow.
        (r"find . -exec sh {} -c \;", Decision::Ask),
        (r"find . -exec sh {} -c true \;", Decision::Ask),
        (r"find . -exec bash {} -career \;", Decision::Ask),
        // Finding 4: `fish` documents `--command` as `-c`'s long spelling
        // -- must recurse through it like `-c`, not treat it as absent.
        (r"find . -exec fish --command ls \;", Decision::Allow),
        (
            r#"find . -exec fish --command "rm -rf /" \;"#,
            Decision::Block,
        ),
        // The flag position itself unresolvable must still fail closed via
        // rule 6a's existing `Uncertain` handling, unaffected by this fix.
        (
            r#"find . -exec sh $(echo -c) "rm -rf /" \;"#,
            Decision::Block,
        ),
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

/// Issue #140: `find -exec rm -f {}`/`... {} +` was recursed into
/// `rm-recursive-force-dangerous-target`, but that rule requires BOTH
/// `-r` and `-f`, so the `-r`-less shape slipped through even though it
/// deletes every matched file just as unrecoverably as `find -delete`
/// does (`-r` is never needed for `rm -f` against find's own `{}`
/// placeholder: a plain-file match is removed by `-f` alone, and a
/// directory match simply fails without `-r`). Covers the new
/// `rm-force-find-placeholder-target` rule plus, deliberately, the
/// everyday benign-looking idiom (`find . -name '*.tmp' -exec rm -f {}
/// +`) Blocking too — that mirrors `find -delete`'s own long-standing,
/// root-independent Block (pinned below), not a new false positive.
#[test]
fn guardfall_find_exec_rm_force_placeholder_cases() {
    let cases: &[(&str, Decision)] = &[
        // The issue's own repros.
        (r"find /x -type f -exec rm -rf {} +", Decision::Block), // already covered pre-#140, control
        (r"find /x -type f -exec rm -f {} +", Decision::Block),
        (r"find /x -exec rm -f {} +", Decision::Block),
        // Known gap, pinned so a future contains-style matcher has a
        // regression anchor: find substitutes `{}` anywhere inside a word,
        // so this genuinely deletes every match, but `exact = "{}"` only
        // matches a token that IS the placeholder. Shared with the `-rf`
        // rule, which has the same gap.
        (r"find . -exec rm -f ./{} \;", Decision::Allow),
        // Quoting is stripped by the shell before shguard sees the token.
        (r"find . -exec rm -f '{}' \;", Decision::Block),
        // Everyday benign-looking idiom, both terminator spellings —
        // Block, matching `find -delete`'s existing precedent (pinned
        // right below) for the same "delete every match, regardless of
        // root" effect.
        (r"find . -name '*.tmp' -exec rm -f {} +", Decision::Block),
        (r"find . -name '*.tmp' -exec rm -f {} \;", Decision::Block),
        (r"find . -name '*.tmp' -delete", Decision::Block), // the precedent itself, unaffected by this fix
        // `-execdir`/`-ok`/`-okdir` share the same `RECURSABLE_SLOTS`
        // shape as `-exec` — must Block identically.
        (r"find /x -execdir rm -f {} +", Decision::Block),
        (r"find /x -ok rm -f {} +", Decision::Block),
        (r"find /x -okdir rm -f {} +", Decision::Block),
        // `--force` long spelling.
        (r"find /x -exec rm --force {} +", Decision::Block),
        // Dangerous search roots still Block too (via the same `{}`-target
        // match, independent of the root itself).
        (r"find / -exec rm -f {} +", Decision::Block),
        (r"find ~ -exec rm -f {} +", Decision::Block),
        (r"find /dev -exec rm -f {} +", Decision::Block),
        // Direct (non-`find`) `rm -f {}` also Blocks — consistent with the
        // existing `{}`-target treatment in `rm-recursive-force-dangerous-target`.
        ("rm -f {}", Decision::Block),
        // Controls: out of this issue's scope, unchanged.
        (r"find /x -exec rm -r {} +", Decision::Allow), // -r alone (no -f) matches neither rule, unaffected by this fix
        ("find -delete", Decision::Block),              // unaffected by this fix
        ("rm -f file", Decision::Allow),                // plain rm, no placeholder target
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

/// Issue #198: the protected-path list omitted shell-init/persistence
/// files (`~/.bashrc`, `/etc/crontab`, ...) for `tee`/`cp`/`mv`/`install`/
/// `sed -i`/`dd of=`/`rm`. One representative path per class, crossed with
/// every write-capable mechanism the new `shell-init-*` rules cover, plus
/// benign controls that must stay `Allow` (reading FROM a protected path
/// rather than writing to it, `dd`'s `if=` vs `of=` distinction, and a path
/// that merely shares a prefix with a protected one).
///
/// Bare shell redirection (`>`/`>>`) is deliberately NOT covered — see the
/// "NOT covered" note on this rule family in `rules/blocklist.toml` for
/// why: every embedded `[[redirect]]` rule must stay `Decision::Block`
/// (first-match, no worst-wins folding across a command line's
/// redirections — `rules::tests::embedded_redirect_rules_are_all_block_
/// decision`), so `echo evil >> ~/.bashrc` still reads `Allow` here, on
/// purpose, pending a follow-up issue.
#[test]
fn guardfall_shell_init_persistence_cases() {
    let cases: &[(&str, Decision)] = &[
        // ---- one path per class, one mechanism each ----
        ("tee -a ~/.bashrc evil", Decision::Ask),
        ("tee -a ~/.zshrc evil", Decision::Ask),
        ("cp evil ~/.bash_profile", Decision::Ask),
        ("mv evil ~/.profile", Decision::Ask),
        (
            "install -m 644 evil ~/.config/fish/config.fish",
            Decision::Ask,
        ),
        ("sed -i 's/x/y/' /etc/crontab", Decision::Ask),
        ("dd of=/etc/cron.d/x if=evil", Decision::Ask),
        ("rm ~/.zshenv", Decision::Ask),
        ("unlink ~/.bashrc", Decision::Ask),
        // ln replaces the target's content via a symlink retarget, without
        // ever opening it for writing — same threat tier as the write
        // mechanisms above, not just the delete ones.
        ("ln -sf evil ~/.bashrc", Decision::Ask),
        // ---- the rest of the class, one mechanism (tee) each ----
        ("tee -a /etc/profile evil", Decision::Ask),
        ("tee -a /etc/profile.d/x.sh evil", Decision::Ask),
        ("tee -a /var/spool/cron/root evil", Decision::Ask),
        ("tee -a ~/.config/autostart/x.desktop evil", Decision::Ask),
        (
            "tee -a ~/.config/systemd/user/x.service evil",
            Decision::Ask,
        ),
        ("tee -a ~/.ssh/authorized_keys evil", Decision::Ask),
        ("tee -a ~/.ssh/config evil", Decision::Ask),
        ("tee -a /etc/ld.so.preload evil", Decision::Ask),
        // ---- benign controls: must NOT regress ----
        ("echo x > /tmp/f", Decision::Allow),
        ("cat ~/.bashrc", Decision::Allow),
        // Known open gap (documented above): redirection into a protected
        // path is not yet covered by any rule.
        ("echo evil >> ~/.bashrc", Decision::Allow),
        // dd's `of=`/`if=` split genuinely distinguishes write from read —
        // reading FROM a protected path is not a write TO it.
        ("dd if=~/.bashrc of=/tmp/backup", Decision::Allow),
        // A path that merely shares a prefix with a protected file is not
        // the file itself.
        ("tee -a ~/.bashrc.bak evil", Decision::Allow),
        ("cp evil ~/.bash_history", Decision::Allow),
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

/// Fable review of PR #259 (issue #198): a `normalized_prefix` target only
/// matches paths *under* the directory it names — the bare directory token
/// itself (`/etc/cron.d`, with or without a trailing slash) never matched,
/// so dropping a file straight INTO a protected directory
/// (`cp backdoor /etc/cron.d/`, the canonical cron-persistence attack) sailed
/// through as `Allow`. Each prefix-style target now carries a
/// bare `{ normalized = "..." }` alternative alongside its
/// `normalized_prefix`, mirroring the self-protect-config family's
/// bare-directory precedent (`rules/blocklist.toml`, issue #22/#28). Pinned
/// here with and without a trailing slash, across every mechanism whose
/// `targets` matcher can see a bare directory token as its own argv
/// argument (`cp`/`mv`/`install`/`rm`; `dd`'s `of=`-stripped form and
/// `tee`/`sed -i`'s plain form get the same fix but aren't re-pinned here to
/// keep this table's size in check).
#[test]
fn guardfall_shell_init_directory_token_cases() {
    let dirs: &[&str] = &[
        "/etc/profile.d",
        "/etc/cron.d",
        "/var/spool/cron",
        "~/.config/autostart",
        "~/.config/systemd/user",
        // Issue #198 path-parity additions (rules/blocklist.toml's
        // disclosed-gap comment) get the same bare-directory-token coverage.
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/zsh",
        "~/.config/fish/conf.d",
    ];

    for dir in dirs {
        for suffix in ["", "/"] {
            let target = format!("{dir}{suffix}");
            for command in [
                format!("cp evil {target}"),
                format!("mv evil {target}"),
                format!("install -m 755 evil {target}"),
                format!("rm -rf {target}"),
            ] {
                let verdict = shguard::analyze(&command);
                assert_eq!(
                    verdict.decision(),
                    Decision::Ask,
                    "command {command:?}: expected Ask, got {:?}",
                    verdict.decision()
                );
            }
        }
    }
}

/// Issue #198 follow-up: `cp`/`mv`/`install` can't tell a protected path
/// used as the read SOURCE from the same path used as the write
/// DESTINATION apart (`targets` matches ANY argv token, not a specific
/// position — the same limitation the self-protection ancestor rules
/// already document). This is a disclosed, accepted cost of `decision =
/// "ask"`, not a bug: an ordinary backup command now asks for confirmation
/// instead of running silently.
#[test]
fn guardfall_shell_init_source_destination_ambiguity_cases() {
    let cases: &[(&str, Decision)] = &[
        ("cp ~/.bashrc ~/.bashrc.bak", Decision::Ask),
        ("cp ~/.bashrc /tmp/backup", Decision::Ask),
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

/// Issue #198: the new `shell-init-*` `ask` rules must never shadow an
/// earlier, stricter `block` rule on the same command — `Rules::
/// match_command` is first-match over `rules/blocklist.toml`'s declared
/// order, so the new rules being appended at the END of the file is
/// load-bearing, not incidental (see the comment on this rule family in
/// `rules/blocklist.toml`). One case per mechanism (fable review of PR
/// #259, finding 5) so a future reorder that puts a `shell-init-*` rule
/// ahead of its stricter sibling can't silently regress unnoticed — each
/// command carries one token matching the earlier rule's targets and one
/// matching the new rule's, and only the earlier rule's `Block` may win.
#[test]
fn guardfall_shell_init_does_not_shadow_stricter_block_rules() {
    let cases: &[(&str, &str)] = &[
        // tee-write-device-or-critical-file vs. shell-init-tee.
        (
            "tee /etc/passwd ~/.bashrc",
            "tee-write-device-or-critical-file",
        ),
        // self-protect-config-cp-tilde vs. shell-init-cp.
        (
            "cp ~/.config/shguard/foo ~/.bashrc",
            "self-protect-config-cp-tilde",
        ),
        // self-protect-config-sed-tilde vs. shell-init-sed.
        (
            "sed -i s/a/b/ ~/.config/shguard/foo ~/.bashrc",
            "self-protect-config-sed-tilde",
        ),
        // rm-recursive-force-dangerous-target vs. shell-init-rm.
        ("rm -rf ~ ~/.bashrc", "rm-recursive-force-dangerous-target"),
        // dd-write-device vs. shell-init-dd.
        ("dd of=/dev/sda of=~/.bashrc", "dd-write-device"),
    ];

    for (command, expected_rule) in cases {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            Decision::Block,
            "command {command:?}: expected Block, got {:?}",
            verdict.decision()
        );
        let reason = verdict.reason().map(shguard::verdict::Reason::as_str);
        assert!(
            reason.is_some_and(|r| r.contains(expected_rule)),
            "command {command:?}: expected reason to mention {expected_rule:?}, got {reason:?}"
        );
    }
}

/// Issue #198: closes the PATH half of the parity gap disclosed in
/// `rules/blocklist.toml`'s "Known parity gaps" comment on the
/// `shell-init-*` family — `/etc/cron.{hourly,daily,weekly,monthly}/`,
/// `/etc/bash.bashrc`, `/etc/zsh/`, `~/.ssh/rc`, and
/// `~/.config/fish/conf.d/` are now `targets` in every `shell-init-*` rule,
/// the same way `/etc/cron.d/` already was. One path per new family,
/// crossed with at least two mechanisms each (mirroring
/// `guardfall_shell_init_persistence_cases`'s shape), plus benign controls
/// that must stay `Allow`. The MECHANISM half of the gap (rsync, perl -i,
/// patch, curl -o, wget -O, crontab <file>) stays open and is deliberately
/// not exercised here.
#[test]
fn guardfall_shell_init_path_parity_198_cases() {
    let cases: &[(&str, Decision)] = &[
        // ---- /etc/cron.{hourly,daily,weekly,monthly}/ ----
        ("tee -a /etc/cron.daily/x evil", Decision::Ask),
        ("cp evil /etc/cron.hourly/x", Decision::Ask),
        ("mv evil /etc/cron.weekly/x", Decision::Ask),
        ("rm /etc/cron.monthly/x", Decision::Ask),
        // ---- /etc/bash.bashrc ----
        ("cp evil /etc/bash.bashrc", Decision::Ask),
        ("tee -a /etc/bash.bashrc evil", Decision::Ask),
        ("unlink /etc/bash.bashrc", Decision::Ask),
        // ---- /etc/zsh/ ----
        ("tee -a /etc/zsh/zshrc evil", Decision::Ask),
        ("mv evil /etc/zsh/zprofile", Decision::Ask),
        ("dd of=/etc/zsh/zshrc if=evil", Decision::Ask),
        // ---- ~/.ssh/rc ----
        ("tee -a ~/.ssh/rc evil", Decision::Ask),
        ("rm ~/.ssh/rc", Decision::Ask),
        ("ln -sf evil ~/.ssh/rc", Decision::Ask),
        // ---- ~/.config/fish/conf.d/ ----
        ("cp evil ~/.config/fish/conf.d/x.fish", Decision::Ask),
        (
            "install -m 644 evil ~/.config/fish/conf.d/x.fish",
            Decision::Ask,
        ),
        // ---- benign controls: must NOT regress ----
        ("cat /etc/bash.bashrc", Decision::Allow),
        // dd's `of=`/`if=` split genuinely distinguishes write from read.
        ("dd if=/etc/zsh/zshrc of=/tmp/backup", Decision::Allow),
        // A path that merely shares a prefix with a protected file is not
        // the file itself.
        ("tee -a /etc/bash.bashrc.bak evil", Decision::Allow),
        ("cp evil ~/.ssh/rce", Decision::Allow),
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
