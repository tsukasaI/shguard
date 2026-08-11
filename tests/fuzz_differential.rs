//! Differential fuzzing harness (issue #93): generates candidate shell
//! command strings via a grammar-aware mutator seeded from
//! `tests/guardfall.rs`'s corpus and the published GuardFall bypass classes
//! (README "Attribution"), then diffs shguard's static normalization
//! against bash's *real* post-expansion argv for the same text. A
//! divergence -- shguard resolved a word to something bash does not
//! actually produce -- is the class of bug this harness exists to find
//! mechanically rather than by one-off manual review (see README "The
//! regression table").
//!
//! # Scope: per-simple-command argv, never full pipeline runtime
//!
//! The capture technique below (`Sandbox::capture_argv`) only ever proves
//! what bash would put in `argv` for ONE simple command's word list -- it
//! never actually connects a pipe between two real processes. For a
//! candidate with a top-level `|` (the decode-fed-pipe class), each stage's
//! text is captured and diffed independently against shguard's own
//! per-stage `analyze()` call; the harness never asserts anything about
//! end-to-end pipeline runtime behavior (what stage 2 would actually read
//! from stage 1's real stdout). Making that safe would need a much heavier
//! sandbox (real process isolation with no shared filesystem/network at
//! all) than a PATH-shim can provide, since the receiving end of a real
//! pipe can act on whatever bytes the sending end produces.
//!
//! # Safety design (read before touching `Sandbox`/`capture_argv`)
//!
//! Every candidate LOOKS like it could run `rm -rf /` for real. Layered
//! defenses, each independently sufficient:
//!
//! 1. **PATH-shim sandbox.** Every bash process this harness spawns runs
//!    with `PATH` pointing only at [`SHIM_COMMANDS`] no-op scripts,
//!    `HOME`/cwd in fresh tempdirs (never the real `$HOME` -- several
//!    guardfall cases reference `~/.config/shguard/config.toml`), and
//!    `env_clear()` otherwise.
//! 2. **Static reject-list before ANY execution** ([`is_unsafe_to_execute`]):
//!    an absolute-path command invocation (`/bin/rm`, bypassing the PATH
//!    shim entirely) or a redirect operator (`>`, `>>`, `<>`) aimed at an
//!    absolute/tilde/parent-relative target ANYWHERE in the text --
//!    including inside a `$(...)`/backtick substitution, where a redirect
//!    is a shell builtin that never goes through PATH at all, so no shim
//!    can catch it. Both checks scan the raw text unconditionally, in
//!    addition to (never instead of) the shim.
//! 3. **The capture technique itself never executes the candidate as a
//!    command.** [`Sandbox::capture_argv`] splices the candidate as
//!    trailing *arguments* to a fixed inner echo-back command, so the
//!    candidate's own words are only ever used as literal argv/positional-
//!    parameter data -- the only real subprocess execution that happens is
//!    (a) the two bash invocations the harness itself controls, invoked by
//!    absolute path (see point 4), and (b) any command/process substitution
//!    embedded IN the candidate, which bash genuinely evaluates as part of
//!    expansion -- exactly where the PATH shim does its job.
//! 4. **The harness's own two bash invocations never resolve through the
//!    shim.** `bash`/`sh` are deliberately IN [`SHIM_COMMANDS`] (a candidate
//!    can embed `$(sh -c '...')`), which means the shimmed `PATH` would
//!    swallow a bare `bash` lookup too -- including the harness's OWN
//!    wrapper command, silently breaking capture (the inner `printf` never
//!    runs, every comparison would spuriously "diverge" or silently
//!    compare against nothing). [`find_real_bash`] resolves bash's
//!    absolute path once via the *test process's own* unmodified `PATH`,
//!    before any sandbox env is ever constructed; both the outer spawn and
//!    the inner reference embedded in the wrapper script use that absolute
//!    path, so neither ever performs a PATH lookup that could hit the shim.
//!
//! A crafted string engineered to defeat any ONE of these still has to get
//! past the others -- see `sandbox_never_executes_the_real_rm` and
//! `absolute_path_and_redirect_guard_rejects_crafted_bypass_attempts` below.
//!
//! # Known-open findings
//!
//! Two shapes of "this isn't a fresh divergence" are recognized WITHOUT
//! narrowing the mutator's own mechanism pool (issue #93 review point 4):
//!
//! - [`shguard_argv_contains_unexpanded_tilde`]: a fully intentional,
//!   `src/normalize.rs`-documented design choice (tilde never resolves to a
//!   real path), not a bug -- skipped from comparison entirely, never
//!   logged as a divergence at all.
//! - [`is_known_empty_brace_elision_gap`]: a real, confirmed
//!   `src/normalize.rs` bug (an unquoted empty brace-alternation member
//!   should be elided from argv the way bash elides it, but isn't) --
//!   recognized by SHAPE (not a fixed candidate-string list), logged and
//!   reported on every run, but excluded from the main sweep's pass/fail
//!   assertion. `known_gap_unquoted_empty_brace_member_is_not_elided`
//!   below pins ONE concrete reproducer as an `#[ignore]`d test
//!   (`cargo test -- --ignored` surfaces it) so the finding stays
//!   discoverable rather than silently narrowed away; see that test's doc
//!   for the followup-issue writeup.
//!
//! [`KNOWN_OPEN_FINDINGS`] is the same kind of escape hatch by exact
//! candidate string, for a finding that isn't (yet) cleanly
//! shape-characterizable -- currently holds one entry: an unquoted `$IFS`
//! reference glued directly against a brace group produces a word count
//! real bash's documented expansion order doesn't predict (confirmed
//! independent of this harness's own capture code; the underlying bash
//! mechanism itself isn't diagnosed). See
//! `known_gap_ifs_glued_directly_to_brace_group` below for the full
//! reproducer and reasoning.
//!
//! # Bash version
//!
//! macOS ships bash 3.2; CI (`ubuntu-latest`) runs bash 5.x. The specific
//! combinators exercised here (ANSI-C quoting, `$IFS` splitting, brace
//! alternation, tilde forms, variable indirection) are stable since bash
//! 3.0, so this is a diagnostic, not a blocker: [`find_real_bash`] prefers
//! whatever `bash` a contributor's `PATH` resolves first (typically a
//! Homebrew-installed newer bash ahead of `/bin/bash` on macOS), and the
//! resolved version string is printed as part of the test's diagnostic
//! output and included in the structured divergence report.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use shguard::normalize::Resolution;
use shguard::verdict::Decision;
use tempfile::TempDir;

// =====================================================================
// Hand-rolled deterministic PRNG (splitmix64) -- no `rand` dependency
// permitted (see PR scope). Deterministic by default so `cargo test` is
// 100% reproducible; `SHGUARD_FUZZ_SEED` overrides for nightly CI.
// =====================================================================

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid an all-zero state, which would make every subsequent
        // splitmix64 step degenerate to zero forever.
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform value in `0..bound`. `bound` is always a small, fixed-size
    /// slice/list length in this file, so the modulo-bias this introduces
    /// (favoring the low end by a fraction of a percent) is irrelevant to a
    /// structural mutator that only needs "pick one of these" diversity,
    /// not statistically uniform sampling.
    fn gen_range(&mut self, bound: usize) -> usize {
        debug_assert!(bound > 0, "gen_range bound must be non-zero");
        (self.next_u64() % bound as u64) as usize
    }

    fn gen_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// =====================================================================
// Static reject-list (defense layer 2) -- scanned unconditionally, on the
// RAW candidate text, before any bash process is spawned for it. Never
// executed instead of the PATH shim; both defenses are always active.
// =====================================================================

/// Absolute-path command invocations that would bypass the PATH shim
/// entirely (`/bin/rm`, `` `$(/sbin/reboot)` ``). The mutator never
/// generates these -- every seed token is a bare command name -- but this
/// guards the gap explicitly rather than trusting that by construction.
const ABSOLUTE_COMMAND_PREFIXES: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/sbin/",
    "/usr/sbin/",
];

/// Characters that legitimately precede a NEW command in bash (so a match
/// right after one of them, or at the very start of the string, or right
/// after a run of whitespace containing a real newline, counts as
/// "command position" -- a plain space does not, since `echo /bin/rm` is
/// just an ordinary argument to `echo`, never an invocation of `/bin/rm`).
const COMMAND_BOUNDARY: &[char] = &[';', '&', '|', '`', '(', '{'];

fn contains_absolute_path_invocation(text: &str) -> bool {
    for prefix in ABSOLUTE_COMMAND_PREFIXES {
        for (idx, _) in text.match_indices(prefix) {
            let before = text[..idx].trim_end();
            let boundary_ok = before.is_empty()
                || text[before.len()..idx].contains('\n')
                || before.ends_with(COMMAND_BOUNDARY);
            if boundary_ok {
                return true;
            }
        }
    }
    false
}

/// A redirect operator (`>`, `>>`, `<>`, optionally fd-prefixed like `2>`)
/// aimed at an absolute, tilde, or parent-relative-ascent target, scanned
/// ANYWHERE in the text -- not just at top level. Redirects are a shell
/// builtin, never subject to PATH lookup, so `$(: > /etc/cron.d/x)` would
/// genuinely write a real file even inside a perfect command-name shim;
/// this is the independent guard against exactly that. `<(`/`>(` process
/// substitution is excluded (not a redirect at all).
fn contains_dangerous_redirect(text: &str) -> bool {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        let c = bytes[i];
        if c != b'>' && c != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < n && bytes[j] == b'(' {
            // Process substitution, not a redirect at all.
            i += 1;
            continue;
        }
        if j < n && bytes[j] == c {
            j += 1; // `>>` append, or a heredoc `<<` (still not our target
        // shape below, but consuming the second char keeps the target
        // scan correctly positioned either way).
        } else if c == b'<' && j < n && bytes[j] == b'>' {
            j += 1; // `<>` read-write redirect.
        } else if c == b'>' && j < n && bytes[j] == b'|' {
            j += 1; // `>|` clobber-override write (fable review follow-up).
        }
        while j < n && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if text.is_char_boundary(j) {
            let rest = &text[j..];
            if rest.starts_with('/') || rest.starts_with('~') || rest.starts_with("..") {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// The combined static reject-list: refuse to execute (skip the candidate,
/// never panic) rather than rely solely on the PATH shim.
fn is_unsafe_to_execute(text: &str) -> bool {
    text.contains('\0')
        || contains_absolute_path_invocation(text)
        || contains_dangerous_redirect(text)
}

#[test]
fn absolute_path_and_redirect_guard_rejects_crafted_bypass_attempts() {
    assert!(contains_absolute_path_invocation("/bin/rm -rf /"));
    assert!(contains_absolute_path_invocation(
        "echo hi && /usr/bin/rm -rf /"
    ));
    assert!(contains_absolute_path_invocation("$(/sbin/reboot)"));
    // A brace command GROUP (`{ ...; }`) also puts its contents in command
    // position (fable review follow-up) -- the mutator never generates
    // this shape, but the guard should not silently miss it either.
    assert!(contains_absolute_path_invocation("{ /bin/rm -rf /; }"));
    // Not at a command boundary -- an ordinary argument to `echo`, not an
    // invocation of `/bin/rm`. Still fully safe to attempt (see the
    // sandbox self-test below); this only documents the guard's own
    // boundary logic, not the harness's overall safety.
    assert!(!contains_absolute_path_invocation("echo /bin/rm"));

    assert!(contains_dangerous_redirect("echo hi > /etc/passwd"));
    assert!(contains_dangerous_redirect("echo hi >> /etc/shadow"));
    // `>|` (clobber-override, ignores `set -o noclobber`) is still a write
    // redirect -- fable review follow-up, the byte-scanner previously left
    // the `|` unconsumed and never reached the target text.
    assert!(contains_dangerous_redirect("echo hi >| /etc/passwd"));
    assert!(contains_dangerous_redirect("$(: > /etc/cron.d/x)"));
    assert!(contains_dangerous_redirect(
        "`: > /root/.ssh/authorized_keys`"
    ));
    assert!(contains_dangerous_redirect(
        "echo hi > ~/.config/shguard/config.toml"
    ));
    assert!(contains_dangerous_redirect("echo hi > ../../etc/passwd"));
    assert!(!contains_dangerous_redirect("echo hi > local.log"));
    assert!(!contains_dangerous_redirect("echo <(cat local.log)"));

    assert!(is_unsafe_to_execute("/bin/rm -rf /"));
    assert!(is_unsafe_to_execute("$(: > /etc/passwd)"));
    assert!(!is_unsafe_to_execute("rm -rf /"));
}

// =====================================================================
// Top-level metachar classifier: decides whether the capture technique
// (single simple command, or a pure top-level pipe split into stages) can
// be attempted at all, or whether the candidate is Ineligible (`;`, `&`,
// `&&`, `||`, a literal newline, a heredoc marker, or a bare top-level
// redirect). Missing a top-level `;`/`&` here is bounded by the PATH shim
// (a second statement's command name is still looked up via the shimmed
// PATH); missing a top-level bare redirect is NOT bounded the same way --
// `>`/`<` are shell builtins -- which is why [`contains_dangerous_redirect`]
// above exists as an unconditional, independent second check rather than
// relying on this classifier alone.
// =====================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// `$(...)`, `` `...` ``'s cousin via parens, `<(...)`, `>(...)`, or a
    /// bare `(...)` grouping -- closes on an unescaped `)`.
    Paren,
    /// `${...}` -- closes on an unescaped `}`.
    Brace,
    /// Inside an (unquoted-at-open) `"..."` region -- closes on an
    /// unescaped `"`. Real bash resets quoting inside a nested `$(...)`,
    /// which falls out naturally here: entering a `$(`/`` ` `` push adds a
    /// NEW frame on top of this one, so a fresh `"..."` inside it pushes
    /// its own independent `Dq` frame rather than trying to close this one.
    Dq,
}

/// Returns the byte ranges of each `|`-separated stage when `text` is safe
/// for [`Sandbox::capture_argv`]'s technique (a single simple command, or a
/// pure top-level pipe chain with no other top-level separator/redirect) --
/// a single range covering the whole string when there is no top-level
/// pipe at all. Returns `None` (Ineligible) for anything else: a top-level
/// `;`, `&`, `&&`, `||`, a literal (unescaped) newline, or a bare top-level
/// `<`/`>` redirect (including a heredoc `<<`, which starts with a bare
/// `<`). Fails closed (`None`) on any unterminated quote/substitution too.
fn split_top_level_stages(text: &str) -> Option<Vec<(usize, usize)>> {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut stack: Vec<Frame> = Vec::new();
    let mut stage_start = 0usize;
    let mut ranges = Vec::new();

    while i < n {
        let c = bytes[i];
        let top = stack.last().copied();

        // Single-quoted region: fully literal, no escapes at all. Valid in
        // any context except while the innermost frame is already a `Dq`
        // region, where an unescaped `'` is just an ordinary character.
        if c == b'\'' && top != Some(Frame::Dq) {
            i += 1;
            while i < n && bytes[i] != b'\'' {
                i += 1;
            }
            if i >= n {
                return None;
            }
            i += 1;
            continue;
        }

        // ANSI-C quoting `$'...'` -- recognized in any context except
        // inside an already-open `Dq` region (bash does not recognize
        // `$'...'` there; the `$` and following text are ordinary).
        if c == b'$' && i + 1 < n && bytes[i + 1] == b'\'' && top != Some(Frame::Dq) {
            i += 2;
            loop {
                if i >= n {
                    return None;
                }
                match bytes[i] {
                    b'\\' => {
                        if i + 1 >= n {
                            return None;
                        }
                        i += 2;
                    }
                    b'\'' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }

        // Backslash: escapes the next character everywhere else (a close
        // enough approximation of bash's real double-quote-vs-bare
        // escaping rules for the purpose of finding boundaries -- see
        // module docs; never inside a bare single-quoted region, already
        // fully consumed above).
        if c == b'\\' {
            if i + 1 >= n {
                return None;
            }
            i += 2;
            continue;
        }

        if c == b'"' {
            if top == Some(Frame::Dq) {
                stack.pop();
            } else {
                stack.push(Frame::Dq);
            }
            i += 1;
            continue;
        }

        if c == b'`' {
            // Backticks are flat (no nesting) -- skip to the next
            // unescaped backtick.
            i += 1;
            loop {
                if i >= n {
                    return None;
                }
                match bytes[i] {
                    b'\\' => {
                        if i + 1 >= n {
                            return None;
                        }
                        i += 2;
                    }
                    b'`' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }

        if c == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
            stack.push(Frame::Paren);
            i += 2;
            continue;
        }
        if c == b'$' && i + 1 < n && bytes[i + 1] == b'{' {
            stack.push(Frame::Brace);
            i += 2;
            continue;
        }
        if (c == b'<' || c == b'>') && i + 1 < n && bytes[i + 1] == b'(' {
            stack.push(Frame::Paren);
            i += 2;
            continue;
        }
        if c == b'(' {
            stack.push(Frame::Paren);
            i += 1;
            continue;
        }
        if c == b')' {
            match top {
                Some(Frame::Paren) => {
                    stack.pop();
                    i += 1;
                    continue;
                }
                _ => return None, // unmatched, or mismatched against Brace/Dq
            }
        }
        // A bare `{`/`}` is brace-ALTERNATION syntax (word-internal, never a
        // nesting operator this scanner needs to track) -- only `${`
        // (handled above) pushes a `Brace` frame, so a bare one here is
        // always just an ordinary character.
        if c == b'{' {
            i += 1;
            continue;
        }
        if c == b'}' {
            if top == Some(Frame::Brace) {
                stack.pop();
            }
            i += 1;
            continue;
        }

        if top.is_none() {
            match c {
                b'\n' | b';' | b'&' => return None,
                b'<' | b'>' => return None,
                b'|' => {
                    if i + 1 < n && bytes[i + 1] == b'|' {
                        return None; // `||`, a control operator, not a pipe
                    }
                    ranges.push((stage_start, i));
                    i += 1;
                    stage_start = i;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }

    if !stack.is_empty() {
        return None; // unterminated quote/substitution
    }
    ranges.push((stage_start, n));
    Some(ranges)
}

#[test]
fn classifier_rejects_top_level_semicolon_and_control_operators() {
    assert!(split_top_level_stages("echo hi; rm -rf /").is_none());
    assert!(split_top_level_stages("true && rm -rf /").is_none());
    assert!(split_top_level_stages("true || rm -rf /").is_none());
    assert!(split_top_level_stages("rm -rf / &").is_none());
    assert!(split_top_level_stages("echo hi\nrm -rf /").is_none());
}

#[test]
fn classifier_rejects_top_level_redirect_including_heredoc() {
    assert!(split_top_level_stages("echo hi > /dev/sda").is_none());
    assert!(split_top_level_stages("cat <<EOF\nhi\nEOF").is_none());
}

#[test]
fn classifier_splits_top_level_pipe_but_not_nested_pipe() {
    let text = "echo cm0gLXJmIC8= | base64 -d | sh";
    let ranges = split_top_level_stages(text).expect("should classify as a pipeline");
    assert_eq!(ranges.len(), 3);
    assert_eq!(&text[ranges[0].0..ranges[0].1], "echo cm0gLXJmIC8= ");
    assert_eq!(&text[ranges[1].0..ranges[1].1], " base64 -d ");
    assert_eq!(&text[ranges[2].0..ranges[2].1], " sh");

    // A pipe living inside a command substitution must never be treated as
    // an OUTER stage boundary.
    let ranges = split_top_level_stages("$(echo cm0gLXJmIC8= | base64 -d)")
        .expect("should classify as a single command");
    assert_eq!(ranges.len(), 1);
}

#[test]
fn classifier_fails_closed_on_unterminated_quote_or_substitution() {
    assert!(split_top_level_stages("echo 'unterminated").is_none());
    assert!(split_top_level_stages("echo $(unterminated").is_none());
    assert!(split_top_level_stages("echo \"unterminated").is_none());
}

// =====================================================================
// Sandbox: PATH-shim directory, isolated HOME/cwd, and the argv-capture
// technique itself (defense layers 1, 3, 4 -- see module docs).
// =====================================================================

/// Every command name any seed corpus line, GuardFall class, or mutator
/// mechanism in this file can produce -- enumerated from `tests/guardfall.rs`
/// plus the task's own explicit list. `bash`/`sh` are included so a
/// candidate-embedded `$(sh -c '...')` never reaches a real interpreter,
/// even though the harness's OWN two bash invocations always bypass this
/// shim via [`find_real_bash`]'s resolved absolute path (see module docs,
/// point 4).
const SHIM_COMMANDS: &[&str] = &[
    "rm", "dd", "shred", "truncate", "tar", "find", "git", "tee", "cat", "echo", "printf", "sh",
    "bash", "base64", "sed", "chmod", "mkswap", "timeout", "chrt", "taskset", "busybox", "true",
    "date", "ls", "cp", "mv", "install",
];

/// Every shim is byte-identical: a no-op that logs its own invocation
/// (argv, unit-separator-joined) to `$SHGUARD_FUZZ_SHIM_LOG` when set, then
/// exits 0. It does not need to behave like the real tool at all -- only
/// that nothing dangerous ever runs, and that a self-test can confirm IT
/// (not the real binary) was the thing invoked.
const SHIM_SCRIPT: &str = "#!/bin/sh\nif [ -n \"$SHGUARD_FUZZ_SHIM_LOG\" ]; then\n  { printf '%s' \"$0\"; for a in \"$@\"; do printf '\\x1f%s' \"$a\"; done; printf '\\n'; } >> \"$SHGUARD_FUZZ_SHIM_LOG\"\nfi\nexit 0\n";

fn build_shims(dir: &Path) {
    for name in SHIM_COMMANDS {
        let path = dir.join(name);
        fs::write(&path, SHIM_SCRIPT).expect("shim script should write");
        let mut perms = fs::metadata(&path)
            .expect("shim metadata should read")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("shim permissions should set");
    }
}

/// Resolves bash's real absolute path via the TEST PROCESS's own,
/// unmodified `PATH` -- before any sandbox env is ever constructed (see
/// module docs, point 4). Prefers whichever `bash` the ambient `PATH`
/// resolves first, which on a typical macOS setup means a Homebrew-newer
/// bash ahead of the system's bash 3.2 (issue #93 review point 3).
fn find_real_bash() -> PathBuf {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("bash");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("/bin/bash")
}

/// Single-quotes `s` for safe splicing into a bash script string (fable
/// review follow-up): [`find_real_bash`]'s resolved path was previously
/// interpolated unquoted, so a `PATH` entry containing whitespace would
/// word-split and silently break the capture. Escapes an embedded single
/// quote by closing, emitting an escaped quote, and reopening -- the
/// standard POSIX-shell single-quote escape, though a resolved bash binary
/// path is never expected to contain one in practice.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The inner echo-back script, pre-quoted for direct splicing into the
/// outer wrapper: single-quoted so the OUTER bash passes it through
/// untouched, and the INNER bash (which actually runs it) sees exactly
/// `printf "%s\0" "$#"; printf "%s\0" "$@"` -- printf's own escape handling
/// turns `\0` into a literal NUL byte per field, which is what makes
/// NUL-splitting the captured stdout safe even when a candidate's own
/// expansion contains embedded whitespace or newlines.
///
/// The leading `"$#"` field is load-bearing, not decoration: NUL-splitting
/// alone cannot tell a genuine trailing empty ARGUMENT apart from the
/// trailing empty SPLIT ARTIFACT every NUL-terminated stream produces after
/// its final separator (`printf` always emits a NUL after each field, so
/// splitting produces one more empty piece than there are real fields).
/// An earlier version of this harness guessed by popping one trailing
/// empty piece unconditionally -- which silently ate a real, meaningful
/// trailing empty argv element whenever a candidate's LAST word was itself
/// empty (e.g. a brace alternation ending in `,}`). Reading the exact
/// count first and taking exactly that many fields afterward removes the
/// ambiguity entirely, regardless of how many trailing artifacts follow.
const INNER_ECHO_SCRIPT_QUOTED: &str = r#"'printf "%s\0" "$#"; printf "%s\0" "$@"'"#;

struct Sandbox {
    shim_dir: TempDir,
    home_dir: TempDir,
    cwd_dir: TempDir,
    log_path: PathBuf,
    bash_path: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let shim_dir = tempfile::tempdir().expect("tempdir should create");
        let home_dir = tempfile::tempdir().expect("tempdir should create");
        let cwd_dir = tempfile::tempdir().expect("tempdir should create");
        build_shims(shim_dir.path());
        let log_path = shim_dir.path().join(".shim-log");
        let bash_path = find_real_bash();
        Self {
            shim_dir,
            home_dir,
            cwd_dir,
            log_path,
            bash_path,
        }
    }

    fn bash_version_line(&self) -> String {
        Command::new(&self.bash_path)
            .arg("--version")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| s.lines().next().map(str::to_string))
            .unwrap_or_else(|| "<unknown bash version>".to_string())
    }

    /// Captures bash's real post-expansion argv for `stage_text`, a single
    /// simple command's own text (never a multi-stage string -- callers
    /// split on `|` themselves first via [`split_top_level_stages`]).
    /// Returns `None` if the static reject-list flags the text, if the
    /// spawn itself fails, or if the outer bash exits non-zero (a
    /// generated candidate with invalid syntax, e.g. an unbalanced
    /// quote-split -- not a divergence, just not comparable).
    fn capture_argv(&self, stage_text: &str) -> Option<Vec<String>> {
        if is_unsafe_to_execute(stage_text) {
            return None;
        }
        let script = format!(
            "{bash} -c {inner} -- {stage}",
            bash = shell_single_quote(&self.bash_path.display().to_string()),
            inner = INNER_ECHO_SCRIPT_QUOTED,
            stage = stage_text,
        );
        let output = Command::new(&self.bash_path)
            .arg("-c")
            .arg(&script)
            .env_clear()
            .env("PATH", self.shim_dir.path())
            .env("HOME", self.home_dir.path())
            .env("SHGUARD_FUZZ_SHIM_LOG", &self.log_path)
            .current_dir(self.cwd_dir.path())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let fields: Vec<&[u8]> = output.stdout.split(|&b| b == 0).collect();
        let count: usize = std::str::from_utf8(fields.first().copied()?)
            .ok()?
            .parse()
            .ok()?;
        // Exactly `count` fields follow the count field itself, regardless
        // of how many trailing empty artifacts the NUL-split produced
        // beyond that point (see `INNER_ECHO_SCRIPT_QUOTED`'s doc).
        let argv = fields.get(1..1 + count)?;
        Some(
            argv.iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect(),
        )
    }
}

#[test]
fn sandbox_never_executes_the_real_rm() {
    let sandbox = Sandbox::new();
    let canary_dir = tempfile::tempdir().expect("tempdir should create");
    let canary = canary_dir.path().join("canary.txt");
    fs::write(&canary, "still here").expect("canary should write");
    let canary_dir_display = canary_dir.path().display();

    // Plain-argument form: per the capture technique's own design, the
    // candidate's words are only ever data handed to the inner echo
    // command -- "rm" here is never looked up on PATH at all.
    let argv = sandbox
        .capture_argv(&format!("rm -rf {canary_dir_display}"))
        .expect("capture should succeed");
    assert_eq!(argv[0], "rm");
    assert!(
        canary.exists(),
        "canary must survive a plain-argument rm candidate"
    );

    // Command-substitution form: `rm` genuinely executes here as part of
    // expanding the word, but PATH resolves it to the harmless shim, which
    // prints nothing -- the substitution's result is the empty string, and
    // since it is both unquoted and the word's ENTIRE content, ordinary
    // field-splitting elimination drops it from argv entirely (real bash:
    // `echo $(true)` passes echo zero arguments, not one empty argument --
    // unlike a brace-alternation-produced empty word, which is a literal
    // word from an earlier, separate expansion stage and is never subject
    // to this elimination).
    let argv = sandbox
        .capture_argv(&format!("$(rm -rf {canary_dir_display})"))
        .expect("capture should succeed");
    assert_eq!(argv, Vec::<String>::new());
    assert!(
        canary.exists(),
        "canary must survive a command-substitution rm candidate"
    );

    let log = fs::read_to_string(&sandbox.log_path).expect("shim log should read");
    assert!(
        log.contains("/rm\x1f-rf\x1f"),
        "the rm shim (not the real binary) should have logged its own invocation: {log:?}"
    );
}

// =====================================================================
// Grammar-aware mutator: composable generator functions for each GuardFall
// mechanism, applied to a small set of seed token lists structurally
// (nested/combined) rather than mutating uniform random bytes. Mechanisms
// only need to be SYNTACTICALLY valid bash -- they do not need to preserve
// the token's original meaning, since the whole point of the harness is to
// let shguard and real bash EACH independently compute what a construct
// resolves to and diff the results.
// =====================================================================

/// Case 2 (README "Attribution"): `$'\xHH...'` ANSI-C hex-escapes every
/// byte of `s`.
fn ansi_c_encode(s: &str) -> String {
    let mut out = String::from("$'");
    for b in s.as_bytes() {
        out.push_str(&format!("\\x{b:02x}"));
    }
    out.push('\'');
    out
}

/// Case A: splits `s` at a random interior point with an adjacent empty
/// quote pair (`r''m`/`r""m`), which bash re-joins via ordinary
/// quote-removal into one word.
fn quote_split(s: &str, rng: &mut Rng) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 2 {
        return format!("''{s}");
    }
    let split_at = 1 + rng.gen_range(chars.len() - 1);
    let head: String = chars[..split_at].iter().collect();
    let tail: String = chars[split_at..].iter().collect();
    if rng.gen_bool() {
        format!("{head}''{tail}")
    } else {
        format!("{head}\"\"{tail}")
    }
}

/// Wraps `s` in a brace alternation against an empty alternative -- bash
/// expands `{s,}`/`{,s}` into TWO words (`s` and `""`), exactly the
/// cartesian-product multiplication `src/normalize.rs`'s own brace folding
/// documents; the harness doesn't need `s`'s meaning preserved, only that
/// this is valid brace syntax.
fn brace_wrap(s: &str, rng: &mut Rng) -> String {
    if rng.gen_bool() {
        format!("{{{s},}}")
    } else {
        format!("{{,{s}}}")
    }
}

/// One of shguard's own tilde-form extensions (`~`, `~+`, `~-`, `~user`),
/// plus the self-protection corpus's own tilde-path shape.
fn tilde_form(rng: &mut Rng) -> &'static str {
    const FORMS: &[&str] = &["~", "~+", "~-", "~root", "~/.config/shguard/config.toml"];
    FORMS[rng.gen_range(FORMS.len())]
}

/// Case C: wraps `s` in a real command substitution (`$(...)` or
/// backticks) around a `printf` invocation -- `printf` is shimmed to a
/// no-op, so the substitution's real runtime value is always the empty
/// string; the substitution still genuinely executes (through the shim),
/// which is exactly the construct shguard's normalize.rs always folds to
/// `Unresolvable(CommandSubstitution)` regardless of content.
fn subst_wrap(s: &str, rng: &mut Rng) -> String {
    if rng.gen_bool() {
        format!("$(printf '%s' '{s}')")
    } else {
        format!("`printf '%s' '{s}'`")
    }
}

/// Case C-ext: `X=<current-token>; ` prefix plus `$X` in its place --
/// shguard's own same-line variable-indirection extension. Always renders
/// with a top-level `;`, which [`split_top_level_stages`] always correctly
/// classifies as Ineligible (variable indirection genuinely requires two
/// sequential statements in real bash -- a `VAR=val` prefix on the SAME
/// simple command as `$VAR` does not expand `$VAR` against it, since
/// expansion of a command line happens before that line's own assignment
/// prefix takes effect). This mechanism is included for generation
/// diversity (shguard's own `analyze()` still runs on the result) even
/// though the classifier excludes every candidate that uses it from the
/// bash-diffable pool by construction -- a real, documented scope boundary
/// (module docs), not an oversight.
fn wrap_var_indirection(cmd_word: &str) -> (String, String) {
    (format!("X={cmd_word}; "), "$X".to_string())
}

fn is_plain_word(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.' | '~'))
}

fn plain_word_index(tokens: &[String], rng: &mut Rng) -> Option<usize> {
    let candidates: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| is_plain_word(t))
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates[rng.gen_range(candidates.len())])
    }
}

#[derive(Clone, Copy)]
enum Mechanism {
    AnsiC,
    QuoteSplit,
    BraceWrap,
    TildeForm,
    SubstWrap,
    IfsJoin,
    VarIndirection,
}

const MECHANISMS: &[Mechanism] = &[
    Mechanism::AnsiC,
    Mechanism::QuoteSplit,
    Mechanism::BraceWrap,
    Mechanism::TildeForm,
    Mechanism::SubstWrap,
    Mechanism::IfsJoin,
    Mechanism::VarIndirection,
];

/// Same as [`MECHANISMS`] minus [`Mechanism::VarIndirection`] -- used when
/// mutating ONE stage of a multi-stage pipeline candidate.
/// `VarIndirection` always renders with a top-level `;` (module docs on
/// [`wrap_var_indirection`]), which is fine for a standalone single-stage
/// candidate (the classifier correctly marks the WHOLE thing Ineligible,
/// same as any other `;`-bearing text) but would corrupt a pipeline
/// candidate's own assumed stage boundaries if applied to just one of its
/// stages -- not a mutator bug, just a mechanism that is fundamentally
/// scoped to "the whole candidate", never "one piece of an already-piped
/// structure". Excluding it here (rather than letting every such pipeline
/// draw get silently counted as a "generator desync") keeps that counter
/// meaningful as a signal for genuine bugs.
const PIPELINE_STAGE_MECHANISMS: &[Mechanism] = &[
    Mechanism::AnsiC,
    Mechanism::QuoteSplit,
    Mechanism::BraceWrap,
    Mechanism::TildeForm,
    Mechanism::SubstWrap,
    Mechanism::IfsJoin,
];

/// Applies 1-3 randomly chosen mechanisms to `tokens` (a single stage's
/// words), nesting/combining them in place -- e.g. ANSI-C-encoding a
/// command name AND THEN wrapping the encoded result as a variable
/// assignment's RHS -- and renders the result as one candidate string.
/// `mechanisms` is [`MECHANISMS`] for a standalone (single-stage)
/// candidate, or [`PIPELINE_STAGE_MECHANISMS`] when mutating one stage of a
/// multi-stage pipeline (see that constant's doc). Never generates a raw
/// unquoted `|`/`;`/`&`/newline anywhere in the output otherwise: every
/// mechanism here only ever emits `$IFS`, brace syntax, quotes, or a
/// `$(...)`/backtick substitution around already-safe text, which is what
/// makes [`pipeline_stage_count_is_consistent`]'s defensive re-check
/// (issue #93 review point 5) expected to always pass rather than trusted
/// blindly.
fn mutate_stage(
    tokens: &[String],
    rng: &mut Rng,
    mechanism_count: usize,
    mechanisms: &[Mechanism],
) -> String {
    let mut tokens: Vec<String> = tokens.to_vec();
    let mut separator = " ".to_string();
    let mut prefix = String::new();
    let mut var_indirection_used = false;

    for _ in 0..mechanism_count {
        if tokens.is_empty() {
            break;
        }
        match mechanisms[rng.gen_range(mechanisms.len())] {
            Mechanism::AnsiC => {
                if let Some(idx) = plain_word_index(&tokens, rng) {
                    tokens[idx] = ansi_c_encode(&tokens[idx]);
                }
            }
            Mechanism::QuoteSplit => {
                if let Some(idx) = plain_word_index(&tokens, rng) {
                    tokens[idx] = quote_split(&tokens[idx], rng);
                }
            }
            Mechanism::BraceWrap => {
                let idx = rng.gen_range(tokens.len());
                tokens[idx] = brace_wrap(&tokens[idx], rng);
            }
            Mechanism::TildeForm => {
                if tokens.len() > 1 {
                    let idx = 1 + rng.gen_range(tokens.len() - 1);
                    tokens[idx] = tilde_form(rng).to_string();
                }
            }
            Mechanism::SubstWrap => {
                let idx = rng.gen_range(tokens.len());
                tokens[idx] = subst_wrap(&tokens[idx], rng);
            }
            Mechanism::IfsJoin => {
                separator = "$IFS".to_string();
            }
            Mechanism::VarIndirection => {
                if !var_indirection_used {
                    let (p, v) = wrap_var_indirection(&tokens[0]);
                    prefix = p;
                    tokens[0] = v;
                    var_indirection_used = true;
                }
            }
        }
    }

    format!("{prefix}{}", tokens.join(&separator))
}

// =====================================================================
// Seed corpus: base command shapes drawn from `tests/guardfall.rs`'s
// dangerous cases (never its `guardfall_redirect_and_tee_cases` module --
// those seed strings contain LIVE redirects to real absolute paths like
// `> /etc/passwd`/`> /dev/sda` and must never reach [`Sandbox::capture_argv`]
// at all, per issue #93 review point 1), represented as token lists so the
// mutator can target individual words rather than re-parsing opaque text.
// =====================================================================

fn seed_templates() -> Vec<Vec<&'static str>> {
    vec![
        vec!["rm", "-rf", "/"],
        vec!["rm", "-rf", "."],
        vec!["rm", "-rf", ".."],
        vec!["git", "push", "--force", "origin", "main"],
        vec!["git", "reset", "--hard", "HEAD"],
        vec!["git", "clean", "-fd"],
        vec!["find", "/x", "-delete"],
        vec!["dd", "if=/dev/zero", "of=/dev/sda"],
        vec!["shred", "/dev/sda"],
        vec!["truncate", "-s", "0", "/important"],
        vec!["tar", "-C", "/", "-x"],
        vec!["tee", "~/.config/shguard/config.toml"],
        vec!["sed", "-i", "~/.config/shguard/config.toml"],
        vec!["busybox", "rm", "-rf", "/"],
        vec!["timeout", "5", "rm", "-rf", "/"],
        vec!["chrt", "-f", "99", "rm", "-rf", "/"],
        vec!["taskset", "0x1", "rm", "-rf", "/"],
        vec!["cp", "evil.toml", "target.toml"],
        vec!["mv", "src", "dst"],
        vec!["echo", "hello"],
        vec!["cat", "file"],
        vec!["chmod", "777", "/etc/passwd"],
    ]
}

fn seed_pipeline_templates() -> Vec<Vec<Vec<&'static str>>> {
    vec![vec![
        vec!["echo", "cm0gLXJmIC8="],
        vec!["base64", "-d"],
        vec!["sh"],
    ]]
}

/// Literal, verbatim `tests/guardfall.rs` corpus lines, run through the
/// SAME classify/capture/compare pipeline as generated candidates rather
/// than a separately-mutated one -- directly exercises the classifier
/// against real published corpus shapes (a pipe nested inside a command
/// substitution, a top-level `;` from variable indirection) rather than
/// only against synthetic text. Deliberately excludes every
/// `guardfall_redirect_and_tee_cases` line (see this module's own doc).
const LITERAL_SEEDS: &[&str] = &[
    "r''m -rf /",
    "$'\\x72\\x6d' -rf /",
    "rm$IFS-rf$IFS/",
    "echo cm0gLXJmIC8= | base64 -d | sh",
    "git commit -m 'rm -rf /'",
    "X=rm; $X -rf /",
    "$(echo cm0gLXJmIC8= | base64 -d)",
    "busybox mkswap /dev/sda1",
    "tar -C ~ -xf evil.tar",
    "git push --force origin main",
];

/// A candidate: one or more `|`-joined stage texts, already individually
/// rendered (never re-mutated after this point).
fn generate_candidate(rng: &mut Rng) -> Vec<String> {
    let mechanism_count = 1 + rng.gen_range(3);
    if rng.gen_range(4) == 0 {
        let pipelines = seed_pipeline_templates();
        let template = &pipelines[rng.gen_range(pipelines.len())];
        template
            .iter()
            .map(|stage| {
                let tokens: Vec<String> = stage.iter().map(ToString::to_string).collect();
                mutate_stage(&tokens, rng, mechanism_count, PIPELINE_STAGE_MECHANISMS)
            })
            .collect()
    } else {
        let templates = seed_templates();
        let template = &templates[rng.gen_range(templates.len())];
        let tokens: Vec<String> = template.iter().map(ToString::to_string).collect();
        vec![mutate_stage(&tokens, rng, mechanism_count, MECHANISMS)]
    }
}

/// Defensive check (issue #93 review point 5): a generated multi-stage
/// candidate's OWN per-stage text must never contain a bare, unquoted
/// top-level separator that would desync the harness's assumed stage
/// boundary from bash's real tokenization. None of [`mutate_stage`]'s
/// mechanisms emit one (checked in its own doc comment), but this
/// re-derives the split from scratch via the same classifier the literal
/// seeds use -- the same source of truth the main loop actually acts on --
/// rather than trusting that invariant blindly. Always `true` for a
/// single-stage candidate (nothing to desync against); for a genuine
/// multi-stage one, `false` means the intended pipe-stage structure did
/// not survive rendering (e.g. a mechanism introduced its own top-level
/// separator), which the main loop counts as a generator bug and drops
/// rather than comparing.
fn pipeline_stage_count_is_consistent(rendered_stages: &[String]) -> bool {
    if rendered_stages.len() <= 1 {
        return true;
    }
    let full_text = rendered_stages.join(" | ");
    matches!(
        split_top_level_stages(&full_text),
        Some(ranges) if ranges.len() == rendered_stages.len()
    )
}

// =====================================================================
// The comparator: shguard's fully-resolved argv vs bash's real argv for
// one stage's text. An `Unresolvable` word anywhere in shguard's argv is a
// legitimate non-divergence (shguard correctly declined to guess) and is
// never compared -- only a candidate shguard resolved IN FULL gets diffed
// against bash's ground truth.
// =====================================================================

struct DivergenceReport {
    candidate: String,
    decision: Decision,
    shguard_argv: Vec<String>,
    bash_argv: Vec<String>,
    /// `true` for a divergence already confirmed (manually, against real
    /// bash) to be [`is_known_empty_brace_elision_gap`]'s tracked finding --
    /// still logged and reported, but excluded from the main sweep's
    /// pass/fail assertion (see that function's doc and the `#[ignore]`d
    /// reproducer test below for the followup-issue writeup).
    known_open: bool,
}

enum SkipReason {
    Unresolvable,
    /// shguard resolved every word, but at least one resolved to a literal,
    /// un-expanded tilde form (`~`, `~+`, `~-`, `~user`) -- `src/normalize.rs`
    /// documents this as fully intentional (`WordPiece::Tilde`'s own doc:
    /// resolving to a real home directory would need an env lookup, which
    /// the normalize stage never performs; blocklist rules are written to
    /// match the literal `~` text instead, e.g. `guardfall.rs`'s
    /// `tar -C~` case). Comparing this against bash's environment-dependent
    /// real expansion would flag EVERY tilde use as a "divergence" and
    /// drown out genuine findings under a known, accepted design choice --
    /// never a divergence worth reporting.
    TildeNotExpanded,
    CaptureFailed,
}

/// A divergence already manually confirmed (via a direct, harness-
/// independent `bash -c 'set -- ...; echo "$#"'` check, not just this
/// harness's own capture technique) to be ONE specific, narrow shguard gap:
/// `src/normalize.rs`'s `chunks_to_words` keeps an unquoted brace-
/// alternation member that resolves to the empty string as a real
/// `Resolved("")` word (its own doc scopes the "an empty resolved segment
/// vanishes" rule to an *`$IFS`-split* boundary specifically, never to a
/// brace-alternative boundary) -- but real bash elides a fully-unquoted
/// empty word from argv regardless of which earlier expansion produced the
/// emptiness. `{a,}` therefore resolves to `["a", ""]` in shguard's argv
/// but only `["a"]` in bash's. This is a real, reproducible bug (not a
/// harness artifact -- verified independent of this harness's own
/// capture/comparison code), but fixing `src/normalize.rs` is out of scope
/// for issue #93 (see this file's own module docs and the `#[ignore]`d
/// `known_gap_unquoted_empty_brace_member_is_not_elided` test below for the
/// full reproducer). Recognized by SHAPE, gated on the stage text actually
/// containing an unquoted empty brace member (`{,`/`,}`, exactly what
/// [`brace_wrap`] generates) -- fable-review follow-up: an earlier version
/// matched on the argv shape alone ("shguard's argv, with every empty word
/// stripped, equals bash's argv"), which is broader than this root cause
/// and would have silently absorbed ANY future `src/normalize.rs`
/// regression that spuriously injects an unrelated empty `Resolved("")`
/// word into the same bucket. Requiring the brace-member marker in the
/// source text keeps the bucket scoped to the one diagnosed mechanism.
fn is_known_empty_brace_elision_gap(
    stage_text: &str,
    shguard_argv: &[String],
    bash_argv: &[String],
) -> bool {
    if !stage_text.contains(",}") && !stage_text.contains("{,") {
        return false;
    }
    let without_empties: Vec<&String> = shguard_argv.iter().filter(|s| !s.is_empty()).collect();
    without_empties.len() == bash_argv.len() && without_empties.into_iter().eq(bash_argv.iter())
}

fn shguard_argv_contains_unexpanded_tilde(argv: &[String]) -> bool {
    argv.iter().any(|w| w.starts_with('~'))
}

fn compare_stage(
    sandbox: &Sandbox,
    stage_text: &str,
) -> Result<Option<DivergenceReport>, SkipReason> {
    let verdict = shguard::analyze(stage_text);
    let mut resolved = Vec::with_capacity(verdict.normalized_argv().len());
    for word in verdict.normalized_argv() {
        match word.resolution() {
            Resolution::Resolved(s) => resolved.push(s.clone()),
            Resolution::Unresolvable(_) => return Err(SkipReason::Unresolvable),
        }
    }
    if shguard_argv_contains_unexpanded_tilde(&resolved) {
        return Err(SkipReason::TildeNotExpanded);
    }
    let Some(bash_argv) = sandbox.capture_argv(stage_text) else {
        return Err(SkipReason::CaptureFailed);
    };
    if resolved == bash_argv {
        Ok(None)
    } else {
        Ok(Some(DivergenceReport {
            candidate: stage_text.to_string(),
            decision: verdict.decision(),
            known_open: is_known_empty_brace_elision_gap(stage_text, &resolved, &bash_argv),
            shguard_argv: resolved,
            bash_argv,
        }))
    }
}

fn report_divergences(divergences: &[DivergenceReport], bash_version: &str) {
    if let Ok(path) = std::env::var("SHGUARD_FUZZ_REPORT_PATH") {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("failed to open SHGUARD_FUZZ_REPORT_PATH {path}: {e}"));
        for d in divergences {
            let line = serde_json::json!({
                "candidate": d.candidate,
                "decision": format!("{:?}", d.decision),
                "shguard_argv": d.shguard_argv,
                "bash_argv": d.bash_argv,
                "bash_version": bash_version,
                "known_open": d.known_open,
            });
            writeln!(file, "{line}")
                .unwrap_or_else(|e| panic!("failed to write divergence report line: {e}"));
        }
    }
    for d in divergences {
        eprintln!(
            "DIVERGENCE candidate={:?} decision={:?} known_open={}\n  shguard_argv={:?}\n  bash_argv={:?}",
            d.candidate, d.decision, d.known_open, d.shguard_argv, d.bash_argv
        );
    }
}

/// Fixed by default so `cargo test` is 100% reproducible; override via
/// `SHGUARD_FUZZ_SEED` (nightly CI passes something run-specific, e.g.
/// derived from `github.run_id`, so it doesn't repeat the exact same
/// sequence every night).
const DEFAULT_SEED: u64 = 0x5347_5541_5244_2123; // "SGUARD!#" in ASCII hex

/// Kept small so the always-on `cargo test` path stays fast (a handful of
/// process spawns per candidate); nightly CI overrides via
/// `SHGUARD_FUZZ_ITERATIONS` with a much larger sweep.
const DEFAULT_ITERATIONS: u64 = 200;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Exact candidate strings the fuzzer has already shown, by manual
/// verification against real bash, to genuinely diverge from shguard's
/// static resolution -- see the `#[ignore]`d reproducer test(s) immediately
/// below this constant for the specific argv diff and reasoning. Excluded
/// from the main randomized sweep's pass/fail assertion (so `cargo test`
/// stays green) but never silently dropped from the corpus: each entry
/// here is also its own always-generated, always-`#[ignore]`d test, so
/// `cargo test -- --ignored` surfaces it, mirroring how
/// `tests/guardfall.rs`'s own issue #117 comment documents a known-open gap
/// without pinning it as a passing case.
const KNOWN_OPEN_FINDINGS: &[&str] = &["{echo,}$IFS{cm0gLXJmIC8=,}"];

/// Pinned reproducer for a real, confirmed `src/normalize.rs` gap this
/// fuzzer found at default settings: an unquoted brace-alternation member
/// that resolves to the empty string (`{a,}`, `{,x}`, and any nesting
/// thereof) is kept in shguard's normalized argv as a real `Resolved("")`
/// word, but real bash elides a fully-unquoted empty word from argv
/// regardless of which expansion produced the emptiness. Confirmed
/// independent of this harness's own capture/comparison code via a direct
/// `bash -c 'set -- {a,}; echo "$#"'` check (prints `1`, not `2`).
///
/// `src/normalize.rs`'s `chunks_to_words` doc scopes its "an empty resolved
/// segment vanishes" rule to an `$IFS`-SPLIT boundary specifically (the
/// `!single_segment` condition) -- a brace alternative always resolves
/// through its own, separate `fold_word` loop iteration, so `single_segment`
/// is `true` for it and the empty result is kept unconditionally.
///
/// Out of scope to fix here (issue #93 is the fuzzer harness, not a
/// `src/normalize.rs` change) -- flagged to the maintainer as a followup
/// issue candidate. `#[ignore]`d rather than silently excluded so
/// `cargo test -- --ignored` keeps it discoverable; if `src/normalize.rs`
/// is ever fixed to match bash here, this assertion will itself start
/// failing (a signal to update/remove it, not a silent bit-rot risk).
#[test]
#[ignore = "known src/normalize.rs gap (issue #93 fuzzer finding, not yet its own tracked issue): \
            an unquoted empty brace-alternation member is not elided from argv the way bash elides it"]
fn known_gap_unquoted_empty_brace_member_is_not_elided() {
    let sandbox = Sandbox::new();
    let candidate = "echo {a,}";

    let verdict = shguard::analyze(candidate);
    let shguard_argv: Vec<String> = verdict
        .normalized_argv()
        .iter()
        .map(|w| match w.resolution() {
            Resolution::Resolved(s) => s.clone(),
            Resolution::Unresolvable(kind) => panic!("expected fully resolved, got {kind:?}"),
        })
        .collect();
    let bash_argv = sandbox
        .capture_argv(candidate)
        .expect("capture should succeed for a plain candidate with no substitutions");

    assert_eq!(shguard_argv, vec!["echo", "a", ""]);
    assert_eq!(bash_argv, vec!["echo", "a"]);
    assert_ne!(
        shguard_argv, bash_argv,
        "if this now passes, src/normalize.rs has been fixed -- remove #[ignore] \
         and fold this case into tests/guardfall.rs instead"
    );
}

/// Second pinned reproducer, structurally unrelated to the brace-elision
/// gap above: an unquoted `$IFS` reference sitting DIRECTLY adjacent to a
/// brace group (no literal text or whitespace between them, e.g.
/// `echo$IFS{Y,}`) makes real bash produce a WORD COUNT that a careful
/// manual trace of the documented expansion order (brace expansion, then
/// independently `$IFS`-split each resulting alternative) does not predict
/// -- confirmed with a harness-independent direct check
/// (`bash -c 'set -- echo$IFS{Y,}; echo "$#"'` prints `2`, not the `3` a
/// "cartesian product first, then split each alternative" model predicts;
/// `set -- echo$IFS{Y=,}` goes further and produces `echo=`/`echo`, with a
/// `=` character that has no origin in that model at all).
///
/// Unlike the brace-elision gap, this file does not have a settled
/// explanation for the underlying bash mechanism -- only an empirical,
/// independently-reproduced confirmation that shguard's model (which
/// mirrors the "brace first, then split" textbook order) and bash's actual
/// behavior disagree for this specific adjacency. Tracked via
/// [`KNOWN_OPEN_FINDINGS`] (an exact-string match, not a shape-based
/// filter, precisely because the mechanism isn't understood well enough
/// yet to characterize by shape without risking masking a DIFFERENT bug
/// under too broad a net) rather than fixed here -- flagged to the
/// maintainer as a second followup-issue candidate, distinct from the
/// brace-elision one.
#[test]
#[ignore = "known shguard-vs-bash argv-count disagreement for $IFS glued directly \
            against a brace group (issue #93 fuzzer finding, mechanism not yet \
            diagnosed, not yet its own tracked issue)"]
fn known_gap_ifs_glued_directly_to_brace_group() {
    let sandbox = Sandbox::new();
    let candidate = "{echo,}$IFS{cm0gLXJmIC8=,}";

    let verdict = shguard::analyze(candidate);
    let shguard_argv: Vec<String> = verdict
        .normalized_argv()
        .iter()
        .map(|w| match w.resolution() {
            Resolution::Resolved(s) => s.clone(),
            Resolution::Unresolvable(kind) => panic!("expected fully resolved, got {kind:?}"),
        })
        .collect();
    let bash_argv = sandbox
        .capture_argv(candidate)
        .expect("capture should succeed for a plain candidate with no substitutions");

    assert_eq!(
        shguard_argv,
        vec!["echo", "cm0gLXJmIC8=", "echo", "cm0gLXJmIC8="]
    );
    assert_eq!(bash_argv, vec!["echo=", "echo", "="]);
    assert_ne!(
        shguard_argv, bash_argv,
        "if this now passes, either src/normalize.rs or this test's own \
         understanding of the construct has changed -- re-diagnose before \
         removing #[ignore]"
    );
}

/// The main differential-fuzz sweep. Generates [`DEFAULT_ITERATIONS`] (or
/// `SHGUARD_FUZZ_ITERATIONS`) mutated candidates from [`generate_candidate`]
/// plus every [`LITERAL_SEEDS`] entry, classifies and (where eligible)
/// captures+compares each resulting stage, and fails loudly -- printing the
/// exact candidate and both argvs -- on any divergence not already tracked
/// in [`KNOWN_OPEN_FINDINGS`].
///
/// # Replaying one specific candidate (CONTRIBUTING.md triage step 1)
///
/// A nightly-filed issue's body contains the exact candidate string, not a
/// seed -- `SHGUARD_FUZZ_SEED` alone can't reproduce it on demand (the
/// mutator's own template/mechanism pool can change between the run that
/// found it and the run reproducing it). Setting `SHGUARD_FUZZ_REPLAY` to
/// that literal string skips generation ENTIRELY and runs just that one
/// candidate through the same classify/capture/compare pipeline, with the
/// same pass/fail semantics (still fails if it's a genuinely new
/// divergence) -- e.g.
/// `SHGUARD_FUZZ_REPLAY='rm$IFS-rf$IFS/' cargo test --test fuzz_differential -- --nocapture`.
#[test]
fn differential_fuzz_shguard_vs_bash_argv() {
    let sandbox = Sandbox::new();
    eprintln!("fuzz: using {}", sandbox.bash_version_line());

    let mut generated: u64 = 0;
    let mut skipped_ineligible: u64 = 0;
    let mut skipped_unresolvable: u64 = 0;
    let mut skipped_tilde_not_expanded: u64 = 0;
    let mut skipped_capture_failed: u64 = 0;
    let mut generator_desync: u64 = 0;
    let mut compared: u64 = 0;
    let mut divergences: Vec<DivergenceReport> = Vec::new();

    let mut candidates: Vec<Vec<String>>;
    if let Ok(replay) = std::env::var("SHGUARD_FUZZ_REPLAY") {
        eprintln!("fuzz: replaying a single candidate from SHGUARD_FUZZ_REPLAY: {replay:?}");
        candidates = vec![vec![replay]];
    } else {
        let seed = env_u64("SHGUARD_FUZZ_SEED", DEFAULT_SEED);
        let iterations = env_u64("SHGUARD_FUZZ_ITERATIONS", DEFAULT_ITERATIONS);
        let mut rng = Rng::new(seed);
        candidates = LITERAL_SEEDS
            .iter()
            .map(|s| vec![(*s).to_string()])
            .collect();
        for _ in 0..iterations {
            candidates.push(generate_candidate(&mut rng));
        }
    }

    for stages in candidates {
        generated += 1;
        if !pipeline_stage_count_is_consistent(&stages) {
            generator_desync += 1;
            continue;
        }
        let full_text = stages.join(" | ");
        let Some(ranges) = split_top_level_stages(&full_text) else {
            skipped_ineligible += 1;
            continue;
        };
        for (start, end) in ranges {
            let stage_text = full_text[start..end].trim();
            if stage_text.is_empty() || KNOWN_OPEN_FINDINGS.contains(&stage_text) {
                continue;
            }
            match compare_stage(&sandbox, stage_text) {
                Ok(None) => compared += 1,
                Ok(Some(report)) => {
                    compared += 1;
                    divergences.push(report);
                }
                Err(SkipReason::Unresolvable) => skipped_unresolvable += 1,
                Err(SkipReason::TildeNotExpanded) => skipped_tilde_not_expanded += 1,
                Err(SkipReason::CaptureFailed) => skipped_capture_failed += 1,
            }
        }
    }

    let (known_open, new_divergences): (Vec<_>, Vec<_>) =
        divergences.into_iter().partition(|d| d.known_open);

    eprintln!(
        "fuzz summary: generated={generated} compared={compared} \
         skipped_ineligible={skipped_ineligible} skipped_unresolvable={skipped_unresolvable} \
         skipped_tilde_not_expanded={skipped_tilde_not_expanded} \
         skipped_capture_failed={skipped_capture_failed} generator_desync={generator_desync} \
         known_open_divergences={} new_divergences={}",
        known_open.len(),
        new_divergences.len()
    );

    if !known_open.is_empty() || !new_divergences.is_empty() {
        let bash_version = sandbox.bash_version_line();
        report_divergences(&known_open, &bash_version);
        report_divergences(&new_divergences, &bash_version);
    }

    assert_eq!(
        generator_desync, 0,
        "a generated pipeline candidate's rendered stages did not survive \
         reclassification with the same stage count -- generator bug, not \
         a bash/shguard divergence"
    );
    assert!(
        compared > 0,
        "harness compared zero candidates -- check the generator/classifier \
         wiring before trusting this test's green result"
    );
    assert!(
        new_divergences.is_empty(),
        "found {} NEW shguard-vs-bash argv divergence(s) not already tracked \
         via is_known_empty_brace_elision_gap; see stderr for the exact \
         candidate and both argvs",
        new_divergences.len()
    );
}
