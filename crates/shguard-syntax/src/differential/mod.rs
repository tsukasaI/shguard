//! Differential tests for assumption P1: for every input that [`parse`]
//! accepts, three independent oracles must read the same AST as we do.
//!
//! - `brush` compares against `brush-parser` (pure Rust, runs in the normal
//!   test run);
//! - `shfmt` compares against `shfmt -ln bash --to-json`;
//! - `bash` runs `bash -n` and requires exit status 0;
//! - `argv` asks bash 5 for the argv of every simple command and compares it
//!   with the words in our AST (see that module for why nothing executes).
//!
//! The last three are `#[ignore]`d because they need the tools from the flake
//! devShell: run them with
//! `nix develop -c cargo test -p shguard-syntax --locked -- --include-ignored --nocapture`
//! (`--nocapture`, because a failing test under the devShell aborts and loses
//! the captured panic message).
//! When run, a missing tool is a failure, not a skip.
//!
//! Both our AST and each oracle's tree are mapped into the canonical
//! [`Shape`] and compared with equality. An oracle that cannot express
//! something we accepted (an unmappable node, a parse error) is a
//! disagreement too. Inputs the parser rejects are not compared.

mod argv;
mod bash;
mod brush;
mod shfmt;

use crate::generate::gscript;
use crate::parse;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use shguard_kernel::ast::{AndOr, Connector, Opaque, Part, Pipeline, Redir, Script, Simple, Word};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Generated scripts per oracle.
const GENERATED: usize = 256;

/// A script in the canonical form.
type Shape = Vec<AndOrS>;

#[derive(Debug, PartialEq, Eq)]
struct AndOrS {
    first: Vec<SimpleS>,
    rest: Vec<(Conn, Vec<SimpleS>)>,
}

#[derive(Debug, PartialEq, Eq)]
struct SimpleS {
    words: Vec<Vec<CPart>>,
    redirs: Vec<Redir>,
}

#[derive(Clone, PartialEq, Eq)]
enum CPart {
    Lit(Vec<u8>),
    Var(Vec<u8>),
    Tilde,
}

/// Prints bytes as text, so a failure reads `Lit("echo")` and not a list of
/// numbers.
impl std::fmt::Debug for CPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CPart::Lit(bytes) => write!(f, "Lit(\"{}\")", bytes.escape_ascii()),
            CPart::Var(bytes) => write!(f, "Var(\"{}\")", bytes.escape_ascii()),
            CPart::Tilde => write!(f, "Tilde"),
        }
    }
}

/// A file descriptor written as ASCII digits only (`+1` is not one).
fn fd_digits(text: &[u8]) -> Option<u8> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// `from>&to` as one of the four accepted redirects; any other descriptor
/// pair is outside the subset.
fn redir_dup(from: u8, to: u8) -> Result<Redir, String> {
    match (from, to) {
        (2, 1) => Ok(Redir::ErrToOut),
        (1, 2) => Ok(Redir::OutToErr),
        _ => Err(format!("unmappable duplicate {from}>&{to}")),
    }
}

/// `fd>/dev/null` as one of the four accepted redirects.
fn redir_dev_null(fd: u8) -> Result<Redir, String> {
    match fd {
        1 => Ok(Redir::OutDevNull),
        2 => Ok(Redir::ErrDevNull),
        _ => Err(format!("unmappable /dev/null redirect on descriptor {fd}")),
    }
}

/// `[A-Za-z_][A-Za-z0-9_]*`
fn is_name(text: &[u8]) -> bool {
    match text.split_first() {
        Some((first, rest)) => {
            (first.is_ascii_alphabetic() || *first == b'_')
                && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        }
        None => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conn {
    And,
    Or,
}

/// Merges adjacent literals and drops empty ones, except that a word with no
/// other content stays `[Lit([])]` (`''` is a word).
fn canon(parts: Vec<CPart>) -> Vec<CPart> {
    let mut out: Vec<CPart> = Vec::new();
    for part in parts {
        match (out.last_mut(), part) {
            (_, CPart::Lit(bytes)) if bytes.is_empty() => {}
            (Some(CPart::Lit(prev)), CPart::Lit(bytes)) => prev.extend(bytes),
            (_, part) => out.push(part),
        }
    }
    if out.is_empty() {
        out.push(CPart::Lit(Vec::new()));
    }
    out
}

fn ours_word(word: &Word) -> Vec<CPart> {
    canon(
        word.parts()
            .iter()
            .map(|part| match part {
                Part::Lit(bytes) => CPart::Lit(bytes.clone()),
                Part::Opaque(Opaque::Var(name)) => CPart::Var(name.clone()),
                Part::Opaque(Opaque::Tilde) => CPart::Tilde,
            })
            .collect(),
    )
}

fn ours_simple(simple: &Simple) -> SimpleS {
    SimpleS {
        words: simple.words().iter().map(ours_word).collect(),
        redirs: simple.redirs().to_vec(),
    }
}

fn ours_pipeline(pipeline: &Pipeline) -> Vec<SimpleS> {
    pipeline.cmds().iter().map(ours_simple).collect()
}

fn ours_and_or(and_or: &AndOr) -> AndOrS {
    AndOrS {
        first: ours_pipeline(and_or.first()),
        rest: and_or
            .rest()
            .iter()
            .map(|link| {
                let conn = match link.op() {
                    Connector::And => Conn::And,
                    Connector::Or => Conn::Or,
                };
                (conn, ours_pipeline(link.rhs()))
            })
            .collect(),
    }
}

fn ours(script: &Script) -> Shape {
    script.items().iter().map(ours_and_or).collect()
}

/// Bytes of `raw` with the shell's quote removal for unquoted text: `\c`
/// gives `c` and backslash-newline disappears.
fn unescape_unquoted(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = raw.iter().copied();
    while let Some(b) = bytes.next() {
        if b == b'\\' {
            match bytes.next() {
                Some(b'\n') => {}
                Some(next) => out.push(next),
                None => out.push(b),
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// Bytes of `raw` with the quote removal for double-quoted text: only
/// `\$`, `` \` ``, `\"` and `\\` lose the backslash, and backslash-newline
/// disappears.
fn unescape_double(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        match (b, raw.get(i + 1).copied()) {
            (b'\\', Some(b'\n')) => i += 2,
            (b'\\', Some(next @ (b'$' | b'`' | b'"' | b'\\'))) => {
                out.push(next);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// One input of the corpus together with our shape for it.
struct Case {
    input: String,
    ours: Shape,
}

/// The accepted inputs and how many each source supplied.
struct Corpus {
    cases: Vec<Case>,
    /// Lines in `acceptance/*.jsonl`, and those we accept.
    acceptance_total: usize,
    acceptance_accepted: usize,
    edge_total: usize,
    edge_accepted: usize,
    generated: usize,
}

fn acceptance_commands() -> Vec<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../acceptance");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("acceptance directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 5, "acceptance/*.jsonl: {files:?}");
    let mut commands = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("jsonl file");
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let value: serde_json::Value = serde_json::from_str(line).expect("json line");
            let command = value
                .get("command")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("no command in {line:?}"));
            commands.push(command.to_string());
        }
    }
    commands
}

/// Hand-written inputs for the constructs where bash and a hasty parser
/// differ: quoting, escapes, expansions, tildes, redirect placement, IO
/// numbers, separators, reserved-looking words and non-ASCII.
const EDGE: &[&str] = &[
    "",
    "\n\n",
    "  \t\n ",
    "ls -la",
    "git log --oneline | head -5",
    "a && b || c; d",
    "a; b",
    "a\n\nb",
    "\n\na\n",
    "a;",
    "a;\n",
    "a;\n\n b",
    "a &&\n b",
    "a ||\n\n b",
    "a |\n b",
    "a | b | c",
    "a && b | c || d | e",
    "cmd 2>&1 >/dev/null",
    "cmd >/dev/null 2>&1",
    ">/dev/null cmd",
    "echo >&2 hi",
    "echo hi >&2",
    "echo 2>&1",
    "echo 1>&2 a 2>/dev/null b",
    ">/dev/null 2>&1 cmd arg",
    "2>&1 >/dev/null cmd",
    "cmd >&2 | other 2>&1",
    "cmd 9>&1",
    "cmd 0>/dev/null",
    "cmd >/dev/null\nnext",
    "cmd 2>&1; cmd2 >&2",
    "echo '2'>&1",
    "echo '2' >&1",
    "ls2>&1",
    "echo a2>&1",
    "echo \"2\">&1",
    "echo \\2>&1",
    "echo 2>/dev/null x",
    "echo >\"/dev/null\"",
    "echo >'/dev/null'",
    "echo >/dev/nul''l",
    "'FOO=1' cmd",
    "'if' x",
    "\\if x",
    "i\"\"f x",
    "i''f x",
    "echo if",
    "echo if done",
    "env A=b",
    "echo A=b",
    "echo \"$HOME\" ~",
    "echo \"${HOME}\"",
    "echo \"${HOME}/x\"",
    "echo \"a$HOME b\"",
    "echo \"$HOME$USER\"",
    "echo \"x${HOME}y\"",
    "echo \"$_a1\"",
    "\"$X\" a",
    "\"${X}\" a",
    "~/bin/x a",
    "~ a",
    "~/x",
    "git diff HEAD~1",
    "git diff a~b",
    "scp h:~/f .",
    "echo --opt=~/x",
    "echo a~",
    "echo ~/",
    "echo ~/a/b",
    "echo '~'",
    "echo \"~\"",
    "echo \\~",
    "echo \\~/x",
    "echo ~'a'",
    "echo ~\"a\"",
    "echo ~\"$X\"",
    "echo ~/'a b'",
    "echo ~/\"$X\"",
    "echo '~'/x",
    "echo x~/y",
    "echo a b  c",
    "echo\ta",
    "  echo a  ",
    "echo 'a b' \"c d\" e\\ f",
    "echo \\;",
    "echo \\| \\& \\< \\> \\( \\) \\$ \\\" \\' \\\\",
    "echo a\\\nb",
    "echo \"a\\\nb\"",
    "echo \\\n a",
    "echo \"\\$HOME \\\\ \\` \\\" \\a \\n\"",
    "echo \"\\\"",
    "echo \"a\\\\\"",
    "echo '\\'",
    "echo '\\n'",
    "echo ';|&<>()$`\"'",
    "echo \";|&<>()\"",
    "echo \"$\"",
    "echo \"a$\"",
    "echo \"$ \"",
    "echo \"%\"",
    "echo 'a'\"b\"c",
    "echo 'a''b'",
    "echo \"a\"\"b\"",
    "echo ''",
    "echo \"\"",
    "echo ''\"\"",
    "echo ''a''",
    "echo a''",
    "echo ''$HOME",
    "echo \"$HOME\"''",
    "echo \"\"\"$HOME\"",
    "''",
    "\"\"",
    "'' a",
    "echo !x",
    "!x",
    "!x y",
    "echo a!",
    "echo ! x",
    "echo a#b",
    "echo a #comment",
    "#c\necho a",
    "echo a # c\necho b",
    "echo é 日本語 'ü' \"ß\" \\é",
    "é 日本語",
    "echo \"é$HOME日本\"",
    "echo 😀",
    "a ;b",
    "a;b",
    "a&&b",
    "a||b",
    "a|b",
    "a|b&&c",
    "echo a;echo b;",
    "echo a ;\n echo b",
    "a\\\n&& b",
    "a &&\\\n b",
    "echo --",
    "echo -n -e",
    "echo a=b",
    "export A=b",
    "export A",
    "export -p",
    "export A=\"b c\" B=~/x",
    "declare a=b",
    "local a=b",
    "readonly A=1",
    "typeset a=b",
    "command export A=b",
    "export A=\"$B\"",
    "export A=b:c",
    "export A+=x",
    "declare -x A=1 B",
    "export 'A'=b",
    "echo a=\"b c\"",
    "echo =",
    "echo ==",
    "echo 1",
    "echo 12>&1",
    "echo \"$X\"",
    "echo \"a$X\"b",
    "echo \"${X}y\"",
    "echo \"$X$Y\"",
    "echo ''\"$X\"''",
    "echo ~",
    "echo ~/a",
    "echo HEAD~1",
    "echo h:~/f",
    "echo \\*",
    "echo '*'",
    "echo \"a b\"",
    "echo a\\ b",
    "echo \"\\$X\"",
    "echo \"\\\\\"",
    "echo \"\\q\"",
    "echo -- \"-n\"",
    "echo na\u{ef}ve",
    "echo \"é${HOME}日本\"",
    "cat file.txt | grep 'foo bar' | sort -u > /dev/null",
];

fn edge_commands() -> Vec<String> {
    EDGE.iter().map(|s| (*s).to_string()).collect()
}

fn generated_commands() -> Vec<String> {
    let mut runner = TestRunner::deterministic();
    let strategy = gscript();
    (0..GENERATED)
        .map(|_| {
            strategy
                .new_tree(&mut runner)
                .expect("generate a script")
                .current()
                .render(None)
        })
        .collect()
}

fn corpus() -> Corpus {
    let mut cases = Vec::new();
    let mut take = |inputs: Vec<String>| -> (usize, usize) {
        let total = inputs.len();
        let mut accepted = 0;
        for input in inputs {
            if let Ok(script) = parse(input.as_bytes()) {
                accepted += 1;
                cases.push(Case {
                    ours: ours(&script),
                    input,
                });
            }
        }
        (total, accepted)
    };
    let (acceptance_total, acceptance_accepted) = take(acceptance_commands());
    let (edge_total, edge_accepted) = take(edge_commands());
    let (_, generated) = take(generated_commands());
    assert_eq!(generated, GENERATED, "the generator emits accepted scripts");
    Corpus {
        cases,
        acceptance_total,
        acceptance_accepted,
        edge_total,
        edge_accepted,
        generated,
    }
}

impl Corpus {
    /// Prints the counts and fails when the corpus is too thin to mean
    /// anything.
    fn report(&self, oracle: &str) {
        eprintln!(
            "{oracle}: acceptance {}/{} accepted, edge {}/{} accepted, generated {}; \
             compared {} accepted inputs",
            self.acceptance_accepted,
            self.acceptance_total,
            self.edge_accepted,
            self.edge_total,
            self.generated,
            self.cases.len(),
        );
        assert!(self.acceptance_accepted > 0, "no acceptance command parsed");
        assert!(self.edge_accepted > 0, "no edge input parsed");
    }

    /// Compares every case against `oracle_shape` and fails with every
    /// disagreement at once.
    fn check(&self, oracle: &str, oracle_shape: impl Fn(&str) -> Result<Shape, String>) {
        let mut failures = Vec::new();
        for case in &self.cases {
            match oracle_shape(&case.input) {
                Ok(theirs) if theirs == case.ours => {}
                Ok(theirs) => failures.push(format!(
                    "input: {:?}\n  ours:   {:?}\n  {oracle}: {theirs:?}",
                    case.input, case.ours
                )),
                Err(why) => failures.push(format!(
                    "input: {:?}\n  ours:   {:?}\n  {oracle}: {why}",
                    case.input, case.ours
                )),
            }
        }
        self.report(oracle);
        assert!(
            failures.is_empty(),
            "{} of {} accepted inputs disagree with {oracle}:\n{}",
            failures.len(),
            self.cases.len(),
            failures.join("\n")
        );
    }
}

/// Runs `program args` with `input` on stdin and returns its output. Panics
/// when the program cannot be started: a missing tool is a failure.
fn run(program: &str, args: &[&str], input: &str) -> std::process::Output {
    let mut command = Command::new(program);
    command.args(args);
    run_command(command, program, input)
}

/// The bash the oracles use: `SHGUARD_DIFF_BASH`, else `bash`, resolved to a
/// path through the test process's own `PATH`. A relative name must be
/// resolved before a test builds a sandbox environment, because the sandbox
/// `PATH` is empty.
fn bash_program() -> PathBuf {
    let name = std::env::var("SHGUARD_DIFF_BASH").unwrap_or_else(|_| "bash".to_string());
    if name.contains('/') {
        return PathBuf::from(name);
    }
    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .map(|dir| dir.join(&name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} not found on PATH (use `nix develop`)"))
}

fn require_bash5(program: &Path) {
    let program = program.to_str().expect("bash path is UTF-8");
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

/// Runs `command` (named `program` in messages) with `input` on stdin, kills
/// it after [`TIMEOUT`] and returns its output.
fn run_command(mut command: Command, program: &str, input: &str) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("cannot run {program} (use `nix develop`): {err}"));
    let mut stdin = child.stdin.take().expect("piped stdin");
    let bytes = input.as_bytes().to_vec();
    // A tool that rejects the input may exit before reading all of it, so a
    // write error is not ours to report.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for the child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{program} did not finish within {TIMEOUT:?} on {input:?}");
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    writer.join().expect("stdin writer");
    std::process::Output {
        status,
        stdout: out_reader.join().expect("stdout reader"),
        stderr: err_reader.join().expect("stderr reader"),
    }
}

/// How long a spawned tool may run on one input.
const TIMEOUT: Duration = Duration::from_secs(10);
