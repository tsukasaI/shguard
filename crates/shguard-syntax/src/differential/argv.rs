//! Oracle 4: the argv real bash 5 builds for every simple command.
//!
//! For each accepted input and each simple command in our AST, the source
//! text of its words (never its redirects) is handed to bash as the arguments
//! of `bash -c 'printf "%s\0" "$#"; printf "%s\0" "$@"' -- WORDS`. Bash does
//! quote removal, escapes and concatenation on them, and prints the resulting
//! argv NUL-separated, count first. That argv must equal the bytes our AST
//! says the words are: a `Lit` as it is, a `Var` as the value bash has for
//! `"$name"`, a `Tilde` as the value bash has for `~`. Those two values come
//! from bash too, so variable semantics stay opaque as in the kernel; what is
//! under test is quote removal, escapes, concatenation, and the absence of
//! splitting and globbing.
//!
//! Why nothing executes: the legacy engine ran candidates behind PATH shims
//! and read an xtrace. The subset has no command or process substitution, so
//! no word can run anything, and running the commands themselves would be
//! dangerous: `/bin/rm -rf /` parses, and `exec`, `trap`, `hash -p` and
//! `enable -f` would take effect for real. Here the command text only ever
//! appears as arguments of the inner bash.
//!
//! Every spawned bash gets a cleared environment, an empty `PATH` directory,
//! a temporary `HOME` and working directory, and the `run_command` timeout.
//! Variables the input references get an adversarial value, which proves that
//! `"$X"` stays one word and is not expanded again.

use super::{Case, bash_program, corpus, require_bash5, run_command};
use crate::{Token, lex, parse};
use shguard_kernel::ast::{Opaque, Part, Script, Simple};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// The inner script, single-quoted for splicing into the outer one. The
/// leading `"$#"` field is what tells a real trailing empty argument from the
/// empty piece after the last NUL.
const INNER_SCRIPT_QUOTED: &str = r#"'printf "%s\0" "$#"; printf "%s\0" "$@"'"#;

/// Variables that get no adversarial value: bash sets or reads them itself,
/// so overriding them would test bash's startup, not word expansion
/// (`HOME` and `PATH` are the sandbox's; `SHELLOPTS`, `POSIXLY_CORRECT`,
/// `GLOBIGNORE` and `ENV` change how bash parses and expands; the loader
/// variables could break the spawn). The value bash has for them is still
/// compared, because both sides read it from bash.
const MANAGED: &[&str] = &[
    "HOME",
    "PATH",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "IFS",
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "BASHPID",
    "UID",
    "EUID",
    "PPID",
    "GROUPS",
    "HOSTNAME",
    "HOSTTYPE",
    "MACHTYPE",
    "OSTYPE",
    "SHELLOPTS",
    "POSIXLY_CORRECT",
    "GLOBIGNORE",
    "ENV",
];

/// Prefixes of managed names: all of `BASH*`, plus the dynamic loader.
const MANAGED_PREFIXES: &[&str] = &["BASH", "LD_", "DYLD_"];

/// Variables whose value differs between two processes, or between the
/// capture of `"$name"` alone and of the whole command, so the two sides
/// cannot agree. An input that references one is skipped and counted.
const VOLATILE: &[&str] = &[
    "_",
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "BASHPID",
    "BASH_COMMAND",
    "BASH_EXECUTION_STRING",
    "BASH_ARGV0",
];

/// Spaces, a tab, a newline, glob bytes, a tilde, a literal command
/// substitution and a trailing space.
const ADVERSARIAL: &str = " a  b\t*?[a] ~ $(echo no)\nz ";

fn is_managed(name: &str) -> bool {
    MANAGED.contains(&name) || MANAGED_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The bash and the directories every spawn uses.
struct Sandbox {
    bash: PathBuf,
    path_dir: TempDir,
    home_dir: TempDir,
    cwd_dir: TempDir,
}

impl Sandbox {
    fn new(bash: PathBuf) -> Sandbox {
        Sandbox {
            bash,
            path_dir: tempfile::tempdir().expect("temporary PATH directory"),
            home_dir: tempfile::tempdir().expect("temporary HOME"),
            cwd_dir: tempfile::tempdir().expect("temporary working directory"),
        }
    }

    /// Bash's argv for the words `text`, in the environment `vars`.
    fn capture(&self, text: &[u8], vars: &[(String, String)]) -> Result<Vec<Vec<u8>>, String> {
        let bash = self.bash.to_str().expect("bash path is UTF-8");
        let mut script = format!(
            "'{}' -c {INNER_SCRIPT_QUOTED} -- ",
            bash.replace('\'', r"'\''")
        )
        .into_bytes();
        script.extend_from_slice(text);
        let mut command = Command::new(&self.bash);
        command
            .arg("-c")
            .arg(OsStr::from_bytes(&script))
            .env_clear()
            .env("PATH", self.path_dir.path())
            .env("HOME", self.home_dir.path())
            .envs(vars.iter().map(|(k, v)| (k, v)))
            .current_dir(self.cwd_dir.path());
        let output = run_command(command, bash, "");
        if !output.status.success() {
            return Err(format!(
                "bash exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let fields: Vec<&[u8]> = output.stdout.split(|&b| b == 0).collect();
        let count: usize = std::str::from_utf8(fields.first().copied().unwrap_or_default())
            .ok()
            .and_then(|count| count.parse().ok())
            .ok_or("no argument count in the output")?;
        // The count, `count` arguments and the empty piece after the last NUL.
        if fields.len() != count + 2 || fields.last().is_some_and(|last| !last.is_empty()) {
            return Err(format!(
                "count {count} but {} fields: {:?}",
                fields.len(),
                output.stdout
            ));
        }
        Ok(fields
            .get(1..=count)
            .unwrap_or_default()
            .iter()
            .map(|field| field.to_vec())
            .collect())
    }

    /// The one field bash gives for the single word `word`.
    fn value(&self, word: &str, vars: &[(String, String)]) -> Result<Vec<u8>, String> {
        let mut argv = self.capture(word.as_bytes(), vars)?;
        match (argv.pop(), argv.is_empty()) {
            (Some(value), true) => Ok(value),
            (_, _) => Err(format!("{word} did not give exactly one field")),
        }
    }
}

/// Every simple command of the script, in source order.
fn simples(script: &Script) -> Vec<&Simple> {
    let mut out = Vec::new();
    for and_or in script.items() {
        out.extend(and_or.first().cmds());
        for link in and_or.rest() {
            out.extend(link.rhs().cmds());
        }
    }
    out
}

fn variable_names(simples: &[&Simple]) -> Vec<String> {
    let mut names = BTreeMap::new();
    for simple in simples {
        for word in simple.words() {
            for part in word.parts() {
                if let Part::Opaque(Opaque::Var(name)) = part {
                    names.insert(String::from_utf8_lossy(name).into_owned(), ());
                }
            }
        }
    }
    names.into_keys().collect()
}

/// The source text of the words of each simple command: lexemes split on
/// operators, redirects dropped, and the word counts checked against the AST.
fn word_texts<'a>(input: &'a [u8], simples: &[&Simple]) -> Vec<Vec<&'a [u8]>> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    for lexeme in lex(input).expect("accepted input lexes") {
        match lexeme.token {
            Token::Word(_) => current.push(&input[lexeme.offset..lexeme.end]),
            Token::Redir(_) => {}
            Token::Op(_) => {
                if !current.is_empty() {
                    groups.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    assert_eq!(
        groups.len(),
        simples.len(),
        "simple commands in {:?}",
        String::from_utf8_lossy(input)
    );
    for (group, simple) in groups.iter().zip(simples) {
        assert_eq!(
            group.len(),
            simple.words().len(),
            "words in {:?}",
            String::from_utf8_lossy(input)
        );
    }
    groups
}

/// Defense in depth before splicing: the lexer must see one word, and no
/// backquote, `$(` or `<`/`>` may be active (outside single quotes and not
/// escaped), because the text is part of a script a shell reads.
fn check_spliceable(text: &[u8]) {
    let lexed = lex(text).unwrap_or_else(|err| panic!("{text:?} does not re-lex: {err}"));
    assert!(
        matches!(lexed.as_slice(), [one] if matches!(one.token, Token::Word(_))),
        "{:?} is not exactly one word",
        String::from_utf8_lossy(text)
    );
    #[derive(PartialEq)]
    enum State {
        Plain,
        Single,
        Double,
    }
    let mut state = State::Plain;
    let mut i = 0;
    while let Some(&b) = text.get(i) {
        let active = match (&state, b) {
            (State::Single, b'\'') => {
                state = State::Plain;
                false
            }
            (State::Single, _) => false,
            (_, b'\\') => {
                i += 1;
                false
            }
            (State::Plain, b'\'') => {
                state = State::Single;
                false
            }
            (State::Plain, b'"') => {
                state = State::Double;
                false
            }
            (State::Double, b'"') => {
                state = State::Plain;
                false
            }
            (_, b'`') => true,
            (_, b'$') => text.get(i + 1) == Some(&b'('),
            (State::Plain, b'<' | b'>') => true,
            (State::Double, _) | (State::Plain, _) => false,
        };
        assert!(
            !active,
            "active metacharacter in {:?}",
            String::from_utf8_lossy(text)
        );
        i += 1;
    }
    assert!(state == State::Plain, "unbalanced quote in {text:?}");
}

#[derive(Default)]
struct Tally {
    simple_commands: usize,
    skipped: usize,
}

/// Compares every simple command of `case`; failures are appended.
fn check_case(sandbox: &Sandbox, case: &Case, tally: &mut Tally, failures: &mut Vec<String>) {
    let input = case.input.as_bytes();
    let script = parse(input).expect("corpus inputs are accepted");
    let simples = simples(&script);
    let names = variable_names(&simples);
    if names.iter().any(|name| VOLATILE.contains(&name.as_str())) {
        tally.skipped += 1;
        return;
    }
    let vars: Vec<(String, String)> = names
        .iter()
        .filter(|name| !is_managed(name))
        .map(|name| (name.clone(), ADVERSARIAL.to_string()))
        .collect();
    let mut values: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut fail = |index: usize, why: String| {
        failures.push(format!(
            "input: {:?}\n  simple command {index}: {why}",
            case.input
        ));
    };
    for name in &names {
        match sandbox.value(&format!("\"${name}\""), &vars) {
            Ok(value) => {
                values.insert(name.clone(), value);
            }
            Err(why) => fail(0, format!("value of ${name}: {why}")),
        }
    }
    let tilde = sandbox.value("~", &vars);
    for (index, (simple, texts)) in simples.iter().zip(word_texts(input, &simples)).enumerate() {
        tally.simple_commands += 1;
        for text in &texts {
            check_spliceable(text);
        }
        let ours: Result<Vec<Vec<u8>>, String> = simple
            .words()
            .iter()
            .map(|word| {
                let mut bytes = Vec::new();
                for part in word.parts() {
                    match part {
                        Part::Lit(lit) => bytes.extend_from_slice(lit),
                        Part::Opaque(Opaque::Var(name)) => {
                            let name = String::from_utf8_lossy(name);
                            bytes.extend_from_slice(
                                values
                                    .get(name.as_ref())
                                    .ok_or("variable without a value")?,
                            );
                        }
                        Part::Opaque(Opaque::Tilde) => {
                            bytes.extend_from_slice(tilde.as_ref().map_err(Clone::clone)?);
                        }
                    }
                }
                Ok(bytes)
            })
            .collect();
        let Ok(ours) = ours else {
            fail(index, "no value for a variable or the tilde".to_string());
            continue;
        };
        let spliced = texts.join(&b' ');
        match sandbox.capture(&spliced, &vars) {
            Ok(theirs) if theirs == ours => {}
            Ok(theirs) => fail(
                index,
                format!(
                    "words {:?}\n  ours:  {}\n  bash:  {}",
                    String::from_utf8_lossy(&spliced),
                    show(&ours),
                    show(&theirs)
                ),
            ),
            Err(why) => fail(
                index,
                format!("words {:?}: {why}", String::from_utf8_lossy(&spliced)),
            ),
        }
    }
}

fn show(argv: &[Vec<u8>]) -> String {
    let words: Vec<String> = argv
        .iter()
        .map(|word| format!("\"{}\"", word.escape_ascii()))
        .collect();
    format!("[{}]", words.join(", "))
}

#[test]
#[ignore = "needs bash 5 (nix develop)"]
fn bash_builds_the_argv_we_expect() {
    let bash: PathBuf = bash_program();
    require_bash5(Path::new(&bash));
    let corpus = corpus();
    let sandbox = Sandbox::new(bash);
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    for case in &corpus.cases {
        check_case(&sandbox, case, &mut tally, &mut failures);
    }
    corpus.report("bash argv");
    eprintln!(
        "bash argv: compared {} simple commands in {} inputs, skipped {} inputs \
         that reference a volatile variable",
        tally.simple_commands,
        corpus.cases.len() - tally.skipped,
        tally.skipped
    );
    assert!(tally.simple_commands > 0, "no simple command was compared");
    assert!(
        failures.is_empty(),
        "{} disagreements with bash:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
