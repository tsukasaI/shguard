//! D2: benign-corpus false-positive suite (issue #16).
//!
//! A table-driven regression test over realistic agent-workflow commands
//! that must all resolve to [`Decision::Allow`]. Unlike `src/gate.rs`'s
//! unit tests — which target specific Block/Ask *rules* — this suite exists
//! to catch the opposite failure mode: a rule change that starts flagging
//! ordinary, non-dangerous commands as Ask/Block.

use shguard::verdict::Decision;

#[test]
fn benign_corpus_no_false_positives() {
    let commands: &[&str] = &[
        // Build/test invocations.
        "cargo test",
        "cargo build --release",
        "cargo clippy",
        "cargo fmt -- --check",
        "npm run build",
        "npm install",
        "make",
        "go build ./...",
        "go test ./...",
        "python -m pytest",
        "mvn clean install",
        // Git commands.
        "git status",
        "git log --oneline -20",
        "git diff HEAD~1",
        "git add .",
        "git checkout -b feature/x",
        "git push origin main",
        "git stash",
        "git pull --rebase",
        // Text searches mentioning dangerous strings as DATA, not commands.
        "rg \"rm -rf\" src/",
        "git commit -m 'rm -rf /'",
        // Argument-position substitutions with benign inner commands.
        "echo $(date)",
        "echo $(whoami)",
        // $VAR arguments (argument-position bare $VAR).
        "cd $HOME",
        "ls $PWD",
        "echo $PATH",
        // File operations.
        "cat README.md",
        "ls -la",
        "mkdir -p src/test",
        "cp file1 file2",
        "touch newfile.txt",
        // Network.
        "curl -s https://api.example.com/health",
        "ping -c 1 localhost",
        // Editors/tools.
        "less file.txt",
        "wc -l src/*.rs",
        "du -sh target/",
    ];

    for command in commands {
        let verdict = shguard::analyze(command);
        assert_eq!(
            verdict.decision(),
            Decision::Allow,
            "false positive on benign command {command:?}: got {:?} (reason: {:?})",
            verdict.decision(),
            verdict.reason().map(|r| r.as_str())
        );
    }
}
