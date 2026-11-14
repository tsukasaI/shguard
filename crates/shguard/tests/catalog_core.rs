//! The embedded core catalog, command to decision. Each test loads the
//! embedded files with no user config and pins only the decision of a
//! command, never a message or a rule id.

#[expect(
    dead_code,
    reason = "each test crate uses only part of the shared helpers"
)]
mod common;

use common::{assert_all, assert_not_allow};
use shguard_kernel::decision::Decision;

#[test]
fn every_row_has_an_allowed_command() {
    let assert_all = |cmds: &[&str], want| {
        common::assert_rows_covered("embedded:core.toml", cmds, &[]);
        common::assert_all(cmds, want);
    };
    assert_all(
        &[
            "cd src",
            "cd",
            "cd -P src",
            "pwd",
            "pwd -P",
            "echo hi",
            "echo -n hi there",
            "echo +x",
            "ls",
            "ls -la src",
            "ls -1 -- src",
            "cat a.txt",
            "cat -n a.txt b.txt",
            "head -n 5 a.txt",
            "head -c 10 a.txt",
            "tail -n 5 a.txt",
            "tail -n +2 a.txt",
            "wc -l a.txt",
            "tr -d x",
            "tr a-z A-Z",
            "sort -u a.txt",
            "sort -t , -k 2 -n a.txt",
            "uniq -c a.txt",
            "uniq a.txt b.txt",
            "mkdir -p build/out",
            "mkdir -m 755 build",
            "rm -f a.txt",
            "rm -rf build",
            "cp a.txt b.txt",
            "cp -R src dst",
            "grep -n foo a.txt",
            "grep -e foo -i a.txt",
            "grep -rn foo src",
            "rg -n foo src",
            "rg foo",
            "rg -g '*.rs' -t rust foo src",
            "rg foo -n",
            "tokei",
            "tokei src --files",
            "fd",
            "fd -e ts src",
            "fd -H -t f -E target 'Cargo\\.toml$' .",
            "fd --max-depth=2 -g '*.rs' crates",
            "fd -0 foo | wc -l",
            "eza",
            "eza -la --git src",
            "eza -T -L 2 --git-ignore",
            "tree",
            "tree -d src",
            "tree -a --gitignore --dirsfirst",
            "eza -l /etc",
        ],
        Decision::Allow,
    );
}

#[test]
fn pipelines_of_covered_commands_are_allowed() {
    assert_all(
        &[
            "cat file | grep x | head",
            "echo hi | cat | wc -l",
            "cat a.txt | sort | uniq -c | sort -n",
            "cat -- ~/.bashrc",
            "ls / && ls /tmp",
        ],
        Decision::Allow,
    );
}

#[test]
fn every_row_has_a_non_allowed_command() {
    let assert_not_allow = |cmds: &[&str]| {
        common::assert_rows_covered("embedded:core.toml", cmds, &[]);
        common::assert_not_allow(cmds);
    };
    assert_not_allow(&[
        "cd -e src",
        "cd a b",
        "pwd x",
        "pwd -x",
        "echo -x hi",
        "echo hi -n",
        "echo -- hi",
        "ls --color=auto",
        "ls -o",
        "ls dir -l",
        "cat -A a.txt",
        "cat a.txt -n",
        "head -5 a.txt",
        "head -q a.txt",
        "tail -f a.txt",
        "tail -F a.txt",
        "wc -L a.txt",
        "tr -t a b",
        "sort -o out.txt a.txt",
        "sort -T /tmp a.txt",
        "sort --compress-program=gzip a.txt",
        "uniq -D a.txt",
        "uniq a b c",
        "mkdir -Z build",
        "rm -P a.txt",
        "rm --recursive build",
        "cp -r src dst",
        "cp -t dst a.txt",
        "cp --target-directory=dst a.txt",
        "grep -P foo a.txt",
        "grep -z foo a.txt",
        "grep -C 2 foo a.txt",
        "rg --pre cat foo",
        "rg -z foo",
        "rg --search-zip foo",
        "rg --hostname-bin x foo",
        "tokei -i stats.json",
        "fd -x rm",
        "fd -X cat",
        "fd -l",
        "fd -Hl foo",
        "fd --exec rm x",
        "fd --exec=rm",
        "fd --exec-batch cat",
        "fd --list-details",
        "fd -C /tmp foo",
        "fd --batch-size 2 foo",
        "fd --ignore-file /Users/me/.aws/credentials x",
        "fd . /",
        "fd . /Users/me",
        "fd --search-path /home/me x",
        "eza --icons src",
        "eza --stdin",
        "eza --color-scale all",
        "tree -o out.txt",
        "tree -dLo 1 out.txt",
        "tree -Io x out.txt",
        "tree -Po x out.txt",
        "tree -L2o out.txt",
        "tree -L 2",
        "tree --fromfile list.txt",
        "tree -H . -o x.html",
        "tree --gitfile=x",
        "tree /",
        "tree -L 2 /Users/me",
        "tree -d /Users/me",
        "eza -R /",
        "eza -T /home/me",
    ]);
}

#[test]
fn absolute_and_home_targets_of_a_writing_row_are_asked() {
    assert_all(
        &[
            "cp a /x",
            "cp /x a",
            "cp -- a ~/x",
            "cp -- ~/x a",
            "rm /x",
            "rm -- ~/x",
            "rm -rf /var/tmp/x",
            "mkdir /x",
            "mkdir -- ~/x",
            "mkdir -p /tmp/a/b",
            "uniq a /x",
            "uniq -- a ~/x",
            "uniq /x",
            "uniq -- ~/x",
            "rm -rf ^foo",
            "cp ^foo dst",
        ],
        Decision::Ask,
    );
}

/// The kernel reads a `~` word in option position, or after an operand, as a
/// word that might be an option, so these are Unknown rather than a rule hit.
#[test]
fn home_targets_without_a_dashdash_are_not_allowed() {
    assert_not_allow(&[
        "cp a ~/x",
        "cp ~/x a",
        "rm ~/x",
        "rm -rf ~",
        "mkdir ~/x",
        "uniq a ~/x",
        "uniq ~/x",
        "cp a ~/.bashrc",
        "cat ~/.ssh/id_ed25519",
        "cat ~/.bashrc",
    ]);
}

#[test]
fn recursive_rm_of_a_dangerous_target_is_blocked() {
    assert_all(
        &[
            "rm -rf /",
            "rm -rf -- /",
            "rm -R -- ~",
            "rm -r -- ~/",
            "rm -rf /etc",
            "rm -rf /usr/lib",
            "rm -r /System",
            "rm -r /Users",
            "rm -r /home/",
            "rm -fr /var",
            "rm -rf .",
            "rm -Rf ./",
        ],
        Decision::Block,
    );
    // Not recursive, or not one of the listed directories.
    assert_all(&["rm /", "rm -f /Users"], Decision::Ask);
}

#[test]
fn writes_into_dev_are_blocked() {
    assert_all(
        &[
            "cp a /dev/sda",
            "rm /dev/sda",
            "mkdir /dev/x",
            "uniq a /dev/sda",
            "cp /dev/zero a",
        ],
        Decision::Block,
    );
    // The inline spellings of `-t` are not in the cp row at all.
    assert_not_allow(&["cp --target-directory=/dev/sda a", "cp -t/dev/sda a"]);
}

#[test]
fn writes_to_init_config_and_secret_targets_are_blocked() {
    assert_all(
        &[
            "cp -- a ~/.bashrc",
            "cp -- a ~/.zshrc",
            "cp -- a ~/.zshenv",
            "cp -- a ~/.zprofile",
            "cp -- a ~/.profile",
            "cp -- a ~/.bash_profile",
            "cp -- a ~/.bash_login",
            "cp -- a ~/.zlogin",
            "rm -- ~/.bashrc",
            "mkdir -- ~/.config/fish",
            "cp -- a ~/.config/shguard/config.toml",
            "cp -- a ~/.config/git/config",
            "cp -- a ~/.config/autostart/x.desktop",
            "cp -- a ~/.config/systemd/user/x.service",
            "rm -rf -- ~/.claude",
            "cp -- a ~/.claude/settings.json",
            "cp -- a ~/.ssh/authorized_keys",
            "rm -- ~/.gnupg/pubring.kbx",
            "cp -- a ~/.gitconfig",
            "mkdir -- ~/.cargo",
            "cp -- a ~/Library/LaunchAgents/x.plist",
            "uniq -- a ~/.zshrc",
        ],
        Decision::Block,
    );
}

#[test]
fn writes_to_project_local_hook_and_config_paths_are_blocked() {
    assert_all(
        &[
            "mkdir .git/hooks",
            "mkdir ./.git/hooks",
            "cp a .git/hooks/pre-commit",
            "cp a ./.git/config",
            "rm -rf .git",
            "rm -rf ./.git",
            "rm -rf .claude",
            "cp a .claude/settings.json",
            "cp a ./.claude/settings.json",
            "mkdir .cargo",
            "cp a ./.cargo/config.toml",
            "uniq a .git/hooks/x",
        ],
        Decision::Block,
    );
    // Neighbours with another name are ordinary relative paths.
    assert_all(
        &[
            "mkdir .github",
            "cp a .gitignore",
            "mkdir -p .github/workflows",
            "cp a .claude-notes",
        ],
        Decision::Allow,
    );
}

#[test]
fn reading_credential_directories_is_asked() {
    assert_all(
        &[
            "cat -- ~/.ssh/id_ed25519",
            "head -- ~/.aws/credentials",
            "tail -n 5 -- ~/.gnupg/trustdb.gpg",
            "grep -- token ~/.config/gh/hosts.yml",
            "grep -e token -- ~/.ssh/config",
            "rg -- token ~/.ssh",
            "rg -e token -- ~/.aws",
            "wc -- ~/.ssh/known_hosts",
            "sort -- ~/.aws/config",
        ],
        Decision::Ask,
    );
}

/// #1113: the absolute home spelling, other volumes, and names at any depth.
#[test]
fn credential_files_are_asked_wherever_they_are() {
    assert_all(
        &[
            "cat /Users/me/.ssh/id_rsa",
            "cat /home/me/.ssh/id_ed25519",
            "cat /System/Volumes/Data/Users/me/.ssh/id_rsa",
            "cat /USERS/ME/.SSH/ID_RSA",
            "head /Users/me/.aws/credentials",
            "tail /root/.config/gh/hosts.yml",
            "grep token /Users/me/.netrc",
            "wc -l /Users/me/.zsh_history",
            "sort /Users/me/.git-credentials",
            "cat .env",
            "cat sub/.env",
            "cat ./app/.env.local",
            "cat keys/id_rsa",
            "cat /tmp/backup/id_ed25519.pub",
            "cat /Users/me/.claude/.credentials.json",
            "cat /Users/me/.claude.json",
            "cp sub/.env x",
            "uniq app/.env.prod",
            "rg token app/.env",
            "cat .envrc",
            "cat /Users/me/.cargo/credentials.toml",
            "cat sub/.env-prod",
        ],
        Decision::Ask,
    );
    // Neighbouring names are ordinary paths.
    assert_all(
        &[
            "cat envrc.md",
            "cat sub/x.env",
            "cat .sshd_config",
            "cat docs/ssh.md",
            "cat .claude/settings.json",
            "cat CLAUDE.md",
        ],
        Decision::Allow,
    );
}

#[test]
fn relative_paths_after_cd_and_dotdot_are_asked() {
    assert_all(
        &[
            "cd src && cat a.txt",
            "cd /Users/me && fd -H",
            "cd src && fd -e rs",
            "cat ../a.txt",
            "rm -rf ../build",
            "cp a ../b",
        ],
        Decision::Ask,
    );
}

#[test]
fn unknown_heads_are_asked_even_when_they_wrap_a_blocked_command() {
    assert_all(
        &["unknowntool rm -rf /", "xargs rm -rf /", "sudo rm -rf /"],
        Decision::Ask,
    );
}

#[test]
fn unnormalized_relative_leads_hit_the_block_targets() {
    assert_all(
        &[
            "cp x .//.git/hooks/y",
            "mkdir .//.git/hooks",
            "rm -rf ././.git",
            "cp x ././.claude/settings.json",
            "rm -rf .//",
            "rm -rf ././",
            "cp x ./.mcp.json",
            "cp x .//lefthook.yml",
        ],
        Decision::Block,
    );
    // `./.foo` was asked by a stopgap before the kernel normalized relative
    // paths; it is an ordinary relative path.
    assert_all(&["cp x ./.foo", "rm -rf ./build"], Decision::Allow);
}

#[test]
fn case_variants_of_blocked_paths_are_not_allowed() {
    assert_all(
        &[
            "rm -rf .GIT",
            "cp x .GIT/hooks/pre-commit",
            "cp x .Claude/settings.json",
            "rm -r /ETC",
            "cp x /DEV/sda",
            "cp -- x ~/.SSH/authorized_keys",
        ],
        Decision::Block,
    );
    assert_all(&["cat -- ~/.SSH/id_rsa", "cat .ENV"], Decision::Ask);
}

#[test]
fn under_targets_stop_at_a_component_boundary() {
    assert_all(
        &[
            "rm -r /etc",
            "rm -r /etc/",
            "rm -r /etc/x",
            "cp x /dev/sda",
            "rm -r /lib64",
            "rm -r /lib32/x",
            "rm -r /libx32",
            "rm -r /libexec/x",
        ],
        Decision::Block,
    );
    // Not below the target: only the absolute-path Ask.
    assert_all(&["rm -r /etcfoo", "cp x /devops/y"], Decision::Ask);
    assert_all(&["mkdir .github", "cp a .gitignore"], Decision::Allow);
}

#[test]
fn prefix_targets_stay_byte_prefixes() {
    assert_all(
        &["cp x ^foo", "cat .env.local", "cat ./.env.local"],
        Decision::Ask,
    );
    // `~/.claude.json` is a byte prefix: its backups are asked too.
    assert_all(&["cat -- ~/.claude.json.backup"], Decision::Ask);
}

#[test]
fn non_ascii_paths_are_not_allowed() {
    // APFS folds Unicode case: `\u{17F}` (long s) can name `~/.ssh`.
    assert_not_allow(&["cat -- ~/.\u{17F}\u{17F}h/id_rsa", "rm -rf .gi\u{1E6B}"]);
    assert_all(&["cat \u{65E5}\u{672C}.txt"], Decision::Ask);
}

#[test]
fn recursive_readers_of_broad_roots_are_not_allowed() {
    assert_not_allow(&[
        "grep -r -- BEGIN ~",
        "grep -rl -- x /",
        "rg -- BEGIN ~",
        "rg --files /Users/x",
        "ls -laR -- ~",
        "grep -rA40 PRIVATE /System/Volumes/Data/Users/me",
        "rg -A 40 PRIVATE /System/Volumes/Data/Users/me",
        "grep -r x /System",
        "grep -r x /System/Volumes",
        "rg x /System/Volumes",
        "grep -r x /var/root",
        "grep -r x /private/var/root",
        "ls -R /System/Volumes/Data/Users/me",
        "fd . /System/Volumes/Data/Users/me",
        "tree /System/Volumes/Data/Users/me",
        "eza -T /System/Volumes/Data/Users/me",
    ]);
    assert_all(
        &["grep -r foo src", "rg foo src", "ls -R src"],
        Decision::Allow,
    );
}

#[test]
fn a_search_pattern_naming_a_credential_is_a_path_unless_given_with_e() {
    assert_not_allow(&["grep .ssh docs/", "grep -rn .env src/"]);
    assert_all(&["grep -e .ssh docs/", "rg -e .env src/"], Decision::Allow);
}

#[test]
fn more_credential_files_are_asked() {
    assert_not_allow(&[
        "cat -- ~/.claude/.credentials.json",
        "cat -- ~/.netrc",
        "cat -- ~/.zsh_history",
        "cat .env",
        "cat .env.local",
        "cat ./.env",
    ]);
    assert_all(&["cat README.md", "cat .envrc.example"], Decision::Allow);
}

#[test]
fn project_local_code_running_configs_are_blocked() {
    assert_all(
        &[
            "cp x .mcp.json",
            "cp x .envrc",
            "cp x .husky/pre-commit",
            "cp x ./.githooks/pre-push",
            "cp x lefthook.yaml",
            "cp x ./.lefthook.yml",
            "rm -rf .husky",
        ],
        Decision::Block,
    );
}

const TWO_ROWS: &str = r#"
[[row]]
key = ["git"]
[[row]]
key = ["git", "log"]
[[rule]]
id = "not-a-row"
"#;

#[test]
fn a_row_without_a_test_command_is_reported() {
    let missing = common::uncovered_row_keys(TWO_ROWS, &["git status", "git -C x log"], &[]);
    assert_eq!(missing, Ok(vec!["git log".to_owned()]));
}

#[test]
fn a_command_counts_for_the_longest_row_key_it_starts_with() {
    let missing = common::uncovered_row_keys(TWO_ROWS, &["git log -p"], &[]);
    assert_eq!(missing, Ok(vec!["git".to_owned()]));
}

#[test]
fn an_exempt_row_is_not_reported() {
    let missing = common::uncovered_row_keys(TWO_ROWS, &["git log"], &[&["git"]]);
    assert_eq!(missing, Ok(Vec::new()));
}

#[test]
fn a_stale_or_unknown_exemption_is_rejected() {
    assert_eq!(
        common::uncovered_row_keys(TWO_ROWS, &["git"], &[&["git"]]),
        Err(common::CoverageError::StaleExempt("git".to_owned()))
    );
    assert_eq!(
        common::uncovered_row_keys(TWO_ROWS, &["git"], &[&["git", "nope"]]),
        Err(common::CoverageError::UnknownExempt("git nope".to_owned()))
    );
}

#[test]
fn a_text_without_rows_is_rejected() {
    assert_eq!(
        common::uncovered_row_keys("[[rule]]\nid = \"x\"\n", &["git"], &[]),
        Err(common::CoverageError::NoRows)
    );
}

#[test]
#[should_panic(expected = "no embedded catalog file")]
fn an_unknown_source_name_panics() {
    common::assert_rows_covered("embedded:nope.toml", &["git"], &[]);
}
