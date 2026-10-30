//! The embedded core catalog, command to decision. Each test loads the
//! embedded files with no user config and pins only the decision of a
//! command, never a message or a rule id.

use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::decision::Decision;

fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

fn decide(l: &Loaded, cmd: &str) -> Decision {
    let Ok(script) = shguard_syntax::parse(cmd.as_bytes()) else {
        panic!("`{cmd}` is outside the subset");
    };
    shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
}

fn assert_all(cmds: &[&str], want: Decision) {
    let l = embedded();
    for cmd in cmds {
        assert_eq!(decide(&l, cmd), want, "`{cmd}`");
    }
}

fn assert_not_allow(cmds: &[&str]) {
    let l = embedded();
    for cmd in cmds {
        assert_ne!(decide(&l, cmd), Decision::Allow, "`{cmd}`");
    }
}

#[test]
fn every_row_has_an_allowed_command() {
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

#[test]
fn relative_paths_after_cd_and_dotdot_are_asked() {
    assert_all(
        &[
            "cd src && cat a.txt",
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
