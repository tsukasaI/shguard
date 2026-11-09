//! Tests of the catalog loader: one rejection per check, the shape of a valid
//! load, end-to-end decisions, and the `check` subcommand.

#[expect(
    dead_code,
    reason = "each test crate uses only part of the shared helpers"
)]
mod common;

use std::process::Command;

use common::decide;
use shguard::catalog::{GuidanceText, LoadError, Loaded, Origin, Source, load};
use shguard_kernel::ast::{Opaque, Part};
use shguard_kernel::catalog::{
    Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role, Row,
    RunsCode, ShortName,
};
use shguard_kernel::decision::Decision;
use shguard_kernel::rule::{OptAlts, Outcome, Pat, PatKind, Rule, RuleId, Scope};

fn load_one(text: &str) -> Result<Loaded, Vec<LoadError>> {
    load(&[Source {
        origin: Origin::User,
        name: "t.toml",
        text,
    }])
}

fn errors(text: &str) -> Vec<LoadError> {
    match load_one(text) {
        Ok(_) => panic!("expected load errors"),
        Err(e) => e,
    }
}

fn loaded(text: &str) -> Loaded {
    match load_one(text) {
        Ok(l) => l,
        Err(e) => panic!("load failed: {e:?}"),
    }
}

fn row(key: &str, extra: &str) -> String {
    format!(
        "[[row]]\nkey = [{key}]\nsource = \"https://example.com\"\norder = \"permute\"\ndashdash = \"ends\"\n{extra}\n"
    )
}

fn rule(extra: &str) -> String {
    format!("[[rule]]\nid = \"r\"\nkey = [\"rm\"]\noutcome = \"block\"\n{extra}\n")
}

#[test]
fn toml_error() {
    assert!(matches!(errors("[[row]\n")[0], LoadError::Toml { .. }));
    assert!(matches!(errors("bogus = 1\n")[0], LoadError::Toml { .. }));
    let bad = row("\"ls\"", "").replace("permute", "sideways");
    assert!(matches!(errors(&bad)[0], LoadError::Toml { .. }));
}

#[test]
fn toml_error_is_not_in_the_source_chain() {
    let errs = errors("[[row]\n");
    assert!(
        std::error::Error::source(&errs[0]).is_none(),
        "the TOML error is already in Display, so a chain walker would print it twice"
    );
}

#[test]
fn read_error_is_not_in_the_source_chain() {
    let err = LoadError::Read {
        file: "t.toml".to_owned(),
        error: std::io::Error::other("e"),
    };
    assert!(
        std::error::Error::source(&err).is_none(),
        "the I/O error is already in Display, so a chain walker would print it twice"
    );
}

#[test]
fn toml_error_in_one_file_does_not_hide_others() {
    let dup = row("\"ls\"", "");
    let both = format!("{dup}{dup}");
    let errs = load(&[
        Source {
            origin: Origin::User,
            name: "a.toml",
            text: "[[row]\n",
        },
        Source {
            origin: Origin::User,
            name: "b.toml",
            text: &both,
        },
    ])
    .unwrap_err();
    assert!(errs.iter().any(|e| matches!(e, LoadError::Toml { .. })));
    assert!(
        errs.iter()
            .any(|e| matches!(e, LoadError::DuplicateRow { .. }))
    );
}

#[test]
fn missing_or_empty_source() {
    let none = "[[row]]\nkey = [\"ls\"]\norder = \"permute\"\ndashdash = \"ends\"\n";
    assert!(matches!(errors(none)[0], LoadError::MissingSource { .. }));
    let blank = row("\"ls\"", "").replace("https://example.com", "  ");
    assert!(matches!(errors(&blank)[0], LoadError::MissingSource { .. }));
}

#[test]
fn bad_row_key() {
    assert!(matches!(
        errors(&row("", ""))[0],
        LoadError::BadRowKey { .. }
    ));
    assert!(
        errors(&row("\"git\", \"\"", ""))
            .iter()
            .any(|e| matches!(e, LoadError::BadRowKey { .. }))
    );
}

#[test]
fn bad_option_name() {
    for opt in [
        "short = \"ab\"",
        "short = \"-\"",
        "long = \"a=b\"",
        "long = \"-x\"",
        "long = \"\"",
    ] {
        let t = row("\"ls\"", &format!("[[row.opt]]\n{opt}\n"));
        assert!(
            errors(&t)
                .iter()
                .any(|e| matches!(e, LoadError::BadOptName { .. })),
            "{opt}"
        );
    }
}

#[test]
fn option_without_name() {
    let t = row("\"ls\"", "[[row.opt]]\nvalue = \"flag\"\n");
    assert!(matches!(errors(&t)[0], LoadError::OptWithoutName { .. }));
}

#[test]
fn duplicate_row_key_across_files() {
    let t = row("\"ls\"", "");
    let errs = load(&[
        Source {
            origin: Origin::User,
            name: "a.toml",
            text: &t,
        },
        Source {
            origin: Origin::User,
            name: "b.toml",
            text: &t,
        },
    ])
    .unwrap_err();
    assert!(matches!(errs[0], LoadError::DuplicateRow { .. }));
}

#[test]
fn duplicate_option_names() {
    let cases = [
        "[[row.opt]]\nshort = \"a\"\n[[row.opt]]\nshort = \"a\"\n",
        "[[row.opt]]\nlong = \"all\"\n[[row.opt]]\nlong = \"all\"\n",
        "[[row.opt]]\nshort = \"a\"\nlong = \"all\"\n[[row.opt]]\nlong = \"all\"\n",
        "[[row.opt]]\nshort = \"a\"\nlong = \"all\"\n[[row.opt]]\nshort = \"a\"\n",
    ];
    for c in cases {
        assert!(
            errors(&row("\"ls\"", c))
                .iter()
                .any(|e| matches!(e, LoadError::DuplicateOpt { .. })),
            "{c}"
        );
    }
}

#[test]
fn orphan_row() {
    let t = row("\"git\", \"status\"", "");
    assert!(matches!(errors(&t)[0], LoadError::OrphanRow { .. }));
}

#[test]
fn denylisted_head() {
    for head in [
        "tar",
        "ps",
        "ar",
        "find",
        "eval",
        "source",
        ".",
        "exec",
        "command",
        "builtin",
        "trap",
        "ssh",
        "docker",
        "kubectl",
        "socat",
        "flock",
        "strace",
        "tmux",
        "crontab",
        "xargs",
        "env",
        "nohup",
        "timeout",
        "nice",
        "sudo",
        "doas",
        "watch",
        "script",
        "parallel",
        "gxargs",
        "gsed",
        "gfind",
        "gtar",
        "sed",
        "awk",
        "perl",
        "node",
        "python",
        "python3",
        "ruby",
        "bash",
        "sh",
        "zsh",
        "gtimeout",
        "genv",
        "gnohup",
        "gnice",
        "su",
        "dash",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "deno",
        "bun",
        "php",
        "lua",
        "osascript",
        "python2",
        "python3.11",
        "python3.12",
        "python3.13",
        "python3.14",
        "python3.10",
        "python3.9",
        "python3.15",
        "python3.13t",
        "python3.13-intel64",
        "Python3",
        "pythonw",
        "pythonw3",
        "Pythonw3",
        "ENV",
        "Bash",
        "perl5.30",
        "lua5.4",
        "php8.3",
        "ruby3.1",
        "pypy",
        "pypy3",
        "ipython",
        "luajit",
        "tclsh",
        "expect",
        "pwsh",
    ] {
        let t = row(&format!("\"{head}\""), "");
        assert!(
            matches!(errors(&t)[0], LoadError::DenylistedHead { .. }),
            "{head}"
        );
        let ok = row(&format!("\"{head}\""), "runs_code = true");
        assert!(load_one(&ok).is_ok(), "{head}");
    }
    // Only `w` alone or before a digit is denylisted.
    for head in ["pythonwx", "pythonic"] {
        assert!(load_one(&row(&format!("\"{head}\""), "")).is_ok(), "{head}");
    }
    // A versioned interpreter needs a digit right after its name.
    for head in ["perlx", "phpize", "rubygems"] {
        assert!(load_one(&row(&format!("\"{head}\""), "")).is_ok(), "{head}");
    }
}

#[test]
fn a_path_head_is_a_load_error() {
    // A path head would skip the head checks a bare name gets.
    for head in ["/bin/bash", "/opt/homebrew/bin/fd", "./fd", "bin/ls"] {
        let t = row(&format!("\"{head}\""), "");
        assert!(
            errors(&t)
                .iter()
                .any(|e| matches!(e, LoadError::PathHead { .. })),
            "{head}"
        );
    }
}

#[test]
fn non_ascii_head() {
    // Unconditional: `runs_code` does not excuse a head the ASCII-only head
    // checks cannot see through.
    for head in ["baſh", "pythön", "ｆｄ"] {
        for extra in ["", "runs_code = true"] {
            let t = row(&format!("\"{head}\""), extra);
            assert!(
                errors(&t)
                    .iter()
                    .any(|e| matches!(e, LoadError::NonAsciiHead { .. })),
                "{head} {extra}"
            );
        }
    }
}

#[test]
fn code_option_heads_load_without_their_code_options() {
    for head in ["fd", "split", "gsplit"] {
        let t = row(&format!("\"{head}\""), "rest = \"path\"");
        assert!(load_one(&t).is_ok(), "{head}");
    }
    let fd = |opt: &str| {
        row(
            "\"fd\"",
            &format!("positionals = [\"inert\"]\nrest = \"path\"\n[[row.opt]]\n{opt}\n"),
        )
    };
    for opt in [
        "short = \"x\"\nvalue = { takes = \"inert\" }",
        "long = \"exec\"\nvalue = { takes = \"path\" }",
        "short = \"q\"\nlong = \"exec-batch\"",
        "short = \"X\"",
        "short = \"l\"",
        "long = \"list-details\"",
    ] {
        assert!(
            matches!(errors(&fd(opt))[0], LoadError::CodeOptionNotCode { .. }),
            "{opt}"
        );
    }
    // An optional value is read only inline, so it is refused even as code.
    for opt in [
        "short = \"x\"\nvalue = { optional = \"code\" }",
        "short = \"l\"\nvalue = { optional = \"code\" }",
    ] {
        assert!(
            matches!(errors(&fd(opt))[0], LoadError::CodeOptionNotCode { .. }),
            "{opt}"
        );
    }
    // fdfind is fd under its Debian name.
    let fdfind = row(
        "\"fdfind\"",
        "[[row.opt]]\nshort = \"x\"\nvalue = { takes = \"inert\" }",
    );
    assert!(matches!(
        errors(&fdfind)[0],
        LoadError::CodeOptionNotCode { .. }
    ));
    // ASCII case variants of the head are checked too (#1138).
    for (head, opt) in [
        ("FD", "short = \"x\"\nvalue = { takes = \"inert\" }"),
        ("FdFind", "short = \"x\"\nvalue = { takes = \"inert\" }"),
        ("SPLIT", "long = \"fil\"\nvalue = { takes = \"inert\" }"),
        ("Gsplit", "long = \"filter\"\nvalue = { takes = \"inert\" }"),
    ] {
        let t = row(&format!("\"{head}\""), &format!("[[row.opt]]\n{opt}"));
        assert!(
            matches!(errors(&t)[0], LoadError::CodeOptionNotCode { .. }),
            "{head}"
        );
    }
    // split takes abbreviations, so a prefix of `--filter` is refused too.
    for long in ["filter", "fil", "f"] {
        let split = row(
            "\"split\"",
            &format!("[[row.opt]]\nlong = \"{long}\"\nvalue = {{ takes = \"inert\" }}"),
        );
        assert!(
            matches!(errors(&split)[0], LoadError::CodeOptionNotCode { .. }),
            "{long}"
        );
    }
    // fd does not take abbreviations.
    assert!(load_one(&fd("long = \"ex\"")).is_ok());
    // Declared with a `code` value, the option loads and makes the command
    // an Ask; left out, it is Unknown.
    let l = loaded(&fd(
        "short = \"x\"\nlong = \"exec\"\nvalue = { takes = \"code\" }",
    ));
    assert_eq!(decide(&l, "fd ts src"), Decision::Allow);
    for cmd in [
        "fd -x rm",
        "fd --exec rm",
        "fd -X cat",
        "fd -l",
        "fd -Hl foo",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Ask, "{cmd}");
    }
    // A runs_code row may list them freely.
    assert!(
        load_one(&row(
            "\"fd\"",
            "runs_code = true\n[[row.opt]]\nshort = \"x\""
        ))
        .is_ok()
    );
}

#[test]
fn parent_option_spelling_child_must_take_code() {
    let child = row("\"pylang\", \"-c\"", "runs_code = true");
    let parent = |value: &str| {
        row(
            "\"pylang\"",
            &format!("[[row.opt]]\nshort = \"c\"\nvalue = {value}\n"),
        )
    };
    for v in [
        "\"flag\"",
        "{ takes = \"inert\" }",
        "{ optional = \"path\" }",
        "{ optional = \"code\" }",
    ] {
        let errs = errors(&format!("{}{child}", parent(v)));
        assert!(
            errs.iter()
                .any(|e| matches!(e, LoadError::ParentOptNotCode { .. })),
            "{v}"
        );
    }
    assert!(load_one(&format!("{}{child}", parent("{ takes = \"code\" }"))).is_ok());
    let both_parent = row(
        "\"pylang\"",
        "[[row.opt]]\nshort = \"c\"\nlong = \"command\"\n",
    );
    assert!(
        errors(&format!("{both_parent}{child}"))
            .iter()
            .any(|e| matches!(e, LoadError::ParentOptNotCode { .. }))
    );
    let long_child = row("\"pylang\", \"--command\"", "runs_code = true");
    let long_parent = row("\"pylang\"", "[[row.opt]]\nlong = \"command\"\n");
    assert!(
        errors(&format!("{long_parent}{long_child}"))
            .iter()
            .any(|e| matches!(e, LoadError::ParentOptNotCode { .. }))
    );
}

#[test]
fn duplicate_rule_id() {
    let t = format!("{}{}{}", row("\"rm\"", ""), rule(""), rule(""));
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::DuplicateRuleId { .. }))
    );
}

#[test]
fn empty_rule_id() {
    for id in ["", " ", "\\t"] {
        let t = format!(
            "{}[[rule]]\nid = \"{id}\"\nkey = [\"rm\"]\noutcome = \"block\"\n",
            row("\"rm\"", "")
        );
        assert!(
            errors(&t)
                .iter()
                .any(|e| matches!(e, LoadError::EmptyRuleId { .. })),
            "{id:?}"
        );
    }
}

#[test]
fn bad_rule_key() {
    let t = format!(
        "{}[[rule]]\nid = \"r\"\nkey = []\noutcome = \"ask\"\n",
        row("\"rm\"", "")
    );
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::BadRuleKey { .. }))
    );
}

#[test]
fn dead_rule() {
    let t = format!("{}{}", row("\"ls\"", ""), rule(""));
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::DeadRule { .. }))
    );
    // A rule whose key extends a row's key is live.
    let live = format!(
        "{}[[rule]]\nid = \"a\"\nkey = [\"git\", \"push\"]\noutcome = \"ask\"\n",
        row("\"git\"", "")
    );
    assert!(load_one(&live).is_ok());
}

#[test]
fn malformed_or_unknown_rule_option() {
    let rm = row(
        "\"rm\"",
        "[[row.opt]]\nshort = \"r\"\nlong = \"recursive\"\n",
    );
    for bad in ["-rf", "r", "--", "-"] {
        let t = format!("{rm}{}", rule(&format!("opts = [[\"{bad}\"]]")));
        assert!(
            errors(&t)
                .iter()
                .any(|e| matches!(e, LoadError::BadRuleOpt { .. })),
            "{bad}"
        );
    }
    for unknown in ["-q", "--quiet"] {
        let t = format!("{rm}{}", rule(&format!("opts = [[\"{unknown}\"]]")));
        assert!(
            errors(&t)
                .iter()
                .any(|e| matches!(e, LoadError::UnknownRuleOpt { .. })),
            "{unknown}"
        );
    }
    for ok in ["--recursive", "-r"] {
        let t = format!("{rm}{}", rule(&format!("opts = [[\"{ok}\"]]")));
        assert!(load_one(&t).is_ok(), "{ok}");
    }
}

#[test]
fn empty_alias_set_empty_target_and_dollar_target() {
    let rm = row("\"rm\"", "");
    let t = format!("{rm}{}", rule("opts = [[]]"));
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::EmptyAlts { .. }))
    );
    let t = format!(
        "{rm}{}",
        rule("targets = [{ pat = \"\", kind = \"exact\" }]")
    );
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::EmptyTarget { .. }))
    );
    let t = format!(
        "{rm}{}",
        rule("targets = [{ pat = \"$HOME\", kind = \"prefix\" }]")
    );
    assert!(
        errors(&t)
            .iter()
            .any(|e| matches!(e, LoadError::TargetHasDollar { .. }))
    );
}

#[test]
fn targets_must_be_in_normal_form() {
    let rm = row("\"rm\"", "rest = \"path\"");
    let target = |pat: &str, kind: &str| {
        format!(
            "{rm}{}",
            rule(&format!(
                "targets = [{{ pat = \"{pat}\", kind = \"{kind}\" }}]"
            ))
        )
    };
    for (pat, normal) in [
        ("./x", "x"),
        ("a//b", "a/b"),
        ("x/", "x"),
        ("~/./.ssh", "~/.ssh"),
        ("/etc/", "/etc"),
    ] {
        let errs = errors(&target(pat, "exact"));
        assert!(
            errs.iter().any(|e| matches!(
                e,
                LoadError::TargetNotNormal { normal: n, .. } if n == normal
            )),
            "{pat}: {errs:?}"
        );
    }
    for pat in [".git/", "~/", "/etc/", "~/.", "~//"] {
        let errs = errors(&target(pat, "prefix"));
        assert!(
            errs.iter()
                .any(|e| matches!(e, LoadError::PrefixEndsInSlash { .. })),
            "{pat}: {errs:?}"
        );
    }
    for pat in ["~foo", "~root/.ssh", "~+", "~-"] {
        for kind in ["exact", "prefix", "under"] {
            let errs = errors(&target(pat, kind));
            assert!(
                errs.iter()
                    .any(|e| matches!(e, LoadError::TildeUserTarget { .. })),
                "{pat} {kind}: {errs:?}"
            );
        }
    }
    for pat in ["~/.ssh", "/.ssh", "~", "/"] {
        for kind in ["component", "component_prefix"] {
            let errs = errors(&target(pat, kind));
            assert!(
                errs.iter()
                    .any(|e| matches!(e, LoadError::AnchoredComponentTarget { .. })),
                "{pat} {kind}: {errs:?}"
            );
        }
    }
    for pat in ["..", "a/..", "../b"] {
        for kind in ["component", "component_prefix"] {
            let errs = errors(&target(pat, kind));
            assert!(
                errs.iter()
                    .any(|e| matches!(e, LoadError::DotDotTarget { .. })),
                "{pat} {kind}: {errs:?}"
            );
        }
    }
    for kind in ["prefix", "under", "component", "component_prefix"] {
        let errs = errors(&target(".", kind));
        assert!(
            errs.iter()
                .any(|e| matches!(e, LoadError::DotTarget { .. })),
            "{kind}: {errs:?}"
        );
    }
    // Normal forms load, uppercase included; `under` is a kind.
    for (pat, kind) in [
        ("/", "prefix"),
        ("/", "under"),
        ("~", "under"),
        ("~", "prefix"),
        ("~/x", "exact"),
        (".", "exact"),
        (".git", "prefix"),
        (".git", "under"),
        ("/ETC", "under"),
        ("~/.SSH", "prefix"),
        ("^", "prefix"),
        (".ssh", "component"),
        (".config/gh", "component"),
        (".env.", "component_prefix"),
    ] {
        assert!(load_one(&target(pat, kind)).is_ok(), "{pat} {kind}");
    }
}

#[test]
fn component_target_decisions() {
    let rm = row("\"rm\"", "rest = \"path\"");
    let l = loaded(&format!(
        "{rm}{}",
        rule(
            "targets = [{ pat = \".ssh\", kind = \"component\" }, { pat = \".env.\", kind = \"component_prefix\" }]"
        )
    ));
    for cmd in [
        "rm .ssh",
        "rm /Users/me/.ssh/id_rsa",
        "rm a/.SSH/b",
        "rm -- ~/.ssh",
        "rm sub/.env.local",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Block, "{cmd}");
    }
    for cmd in ["rm .sshx", "rm x.ssh", "rm sub/.env", "rm a.env.x"] {
        assert_eq!(decide(&l, cmd), Decision::Allow, "{cmd}");
    }
}

#[test]
fn under_target_decisions() {
    let rm = row("\"rm\"", "rest = \"path\"");
    let l = loaded(&format!(
        "{rm}{}",
        rule(
            "targets = [{ pat = \".git\", kind = \"under\" }, { pat = \"/dev\", kind = \"under\" }]"
        )
    ));
    for cmd in [
        "rm .git",
        "rm .git/x",
        "rm ./.GIT/x",
        "rm /dev/sda",
        "rm //dev",
    ] {
        assert_eq!(decide(&l, cmd), Decision::Block, "{cmd}");
    }
    for cmd in ["rm .github", "rm .gitignore", "rm /devops"] {
        assert_eq!(decide(&l, cmd), Decision::Allow, "{cmd}");
    }
}

#[test]
fn all_errors_are_collected() {
    let t = format!("{}{}", row("\"git\", \"status\"", ""), rule(""));
    assert!(errors(&t).len() >= 2);
}

#[test]
fn changes_cwd_and_cwd_sensitive_conflict() {
    let t = row("\"git\"", "changes_cwd = true\ncwd_sensitive = true");
    assert!(matches!(errors(&t)[0], LoadError::ConflictingCwd { .. }));
}

#[test]
fn cwd_sensitive_row_is_asked_after_cd() {
    let text = format!(
        "{}{}",
        "[[row]]\nkey = [\"cd\"]\nsource = \"https://example.com/cd\"\norder = \"strict\"\ndashdash = \"literal\"\nplus_words = \"operand\"\npositionals = [\"path\"]\nchanges_cwd = true\n",
        row("\"git\"", "cwd_sensitive = true\npositionals = []"),
    );
    let l = loaded(&text);
    assert_eq!(decide(&l, "git"), Decision::Allow);
    assert_eq!(decide(&l, "cd /x && git"), Decision::Ask);
    assert_eq!(decide(&l, "cd /x; git"), Decision::Ask);
}

#[test]
fn child_of_cwd_sensitive_row_must_be_cwd_sensitive() {
    let parent = row("\"git\"", "cwd_sensitive = true\npositionals = []");
    let t = format!("{parent}{}", row("\"git\", \"status\"", ""));
    assert!(matches!(
        errors(&t)[0],
        LoadError::CwdSensitiveParent { .. }
    ));
    let cd = "[[row]]\nkey = [\"cd\"]\nsource = \"https://example.com/cd\"\norder = \"strict\"\ndashdash = \"literal\"\nplus_words = \"operand\"\npositionals = [\"path\"]\nchanges_cwd = true\n";
    let ok = format!(
        "{cd}{parent}{}",
        row("\"git\", \"status\"", "cwd_sensitive = true")
    );
    let l = loaded(&ok);
    assert_eq!(decide(&l, "git status"), Decision::Allow);
    assert_eq!(decide(&l, "cd /x && git status"), Decision::Ask);
    assert_eq!(decide(&l, "cd /x | git status"), Decision::Ask);

    // Every level is checked against its own parent.
    let mid = row("\"git\", \"remote\"", "cwd_sensitive = true");
    let t = format!("{parent}{mid}{}", row("\"git\", \"remote\", \"show\"", ""));
    assert!(matches!(
        errors(&t)[0],
        LoadError::CwdSensitiveParent { .. }
    ));
}

#[test]
fn valid_catalog_equals_hand_built() {
    let text = format!(
        "{}{}{}{}{}{}",
        row(
            "\"ls\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"l\"\n[[row.opt]]\nshort = \"n\"\nlong = \"lines\"\nvalue = { takes = \"inert\" }\n[[row.opt]]\nlong = \"color\"\nvalue = { optional = \"path\" }\n"
        ),
        "[[row]]\nkey = [\"cd\"]\nsource = \"https://example.com/cd\"\norder = \"strict\"\ndashdash = \"literal\"\nplus_words = \"operand\"\npositionals = [\"path\"]\nchanges_cwd = true\n",
        row(
            "\"rm\"",
            "[[row.opt]]\nshort = \"r\"\n[[row.opt]]\nshort = \"R\"\n[[row.opt]]\nlong = \"recursive\"\n"
        ),
        row(
            "\"shx\"",
            "[[row.opt]]\nshort = \"c\"\nvalue = { takes = \"code\" }\n"
        ),
        row("\"shx\", \"-c\"", "runs_code = true"),
        "[[rule]]\nid = \"rm-root\"\nscope = \"pipe_into\"\nkey = [\"rm\"]\nopts = [[\"-r\", \"-R\", \"--recursive\"]]\ntargets = [{ pat = \"/\", kind = \"exact\" }, { pat = \"~/x\", kind = \"prefix\" }, { pat = \"~\", kind = \"exact\" }]\noutcome = \"block\"\n",
    );
    let l = loaded(&text);
    let short = |b: u8| ShortName::new(b).unwrap();
    let long = |s: &str| LongName::new(s.as_bytes().to_vec()).unwrap();
    let ls = Row::new(
        vec![b"ls".to_vec()],
        Grammar::new(
            vec![
                Opt::new(OptName::Short(short(b'l')), OptValue::Flag),
                Opt::new(
                    OptName::Both(short(b'n'), long("lines")),
                    OptValue::Takes(Role::Inert),
                ),
                Opt::new(OptName::Long(long("color")), OptValue::Optional(Role::Path)),
            ],
            vec![],
            Some(Role::Path),
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        ),
        RunsCode::No,
        Cwd::Keeps,
    )
    .unwrap();
    let cd = Row::new(
        vec![b"cd".to_vec()],
        Grammar::new(
            vec![],
            vec![Role::Path],
            None,
            Order::Strict,
            DashDash::Literal,
            PlusWords::Operand,
        ),
        RunsCode::No,
        Cwd::Changes,
    )
    .unwrap();
    let rm = Row::new(
        vec![b"rm".to_vec()],
        Grammar::new(
            vec![
                Opt::new(OptName::Short(short(b'r')), OptValue::Flag),
                Opt::new(OptName::Short(short(b'R')), OptValue::Flag),
                Opt::new(OptName::Long(long("recursive")), OptValue::Flag),
            ],
            vec![],
            None,
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        ),
        RunsCode::No,
        Cwd::Keeps,
    )
    .unwrap();
    let sh = Row::new(
        vec![b"shx".to_vec()],
        Grammar::new(
            vec![Opt::new(
                OptName::Short(short(b'c')),
                OptValue::Takes(Role::Code),
            )],
            vec![],
            None,
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        ),
        RunsCode::No,
        Cwd::Keeps,
    )
    .unwrap();
    let sh_c = Row::new(
        vec![b"shx".to_vec(), b"-c".to_vec()],
        Grammar::new(
            vec![],
            vec![],
            None,
            Order::Permute,
            DashDash::Ends,
            PlusWords::Reject,
        ),
        RunsCode::Yes,
        Cwd::Keeps,
    )
    .unwrap();
    assert_eq!(l.catalog, Catalog::new(vec![ls, cd, rm, sh, sh_c], vec![]));
    let expected = Rule::new(
        RuleId(0),
        Scope::PipeInto,
        vec![b"rm".to_vec()],
        vec![
            OptAlts::new(vec![
                OptName::Short(short(b'r')),
                OptName::Short(short(b'R')),
                OptName::Long(long("recursive")),
            ])
            .unwrap(),
        ],
        vec![
            Pat::new(vec![Part::Lit(b"/".to_vec())], PatKind::Exact).unwrap(),
            Pat::new(
                vec![Part::Opaque(Opaque::Tilde), Part::Lit(b"/x".to_vec())],
                PatKind::Prefix,
            )
            .unwrap(),
            Pat::new(vec![Part::Opaque(Opaque::Tilde)], PatKind::Exact).unwrap(),
        ],
        Outcome::Block,
    )
    .unwrap();
    assert_eq!(l.rules, vec![expected]);
    assert_eq!(l.rule_ids, vec!["rm-root".to_owned()]);
}

#[test]
fn end_to_end_decisions() {
    let date = |plus: &str| row("\"date\"", &format!("rest = \"inert\"\n{plus}"));
    let base = format!(
        "{}{}{}{}{}{}",
        row(
            "\"ls\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"l\"\n[[row.opt]]\nshort = \"a\"\n"
        ),
        row(
            "\"rm\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"r\"\nlong = \"recursive\"\n[[row.opt]]\nshort = \"R\"\n[[row.opt]]\nshort = \"f\"\n"
        ),
        rule(
            "opts = [[\"-r\", \"-R\", \"--recursive\"]]\ntargets = [{ pat = \"/\", kind = \"exact\" }]"
        ),
        row(
            "\"pylang\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"c\"\nvalue = { takes = \"code\" }\n"
        ),
        row("\"pylang\", \"-c\"", "runs_code = true"),
        row("\"tar\"", "runs_code = true"),
    );
    let l = loaded(&format!("{base}{}", date("")));
    assert_eq!(decide(&l, "ls -la"), Decision::Allow);
    assert_eq!(decide(&l, "rm -rf /"), Decision::Block);
    assert_eq!(decide(&l, "pylang -c x"), Decision::Ask);
    assert_eq!(decide(&l, "tar xf a"), Decision::Ask);
    assert_eq!(decide(&l, "date +%s"), Decision::Ask);
    let l = loaded(&format!("{base}{}", date("plus_words = \"operand\"")));
    assert_eq!(decide(&l, "date +%s"), Decision::Allow);
}

#[test]
fn option_like_key_segment() {
    // The shape that matters: a user row ["rm", "-rf"] next to an embedded
    // ["rm"] would be selected over it and swallow `-rf`.
    let rm = row("\"rm\"", "rest = \"path\"\n[[row.opt]]\nshort = \"r\"\n");
    for seg in ["-rf", "+x", "--force"] {
        let user = row(&format!("\"rm\", \"{seg}\""), "rest = \"path\"");
        assert!(
            errors(&format!("{rm}{user}"))
                .iter()
                .any(|e| matches!(e, LoadError::OptionLikeKey { .. })),
            "{seg}"
        );
        // Across files, as an embedded row and a user row.
        let errs = load(&[
            Source {
                origin: Origin::Embedded,
                name: "embedded.toml",
                text: &rm,
            },
            Source {
                origin: Origin::User,
                name: "user.toml",
                text: &user,
            },
        ])
        .unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, LoadError::OptionLikeKey { file, .. } if file == "user.toml")),
            "{seg}"
        );
    }
    // A `runs_code` row may be option-like only as a single option spelling.
    let code = row("\"rm\", \"-rf\"", "runs_code = true");
    assert!(
        errors(&format!("{rm}{code}"))
            .iter()
            .any(|e| matches!(e, LoadError::OptionLikeKey { .. }))
    );
    let flag_f = row("\"rm\"", "[[row.opt]]\nshort = \"f\"\n");
    let rm_f = row("\"rm\", \"-f\"", "runs_code = true");
    assert!(
        errors(&format!("{flag_f}{rm_f}"))
            .iter()
            .any(|e| matches!(e, LoadError::ParentOptNotCode { .. }))
    );
    let py = row(
        "\"pylang\"",
        "[[row.opt]]\nshort = \"c\"\nvalue = { takes = \"code\" }\n",
    );
    let py_c = row("\"pylang\", \"-c\"", "runs_code = true");
    assert!(load_one(&format!("{py}{py_c}")).is_ok());
    // Rules: rejected unless the key is that of a `runs_code` row.
    let bad_rule = "[[rule]]\nid = \"r\"\nkey = [\"rm\", \"-rf\"]\noutcome = \"ask\"\n";
    assert!(
        errors(&format!("{rm}{bad_rule}"))
            .iter()
            .any(|e| matches!(e, LoadError::OptionLikeKey { .. }))
    );
    let py_rule = "[[rule]]\nid = \"r\"\nkey = [\"pylang\", \"-c\"]\noutcome = \"ask\"\n";
    assert!(load_one(&format!("{py}{py_c}{py_rule}")).is_ok());
}

#[test]
fn rule_with_only_a_key_hits_every_command_under_it() {
    // What `[[rule]] key = ["rm"] outcome = "ask"` does: no opts and no
    // targets means it hits unconditionally, so it can distrust a row.
    let l = loaded(&format!(
        "{}[[rule]]\nid = \"distrust\"\nkey = [\"rm\"]\noutcome = \"ask\"\n",
        row("\"rm\"", "rest = \"path\"\n[[row.opt]]\nshort = \"f\"\n")
    ));
    assert_eq!(decide(&l, "rm x"), Decision::Ask);
    assert_eq!(decide(&l, "rm -f x"), Decision::Ask);
    assert_eq!(decide(&l, "rm"), Decision::Ask);
}

fn run_check(args: &[&std::path::Path]) -> Option<i32> {
    let out = Command::new(env!("CARGO_BIN_EXE_shguard"))
        .arg("check")
        .args(args)
        .output();
    match out {
        Ok(o) => o.status.code(),
        Err(e) => panic!("cannot run shguard: {e}"),
    }
}

#[test]
fn check_subcommand_status() {
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.toml");
    std::fs::write(&ok, row("\"ls\"", "")).unwrap();
    let dup = dir.path().join("dup.toml");
    std::fs::write(&dup, format!("{}{}", row("\"ls\"", ""), row("\"ls\"", ""))).unwrap();
    assert_eq!(run_check(&[&ok]), Some(0));
    assert_eq!(run_check(&[&dup]), Some(1));
    assert_eq!(run_check(&[&dir.path().join("missing.toml")]), Some(1));
    // `check` with no files, and the bare binary, are covered in
    // `hook_contract.rs`.
}

fn run_check_config(args: &[&std::path::Path], home: &std::path::Path) -> Option<i32> {
    let out = Command::new(env!("CARGO_BIN_EXE_shguard"))
        .args(["check", "--config"])
        .args(args)
        .env("HOME", home)
        .env_remove("SHGUARD_CONFIG")
        .output();
    match out {
        Ok(o) => o.status.code(),
        Err(e) => panic!("cannot run shguard: {e}"),
    }
}

#[test]
fn check_config_loads_like_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.toml");
    std::fs::write(
        &ok,
        "ask_outcome = \"ask\"\n[[rule]]\nid = \"distrust\"\nkey = [\"rm\"]\noutcome = \"ask\"\n",
    )
    .unwrap();
    let dup = dir.path().join("dup.toml");
    std::fs::write(&dup, row("\"ls\"", "")).unwrap();
    assert_eq!(run_check_config(&[&ok], dir.path()), Some(0));
    assert_eq!(run_check_config(&[&dup], dir.path()), Some(1));
    // The catalog mode does not accept `ask_outcome`.
    assert_eq!(run_check(&[&ok]), Some(1));
    // An explicit path must exist.
    assert_eq!(
        run_check_config(&[&dir.path().join("missing.toml")], dir.path()),
        Some(1)
    );
}

#[test]
fn check_config_without_a_path_uses_the_default_location() {
    let home = tempfile::tempdir().unwrap();
    // No file at the default path: embedded catalog only, as in the hook.
    assert_eq!(run_check_config(&[], home.path()), Some(0));
    let config_dir = home.path().join(".config").join("shguard");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("config.toml");
    std::fs::write(&config, row("\"ls\"", "")).unwrap();
    assert_eq!(run_check_config(&[], home.path()), Some(1));
    std::fs::write(&config, "ask_outcome = \"ask\"\n").unwrap();
    assert_eq!(run_check_config(&[], home.path()), Some(0));
}

/// Runs `shguard <args>` with `HOME` and `SHGUARD_CONFIG` set as given
/// (`None` removes the variable).
fn run_with_env(
    args: &[&std::ffi::OsStr],
    home: Option<&std::path::Path>,
    config: Option<&str>,
) -> Option<i32> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.args(args);
    match home {
        Some(h) => cmd.env("HOME", h),
        None => cmd.env_remove("HOME"),
    };
    match config {
        Some(c) => cmd.env("SHGUARD_CONFIG", c),
        None => cmd.env_remove("SHGUARD_CONFIG"),
    };
    match cmd.output() {
        Ok(o) => o.status.code(),
        Err(e) => panic!("cannot run shguard: {e}"),
    }
}

#[test]
fn check_usage_and_location_edge_cases() {
    use std::ffi::OsStr;
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.toml");
    std::fs::write(&ok, "ask_outcome = \"ask\"\n").unwrap();
    let home = Some(dir.path());
    let check = OsStr::new("check");
    let flag = OsStr::new("--config");
    // An option-like first argument is not a catalog path.
    assert_eq!(
        run_with_env(&[check, OsStr::new("--config=x")], home, None),
        Some(2)
    );
    // A relative SHGUARD_CONFIG fails the default-location form.
    assert_eq!(
        run_with_env(&[check, flag], home, Some("rel.toml")),
        Some(1)
    );
    // No HOME and no SHGUARD_CONFIG: embedded catalog only.
    assert_eq!(run_with_env(&[check, flag], None, None), Some(0));
    // More than one path is misuse.
    assert_eq!(
        run_with_env(&[check, flag, ok.as_os_str(), ok.as_os_str()], home, None),
        Some(2)
    );
    // An explicit path does not look at SHGUARD_CONFIG.
    assert_eq!(
        run_with_env(&[check, flag, ok.as_os_str()], home, Some("rel.toml")),
        Some(0)
    );
}

/// #1112: rule reasons and hints.
#[test]
fn reason_and_hint_texts_are_checked() {
    let rm = row("\"rm\"", "rest = \"path\"");
    let ok = format!(
        "{rm}{}[[hint]]\nkey = [\"find\"]\ntext = \"use fd\"\n",
        rule("reason = \"rm -r of / is never wanted\"")
    );
    let l = loaded(&ok);
    assert_eq!(
        l.rule_reasons
            .iter()
            .map(|r| r.as_ref().map(GuidanceText::as_str))
            .collect::<Vec<_>>(),
        vec![Some("rm -r of / is never wanted")]
    );
    assert_eq!(l.hints.len(), 1);
    assert_eq!(
        loaded(&format!("{rm}{}", rule(""))).rule_reasons,
        vec![None]
    );
    let long = "x".repeat(301);
    for bad in [
        "",
        "   ",
        "two\\nlines",
        "tab\\there",
        "bidi \\u202e txt",
        "line \\u2028 sep",
        "zero \\u200b width",
        "bom \\ufeff",
        "arabic mark \\u061c",
        "tag \\U000e0041",
        "selector \\ufe0f",
        "soft \\u00ad hyphen",
        "\\u3164",
        "word joiner \\u206a",
        long.as_str(),
    ] {
        let text = format!("{rm}{}", rule(&format!("reason = \"{bad}\"")));
        assert!(
            errors(&text)
                .iter()
                .any(|e| matches!(e, LoadError::BadText { .. })),
            "reason {bad:?}"
        );
        let hint = format!("[[hint]]\nkey = [\"find\"]\ntext = \"{bad}\"\n");
        assert!(
            errors(&hint)
                .iter()
                .any(|e| matches!(e, LoadError::BadText { .. })),
            "hint {bad:?}"
        );
    }
    assert!(
        load_one(&format!(
            "{rm}{}",
            rule(&format!("reason = \"{}\"", "x".repeat(300)))
        ))
        .is_ok()
    );
    for key in [
        "[]",
        "[\"\"]",
        "[\"git\", \"-c\"]",
        "[\"+x\"]",
        "[\"a b\"]",
        "[\"a\\u200bb\"]",
    ] {
        let hint = format!("[[hint]]\nkey = {key}\ntext = \"t\"\n");
        assert!(
            errors(&hint)
                .iter()
                .any(|e| matches!(e, LoadError::BadHintKey { .. })),
            "{key}"
        );
    }
    let dup =
        "[[hint]]\nkey = [\"find\"]\ntext = \"a\"\n[[hint]]\nkey = [\"find\"]\ntext = \"b\"\n";
    assert!(
        errors(dup)
            .iter()
            .any(|e| matches!(e, LoadError::DuplicateHint { .. }))
    );
    // A hint needs no row, and unknown fields are refused.
    assert!(load_one("[[hint]]\nkey = [\"find\"]\ntext = \"t\"\n").is_ok());
    assert!(matches!(
        errors("[[hint]]\nkey = [\"find\"]\ntext = \"t\"\nbogus = 1\n")[0],
        LoadError::Toml { .. }
    ));
}

/// The "longer than N bytes" message names the real cap.
#[test]
fn the_text_cap_message_names_the_cap() {
    let long = "x".repeat(shguard::catalog::TEXT_CAP + 1);
    let rm = row("\"rm\"", "rest = \"path\"");
    let errs = errors(&format!("{rm}{}", rule(&format!("reason = \"{long}\""))));
    assert!(errs.iter().any(|e| matches!(
        e,
        LoadError::BadText { why, .. } if why.contains(&shguard::catalog::TEXT_CAP.to_string())
    )));
}

/// Pins presence only: every embedded rule explains itself.
#[test]
fn every_embedded_rule_has_a_reason() {
    let loaded = load(shguard::catalog::EMBEDDED).expect("embedded catalog loads");
    assert!(!loaded.rule_reasons.is_empty());
    assert!(loaded.rule_reasons.iter().all(Option::is_some));
}

/// A user hint replaces the embedded hint with the same key; two hints of
/// one origin with the same key stay an error.
#[test]
fn a_user_hint_replaces_an_embedded_one() {
    let user = "[[hint]]\nkey = [\"find\"]\ntext = \"mine\"\n";
    let mut sources = shguard::catalog::EMBEDDED.to_vec();
    sources.push(Source {
        origin: Origin::User,
        name: "user.toml",
        text: user,
    });
    let l = load(&sources).expect("loads");
    let key = vec![b"find".to_vec()];
    let found: Vec<_> = l.hints.iter().filter(|h| h.key == key).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text.as_str(), "mine");
    // Two user files with the same key are still a duplicate.
    sources.push(Source {
        origin: Origin::User,
        name: "user2.toml",
        text: user,
    });
    let errs = load(&sources).expect_err("duplicate");
    assert!(
        errs.iter()
            .any(|e| matches!(e, LoadError::DuplicateHint { .. }))
    );
    // So is one file with the key twice.
    let twice = format!("{user}{user}");
    assert!(
        errors(&twice)
            .iter()
            .any(|e| matches!(e, LoadError::DuplicateHint { .. }))
    );
}

#[test]
fn rule_ids_use_a_plain_charset() {
    let rm = row("\"rm\"", "rest = \"path\"");
    for id in ["x y", "x\\u202ey", "x\\ny", "x/y"] {
        let text = format!("{rm}[[rule]]\nid = \"{id}\"\nkey = [\"rm\"]\noutcome = \"block\"\n");
        assert!(
            errors(&text)
                .iter()
                .any(|e| matches!(e, LoadError::BadRuleId { .. })),
            "{id}"
        );
    }
    let ok =
        format!("{rm}[[rule]]\nid = \"dotfiles-a.b_C9\"\nkey = [\"rm\"]\noutcome = \"block\"\n");
    assert!(load_one(&ok).is_ok());
}

/// The origin is typed: a user file named like an embedded one still
/// replaces the embedded hint, and is not mistaken for embedded.
#[test]
fn a_user_source_named_embedded_still_replaces_the_embedded_hint() {
    let mut sources = shguard::catalog::EMBEDDED.to_vec();
    sources.push(Source {
        origin: Origin::User,
        name: "embedded:x.toml",
        text: "[[hint]]\nkey = [\"find\"]\ntext = \"mine\"\n",
    });
    let l = load(&sources).expect("no DuplicateHint");
    let key = vec![b"find".to_vec()];
    let found: Vec<_> = l.hints.iter().filter(|h| h.key == key).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text.as_str(), "mine");
}
