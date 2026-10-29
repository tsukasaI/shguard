//! Tests of the catalog loader: one rejection per check, the shape of a valid
//! load, end-to-end decisions, and the `check` subcommand.

use std::process::Command;

use shguard::catalog::{LoadError, Loaded, Source, load};
use shguard_kernel::ast::{Opaque, Part};
use shguard_kernel::catalog::{
    Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role, Row,
    RunsCode, ShortName,
};
use shguard_kernel::decision::Decision;
use shguard_kernel::rule::{OptAlts, Outcome, Pat, PatKind, Rule, RuleId, Scope};

fn load_one(text: &str) -> Result<Loaded, Vec<LoadError>> {
    load(&[Source {
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

fn decision(l: &Loaded, cmd: &str) -> Decision {
    let Ok(script) = shguard_syntax::parse(cmd.as_bytes()) else {
        panic!("`{cmd}` is outside the subset");
    };
    shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
}

#[test]
fn toml_error() {
    assert!(matches!(errors("[[row]\n")[0], LoadError::Toml { .. }));
    assert!(matches!(errors("bogus = 1\n")[0], LoadError::Toml { .. }));
    let bad = row("\"ls\"", "").replace("permute", "sideways");
    assert!(matches!(errors(&bad)[0], LoadError::Toml { .. }));
}

#[test]
fn toml_error_in_one_file_does_not_hide_others() {
    let dup = row("\"ls\"", "");
    let both = format!("{dup}{dup}");
    let errs = load(&[
        Source {
            name: "a.toml",
            text: "[[row]\n",
        },
        Source {
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
            name: "a.toml",
            text: &t,
        },
        Source {
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
    for head in ["tar", "ps", "ar", "find"] {
        let t = row(&format!("\"{head}\""), "");
        assert!(
            matches!(errors(&t)[0], LoadError::DenylistedHead { .. }),
            "{head}"
        );
        let ok = row(&format!("\"{head}\""), "runs_code = true");
        assert!(load_one(&ok).is_ok(), "{head}");
    }
}

#[test]
fn parent_option_spelling_child_must_take_code() {
    let child = row("\"python\", \"-c\"", "runs_code = true");
    let parent = |value: &str| {
        row(
            "\"python\"",
            &format!("[[row.opt]]\nshort = \"c\"\nvalue = {value}\n"),
        )
    };
    for v in [
        "\"flag\"",
        "{ takes = \"inert\" }",
        "{ optional = \"path\" }",
    ] {
        let errs = errors(&format!("{}{child}", parent(v)));
        assert!(
            errs.iter()
                .any(|e| matches!(e, LoadError::ParentOptNotCode { .. })),
            "{v}"
        );
    }
    assert!(load_one(&format!("{}{child}", parent("{ takes = \"code\" }"))).is_ok());
    let long_child = row("\"python\", \"--command\"", "runs_code = true");
    let long_parent = row("\"python\"", "[[row.opt]]\nlong = \"command\"\n");
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
    let t = format!("{rm}{}", rule("opts = [[\"--recursive\"]]"));
    assert!(load_one(&t).is_ok());
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
fn all_errors_are_collected() {
    let t = format!("{}{}", row("\"git\", \"status\"", ""), rule(""));
    assert!(errors(&t).len() >= 2);
}

#[test]
fn valid_catalog_equals_hand_built() {
    let text = format!(
        r#"{}{}{}{}"#,
        row(
            "\"ls\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"l\"\n[[row.opt]]\nshort = \"n\"\nlong = \"lines\"\nvalue = { takes = \"inert\" }\n"
        ),
        "[[row]]\nkey = [\"cd\"]\nsource = \"https://example.com/cd\"\norder = \"strict\"\ndashdash = \"literal\"\nplus_words = \"operand\"\npositionals = [\"path\"]\nchanges_cwd = true\n",
        row(
            "\"rm\"",
            "[[row.opt]]\nshort = \"r\"\n[[row.opt]]\nshort = \"R\"\n[[row.opt]]\nlong = \"recursive\"\n"
        ),
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
    assert_eq!(l.catalog, Catalog::new(vec![ls, cd, rm], vec![]));
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
            "\"python\"",
            "rest = \"path\"\n[[row.opt]]\nshort = \"c\"\nvalue = { takes = \"code\" }\n"
        ),
        row("\"python\", \"-c\"", "runs_code = true"),
        row("\"tar\"", "runs_code = true"),
    );
    let l = loaded(&format!("{base}{}", date("")));
    assert_eq!(decision(&l, "ls -la"), Decision::Allow);
    assert_eq!(decision(&l, "rm -rf /"), Decision::Block);
    assert_eq!(decision(&l, "python -c x"), Decision::Ask);
    assert_eq!(decision(&l, "tar xf a"), Decision::Ask);
    assert_eq!(decision(&l, "date +%s"), Decision::Ask);
    let l = loaded(&format!("{base}{}", date("plus_words = \"operand\"")));
    assert_eq!(decision(&l, "date +%s"), Decision::Allow);
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
    assert_eq!(run_check(&[]), Some(1));
    let bare = Command::new(env!("CARGO_BIN_EXE_shguard"))
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
}
