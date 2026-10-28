//! Oracle 2: `shfmt -ln bash --to-json` (mvdan/sh 3.13.1), input on stdin.
//!
//! The numeric `Op` codes are mvdan/sh's `syntax.BinCmdOperator` and
//! `syntax.RedirOperator` values. They were found by running the pinned
//! shfmt on fixtures and reading the `Op` field of the JSON: `a && b` gives
//! 11, `a || b` 12, `a | b` 13 (and `a |& b` 14), `a >f` 63 (`a >>f` is 64)
//! and `a 2>&1` 68. Any other code is a disagreement.

use super::{
    AndOrS, CPart, Conn, Shape, SimpleS, canon, corpus, fd_digits, is_name, run, unescape_double,
    unescape_unquoted,
};
use serde_json::Value;
use shguard_kernel::ast::Redir;

/// `a && b`
const OP_AND: u64 = 11;
/// `a || b`
const OP_OR: u64 = 12;
/// `a | b`
const OP_PIPE: u64 = 13;
/// `>file`
const OP_REDIR_OUT: u64 = 63;
/// `>&N`
const OP_DUP_OUT: u64 = 68;

fn str_field<'a>(node: &'a Value, key: &str) -> Option<&'a str> {
    node.get(key).and_then(Value::as_str)
}

/// Rejects keys outside `allowed`, so a field that carries meaning we do not
/// map (an expansion operator, a flag) cannot be silently ignored.
fn only_keys(node: &Value, allowed: &[&str], what: &str) -> Result<(), String> {
    let object = node
        .as_object()
        .ok_or_else(|| format!("{what} is not an object"))?;
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!("{what} has unexpected field {key:?}")),
        None => Ok(()),
    }
}

fn is_true(node: &Value, key: &str) -> bool {
    node.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn param_exp(node: &Value) -> Result<CPart, String> {
    only_keys(
        node,
        &["Type", "Pos", "End", "Dollar", "Rbrace", "Short", "Param"],
        "ParamExp",
    )?;
    let param = node.get("Param").ok_or("ParamExp without Param")?;
    only_keys(
        param,
        &["Pos", "End", "ValuePos", "ValueEnd", "Value"],
        "Param",
    )?;
    let name = str_field(param, "Value").ok_or("Param without Value")?;
    if !is_name(name.as_bytes()) {
        return Err(format!("parameter {name:?} is not a plain variable name"));
    }
    Ok(CPart::Var(name.as_bytes().to_vec()))
}

fn double_quoted(node: &Value, out: &mut Vec<CPart>) -> Result<(), String> {
    only_keys(
        node,
        &["Type", "Pos", "End", "Left", "Right", "Dollar", "Parts"],
        "DblQuoted",
    )?;
    let parts = node.get("Parts").and_then(Value::as_array);
    for part in parts.map_or(&[][..], Vec::as_slice) {
        match str_field(part, "Type") {
            Some("Lit") => {
                let raw = str_field(part, "Value").ok_or("Lit without Value")?;
                out.push(CPart::Lit(unescape_double(raw.as_bytes())));
            }
            Some("ParamExp") => out.push(param_exp(part)?),
            Some(other) => return Err(format!("unmappable node {other} in double quotes")),
            None => return Err("node without Type in double quotes".to_string()),
        }
    }
    Ok(())
}

/// An unquoted literal. mvdan/sh keeps a tilde in the literal, so a leading
/// `~` followed by the end of the word or by `/` becomes `Tilde` here.
fn unquoted_lit(raw: &str, first: bool, last: bool, out: &mut Vec<CPart>) {
    let bytes = raw.as_bytes();
    if first && let Some(rest) = bytes.strip_prefix(b"~") {
        let ends = rest.is_empty() && last;
        if ends || rest.first() == Some(&b'/') {
            out.push(CPart::Tilde);
            out.push(CPart::Lit(unescape_unquoted(rest)));
            return;
        }
    }
    out.push(CPart::Lit(unescape_unquoted(bytes)));
}

fn word(node: &Value) -> Result<Vec<CPart>, String> {
    only_keys(node, &["Pos", "End", "Parts"], "Word")?;
    let parts = node
        .get("Parts")
        .and_then(Value::as_array)
        .ok_or("Word without Parts")?;
    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let (first, last) = (i == 0, i + 1 == parts.len());
        match str_field(part, "Type") {
            Some("Lit") => {
                let raw = str_field(part, "Value").ok_or("Lit without Value")?;
                unquoted_lit(raw, first, last, &mut out);
            }
            Some("SglQuoted") => {
                if is_true(part, "Dollar") {
                    return Err("$'...' quoting".to_string());
                }
                only_keys(
                    part,
                    &["Type", "Pos", "End", "Left", "Right", "Dollar", "Value"],
                    "SglQuoted",
                )?;
                // shfmt omits `Value` for `''`.
                let value = str_field(part, "Value").unwrap_or("");
                out.push(CPart::Lit(value.as_bytes().to_vec()));
            }
            Some("DblQuoted") => {
                if is_true(part, "Dollar") {
                    return Err("$\"...\" quoting".to_string());
                }
                double_quoted(part, &mut out)?;
            }
            Some("ParamExp") => return Err("unquoted parameter expansion".to_string()),
            Some(other) => return Err(format!("unmappable word part {other}")),
            None => return Err("word part without Type".to_string()),
        }
    }
    Ok(canon(out))
}

fn redirect(node: &Value) -> Result<Redir, String> {
    only_keys(
        node,
        &["Pos", "End", "Op", "OpPos", "N", "Word"],
        "Redirect",
    )?;
    let from = match node.get("N") {
        Some(n) => {
            only_keys(n, &["Pos", "End", "ValuePos", "ValueEnd", "Value"], "N")?;
            str_field(n, "Value")
                .and_then(|s| fd_digits(s.as_bytes()))
                .ok_or("redirect N is not a descriptor number")?
        }
        None => 1,
    };
    let target = word(node.get("Word").ok_or("redirect without Word")?)?;
    match node.get("Op").and_then(Value::as_u64) {
        Some(OP_DUP_OUT) => match target.as_slice() {
            [CPart::Lit(digits)] => {
                let to = fd_digits(digits).ok_or("duplicate target is not a number")?;
                Ok(Redir::Dup { from, to })
            }
            _ => Err(format!("unmappable duplicate target {target:?}")),
        },
        Some(OP_REDIR_OUT) if target == [CPart::Lit(b"/dev/null".to_vec())] => {
            Ok(Redir::DevNull { fd: from })
        }
        op => Err(format!("unmappable redirect Op {op:?} to {target:?}")),
    }
}

fn check_plain_stmt(stmt: &Value) -> Result<(), String> {
    only_keys(
        stmt,
        &[
            "Cmd",
            "Redirs",
            "Comments",
            "Pos",
            "End",
            "Position",
            "Semicolon",
            "Negated",
            "Background",
            "Coprocess",
        ],
        "Stmt",
    )?;
    for flag in ["Negated", "Background", "Coprocess"] {
        if is_true(stmt, flag) {
            return Err(format!("statement is {flag}"));
        }
    }
    Ok(())
}

fn cmd_of(stmt: &Value) -> Result<&Value, String> {
    stmt.get("Cmd")
        .ok_or_else(|| "statement without Cmd".to_string())
}

/// The words of a `DeclClause` (`export`, `declare`, `local`, `readonly`,
/// `typeset`): the builtin name, then each argument. mvdan/sh parses the
/// arguments as assignments; inside the accepted subset the argv bash builds
/// equals the plain words, so each one maps back to its text.
/// Whether an unquoted `~` follows an unquoted `=` or `:` in an
/// assignment-shaped word (`NAME=` or `NAME+=` at the start), where bash
/// expands it outside POSIX mode. Written here, not borrowed from the lexer,
/// so the oracle stays independent of it.
fn assignment_tilde(parts: &[Value]) -> bool {
    let Some(first) = parts.first() else {
        return false;
    };
    if str_field(first, "Type") != Some("Lit") {
        return false;
    }
    let raw = str_field(first, "Value").unwrap_or("").as_bytes();
    let name_len = raw
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(raw.len());
    let rest = raw.get(name_len..).unwrap_or(&[]);
    let after_name = rest.strip_prefix(b"+").unwrap_or(rest);
    if !is_name(raw.get(..name_len).unwrap_or(&[])) || !after_name.starts_with(b"=") {
        return false;
    }
    // After the first `=`, `sep` says the previous byte was an unescaped `=`
    // or `:`; a quoted part resets it.
    let mut sep = false;
    let mut started = false;
    for part in parts {
        if str_field(part, "Type") != Some("Lit") {
            sep = false;
            continue;
        }
        let bytes = str_field(part, "Value").unwrap_or("").as_bytes();
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            if !started {
                // Skip to just after the first `=`.
                if b == b'=' {
                    started = true;
                    sep = true;
                }
                i += 1;
                continue;
            }
            match b {
                b'\\' => {
                    sep = false;
                    i += 2;
                    continue;
                }
                b'~' if sep => return true,
                b'=' | b':' => sep = true,
                _ => sep = false,
            }
            i += 1;
        }
    }
    false
}

fn decl_words(cmd: &Value) -> Result<Vec<Vec<CPart>>, String> {
    only_keys(
        cmd,
        &["Type", "Pos", "End", "Variant", "Args"],
        "DeclClause",
    )?;
    let variant = cmd.get("Variant").ok_or("DeclClause without Variant")?;
    only_keys(
        variant,
        &["Pos", "End", "ValuePos", "ValueEnd", "Value"],
        "Variant",
    )?;
    let builtin = str_field(variant, "Value").ok_or("Variant without Value")?;
    let mut words = vec![canon(vec![CPart::Lit(builtin.as_bytes().to_vec())])];
    let args = cmd.get("Args").and_then(Value::as_array);
    for arg in args.map_or(&[][..], Vec::as_slice) {
        only_keys(
            arg,
            &["Pos", "End", "Append", "Naked", "Name", "Value"],
            "Assign",
        )?;
        let name = match arg.get("Name") {
            Some(n) => {
                only_keys(n, &["Pos", "End", "ValuePos", "ValueEnd", "Value"], "Name")?;
                Some(str_field(n, "Value").ok_or("Name without Value")?)
            }
            None => None,
        };
        let value = arg.get("Value").map(word).transpose()?;
        if is_true(arg, "Naked") {
            // A flag or a bare name: exactly one of Value and Name.
            match (name, value) {
                (None, Some(value)) => words.push(value),
                (Some(name), None) => {
                    words.push(canon(vec![CPart::Lit(name.as_bytes().to_vec())]));
                }
                _ => return Err(format!("naked assign with unexpected fields: {arg}")),
            }
        } else {
            let name = name.ok_or("assign without Name")?;
            let op = if is_true(arg, "Append") { "+=" } else { "=" };
            let mut parts = vec![CPart::Lit(format!("{name}{op}").into_bytes())];
            parts.extend(value.unwrap_or_default());
            words.push(canon(parts));
        }
    }
    Ok(words)
}

fn simple(stmt: &Value) -> Result<SimpleS, String> {
    let cmd = cmd_of(stmt)?;
    let words = match str_field(cmd, "Type") {
        Some("CallExpr") => {
            only_keys(cmd, &["Type", "Pos", "End", "Args", "Assigns"], "CallExpr")?;
            if cmd
                .get("Assigns")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
            {
                return Err("assignment".to_string());
            }
            let args = cmd
                .get("Args")
                .and_then(Value::as_array)
                .ok_or("CallExpr without Args")?;
            for arg in args {
                let parts = arg.get("Parts").and_then(Value::as_array);
                if assignment_tilde(parts.map_or(&[][..], Vec::as_slice)) {
                    return Err("tilde expanded inside an assignment-shaped word".to_string());
                }
            }
            args.iter().map(word).collect::<Result<Vec<_>, _>>()?
        }
        Some("DeclClause") => decl_words(cmd)?,
        other => return Err(format!("unmappable command {other:?}")),
    };
    let redirs = stmt
        .get("Redirs")
        .and_then(Value::as_array)
        .map_or(Ok(Vec::new()), |list| {
            list.iter().map(redirect).collect::<Result<Vec<_>, _>>()
        })?;
    Ok(SimpleS { words, redirs })
}

fn binary(stmt: &Value) -> Result<Option<(u64, &Value, &Value)>, String> {
    let cmd = cmd_of(stmt)?;
    if str_field(cmd, "Type") != Some("BinaryCmd") {
        return Ok(None);
    }
    only_keys(
        cmd,
        &["Type", "Pos", "End", "OpPos", "Op", "X", "Y"],
        "BinaryCmd",
    )?;
    if stmt
        .get("Redirs")
        .and_then(Value::as_array)
        .is_some_and(|r| !r.is_empty())
    {
        return Err("redirect on a binary command".to_string());
    }
    let op = cmd
        .get("Op")
        .and_then(Value::as_u64)
        .ok_or("BinaryCmd without Op")?;
    let x = cmd.get("X").ok_or("BinaryCmd without X")?;
    let y = cmd.get("Y").ok_or("BinaryCmd without Y")?;
    Ok(Some((op, x, y)))
}

/// The commands of a pipeline tree, left to right.
fn pipeline(stmt: &Value, out: &mut Vec<SimpleS>) -> Result<(), String> {
    check_plain_stmt(stmt)?;
    match binary(stmt)? {
        Some((OP_PIPE, x, y)) => {
            pipeline(x, out)?;
            pipeline(y, out)
        }
        Some((op, ..)) => Err(format!("unexpected Op {op} inside a pipeline")),
        None => {
            out.push(simple(stmt)?);
            Ok(())
        }
    }
}

/// The pipelines of an and-or tree, left to right, each with the connector
/// that precedes it (`None` for the first).
fn and_or(stmt: &Value, out: &mut Vec<(Option<Conn>, Vec<SimpleS>)>) -> Result<(), String> {
    check_plain_stmt(stmt)?;
    match binary(stmt)? {
        Some((op @ (OP_AND | OP_OR), x, y)) => {
            and_or(x, out)?;
            let at = out.len();
            and_or(y, out)?;
            let conn = if op == OP_AND { Conn::And } else { Conn::Or };
            let joined = out.get_mut(at).ok_or("empty right operand")?;
            joined.0 = Some(conn);
            Ok(())
        }
        Some((OP_PIPE, ..)) | None => {
            let mut cmds = Vec::new();
            pipeline(stmt, &mut cmds)?;
            out.push((None, cmds));
            Ok(())
        }
        Some((op, ..)) => Err(format!("unmappable BinaryCmd Op {op}")),
    }
}

fn shape(input: &str) -> Result<Shape, String> {
    let output = run("shfmt", &["-ln", "bash", "--to-json"], input);
    if !output.status.success() {
        return Err(format!(
            "shfmt exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let file: Value = serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
    let stmts = file.get("Stmts").and_then(Value::as_array);
    let mut script = Vec::new();
    for stmt in stmts.map_or(&[][..], Vec::as_slice) {
        let mut chain = Vec::new();
        and_or(stmt, &mut chain)?;
        let mut chain = chain.into_iter();
        let (_, first) = chain.next().ok_or("empty statement")?;
        script.push(AndOrS {
            first,
            rest: chain
                .map(|(conn, p)| conn.map(|c| (c, p)).ok_or("missing connector"))
                .collect::<Result<_, _>>()?,
        });
    }
    Ok(script)
}

#[test]
#[ignore = "needs shfmt and bash 5 (nix develop)"]
fn shfmt_reads_accepted_inputs_as_we_do() {
    corpus().check("shfmt", shape);
}
