//! Issues #578/#580: modified parameter expansions (`${x%p}`, `${x:-w}`,
//! `${x:o:l}`, `${PIPESTATUS[n]}`, ...) are opaque words, never resolved
//! literals. Substitutions inside their operands are still analyzed, and a
//! modified expansion in command position stays at least Ask.

use shguard::verdict::Decision;

fn check(cases: &[(&str, Decision)]) {
    for (command, expected) in cases {
        assert_eq!(
            shguard::analyze(command).decision(),
            *expected,
            "command: {command}"
        );
    }
}

#[test]
fn pipestatus_literal_index_is_an_opaque_argument() {
    check(&[
        ("echo \"exit=$?\"", Decision::Allow),
        ("echo \"exit=${PIPESTATUS[0]}\"", Decision::Allow),
        ("echo \"exit=${pipestatus[1]}\"", Decision::Allow),
        ("echo ${PIPESTATUS[@]}", Decision::Allow),
        ("echo \"${PIPESTATUS[@]}\"", Decision::Allow),
        ("echo ${PIPESTATUS[*]}", Decision::Allow),
        (
            "cargo clippy 2>&1 | tail -5; echo \"exit=${PIPESTATUS[0]}\"",
            Decision::Allow,
        ),
    ]);
}

#[test]
fn pipestatus_never_resolves_in_command_position() {
    check(&[
        ("${PIPESTATUS[0]} foo", Decision::Ask),
        ("PIPESTATUS=rm; ${PIPESTATUS[0]} -rf ~", Decision::Ask),
        ("echo ${PIPESTATUS[$i]}", Decision::Ask),
        ("echo ${arr[0]}", Decision::Ask),
        ("echo ${arr[$(rm -rf ~)]}", Decision::Ask),
        ("echo ${PIPESTATUS[$(rm -rf ~)]}", Decision::Ask),
        ("echo ${PIPESTATUS[0]%x}", Decision::Ask),
        ("echo ${!x}", Decision::Ask),
    ]);
}

#[test]
fn non_assigning_forms_are_allowed_as_arguments() {
    check(&[
        ("for f in *.ts; do echo \"${f%.ts}\"; done", Decision::Allow),
        ("echo ${TMPDIR:-/tmp}", Decision::Allow),
        ("echo ${x-d}", Decision::Allow),
        ("echo ${x:+w}", Decision::Allow),
        ("echo ${x%.ts}", Decision::Allow),
        ("echo ${x%%.ts}", Decision::Allow),
        ("echo ${x#*/}", Decision::Allow),
        ("echo ${x##*/}", Decision::Allow),
        ("echo ${x:0:3}", Decision::Allow),
        ("echo ${x:o:l}", Decision::Allow),
        ("echo \"${@:2}\"", Decision::Allow),
        ("echo ${#x}", Decision::Allow),
        ("echo ${x/a/b}", Decision::Allow),
        ("echo ${x^^}", Decision::Allow),
    ]);
}

#[test]
fn substitutions_inside_operands_are_still_analyzed() {
    check(&[
        ("echo ${x:-$(rm -rf ~)}", Decision::Block),
        ("echo \"${x:-$(rm -rf ~)}\"", Decision::Block),
        ("echo ${x%$(rm -rf ~)}", Decision::Block),
        ("echo ${x:-`rm -rf ~`}", Decision::Block),
        ("${x:-$(rm -rf ~)} foo", Decision::Block),
        ("echo ${x:-${y:-$(rm -rf ~)}}", Decision::Block),
        ("echo ${x/$(rm -rf ~)/b}", Decision::Block),
    ]);
}

#[test]
fn modified_expansion_in_command_position_is_at_least_ask() {
    check(&[
        ("${B:-rm} -rf ~", Decision::Ask),
        ("B=rm; ${B%x} -rf ~", Decision::Ask),
        ("B=${y:-rm}; $B -rf ~", Decision::Ask),
        ("rm${IFS%x}-rf${IFS%x}/", Decision::Ask),
        ("echo ${IFS:-x}", Decision::Ask),
        ("echo ${x:-$IFS}", Decision::Ask),
    ]);
}

#[test]
fn assigning_indirect_and_exotic_forms_stay_unsupported() {
    check(&[
        ("echo ${x:=w}", Decision::Ask),
        ("echo ${x=w}", Decision::Ask),
        (": ${B:=rm}; $B -rf ~", Decision::Ask),
        ("echo ${x:-<(rm -rf ~)}", Decision::Ask),
        ("echo ${x:$(cmd):3}", Decision::Ask),
        ("echo ${x@Q}", Decision::Ask),
        ("echo ${!x%y}", Decision::Ask),
        ("echo ${x:-$(", Decision::Ask),
    ]);
}

#[test]
fn quotes_inside_double_quoted_operand_cannot_hide_a_substitution() {
    check(&[
        ("echo \"${x:-'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x:-$'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x%'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x/a/'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x//a/'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x^^'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x:?'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x:+'$(rm -rf ~)'}\"", Decision::Block),
        ("echo \"${x:-'`rm -rf ~`'}\"", Decision::Block),
        ("echo \"${x:-${y:-'$(rm -rf ~)'}}\"", Decision::Block),
        ("\"${x:-'$(rm -rf ~)'}\" foo", Decision::Block),
        ("B=\"${x:-'$(rm -rf ~)'}\"", Decision::Block),
        ("echo hi > \"${x:-'$(rm -rf ~)'}\"", Decision::Block),
    ]);
}

#[test]
fn quotes_in_unquoted_operand_are_still_honoured() {
    check(&[
        ("echo ${x:-'$(rm -rf ~)'}", Decision::Allow),
        ("echo \"${x:-plain}\"", Decision::Allow),
    ]);
}

#[test]
fn issue_580_pins() {
    check(&[
        ("cd \"${HOME:-/tmp}\"", Decision::Allow),
        // Stays Ask (not Block) until command-position resolution of
        // `%`/`#` forms is added as a follow-up; never weaker than main.
        ("B=rm; ${B%x} -rf ~", Decision::Ask),
    ]);
}
