//! The closed command catalog: per-command grammars that say how to read a
//! command's argv.
//!
//! Like the AST, values are well-formed by construction: fields are
//! `pub(crate)` and the types with an invariant are built through checked
//! constructors. Key uniqueness is not enforced here; the catalog loader
//! rejects duplicates.
//!
//! Two refinements over the plan's sketch:
//! - `Grammar::rest` is an `Option<Role>` (`None` means no operands beyond
//!   `positionals`), not a bare `Role`.
//! - An option is `Opt { name: OptName, value: OptValue }`, not
//!   `{ short, long, takes_value, value_role }`, so it always has a name and a
//!   flag cannot carry a value role.

#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// What an argument position does with its word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Role {
    /// The word is plain data.
    Inert,
    /// The word names a file system path.
    Path,
    /// The word is run as code.
    Code,
}

/// A short option name: one printable ASCII byte other than `-`.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct ShortName {
    pub(crate) byte: u8,
}

/// A short name is printable ASCII (`0x21..=0x7E`) and not `-`.
#[cfg(creusot)]
#[logic(open)]
pub fn short_name_wf(b: u8) -> bool {
    // 45 is `-`: Creusot logic has no byte literals.
    0x21u8 <= b && b <= 0x7Eu8 && b != 45u8
}

#[cfg(creusot)]
impl Invariant for ShortName {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { short_name_wf(self.byte) }
    }
}

impl ShortName {
    /// Builds a short name, or `None` when `b` is not printable ASCII or is
    /// `-`.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(s) => s.byte == b,
        None => !short_name_wf(b),
    }))]
    #[must_use]
    pub fn new(b: u8) -> Option<ShortName> {
        match b {
            b'-' => None,
            0x21..=0x7E => Some(ShortName { byte: b }),
            _ => None,
        }
    }

    /// The name's byte.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.byte))]
    #[must_use]
    pub fn byte(&self) -> u8 {
        self.byte
    }
}

/// A long option name, without the leading `--`. Never empty, never starts
/// with `-`, and never contains `=`.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct LongName {
    pub(crate) bytes: Vec<u8>,
}

/// A long name has at least one byte, does not start with `-` (that would
/// read as `---x`), and has no `=` (the first `=` splits name from value).
/// The literals are `-` (45) and `=` (61); logic has no byte literals.
#[cfg(creusot)]
#[logic(open)]
pub fn long_name_wf(bytes: Seq<u8>) -> bool {
    pearlite! {
        bytes.len() > 0 && bytes[0] != 45u8
            && forall<i> 0 <= i && i < bytes.len() ==> bytes[i] != 61u8
    }
}

#[cfg(creusot)]
impl Invariant for LongName {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { long_name_wf(self.bytes@) }
    }
}

impl LongName {
    /// Builds a long name, or `None` when `bytes` is empty, starts with `-`,
    /// or contains `=`.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(n) => n.bytes@ == bytes@,
        None => !long_name_wf(bytes@),
    }))]
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<LongName> {
        if <[_]>::is_empty(&bytes) || bytes[0] == b'-' {
            return None;
        }
        let mut i: usize = 0;
        #[cfg_attr(creusot, variant(bytes@.len() - i@))]
        #[cfg_attr(creusot, invariant(i@ <= bytes@.len()))]
        #[cfg_attr(creusot, invariant(forall<k> 0 <= k && k < i@ ==> bytes@[k] != 61u8))]
        while i < bytes.len() {
            if bytes[i] == b'=' {
                return None;
            }
            i += 1;
        }
        Some(LongName { bytes })
    }

    /// The name's bytes.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.bytes@))]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The name of an option; an option always has at least one name.
///
/// The short name lives in a [`ShortName`] (printable ASCII, not `-`) and the
/// long name in a [`LongName`] (non-empty, no leading `-`, no `=`); the enum
/// inherits their invariants. A bare `u8` or `Vec<u8>` payload would stay
/// mutable through a `&mut` pattern even with `#[non_exhaustive]` variants.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub enum OptName {
    /// Only a short name: `-v` is `Short(..)` holding `b'v'`.
    Short(ShortName),
    /// Only a long name: `--verbose` is `Long(..)`.
    Long(LongName),
    /// Both spellings: `-v` and `--verbose`.
    Both(ShortName, LongName),
}

/// Whether an option takes a value, and what the value does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum OptValue {
    /// A flag: no value.
    Flag,
    /// The option consumes a value with this role: inline (`--lines=5`,
    /// `-n5`) or, failing that, the next word.
    Takes(Role),
    /// The option has an optional value with this role, taken only inline:
    /// after `=` in a long option, or the rest of a short cluster (`-iSUF`).
    /// It never takes the next word: `--interactive x` has no value and `x`
    /// is an operand.
    Optional(Role),
}

/// How a grammar reads a word whose known bytes start with `+`, where it
/// would still read options (and after the first operand, without
/// `permute`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum PlusWords {
    /// The word is Unknown: tools such as vim and less run a `+cmd` word as
    /// a command. The choice for every tool not known to read it as data.
    Reject,
    /// The word is an ordinary operand.
    Operand,
}

/// Whether a command runs other code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum RunsCode {
    /// The command runs other code (`env`, `xargs`, `sh -c`).
    Yes,
    /// The command does not run other code.
    No,
}

/// How a command relates to the working directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Cwd {
    /// The command changes the working directory (`cd`, `pushd`).
    Changes,
    /// The command leaves the working directory alone, but what it does
    /// depends on configuration found there (`git` reads `.git/config`,
    /// which can name programs to run), so it is asked after an earlier
    /// command that changes the working directory.
    Sensitive,
    /// The command leaves the working directory alone.
    Keeps,
}

/// Whether options may follow operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Order {
    /// GNU style: options may follow operands.
    Permute,
    /// An option-looking word after the first operand is Unknown, because
    /// the real tool may still read it as an option.
    Strict,
}

/// What `--` does in a grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum DashDash {
    /// `--` ends option parsing.
    Ends,
    /// `--` is an ordinary word.
    Literal,
}

/// One option of a grammar.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Opt {
    pub(crate) name: OptName,
    pub(crate) value: OptValue,
}

impl Opt {
    /// Builds an option.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.name == name && result.value == value))]
    #[must_use]
    pub fn new(name: OptName, value: OptValue) -> Opt {
        Opt { name, value }
    }

    /// The option's name.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.name))]
    #[must_use]
    pub fn name(&self) -> &OptName {
        &self.name
    }

    /// Whether the option takes a value.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.value))]
    #[must_use]
    pub fn value(&self) -> OptValue {
        self.value
    }
}

/// How to read the argv of a command.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Grammar {
    pub(crate) opts: Vec<Opt>,
    pub(crate) positionals: Vec<Role>,
    pub(crate) rest: Option<Role>,
    pub(crate) permute: bool,
    pub(crate) dashdash: bool,
    pub(crate) plus: PlusWords,
}

impl Grammar {
    /// Builds a grammar.
    ///
    /// - `positionals`: roles of the leading operands, in order.
    /// - `rest`: the role of every operand after them; `None` means there are
    ///   none.
    /// - `order`: [`Order::Permute`] lets options follow operands (GNU
    ///   style). With [`Order::Strict`], an option-looking word after the
    ///   first operand is Unknown, because the real tool may still read it
    ///   as an option.
    /// - `dashdash`: [`DashDash::Ends`] means `--` ends option parsing.
    /// - `plus`: how a `+word` is read where options are still read, and
    ///   after the first operand with [`Order::Strict`].
    ///
    /// The two choices are stored as booleans; the accessors return the enums
    /// again.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.opts@ == opts@ && result.positionals@ == positionals@
        && result.rest == rest && result.permute == (order == Order::Permute)
        && result.dashdash == (dashdash == DashDash::Ends) && result.plus == plus))]
    #[must_use]
    pub fn new(
        opts: Vec<Opt>,
        positionals: Vec<Role>,
        rest: Option<Role>,
        order: Order,
        dashdash: DashDash,
        plus: PlusWords,
    ) -> Grammar {
        let permute = match order {
            Order::Permute => true,
            Order::Strict => false,
        };
        let dashdash = match dashdash {
            DashDash::Ends => true,
            DashDash::Literal => false,
        };
        Grammar {
            opts,
            positionals,
            rest,
            permute,
            dashdash,
            plus,
        }
    }

    /// The options.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.opts@))]
    #[must_use]
    pub fn opts(&self) -> &[Opt] {
        &self.opts
    }

    /// The roles of the leading operands.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.positionals@))]
    #[must_use]
    pub fn positionals(&self) -> &[Role] {
        &self.positionals
    }

    /// The role of the operands after the leading ones, if any are allowed.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.rest))]
    #[must_use]
    pub fn rest(&self) -> Option<Role> {
        self.rest
    }

    /// Whether options may follow operands: [`Order::Permute`] when they may.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Order::Permute => self.permute,
        Order::Strict => !self.permute,
    }))]
    #[must_use]
    pub fn permute(&self) -> Order {
        if self.permute {
            Order::Permute
        } else {
            Order::Strict
        }
    }

    /// Whether `--` ends option parsing: [`DashDash::Ends`] when it does.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        DashDash::Ends => self.dashdash,
        DashDash::Literal => !self.dashdash,
    }))]
    #[must_use]
    pub fn dashdash(&self) -> DashDash {
        if self.dashdash {
            DashDash::Ends
        } else {
            DashDash::Literal
        }
    }

    /// How a `+word` in option position is read.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.plus))]
    #[must_use]
    pub fn plus_words(&self) -> PlusWords {
        self.plus
    }
}

/// A command key is non-empty and every segment is non-empty.
#[cfg(creusot)]
#[logic(open)]
pub fn key_wf(key: Seq<Vec<u8>>) -> bool {
    pearlite! { key.len() > 0 && forall<i> 0 <= i && i < key.len() ==> key[i]@.len() > 0 }
}

/// Runtime check of [`key_wf`].
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == key_wf(key@)))]
#[must_use]
pub fn key_ok(key: &[Vec<u8>]) -> bool {
    if <[_]>::is_empty(key) {
        return false;
    }
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(key@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= key@.len()))]
    #[cfg_attr(creusot, invariant(forall<k> 0 <= k && k < i@ ==> key@[k]@.len() > 0))]
    while i < key.len() {
        if <[_]>::is_empty(&key[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// A catalog row: the grammar of one command (or subcommand) and its flags.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Row {
    pub(crate) key: Vec<Vec<u8>>,
    pub(crate) grammar: Grammar,
    pub(crate) runs_code: bool,
    pub(crate) changes_cwd: bool,
    pub(crate) cwd_sensitive: bool,
}

#[cfg(creusot)]
impl Invariant for Row {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { key_wf(self.key@) }
    }
}

impl Row {
    /// Builds a row, or `None` when `key` is empty or has an empty segment.
    ///
    /// Subcommands are flattened into the key (`["git", "status"]`).
    /// `runs_code` and `cwd` are stored as booleans; the accessors return the
    /// enums again.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(r) => r.key@ == key@ && r.grammar == grammar
            && r.runs_code == (runs_code == RunsCode::Yes)
            && r.changes_cwd == (cwd == Cwd::Changes)
            && r.cwd_sensitive == (cwd == Cwd::Sensitive),
        None => !key_wf(key@),
    }))]
    #[must_use]
    pub fn new(key: Vec<Vec<u8>>, grammar: Grammar, runs_code: RunsCode, cwd: Cwd) -> Option<Row> {
        let runs_code = match runs_code {
            RunsCode::Yes => true,
            RunsCode::No => false,
        };
        let (changes_cwd, cwd_sensitive) = match cwd {
            Cwd::Changes => (true, false),
            Cwd::Sensitive => (false, true),
            Cwd::Keeps => (false, false),
        };
        if key_ok(&key) {
            Some(Row {
                key,
                grammar,
                runs_code,
                changes_cwd,
                cwd_sensitive,
            })
        } else {
            None
        }
    }

    /// The key segments.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.key@))]
    #[must_use]
    pub fn key(&self) -> &[Vec<u8>] {
        &self.key
    }

    /// The grammar of the command's own argv.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.grammar))]
    #[must_use]
    pub fn grammar(&self) -> &Grammar {
        &self.grammar
    }

    /// Whether the command runs other code: [`RunsCode::Yes`] when it does.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        RunsCode::Yes => self.runs_code,
        RunsCode::No => !self.runs_code,
    }))]
    #[must_use]
    pub fn runs_code(&self) -> RunsCode {
        if self.runs_code {
            RunsCode::Yes
        } else {
            RunsCode::No
        }
    }

    /// How the command relates to the working directory: [`Cwd::Changes`]
    /// when it changes it, [`Cwd::Sensitive`] when its configuration is read
    /// from it.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Cwd::Changes => self.changes_cwd,
        Cwd::Sensitive => !self.changes_cwd && self.cwd_sensitive,
        Cwd::Keeps => !self.changes_cwd && !self.cwd_sensitive,
    }))]
    #[must_use]
    pub fn cwd(&self) -> Cwd {
        if self.changes_cwd {
            Cwd::Changes
        } else if self.cwd_sensitive {
            Cwd::Sensitive
        } else {
            Cwd::Keeps
        }
    }
}

/// The grammar of the words between key segments, such as `-C x` in
/// `git -C x status`.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Global {
    pub(crate) head: Vec<u8>,
    pub(crate) grammar: Grammar,
}

/// A global's head (the command it belongs to) is non-empty.
#[cfg(creusot)]
#[logic(open)]
pub fn head_wf(head: Seq<u8>) -> bool {
    head.len() > 0
}

#[cfg(creusot)]
impl Invariant for Global {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { head_wf(self.head@) }
    }
}

impl Global {
    /// Builds a global grammar, or `None` when `head` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(g) => g.head@ == head@ && g.grammar == grammar,
        None => !head_wf(head@),
    }))]
    #[must_use]
    pub fn new(head: Vec<u8>, grammar: Grammar) -> Option<Global> {
        if <[_]>::is_empty(&head) {
            None
        } else {
            Some(Global { head, grammar })
        }
    }

    /// The command name this grammar belongs to.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.head@))]
    #[must_use]
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The grammar of the words between key segments.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.grammar))]
    #[must_use]
    pub fn grammar(&self) -> &Grammar {
        &self.grammar
    }
}

/// The rows and global grammars.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Catalog {
    pub(crate) rows: Vec<Row>,
    pub(crate) globals: Vec<Global>,
}

impl Catalog {
    /// Builds a catalog. Key uniqueness is the loader's job, not the
    /// kernel's.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.rows@ == rows@ && result.globals@ == globals@))]
    #[must_use]
    pub fn new(rows: Vec<Row>, globals: Vec<Global>) -> Catalog {
        Catalog { rows, globals }
    }

    /// The rows.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.rows@))]
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The global grammars.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.globals@))]
    #[must_use]
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Catalog, Cwd, DashDash, Global, Grammar, LongName, Opt, OptName, OptValue, Order,
        PlusWords, Role, Row, RunsCode, ShortName, key_ok,
    };

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn grammar() -> Grammar {
        Grammar::new(
            Vec::new(),
            Vec::new(),
            None,
            Order::Strict,
            DashDash::Ends,
            PlusWords::Reject,
        )
    }

    fn short(b: u8) -> ShortName {
        ShortName::new(b).expect("printable, not '-'")
    }

    #[test]
    fn short_name_constructor() {
        assert_eq!(short(b'v').byte(), b'v');
        assert_eq!(short(b'!').byte(), b'!');
        assert_eq!(short(b'~').byte(), b'~');
        assert!(ShortName::new(b'-').is_none());
        assert!(ShortName::new(b' ').is_none());
        assert!(ShortName::new(0x00).is_none());
        assert!(ShortName::new(0x20).is_none());
        assert!(ShortName::new(0x7F).is_none());
        assert!(ShortName::new(0x80).is_none());
        assert!(ShortName::new(0xFF).is_none());
    }

    #[test]
    fn long_name_constructor() {
        let name = LongName::new(bytes("verbose")).expect("well-formed long name");
        assert_eq!(name.bytes(), b"verbose");
        assert!(LongName::new(Vec::new()).is_none());
        assert!(LongName::new(bytes("-x")).is_none());
        assert!(LongName::new(bytes("-")).is_none());
        assert!(LongName::new(bytes("a=b")).is_none());
        assert!(LongName::new(bytes("a=")).is_none());
        assert!(LongName::new(bytes("=")).is_none());
        assert!(LongName::new(bytes("a-b")).is_some());
        assert!(LongName::new(bytes("a b")).is_some());

        let both = OptName::Both(short(b'v'), name.clone());
        assert_ne!(both, OptName::Long(name));
    }

    #[test]
    fn key_ok_cases() {
        assert!(key_ok(&[bytes("git")]));
        assert!(key_ok(&[bytes("git"), bytes("status")]));
        assert!(!key_ok(&[]));
        assert!(!key_ok(&[Vec::new()]));
        assert!(!key_ok(&[bytes("git"), Vec::new()]));
        assert!(!key_ok(&[Vec::new(), bytes("status")]));
    }

    #[test]
    fn row_constructor() {
        let row = Row::new(
            vec![bytes("git"), bytes("status")],
            grammar(),
            RunsCode::No,
            Cwd::Changes,
        )
        .expect("valid key");
        assert_eq!(row.key(), [bytes("git"), bytes("status")]);
        assert_eq!(*row.grammar(), grammar());
        assert_eq!(row.runs_code(), RunsCode::No);
        assert_eq!(row.cwd(), Cwd::Changes);

        let other =
            Row::new(vec![bytes("sh")], grammar(), RunsCode::Yes, Cwd::Keeps).expect("valid key");
        assert_eq!(other.runs_code(), RunsCode::Yes);
        assert_eq!(other.cwd(), Cwd::Keeps);
        let git = Row::new(vec![bytes("git")], grammar(), RunsCode::No, Cwd::Sensitive)
            .expect("valid key");
        assert_eq!(git.cwd(), Cwd::Sensitive);

        assert!(Row::new(Vec::new(), grammar(), RunsCode::No, Cwd::Keeps).is_none());
        assert!(Row::new(vec![Vec::new()], grammar(), RunsCode::No, Cwd::Keeps).is_none());
        assert!(
            Row::new(
                vec![bytes("git"), Vec::new()],
                grammar(),
                RunsCode::No,
                Cwd::Keeps
            )
            .is_none()
        );
    }

    #[test]
    fn global_constructor() {
        let global = Global::new(bytes("git"), grammar()).expect("valid head");
        assert_eq!(global.head(), b"git");
        assert_eq!(*global.grammar(), grammar());
        assert!(Global::new(Vec::new(), grammar()).is_none());
    }

    #[test]
    fn grammar_and_catalog_accessors() {
        let opt = Opt::new(OptName::Short(short(b'C')), OptValue::Takes(Role::Path));
        assert_eq!(*opt.name(), OptName::Short(short(b'C')));
        assert_eq!(opt.value(), OptValue::Takes(Role::Path));

        let g = Grammar::new(
            vec![opt.clone()],
            vec![Role::Inert],
            Some(Role::Path),
            Order::Permute,
            DashDash::Literal,
            PlusWords::Operand,
        );
        assert_eq!(g.opts(), [opt]);
        assert_eq!(g.positionals(), [Role::Inert]);
        assert_eq!(g.rest(), Some(Role::Path));
        assert_eq!(g.permute(), Order::Permute);
        assert_eq!(g.dashdash(), DashDash::Literal);
        assert_eq!(g.plus_words(), PlusWords::Operand);

        let strict = Grammar::new(
            Vec::new(),
            Vec::new(),
            None,
            Order::Strict,
            DashDash::Ends,
            PlusWords::Reject,
        );
        assert_eq!(strict.permute(), Order::Strict);
        assert_eq!(strict.dashdash(), DashDash::Ends);

        let row = Row::new(vec![bytes("ls")], g, RunsCode::No, Cwd::Keeps).expect("valid key");
        let global = Global::new(bytes("git"), grammar()).expect("valid head");
        let cat = Catalog::new(vec![row.clone()], vec![global.clone()]);
        assert_eq!(cat.rows(), [row]);
        assert_eq!(cat.globals(), [global]);
    }
}
