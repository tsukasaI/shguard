//! The lexer for the v1 bash subset.
//!
//! Assumption P1 (bash reads every accepted string as the same AST) is won or
//! lost here, so the rule is: when unsure what bash does with a byte
//! sequence, it is `Unsupported`. Accepting is not a claim that the command
//! is safe.

#[cfg(test)]
pub(crate) mod tests;

/// Longest input the lexer looks at, in bytes.
const MAX_INPUT_LEN: usize = 64 * 1024;

/// A separator or control operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `;`
    Semi,
    /// A newline.
    Newline,
    /// `&&`
    AndIf,
    /// `||`
    OrIf,
    /// `|`
    Pipe,
}

/// Whether a literal came from quotes or an escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quoting {
    /// Plain bytes in the source.
    Unquoted,
    /// From `'..'`, `".."` or a backslash escape.
    Quoted,
}

/// One piece of a word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LexPart {
    /// Literal bytes; empty for `''` and `""`.
    Lit {
        /// The bytes after quote removal.
        bytes: Vec<u8>,
        /// How they were written.
        quoting: Quoting,
    },
    /// `$NAME` or `${NAME}` inside double quotes; holds the name.
    Var(Vec<u8>),
    /// An unquoted leading `~` followed by the end of the word or `/`.
    Tilde,
}

/// A word: a first part and the parts after it, so it is never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LexWord {
    first: LexPart,
    rest: Vec<LexPart>,
}

impl LexWord {
    /// Builds a word from its first part and the parts after it.
    #[must_use]
    pub fn new(first: LexPart, rest: Vec<LexPart>) -> LexWord {
        LexWord { first, rest }
    }

    /// The first part.
    #[must_use]
    pub fn first(&self) -> &LexPart {
        &self.first
    }

    /// The parts after the first.
    #[must_use]
    pub fn rest(&self) -> &[LexPart] {
        &self.rest
    }

    /// Splits the word into its first part and the parts after it.
    #[must_use]
    pub fn into_parts(self) -> (LexPart, Vec<LexPart>) {
        (self.first, self.rest)
    }

    fn is_dev_null(&self) -> bool {
        let mut all = Vec::new();
        for part in std::iter::once(&self.first).chain(&self.rest) {
            match part {
                LexPart::Lit { bytes, .. } => all.extend_from_slice(bytes),
                LexPart::Var(_) | LexPart::Tilde => return false,
            }
        }
        all == b"/dev/null"
    }
}

/// A redirect the subset accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexRedir {
    /// `[N]>&M`; `from` defaults to 1.
    Dup {
        /// The descriptor being redirected.
        from: u8,
        /// The descriptor it becomes a copy of.
        to: u8,
    },
    /// `[N]>/dev/null`; `fd` defaults to 1.
    DevNull {
        /// The descriptor being redirected.
        fd: u8,
    },
}

/// A lexed token. Blanks are not tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// A word.
    Word(LexWord),
    /// A redirect.
    Redir(LexRedir),
    /// An operator.
    Op(Op),
}

/// The construct that put the input outside the subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedKind {
    /// More than 64 KiB of input.
    #[error("input longer than 64 KiB")]
    InputTooLarge,
    /// A control byte other than tab or newline (CR and NUL included).
    #[error("control byte")]
    ControlByte,
    /// A `'` with no closing `'`.
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    /// A `"` with no closing `"`.
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    /// A lone `&` (background job).
    #[error("`&` (background)")]
    BackgroundAmpersand,
    /// `|&`
    #[error("`|&`")]
    PipeAmpersand,
    /// `;;`
    #[error("`;;`")]
    DoubleSemicolon,
    /// `;&`
    #[error("`;&`")]
    SemicolonAmpersand,
    /// `(` or `)`
    #[error("parenthesis")]
    Parenthesis,
    /// `<` in any form: input redirect, heredoc, here-string, `<(`.
    #[error("input redirect")]
    InputRedirect,
    /// `>>`
    #[error("`>>`")]
    AppendRedirect,
    /// `>|`
    #[error("`>|`")]
    ClobberRedirect,
    /// `&>` or `&>>`
    #[error("`&>`")]
    AmpersandRedirect,
    /// `>(`
    #[error("output process substitution")]
    ProcessSubstitution,
    /// An unquoted `{` or `}`.
    #[error("unquoted brace")]
    Brace,
    /// An unquoted `*`, `?` or `[`.
    #[error("unquoted glob byte")]
    Glob,
    /// An unquoted `#` at the start of a word.
    #[error("comment")]
    Comment,
    /// An unquoted `$` in any form.
    #[error("unquoted `$`")]
    UnquotedDollar,
    /// A backquote outside single quotes.
    #[error("backquote")]
    Backquote,
    /// `$(` or `$((` inside double quotes.
    #[error("command or arithmetic substitution")]
    DollarParen,
    /// `${` inside double quotes that is not exactly `${NAME}`.
    #[error("parameter expansion other than ${{NAME}}")]
    BracedParameter,
    /// A special or positional parameter inside double quotes.
    #[error("special or positional parameter")]
    SpecialParameter,
    /// `$NAME` inside double quotes with a non-ASCII byte right after the
    /// name: bash may count that byte as part of the name.
    #[error("`$NAME` followed by a non-ASCII byte")]
    NameBeforeNonAscii,
    /// A backslash right after a byte >= 0x80: in some multibyte locales the
    /// backslash is part of that character and escapes nothing.
    #[error("backslash after a non-ASCII byte")]
    BackslashAfterNonAscii,
    /// A `$` inside double quotes that starts no variable and is not followed
    /// by the closing quote.
    #[error("bare `$` in double quotes")]
    BareDollar,
    /// A backslash followed by a newline.
    #[error("line continuation")]
    LineContinuation,
    /// A backslash as the last byte of the input.
    #[error("backslash at end of input")]
    BackslashAtEnd,
    /// A leading `~` followed by something other than the end of the word
    /// or `/`.
    #[error("tilde form other than a bare `~`")]
    TildeForm,
    /// An unquoted `~` after `=` or `:` in an assignment-shaped word.
    #[error("tilde in an assignment-shaped word")]
    TildeAssignment,
    /// A multi-digit descriptor before `>`.
    #[error("multi-digit file descriptor")]
    MultiDigitFd,
    /// A `>&` operand that is not a single digit followed by a token end.
    #[error("`>&` operand other than one digit")]
    DupOperand,
    /// A `>` target other than `/dev/null`.
    #[error("redirect target other than /dev/null")]
    RedirectTarget,
    /// A `;` where a command must start: at the start of the script or right
    /// after another separator (`;a`, `a; ;b`, `a\n;b`), or right after `|`,
    /// `&&` or `||` (`a |;`). Reported by the parser.
    #[error("`;` where a command must start")]
    LeadingSeparator,
    /// A `|`, `&&` or `||` where a command must start, or the end of the
    /// input right after one (`| a`, `a |`, `a &&`). Reported by the parser.
    #[error("missing command")]
    MissingCommand,
    /// A command with redirects but no word (`>/dev/null`). Reported by the
    /// parser.
    #[error("redirect without a command")]
    RedirectOnly,
    /// An assignment-shaped first word (`FOO=1 cmd`). Reported by the
    /// parser.
    #[error("assignment")]
    Assignment,
    /// An unquoted reserved word as the first word of a command (`if`,
    /// `time`, `!`, ...). Reported by the parser.
    #[error("reserved word")]
    ReservedWord,
    /// More than 4096 words in the script. Reported by the parser.
    #[error("more than 4096 words")]
    TooManyWords,
}

/// A construct outside the subset, and where it starts. The lexer reports the
/// first one it meets; the parser only runs on input the lexer accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported at byte {offset}: {kind}")]
pub struct Unsupported {
    /// What was found.
    pub kind: UnsupportedKind,
    /// Byte index in the input where the construct starts. For a redirect it
    /// is the start of the whole redirect, descriptor included.
    pub offset: usize,
}

/// A token and the byte offset where it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lexeme {
    /// Byte index in the input where the token starts. For a redirect it is
    /// the start of the whole redirect, descriptor included.
    pub offset: usize,
    /// Byte index in the input just past the token (exclusive), so
    /// `input[offset..end]` is its exact source text. A word's text spans
    /// its quotes and escapes.
    pub end: usize,
    /// The token.
    pub token: Token,
}

/// Lexes `input`, or reports the first construct outside the subset.
///
/// # Errors
///
/// Returns [`Unsupported`] for the first byte sequence the subset does not
/// cover.
pub fn lex(input: &[u8]) -> Result<Vec<Lexeme>, Unsupported> {
    if input.len() > MAX_INPUT_LEN {
        return Err(fail(UnsupportedKind::InputTooLarge, 0));
    }
    Lexer { input, pos: 0 }.run()
}

pub(crate) fn fail(kind: UnsupportedKind, offset: usize) -> Unsupported {
    Unsupported { kind, offset }
}

fn is_control(b: u8) -> bool {
    (b < 0x20 && b != b'\t' && b != b'\n') || b == 0x7F
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Bytes that end an unquoted word.
fn is_word_terminator(b: u8) -> bool {
    is_blank(b) || matches!(b, b';' | b'\n' | b'&' | b'|' | b'<' | b'>' | b'(' | b')')
}

/// The end-of-token set that `>&D` and a bare `~` are checked against. It is
/// narrower than `is_word_terminator` on purpose: `(` and `)` are
/// unsupported anyway, so a tilde or dup operand next to them stays
/// unsupported rather than guessing.
fn is_token_end(b: Option<u8>) -> bool {
    match b {
        None => true,
        Some(b) => is_blank(b) || matches!(b, b';' | b'\n' | b'&' | b'|' | b'>' | b'<'),
    }
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True when `bytes` starts with `NAME=` or `NAME+=` (bash's `assignment()`
/// accepts both, and tilde-expands after either).
///
/// A byte >= 0x80 counts as a possible name byte: whether it is one depends on
/// the locale and the bash build (bash 5.3p9 took Latin-1 letter bytes into
/// names), so `ê=~` must not be read as a plain word.
pub(crate) fn starts_with_assignment(bytes: &[u8]) -> bool {
    let may_be_name_start = |b: u8| is_name_start(b) || b >= 0x80;
    let may_be_name_byte = |b: u8| is_name_byte(b) || b >= 0x80;
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    if !may_be_name_start(first) {
        return false;
    }
    let name_len = rest.iter().take_while(|&&b| may_be_name_byte(b)).count();
    matches!(rest.get(name_len..), Some([b'=', ..] | [b'+', b'=', ..]))
}

/// Parts of a word under construction: the parts before the last one, and the
/// last one, so the value is never empty. Adjacent literals with the same
/// quoting merge: `'a''b'` is one literal, while `a'b'` keeps the boundary
/// between the unquoted and the quoted part.
struct Parts {
    init: Vec<LexPart>,
    last: LexPart,
}

impl Parts {
    fn of(last: LexPart) -> Parts {
        Parts {
            init: Vec::new(),
            last,
        }
    }

    fn lit(bytes: Vec<u8>, quoting: Quoting) -> Parts {
        Parts::of(LexPart::Lit { bytes, quoting })
    }

    /// Adds a part at the end, merging it into the last one when both are
    /// literals with the same quoting.
    fn push(&mut self, part: LexPart) {
        if let LexPart::Lit {
            bytes: last,
            quoting: last_quoting,
        } = &mut self.last
            && let LexPart::Lit { bytes, quoting } = &part
            && last_quoting == quoting
        {
            last.extend_from_slice(bytes);
            return;
        }
        self.init.push(std::mem::replace(&mut self.last, part));
    }

    fn append(&mut self, other: Parts) {
        for part in other.init {
            self.push(part);
        }
        self.push(other.last);
    }

    /// Adds a byte inside double quotes, where every literal is quoted.
    fn push_quoted_byte(&mut self, byte: u8) {
        if let LexPart::Lit {
            bytes,
            quoting: Quoting::Quoted,
        } = &mut self.last
        {
            bytes.push(byte);
        } else {
            let lit = LexPart::Lit {
                bytes: vec![byte],
                quoting: Quoting::Quoted,
            };
            self.init.push(std::mem::replace(&mut self.last, lit));
        }
    }

    /// Adds a variable inside double quotes. The empty literal that `""`
    /// starts with is dropped, so `"$X"` is exactly one `Var`.
    fn push_var(&mut self, name: Vec<u8>) {
        let old = std::mem::replace(&mut self.last, LexPart::Var(name));
        if !matches!(&old, LexPart::Lit { bytes, .. } if bytes.is_empty()) {
            self.init.push(old);
        }
    }

    /// The word so far looks like `NAME=...` and ends in an unquoted `=` or
    /// `:`, which is where bash tilde-expands outside POSIX mode.
    fn tilde_would_expand(&self) -> bool {
        let first = self.init.first().unwrap_or(&self.last);
        let starts_assignment = matches!(
            first,
            LexPart::Lit { bytes, quoting: Quoting::Unquoted } if starts_with_assignment(bytes)
        );
        let after_separator = matches!(
            &self.last,
            LexPart::Lit { bytes, quoting: Quoting::Unquoted }
                if matches!(bytes.last(), Some(b'=' | b':'))
        );
        starts_assignment && after_separator
    }

    fn into_word(self) -> LexWord {
        let mut init = self.init.into_iter();
        match init.next() {
            Some(first) => {
                let mut rest: Vec<LexPart> = init.collect();
                rest.push(self.last);
                LexWord::new(first, rest)
            }
            None => LexWord::new(self.last, Vec::new()),
        }
    }
}

struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<u8> {
        self.peek_at(0)
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.input.get(self.pos + ahead).copied()
    }

    fn run(mut self) -> Result<Vec<Lexeme>, Unsupported> {
        let mut lexemes = Vec::new();
        while let Some(b) = self.peek() {
            let start = self.pos;
            if is_control(b) {
                return Err(fail(UnsupportedKind::ControlByte, start));
            }
            let token = match b {
                b' ' | b'\t' => {
                    self.pos += 1;
                    continue;
                }
                b'\n' => {
                    self.pos += 1;
                    Token::Op(Op::Newline)
                }
                b';' => self.semicolon()?,
                b'&' => self.ampersand()?,
                b'|' => self.pipe()?,
                b'(' | b')' => return Err(fail(UnsupportedKind::Parenthesis, start)),
                b'<' => return Err(fail(UnsupportedKind::InputRedirect, start)),
                b'>' => self.redirect(start, 1)?,
                _ => match self.io_number()? {
                    Some(fd) => self.redirect(start, fd)?,
                    None => Token::Word(self.word(b)?),
                },
            };
            lexemes.push(Lexeme {
                offset: start,
                end: self.pos,
                token,
            });
        }
        Ok(lexemes)
    }

    fn semicolon(&mut self) -> Result<Token, Unsupported> {
        let start = self.pos;
        match self.peek_at(1) {
            Some(b';') => Err(fail(UnsupportedKind::DoubleSemicolon, start)),
            Some(b'&') => Err(fail(UnsupportedKind::SemicolonAmpersand, start)),
            Some(_) | None => {
                self.pos += 1;
                Ok(Token::Op(Op::Semi))
            }
        }
    }

    fn ampersand(&mut self) -> Result<Token, Unsupported> {
        let start = self.pos;
        match self.peek_at(1) {
            Some(b'&') => {
                self.pos += 2;
                Ok(Token::Op(Op::AndIf))
            }
            Some(b'>') => Err(fail(UnsupportedKind::AmpersandRedirect, start)),
            Some(_) | None => Err(fail(UnsupportedKind::BackgroundAmpersand, start)),
        }
    }

    fn pipe(&mut self) -> Result<Token, Unsupported> {
        let start = self.pos;
        match self.peek_at(1) {
            Some(b'|') => {
                self.pos += 2;
                Ok(Token::Op(Op::OrIf))
            }
            Some(b'&') => Err(fail(UnsupportedKind::PipeAmpersand, start)),
            Some(_) | None => {
                self.pos += 1;
                Ok(Token::Op(Op::Pipe))
            }
        }
    }

    /// A digit run that starts a token and is directly followed by `>` is a
    /// descriptor; `a2>&1` never gets here because `a2` is lexed as a word.
    /// Consumes the digits when it returns `Some`.
    fn io_number(&mut self) -> Result<Option<u8>, Unsupported> {
        let start = self.pos;
        let rest = self.input.get(start..).unwrap_or_default();
        let len = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if len == 0 || rest.get(len) != Some(&b'>') {
            return Ok(None);
        }
        match rest.first() {
            Some(&digit) if len == 1 => {
                self.pos += 1;
                Ok(Some(digit - b'0'))
            }
            Some(_) | None => Err(fail(UnsupportedKind::MultiDigitFd, start)),
        }
    }

    /// `self.pos` is at the `>`; `start` is where the redirect began.
    fn redirect(&mut self, start: usize, from: u8) -> Result<Token, Unsupported> {
        match self.peek_at(1) {
            Some(b'>') => Err(fail(UnsupportedKind::AppendRedirect, start)),
            Some(b'|') => Err(fail(UnsupportedKind::ClobberRedirect, start)),
            Some(b'(') => Err(fail(UnsupportedKind::ProcessSubstitution, start)),
            Some(b'&') => {
                // Only `>&D` plus a token end is a dup: bash opens a file
                // named `1x` for `>&1x`, and `>&-` closes the descriptor.
                match self.peek_at(2) {
                    Some(d) if d.is_ascii_digit() && is_token_end(self.peek_at(3)) => {
                        self.pos += 3;
                        Ok(Token::Redir(LexRedir::Dup { from, to: d - b'0' }))
                    }
                    Some(_) | None => Err(fail(UnsupportedKind::DupOperand, start)),
                }
            }
            Some(_) | None => {
                self.pos += 1;
                while self.peek().is_some_and(is_blank) {
                    self.pos += 1;
                }
                match self.peek() {
                    Some(b) if !is_word_terminator(b) => {
                        if self.word(b)?.is_dev_null() {
                            Ok(Token::Redir(LexRedir::DevNull { fd: from }))
                        } else {
                            Err(fail(UnsupportedKind::RedirectTarget, start))
                        }
                    }
                    Some(_) | None => Err(fail(UnsupportedKind::RedirectTarget, start)),
                }
            }
        }
    }

    /// Lexes one word starting with `first`, the byte at `self.pos`. The
    /// caller guarantees `first` is not a word terminator.
    fn word(&mut self, first: u8) -> Result<LexWord, Unsupported> {
        let mut parts = self.chunk(first, None)?;
        while let Some(b) = self.peek()
            && !is_word_terminator(b)
        {
            let next = self.chunk(b, Some(&parts))?;
            parts.append(next);
        }
        Ok(parts.into_word())
    }

    /// Lexes the next unit of a word: a quoted string, an escaped byte, a
    /// leading tilde or one plain byte. `b` is the byte at `self.pos`;
    /// `so_far` is `None` for the first unit of the word.
    fn chunk(&mut self, b: u8, so_far: Option<&Parts>) -> Result<Parts, Unsupported> {
        let at = self.pos;
        if is_control(b) {
            return Err(fail(UnsupportedKind::ControlByte, at));
        }
        match b {
            b'\'' => self.single_quoted(),
            b'"' => self.double_quoted(),
            b'\\' => {
                self.reject_backslash_after_non_ascii()?;
                let escaped = self.escaped_byte()?;
                self.pos += 2;
                Ok(Parts::lit(vec![escaped], Quoting::Quoted))
            }
            b'$' => Err(fail(UnsupportedKind::UnquotedDollar, at)),
            b'`' => Err(fail(UnsupportedKind::Backquote, at)),
            b'{' | b'}' => Err(fail(UnsupportedKind::Brace, at)),
            b'*' | b'?' | b'[' => Err(fail(UnsupportedKind::Glob, at)),
            b'#' if so_far.is_none() => Err(fail(UnsupportedKind::Comment, at)),
            b'~' if so_far.is_none() => {
                let next = self.peek_at(1);
                if is_token_end(next) || next == Some(b'/') {
                    self.pos += 1;
                    Ok(Parts::of(LexPart::Tilde))
                } else {
                    Err(fail(UnsupportedKind::TildeForm, at))
                }
            }
            b'~' if so_far.is_some_and(Parts::tilde_would_expand) => {
                Err(fail(UnsupportedKind::TildeAssignment, at))
            }
            _ => {
                self.pos += 1;
                Ok(Parts::lit(vec![b], Quoting::Unquoted))
            }
        }
    }

    /// Rejects the backslash at `self.pos` when the byte before it is >= 0x80.
    /// In SJIS, GBK, GB18030 and Big5 locales `\` (0x5C) can be the trail byte
    /// of a multibyte character, and bash then does not treat it as an escape
    /// (`echo \x83\;printf BOOM` runs `printf`). The test is "previous byte
    /// is at least 0x80", not "previous byte is a lead byte", because that
    /// depends on the encoding: `日\` is a `\` after a complete character in
    /// SJIS terms, but `A5 5C` is a single GBK character.
    fn reject_backslash_after_non_ascii(&self) -> Result<(), Unsupported> {
        let before = self.pos.checked_sub(1).and_then(|i| self.input.get(i));
        if before.is_some_and(|b| *b >= 0x80) {
            Err(fail(UnsupportedKind::BackslashAfterNonAscii, self.pos))
        } else {
            Ok(())
        }
    }

    /// The byte after the backslash at `self.pos`, after checking that it is
    /// neither the end of input, a newline nor a control byte.
    fn escaped_byte(&self) -> Result<u8, Unsupported> {
        match self.peek_at(1) {
            None => Err(fail(UnsupportedKind::BackslashAtEnd, self.pos)),
            Some(b'\n') => Err(fail(UnsupportedKind::LineContinuation, self.pos)),
            Some(c) if is_control(c) => Err(fail(UnsupportedKind::ControlByte, self.pos + 1)),
            Some(c) => Ok(c),
        }
    }

    fn single_quoted(&mut self) -> Result<Parts, Unsupported> {
        let start = self.pos;
        self.pos += 1;
        let body_start = self.pos;
        loop {
            match self.peek() {
                None => return Err(fail(UnsupportedKind::UnterminatedSingleQuote, start)),
                Some(b'\'') => break,
                Some(c) if is_control(c) => {
                    return Err(fail(UnsupportedKind::ControlByte, self.pos));
                }
                Some(_) => self.pos += 1,
            }
        }
        let body = self.input.get(body_start..self.pos).unwrap_or_default();
        self.pos += 1;
        Ok(Parts::lit(body.to_vec(), Quoting::Quoted))
    }

    fn double_quoted(&mut self) -> Result<Parts, Unsupported> {
        let start = self.pos;
        self.pos += 1;
        // `""` is a word, so the parts start with an empty literal; the first
        // variable replaces it, so `"$X"` does not grow one.
        let mut parts = Parts::lit(Vec::new(), Quoting::Quoted);
        loop {
            let at = self.pos;
            match self.peek() {
                None => return Err(fail(UnsupportedKind::UnterminatedDoubleQuote, start)),
                Some(b'"') => break,
                Some(c) if is_control(c) => {
                    return Err(fail(UnsupportedKind::ControlByte, at));
                }
                Some(b'`') => return Err(fail(UnsupportedKind::Backquote, at)),
                Some(b'\\') => {
                    self.reject_backslash_after_non_ascii()?;
                    let escaped = self.escaped_byte()?;
                    // Only these four are escapable; bash keeps the
                    // backslash before anything else.
                    if !matches!(escaped, b'$' | b'`' | b'"' | b'\\') {
                        parts.push_quoted_byte(b'\\');
                    }
                    parts.push_quoted_byte(escaped);
                    self.pos += 2;
                }
                Some(b'$') => match self.dollar_in_quotes()? {
                    Some(name) => parts.push_var(name),
                    None => parts.push_quoted_byte(b'$'),
                },
                Some(c) => {
                    parts.push_quoted_byte(c);
                    self.pos += 1;
                }
            }
        }
        self.pos += 1;
        Ok(parts)
    }

    /// `self.pos` is at a `$` inside double quotes. Returns the variable name
    /// for `$NAME`/`${NAME}`; a `$` right before the closing quote is a
    /// literal `$` and yields `None`.
    fn dollar_in_quotes(&mut self) -> Result<Option<Vec<u8>>, Unsupported> {
        let at = self.pos;
        match self.peek_at(1) {
            Some(b'"') => {
                self.pos += 1;
                Ok(None)
            }
            Some(b'(') => Err(fail(UnsupportedKind::DollarParen, at)),
            Some(b'{') => {
                let name = self.name_at(self.pos + 2);
                if !name.is_empty() && self.input.get(self.pos + 2 + name.len()) == Some(&b'}') {
                    let name = name.to_vec();
                    self.pos += name.len() + 3;
                    Ok(Some(name))
                } else {
                    Err(fail(UnsupportedKind::BracedParameter, at))
                }
            }
            Some(c) if is_name_start(c) => {
                let name = self.name_at(self.pos + 1).to_vec();
                // Which bytes form a name depends on the locale and the bash
                // build: bash 5.3p9 on macOS with no `LC_*` set took 0xE6 into
                // `$HOME日`, while `LC_ALL=C` and bash 5.3p20 did not. A
                // non-ASCII byte right after the name makes the boundary
                // ambiguous.
                if self
                    .input
                    .get(self.pos + 1 + name.len())
                    .is_some_and(|b| *b >= 0x80)
                {
                    return Err(fail(UnsupportedKind::NameBeforeNonAscii, at));
                }
                self.pos += name.len() + 1;
                Ok(Some(name))
            }
            Some(b'0'..=b'9' | b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!') => {
                Err(fail(UnsupportedKind::SpecialParameter, at))
            }
            Some(_) | None => Err(fail(UnsupportedKind::BareDollar, at)),
        }
    }

    /// The longest `[A-Za-z_][A-Za-z0-9_]*` starting at `from`, or empty.
    fn name_at(&self, from: usize) -> &[u8] {
        let rest = self.input.get(from..).unwrap_or_default();
        match rest.split_first() {
            Some((&first, tail)) if is_name_start(first) => {
                let len = 1 + tail.iter().take_while(|&&b| is_name_byte(b)).count();
                rest.get(..len).unwrap_or_default()
            }
            Some(_) | None => &[],
        }
    }
}
