//! The lexer for the v1 bash subset.
//!
//! Assumption P1 (bash reads every accepted string as the same AST) is won or
//! lost here, so the rule is: when unsure what bash does with a byte
//! sequence, it is `Unsupported`. Accepting is not a claim that the command
//! is safe.

#[cfg(test)]
mod tests;

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

/// A word: one or more parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LexWord {
    parts: Vec<LexPart>,
}

impl LexWord {
    /// Builds a word, or `None` when `parts` is empty.
    #[must_use]
    pub fn new(parts: Vec<LexPart>) -> Option<LexWord> {
        if parts.is_empty() {
            None
        } else {
            Some(LexWord { parts })
        }
    }

    /// The parts of the word.
    #[must_use]
    pub fn parts(&self) -> &[LexPart] {
        &self.parts
    }

    fn is_dev_null(&self) -> bool {
        let mut all = Vec::new();
        for part in &self.parts {
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
    /// A word with no parts. Unreachable by construction; kept so the word
    /// invariant fails closed instead of panicking.
    #[error("empty word")]
    EmptyWord,
}

/// The first construct outside the subset, and where it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported at byte {offset}: {kind}")]
pub struct Unsupported {
    /// What was found.
    pub kind: UnsupportedKind,
    /// Byte index in the input where the construct starts. For a redirect it
    /// is the start of the whole redirect, descriptor included.
    pub offset: usize,
}

/// Lexes `input`, or reports the first construct outside the subset.
///
/// # Errors
///
/// Returns [`Unsupported`] for the first byte sequence the subset does not
/// cover.
pub fn lex(input: &[u8]) -> Result<Vec<Token>, Unsupported> {
    if input.len() > MAX_INPUT_LEN {
        return Err(fail(UnsupportedKind::InputTooLarge, 0));
    }
    Lexer { input, pos: 0 }.run()
}

fn fail(kind: UnsupportedKind, offset: usize) -> Unsupported {
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
fn starts_with_assignment(bytes: &[u8]) -> bool {
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    if !is_name_start(first) {
        return false;
    }
    let name_len = rest.iter().take_while(|&&b| is_name_byte(b)).count();
    matches!(rest.get(name_len..), Some([b'=', ..] | [b'+', b'=', ..]))
}

/// Parts of a word under construction. Adjacent literals with the same
/// quoting merge, so `a'b'c` keeps its quoting boundaries and `'a''b'` does
/// not.
#[derive(Default)]
struct Parts(Vec<LexPart>);

impl Parts {
    fn push_lit(&mut self, bytes: &[u8], quoting: Quoting) {
        if let Some(LexPart::Lit {
            bytes: last,
            quoting: last_quoting,
        }) = self.0.last_mut()
            && *last_quoting == quoting
        {
            last.extend_from_slice(bytes);
            return;
        }
        self.0.push(LexPart::Lit {
            bytes: bytes.to_vec(),
            quoting,
        });
    }

    /// The word so far looks like `NAME=...` and ends in an unquoted `=` or
    /// `:`, which is where bash tilde-expands outside POSIX mode.
    fn tilde_would_expand(&self) -> bool {
        let starts_assignment = matches!(
            self.0.first(),
            Some(LexPart::Lit { bytes, quoting: Quoting::Unquoted }) if starts_with_assignment(bytes)
        );
        let after_separator = matches!(
            self.0.last(),
            Some(LexPart::Lit { bytes, quoting: Quoting::Unquoted })
                if matches!(bytes.last(), Some(b'=' | b':'))
        );
        starts_assignment && after_separator
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

    fn run(mut self) -> Result<Vec<Token>, Unsupported> {
        let mut tokens = Vec::new();
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
                    None => Token::Word(self.word()?),
                },
            };
            tokens.push(token);
        }
        Ok(tokens)
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
                    Some(b) if !is_word_terminator(b) => {}
                    Some(_) | None => {
                        return Err(fail(UnsupportedKind::RedirectTarget, start));
                    }
                }
                if self.word()?.is_dev_null() {
                    Ok(Token::Redir(LexRedir::DevNull { fd: from }))
                } else {
                    Err(fail(UnsupportedKind::RedirectTarget, start))
                }
            }
        }
    }

    /// Lexes one word. The caller guarantees the next byte is not a word
    /// terminator.
    fn word(&mut self) -> Result<LexWord, Unsupported> {
        let word_start = self.pos;
        let mut parts = Parts::default();
        while let Some(b) = self.peek() {
            if is_word_terminator(b) {
                break;
            }
            let at = self.pos;
            if is_control(b) {
                return Err(fail(UnsupportedKind::ControlByte, at));
            }
            match b {
                b'\'' => self.single_quoted(&mut parts)?,
                b'"' => self.double_quoted(&mut parts)?,
                b'\\' => {
                    let escaped = self.escaped_byte()?;
                    parts.push_lit(&[escaped], Quoting::Quoted);
                    self.pos += 2;
                }
                b'$' => return Err(fail(UnsupportedKind::UnquotedDollar, at)),
                b'`' => return Err(fail(UnsupportedKind::Backquote, at)),
                b'{' | b'}' => return Err(fail(UnsupportedKind::Brace, at)),
                b'*' | b'?' | b'[' => return Err(fail(UnsupportedKind::Glob, at)),
                b'#' if at == word_start => return Err(fail(UnsupportedKind::Comment, at)),
                b'~' if at == word_start => {
                    let next = self.peek_at(1);
                    if is_token_end(next) || next == Some(b'/') {
                        parts.0.push(LexPart::Tilde);
                        self.pos += 1;
                    } else {
                        return Err(fail(UnsupportedKind::TildeForm, at));
                    }
                }
                b'~' if parts.tilde_would_expand() => {
                    return Err(fail(UnsupportedKind::TildeAssignment, at));
                }
                _ => {
                    parts.push_lit(&[b], Quoting::Unquoted);
                    self.pos += 1;
                }
            }
        }
        LexWord::new(parts.0).ok_or_else(|| fail(UnsupportedKind::EmptyWord, word_start))
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

    fn single_quoted(&mut self, parts: &mut Parts) -> Result<(), Unsupported> {
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
        parts.push_lit(body, Quoting::Quoted);
        self.pos += 1;
        Ok(())
    }

    fn double_quoted(&mut self, parts: &mut Parts) -> Result<(), Unsupported> {
        let start = self.pos;
        self.pos += 1;
        let mut buf: Vec<u8> = Vec::new();
        let mut emitted_var = false;
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
                    let escaped = self.escaped_byte()?;
                    // Only these four are escapable; bash keeps the
                    // backslash before anything else.
                    if !matches!(escaped, b'$' | b'`' | b'"' | b'\\') {
                        buf.push(b'\\');
                    }
                    buf.push(escaped);
                    self.pos += 2;
                }
                Some(b'$') => {
                    if let Some(name) = self.dollar_in_quotes(&mut buf)? {
                        if !buf.is_empty() {
                            parts.push_lit(&buf, Quoting::Quoted);
                            buf.clear();
                        }
                        parts.0.push(LexPart::Var(name));
                        emitted_var = true;
                    }
                }
                Some(c) => {
                    buf.push(c);
                    self.pos += 1;
                }
            }
        }
        // `""` is a word, but `"$X"` must not grow an empty literal.
        if !buf.is_empty() || !emitted_var {
            parts.push_lit(&buf, Quoting::Quoted);
        }
        self.pos += 1;
        Ok(())
    }

    /// `self.pos` is at a `$` inside double quotes. Returns the variable name
    /// for `$NAME`/`${NAME}`; a `$` right before the closing quote is pushed
    /// to `buf` as a literal and yields `None`.
    fn dollar_in_quotes(&mut self, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, Unsupported> {
        let at = self.pos;
        match self.peek_at(1) {
            Some(b'"') => {
                buf.push(b'$');
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
