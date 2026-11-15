//! `shguard report`: counts a decision log by class.
//!
//! The log is read one line at a time. A line is a JSON object; its `class`
//! string is the key. A line without a `class` string (written before the
//! field existed) counts as `unclassified`; a line that is not a JSON object,
//! or not UTF-8, or longer than [`LINE_CAP`], or whose `class` is not a name
//! this version knows, counts as `invalid` (the unknown text is never kept or
//! printed); an empty line is skipped.
//!
//! The output is one `<count>\t<class>` line per listed class, most frequent
//! first and by class name among equals, then `<total>\ttotal`, which counts
//! every line, listed or not. Command text is printed only under
//! [`CommandText::Show`], as `\t<count>\t<command>` under its class. The
//! command is JSON-quoted and then further escaped for display: every control
//! character and bidi control left raw by the quoting is written as `\u{XXXX}`,
//! so the text is one line that cannot drive the terminal. A class says which
//! path produced an answer; it does not say a command is safe.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use serde_json::Value;

use crate::decision_class::DecisionClass;

/// The class counted for a line with no `class` string.
pub const UNCLASSIFIED: &str = "unclassified";
/// The class counted for a line that is not a JSON object.
pub const INVALID: &str = "invalid";

/// The longest line that is parsed: above the hook's 1 MiB input cap, so a
/// line the hook wrote fits. A longer line counts as `invalid`.
pub const LINE_CAP: usize = 2 * 1024 * 1024;

/// How many classes the report lists unless told otherwise.
pub const DEFAULT_LIMIT: usize = 20;
/// How many distinct commands are listed under a class.
pub const COMMANDS_PER_CLASS: usize = 5;

/// Whether the report may print command text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandText {
    /// Counts only.
    Hide,
    /// Also the most frequent distinct commands of each listed class. The
    /// tally holds every distinct command of every class in memory (memory
    /// grows with the number of distinct commands), which is why it is opt-in.
    Show,
}

/// Counts per class, and per command when command text was asked for.
#[derive(Debug, Default)]
pub struct Tally {
    classes: HashMap<String, u64>,
    commands: HashMap<String, HashMap<String, u64>>,
    total: u64,
}

/// Reads `log` to its end and counts each line.
///
/// # Errors
///
/// The I/O error of a read.
pub fn tally(log: impl BufRead, text: CommandText) -> io::Result<Tally> {
    tally_capped(log, text, LINE_CAP)
}

fn tally_capped(mut log: impl BufRead, text: CommandText, cap: usize) -> io::Result<Tally> {
    let mut tally = Tally::default();
    let mut raw = Vec::new();
    let take_len = u64::try_from(cap).map_or(u64::MAX, |c| c.saturating_add(1));
    loop {
        raw.clear();
        let mut bounded = io::Read::take(&mut log, take_len);
        if bounded.read_until(b'\n', &mut raw)? == 0 {
            return Ok(tally);
        }
        let overlong = raw.len() > cap && raw.last() != Some(&b'\n');
        if overlong {
            // The rest of the line is dropped unread into memory.
            skip_line(&mut log)?;
        }
        let line = raw.trim_ascii();
        if line.is_empty() && !overlong {
            continue;
        }
        let object = std::str::from_utf8(line)
            .ok()
            .filter(|_| !overlong)
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .filter(Value::is_object);
        let (class, command) = match &object {
            Some(o) => match o.get("class").and_then(Value::as_str) {
                None => (UNCLASSIFIED, o.get("command").and_then(Value::as_str)),
                Some(name) if DecisionClass::is_known(name) => {
                    (name, o.get("command").and_then(Value::as_str))
                }
                Some(_) => (INVALID, None),
            },
            None => (INVALID, None),
        };
        tally.total = tally.total.saturating_add(1);
        bump(&mut tally.classes, class);
        if let (CommandText::Show, Some(command)) = (text, command) {
            bump(tally.commands.entry(class.to_owned()).or_default(), command);
        }
    }
}

/// Consumes through the next newline (or the end) without keeping any of it.
fn skip_line(log: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buf = log.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        let newline = buf.iter().position(|b| *b == b'\n');
        let used = newline.map_or(buf.len(), |i| i + 1);
        log.consume(used);
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn bump(counts: &mut HashMap<String, u64>, key: &str) {
    let n = counts.entry(key.to_owned()).or_insert(0);
    *n = n.saturating_add(1);
}

/// Most frequent first, then by key.
fn ranked(counts: &HashMap<String, u64>) -> Vec<(&str, u64)> {
    let mut rows: Vec<(&str, u64)> = counts.iter().map(|(k, n)| (k.as_str(), *n)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
}

// Not the JSON quoting alone: serde_json leaves DEL, the C1 controls (U+009B
// is a CSI on some terminals) and the bidi controls raw.
fn display_command(command: &str) -> String {
    let quoted = Value::from(command).to_string();
    let mut out = String::with_capacity(quoted.len());
    for c in quoted.chars() {
        if c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
            out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

impl Tally {
    /// Writes the report: at most `limit` classes, then the total.
    ///
    /// # Errors
    ///
    /// The I/O error of a write.
    pub fn write_to(&self, limit: usize, out: &mut impl Write) -> io::Result<()> {
        for (class, count) in ranked(&self.classes).into_iter().take(limit) {
            writeln!(out, "{count}\t{class}")?;
            if let Some(commands) = self.commands.get(class) {
                for (command, n) in ranked(commands).into_iter().take(COMMANDS_PER_CLASS) {
                    let shown = display_command(command);
                    writeln!(out, "\t{n}\t{shown}")?;
                }
            }
        }
        writeln!(out, "{}\ttotal", self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(log: &str, text: CommandText, limit: usize) -> String {
        let counted = match tally(log.as_bytes(), text) {
            Ok(t) => t,
            Err(e) => panic!("{e}"),
        };
        let mut out = Vec::new();
        if let Err(e) = counted.write_to(limit, &mut out) {
            panic!("{e}");
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn counts_sort_by_count_then_name_and_total_counts_every_line() {
        let log = concat!(
            "{\"class\":\"load_error\"}\n",
            "{\"class\":\"allow_user_row\"}\n",
            "{\"class\":\"allow\"}\n",
            "{\"class\":\"allow\"}\n",
            "{\"ts\":1}\n",
            "[1]\n",
            "not json\n",
            "\n",
        );
        assert_eq!(
            run(log, CommandText::Hide, 3),
            "2\tallow\n2\tinvalid\n1\tallow_user_row\n7\ttotal\n"
        );
        assert_eq!(
            run(log, CommandText::Hide, 20),
            "2\tallow\n2\tinvalid\n1\tallow_user_row\n1\tload_error\n1\tunclassified\n7\ttotal\n"
        );
    }

    #[test]
    fn a_line_that_is_not_utf8_is_invalid() {
        let bytes: &[u8] = b"{\"class\":\"allow\"}\n\xff\xfe\n";
        let Ok(t) = tally(bytes, CommandText::Hide) else {
            panic!("reads");
        };
        let mut out = Vec::new();
        assert!(t.write_to(20, &mut out).is_ok());
        assert_eq!(out, b"1\tallow\n1\tinvalid\n2\ttotal\n");
    }

    #[test]
    fn an_overlong_line_is_invalid_and_the_next_line_is_still_read() {
        let log = "{\"class\":\"allow\"}\n\
                   {\"class\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n\
                   {\"class\":\"load_error\"}\n\
                   {\"class\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}";
        // 22 bytes fit (`{"class":"load_error"}` is exactly 22); the long
        // lines (the last has no newline) do not.
        let Ok(t) = tally_capped(log.as_bytes(), CommandText::Hide, 22) else {
            panic!("reads");
        };
        let mut out = Vec::new();
        assert!(t.write_to(20, &mut out).is_ok());
        assert_eq!(out, b"2\tinvalid\n1\tallow\n1\tload_error\n4\ttotal\n");
    }

    #[test]
    fn an_overlong_line_of_whitespace_is_invalid_not_skipped() {
        let log = format!(
            "{}\n{{\"class\":\"rule_hit\"}}\n{{\"class\":\"allow\"}}\n",
            " ".repeat(30)
        );
        let Ok(t) = tally_capped(log.as_bytes(), CommandText::Hide, 22) else {
            panic!("reads");
        };
        let mut out = Vec::new();
        assert!(t.write_to(20, &mut out).is_ok());
        assert_eq!(out, b"1\tallow\n1\tinvalid\n1\trule_hit\n3\ttotal\n");
    }

    #[test]
    fn commands_are_listed_only_on_request() {
        let log = "{\"class\":\"allow\",\"command\":\"ls\\n-l\"}\n\
                   {\"class\":\"allow\",\"command\":\"ls\\n-l\"}\n\
                   {\"class\":\"allow\",\"command\":\"pwd\"}\n";
        assert!(!run(log, CommandText::Hide, 20).contains("pwd"));
        assert_eq!(
            run(log, CommandText::Show, 20),
            "3\tallow\n\t2\t\"ls\\n-l\"\n\t1\t\"pwd\"\n3\ttotal\n"
        );
    }

    #[test]
    fn display_escapes_controls_and_bidi_but_keeps_json_escapes_and_text() {
        assert_eq!(display_command("a\nb"), "\"a\\nb\"");
        assert_eq!(display_command("\u{1b}"), "\"\\u001b\"");
        assert_eq!(display_command("\\u{009B}"), "\"\\\\u{009B}\"");
        assert_eq!(display_command("\u{7F}"), "\"\\u{007F}\"");
        assert_eq!(display_command("\u{85}"), "\"\\u{0085}\"");
        assert_eq!(display_command("\u{9B}"), "\"\\u{009B}\"");
        assert_eq!(display_command("\u{202A}"), "\"\\u{202A}\"");
        assert_eq!(display_command("\u{202E}"), "\"\\u{202E}\"");
        assert_eq!(display_command("\u{2066}"), "\"\\u{2066}\"");
        assert_eq!(display_command("\u{2069}"), "\"\\u{2069}\"");
        assert_eq!(display_command("é日"), "\"é日\"");
    }

    #[test]
    fn an_unknown_class_is_invalid_and_its_command_is_never_kept() {
        let log = "{\"class\":\"unknown:from_the_future\",\"command\":\"SENT\"}\n\
                   {\"class\":\"allow\",\"command\":\"ls\"}\n";
        assert_eq!(
            run(log, CommandText::Show, 20),
            "1\tallow\n\t1\t\"ls\"\n1\tinvalid\n2\ttotal\n"
        );
    }
}
