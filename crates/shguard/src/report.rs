//! `shguard report`: counts a decision log by class.
//!
//! The log is read one line at a time. A line is a JSON object; its `class`
//! string is the key. A line without a `class` string (written before the
//! field existed) counts as `unclassified`; a line that is not a JSON object,
//! or not UTF-8, counts as `invalid`; an empty line is skipped.
//!
//! The output is one `<count>\t<class>` line per listed class, most frequent
//! first and by class name among equals, then `<total>\ttotal`, which counts
//! every line, listed or not. Command text is printed only under
//! [`CommandText::Show`], as `\t<count>\t<command as a JSON string>` under its
//! class. A class says which path produced an answer; it does not say a
//! command is safe.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use serde_json::Value;

/// The class counted for a line with no `class` string.
pub const UNCLASSIFIED: &str = "unclassified";
/// The class counted for a line that is not a JSON object.
pub const INVALID: &str = "invalid";

/// How many classes the report lists unless told otherwise.
pub const DEFAULT_LIMIT: usize = 20;
/// How many distinct commands are listed under a class.
pub const COMMANDS_PER_CLASS: usize = 5;

/// Whether the report may print command text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandText {
    /// Counts only.
    Hide,
    /// Also the most frequent distinct commands of each listed class.
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
pub fn tally(mut log: impl BufRead, text: CommandText) -> io::Result<Tally> {
    let mut tally = Tally::default();
    let mut raw = Vec::new();
    loop {
        raw.clear();
        if log.read_until(b'\n', &mut raw)? == 0 {
            return Ok(tally);
        }
        let line = raw.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let object = std::str::from_utf8(line)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .filter(Value::is_object);
        let (class, command) = match &object {
            Some(o) => (
                o.get("class")
                    .and_then(Value::as_str)
                    .unwrap_or(UNCLASSIFIED),
                o.get("command").and_then(Value::as_str),
            ),
            None => (INVALID, None),
        };
        tally.total = tally.total.saturating_add(1);
        bump(&mut tally.classes, class);
        if let (CommandText::Show, Some(command)) = (text, command) {
            bump(tally.commands.entry(class.to_owned()).or_default(), command);
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
                    let quoted = Value::from(command).to_string();
                    writeln!(out, "\t{n}\t{quoted}")?;
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
            "{\"class\":\"b\"}\n",
            "{\"class\":\"a\"}\n",
            "{\"class\":\"c\"}\n",
            "{\"class\":\"c\"}\n",
            "{\"ts\":1}\n",
            "[1]\n",
            "not json\n",
            "\n",
        );
        assert_eq!(
            run(log, CommandText::Hide, 3),
            "2\tc\n2\tinvalid\n1\ta\n7\ttotal\n"
        );
        assert_eq!(
            run(log, CommandText::Hide, 20),
            "2\tc\n2\tinvalid\n1\ta\n1\tb\n1\tunclassified\n7\ttotal\n"
        );
    }

    #[test]
    fn a_line_that_is_not_utf8_is_invalid() {
        let bytes: &[u8] = b"{\"class\":\"a\"}\n\xff\xfe\n";
        let Ok(t) = tally(bytes, CommandText::Hide) else {
            panic!("reads");
        };
        let mut out = Vec::new();
        assert!(t.write_to(20, &mut out).is_ok());
        assert_eq!(out, b"1\ta\n1\tinvalid\n2\ttotal\n");
    }

    #[test]
    fn commands_are_listed_only_on_request() {
        let log = "{\"class\":\"a\",\"command\":\"ls\\n-l\"}\n\
                   {\"class\":\"a\",\"command\":\"ls\\n-l\"}\n\
                   {\"class\":\"a\",\"command\":\"pwd\"}\n";
        assert!(!run(log, CommandText::Hide, 20).contains("pwd"));
        assert_eq!(
            run(log, CommandText::Show, 20),
            "3\ta\n\t2\t\"ls\\n-l\"\n\t1\t\"pwd\"\n3\ttotal\n"
        );
    }
}
