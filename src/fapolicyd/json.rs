//! The `--format json` document, DESIGN.md §9.1. Pure like the rest of `fapolicyd/`:
//! entries in, bytes out.
//!
//! Every field here is published, so the structs are views over the model and never the
//! model itself: a field added to `WhyRow` or to `check::Key` has to be added here too
//! before anyone sees it. The two report actions share one envelope -- `schema`,
//! `action`, `diagnostics`, `entries` -- so a reader can tell them apart without
//! guessing from the entry shape.

use super::analyze::WhyRow;
use super::check;
use super::model::Diagnostic;
use serde::Serialize;

/// The document version, bumped when a field changes meaning or leaves. `1` is 0.10.0.
const SCHEMA: u32 = 1;

/// The envelope. `entries` is generic because the two actions' entries are the only
/// part that differs, and a second envelope would be a second thing to keep in step.
#[derive(Serialize)]
struct Document<'a, E> {
    schema: u32,
    action: &'a str,
    diagnostics: Vec<Note<'a>>,
    entries: E,
}

/// One diagnostic. The text path writes these as `# rulesteward:` comments ahead of the
/// artifact; in a document they are an array, because a JSON comment does not exist.
/// `artifact` is not serialised: the caller has already filtered by it, so it would say
/// nothing about the entries the reader has.
#[derive(Serialize)]
struct Note<'a> {
    line: Option<usize>,
    msg: &'a str,
}

/// One `why` row as data (§9.1): no verdict string, so the report's wording stays the
/// report's. `text` and `subject_side` are `null` together, when there was no rules file
/// or it did not have that number; `file` is `null` whenever no `rules.d/` component was
/// found to hold the rule, which includes every run that read no rules at all.
#[derive(Serialize)]
struct WhyEntry<'a> {
    rule: usize,
    file: Option<&'a str>,
    text: Option<&'a str>,
    denials: usize,
    subject_side: Option<bool>,
    rules: usize,
    trust: usize,
}

pub fn why(diagnostics: &[Diagnostic], rows: &[WhyRow], compact: bool) -> Vec<u8> {
    let entries: Vec<WhyEntry> = rows
        .iter()
        .map(|row| WhyEntry {
            rule: row.rule,
            // `WhyRow.file` is the empty string when the row was not located, which is
            // an absence and not a filename.
            file: Some(row.file.as_str()).filter(|f| !f.is_empty()),
            text: row.matched.as_ref().map(|r| r.text.as_str()),
            denials: row.denials,
            subject_side: row.matched.as_ref().map(|r| r.refuses),
            rules: row.rules,
            trust: row.trust,
        })
        .collect();
    document("why", diagnostics, entries, compact)
}

pub fn check(diagnostics: &[Diagnostic], entries: Vec<check::Entry>, compact: bool) -> Vec<u8> {
    document("check", diagnostics, entries, compact)
}

/// A record's value as a document carries it (§9.1): the true bytes lossily decoded, and
/// the bytes themselves in hex when they were not UTF-8.
///
/// Not `check::shown`'s octal form. That spelling exists because §9 promises bare lines
/// on stdout and an unescaped newline would write two of them; JSON escapes control
/// characters itself, so the octal would be a second escaping of an already-escaped
/// value. What lossy decoding does destroy is a non-UTF-8 byte, hence the hex sibling.
pub fn lossy_hex(bytes: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), None),
        Err(_) => (
            String::from_utf8_lossy(bytes).into_owned(),
            Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
        ),
    }
}

/// §9.1: `json` is indented and `json-compact` is one line, and both end in exactly one
/// `\n` -- serde writes none, and a document without it is not a line anything can read.
fn document<E: Serialize>(
    action: &str,
    diagnostics: &[Diagnostic],
    entries: E,
    compact: bool,
) -> Vec<u8> {
    let doc = Document {
        schema: SCHEMA,
        action,
        diagnostics: diagnostics
            .iter()
            .map(|d| Note {
                line: d.line,
                msg: &d.msg,
            })
            .collect(),
        entries,
    };
    // Serialising these cannot fail: every field is a number, a bool, a string or an
    // option of one, and serde_json's only other error is an io error the writer does
    // not have. Empty rather than a panic if that reasoning is ever wrong -- the exit
    // code is the run's answer and nothing here is worth aborting it.
    let text = if compact {
        serde_json::to_string(&doc)
    } else {
        serde_json::to_string_pretty(&doc)
    }
    .unwrap_or_default();
    let mut bytes = escaped(&text).into_bytes();
    bytes.push(b'\n');
    bytes
}

/// DEL and the C1 controls as `\u00xx`, which serde_json does not do: it escapes below
/// U+0020 and stops there, so U+007F and U+009B -- CSI on a terminal that honours it --
/// would reach stdout as themselves, while `check::shown` spells exactly those
/// characters for the text report. One rule for both reports.
///
/// A pass over the serialised document rather than a `Formatter`, because outside a
/// string literal serde_json writes only ASCII structure, digits, `true`/`false`/`null`
/// and whitespace: a character in this range is inside a string, where `\u00xx` parses
/// back to the character it replaced and nothing else changes. Parity with `shown` is
/// the whole rule -- a bidi or other format character is raw in the report and raw here.
fn escaped(document: &str) -> String {
    let mut out = String::with_capacity(document.len());
    for c in document.chars() {
        match c {
            '\u{7f}'..='\u{9f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends of the range, and the two characters just outside it: `~` and the
    /// no-break space are ordinary text in the report and stay ordinary here.
    #[test]
    fn del_and_the_c1_controls_are_escaped_and_their_neighbours_are_not() {
        assert_eq!(
            escaped("~\u{7f}\u{9b}\u{9f}\u{a0}"),
            "~\\u007f\\u009b\\u009f\u{a0}"
        );
    }

    /// What serde_json already escaped is text by the time this runs, and a second pass
    /// over `\u001b` must not touch the backslash or re-escape the digits.
    #[test]
    fn an_escape_serde_json_wrote_is_left_alone() {
        assert_eq!(escaped("\"\\u001b\""), "\"\\u001b\"");
    }
}
