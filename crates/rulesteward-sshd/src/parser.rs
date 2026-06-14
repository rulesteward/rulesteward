//! `sshd_config` parser.
//!
//! # Grounding (`sshd_config(5)`, OpenBSD canonical source)
//! - Line-oriented: each non-comment, non-blank line is `Keyword arg [arg ...]`,
//!   whitespace-separated, no `=`.
//! - Comments are WHOLE-LINE only: a line whose first non-blank character is `#`.
//!   There are no inline comments (unlike shell). Blank lines are ignored.
//! - Keywords are case-insensitive; arguments are case-sensitive.
//! - A single `=` separates a keyword from its value (OpenSSH's `strdelim` with
//!   `split_equals`): `MaxAuthTries=4` and `MaxAuthTries = 4` both mean
//!   `maxauthtries 4`. A `=` INSIDE an argument value is literal, though
//!   (`SetEnv FOO=bar` keeps `FOO=bar`), so the delimiter is consumed only at the
//!   keyword/value boundary. Verified against OpenSSH 10.2p1 `sshd -T`.
//! - Arguments with spaces are double-quoted; quoted strings have NO `\n`/`\t`
//!   escapes - literal characters until the closing `"`.
//! - No line continuation - every directive is a single logical line.
//! - `Match <criteria>` opens a conditional block scoping the directives that
//!   follow it until the next `Match` or EOF (positional, no delimiter).
//!
//! # Design
//! Hand-rolled tokenizer (NOT chumsky), mirroring the auditd crate: the grammar
//! is a flat keyword + argument list per line plus positional Match scoping.
//! KISS per CLAUDE.md - no grammar DSL is warranted.

use std::iter::Peekable;
use std::path::Path;
use std::str::Chars;

use crate::ast::{Block, Directive, MatchBlock, MatchCriterion};

/// A parse error with file provenance, mapped to `sshd-F01` by the CLI.
///
/// `line == 0` marks a file-level error (e.g. an unreadable file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedParseError {
    pub file: std::path::PathBuf,
    pub line: usize,
    pub message: String,
}

/// Parse an `sshd_config` file from a string, with file provenance.
///
/// Returns the file's [`Block`] list on success: `blocks[0]` is always the
/// global block (possibly empty), followed by one [`Block::Match`] per `Match`
/// header in source order.
///
/// # Errors
/// Returns `Err` with one [`LocatedParseError`] per malformed line (unterminated
/// quote, a `Match` header with no or incomplete criteria). All errors are
/// accumulated; parsing does not stop at the first.
pub fn parse_config_str_located(
    input: &str,
    file: &Path,
) -> Result<Vec<Block>, Vec<LocatedParseError>> {
    let mut global: Vec<Directive> = Vec::new();
    let mut matches: Vec<MatchBlock> = Vec::new();
    let mut current: Option<MatchBlock> = None;
    let mut errors: Vec<LocatedParseError> = Vec::new();

    // Manual offset walk over `split('\n')` (not `lines()`) so each directive's
    // span is the exact byte range of its raw line. A trailing `\r` is
    // whitespace, so trimming keeps behavior identical to `lines()`.
    let mut offset = 0usize;
    for (idx, raw_line) in input.split('\n').enumerate() {
        let lineno = idx + 1; // 1-based
        let span = offset..offset + raw_line.len();
        offset += raw_line.len() + 1; // +1 for the consumed '\n'

        // Whole-line comment (first non-blank char is `#`) or blank line: skip.
        let trimmed = raw_line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens = match tokenize_line(raw_line) {
            Ok(t) => t,
            Err(message) => {
                errors.push(LocatedParseError {
                    file: file.to_path_buf(),
                    line: lineno,
                    message,
                });
                continue;
            }
        };
        // tokenize_line never yields an empty Vec for a non-blank line (it has at
        // least one non-whitespace run), so `tokens[0]` is the keyword.
        let (keyword, args) = tokens.split_first().expect("non-blank line has a keyword");

        if keyword.eq_ignore_ascii_case("match") {
            // A `Match` header closes any open Match block and opens a new one.
            match parse_criteria(args) {
                Ok(criteria) => {
                    if let Some(prev) = current.take() {
                        matches.push(prev);
                    }
                    current = Some(MatchBlock {
                        criteria,
                        body: Vec::new(),
                        line: lineno,
                        span,
                    });
                }
                Err(message) => errors.push(LocatedParseError {
                    file: file.to_path_buf(),
                    line: lineno,
                    message,
                }),
            }
            continue;
        }

        let directive = Directive {
            keyword: keyword.clone(),
            args: args.to_vec(),
            line: lineno,
            span,
        };
        match current.as_mut() {
            Some(block) => block.body.push(directive),
            None => global.push(directive),
        }
    }

    if let Some(last) = current.take() {
        matches.push(last);
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // Invariant: blocks[0] is always the global block (possibly empty).
    let mut blocks = Vec::with_capacity(1 + matches.len());
    blocks.push(Block::Global(global));
    blocks.extend(matches.into_iter().map(Block::Match));
    Ok(blocks)
}

/// Split one raw directive line into tokens, honoring the OpenSSH `=`
/// keyword/value delimiter and double-quoted arguments.
///
/// A single `=` separating the keyword from its arguments is consumed as a
/// delimiter, directly or with surrounding whitespace (`MaxAuthTries=4` and
/// `MaxAuthTries = 4` both yield `["MaxAuthTries", "4"]`), matching OpenSSH's
/// `strdelim` with `split_equals`. A `=` INSIDE an argument value is literal
/// (`SetEnv FOO=bar` yields `["SetEnv", "FOO=bar"]`), since the delimiter is only
/// consumed at the keyword/value boundary. A `"` is only special at a token
/// boundary (opens a quoted token to the closing `"`); a `#` is never special
/// here (no inline comments).
///
/// # Errors
/// Returns the error message for an unterminated quoted string.
fn tokenize_line(line: &str) -> Result<Vec<String>, String> {
    let mut chars = line.chars().peekable();
    let mut tokens = Vec::new();

    skip_whitespace(&mut chars);
    if chars.peek().is_none() {
        return Ok(tokens);
    }

    // The keyword is the first token; it ends at whitespace or a `=` separator.
    tokens.push(read_keyword(&mut chars));

    // Consume a single `=` keyword/value separator (with surrounding whitespace).
    skip_whitespace(&mut chars);
    if chars.peek() == Some(&'=') {
        chars.next();
        skip_whitespace(&mut chars);
    }

    // Remaining arguments split on whitespace / quotes only (`=` is literal).
    while chars.peek().is_some() {
        tokens.push(read_arg(&mut chars)?);
        skip_whitespace(&mut chars);
    }
    Ok(tokens)
}

/// Advance past any run of whitespace.
fn skip_whitespace(chars: &mut Peekable<Chars>) {
    while chars.peek().is_some_and(|c| c.is_whitespace()) {
        chars.next();
    }
}

/// Read the keyword token: characters up to whitespace or a `=` separator.
///
/// Keywords are never quoted, so `"` is treated as an ordinary keyword character;
/// a malformed quoted keyword is a lint concern, not the tokenizer's.
fn read_keyword(chars: &mut Peekable<Chars>) -> String {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '=' {
            break;
        }
        s.push(c);
        chars.next();
    }
    s
}

/// Read one argument token: a double-quoted string (quotes stripped, no escapes)
/// when it starts with `"`, otherwise a bareword running to the next whitespace
/// (a `=` or `#` inside the bareword is literal).
///
/// # Errors
/// Returns the error message for an unterminated quoted string.
fn read_arg(chars: &mut Peekable<Chars>) -> Result<String, String> {
    if chars.peek() == Some(&'"') {
        chars.next(); // consume the opening quote
        let mut s = String::new();
        for c in chars.by_ref() {
            if c == '"' {
                return Ok(s);
            }
            s.push(c);
        }
        return Err("unterminated quoted string".to_string());
    }
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            break;
        }
        s.push(c);
        chars.next();
    }
    Ok(s)
}

/// Parse the criteria tokens of a `Match` header into `(keyword, values)` pairs.
///
/// Each criterion is either `Keyword=value` (a single token, the `=` form) or
/// `Keyword value` (two tokens, the space form), except `All` (case-insensitive)
/// which takes no value. Each value is comma-split into parts (negation `!` and
/// wildcard `*` are kept verbatim - their meaning is a lint concern).
///
/// # Errors
/// Returns an error if there are no criteria, or a space-form value-taking
/// criterion has no following value.
fn parse_criteria(tokens: &[String]) -> Result<Vec<MatchCriterion>, String> {
    if tokens.is_empty() {
        return Err("Match block requires at least one criterion".to_string());
    }
    let mut criteria = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        i += 1;
        if let Some((keyword, value)) = token.split_once('=') {
            // `Keyword=value[,value...]` form: the value rides the same token.
            criteria.push(MatchCriterion {
                keyword: keyword.to_string(),
                values: value.split(',').map(str::to_string).collect(),
            });
        } else if token.eq_ignore_ascii_case("all") {
            criteria.push(MatchCriterion {
                keyword: token.clone(),
                values: Vec::new(),
            });
        } else {
            // `Keyword value` form: the next token is the value.
            let Some(value) = tokens.get(i) else {
                return Err(format!("Match criterion '{token}' requires a value"));
            };
            i += 1;
            criteria.push(MatchCriterion {
                keyword: token.clone(),
                values: value.split(',').map(str::to_string).collect(),
            });
        }
    }
    Ok(criteria)
}

#[cfg(test)]
mod tests {
    use super::{parse_criteria, tokenize_line};

    #[test]
    fn tokenize_line_splits_on_runs_of_whitespace() {
        assert_eq!(tokenize_line("a   b\tc").unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn tokenize_line_consumes_equals_keyword_separator() {
        assert_eq!(
            tokenize_line("MaxAuthTries=4").unwrap(),
            vec!["MaxAuthTries", "4"]
        );
        assert_eq!(
            tokenize_line("MaxAuthTries = 4").unwrap(),
            vec!["MaxAuthTries", "4"],
            "a spaced `=` is the keyword/value delimiter"
        );
    }

    #[test]
    fn tokenize_line_keeps_equals_inside_an_argument() {
        assert_eq!(
            tokenize_line("SetEnv FOO=bar").unwrap(),
            vec!["SetEnv", "FOO=bar"]
        );
    }

    #[test]
    fn tokenize_line_keeps_hash_inside_a_bare_token() {
        assert_eq!(tokenize_line("Banner x#y").unwrap(), vec!["Banner", "x#y"]);
    }

    #[test]
    fn tokenize_line_errors_on_unterminated_quote() {
        assert!(tokenize_line("Banner \"abc").is_err());
    }

    #[test]
    fn parse_criteria_rejects_empty() {
        assert!(parse_criteria(&[]).is_err());
    }

    #[test]
    fn parse_criteria_all_takes_no_value() {
        let c = parse_criteria(&["All".to_string()]).unwrap();
        assert_eq!(c.len(), 1);
        assert!(c[0].values.is_empty());
    }

    #[test]
    fn parse_criteria_accepts_both_equals_and_space_forms() {
        let eq = parse_criteria(&["User=alice".to_string()]).unwrap();
        assert_eq!(eq[0].keyword, "User");
        assert_eq!(eq[0].values, vec!["alice".to_string()]);
        let sp = parse_criteria(&["User".to_string(), "alice".to_string()]).unwrap();
        assert_eq!(sp[0].keyword, "User");
        assert_eq!(sp[0].values, vec!["alice".to_string()]);
    }
}
