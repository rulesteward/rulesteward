//! `sshd_config` parser.
//!
//! # Grounding (`sshd_config(5)`, OpenBSD canonical source)
//! - Line-oriented: each non-comment, non-blank line is `Keyword arg [arg ...]`,
//!   whitespace-separated, no `=`.
//! - Comments are WHOLE-LINE when the first non-blank character is `#`. sshd ALSO
//!   supports whitespace-delimited `#` as an inline end-of-line comment (verified
//!   OpenSSH 9.9p1/10.2p1 `sshd -T`): `Ciphers aes128-cbc # legacy` is a valid
//!   line that loads `aes128-cbc`. This tokenizer does NOT strip inline comments at
//!   the parse layer -- the `#` token and any trailing words are kept as additional
//!   args. Algorithm-list lints (W03/W06) strip a trailing `#`-comment before their
//!   single-arg check via `algo_list_value`; broader parser-level inline-comment
//!   handling for other directives is future work. Blank lines are ignored.
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
///
/// `span` is the byte range of the failing raw line within the source string,
/// matching the running-offset pattern in [`parse_config_str_located`]. File-level
/// errors (line == 0) carry `span = 0..0` because no source byte range exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedParseError {
    pub file: std::path::PathBuf,
    pub line: usize,
    pub message: String,
    pub span: std::ops::Range<usize>,
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
                    span: span.clone(),
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
                    span: span.clone(),
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
/// consumed at the keyword/value boundary. Argument values honor OpenSSH
/// `argv_split` quoting (single- and double-quote spans, stripped, which may
/// start mid-token) and backslash escapes; see the argument loop below. A `#`
/// glued inside a bareword is literal (`Banner x#y` => `["Banner", "x#y"]`); a
/// whitespace-delimited `#` that starts its own token is kept literally
/// (inline-comment stripping is deferred to the lint layer via `algo_list_value`).
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

    // Remaining arguments: split on unquoted ASCII whitespace, honoring OpenSSH
    // `argv_split` quoting. Separator-class note (grounded on real sshd -T, OpenSSH
    // 10.2p1): sshd's argv_split separates on SPACE/TAB only and keeps other control
    // chars (FF/CR/VT/NBSP) literal mid-token. We use `is_ascii_whitespace`
    // (space/tab/LF/CR/FF), not Unicode `char::is_whitespace()`, for two reasons:
    //   1. lines are split on '\n' keeping a trailing '\r' (parse_config_str_located
    //      uses `.split('\n')`, not `.lines()`), and sshd strips that CRLF '\r'
    //      before argv_split. Treating '\r' as a separator is load-bearing: otherwise
    //      `Ciphers aes128-cbc\r` on a CRLF file tokenizes to `aes128-cbc\r` and MISSES
    //      the weak cipher -- a false negative. (Unicode would strip it too, but also
    //      splits VT/NBSP.)
    //   2. it does NOT split VT/NBSP, matching sshd (the Unicode superset would).
    // It does still split a mid-line FF/CR (sshd keeps those literal) -- a rare
    // over-report on a line sshd rejects anyway, tracked with the other
    // whitespace-class false positives in #389; never a false negative.
    // This is a single `while let Some(c) = chars.next()`
    // state machine: every iteration consumes at least one character via the loop
    // header, so no body/return mutation can leave the shared cursor un-advanced
    // and spin the loop forever (issue #387 -- the prior
    // `while { read_arg(); skip_whitespace() }` delegation could stall into an
    // unbounded token push if a helper stopped advancing; this structurally cannot).
    //
    // Quoting/escape rules, grounded against real `sshd -T` (OpenSSH 10.2p1):
    //   * `"` and `'` each open/close a span; the quote char is stripped, and a
    //     span may start mid-token (`x"a b"y` -> one arg `xa by`). The OTHER quote
    //     char inside a span is literal (`"a'b"` -> `a'b`, `'a"b'` -> `a"b`).
    //   * `\` escapes `"`, `'`, and `\` in any context, plus unquoted ASCII
    //     whitespace (`a\ b` -> one arg `a b`); `\` before anything else (or EOL) is kept
    //     literally (`a\b` -> `a\b`). Inside a span, `\ ` keeps the backslash
    //     (`'a\ b'` -> `a\ b`) since whitespace is not escapable there.
    //   * an unterminated span is an error (`'abc` -> Err), matching sshd rc 255.
    // `=` and `#` are ordinary characters here; inline-comment stripping is a
    // lint-layer concern (`algo_list_value`).
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if quote.is_none() && c.is_ascii_whitespace() {
            if in_token {
                tokens.push(std::mem::take(&mut cur));
                in_token = false;
            }
            continue;
        }
        in_token = true;
        match c {
            '\\' => match chars.next() {
                // Trailing backslash (EOL): kept literally.
                None => cur.push('\\'),
                Some(next) => {
                    let escaped = next == '"'
                        || next == '\''
                        || next == '\\'
                        || (quote.is_none() && next.is_ascii_whitespace());
                    if escaped {
                        cur.push(next);
                    } else {
                        // Not an escape: keep the backslash and the following
                        // char literally (the char is never a quote toggle or an
                        // unquoted-whitespace break here -- those are `escaped`).
                        cur.push('\\');
                        cur.push(next);
                    }
                }
            },
            '"' | '\'' => match quote {
                None => quote = Some(c),
                Some(q) if q == c => quote = None,
                Some(_) => cur.push(c),
            },
            _ => cur.push(c),
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string".to_string());
    }
    if in_token {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Advance past any run of ASCII whitespace (sshd's separator class; matches the
/// argument tokenizer, which uses ASCII whitespace rather than Unicode).
fn skip_whitespace(chars: &mut Peekable<Chars>) {
    while chars.peek().is_some_and(char::is_ascii_whitespace) {
        chars.next();
    }
}

/// Read the keyword token, honoring sshd's keyword-quoting (`strdelim`).
///
/// The keyword ends at unquoted ASCII whitespace or a `=` separator. A double-quote
/// opens a quoted span: the content up to the matching `"` is taken literally (the
/// quote chars removed) and -- unlike the argument tokenizer's `argv_split`, which
/// CONTINUES past a close quote -- the keyword TOKEN ENDS at the closing quote, so
/// any characters after it begin the next token. Grounded on real `sshd -T` (OpenSSH
/// 10.2p1): `"Ciphers"` and `Cip"hers"` both resolve to keyword `Ciphers` and load
/// (rc 0); `Ci"ph"ers` resolves to `Ciph` (then a separate `ers` token) and is
/// rejected (rc 255). Single quotes are NOT special in a keyword (`'Ciphers'` stays
/// literal -> unknown directive, sshd rc 255). An unterminated span consumes the rest
/// of the line (real sshd then silently ignores the line); the partial content is
/// returned and can only classify as an UNKNOWN directive, never a recognized one, so
/// a quoted keyword can never hide a weak algorithm behind an "unknown" verdict (#388).
fn read_keyword(chars: &mut Peekable<Chars>) -> String {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() || c == '=' {
            break;
        }
        if c == '"' {
            // Open a quoted span; the keyword token ends at the closing quote
            // (strdelim), so we return there rather than continuing the outer scan.
            chars.next();
            for d in chars.by_ref() {
                if d == '"' {
                    return s;
                }
                s.push(d);
            }
            // Unterminated span: consumed to end of line.
            return s;
        }
        s.push(c);
        chars.next();
    }
    s
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
    // Drive the walk by the slice iterator itself (no manual index counter): the
    // space-form arm consumes its following value token with a second `next()`.
    // Structural advancement means no loop-counter mutant can stall the cursor and
    // spin this `push` forever (the manual `while i < len; i += 1` form let
    // cargo-mutants synthesize an unbounded-allocation OOM via `i *= 1` / `i -= 1`).
    let mut it = tokens.iter();
    while let Some(token) = it.next() {
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
            let Some(value) = it.next() else {
                return Err(format!("Match criterion '{token}' requires a value"));
            };
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

    // -----------------------------------------------------------------------
    // Quote-concatenation model (issue #348)
    //
    // OpenSSH strips ALL `"` characters from a whitespace-delimited token and
    // concatenates the runs: `"aes128-cbc"#x` is the single arg `aes128-cbc#x`
    // (verified sshd -T OpenSSH 10.2p1). The tests below were RED until the arg
    // tokenizer (then a `read_arg` helper, since inlined into `tokenize_line`) was
    // updated by #348 to consume the whole token (not stop at the first closing
    // quote); they are now GREEN.
    // -----------------------------------------------------------------------

    #[test]
    fn tokenize_line_glued_hash_after_closing_quote_concatenates() {
        // `Ciphers "aes128-cbc"#x` -- `#x` is glued directly to the closing `"`.
        // sshd strips the quotes and sees one token `aes128-cbc#x` (not two args).
        // Grounding: sshd -T -> "Bad SSH2 cipher spec 'aes128-cbc#x'" (rc 255,
        // verified OpenSSH 10.2p1). The concatenation model must yield ONE arg.
        assert_eq!(
            tokenize_line("Ciphers \"aes128-cbc\"#x").unwrap(),
            vec!["Ciphers", "aes128-cbc#x"],
            "glued `#` after closing quote: quote-strip + concatenation yields one arg"
        );
    }

    #[test]
    fn tokenize_line_empty_quoted_prefix_concatenates() {
        // `Ciphers ""aes128-cbc` -- an empty quoted prefix immediately followed
        // by a bareword run. sshd strips the `""` and sees `aes128-cbc` as one
        // token. Grounding: sshd -T loads aes128-cbc (rc 0, verified OpenSSH
        // 10.2p1). The concatenation model must yield ONE arg.
        assert_eq!(
            tokenize_line("Ciphers \"\"aes128-cbc").unwrap(),
            vec!["Ciphers", "aes128-cbc"],
            "empty quoted prefix followed by bareword: concat yields one arg"
        );
    }

    #[test]
    fn tokenize_line_quote_pair_splitting_a_token_concatenates() {
        // `Ciphers "aes128""-cbc"` -- two adjacent quoted runs with no whitespace.
        // sshd strips both quote pairs and concatenates: `aes128` + `-cbc` = `aes128-cbc`.
        // Grounding: sshd -T loads aes128-cbc (rc 0, verified OpenSSH 10.2p1).
        // The concatenation model must yield ONE arg.
        assert_eq!(
            tokenize_line("Ciphers \"aes128\"\"-cbc\"").unwrap(),
            vec!["Ciphers", "aes128-cbc"],
            "adjacent quoted runs with no whitespace: concat yields one arg"
        );
    }

    // -----------------------------------------------------------------------
    // Regression guards: these MUST stay GREEN after the quote-concatenation fix
    // -----------------------------------------------------------------------

    #[test]
    fn tokenize_line_spaced_hash_after_closing_quote_stays_separate() {
        // `Ciphers "aes128-cbc" #x` -- SPACE before `#x`.
        // The space ends the token; `#x` is a separate arg (an inline comment
        // token kept by the tokenizer, stripped at the lint layer). This must
        // NOT be changed by the concatenation fix.
        assert_eq!(
            tokenize_line("Ciphers \"aes128-cbc\" #x").unwrap(),
            vec!["Ciphers", "aes128-cbc", "#x"],
            "spaced `#x` after closing quote: separate token, not concatenated"
        );
    }

    #[test]
    fn tokenize_line_quoted_whitespace_stays_literal() {
        // `Banner "two words"` -- whitespace INSIDE quotes is literal; the
        // quoted span is a single arg `two words`. The concatenation fix must
        // not break quoted-whitespace support.
        assert_eq!(
            tokenize_line("Banner \"two words\"").unwrap(),
            vec!["Banner", "two words"],
            "whitespace inside quotes is literal: one arg"
        );
    }

    // -----------------------------------------------------------------------
    // Backslash-escape semantics (issue #348 regression, grounded against
    // sshd -T OpenSSH 10.2p1 on this machine -- see Step 1 grounding table).
    //
    // Grounded truth table (exact bytes via printf + od -c, then sshd -T):
    //   File bytes    | rc | sshd value  | Semantic
    //   a\"b          |  0 | a"b         | \" -> literal `"`, backslash consumed
    //   /etc/motd\"   |  0 | /etc/motd"  | same, end-of-token
    //   "a\"b"        |  0 | a"b         | \" also escapes inside dquotes
    //   a\\b          |  0 | a\b         | \\ -> literal `\`, one backslash consumed
    //   a\b           |  0 | a\b         | `\` before ordinary char: backslash KEPT
    //   abc\          |  0 | abc\        | trailing `\`: backslash KEPT
    //   "abc          |255 | (error)     | unterminated quote: still rejected
    //   abc\\"        |255 | (error)     | \\ consumed -> lone " opens unterminated quote
    //
    // Escape rule: `\"` and `\\` are two-char escape sequences (backslash consumed).
    // `\` before any other character keeps the backslash literal. The toggle model
    // that omitted backslash handling regressed the `\"` cases to Err (sshd-F01).
    // -----------------------------------------------------------------------

    #[test]
    fn tokenize_line_backslash_quote_bareword_is_accepted() {
        // `Banner a\"b` -- backslash before the quote escapes it; sshd rc 0, value `a"b`.
        // Without backslash handling, the tokenizer would open a quote span at `"` and
        // reach EOL still inside it (unterminated). With `\"` handling, the escaped `"`
        // is a literal in the value, NOT an error.
        assert_eq!(
            tokenize_line("Banner a\\\"b").unwrap(),
            vec!["Banner", "a\"b"],
            "backslash-quote mid-bareword: no error, value has literal quote"
        );
    }

    #[test]
    fn tokenize_line_backslash_quote_end_of_token_is_accepted() {
        // `Banner /etc/motd\"` -- trailing backslash-quote; sshd rc 0, value `/etc/motd"`.
        assert_eq!(
            tokenize_line("Banner /etc/motd\\\"").unwrap(),
            vec!["Banner", "/etc/motd\""],
            "backslash-quote at end of token: no error, value ends with literal quote"
        );
    }

    #[test]
    fn tokenize_line_backslash_quote_inside_dquotes_is_accepted() {
        // `Banner "a\"b"` -- backslash-quote INSIDE dquotes; sshd rc 0, value `a"b`.
        assert_eq!(
            tokenize_line("Banner \"a\\\"b\"").unwrap(),
            vec!["Banner", "a\"b"],
            "backslash-quote inside dquotes: no error, value has literal quote"
        );
    }

    #[test]
    fn tokenize_line_double_backslash_yields_single_backslash() {
        // `Banner a\\b` (file has two literal backslashes); sshd rc 0, value `a\b`.
        // `\\` is an escape sequence: first backslash consumed, second kept.
        assert_eq!(
            tokenize_line("Banner a\\\\b").unwrap(),
            vec!["Banner", "a\\b"],
            "double backslash: yields one literal backslash in value"
        );
    }

    #[test]
    fn tokenize_line_backslash_before_ordinary_char_keeps_backslash() {
        // `Banner a\b` (file has one backslash + b); sshd rc 0, value `a\b`.
        // `\` before an ordinary char is NOT an escape; the backslash is kept.
        assert_eq!(
            tokenize_line("Banner a\\b").unwrap(),
            vec!["Banner", "a\\b"],
            "backslash before ordinary char: backslash kept in value"
        );
    }

    #[test]
    fn tokenize_line_trailing_backslash_kept() {
        // `Banner abc\` (file has trailing backslash); sshd rc 0, value `abc\`.
        assert_eq!(
            tokenize_line("Banner abc\\").unwrap(),
            vec!["Banner", "abc\\"],
            "trailing backslash: kept in value, no error"
        );
    }

    #[test]
    fn tokenize_line_double_backslash_before_quote_is_unterminated() {
        // `Banner abc\\"` (file: two backslashes then a quote); sshd rc 255.
        // `\\` consumes both backslashes (yields `\`), then the lone `"` opens
        // an unterminated quoted string.
        assert!(
            tokenize_line("Banner abc\\\\\"").is_err(),
            "double-backslash before a quote: \\\\ consumed, lone quote -> unterminated"
        );
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

    // -----------------------------------------------------------------------
    // argv_split fidelity (issue #374, implemented)
    //
    // These tests pin the grounded-correct (sshd-faithful) behavior for the
    // tokenizer gaps scoped OUT of #348 and closed in #374 (single-quote
    // quoting, escaped-space, `\'`), implemented by the consuming-state-machine
    // tokenizer in `tokenize_line`. Kept as regression guards.
    //
    // Grounding: real `/usr/sbin/sshd -T` with OpenSSH 10.2p1 (the same binary
    // used for the #348 grounding table).
    //
    //   Input bytes         | rc | sshd value    | Semantic
    //   Banner 'two words'  |  0 | two words     | single-quote quoting: space literal
    //   Banner 'abc         |255 | (error)       | unterminated single-quote -> error
    //   Banner a\ b         |  0 | a b           | escaped-space: backslash-space -> space
    //   Banner a\'b         |  0 | a'b           | backslash-single-quote -> literal '
    // -----------------------------------------------------------------------

    #[test]
    fn tokenize_line_single_quoted_value_is_one_token() {
        // `Banner 'two words'` -- single quotes delimit a span with a literal space.
        // sshd rc 0, value `two words` (grounding: sshd -T OpenSSH 10.2p1).
        // Single-quote quoting is handled since #374 (the faithful argv_split
        // tokenizer); before #374 this yielded `["Banner", "'two", "words'"]`.
        assert_eq!(
            tokenize_line("Banner 'two words'").unwrap(),
            vec!["Banner", "two words"],
            "single-quoted span with space: one arg `two words`"
        );
    }

    #[test]
    fn tokenize_line_unterminated_single_quote_is_error() {
        // `Banner 'abc` -- unterminated single-quote; sshd rc 255 (error).
        // The correct behavior is to return Err, matching sshd's rejection.
        assert!(
            tokenize_line("Banner 'abc").is_err(),
            "unterminated single-quote must be an error"
        );
    }

    #[test]
    fn tokenize_line_escaped_space_outside_quotes_is_literal_space() {
        // `Banner a\ b` (backslash then space) -- escaped space outside quotes.
        // sshd rc 0, value `a b` (grounding: sshd -T OpenSSH 10.2p1).
        // Escaped space is handled since #374; before #374 the `\` was kept literal
        // and the space ended the token, yielding `["Banner", "a\\", "b"]`.
        assert_eq!(
            tokenize_line("Banner a\\ b").unwrap(),
            vec!["Banner", "a b"],
            "backslash-space: produces literal space, one arg"
        );
    }

    #[test]
    fn tokenize_line_backslash_single_quote_yields_literal_quote() {
        // `Banner a\'b` (backslash then single-quote) -- escape sequence.
        // sshd rc 0, value `a'b` (grounding: sshd -T OpenSSH 10.2p1).
        // `\'` is recognized as an escape since #374; before #374 the backslash was
        // kept literally and the `'` treated as ordinary, yielding `a\'b`.
        assert_eq!(
            tokenize_line("Banner a\\'b").unwrap(),
            vec!["Banner", "a'b"],
            "backslash-single-quote: produces literal single-quote in value"
        );
    }

    #[test]
    fn tokenize_line_single_quote_inside_double_span_is_literal() {
        // `Banner "a'b"` -- a single quote inside a double-quoted span is a
        // literal char, NOT a span toggle; sshd rc 0, value `a'b` (grounding:
        // sshd -T OpenSSH 10.2p1). Pins that only the MATCHING quote closes a
        // span (kills the `q == c -> true` close-guard mutant, which would let
        // the `'` close the `"` span and leave the trailing `"` unterminated).
        assert_eq!(
            tokenize_line("Banner \"a'b\"").unwrap(),
            vec!["Banner", "a'b"],
            "single quote inside a double-quoted span is literal"
        );
    }

    #[test]
    fn tokenize_line_double_quote_inside_single_span_is_literal() {
        // `Banner 'a"b'` -- a double quote inside a single-quoted span is a
        // literal char, NOT a span toggle; sshd rc 0, value `a"b` (grounding:
        // sshd -T OpenSSH 10.2p1). The mirror of the case above.
        assert_eq!(
            tokenize_line("Banner 'a\"b'").unwrap(),
            vec!["Banner", "a\"b"],
            "double quote inside a single-quoted span is literal"
        );
    }

    #[test]
    fn tokenize_line_separator_class_is_ascii_whitespace_only() {
        // The tokenizer separates on ASCII whitespace (`is_ascii_whitespace`), not the
        // Unicode `char::is_whitespace()` superset. Grounded on sshd -T OpenSSH 10.2p1:
        // sshd's argv_split keeps VT (U+000B) and NBSP (U+00A0) LITERAL mid-token, so
        // `Ciphers aes128-cbc\u{0b}` is one glued arg sshd REJECTS (rc 255) -- Unicode
        // `is_whitespace()` would wrongly split it and over-report a weak cipher. We
        // match sshd here: VT/NBSP stay in the token.
        assert_eq!(
            tokenize_line("Ciphers aes128-cbc\u{0b}").unwrap(),
            vec!["Ciphers", "aes128-cbc\u{0b}"],
            "vertical-tab is not an sshd separator; stays in the token"
        );
        assert_eq!(
            tokenize_line("Ciphers aes128-cbc\u{a0}").unwrap(),
            vec!["Ciphers", "aes128-cbc\u{a0}"],
            "NBSP is not an sshd separator; stays in the token"
        );
        // Trailing CR (a CRLF line ending, retained because lines are split on '\n',
        // not `.lines()`) IS stripped, matching sshd's CRLF handling. Load-bearing:
        // keeping it would tokenize `aes128-cbc\r` and MISS the weak cipher (a false
        // negative).
        assert_eq!(
            tokenize_line("Ciphers aes128-cbc\r").unwrap(),
            vec!["Ciphers", "aes128-cbc"],
            "trailing CR (CRLF) is stripped; matches sshd, prevents a weak-cipher FN"
        );
    }
}
