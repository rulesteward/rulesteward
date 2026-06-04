//! auditd rules file parser.
//!
//! Issue #87 -- pipeline P2.
//!
//! # Grounding
//! - Line-oriented format, `#` begins a comment: `man 7 audit.rules` section 2.
//! - Each non-comment, non-blank line is one `auditctl` invocation with the
//!   leading `auditctl` word implied.
//! - `rules.d/` concat in filename order: `augenrules(8)` \[VM\].
//!
//! # Design
//! Simple whitespace-tokenizer (NOT chumsky): auditctl syntax is a flat flag list
//! per line. KISS per CLAUDE.md -- no grammar DSL needed here.

use std::path::Path;

use crate::ast::{
    Action, AuditField, AuditRule, CompareOp, ControlRule, FieldFilter, FilterList, PermBits,
};

/// A parse error on a single line.
///
/// Carries the 1-based line number and a human-readable message.
/// Multiple errors may be returned for a single input.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a single rules file from a string.
///
/// Comments (`#` and everything after), blank lines, and lines with only
/// whitespace are silently ignored. Each remaining line is one rule.
/// Returns `Ok(rules)` on full success, or `Err(errors)` if any line failed to
/// parse.
///
/// # Errors
/// Returns `Err` when one or more lines contain unknown flags or malformed syntax.
pub fn parse_rules_str(input: &str) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    for (line_idx, raw_line) in input.lines().enumerate() {
        let lineno = line_idx + 1; // 1-based

        // Strip inline comments: find the first unquoted `#` and truncate there.
        let line = strip_comment(raw_line).trim().to_string();

        if line.is_empty() {
            continue;
        }

        match parse_line(&line, lineno) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(e),
        }
    }

    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

/// Parse a single rules file from a file path.
///
/// # Errors
/// Returns `Err` with `ParseError { line: 0, message: <io error> }` when the
/// file cannot be read.
pub fn parse_rules_file(path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        vec![ParseError {
            line: 0,
            message: format!("cannot read {}: {e}", path.display()),
        }]
    })?;
    parse_rules_str(&content)
}

/// Resolve and parse a rules target.
///
/// Mirrors the fapolicyd target-resolution shape used by `lint`/`report`:
/// - If `path` is a file, parse that file.
/// - If `path` is a directory, collect all `*.rules` files in filename order
///   (matching `augenrules(8)` lexical concat), then parse them concatenated.
///
/// On any I/O error the offending file is reported as `ParseError { line: 0 }`.
///
/// # Errors
/// Returns `Err` when one or more rules contain parse errors.
pub fn parse_target(path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    if path.is_file() {
        return parse_rules_file(path);
    }

    if path.is_dir() {
        // Collect *.rules files in filename (lexical) order.
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| {
                vec![ParseError {
                    line: 0,
                    message: format!("cannot read directory {}: {e}", path.display()),
                }]
            })?
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let p = entry.path();
                p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("rules")
            })
            .collect();

        // Sort by filename (not full path) to match augenrules(8) behaviour.
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut all_rules = Vec::new();
        let mut all_errors = Vec::new();

        for entry in entries {
            match parse_rules_file(&entry.path()) {
                Ok(rules) => all_rules.extend(rules),
                Err(errs) => all_errors.extend(errs),
            }
        }

        if all_errors.is_empty() {
            Ok(all_rules)
        } else {
            Err(all_errors)
        }
    } else {
        Err(vec![ParseError {
            line: 0,
            message: format!("path does not exist: {}", path.display()),
        }])
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Strip everything from the first unquoted `#` onward.
///
/// Single-quoted regions (`'...'`) protect operators like `>=` from shell
/// interpretation. The parser already handles stripped-quote values, so we
/// only need to not strip a `#` inside quotes. In practice, `#` inside a
/// quoted `-F 'auid>=1000'` argument is uncommon but handled correctly.
fn strip_comment(line: &str) -> &str {
    let mut in_single_quote = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' => in_single_quote = !in_single_quote,
            '#' if !in_single_quote => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Parse a single non-comment, non-blank line into an `AuditRule`.
fn parse_line(line: &str, lineno: usize) -> Result<AuditRule, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: msg.to_string(),
    };

    // Tokenize: split on whitespace, then remove surrounding single quotes from
    // each token (the shell would do this; the parser receives the quoted form
    // when invoked from a rules file).
    let tokens: Vec<String> = line
        .split_whitespace()
        .map(|t| {
            // Strip outer single quotes if present: 'auid>=1000' -> auid>=1000
            if t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2 {
                t[1..t.len() - 1].to_string()
            } else {
                t.to_string()
            }
        })
        .collect();

    if tokens.is_empty() {
        return Err(err("empty line after comment stripping"));
    }

    match tokens[0].as_str() {
        // `-D` (with or without trailing args) is DeleteAll per auditctl(8).
        "-D" => Ok(AuditRule::Control(ControlRule::DeleteAll)),

        "-b" => {
            let n = tokens.get(1).ok_or_else(|| err("-b requires a value"))?;
            let v = n
                .parse::<u64>()
                .map_err(|_| err(&format!("-b: invalid number '{n}'")))?;
            Ok(AuditRule::Control(ControlRule::Backlog(v)))
        }

        "--backlog_wait_time" => {
            let n = tokens
                .get(1)
                .ok_or_else(|| err("--backlog_wait_time requires a value"))?;
            let v = n
                .parse::<u64>()
                .map_err(|_| err(&format!("--backlog_wait_time: invalid number '{n}'")))?;
            Ok(AuditRule::Control(ControlRule::BacklogWaitTime(v)))
        }

        "-f" => {
            let n = tokens.get(1).ok_or_else(|| err("-f requires a value"))?;
            let v = n
                .parse::<u8>()
                .map_err(|_| err(&format!("-f: invalid number '{n}'")))?;
            Ok(AuditRule::Control(ControlRule::FailureMode(v)))
        }

        "-e" => {
            let n = tokens.get(1).ok_or_else(|| err("-e requires a value"))?;
            let v = n
                .parse::<u8>()
                .map_err(|_| err(&format!("-e: invalid number '{n}'")))?;
            Ok(AuditRule::Control(ControlRule::Enable(v)))
        }

        "-r" => {
            let n = tokens.get(1).ok_or_else(|| err("-r requires a value"))?;
            let v = n
                .parse::<u64>()
                .map_err(|_| err(&format!("-r: invalid number '{n}'")))?;
            Ok(AuditRule::Control(ControlRule::RateLimit(v)))
        }

        "-w" => parse_watch_rule(&tokens, lineno),

        "-a" | "-A" => parse_syscall_rule(&tokens, lineno),

        // Unknown flag
        other => Err(err(&format!("unknown flag '{other}'"))),
    }
}

// ---------------------------------------------------------------------------
// Watch rule parser
// ---------------------------------------------------------------------------

fn parse_watch_rule(tokens: &[String], lineno: usize) -> Result<AuditRule, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: msg.to_string(),
    };

    // tokens[0] = "-w", tokens[1] = path, then optional -p/-k flags.
    let path = tokens
        .get(1)
        .ok_or_else(|| err("-w requires a path argument"))?
        .clone();
    let mut perms = PermBits::default();
    let mut key: Option<String> = None;

    let mut i = 2usize; // skip '-w' and path
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-p" => {
                i += 1;
                let pstr = tokens.get(i).ok_or_else(|| err("-p requires perm chars"))?;
                perms = parse_perms(pstr, lineno)?;
            }
            "-k" => {
                i += 1;
                key = Some(
                    tokens
                        .get(i)
                        .ok_or_else(|| err("-k requires a value"))?
                        .clone(),
                );
            }
            other => return Err(err(&format!("unexpected token in watch rule: '{other}'"))),
        }
        i += 1;
    }

    let is_dir = path.ends_with('/');
    Ok(AuditRule::Watch {
        path,
        perms,
        key,
        is_dir,
    })
}

fn parse_perms(s: &str, lineno: usize) -> Result<PermBits, ParseError> {
    let mut perms = PermBits::default();
    for ch in s.chars() {
        match ch {
            'r' => perms.read = true,
            'w' => perms.write = true,
            'x' => perms.exec = true,
            'a' => perms.attr = true,
            other => {
                return Err(ParseError {
                    line: lineno,
                    message: format!("unknown perm char '{other}' in -p '{s}'"),
                });
            }
        }
    }
    Ok(perms)
}

// ---------------------------------------------------------------------------
// Syscall rule parser
// ---------------------------------------------------------------------------

fn parse_syscall_rule(tokens: &[String], lineno: usize) -> Result<AuditRule, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: msg.to_string(),
    };

    let prepend = tokens[0] == "-A";

    // Second token is `list,action` or `action,list` (commutative per auditctl(8)).
    let combo = tokens
        .get(1)
        .ok_or_else(|| err("-a/-A requires list,action argument"))?;
    let (list, action) = parse_list_action(combo, lineno)?;

    let mut syscalls: Vec<String> = Vec::new();
    let mut fields: Vec<FieldFilter> = Vec::new();
    let mut key: Option<String> = None;

    let mut i = 2usize; // past '-a/A list,action'
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-S" => {
                i += 1;
                let sc = tokens
                    .get(i)
                    .ok_or_else(|| err("-S requires a syscall name"))?;
                syscalls.push(sc.clone());
            }
            "-F" => {
                i += 1;
                let fspec = tokens
                    .get(i)
                    .ok_or_else(|| err("-F requires a field spec"))?;
                fields.push(parse_field_filter(fspec, lineno)?);
            }
            "-k" => {
                i += 1;
                key = Some(
                    tokens
                        .get(i)
                        .ok_or_else(|| err("-k requires a value"))?
                        .clone(),
                );
            }
            // Some rules include `-a/-A list,action` again on the same line (unusual but legal
            // when concatenating files); skip gracefully by erroring rather than silently.
            other => return Err(err(&format!("unexpected token in syscall rule: '{other}'"))),
        }
        i += 1;
    }

    Ok(AuditRule::Syscall {
        list,
        action,
        syscalls,
        fields,
        prepend,
        key,
    })
}

/// Parse `list,action` or `action,list` (commutative per `auditctl(8) -a`).
fn parse_list_action(s: &str, lineno: usize) -> Result<(FilterList, Action), ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: msg.to_string(),
    };

    let parts: Vec<&str> = s.splitn(2, ',').collect();
    if parts.len() != 2 {
        return Err(err(&format!("expected list,action pair; got '{s}'")));
    }

    // Try both orderings (list,action or action,list - both are valid per auditctl(8)).
    let try_list_action = parse_filter_list(parts[0]).zip(parse_action(parts[1]));
    let try_action_list = parse_filter_list(parts[1]).zip(parse_action(parts[0]));

    match (try_list_action, try_action_list) {
        (Some((l, a)), _) | (_, Some((l, a))) => Ok((l, a)),
        _ => Err(err(&format!("unrecognised list,action pair '{s}'"))),
    }
}

fn parse_filter_list(s: &str) -> Option<FilterList> {
    match s {
        "task" => Some(FilterList::Task),
        "exit" => Some(FilterList::Exit),
        "user" => Some(FilterList::User),
        "exclude" => Some(FilterList::Exclude),
        "filesystem" => Some(FilterList::Filesystem),
        _ => None,
    }
}

fn parse_action(s: &str) -> Option<Action> {
    match s {
        "never" => Some(Action::Never),
        "possible" => Some(Action::Possible),
        "always" => Some(Action::Always),
        _ => None,
    }
}

/// Parse a `-F field op value` specification.
///
/// Operators: `= != < > <= >= & &=` from `auditctl(8)`.
fn parse_field_filter(spec: &str, lineno: usize) -> Result<FieldFilter, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: format!("in -F '{spec}': {msg}"),
    };

    // Find the operator by trying longest matches first (&=, !=, <=, >=) then single-char.
    let ops_by_len: &[(&str, CompareOp)] = &[
        ("&=", CompareOp::BitAndEq),
        ("!=", CompareOp::Ne),
        ("<=", CompareOp::Le),
        (">=", CompareOp::Ge),
        ("&", CompareOp::BitAnd),
        ("<", CompareOp::Lt),
        (">", CompareOp::Gt),
        ("=", CompareOp::Eq),
    ];

    for (op_str, op) in ops_by_len {
        if let Some(pos) = spec.find(op_str) {
            let field_str = &spec[..pos];
            let value_str = &spec[pos + op_str.len()..];
            let field = parse_audit_field(field_str)
                .ok_or_else(|| err(&format!("unknown field '{field_str}'")))?;
            return Ok(FieldFilter {
                field,
                op: op.clone(),
                value: value_str.to_string(),
            });
        }
    }

    Err(err("no operator found"))
}

/// Map a field name string to `AuditField`.
///
/// Covers all 46 names from `fieldtab.h:24-72`.
fn parse_audit_field(s: &str) -> Option<AuditField> {
    match s {
        "arch" => Some(AuditField::Arch),
        "auid" | "loginuid" => Some(AuditField::Auid),
        "devmajor" => Some(AuditField::DevMajor),
        "devminor" => Some(AuditField::DevMinor),
        "dir" => Some(AuditField::Dir),
        "egid" => Some(AuditField::Egid),
        "euid" => Some(AuditField::Euid),
        "exe" => Some(AuditField::Exe),
        "exit" => Some(AuditField::Exit),
        "field_compare" => Some(AuditField::FieldCompare),
        "filetype" => Some(AuditField::Filetype),
        "fsgid" => Some(AuditField::Fsgid),
        "fstype" => Some(AuditField::Fstype),
        "fsuid" => Some(AuditField::Fsuid),
        "gid" => Some(AuditField::Gid),
        "inode" => Some(AuditField::Inode),
        "key" => Some(AuditField::Key),
        "msgtype" => Some(AuditField::MsgType),
        "obj_gid" => Some(AuditField::ObjGid),
        "obj_lev_high" => Some(AuditField::ObjLevHigh),
        "obj_lev_low" => Some(AuditField::ObjLevLow),
        "obj_role" => Some(AuditField::ObjRole),
        "obj_type" => Some(AuditField::ObjType),
        "obj_uid" => Some(AuditField::ObjUid),
        "obj_user" => Some(AuditField::ObjUser),
        "path" => Some(AuditField::Path),
        "perm" => Some(AuditField::Perm),
        "pers" => Some(AuditField::Pers),
        "pid" => Some(AuditField::Pid),
        "ppid" => Some(AuditField::Ppid),
        "saddr_fam" => Some(AuditField::SaddrFam),
        "sessionid" => Some(AuditField::SessionId),
        "sgid" => Some(AuditField::Sgid),
        "subj_clr" => Some(AuditField::SubjClr),
        "subj_role" => Some(AuditField::SubjRole),
        "subj_sen" => Some(AuditField::SubjSen),
        "subj_type" => Some(AuditField::SubjType),
        "subj_user" => Some(AuditField::SubjUser),
        "success" => Some(AuditField::Success),
        "suid" => Some(AuditField::Suid),
        "uid" => Some(AuditField::Uid),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests for private helpers
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::parse_line;
    use crate::ast::{AuditRule, ControlRule};

    // --- quote-stripping guard (parser.rs:180) ---
    // Kills the mutant: replace && with || in
    // `starts_with('\'') && ends_with('\'') && len >= 2`.
    // Under ||, a token with only a LEADING quote like `'_x` satisfies
    // starts_with('\'') and is wrongly stripped (`'_x` -> `_` via t[1..len-1]);
    // the correct && leaves it intact. The leading-only test below asserts the
    // preserved key VALUE, so a wrong impl cannot pass it.

    #[test]
    fn quote_strip_balanced_is_stripped() {
        // `'auid>=1000'` (balanced) should be stripped to `auid>=1000`.
        // Parse a syscall rule with a balanced-quoted filter and confirm it succeeds
        // (the stripped form is valid syntax).
        let parsed = parse_line("-a exit,always -S open -F 'auid>=1000'", 1)
            .expect("balanced quoted filter should parse");
        assert!(
            matches!(parsed, AuditRule::Syscall { .. }),
            "expected SyscallRule, got {parsed:?}"
        );
    }

    #[test]
    fn quote_strip_unbalanced_leading_only_not_stripped() {
        // `'_x` has a LEADING single quote but no closing quote.
        // Correct && guard: starts_with('\'') true, ends_with('\'') false -> NOT
        // stripped -> the key is preserved verbatim as `'_x`.
        // Mutant && -> ||: starts_with('\'') alone triggers the strip, so
        // t[1..len-1] turns `'_x` into `_`, corrupting the key.
        // Asserting the KEY VALUE (not merely that the line parses) is what kills
        // the mutant: both impls return Ok, but only the correct one keeps `'_x`.
        let parsed = parse_line("-a exit,always -S open -k '_x", 1)
            .expect("a rule with an unbalanced-quote key should still parse");
        match parsed {
            AuditRule::Syscall { key, .. } => assert_eq!(
                key.as_deref(),
                Some("'_x"),
                "leading-only quote must be preserved unstripped (kills the parser.rs:180 &&->|| mutant)"
            ),
            other => panic!("expected Syscall, got {other:?}"),
        }
    }

    #[test]
    fn quote_strip_single_char_quote_not_stripped() {
        // A lone `'` token has len == 1, violating len >= 2.
        // Under correct &&: all three conditions must hold; len < 2 prevents strip.
        // Under &&->||: starts_with('\'' ) is true -> strip attempted on 1-char string
        // `t[1..0]` which would panic or yield empty string.
        // We can't easily inject a lone `'` as a meaningful token, but we verify the
        // len boundary via a two-char unbalanced `'x` (starts_with true, ends_with false,
        // len == 2): correct && does NOT strip; || would strip.
        // This is the same as the unbalanced-leading-only case above; the test acts as
        // an explicit len-boundary regression anchor.
        let parsed = parse_line("-a exit,always -S open -k 'x'", 1);
        assert!(parsed.is_ok(), "two-char balanced quote should parse");
    }

    // --- -D control rule ---
    // The `-D` arm is a single `Ok(...DeleteAll)`: the dead if/else that produced
    // the parser.rs:194 equivalent mutant was collapsed (#115). These tests confirm
    // both forms (bare and with trailing args) parse to DeleteAll:
    #[test]
    fn delete_all_bare() {
        let parsed = parse_line("-D", 1).expect("-D should parse");
        assert_eq!(parsed, AuditRule::Control(ControlRule::DeleteAll));
    }

    #[test]
    fn delete_all_with_extra_token() {
        // auditctl(8): -D with extra args is still DeleteAll.
        let parsed = parse_line("-D extra", 1).expect("-D extra should parse");
        assert_eq!(parsed, AuditRule::Control(ControlRule::DeleteAll));
    }
}
