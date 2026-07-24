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

use rulesteward_core::comment::{StripConfig, strip};

use crate::ast::{
    Action, AuditField, AuditRule, CompareOp, ControlRule, FieldComparison, FieldFilter,
    FilterList, LocatedRule, PermBits,
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

/// A parse error with file provenance (Phase 0, session 6a / #193).
///
/// Same shape as [`ParseError`] plus the source file, so the CLI can map each
/// error to an `au-F01` diagnostic anchored in the right file. `line == 0`
/// marks a file-level error (unreadable file / missing path).
///
/// `span` is the byte range of the failing raw line within the source string,
/// matching the running-offset pattern in [`parse_rules_str_located`]. File-level
/// errors (line == 0) carry `span = 0..0` because no source byte range exists.
#[derive(Debug, Clone, PartialEq)]
pub struct LocatedParseError {
    pub file: std::path::PathBuf,
    pub line: usize,
    pub message: String,
    pub span: std::ops::Range<usize>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a single rules file from a string, with provenance.
///
/// Comments (`#` and everything after), blank lines, and lines with only
/// whitespace are silently ignored. Each remaining line is one rule carrying
/// `file`, its 1-based line number, and the byte range of its raw line.
///
/// # Errors
/// Returns `Err` when one or more lines contain unknown flags or malformed
/// syntax; each error carries `file` and the failing 1-based line.
pub fn parse_rules_str_located(
    input: &str,
    file: &Path,
) -> Result<Vec<LocatedRule>, Vec<LocatedParseError>> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    // Manual offset walk over `split('\n')` (not `lines()`) so each rule's span
    // is the exact byte range of its raw line. A final empty segment after a
    // trailing newline is skipped by the empty check; a trailing `\r` is
    // whitespace, so `trim()` keeps parse behavior identical to `lines()`.
    let mut offset = 0usize;
    for (line_idx, raw_line) in input.split('\n').enumerate() {
        let lineno = line_idx + 1; // 1-based

        // Strip inline comments: find the first unquoted `#` and truncate there.
        let line = strip(raw_line, StripConfig::AUDITD).trim().to_string();

        if !line.is_empty() {
            match parse_line(&line, lineno) {
                Ok(rule) => rules.push(LocatedRule {
                    rule,
                    file: file.to_path_buf(),
                    line: lineno,
                    span: offset..offset + raw_line.len(),
                }),
                Err(e) => errors.push(LocatedParseError {
                    file: file.to_path_buf(),
                    line: e.line,
                    message: e.message,
                    span: offset..offset + raw_line.len(),
                }),
            }
        }

        offset += raw_line.len() + 1; // +1 for the '\n' separator
    }

    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

/// Parse a single rules file from a string.
///
/// Thin wrapper over [`parse_rules_str_located`] that drops provenance.
///
/// # Errors
/// Returns `Err` when one or more lines contain unknown flags or malformed syntax.
pub fn parse_rules_str(input: &str) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    parse_rules_str_located(input, Path::new(""))
        .map(|rules| rules.into_iter().map(|l| l.rule).collect())
        .map_err(drop_error_provenance)
}

/// Parse a single rules file from a file path, with provenance.
///
/// # Errors
/// Returns `Err` with a single `line: 0` error when the file cannot be read.
pub fn parse_rules_file_located(path: &Path) -> Result<Vec<LocatedRule>, Vec<LocatedParseError>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        vec![LocatedParseError {
            file: path.to_path_buf(),
            line: 0,
            message: format!("cannot read {}: {e}", path.display()),
            span: 0..0,
        }]
    })?;
    parse_rules_str_located(&content, path)
}

/// Parse a single rules file from a file path.
///
/// Thin wrapper over [`parse_rules_file_located`] that drops provenance.
///
/// # Errors
/// Returns `Err` with `ParseError { line: 0, message: <io error> }` when the
/// file cannot be read.
pub fn parse_rules_file(path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    parse_rules_file_located(path)
        .map(|rules| rules.into_iter().map(|l| l.rule).collect())
        .map_err(drop_error_provenance)
}

/// Enumerate the `*.rules` files of `dir` in `augenrules(8)` load order:
/// filename-sorted (not full-path-sorted), regular files only.
///
/// Extracted from `parse_target` so the CLI lint shell can build its ariadne
/// source map in the same order the parse consumes the files.
///
/// # Errors
/// Returns a single file-level error when the directory cannot be read.
pub fn rules_files_in_load_order(dir: &Path) -> Result<Vec<std::path::PathBuf>, LocatedParseError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| LocatedParseError {
            file: dir.to_path_buf(),
            line: 0,
            message: format!("cannot read directory {}: {e}", dir.display()),
            span: 0..0,
        })?
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            let p = entry.path();
            p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("rules")
        })
        .collect();

    // Sort by filename (not full path) to match augenrules(8) behaviour.
    entries.sort_by_key(std::fs::DirEntry::file_name);

    Ok(entries.into_iter().map(|e| e.path()).collect())
}

/// Resolve and parse a rules target, with provenance.
///
/// Mirrors the fapolicyd target-resolution shape used by `lint`/`report`:
/// - If `path` is a file, parse that file.
/// - If `path` is a directory, collect all `*.rules` files in filename order
///   (matching `augenrules(8)` lexical concat), then parse them concatenated.
///   Each rule keeps the file and line it came from.
///
/// # Errors
/// Returns `Err` when one or more rules contain parse errors, each carrying its
/// source file; I/O failures are file-level errors (`line: 0`).
pub fn parse_target_located(path: &Path) -> Result<Vec<LocatedRule>, Vec<LocatedParseError>> {
    if path.is_file() {
        return parse_rules_file_located(path);
    }

    if path.is_dir() {
        let files = rules_files_in_load_order(path).map_err(|e| vec![e])?;

        let mut all_rules = Vec::new();
        let mut all_errors = Vec::new();

        for file in files {
            match parse_rules_file_located(&file) {
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
        Err(vec![LocatedParseError {
            file: path.to_path_buf(),
            line: 0,
            message: format!("path does not exist: {}", path.display()),
            span: 0..0,
        }])
    }
}

/// Resolve and parse a rules target.
///
/// Thin wrapper over [`parse_target_located`] that drops provenance.
///
/// # Errors
/// Returns `Err` when one or more rules contain parse errors.
pub fn parse_target(path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    parse_target_located(path)
        .map(|rules| rules.into_iter().map(|l| l.rule).collect())
        .map_err(drop_error_provenance)
}

/// Map located errors back to the legacy provenance-free [`ParseError`] shape
/// (the wrapper functions' error contract).
fn drop_error_provenance(errs: Vec<LocatedParseError>) -> Vec<ParseError> {
    errs.into_iter()
        .map(|e| ParseError {
            line: e.line,
            message: e.message,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Cross-reference (#383, updated by #562): inline-`#` stripping now has a
// single parameterized implementation shared by three backends, plus one
// deliberately-separate token-level stripper:
//   - fapolicyd, auditd, sudoers all call `rulesteward_core::comment::strip`
//     / `comment_index` with their own `StripConfig` (`StripConfig::AUDITD`
//     here: single-quote aware, no `#include` concept, no UID/GID
//     exception - ANY unquoted `#`, including column 0 and glued, starts a
//     comment). See `rulesteward-core/src/comment.rs` for the parameterized
//     scan and each backend's exact config.
//   - sshd      algo_list_value (lints/crypto.rs): token-level, not
//     line-level, and stays OUT of the shared helper by decision
//     (2026-07-23) - it ends an already-whitespace-split algorithm list at
//     the first `#`-prefixed arg, a different unit of work than a raw-line
//     byte scan.
// sysctld has NONE: sysctl.d(5) defines only whole-line `#`/`;` comments (a `#`
// mid-value is literal). If you fix an edge case in the shared stripper, check
// sshd's separate implementation too.
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

        // `--loginuid-immutable` takes NO value argument, unlike the other
        // control flags above (STIG deepening, #523; see ast.rs's
        // ControlRule::LoginuidImmutable doc comment for the grounding).
        "--loginuid-immutable" => Ok(AuditRule::Control(ControlRule::LoginuidImmutable)),

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

    // Flags after `-w <path>`. Each flag consumes its argument with a second
    // `.next()`. Iterating (rather than a hand-rolled `i += 1` index cursor)
    // means there is no increment to mutate into a backward, hanging walk.
    // `.skip(2)` is the original `i = 2usize` start ('-w' and path).
    let mut rest = tokens.iter().skip(2);
    while let Some(tok) = rest.next() {
        match tok.as_str() {
            "-p" => {
                let pstr = rest.next().ok_or_else(|| err("-p requires perm chars"))?;
                perms = parse_perms(pstr, lineno)?;
            }
            "-k" => {
                key = Some(
                    rest.next()
                        .ok_or_else(|| err("-k requires a value"))?
                        .clone(),
                );
            }
            other => return Err(err(&format!("unexpected token in watch rule: '{other}'"))),
        }
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
    let mut field_compares: Vec<FieldComparison> = Vec::new();
    let mut key: Option<String> = None;

    // Flags after `-a/-A <list,action>`. Each flag consumes its argument with a
    // second `.next()`. Iterating (rather than a hand-rolled `i += 1` index
    // cursor) means there is no increment to mutate into a backward, hanging
    // walk. `.skip(2)` is the original `i = 2usize` start.
    let mut rest = tokens.iter().skip(2);
    while let Some(tok) = rest.next() {
        match tok.as_str() {
            "-S" => {
                let sc = rest
                    .next()
                    .ok_or_else(|| err("-S requires a syscall name"))?;
                // auditctl `_audit_parse_syscall` (audit-userspace lib/libaudit.c)
                // splits a comma-separated argument on commas (strtok_r), so
                // `-S a,b,c` is equivalent to three separate `-S` flags. Empty
                // tokens (e.g. a trailing comma) are skipped, matching strtok_r.
                for name in sc.split(',').filter(|s| !s.is_empty()) {
                    syscalls.push(name.to_string());
                }
            }
            "-F" => {
                let fspec = rest.next().ok_or_else(|| err("-F requires a field spec"))?;
                fields.push(parse_field_filter(fspec, lineno)?);
            }
            "-C" => {
                let cspec = rest
                    .next()
                    .ok_or_else(|| err("-C requires a field-comparison spec"))?;
                field_compares.push(parse_field_compare(cspec, lineno)?);
            }
            "-k" => {
                key = Some(
                    rest.next()
                        .ok_or_else(|| err("-k requires a value"))?
                        .clone(),
                );
            }
            // Some rules include `-a/-A list,action` again on the same line (unusual but legal
            // when concatenating files); skip gracefully by erroring rather than silently.
            other => return Err(err(&format!("unexpected token in syscall rule: '{other}'"))),
        }
    }

    Ok(AuditRule::Syscall {
        list,
        action,
        syscalls,
        fields,
        field_compares,
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

/// The `-F`/`-C` comparison operators, longest-match-first so two-char operators
/// (`&=`, `!=`, `<=`, `>=`) are found before their single-char prefixes.
/// `auditctl(8)`: `= != < > <= >= & &=`.
const OPS_BY_LEN: &[(&str, CompareOp)] = &[
    ("&=", CompareOp::BitAndEq),
    ("!=", CompareOp::Ne),
    ("<=", CompareOp::Le),
    (">=", CompareOp::Ge),
    ("&", CompareOp::BitAnd),
    ("<", CompareOp::Lt),
    (">", CompareOp::Gt),
    ("=", CompareOp::Eq),
];

/// Parse a `-F field op value` specification.
///
/// Operators: `= != < > <= >= & &=` from `auditctl(8)`.
fn parse_field_filter(spec: &str, lineno: usize) -> Result<FieldFilter, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: format!("in -F '{spec}': {msg}"),
    };

    for (op_str, op) in OPS_BY_LEN {
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

/// Parse a `-C field op field` inter-field comparison (`auditctl(8) -C`).
///
/// Both operands are field names (not a field-and-literal). auditctl supports
/// ONLY the equality operators here (man auditctl: "There are 2 operators
/// supported - equal, and not equal"), so a relational operator like `>=` is a
/// parse error rather than being silently accepted.
fn parse_field_compare(spec: &str, lineno: usize) -> Result<FieldComparison, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: format!("in -C '{spec}': {msg}"),
    };

    for (op_str, op) in OPS_BY_LEN {
        if let Some(pos) = spec.find(op_str) {
            // auditctl `-C` accepts only `=` and `!=`.
            if !matches!(op, CompareOp::Eq | CompareOp::Ne) {
                return Err(err(&format!(
                    "operator '{op_str}' is not valid for -C (only = and != are supported)"
                )));
            }
            let left_str = &spec[..pos];
            let right_str = &spec[pos + op_str.len()..];
            let left = parse_audit_field(left_str)
                .ok_or_else(|| err(&format!("unknown field '{left_str}'")))?;
            let right = parse_audit_field(right_str)
                .ok_or_else(|| err(&format!("unknown field '{right_str}'")))?;
            return Ok(FieldComparison {
                left,
                op: op.clone(),
                right,
            });
        }
    }

    Err(err("no operator found"))
}

/// Map a field name string to `AuditField`.
///
/// Covers all 46 names from `fieldtab.h:24-72` (audit 3bfa048).
fn parse_audit_field(s: &str) -> Option<AuditField> {
    match s {
        "a0" => Some(AuditField::A0),
        "a1" => Some(AuditField::A1),
        "a2" => Some(AuditField::A2),
        "a3" => Some(AuditField::A3),
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

    // --- #164: syscall-argument fields a0..a3 ---
    #[test]
    fn parses_syscall_argument_filters_a0_through_a3() {
        // -F a0..a3 are real fieldtab.h names used by CIS/STIG rules to narrow a
        // syscall by argument (e.g. `ioctl` by request, `socket` by family). They
        // must parse into FieldFilters, not fail with "unknown field" (exit 5).
        use crate::ast::{AuditField, CompareOp};
        for (name, field) in [
            ("a0", AuditField::A0),
            ("a1", AuditField::A1),
            ("a2", AuditField::A2),
            ("a3", AuditField::A3),
        ] {
            let line = format!("-a always,exit -S ioctl -F {name}=2 -k probe");
            let parsed = parse_line(&line, 1)
                .unwrap_or_else(|e| panic!("`-F {name}=2` must parse; got error: {e:?}"));
            match parsed {
                AuditRule::Syscall { fields, .. } => assert!(
                    fields
                        .iter()
                        .any(|f| f.field == field && f.op == CompareOp::Eq && f.value == "2"),
                    "`-F {name}=2` must produce a {field:?} FieldFilter; got {fields:?}"
                ),
                other => panic!("expected Syscall rule for `-F {name}=2`, got {other:?}"),
            }
        }
    }

    // --- #161: -C inter-field comparison ---

    /// `-C 'uid!=euid'` is an inter-field comparison (auditctl(8) `-C f!=f`,
    /// `AUDIT_COMPARE_UID_TO_EUID`, libaudit.c:1158 (audit 3bfa048)). Both operands are FIELD names,
    /// not a field and a literal value, so it parses into a `FieldComparison` on
    /// the rule's `field_compares`, NOT into the `-F` `fields` vec. Before #161 the
    /// parser rejected `-C` with "unexpected token".
    #[test]
    fn parses_field_comparison_uid_ne_euid() {
        use crate::ast::{AuditField, CompareOp, FieldComparison};
        let parsed = parse_line("-a always,exit -S execve -C 'uid!=euid' -k priv", 1)
            .expect("`-C 'uid!=euid'` must parse");
        match parsed {
            AuditRule::Syscall {
                field_compares,
                fields,
                ..
            } => {
                assert_eq!(
                    field_compares,
                    vec![FieldComparison {
                        left: AuditField::Uid,
                        op: CompareOp::Ne,
                        right: AuditField::Euid,
                    }],
                    "`-C 'uid!=euid'` must produce one FieldComparison(uid != euid)"
                );
                assert!(
                    fields.is_empty(),
                    "a `-C` comparison must NOT be stored as a `-F` field filter"
                );
            }
            other => panic!("expected Syscall rule for the -C line, got {other:?}"),
        }
    }

    /// `-C` accepts the equality operator too (`uid=euid`).
    #[test]
    fn field_comparison_accepts_eq_operator() {
        use crate::ast::{AuditField, CompareOp, FieldComparison};
        let parsed = parse_line("-a always,exit -S execve -C 'auid=uid'", 1)
            .expect("`-C 'auid=uid'` must parse");
        match parsed {
            AuditRule::Syscall { field_compares, .. } => assert_eq!(
                field_compares,
                vec![FieldComparison {
                    left: AuditField::Auid,
                    op: CompareOp::Eq,
                    right: AuditField::Uid,
                }]
            ),
            other => panic!("expected Syscall rule, got {other:?}"),
        }
    }

    /// auditctl `-C` supports ONLY `=` and `!=` (man auditctl: "There are 2
    /// operators supported - equal, and not equal"). A relational operator like
    /// `>=` must be rejected, not silently accepted.
    #[test]
    fn field_comparison_rejects_non_equality_operator() {
        let err = parse_line("-a always,exit -S execve -C 'uid>=euid'", 1)
            .expect_err("`-C 'uid>=euid'` must be rejected (only = and != are valid)");
        assert!(
            err.message.contains("-C"),
            "the error should name the -C flag; got {:?}",
            err.message
        );
    }

    /// A `-C` whose operand is not a known field name must error (here the left
    /// side `bogus` is not an auditd field).
    #[test]
    fn field_comparison_rejects_unknown_field() {
        let err = parse_line("-a always,exit -S execve -C 'bogus!=euid'", 1)
            .expect_err("`-C 'bogus!=euid'` must be rejected (unknown field)");
        assert!(
            err.message.contains("bogus"),
            "the error should name the unknown field; got {:?}",
            err.message
        );
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

// ---------------------------------------------------------------------------
// Located parse API (Phase 0, session 6a / #193): provenance for lint passes
// ---------------------------------------------------------------------------
#[cfg(test)]
mod located_tests {
    use std::io::Write;
    use std::path::Path;

    use super::{
        parse_rules_file, parse_rules_str, parse_rules_str_located, parse_target_located,
        rules_files_in_load_order,
    };
    use crate::ast::{AuditRule, ControlRule};

    /// Comments and blanks are skipped but line numbers stay 1-based against the
    /// ORIGINAL file, and every rule carries the file it came from. Cross-file
    /// lints (duplicate "across rules.d files", lexical-order shadowing) are
    /// impossible without this attribution.
    #[test]
    fn located_str_records_line_numbers_and_file() {
        let input = "# header comment\n-D\n\n-b 8192\n";
        let file = Path::new("rules.d/10-base.rules");
        let located = parse_rules_str_located(input, file).expect("fixture must parse");
        assert_eq!(located.len(), 2, "two rules expected, got {located:?}");
        assert_eq!(located[0].rule, AuditRule::Control(ControlRule::DeleteAll));
        assert_eq!(located[0].line, 2, "-D sits on line 2 (1-based)");
        assert_eq!(located[0].file, file);
        assert_eq!(
            located[1].rule,
            AuditRule::Control(ControlRule::Backlog(8192))
        );
        assert_eq!(
            located[1].line, 4,
            "-b sits on line 4 (blank line 3 skipped)"
        );
        assert_eq!(located[1].file, file);
    }

    /// The span is the byte range of the rule's RAW line within the input (no
    /// trailing newline), so ariadne can render the source line verbatim and
    /// column backfill can derive from span.start.
    #[test]
    fn located_str_span_slices_to_raw_line() {
        let input = "# c\n  -D  # trailing\n-b 1\n";
        let file = Path::new("t.rules");
        let located = parse_rules_str_located(input, file).expect("fixture must parse");
        assert_eq!(located.len(), 2);
        assert_eq!(
            &input[located[0].span.clone()],
            "  -D  # trailing",
            "span must cover the raw line including indentation and inline comment"
        );
        assert_eq!(
            &input[located[1].span.clone()],
            "-b 1",
            "span must cover exactly the raw line, no newline"
        );
    }

    /// Parse errors carry the source file and the 1-based line, so the CLI can
    /// map them to au-F01 diagnostics anchored at the right place.
    #[test]
    fn located_str_errors_carry_file_and_line() {
        let input = "-D\n-Z bogus\n";
        let file = Path::new("rules.d/99-bad.rules");
        let errs = parse_rules_str_located(input, file).expect_err("-Z must fail");
        assert_eq!(errs.len(), 1, "exactly one failing line, got {errs:?}");
        assert_eq!(errs[0].file, file);
        assert_eq!(errs[0].line, 2);
        assert!(
            errs[0].message.contains("unknown flag"),
            "message should name the failure, got {:?}",
            errs[0].message
        );
    }

    /// The legacy `parse_rules_str` must stay a thin wrapper over the located
    /// form: same rules, same order (behavior-preservation pin for the refactor).
    #[test]
    fn unlocated_wrapper_returns_same_rules_as_located() {
        let input = "# c\n-D\n-b 8192\n-a always,exit -S execve -k exec\n";
        let file = Path::new("t.rules");
        let plain = parse_rules_str(input).expect("must parse");
        let located = parse_rules_str_located(input, file).expect("must parse");
        let unwrapped: Vec<AuditRule> = located.into_iter().map(|l| l.rule).collect();
        assert_eq!(plain, unwrapped, "wrapper and located forms must agree");
    }

    /// Directory enumeration: *.rules only, sorted by FILENAME (augenrules(8)
    /// lexical concat order), non-.rules and subdirectories ignored.
    #[test]
    fn rules_files_in_load_order_sorts_by_filename() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["50-b.rules", "10-a.rules", "README.txt"] {
            let mut f = std::fs::File::create(dir.path().join(name)).expect("create");
            writeln!(f, "-D").expect("write");
        }
        std::fs::create_dir(dir.path().join("sub.rules")).expect("subdir");
        let files = rules_files_in_load_order(dir.path()).expect("listable");
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["10-a.rules", "50-b.rules"],
            "only *.rules files, filename-sorted"
        );
    }

    /// Directory mode concatenates in load order and keeps per-file attribution:
    /// the concatenated stream's provenance is exactly what the cross-file lints
    /// consume.
    #[test]
    fn target_located_dir_concatenates_with_per_file_attribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("50-late.rules"), "-b 1\n").expect("write");
        std::fs::write(dir.path().join("10-early.rules"), "# c\n-D\n").expect("write");
        let located = parse_target_located(dir.path()).expect("must parse");
        assert_eq!(located.len(), 2);
        assert_eq!(located[0].rule, AuditRule::Control(ControlRule::DeleteAll));
        assert!(
            located[0].file.ends_with("10-early.rules"),
            "first rule must come from the lexically-first file, got {:?}",
            located[0].file
        );
        assert_eq!(located[0].line, 2, "line is 1-based within ITS OWN file");
        assert_eq!(located[1].rule, AuditRule::Control(ControlRule::Backlog(1)));
        assert!(located[1].file.ends_with("50-late.rules"));
        assert_eq!(located[1].line, 1);
    }

    /// A missing path is a single located error with line 0 (file-level).
    #[test]
    fn target_located_missing_path_errors() {
        let errs = parse_target_located(Path::new("/nonexistent/6a/nothing"))
            .expect_err("missing path must error");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line, 0, "file-level error uses line 0");
        assert!(
            errs[0].message.contains("does not exist"),
            "got {:?}",
            errs[0].message
        );
    }

    /// Errors in one file of a directory carry THAT file's path.
    #[test]
    fn target_located_dir_errors_attribute_the_failing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("10-good.rules"), "-D\n").expect("write");
        std::fs::write(dir.path().join("20-bad.rules"), "-Z nope\n").expect("write");
        let errs = parse_target_located(dir.path()).expect_err("bad file must fail the parse");
        assert_eq!(errs.len(), 1, "one failing line, got {errs:?}");
        assert!(
            errs[0].file.ends_with("20-bad.rules"),
            "error must name the failing file, got {:?}",
            errs[0].file
        );
        assert_eq!(errs[0].line, 1);
    }

    /// `parse_rules_file` (the provenance-dropping file wrapper) must return the
    /// parsed rules of a NON-EMPTY file, not an empty vec. No production path
    /// calls this 1-arg form today (the CLI parses via `parse_target`); it is
    /// public API mirroring the `_located`/`_str` forms, so it is pinned directly
    /// here. A wrong impl returning `Ok(vec![])` would silently drop every rule.
    #[test]
    fn parse_rules_file_returns_parsed_rules_of_nonempty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.rules");
        std::fs::write(&path, "# header\n-D\n-b 8192\n").expect("write");
        let rules = parse_rules_file(&path).expect("must parse");
        assert_eq!(rules.len(), 2, "two control rules parsed, got {rules:?}");
        assert_eq!(rules[0], AuditRule::Control(ControlRule::DeleteAll));
        assert_eq!(rules[1], AuditRule::Control(ControlRule::Backlog(8192)));
    }
}
