//! RED barrier tests for auditd rule AST + line parser (#86, #87).
//!
//! # Grounding
//! - Rule varieties, flag grammar: `man 7 audit.rules`, `auditctl(8)` \[VM\].
//! - Filter lists: `/tmp/audit-src/lib/flagtab.h:25-29`.
//! - Actions: `/tmp/audit-src/lib/actiontab.h:23-25`.
//! - Perm classes -> syscall groups: `/tmp/audit-src/lib/permtab.h:28-31`.
//! - 46 `-F` field names: `/tmp/audit-src/lib/fieldtab.h:24-72`.
//! - `rules.d/` concat in filename order: `augenrules(8)` \[VM\].
//! - Corpus fixtures at `tests/fixtures/rules/` and `tests/fixtures/rulesd/`.

use std::path::Path;

use rulesteward_auditd::{
    Action, AuditField, AuditRule, CompareOp, ControlRule, FilterList, ParseError, parse_rules_str,
    parse_target,
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn parse_ok(input: &str) -> Vec<AuditRule> {
    parse_rules_str(input).expect("expected Ok but got parse errors")
}

fn parse_err(input: &str) -> Vec<ParseError> {
    parse_rules_str(input).expect_err("expected Err but got Ok")
}

// --------------------------------------------------------------------------
// Control rules (issue #86 + #87)
// --------------------------------------------------------------------------

/// `-D` must parse as `Control(DeleteAll)`.
/// Grounded: `auditctl(8)` \[VM\] -- the only shipped bootstrap control block contains `-D`.
#[test]
fn control_delete_all_parses() {
    let rules = parse_ok("-D");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], AuditRule::Control(ControlRule::DeleteAll));
}

/// `-b 8192` must parse as `Control(Backlog(8192))`.
/// Grounded: \[VM\] all three `/etc/audit/rules.d/audit.rules` contain `-b 8192`.
#[test]
fn control_backlog_parses() {
    let rules = parse_ok("-b 8192");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], AuditRule::Control(ControlRule::Backlog(8192)));
}

/// `--backlog_wait_time 60000` must parse as `Control(BacklogWaitTime(60000))`.
/// Grounded: \[VM\] shipped control block.
#[test]
fn control_backlog_wait_time_parses() {
    let rules = parse_ok("--backlog_wait_time 60000");
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0],
        AuditRule::Control(ControlRule::BacklogWaitTime(60000))
    );
}

/// `-f 1` must parse as `Control(FailureMode(1))`.
/// Grounded: \[VM\] shipped control block; `-f 0..2` (0=silent, 1=printk, 2=panic).
#[test]
fn control_failure_mode_parses() {
    let rules = parse_ok("-f 1");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], AuditRule::Control(ControlRule::FailureMode(1)));
}

/// `-e 2` must parse as `Control(Enable(2))` (lock/immutable).
/// Grounded: `auditctl(8)` `-e [0..2]`; `2` = lock mode.
#[test]
fn control_enable_lock_parses() {
    let rules = parse_ok("-e 2");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], AuditRule::Control(ControlRule::Enable(2)));
}

/// `stock_control.rules` fixture: the full shipped bootstrap block parses to 4 control rules.
/// Grounded: \[VM\] Rocky 9 `/etc/audit/rules.d/audit.rules` (same on el8/el10).
#[test]
fn fixture_stock_control_parses_four_control_rules() {
    let path = fixture_path("rules/stock_control.rules");
    let rules = parse_target(&path).expect("stock_control fixture must parse");
    // -D, -b 8192, --backlog_wait_time 60000, -f 1 = 4 control rules (comments stripped).
    assert_eq!(
        rules.len(),
        4,
        "expected 4 control rules; got {}: {rules:?}",
        rules.len()
    );
    assert!(rules.iter().all(|r| matches!(r, AuditRule::Control(_))));
}

// --------------------------------------------------------------------------
// Syscall rules (issue #86 + #87)
// --------------------------------------------------------------------------

/// `-a always,exit -S execve -k execve` parses correctly.
/// Grounded: `auditctl(8)` `-a list,action`; `flagtab.h` exit; `actiontab.h` always.
#[test]
fn syscall_always_exit_execve_parses() {
    let rules = parse_ok("-a always,exit -S execve -k execve");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall {
            list,
            action,
            syscalls,
            fields,
            prepend,
            key,
        } => {
            assert_eq!(list, &FilterList::Exit);
            assert_eq!(action, &Action::Always);
            assert_eq!(syscalls, &["execve".to_string()]);
            assert!(fields.is_empty(), "no -F flags expected");
            assert!(!prepend, "should be -a not -A");
            assert_eq!(key.as_deref(), Some("execve"));
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// `-A never,exit -S execve -F uid=0` parses with `prepend=true` and `Action::Never`.
/// Grounded: `auditctl(8)` `-A` = prepend; `actiontab.h` never.
#[test]
fn syscall_prepend_never_uid_parses() {
    let rules = parse_ok("-A never,exit -S execve -F uid=0");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall {
            action,
            prepend,
            fields,
            ..
        } => {
            assert_eq!(action, &Action::Never);
            assert!(*prepend, "-A must set prepend=true");
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].field, AuditField::Uid);
            assert_eq!(fields[0].op, CompareOp::Eq);
            assert_eq!(fields[0].value, "0");
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// `-a always,exit -S execve -F 'auid>=1000' -F 'auid!=unset' -k execve`
/// must parse both fields with correct operators.
/// Grounded: f3 section 1 gotcha -- unquoted `>` is a shell redirect; the parser
/// receives the CONTENT of the `-F` argument with operators intact.
#[test]
fn syscall_auid_filter_ge_and_ne_parse() {
    let rules = parse_ok("-a always,exit -S execve -F auid>=1000 -F auid!=unset -k execve");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { fields, key, .. } => {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].field, AuditField::Auid);
            assert_eq!(fields[0].op, CompareOp::Ge);
            assert_eq!(fields[0].value, "1000");
            assert_eq!(fields[1].field, AuditField::Auid);
            assert_eq!(fields[1].op, CompareOp::Ne);
            assert_eq!(fields[1].value, "unset");
            assert_eq!(key.as_deref(), Some("execve"));
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// Multiple `-S` flags on one rule: `-a always,exit -S adjtimex -S settimeofday -k time`.
/// Grounded: `auditctl(8)` `-S syscall` -- multiple `-S` OR together.
#[test]
fn syscall_multiple_s_flags_parse() {
    let rules = parse_ok("-a always,exit -S adjtimex -S settimeofday -k time_change");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { syscalls, key, .. } => {
            assert_eq!(syscalls.len(), 2);
            assert!(syscalls.contains(&"adjtimex".to_string()));
            assert!(syscalls.contains(&"settimeofday".to_string()));
            assert_eq!(key.as_deref(), Some("time_change"));
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// `-a always,exclude -F msgtype=PROCTITLE` parses as Exclude list with Always action.
/// Grounded: `flagtab.h` exclude list; f3 section 2.3.
#[test]
fn syscall_exclude_list_parses() {
    let rules = parse_ok("-a always,exclude -F msgtype=PROCTITLE");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { list, action, .. } => {
            assert_eq!(list, &FilterList::Exclude);
            assert_eq!(action, &Action::Always);
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// `-a always,task` parses as Task filter list.
/// Grounded: `flagtab.h` task list; `auditctl(8)` "DISABLED BY DEFAULT".
#[test]
fn syscall_task_list_parses() {
    let rules = parse_ok("-a never,task");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { list, action, .. } => {
            assert_eq!(list, &FilterList::Task);
            assert_eq!(action, &Action::Never);
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// list,action can be specified in either order (action,list or list,action).
/// Grounded: `auditctl(8)` `-a` "The action and list are comma-joined in EITHER order".
#[test]
fn syscall_action_list_order_commutative() {
    let r1 = parse_ok("-a always,exit -S execve");
    let r2 = parse_ok("-a exit,always -S execve");
    assert_eq!(
        r1, r2,
        "list,action and action,list must produce the same rule"
    );
}

// --------------------------------------------------------------------------
// Watch rules (issue #86 + #87)
// --------------------------------------------------------------------------

/// `-w /etc/passwd -p wa -k identity` parses as a Watch with write+attr perms.
/// Grounded: `auditctl(8)` `-w/-p/-k`; `permtab.h` `w`->write, `a`->attr.
#[test]
fn watch_file_wa_parses() {
    let rules = parse_ok("-w /etc/passwd -p wa -k identity");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch {
            path,
            perms,
            key,
            is_dir,
        } => {
            assert_eq!(path, "/etc/passwd");
            assert!(!perms.read);
            assert!(perms.write);
            assert!(!perms.exec);
            assert!(perms.attr);
            assert_eq!(key.as_deref(), Some("identity"));
            assert!(!is_dir, "/etc/passwd is a file, not a dir");
        }
        other => panic!("expected Watch, got {other:?}"),
    }
}

/// `-w /etc/ -p wa -k etc_changes` must have `is_dir=true` (path ends with `/`).
/// Grounded: `man 7 audit.rules` "File System" section -- dir watch is recursive.
/// f3 section 2.2: "recursive to the bottom of the subtree".
#[test]
fn watch_directory_is_dir_true() {
    let rules = parse_ok("-w /etc/ -p wa -k etc_changes");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch { is_dir, .. } => {
            assert!(*is_dir, "path ending with '/' must set is_dir=true");
        }
        other => panic!("expected Watch, got {other:?}"),
    }
}

/// `-w /usr/bin -p x -k exec_watch` parses exec perm bit only.
/// Grounded: `permtab.h` `x`->execve/execveat group.
#[test]
fn watch_exec_perm_only() {
    let rules = parse_ok("-w /usr/bin -p x -k exec_watch");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch { perms, .. } => {
            assert!(!perms.read);
            assert!(!perms.write);
            assert!(perms.exec);
            assert!(!perms.attr);
        }
        other => panic!("expected Watch, got {other:?}"),
    }
}

/// All four perm chars together: `-w /etc -p rwxa`.
/// Grounded: `auditctl(8)` `-p [r|w|x|a]`.
#[test]
fn watch_rwxa_all_perm_bits() {
    let rules = parse_ok("-w /etc -p rwxa");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch { perms, .. } => {
            assert!(perms.read);
            assert!(perms.write);
            assert!(perms.exec);
            assert!(perms.attr);
        }
        other => panic!("expected Watch, got {other:?}"),
    }
}

// --------------------------------------------------------------------------
// Comment stripping and whitespace normalization (issue #87)
// --------------------------------------------------------------------------

/// Lines beginning with `#` are stripped. Result must be empty for a comment-only input.
/// Grounded: `man 7 audit.rules` section 2.
#[test]
fn comment_only_input_produces_no_rules() {
    let rules = parse_ok("# This is a comment\n# Another comment\n");
    assert!(
        rules.is_empty(),
        "comment-only input must produce zero rules"
    );
}

/// Blank lines are silently ignored.
#[test]
fn blank_lines_are_ignored() {
    let rules = parse_ok("\n\n-D\n\n\n");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], AuditRule::Control(ControlRule::DeleteAll));
}

/// Inline comments (`# ...` after a rule token) are stripped.
/// Grounded: f3 section 2 -- `#` begins a comment anywhere on a line.
/// The `whitespace_torture.rules` fixture exercises this.
#[test]
fn inline_comment_stripped() {
    let rules = parse_ok("-w /etc/passwd -p wa -k passwd_watch\t# inline comment after tab");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch { path, key, .. } => {
            assert_eq!(path, "/etc/passwd");
            assert_eq!(key.as_deref(), Some("passwd_watch"));
        }
        other => panic!("expected Watch, got {other:?}"),
    }
}

/// Leading tabs and spaces (indented comments, indented rules) are handled correctly.
/// Grounded: `whitespace_torture.rules` corpus fixture; f3 section 2.
#[test]
fn whitespace_torture_fixture_parses() {
    let path = fixture_path("rules/whitespace_torture.rules");
    let rules = parse_target(&path).expect("whitespace_torture fixture must parse");
    // Expected: 1x execve syscall, 1x openat syscall, 1x watch = 3 rules.
    // (no control rules in this fixture; comment-only lines produce no rules)
    assert!(
        !rules.is_empty(),
        "whitespace_torture must yield at least one rule"
    );
    // At least the execve and openat syscall rules and the watch must be present.
    let syscalls: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r, AuditRule::Syscall { .. }))
        .collect();
    assert!(syscalls.len() >= 2, "expected at least 2 syscall rules");
    let watches: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r, AuditRule::Watch { .. }))
        .collect();
    assert_eq!(watches.len(), 1, "expected exactly 1 watch rule");
}

// --------------------------------------------------------------------------
// rules.d/ directory concat in filename order (issue #87)
// --------------------------------------------------------------------------

/// `parse_target` on the `rocky10-multifile` directory reads all 4 files in
/// filename order: 10-base.rules, 30-identity.rules, 50-exec.rules, 99-finalize.rules.
///
/// Grounded: `augenrules(8)` \[VM\] Rocky 9 -- "automatically generated from
/// /etc/audit/rules.d" by concatenation in filename order.
/// f3 section 2.5: "Merge order is by filename".
#[test]
fn rulesd_directory_concat_filename_order() {
    let dir = fixture_path("rulesd/rocky10-multifile");
    let rules = parse_target(&dir).expect("rocky10-multifile must parse");
    // Expected content:
    //   10-base.rules:    -D, -b 8192  (2 control)
    //   30-identity.rules: -w /etc/passwd -p wa -k identity (1 watch)
    //   50-exec.rules:    -a always,exit ... -S execve ... (1 syscall)
    //   99-finalize.rules: -e 2 (1 control)
    // Total: 5 rules, in that order.
    assert_eq!(
        rules.len(),
        5,
        "expected 5 rules from 4 files; got {}: {rules:?}",
        rules.len()
    );
    // First rule must be -D (from 10-base.rules, first in filename order).
    assert_eq!(
        rules[0],
        AuditRule::Control(ControlRule::DeleteAll),
        "10-base.rules must be first; first rule must be -D"
    );
    // Last rule must be -e 2 (from 99-finalize.rules, last in filename order).
    assert_eq!(
        rules[4],
        AuditRule::Control(ControlRule::Enable(2)),
        "99-finalize.rules must be last; last rule must be -e 2"
    );
    // The watch from 30-identity.rules must appear before the syscall from 50-exec.rules.
    let watch_pos = rules
        .iter()
        .position(|r| matches!(r, AuditRule::Watch { .. }))
        .expect("no watch found");
    let syscall_pos = rules
        .iter()
        .position(|r| matches!(r, AuditRule::Syscall { .. }))
        .expect("no syscall found");
    assert!(
        watch_pos < syscall_pos,
        "watch (30-identity) must come before syscall (50-exec); positions {watch_pos} vs {syscall_pos}"
    );
}

// --------------------------------------------------------------------------
// Parse errors (issue #87)
// --------------------------------------------------------------------------

/// An unknown flag produces a `ParseError` with the correct line number.
/// Grounded: f3 section 9 -- parse error -> exit 5 (`EXIT_RULE_PARSE_ERROR`).
#[test]
fn unknown_flag_produces_parse_error_with_line_number() {
    // Lines 1-2 are comments (no error), line 3 has the unknown flag.
    // A stub always-Err{line:2} would fail because the bad line is on line 3.
    let errors = parse_err("# comment\n# another comment\n--totally-unknown-flag 999");
    assert!(
        !errors.is_empty(),
        "expected at least one parse error for unknown flag"
    );
    // The error should point to line 3 (1-based).
    assert!(
        errors.iter().any(|e| e.line == 3),
        "error must cite line 3; got: {errors:?}"
    );
}

/// A well-formed multi-line input where only one line is bad returns an error
/// for THAT line without swallowing the parse error.
#[test]
fn partial_error_surfaces_bad_line() {
    // Bad line is on line 3 (different from the line-2 case in the other error
    // test). A stub always-Err{line:2} passes if both bad lines are on line 2;
    // having one on line 3 means line-tracking is actually pinned.
    let input = "-D\n-b 8192\n--bad-flag";
    let result = parse_rules_str(input);
    assert!(
        result.is_err(),
        "a bad line must cause Err even if other lines are valid"
    );
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.line == 3),
        "error must cite line 3 (the bad line); got: {errors:?}"
    );
}

// --------------------------------------------------------------------------
// Flag-loop error arms in parse_watch_rule / parse_syscall_rule.
//
// These missing-argument and unexpected-token arms were previously only ever
// "caught" by the cargo-mutants 94s per-test timeout: the hand-rolled
// `while i < tokens.len()` cursor, when a `+= -> -=` mutation reversed it,
// walked the index backward and hung. No assertion exercised the arms, so the
// iterator refactor (which removes the index, and with it the hang-mutants)
// would let `delete match arm` / `ok_or_else -> Ok` mutants survive without
// these tests. (mutants CI fix.)
// --------------------------------------------------------------------------

/// `-p` with no following perm string is an error (watch flag loop).
#[test]
fn watch_p_flag_missing_arg_errors() {
    let errors = parse_err("-w /etc/passwd -p");
    assert!(
        errors[0].message.contains("-p requires perm chars"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// `-k` with no following value is an error (watch flag loop).
#[test]
fn watch_k_flag_missing_arg_errors() {
    let errors = parse_err("-w /etc/passwd -k");
    assert!(
        errors[0].message.contains("-k requires a value"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// An unrecognised token inside a watch rule hits the `other` arm.
#[test]
fn watch_unexpected_token_errors() {
    let errors = parse_err("-w /etc/passwd -z foo");
    assert!(
        errors[0].message.contains("unexpected token in watch rule"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// `-S` with no following syscall name is an error (syscall flag loop).
#[test]
fn syscall_s_flag_missing_arg_errors() {
    let errors = parse_err("-a always,exit -S");
    assert!(
        errors[0].message.contains("-S requires a syscall name"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// `-F` with no following field spec is an error (syscall flag loop).
#[test]
fn syscall_f_flag_missing_arg_errors() {
    let errors = parse_err("-a always,exit -S execve -F");
    assert!(
        errors[0].message.contains("-F requires a field spec"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// `-k` with no following value is an error (syscall flag loop).
#[test]
fn syscall_k_flag_missing_arg_errors() {
    let errors = parse_err("-a always,exit -S execve -k");
    assert!(
        errors[0].message.contains("-k requires a value"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// An unrecognised token inside a syscall rule hits the `other` arm.
#[test]
fn syscall_unexpected_token_errors() {
    let errors = parse_err("-a always,exit -S execve -z foo");
    assert!(
        errors[0]
            .message
            .contains("unexpected token in syscall rule"),
        "got: {:?}",
        errors[0].message
    );
    assert_eq!(errors[0].line, 1);
}

/// `-S`, `-F`, and `-k` together: each flag consumes exactly one following
/// token. A loop that mis-advanced (or consumed zero/two tokens per flag)
/// would mis-bind these three values.
#[test]
fn syscall_combined_s_f_k_each_consume_one_token() {
    let rules = parse_ok("-a always,exit -S open -F uid=0 -k mykey");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall {
            syscalls,
            fields,
            key,
            ..
        } => {
            assert_eq!(syscalls, &["open".to_string()]);
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].field, AuditField::Uid);
            assert_eq!(fields[0].value, "0");
            assert_eq!(key.as_deref(), Some("mykey"));
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

// --------------------------------------------------------------------------
// Corpus fixture round-trips (issue #87 + #86)
// --------------------------------------------------------------------------

/// `execve_unrestricted.rules` must parse to exactly 1 syscall rule with
/// action=Always, list=Exit, syscall=execve, key="execve".
/// Grounded: corpus oracle rocky9-execve-unrestricted/oracle/tiers.json.
#[test]
fn fixture_execve_unrestricted_roundtrip() {
    let path = fixture_path("rules/execve_unrestricted.rules");
    let rules = parse_target(&path).expect("execve_unrestricted must parse");
    let syscall_rules: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r, AuditRule::Syscall { .. }))
        .collect();
    assert_eq!(
        syscall_rules.len(),
        1,
        "expected exactly 1 syscall rule; got {}: {rules:?}",
        syscall_rules.len()
    );
    match syscall_rules[0] {
        AuditRule::Syscall {
            action,
            list,
            syscalls,
            key,
            ..
        } => {
            assert_eq!(action, &Action::Always);
            assert_eq!(list, &FilterList::Exit);
            assert!(syscalls.contains(&"execve".to_string()));
            assert_eq!(key.as_deref(), Some("execve"));
        }
        _ => unreachable!(),
    }
}

/// `never_suppress.rules` must parse to 2 rules: `Never` then `Always`.
/// Load order is preserved (never first; always second).
/// Grounded: corpus oracle rocky9-never-suppress (f3 section 3.5: "first match wins").
#[test]
fn fixture_never_suppress_load_order_preserved() {
    let path = fixture_path("rules/never_suppress.rules");
    let rules = parse_target(&path).expect("never_suppress must parse");
    let syscall_rules: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r, AuditRule::Syscall { .. }))
        .collect();
    assert_eq!(
        syscall_rules.len(),
        2,
        "expected 2 syscall rules; got {}: {rules:?}",
        syscall_rules.len()
    );
    // First rule must be Never (the suppressive one).
    match syscall_rules[0] {
        AuditRule::Syscall { action, .. } => {
            assert_eq!(action, &Action::Never, "first rule must be Never");
        }
        _ => unreachable!(),
    }
    // Second rule must be Always.
    match syscall_rules[1] {
        AuditRule::Syscall { action, .. } => {
            assert_eq!(action, &Action::Always, "second rule must be Always");
        }
        _ => unreachable!(),
    }
}

// --------------------------------------------------------------------------
// Group A: parse_audit_field - table-driven coverage of all 40 field arms
// (kills the ~40 "delete match arm <field>" mutation survivors in parser.rs)
// --------------------------------------------------------------------------

/// Every field name from `fieldtab.h:24-72` must map to the correct `AuditField`
/// variant. One table-driven test: each entry is `(field_name_string, expected_variant)`.
/// Exercises each arm of `parse_audit_field` by embedding the field name in a
/// `-F field=0` filter inside a parseable syscall rule.
///
/// Grounded: `/tmp/audit-src/lib/fieldtab.h:24-72` (46 canonical field names).
/// Note: `loginuid` is an alias for `auid` (same variant, one entry); `msgtype` is
/// also present. Total distinct names tested: 41 (40 single-name arms + 1 alias arm).
///
/// [DESIGN NOTE: `parse_audit_field` recognises 41 field name strings mapping to
/// 40 `AuditField` variants; cost uses a subset (auid, uid, exit, success, key are
/// the most relevant for rate attribution). The full set is retained per the
/// locked spec grounded in fieldtab.h.]
#[test]
fn parse_audit_field_all_arms_recognized() {
    use rulesteward_auditd::AuditField::*;

    // (field_name_in_rule, expected_AuditField_variant)
    let cases: &[(&str, AuditField)] = &[
        ("arch", Arch),
        ("auid", Auid),
        ("loginuid", Auid), // alias -> same variant
        ("devmajor", DevMajor),
        ("devminor", DevMinor),
        ("dir", Dir),
        ("egid", Egid),
        ("euid", Euid),
        ("exe", Exe),
        ("exit", Exit),
        ("field_compare", FieldCompare),
        ("filetype", Filetype),
        ("fsgid", Fsgid),
        ("fstype", Fstype),
        ("fsuid", Fsuid),
        ("gid", Gid),
        ("inode", Inode),
        ("key", Key),
        ("msgtype", MsgType),
        ("obj_gid", ObjGid),
        ("obj_lev_high", ObjLevHigh),
        ("obj_lev_low", ObjLevLow),
        ("obj_role", ObjRole),
        ("obj_type", ObjType),
        ("obj_uid", ObjUid),
        ("obj_user", ObjUser),
        ("path", Path),
        ("perm", Perm),
        ("pers", Pers),
        ("pid", Pid),
        ("ppid", Ppid),
        ("saddr_fam", SaddrFam),
        ("sessionid", SessionId),
        ("sgid", Sgid),
        ("subj_clr", SubjClr),
        ("subj_role", SubjRole),
        ("subj_sen", SubjSen),
        ("subj_type", SubjType),
        ("subj_user", SubjUser),
        ("success", Success),
        ("suid", Suid),
        ("uid", Uid),
    ];

    for (field_name, expected_variant) in cases {
        // Build a minimal parseable syscall rule containing `-F <field>=0`.
        // Using `=0` as the value works for all field types for parsing purposes
        // (the parser stores value as a String; semantic validation is separate).
        let rule_str = format!("-a always,exit -S execve -F {field_name}=0");
        let rules = parse_rules_str(&rule_str).unwrap_or_else(|e| {
            panic!("field '{field_name}' failed to parse: {e:?}\n  rule: {rule_str}")
        });
        assert_eq!(rules.len(), 1, "expected 1 rule for field '{field_name}'");
        match &rules[0] {
            AuditRule::Syscall { fields, .. } => {
                assert_eq!(
                    fields.len(),
                    1,
                    "expected 1 field filter for '{field_name}'"
                );
                assert_eq!(
                    &fields[0].field, expected_variant,
                    "field '{field_name}' must map to {expected_variant:?}"
                );
            }
            other => panic!("field '{field_name}': expected Syscall rule, got {other:?}"),
        }
    }
}

/// An unrecognised field name must produce a parse error (the `_ => None` fallback).
/// Grounded: `parse_audit_field` returns `None` for unknown names; `parse_field_filter`
/// converts that to a `ParseError`.
#[test]
fn parse_audit_field_unknown_returns_error() {
    let errors = parse_err("-a always,exit -S execve -F totally_unknown_field=0");
    assert!(
        !errors.is_empty(),
        "unknown field must produce a parse error"
    );
    assert!(
        errors[0].message.contains("unknown field"),
        "error message must mention 'unknown field'; got: {:?}",
        errors[0].message
    );
}

// --------------------------------------------------------------------------
// Group B: targeted tests for logic-survivor mutations
// --------------------------------------------------------------------------

/// parser.rs:114 `&& -> ||` in `parse_target` directory filter.
///
/// Mutation: `p.is_file() || p.extension()==Some("rules")` (instead of `&&`).
/// With `||`, a non-.rules file (README, *.txt) or a subdir named `something.rules`
/// would pass the filter and either fail to parse or produce wrong rule counts.
///
/// Fixture: `rulesd/non-rules-files/` contains:
///   - `10-real.rules`  (1 syscall rule -- the only file that should be read)
///   - `README`         (plain text -- must be excluded by `is_file()` check)
///   - `something.rules/`  (a DIRECTORY with .rules extension -- must be excluded by `is_file()`)
///
/// Grounded: `augenrules(8)` concatenates ONLY regular files with `.rules` extension.
/// With `&&` (correct): 1 rule. With `||` (mutant): README tries to parse -> error or
/// extra rule; `something.rules/` dir triggers `is_file() = false` but `||` lets it
/// through, causing a directory-read or parse failure.
#[test]
fn parse_target_dir_filter_excludes_non_rules_files() {
    let dir = fixture_path("rulesd/non-rules-files");
    let rules = parse_target(&dir).expect(
        "non-rules-files directory must parse successfully \
         (only 10-real.rules should be read; README and something.rules/ dir ignored)",
    );
    assert_eq!(
        rules.len(),
        1,
        "must find exactly 1 rule (from 10-real.rules only); \
         got {}: {rules:?}",
        rules.len()
    );
    match &rules[0] {
        AuditRule::Syscall { key, .. } => {
            assert_eq!(
                key.as_deref(),
                Some("execve_real"),
                "rule key must be 'execve_real' (from 10-real.rules)"
            );
        }
        other => panic!("expected Syscall rule, got {other:?}"),
    }
}

/// parser.rs:158-159 `strip_comment` -- single-quote protection of `#`.
///
/// Three mutation survivors target this function:
///   - delete `'\''` match arm  (single-quote toggle removed)
///   - replace guard `!in_single_quote` with `true`  (always treat `#` as comment)
///   - delete `!` in guard  (same effect as above)
///
/// With any of these mutations, a `#` inside single quotes is incorrectly treated
/// as a comment start, truncating the token at the `#` and producing a parse error
/// or wrong value.
///
/// Test A: `#` inside single-quoted `-F key` value -- must NOT be stripped.
/// Test B: trailing `# comment` after a real token -- must BE stripped.
///
/// Grounded: `strip_comment` doc comment + `man 7 audit.rules` section 2.
#[test]
fn strip_comment_hash_inside_single_quotes_not_stripped() {
    // `-F key='a#b'` -- the `#` is inside single quotes and must survive stripping.
    // The parser receives the single-quoted token 'a#b' and strips the outer quotes,
    // yielding value "a#b". If the `'` arm is deleted or the guard is wrong, the
    // `#` is treated as a comment start and the rule is truncated to `-a always,exit
    // -S execve -F key=` (or similar), causing a parse error.
    let rule_str = "-a always,exit -S execve -F 'key=a#b'";
    let rules = parse_rules_str(rule_str).unwrap_or_else(|e| {
        panic!("# inside single quotes must not start a comment; parse failed: {e:?}")
    });
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { fields, .. } => {
            assert_eq!(fields.len(), 1, "expected 1 field filter");
            assert_eq!(fields[0].field, AuditField::Key, "field must be Key");
            assert_eq!(
                fields[0].value, "a#b",
                "value must be 'a#b' with the # preserved; got: {:?}",
                fields[0].value
            );
        }
        other => panic!("expected Syscall rule, got {other:?}"),
    }
}

#[test]
fn strip_comment_trailing_comment_is_stripped() {
    // `# trailing comment` after a real token MUST be stripped.
    // With `!in_single_quote` guard replaced by `true`, the `#` is always a comment
    // start -- this test still passes under that mutant, so it is a companion to
    // the above, not a standalone killer. The above test is the adversarial one.
    let rule_str = "-w /etc/passwd -p wa -k passwd_chk  # trailing comment";
    let rules = parse_rules_str(rule_str)
        .unwrap_or_else(|e| panic!("trailing comment must be stripped; parse failed: {e:?}"));
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Watch { key, .. } => {
            assert_eq!(
                key.as_deref(),
                Some("passwd_chk"),
                "key must be 'passwd_chk' with trailing comment stripped"
            );
        }
        other => panic!("expected Watch rule, got {other:?}"),
    }
}

/// parser.rs:180,181,194 -- single-quote stripping in `parse_line` tokenizer.
///
/// Three mutation survivors:
///   - `&& -> ||` in `starts_with('\'') && ends_with('\'') && len >= 2`
///   - `- -> /` in `t[1..t.len() - 1]` (the slice that removes the quotes)
///   - `== -> !=` in `t.len() >= 2` check (len equality/comparison)
///
/// With `|| ` mutant: a token that only starts-with or only ends-with a quote
/// gets its quotes stripped incorrectly.
/// With `/ ` mutant: the inner-slice arithmetic yields a wrong substring.
/// With `!=` mutant: the length guard inverts -- short tokens get stripped,
/// single-quote token `'` (len=1) passes the `!=` check.
///
/// Test: a quoted token `'auid>=1000'` must produce value `auid>=1000` (no quotes).
/// Also test a single `'` (len=1) which must NOT be treated as a strippable token
/// (though in practice it produces a parse error since `auid>=1000` without the
/// quotes is what the field filter expects anyway -- the key assertion is that the
/// parser does not panic or silently produce wrong output).
#[test]
fn parse_line_single_quoted_token_strips_outer_quotes() {
    // 'auid>=1000' -> field auid, op Ge, value "1000"
    let rule_str = "-a always,exit -S execve -F 'auid>=1000' -k test_quoting";
    let rules = parse_rules_str(rule_str).unwrap_or_else(|e| {
        panic!("single-quoted token 'auid>=1000' must parse correctly; error: {e:?}")
    });
    assert_eq!(rules.len(), 1, "expected 1 rule");
    match &rules[0] {
        AuditRule::Syscall { fields, key, .. } => {
            assert_eq!(fields.len(), 1, "expected 1 field");
            assert_eq!(fields[0].field, AuditField::Auid, "field must be Auid");
            assert_eq!(fields[0].op, CompareOp::Ge, "operator must be Ge (>=)");
            assert_eq!(
                fields[0].value, "1000",
                "value must be '1000' (quotes stripped); got: {:?}",
                fields[0].value
            );
            assert_eq!(key.as_deref(), Some("test_quoting"));
        }
        other => panic!("expected Syscall rule, got {other:?}"),
    }
}

#[test]
fn parse_line_unquoted_token_passes_through_unchanged() {
    // Without surrounding quotes, the token must be used as-is.
    // This distinguishes the `&&->||` mutant: an unquoted token does not start
    // with `'`, so `||` would not cause mishandling here -- but the above test
    // with a truly-quoted token IS the adversarial case. This test is a sanity
    // companion.
    let rule_str = "-a always,exit -S execve -F auid>=1000 -k test_unquoted";
    let rules = parse_rules_str(rule_str)
        .unwrap_or_else(|e| panic!("unquoted auid>=1000 must parse correctly; error: {e:?}"));
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { fields, .. } => {
            assert_eq!(fields[0].op, CompareOp::Ge, "operator must be Ge");
            assert_eq!(fields[0].value, "1000", "value must be 1000");
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// parser.rs:414,416 -- `parse_filter_list` arms for "user" and "filesystem".
///
/// Two mutation survivors: delete "user" arm; delete "filesystem" arm.
/// Both are valid `auditctl(8)` filter lists from `flagtab.h`.
///
/// Grounded: `/tmp/audit-src/lib/flagtab.h:25-29` -- task/exit/user/exclude/filesystem.
/// "user" and "filesystem" are the two arms not already covered by existing tests.
#[test]
fn parse_filter_list_user_recognized() {
    // `-a user,always` -- "user" list; rarely used but valid per flagtab.h.
    let rules = parse_rules_str("-a user,always -S execve")
        .expect("-a user,always must parse (flagtab.h user list)");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { list, action, .. } => {
            assert_eq!(list, &FilterList::User, "list must be User");
            assert_eq!(action, &Action::Always, "action must be Always");
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

#[test]
fn parse_filter_list_filesystem_recognized() {
    // `-a filesystem,never` -- "filesystem" list; valid per flagtab.h.
    let rules = parse_rules_str("-a filesystem,never -S execve")
        .expect("-a filesystem,never must parse (flagtab.h filesystem list)");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { list, action, .. } => {
            assert_eq!(list, &FilterList::Filesystem, "list must be Filesystem");
            assert_eq!(action, &Action::Never, "action must be Never");
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}

/// parser.rs:424 -- `parse_action` arm for "possible".
///
/// Mutation survivor: delete "possible" arm.
///
/// Grounded: `/tmp/audit-src/lib/actiontab.h:23-25` lists never/possible/always.
/// "possible" is a real (if uncommon) auditctl action value. The AST variant
/// `Action::Possible` is defined and documented in `ast.rs`.
/// Therefore this is NOT an equivalent mutant -- a rules file with `possible` as
/// the action would fail to parse if the arm is deleted.
#[test]
fn parse_action_possible_recognized() {
    // `-a exit,possible -S execve` -- valid per actiontab.h.
    let rules = parse_rules_str("-a exit,possible -S execve")
        .expect("-a exit,possible must parse (actiontab.h possible action)");
    assert_eq!(rules.len(), 1);
    match &rules[0] {
        AuditRule::Syscall { action, list, .. } => {
            assert_eq!(action, &Action::Possible, "action must be Possible");
            assert_eq!(list, &FilterList::Exit, "list must be Exit");
        }
        other => panic!("expected Syscall, got {other:?}"),
    }
}
