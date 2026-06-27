//! Crate-level lint tests for `rulesteward-sysctld` v1 (issue #150), authored at
//! the test-author barrier BEFORE the F01/W01 impl. These call the frozen public
//! entry `parser::lint_str(source, path)` directly and are RED against the Phase-0
//! stub (which returns an empty `Vec`): only a correct tokenizer + W01 pass turns
//! them green. Mirrors how `rulesteward-sshd` / `rulesteward-auditd` structure
//! their lint integration tests.
//!
//! # Ground truth (sysctl.d(5) / sysctl.conf(5), re-verified 2026-06-27)
//! * "Empty lines and lines whose first non-whitespace character is '#' or ';' are
//!   ignored." -> whole-line `#`/`;` comments only; a `#` mid-value is part of the
//!   value (no inline comments).
//! * "If a variable assignment is prefixed with a single '-' character, failure to
//!   set the variable [...] will not cause the service to fail." -> a leading `-`
//!   on an assignment is a VALID line.
//! * "A key may be explicitly excluded from being set by any matching glob patterns
//!   by specifying the key name prefixed with a '-' character and not followed by
//!   '='." -> a BARE `-key` (no `=`) is a VALID glob-exclusion line, NOT malformed.
//! * Separator normalization: "If the first separator is a slash, remaining slashes
//!   and dots are left intact. If the first separator is a dot, dots and slashes are
//!   interchanged." The man page's own example: "'kernel.domainname=foo' and
//!   'kernel/domainname=foo' are equivalent". v1 pins the simple rule the spec
//!   permits: NORMALIZE ALL '/' TO '.' for key-identity, so `net/ipv4/ip_forward`
//!   and `net.ipv4.ip_forward` are the SAME key (matches the man-page equivalence).
//!
//! # F01 = parse failure; W01 = last-wins conflict
//! A non-comment, non-blank line that is NOT a bare `-key` glob-exclusion and has
//! NO `=` is malformed -> `sysctld-F01` (Fatal). The LAST assignment of a key wins;
//! an earlier assignment of the SAME key to a DIFFERENT value is dead -> `sysctld-W01`
//! (Warning), anchored at the OVERRIDDEN earlier line (the dead line is the
//! actionable surprise).

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

const PATH: &str = "/etc/sysctl.d/99-test.conf";

fn lint(source: &str) -> Vec<Diagnostic> {
    rulesteward_sysctld::parser::lint_str(source, Path::new(PATH))
}

/// All `sysctld-F01` (Fatal parse-failure) diagnostics in emission order.
fn f01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-F01")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Fatal,
                "sysctld-F01 must be Fatal, got {:?}",
                d.severity
            );
        })
        .collect()
}

/// All `sysctld-W01` (Warning last-wins) diagnostics in emission order.
fn w01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-W01")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sysctld-W01 must be Warning, got {:?}",
                d.severity
            );
        })
        .collect()
}

// ---------------------------------------------------------------------------
// F01 SHOULD fire (malformed lines)
// ---------------------------------------------------------------------------

#[test]
fn f01_fires_on_bare_key_without_equals() {
    // `kernel.dmesg_restrict` - a bare key, no leading `-`, no `=`: not a comment,
    // not blank, not a glob-exclusion -> malformed.
    let diags = lint("kernel.dmesg_restrict\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the bare key: {diags:?}");
    assert_eq!(f[0].line, 1, "F01 anchors at the malformed line");
}

#[test]
fn f01_fires_on_space_separated_assignment() {
    // `net.ipv4.ip_forward 1` - a space is not an assignment separator; without an
    // `=` this line carries no assignment -> malformed.
    let diags = lint("net.ipv4.ip_forward 1\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the space form: {diags:?}");
    assert_eq!(f[0].line, 1);
}

#[test]
fn f01_fires_on_empty_key() {
    // `= 1` - an assignment with an empty key (nothing before `=`) is malformed.
    let diags = lint("= 1\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the empty key: {diags:?}");
    assert_eq!(f[0].line, 1);
}

#[test]
fn f01_anchors_at_the_offending_line_number() {
    // F01 reports the 1-based line of the malformed line, not line 1 blindly: a
    // valid assignment precedes a malformed bare key.
    let diags = lint("kernel.sysrq = 0\nkernel.dmesg_restrict\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "one malformed line on line 2: {diags:?}");
    assert_eq!(f[0].line, 2, "F01 anchors at line 2, the malformed line");
}

// ---------------------------------------------------------------------------
// F01 SHOULD NOT fire (valid lines)
// ---------------------------------------------------------------------------

#[test]
fn f01_does_not_fire_on_semicolon_comment() {
    assert!(
        f01s(&lint("; this is a comment\n")).is_empty(),
        "a `;` whole-line comment is valid, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_hash_comment() {
    assert!(
        f01s(&lint("# this is a comment\n")).is_empty(),
        "a `#` whole-line comment is valid, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_blank_line() {
    assert!(
        f01s(&lint("\n   \n\t\n")).is_empty(),
        "blank / whitespace-only lines are ignored, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_ignore_error_prefixed_assignment() {
    // `-kernel.dmesg_restrict = 1` - a leading `-` on an ASSIGNMENT means "ignore
    // set errors"; it is a valid assignment line.
    assert!(
        f01s(&lint("-kernel.dmesg_restrict = 1\n")).is_empty(),
        "a leading `-` on an assignment is valid (ignore-error prefix)"
    );
}

#[test]
fn f01_does_not_fire_on_bare_glob_exclusion() {
    // `-net.ipv4.conf.eth0.rp_filter` - a `-key` with NO `=` is a valid
    // glob-EXCLUSION line (man page: "prefixed with a '-' character and not
    // followed by '='"), NOT a malformed bare key.
    assert!(
        f01s(&lint("-net.ipv4.conf.eth0.rp_filter\n")).is_empty(),
        "a bare `-key` (no `=`) is a valid glob-exclusion, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_slash_separated_key() {
    // `net/ipv4/ip_forward = 1` - slash separators are valid (interchangeable with
    // dots per sysctl.d(5)).
    assert!(
        f01s(&lint("net/ipv4/ip_forward = 1\n")).is_empty(),
        "slash-separated keys are a valid assignment"
    );
}

#[test]
fn f01_does_not_fire_on_surrounding_whitespace() {
    // `   kernel.sysrq   =   16   ` - arbitrary surrounding whitespace is tolerated.
    assert!(
        f01s(&lint("   kernel.sysrq   =   16   \n")).is_empty(),
        "surrounding whitespace around key/=/value is valid"
    );
}

#[test]
fn f01_does_not_fire_on_glob_key_assignment() {
    // `net.ipv4.conf.*.rp_filter = 1` - a systemd glob key is a valid assignment.
    assert!(
        f01s(&lint("net.ipv4.conf.*.rp_filter = 1\n")).is_empty(),
        "a glob-key assignment is valid"
    );
}

// ---------------------------------------------------------------------------
// W01 SHOULD fire (last-wins conflict)
// ---------------------------------------------------------------------------

#[test]
fn w01_fires_on_within_file_last_wins_conflict() {
    // The same key assigned two DIFFERENT values: the first (=2) is dead, the
    // last (=1) wins -> one W01.
    let source = "kernel.kptr_restrict=2\nkernel.kptr_restrict=1\n";
    let diags = lint(source);
    let w = w01s(&diags);
    assert_eq!(w.len(), 1, "exactly one W01 for the conflict: {diags:?}");

    // PINNED ANCHOR: W01 points at the DEAD/overridden EARLIER assignment (line 1),
    // the actionable surprise - the dead line is what the operator must remove.
    assert_eq!(
        w[0].line, 1,
        "W01 anchors at the overridden earlier line (the dead assignment)"
    );

    // The message names the conflicting key so the operator can identify it.
    assert!(
        w[0].message.contains("kernel.kptr_restrict"),
        "W01 message names the conflicting key; was: {:?}",
        w[0].message
    );
}

#[test]
fn w01_does_not_fire_without_a_conflict_clean_file() {
    // A single assignment of a key has no conflict.
    assert!(
        w01s(&lint("kernel.kptr_restrict = 2\n")).is_empty(),
        "a single assignment is not a conflict"
    );
}

// ---------------------------------------------------------------------------
// W01 SHOULD NOT fire (no real conflict)
// ---------------------------------------------------------------------------

#[test]
fn w01_does_not_fire_on_same_key_same_value() {
    // Same key, SAME value twice: redundant, not a conflict.
    assert!(
        w01s(&lint("net.ipv4.ip_forward=1\nnet.ipv4.ip_forward=1\n")).is_empty(),
        "same key with the same value is redundant, not a W01 conflict"
    );
}

#[test]
fn w01_does_not_fire_on_separator_normalized_same_value() {
    // `net.ipv4.ip_forward` and `net/ipv4/ip_forward` are the SAME key (normalize
    // `/` to `.`); same value -> NO conflict.
    assert!(
        w01s(&lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=1\n")).is_empty(),
        "separator-normalized same key with the same value is not a conflict"
    );
}

#[test]
fn w01_does_not_fire_on_two_different_keys() {
    // Two different keys never conflict, even with different values.
    assert!(
        w01s(&lint("kernel.kptr_restrict=2\nkernel.dmesg_restrict=1\n")).is_empty(),
        "different keys never conflict"
    );
}

#[test]
fn w01_fires_across_separator_normalized_different_values() {
    // The mirror of the same-value case: `net.ipv4.ip_forward` and
    // `net/ipv4/ip_forward` are the SAME key, so DIFFERENT values DO conflict.
    // Pins that normalization is applied for conflict detection, not just for the
    // no-fire path (guards a mutant that skips normalization on the fire side).
    let diags = lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=0\n");
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "separator-normalized same key with DIFFERENT values is one conflict: {diags:?}"
    );
    assert_eq!(w[0].line, 1, "anchors at the overridden earlier line");
}
