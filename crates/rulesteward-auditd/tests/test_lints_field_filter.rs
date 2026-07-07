//! RED barrier tests for au-E04 (field <-> filter-list legality lint) -- issue #269.
//!
//! au-E04 is an Error-tier, load-aborting class: the kernel/auditctl ABORTS the
//! load when a field is used on a filter list that is illegal for that field.
//! This mirrors the au-E03 class (load-aborting duplicate) in severity.
//!
//! The entrypoint being tested is `lints::field_filter::e04(&[LocatedRule])`.
//! It does NOT exist yet -- these tests are RED by construction.
//!
//! # Grounding
//!
//! Primary source: audit-userspace `lib/libaudit.c` function
//! `audit_rule_fieldpair_data`, grounded in:
//! - v3.1.5 (el8/el9): lines 1536-1933
//! - v4.0.3 (el10): lines ~1560-1942
//! Table is identical across 3.1.2 / 3.1.5 / 4.0.3 (byte-diff clean); one
//! table, no per-version branch needed.
//!
//! Live differential: auditctl -R in --cap-add containers (fapolicyd9:latest,
//! fapolicyd10:latest) and a live rocky10 VM read-only.
//!
//! Full grounding doc:
//! /home/runner/rulesteward-docs/research-notes/overnight/2026-06-17/depth-auditd-fieldtable.md
//!
//! # EAU_* error codes from the live differential
//!
//! | code | kernel rejection |
//! |------|----------------|
//! | EAU_EXITONLY        | `<field> can only be used with exit filter list` |
//! | EAU_MSGTYPEEXCLUDEUSER | `msgtype field can only be used with exclude or user filter list` |
//! | EAU_FIELDUNAVAIL    | `<field> field is not valid for the filter` (fstype off fs list) |
//! | EAU_FIELDNOFILTER   | `<field> must be used with exclude, user, or exit filter` (sessionid) |
//!
//! # Scope corrections (MUST stay clean - a wrong impl fires on these)
//!
//! - `obj_uid`/`obj_gid` are NOT exit-only: they live in the uid/gid arm
//!   (libaudit.c:1641 v3.1.5) which carries NO list guard. AUD-1 over-claimed.
//! - `perm` is legal on exit OR exclude (not exit-only).
//! - `sessionid` is legal on exclude/user/exit (three lists).
//! - Two feature-gated whitelists (MSGTYPECREDEXCLUDE + FS-support) are
//!   NOT flagged by au-E04 (kernel-state-dependent, static linter cannot decide).

// The doc tables above use bare kernel error-code tokens (EAU_EXITONLY, etc.),
// all-caps identifiers, and hand-drawn table continuation lines for readability;
// suppress the doc-formatting lints for this test file (matches the selinux
// guard-test convention) rather than backticking/reindenting each token.
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use std::path::Path;

use rulesteward_auditd::{lints::field_filter::e04, parse_rules_str_located, parse_target_located};
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers (mirror the au-E03 / au-E02 test conventions)
// ---------------------------------------------------------------------------

fn fixture_dir(scenario: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lints/field_filter")
        .join(scenario)
}

/// Parse a single inline rule string for a synthetic file path.
fn located_inline(input: &str) -> Vec<rulesteward_auditd::LocatedRule> {
    let file = Path::new("/etc/audit/rules.d/99-test.rules");
    parse_rules_str_located(input, file).expect("fixture must parse")
}

/// Run e04 on inline input and return diagnostics.
fn lint_inline(input: &str) -> Vec<rulesteward_core::Diagnostic> {
    e04(&located_inline(input))
}

/// Run e04 against a fixture directory and return diagnostics.
fn lint_fixture(scenario: &str) -> Vec<rulesteward_core::Diagnostic> {
    let dir = fixture_dir(scenario);
    let rules = parse_target_located(&dir).expect("fixture must parse");
    e04(&rules)
}

/// Assert that e04 produces no diagnostics (legal control).
fn assert_clean(diags: &[rulesteward_core::Diagnostic], context: &str) {
    assert!(
        diags.is_empty(),
        "expected no au-E04 for {context}, got: {diags:#?}"
    );
}

/// Assert that e04 produces exactly one au-E04 Error diagnostic.
fn assert_one_e04(diags: &[rulesteward_core::Diagnostic], context: &str) {
    assert_eq!(
        diags.len(),
        1,
        "expected exactly 1 au-E04 for {context}, got: {diags:#?}"
    );
    let d = &diags[0];
    assert_eq!(
        d.severity,
        Severity::Error,
        "au-E04 must be Error (load-aborting, mirrors au-E03): {context}"
    );
    assert_eq!(d.code, "au-E04", "code must be au-E04: {context}");
    assert_eq!(d.column, 1, "auditd convention: column is always 1");
}

// ===========================================================================
// ILLEGAL cases - each must fire exactly one au-E04 Error
// ===========================================================================

// ---------------------------------------------------------------------------
// T1: perm on task filter list
//
// perm is legal only on exit or exclude (libaudit.c:1803-1805 v3.1.5).
// task list -> EAU_EXITONLY -> auditctl -R aborts.
// Live: "-a always,user -F perm=r" => "perm can only be used with exit filter list"
// Adversarial: a trivial impl that never checks any restriction would MISS this.
// A wrong impl that treats perm as exit-only (not exit+exclude) would fire on
// exclude too -- see legal-control T6 below.
// ---------------------------------------------------------------------------
#[test]
fn perm_on_task_fires_one_e04() {
    let diags = lint_fixture("perm-on-task");
    assert_one_e04(&diags, "perm on task filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("perm"),
        "message must name the field 'perm', got: {:?}",
        d.message
    );
    assert!(
        d.message.to_lowercase().contains("task") || d.message.to_lowercase().contains("exit"),
        "message must reference the list or legal lists, got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T2: msgtype on exit filter list
//
// msgtype is legal only on exclude or user (libaudit.c:1698-1701 v3.1.5).
// exit list -> EAU_MSGTYPEEXCLUDEUSER -> auditctl -R aborts.
// Live: "-a always,exit -S open -F msgtype=AVC" => rejected.
// Adversarial: an impl that only applies EAU_EXITONLY guards misses msgtype's
// distinct restriction (MSGTYPEEXCLUDEUSER: legal on a different set of lists).
// ---------------------------------------------------------------------------
#[test]
fn msgtype_on_exit_fires_one_e04() {
    let diags = lint_fixture("msgtype-on-exit");
    assert_one_e04(&diags, "msgtype on exit filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("msgtype"),
        "message must name the field 'msgtype', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T3: filetype on user filter list
//
// filetype is legal only on exit (libaudit.c:1844-1845 v3.1.5).
// user list -> EAU_EXITONLY.
// Live: "filetype can only be used with exit filter list".
// ---------------------------------------------------------------------------
#[test]
fn filetype_on_user_fires_one_e04() {
    let diags = lint_fixture("filetype-on-user");
    assert_one_e04(&diags, "filetype on user filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("filetype"),
        "message must name the field 'filetype', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T4: sessionid on task filter list
//
// sessionid is legal on exclude, user, or exit (libaudit.c:1884-1887 v3.1.5).
// task list -> EAU_FIELDNOFILTER.
// Source-confirmed (the FIELDNOFILTER list guard is unconditional in code;
// the live container blocked it earlier via the feature-flag guard, but the
// list guard still applies when the kernel has AUDIT_FEATURE_BITMAP_SESSIONID_FILTER).
// Adversarial: an impl unaware of the FIELDNOFILTER set (exclude/user/exit) would
// wrongly classify task as legal (task is not in the legal set).
// ---------------------------------------------------------------------------
#[test]
fn sessionid_on_task_fires_one_e04() {
    let diags = lint_fixture("sessionid-on-task");
    assert_one_e04(&diags, "sessionid on task filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("sessionid")
            || d.message.to_lowercase().contains("session"),
        "message must name the field 'sessionid', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T5: dir on user filter list (watch/dir exit-only arm)
//
// dir is legal only on exit (libaudit.c:1719-1724 v3.1.5, watch/object arm).
// user list -> EAU_EXITONLY.
// Live: "dir can only be used with exit filter list".
// Adversarial: the watch/dir arm covers a DIFFERENT set of fields from the
// named exit-only fields (exit, success, devmajor/devminor/inode, ppid, filetype).
// An impl that only checks those named fields would miss dir.
// ---------------------------------------------------------------------------
#[test]
fn dir_on_user_fires_one_e04() {
    let diags = lint_fixture("dir-on-user");
    assert_one_e04(&diags, "dir on user filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("dir"),
        "message must name the field 'dir', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T5b: obj_user on user filter list (STRING obj exit-only arm)
//
// obj_user is one of the STRING obj fields (obj_user/obj_role/obj_type/
// obj_lev_low/obj_lev_high) that are exit-only (libaudit.c:1714-1724 v3.1.5).
// user list -> EAU_EXITONLY.
// Live: "obj_user can only be used with exit filter list".
// Adversarial: must distinguish STRING obj fields (exit-only) from NUMERIC
// obj fields (obj_uid/obj_gid, no guard). A wrong impl that treats ALL obj_*
// as exit-only would pass T5b but INCORRECTLY fire on T8/T9 (obj_uid on
// exit/user) which are legal controls.
// ---------------------------------------------------------------------------
#[test]
fn obj_user_on_user_fires_one_e04() {
    let rules = located_inline("-a always,user -F obj_user=system_u -k test-obj-user");
    let diags = e04(&rules);
    assert_one_e04(&diags, "obj_user on user filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("obj_user") || d.message.to_lowercase().contains("obj"),
        "message must name the field, got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T5c: additional exit-only fields (inline) - ppid and success on user
//
// ppid: EAU_EXITONLY default arm (libaudit.c:1917-1918 v3.1.5).
// success: EAU_EXITONLY DEVMAJOR..INODE+SUCCESS arm (libaudit.c:1906-1908 v3.1.5).
// These two are named in the grounding table but not in the primary fixture set;
// inline tests confirm the table covers them.
// ---------------------------------------------------------------------------
#[test]
fn ppid_on_user_fires_one_e04() {
    let diags = lint_inline("-a always,user -F ppid=1 -k test-ppid");
    assert_one_e04(&diags, "ppid on user filter list");
    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("ppid"),
        "message must name 'ppid', got: {:?}",
        d.message
    );
}

#[test]
fn success_on_task_fires_one_e04() {
    let diags = lint_inline("-a always,task -F success=1 -k test-success");
    assert_one_e04(&diags, "success on task filter list");
    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("success"),
        "message must name 'success', got: {:?}",
        d.message
    );
}

// ===========================================================================
// LEGAL controls - au-E04 must NOT fire on these (allRed property)
// ===========================================================================

// ---------------------------------------------------------------------------
// T6: perm on exit filter list - MUST NOT fire
//
// perm is legal on exit OR exclude (not exit-only).
// Scope correction: the naive reading of EAU_EXITONLY would suggest exit-only,
// but libaudit.c:1803-1805 gates on !(EXIT || EXCLUDE), so both are legal.
// Live-confirmed: "-a always,exit -S open -F perm=r" passes userspace.
// Adversarial: an impl that treats perm as exit-only (guarding only on exit)
// would pass this test but fire incorrectly on T7 (perm on exclude).
// ---------------------------------------------------------------------------
#[test]
fn perm_on_exit_must_not_fire() {
    let diags = lint_fixture("perm-on-exit-legal");
    assert_clean(&diags, "perm on exit (legal - exit is in the allowed set)");
}

// ---------------------------------------------------------------------------
// T7: perm on exclude filter list - MUST NOT fire
//
// perm is legal on exit OR exclude (libaudit.c:1803-1805 v3.1.5).
// This is the key scope correction: perm's guard is !(EXIT || EXCLUDE).
// An impl treating perm as exit-only would incorrectly fire here.
// ---------------------------------------------------------------------------
#[test]
fn perm_on_exclude_must_not_fire() {
    let diags = lint_fixture("perm-on-exclude-legal");
    assert_clean(
        &diags,
        "perm on exclude (legal - exclude is in the allowed set)",
    );
}

// ---------------------------------------------------------------------------
// T8: obj_uid on exit filter list - MUST NOT fire
//
// obj_uid is NOT exit-only: it lives in the uid/gid arm (libaudit.c:1641 v3.1.5)
// which carries NO list guard. Legal on ANY list.
// This corrects the AUD-1 over-claim that treated all obj_* as exit-only.
// Live-confirmed: "-a always,exit -F obj_uid=0" passes userspace.
// Adversarial: an impl treating all obj_* as exit-only would pass this (exit
// is exit-only for real exit-only fields), but the exit is also legal for
// non-guarded fields -- the real test is T9.
// ---------------------------------------------------------------------------
#[test]
fn obj_uid_on_exit_must_not_fire() {
    let diags = lint_fixture("obj-uid-on-exit-legal");
    assert_clean(
        &diags,
        "obj_uid on exit (legal - no list guard on uid/gid arm)",
    );
}

// ---------------------------------------------------------------------------
// T9: obj_uid on user filter list - MUST NOT fire (THE adversarial scope case)
//
// This is the sharpest correctness case. A wrong impl treating all obj_* fields
// (including obj_uid/obj_gid) as exit-only would fire au-E04 here.
// The correct impl MUST NOT fire: obj_uid has no list guard.
// Live-confirmed: "-a always,user -F obj_uid=0" => "Operation not permitted"
// (userspace-passed; the error is kernel-level op restriction, not list restriction).
// ---------------------------------------------------------------------------
#[test]
fn obj_uid_on_user_must_not_fire() {
    let diags = lint_fixture("obj-uid-on-user-legal");
    assert_clean(
        &diags,
        "obj_uid on user (legal - obj_uid is NOT exit-only, scope correction from AUD-1)",
    );
}

// ---------------------------------------------------------------------------
// T10: msgtype on exclude filter list - MUST NOT fire
//
// msgtype is legal on exclude OR user (libaudit.c:1698-1701 v3.1.5).
// Live-confirmed: "-a never,exclude -F msgtype=AVC" passes userspace.
// Adversarial: a wrong impl firing msgtype on ALL non-exit lists would pass T2
// but incorrectly fire here.
// ---------------------------------------------------------------------------
#[test]
fn msgtype_on_exclude_must_not_fire() {
    let diags = lint_fixture("msgtype-on-exclude-legal");
    assert_clean(
        &diags,
        "msgtype on exclude (legal - exclude is in the allowed set for msgtype)",
    );
}

// ---------------------------------------------------------------------------
// T11: msgtype on user filter list (inline) - MUST NOT fire
//
// msgtype is legal on exclude or user (both, not just exclude).
// Live-confirmed: "-a always,user -F msgtype=AVC" passes userspace.
// ---------------------------------------------------------------------------
#[test]
fn msgtype_on_user_must_not_fire() {
    let diags = lint_inline("-a always,user -F msgtype=AVC -k test-msgtype-user");
    assert_clean(
        &diags,
        "msgtype on user (legal - user is in the allowed set for msgtype)",
    );
}

// ---------------------------------------------------------------------------
// T12: sessionid on exit filter list (inline) - MUST NOT fire
//
// sessionid is legal on exclude, user, OR exit (libaudit.c:1884-1887 v3.1.5).
// Adversarial: an impl that only allows exclude/user for sessionid (missing exit)
// would incorrectly fire here.
// ---------------------------------------------------------------------------
#[test]
fn sessionid_on_exit_must_not_fire() {
    let diags = lint_inline("-a always,exit -S open -F sessionid=1 -k test-sessionid-exit");
    assert_clean(
        &diags,
        "sessionid on exit (legal - exit is in the allowed set)",
    );
}

// ---------------------------------------------------------------------------
// T13: sessionid on user filter list (inline) - MUST NOT fire
// ---------------------------------------------------------------------------
#[test]
fn sessionid_on_user_must_not_fire() {
    let diags = lint_inline("-a always,user -F sessionid=1 -k test-sessionid-user");
    assert_clean(
        &diags,
        "sessionid on user (legal - user is in the allowed set)",
    );
}

// ---------------------------------------------------------------------------
// T14: obj_gid on user filter list (inline) - MUST NOT fire
//
// obj_gid (like obj_uid) lives in the uid/gid arm with NO list guard.
// Legal on any list. Confirms the scope correction covers both uid and gid.
// ---------------------------------------------------------------------------
#[test]
fn obj_gid_on_user_must_not_fire() {
    let diags = lint_inline("-a always,user -F obj_gid=0 -k test-obj-gid-user");
    assert_clean(
        &diags,
        "obj_gid on user (legal - no list guard on uid/gid arm)",
    );
}

// ---------------------------------------------------------------------------
// T15: catalog registers au-E04 with Error severity
//
// The catalog test pins that au-E04 is present and correctly categorised.
// This will fail (au-E04 is not in the catalog yet) until the implementer adds
// the entry to src/lints/catalog.rs AU_CODES + ALL_CODES.
// ---------------------------------------------------------------------------
#[test]
fn catalog_contains_au_e04_as_error() {
    let entry = rulesteward_auditd::lints::catalog::AU_CODES
        .iter()
        .find(|c| c.code == "au-E04")
        .expect("au-E04 must be in the catalog");
    assert_eq!(
        entry.severity,
        Severity::Error,
        "au-E04 must be Error (load-aborting)"
    );
    assert!(
        !entry.description.is_empty(),
        "au-E04 description must not be empty"
    );
}

// ---------------------------------------------------------------------------
// T17: path on user filter list - ILLEGAL (path is exit-only)
//
// path (-F path= Syscall form) shares the AUDIT_WATCH guard in libaudit.c
// (`case AUDIT_WATCH: case AUDIT_DIR: if (flags != AUDIT_FILTER_EXIT) return
// -EAU_EXITONLY;`). The -w desugaring always targets exit, but the raw -F path=
// Syscall form is equally exit-only. user list -> EAU_EXITONLY.
// Adversarial: an impl that handles Dir but not Path falls through to the
// unrestricted wildcard arm and silently misses this case.
// ---------------------------------------------------------------------------
#[test]
fn path_on_user_fires_one_e04() {
    let diags = lint_fixture("path-on-user");
    assert_one_e04(&diags, "path on user filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("path"),
        "message must name the field 'path', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T18: path on exit filter list - MUST NOT fire
//
// exit is the one legal list for path (same AUDIT_WATCH guard; exit passes).
// An impl that treats path as always-illegal would incorrectly fire here.
// Mirrors the dir-on-exit shape: no fixture exists for dir-on-exit-legal
// because dir on exit is a Watch desugar, but the Syscall form is legal.
// ---------------------------------------------------------------------------
#[test]
fn path_on_exit_must_not_fire() {
    let diags = lint_fixture("path-on-exit-legal");
    assert_clean(
        &diags,
        "path on exit (legal - exit is the one allowed list for path)",
    );
}

// ---------------------------------------------------------------------------
// T16: dispatcher (lints::lint) routes e04 findings
//
// The top-level lint dispatcher must include e04 in its output.
// Confirmed by running a known-illegal rule through lints::lint and checking
// that at least one au-E04 is present.
// This fails until the implementer wires e04 into lints/mod.rs.
// ---------------------------------------------------------------------------
#[test]
fn dispatcher_includes_e04_findings() {
    let rules = located_inline("-a always,task -F perm=r -k test-dispatcher");
    // Use the full dispatcher, not just e04 directly.
    let all_diags =
        rulesteward_auditd::lints::lint(&rules, rulesteward_auditd::lints::LintOptions::default());
    let e04_diags: Vec<_> = all_diags.iter().filter(|d| d.code == "au-E04").collect();
    assert!(
        !e04_diags.is_empty(),
        "lints::lint must include au-E04 findings for perm-on-task; got codes: {:?}",
        all_diags.iter().map(|d| &d.code).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// T19: the diagnostic message pins BOTH the offending filter-list name and the
// legal-lists description verbatim.
//
// The list name comes from filter_list_name() and the legal-lists text from
// legal_lists_str(); both feed ONLY this message. The other illegal-case tests
// (T1-T5c, T17) assert the message names the FIELD, which comes from the shared
// field_name() free fn (lints/field_name.rs, #458); that map is now pinned
// exhaustively by field_name::tests::name_covers_all_45_variants, so this test
// only needs to pin filter_list_name / legal_lists_str. Replacing either of
// those with a constant ("" / "xyzzy") changes the message and fails this
// assertion.
// ---------------------------------------------------------------------------
#[test]
fn message_pins_list_name_and_legal_lists() {
    let diags = lint_inline("-a always,task -F perm=r -k test-msg");
    assert_one_e04(&diags, "perm on task (message-shape pin)");
    assert_eq!(
        diags[0].message,
        "field 'perm' cannot be used on the 'task' filter list (legal: exit or exclude); auditctl aborts the rule load",
        "message must name the offending list ('task', from filter_list_name) AND the \
         legal lists ('exit or exclude', from legal_lists_str) verbatim"
    );
}

// ---------------------------------------------------------------------------
// T20: fstype on a non-filesystem list - ILLEGAL (fstype is filesystem-only).
//
// fstype is legal ONLY on the filesystem list (FIELDUNAVAIL guard, libaudit.c
// 1852-1854 v3.1.5; grounding depth-auditd-fieldtable.md row "fstype | filesystem
// | != FILTER_FS -> EAU_FIELDUNAVAIL"). On any other list the kernel returns
// EAU_FIELDUNAVAIL ("fstype field is not valid for the filter") and aborts the load.
// Live differential: "-a always,user -F fstype=ext4" => EAU_FIELDUNAVAIL.
// Adversarial: an impl missing the Fstype arm falls through to the unrestricted
// wildcard (_ => None) and fires NOTHING -- so this case must fire exactly one au-E04.
// ---------------------------------------------------------------------------
#[test]
fn fstype_on_user_fires_one_e04() {
    let diags = lint_inline("-a always,user -F fstype=ext4 -k test-fstype");
    assert_one_e04(&diags, "fstype on user filter list");

    let d = &diags[0];
    assert!(
        d.message.to_lowercase().contains("fstype"),
        "message must name the field 'fstype', got: {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// T21: fstype on the filesystem list - MUST NOT fire (legal control).
//
// filesystem is the one legal list for fstype. This pins Restriction::FilesystemOnly:
// an impl mapping fstype to e.g. ExitOnly would pass T20 but incorrectly fire here.
// ---------------------------------------------------------------------------
#[test]
fn fstype_on_filesystem_must_not_fire() {
    let diags = lint_inline("-a always,filesystem -F fstype=ext4 -k test-fstype-legal");
    assert_clean(
        &diags,
        "fstype on filesystem (legal - the one allowed list for fstype)",
    );
}
