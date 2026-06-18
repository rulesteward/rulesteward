//! Adversarial barrier tests for `is_te_representable` (issue #268).
//!
//! Asserts the OBSERVABLE CONTRACT: no bogus/uncompilable `allow` emitted by
//! `emit_te` or suggested by `triage` for groups that fail the representability
//! guard. These tests are written BLIND to the implementation (the predicate
//! `is_te_representable` does not exist yet).
//!
//! ## Primary sources
//!
//! - depth-selinux-recordspace.md D1/D2/D3/D-granted/D4 findings
//!   (`/home/runner/rulesteward-docs/research-notes/overnight/2026-06-17/`)
//! - OWNER DECISION C (LOCKED): `is_te_representable` declines when:
//!   - source_type OR target_type contains '=' (SID token)
//!   - ANY perm's first char is not ASCII-alphabetic (e.g. `0x..` hex bit)
//!   - kind is MlsSuspected/RoleSuspected/Constraint/Bounds/ContextInvalid
//!   - verdict is Granted (drop before grouping or carry into group)
//!   - True ONLY for TeAllowable (or Permissive, but Permissive is unchanged)
//! - Grounding evidence: `checkmodule` host + container (RHEL9 v33):
//!   `local.te:N:ERROR 'unrecognized character' at token '='` (D1/D2)
//!   `local.te:N:ERROR 'syntax error' at token '0x4000000'` (D3)
//!   `audit2allow -N` output empty for granted and SID records.
//!
//! ## In-process assertions (NO checkmodule required)
//!
//! Per spec: assert emitted content as a string. Tests self-skip if the
//! assertion is vacuous (they never skip - all assertions are on string content
//! we produce in-process).
//!
//! ## What each test KILLS
//!
//! - (a) SID tests: kill an impl that allows any group whose type contains `=`
//! - (b) hex-perm tests: kill an impl that allows any group whose perms contain
//!       non-alphabetic-first tokens
//! - (c) granted tests: kill an impl that emits allows for granted records
//! - (d) good-case tests: kill an over-conservative impl that declines valid groups

// The module-level doc uses code identifiers (source_type, DenialKind, etc.) and
// multi-word constructs (TeAllowable, RoleSuspected) without backticks throughout
// for readability. Clippy's doc_markdown lint fires on these in test-only files;
// suppress it here rather than adding backticks to every identifier in prose.
#![allow(clippy::doc_markdown)]
#![allow(clippy::doc_overindented_list_items)]

use std::collections::BTreeSet;

use rulesteward_selinux::{
    DenialGroup, DenialKind, build_report, emit_te, group_denials, parse_avc, render_human,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `DenialGroup` with explicit fields for use in direct emit/triage tests.
fn make_group_direct(
    source_type: &str,
    target_type: &str,
    tclass: &str,
    perms: &[&str],
    kind: DenialKind,
) -> DenialGroup {
    DenialGroup {
        source_type: source_type.to_string(),
        target_type: target_type.to_string(),
        tclass: tclass.to_string(),
        perms: perms
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        any_permissive: matches!(kind, DenialKind::Permissive),
        kind,
    }
}

/// Parse a single AVC line and group it, returning the groups.
fn parse_and_group(line: &str) -> Vec<DenialGroup> {
    let denials = parse_avc(line).expect("parse_avc must succeed for well-formed input");
    group_denials(&denials)
}

// ---------------------------------------------------------------------------
// (a) SID token in source_type or target_type
//
// Grounding: D1 (both-SID) + D2 (partial-SID) in depth-selinux-recordspace.md.
// A type like "ssid=42" contains '=' which is NOT a valid TE identifier.
// checkmodule host + container (RHEL9 v33) rejects with:
//   "local.te:N:ERROR 'unrecognized character' at token '='"
// audit2allow -N emits nothing for these records.
//
// Contract:
// - emit_te must NOT emit `allow ssid=42 ...;`
// - emit_te MUST emit a decline comment (not silently skip)
// - triage render_human must NOT produce "Suggested fix: allow ssid=42 ..."
// - triage build_report must NOT contain an "allow ssid=" suggested rule
// ---------------------------------------------------------------------------

/// D1 (both-SID): both source and target are SID tokens (`ssid=42`, `tsid=99`).
/// The denial record lacks scontext=/tcontext=; the kernel stores numeric SIDs.
/// Source: depth-selinux-recordspace.md D1 + corpus rocky9-ssid-fallback.
///
/// Groups: the parser stores "ssid=42"/"tsid=99" in source_type/target_type
/// (see avc.rs:272-285). The grouper carries these verbatim. The guard MUST
/// reject groups with '=' in either type field.
///
/// Kills an impl that gates only on DenialKind (these records become TeAllowable
/// via the floor classifier because there are no levels or non-object_r roles
/// in the SID fallback context).
#[test]
fn a1_sid_both_source_and_target_emit_te_no_bogus_allow() {
    // Use the corpus fixture: both ssid= and tsid= -> source_type="ssid=42", target_type="tsid=99".
    let line = include_str!("corpus/selinux/rocky9-ssid-fallback/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(
        !groups.is_empty(),
        "a1: rocky9-ssid-fallback must parse into at least one group"
    );

    let te = emit_te(&groups, Some("test_sid_a1"));

    // Must NOT emit an allow containing '=' in the type position.
    // The uncompilable form would be `allow ssid=42 tsid=99:file read;`.
    let allow_lines_with_eq: Vec<&str> = te
        .lines()
        .filter(|l| l.trim_start().starts_with("allow ") && l.contains('='))
        .collect();
    assert!(
        allow_lines_with_eq.is_empty(),
        "a1: emit_te must NOT emit an allow rule containing '=' in a type token \
         (that is a SID fallback - uncompilable TE syntax; D1 grounding: \
         checkmodule error 'unrecognized character at token ='); got allow lines:\n{}",
        allow_lines_with_eq.join("\n")
    );

    // Specifically must not emit allow ssid= or allow tsid= in any form.
    assert!(
        !te.contains("allow ssid="),
        "a1: emit_te must NOT emit `allow ssid=...` (SID token is not a valid TE identifier); \
         got:\n{te}"
    );
    assert!(
        !te.contains("allow tsid="),
        "a1: emit_te must NOT emit `allow tsid=...` (SID token is not a valid TE identifier); \
         got:\n{te}"
    );

    // Must emit a PER-GROUP DECLINE COMMENT that NAMES this declined group (not
    // just *any* comment line). te_emit.rs emits one decline comment per declined
    // group: `# rulesteward: declined (not TE-representable): <src> <tgt>:<cls> {..}`.
    // Asserting the comment NAMES the group's type tokens (`ssid=42`/`tsid=99`)
    // kills the `te_emit.rs:87 != -> ==` mutant: that mutant empties the `declined`
    // bucket, so NO per-group decline comment is emitted. A bare `any('#')` check
    // would survive it (the header / zero-denial comment satisfies `any('#')`),
    // but a check that the comment names this group cannot.
    let names_declined_group = te.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with('#') && t.contains("ssid=42") && t.contains("tsid=99")
    });
    assert!(
        names_declined_group,
        "a1: emit_te must emit a per-group decline comment NAMING the SID-token group \
         (containing 'ssid=42' and 'tsid=99'); a generic comment is not enough - the \
         per-group decline comment is the observable that the SID group was actually \
         declined (kills the te_emit.rs declined-filter mutant); got:\n{te}"
    );
}

#[test]
fn a2_sid_both_source_and_target_triage_no_bogus_suggest() {
    // Same corpus fixture as a1.
    let line = include_str!("corpus/selinux/rocky9-ssid-fallback/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(!groups.is_empty(), "a2: rocky9-ssid-fallback must parse");

    let out = render_human(&groups);

    // triage must NOT suggest `allow ssid=42 ...` or `allow tsid=99 ...`.
    // A "Suggested fix:" line must not contain '=' (which would mean it contains a SID token).
    let suggested_with_eq: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("Suggested fix:") && l.contains('='))
        .collect();
    assert!(
        suggested_with_eq.is_empty(),
        "a2: render_human must NOT suggest an allow rule containing '=' in a type position \
         (SID fallback - D1 grounding); got suggested lines:\n{}",
        suggested_with_eq.join("\n")
    );
    assert!(
        !out.contains("Suggested fix: allow ssid="),
        "a2: render_human must NOT produce 'Suggested fix: allow ssid=...' \
         (SID token is not a valid TE identifier); got:\n{out}"
    );
    assert!(
        !out.contains("Suggested fix: allow tsid="),
        "a2: render_human must NOT produce 'Suggested fix: allow tsid=...' \
         (SID token is not a valid TE identifier); got:\n{out}"
    );
}

#[test]
fn a3_sid_both_source_and_target_build_report_no_bogus_rule() {
    // Same corpus fixture as a1 - machine-readable path.
    let line = include_str!("corpus/selinux/rocky9-ssid-fallback/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(!groups.is_empty(), "a3: rocky9-ssid-fallback must parse");

    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("a3: TriageReport must serialize");

    // The JSON must not contain an "allow ssid=" or "allow tsid=" string in any
    // suggested_rule field.
    assert!(
        !json.contains("allow ssid=") && !json.contains("allow tsid="),
        "a3: build_report JSON must NOT contain 'allow ssid=...' or 'allow tsid=...' \
         in a suggested rule (SID fallback is not a valid TE rule); got:\n{json}"
    );
}

/// D2 (partial-SID): source_type is resolved ("httpd_t"), target_type is a SID
/// ("tsid=77"). The target is not a valid TE identifier.
/// Source: depth-selinux-recordspace.md D2.
/// Construct directly (no real AVC record has tsid= with scontext= simultaneously
/// in the corpus; the group is built with the field values that avc.rs would produce).
#[test]
fn a4_partial_sid_target_emit_te_no_bogus_allow() {
    // source_type is a real type, target_type is a SID token (contains '=').
    // Kind is TeAllowable (mirrors a6/a7's source-SID case): an MlsSuspected group
    // is ALREADY declined by existing logic, so using it would make this test pass
    // for the wrong reason. With TeAllowable the ONLY decline reason is the '=' in
    // target_type, which ISOLATES the SID-token guard (D2 grounding).
    let groups = [make_group_direct(
        "httpd_t",
        "tsid=77",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let te = emit_te(&groups, Some("test_partial_sid_a4"));

    // Must NOT emit `allow httpd_t tsid=77:file read;` (uncompilable; D2 grounding).
    assert!(
        !te.contains("allow httpd_t tsid=77"),
        "a4: emit_te must NOT emit allow for a group whose target_type is a SID token \
         'tsid=77' (uncompilable; D2: checkmodule 'unrecognized character at token ='); \
         got:\n{te}"
    );

    // More generally: must not emit any allow with '=' in the type position.
    let allow_with_eq: Vec<&str> = te
        .lines()
        .filter(|l| l.trim_start().starts_with("allow ") && l.contains('='))
        .collect();
    assert!(
        allow_with_eq.is_empty(),
        "a4: emit_te must NOT emit allow rules with '=' in a type token (partial-SID case); \
         got:\n{}",
        allow_with_eq.join("\n")
    );
}

#[test]
fn a5_partial_sid_target_triage_no_bogus_suggest() {
    // Same partial-SID group (D2). Kind is TeAllowable (mirrors a6/a7): an
    // MlsSuspected group is already declined by existing logic, which would make
    // this test vacuously pass; with TeAllowable the ONLY decline reason is the
    // '=' in target_type, isolating the SID-token guard.
    let groups = [make_group_direct(
        "httpd_t",
        "tsid=77",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let out = render_human(&groups);

    // triage must NOT suggest `allow httpd_t tsid=77:file read;`.
    assert!(
        !out.contains("allow httpd_t tsid=77"),
        "a5: render_human must NOT suggest allow for a partial-SID target 'tsid=77' \
         (D2 grounding: the target is not a valid TE identifier); got:\n{out}"
    );
    assert!(
        !out.contains("Suggested fix: allow httpd_t tsid="),
        "a5: render_human must NOT produce 'Suggested fix: allow httpd_t tsid=...' \
         (SID token is not TE-representable); got:\n{out}"
    );
}

/// Variant: source_type contains '=' (source is a SID, target is real).
/// Ensures the guard checks BOTH fields, not just the target.
#[test]
fn a6_partial_sid_source_emit_te_no_bogus_allow() {
    let groups = [make_group_direct(
        "ssid=99",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let te = emit_te(&groups, Some("test_partial_sid_source_a6"));

    assert!(
        !te.contains("allow ssid=99"),
        "a6: emit_te must NOT emit allow for a group whose source_type is a SID token \
         'ssid=99' (source-SID case; type contains '=' -> uncompilable TE); got:\n{te}"
    );
}

#[test]
fn a7_partial_sid_source_triage_no_bogus_suggest() {
    let groups = [make_group_direct(
        "ssid=99",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let out = render_human(&groups);

    assert!(
        !out.contains("allow ssid=99"),
        "a7: render_human must NOT suggest allow ssid=99 (source-SID case; D1 grounding); \
         got:\n{out}"
    );
    assert!(
        !out.contains("Suggested fix: allow ssid="),
        "a7: render_human must NOT produce 'Suggested fix: allow ssid=...' \
         for a source-SID group; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// (b) Hex perm token (first char not ASCII-alphabetic)
//
// Grounding: D3 in depth-selinux-recordspace.md.
// The kernel emits `0x%x` for unknown permission bits (avc.c:677; see avc.rs:17-18).
// checkmodule host + container (RHEL9 v33) rejects with:
//   "local.te:N:ERROR 'syntax error' at token '0x4000000'"
// audit2allow -N declines: "could not convert 0x4000000 to av bit".
//
// Contract:
// - emit_te must NOT emit `allow ... 0x4000;` (or any hex token on an allow line)
// - emit_te MUST emit a decline comment for the declined group
// - triage render_human must NOT produce "Suggested fix: allow ... 0x4000;"
// - triage build_report must NOT contain a suggested rule with a hex token
//
// The corpus fixture (rocky9-hex-perm-token) has BOTH "read" (alpha) and "0x4000"
// (hex) in the same record. The guard must decline the whole group (the D3 spec
// says decline when ANY perm's first char is not ASCII-alphabetic).
// ---------------------------------------------------------------------------

#[test]
fn b1_hex_perm_emit_te_no_bogus_allow() {
    // Corpus: `{ read 0x4000 }` - one alpha perm + one hex perm.
    // The whole group must be declined (any non-alpha perm -> decline).
    let line = include_str!("corpus/selinux/rocky9-hex-perm-token/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(
        !groups.is_empty(),
        "b1: rocky9-hex-perm-token must parse into at least one group"
    );

    let te = emit_te(&groups, Some("test_hexperm_b1"));

    // Must NOT emit any allow containing a hex token like `0x4000`.
    let allow_lines_with_hex: Vec<&str> = te
        .lines()
        .filter(|l| l.trim_start().starts_with("allow ") && l.contains("0x"))
        .collect();
    assert!(
        allow_lines_with_hex.is_empty(),
        "b1: emit_te must NOT emit allow rules containing a hex perm token '0x...' \
         (D3 grounding: checkmodule 'syntax error at token 0x4000000'; \
         audit2allow -N declines); got allow lines:\n{}",
        allow_lines_with_hex.join("\n")
    );

    // Must emit a PER-GROUP DECLINE COMMENT that NAMES this declined group (not
    // just *any* comment line). te_emit.rs emits one decline comment per declined
    // group: `# rulesteward: declined (not TE-representable): logrotate_t shadow_t:file
    // {0x4000 read}`. Asserting the comment NAMES the group (its type tokens and the
    // offending hex perm) kills the `te_emit.rs:87 != -> ==` mutant: that mutant
    // empties the `declined` bucket so NO per-group decline comment is emitted. A
    // bare `any('#')` check would survive it (the module header / zero-denial comment
    // satisfies `any('#')`), but a check that the comment names this group cannot.
    let names_declined_group = te.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with('#')
            && t.contains("logrotate_t")
            && t.contains("shadow_t")
            && t.contains("0x4000")
    });
    assert!(
        names_declined_group,
        "b1: emit_te must emit a per-group decline comment NAMING the hex-perm group \
         (containing 'logrotate_t', 'shadow_t', and the offending '0x4000' token); a \
         generic comment is not enough - the per-group decline comment is the observable \
         that the hex group was actually declined (kills the te_emit.rs declined-filter \
         mutant); got:\n{te}"
    );
}

#[test]
fn b2_hex_perm_triage_no_bogus_suggest() {
    let line = include_str!("corpus/selinux/rocky9-hex-perm-token/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(!groups.is_empty(), "b2: rocky9-hex-perm-token must parse");

    let out = render_human(&groups);

    // triage must NOT suggest an allow containing a hex perm token.
    let suggested_with_hex: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("Suggested fix:") && l.contains("0x"))
        .collect();
    assert!(
        suggested_with_hex.is_empty(),
        "b2: render_human must NOT suggest an allow rule with a hex perm token '0x...' \
         (D3 grounding: the hex token is not a valid permission name; audit2allow -N declines); \
         got:\n{}",
        suggested_with_hex.join("\n")
    );

    // The contract declines the WHOLE group (any non-alpha perm -> decline), not
    // just the hex token. Mirror b4/b5: there must be NO suggested allow for the
    // logrotate_t -> shadow_t group at all. Without this, a WRONG impl that strips
    // the hex bit and keeps the alpha-only allow `allow logrotate_t shadow_t:file
    // read;` would still pass the '0x'-absence check above.
    assert!(
        !out.contains("allow logrotate_t shadow_t"),
        "b2: render_human must NOT suggest ANY allow for the hex-perm group \
         (the contract declines the whole logrotate_t -> shadow_t group when any \
         perm is non-alpha; stripping the hex bit and keeping `allow ... read;` is \
         still wrong - D3 grounding); got:\n{out}"
    );
}

#[test]
fn b3_hex_perm_build_report_no_bogus_rule() {
    let line = include_str!("corpus/selinux/rocky9-hex-perm-token/denials.txt").trim();
    let groups = parse_and_group(line);
    assert!(!groups.is_empty(), "b3: rocky9-hex-perm-token must parse");

    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("b3: TriageReport must serialize");

    // The JSON must not contain a "0x" substring on a suggested_rule line.
    // We can't easily parse suggested_rule vs. other fields, but any "allow ... 0x"
    // string in the JSON is a bug: hex tokens are never valid in TE allow rules.
    assert!(
        !json.contains("allow") || !json.contains("0x"),
        "b3: build_report JSON must NOT contain an allow rule with a hex token '0x...' \
         (D3 grounding); got:\n{json}"
    );

    // The contract declines the WHOLE group, not just the hex token. There must
    // be NO suggested allow for logrotate_t -> shadow_t at all. Without this, a
    // WRONG impl that strips the hex bit and keeps the alpha-only allow
    // `allow logrotate_t shadow_t:file read;` would still pass the '0x'-absence
    // check above (which only fires when BOTH 'allow' AND '0x' appear).
    assert!(
        !json.contains("allow logrotate_t shadow_t"),
        "b3: build_report JSON must NOT contain ANY allow for the hex-perm group \
         (the contract declines the whole logrotate_t -> shadow_t group when any \
         perm is non-alpha; D3 grounding); got:\n{json}"
    );
}

/// Direct group construction: single hex perm only (no alpha perm).
/// Ensures the guard handles a group with NO alpha perms at all.
#[test]
fn b4_hex_only_perm_emit_te_declines() {
    let groups = [make_group_direct(
        "httpd_t",
        "var_t",
        "file",
        &["0x4000000"],
        DenialKind::TeAllowable,
    )];

    let te = emit_te(&groups, Some("test_hex_only_b4"));

    assert!(
        !te.contains("allow httpd_t var_t:file 0x4000000"),
        "b4: emit_te must NOT emit allow for a group with a hex-only perm '0x4000000' \
         (D3 grounding: not a valid TE permission name); got:\n{te}"
    );
    assert!(
        !te.contains("allow httpd_t var_t"),
        "b4: emit_te must NOT emit any allow for the hex-only-perm group; got:\n{te}"
    );
}

#[test]
fn b5_hex_only_perm_triage_declines() {
    let groups = [make_group_direct(
        "httpd_t",
        "var_t",
        "file",
        &["0x4000000"],
        DenialKind::TeAllowable,
    )];

    let out = render_human(&groups);

    assert!(
        !out.contains("Suggested fix: allow httpd_t var_t"),
        "b5: render_human must NOT suggest allow for hex-only-perm group; got:\n{out}"
    );
    assert!(
        !out.contains("0x4000000"),
        "b5: render_human must NOT emit the hex token '0x4000000' as a perm in a suggested rule; \
         got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// (c) Granted-verdict AVC records
//
// Grounding: D-granted in depth-selinux-recordspace.md.
// A record with `avc: granted` was already permitted - there is nothing to allow.
// audit2allow -N emits NOTHING; audit2why says "would be allowed by active policy".
// The current code treats granted records like denied ones (D-granted finding).
//
// Contract:
// - a Verdict::Granted record must produce NO suggested/emitted allow at all
// - The observable test: parse the granted record, group, check emit_te and
//   render_human produce no allow for the granted source/target
//
// Implementation note (per spec IMPLEMENTER section): the cleanest fix is to
// drop Granted records before grouping in group_denials(). The tests assert the
// OBSERVABLE result; they do not mandate where in the pipeline the drop happens.
//
// The corpus rocky9-granted-record has TWO lines:
//   1. avc: granted { read } for ... logrotate_t -> shadow_t:file
//   2. avc: denied { write } for ... logrotate_t -> var_log_t:file
// So the groups after parse+group will include the DENIED write group.
// The test must confirm the GRANTED read produces no allow.
// ---------------------------------------------------------------------------

#[test]
fn c1_granted_record_emit_te_no_allow_for_granted_access() {
    // Corpus: one granted + one denied record.
    let text = include_str!("corpus/selinux/rocky9-granted-record/denials.txt");
    let mut all_denials = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut batch = parse_avc(trimmed)
            .unwrap_or_else(|e| panic!("c1: failed to parse AVC line: {e}\n  line: {trimmed}"));
        all_denials.append(&mut batch);
    }
    let groups = group_denials(&all_denials);

    let te = emit_te(&groups, Some("test_granted_c1"));

    // The granted record is: logrotate_t -> shadow_t:file { read }
    // After the fix, this group must NOT appear in the emitted .te.
    // The denied record is: logrotate_t -> var_log_t:file { write }
    // That SHOULD appear (it is a real denial).
    assert!(
        !te.contains("allow logrotate_t shadow_t:file read;")
            && !te.contains("allow logrotate_t shadow_t:file { read };"),
        "c1: emit_te must NOT emit allow for a Verdict::Granted record \
         (D-granted grounding: audit2allow -N emits nothing for grants; \
         the access was already permitted); got:\n{te}"
    );

    // More specifically: must not emit any allow involving shadow_t as the target
    // (since the only shadow_t record was the granted one).
    let shadow_allow: Vec<&str> = te
        .lines()
        .filter(|l| l.trim_start().starts_with("allow ") && l.contains("shadow_t"))
        .collect();
    assert!(
        shadow_allow.is_empty(),
        "c1: emit_te must NOT emit any allow for the granted logrotate_t -> shadow_t group; \
         got lines:\n{}",
        shadow_allow.join("\n")
    );
}

#[test]
fn c2_granted_record_triage_no_suggest_for_granted_access() {
    let text = include_str!("corpus/selinux/rocky9-granted-record/denials.txt");
    let mut all_denials = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut batch = parse_avc(trimmed)
            .unwrap_or_else(|e| panic!("c2: failed to parse: {e}\n  line: {trimmed}"));
        all_denials.append(&mut batch);
    }
    let groups = group_denials(&all_denials);

    let out = render_human(&groups);

    // The granted read on shadow_t must not be suggested.
    // The denied write on var_log_t may (and should) be suggested.
    assert!(
        !out.contains("Suggested fix: allow logrotate_t shadow_t:file read;")
            && !out.contains("Suggested fix: allow logrotate_t shadow_t:file { read };"),
        "c2: render_human must NOT produce 'Suggested fix: allow logrotate_t shadow_t:file read;' \
         for a Verdict::Granted record (D-granted grounding: the access was already permitted; \
         suggesting an allow is factually wrong); got:\n{out}"
    );
}

#[test]
fn c3_granted_record_build_report_no_suggest_for_granted_access() {
    let text = include_str!("corpus/selinux/rocky9-granted-record/denials.txt");
    let mut all_denials = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut batch = parse_avc(trimmed)
            .unwrap_or_else(|e| panic!("c3: failed to parse: {e}\n  line: {trimmed}"));
        all_denials.append(&mut batch);
    }
    let groups = group_denials(&all_denials);

    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("c3: TriageReport must serialize");

    // The JSON must not contain "allow logrotate_t shadow_t:file read;" in any field.
    assert!(
        !json.contains("allow logrotate_t shadow_t:file read;")
            && !json.contains("allow logrotate_t shadow_t:file { read };"),
        "c3: build_report JSON must NOT contain a suggested allow for the granted \
         logrotate_t -> shadow_t:file {{ read }} record (D-granted grounding); got:\n{json}"
    );
}

/// c4: a pure-grant file (rocky9-granted-no-permissive) with no denied records.
/// After dropping the granted record the group list should be EMPTY, and
/// emit_te should return the zero-denial comment (not an allow rule).
#[test]
fn c4_pure_grant_file_emit_te_produces_no_allow() {
    let text = include_str!("corpus/selinux/rocky9-granted-no-permissive/denials.txt");
    let mut all_denials = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // parse_avc may fail for granted-only lines if Verdict::Granted is filtered
        // before grouping; we use unwrap_or_default to handle the case where parse
        // succeeds but grouping produces zero groups.
        if let Ok(mut batch) = parse_avc(trimmed) {
            all_denials.append(&mut batch);
        }
    }
    let groups = group_denials(&all_denials);

    let te = emit_te(&groups, Some("test_grant_only_c4"));

    // Either no groups at all (emit_te returns the zero-denial comment) OR the
    // group(s) have been declined. Either way: no allow rule for the granted access.
    assert!(
        !te.contains("allow logrotate_t shadow_t"),
        "c4: emit_te must NOT emit an allow rule for a pure-grant file; got:\n{te}"
    );
    assert!(
        !te.lines().any(|l| l.trim_start().starts_with("allow ")),
        "c4: emit_te must produce no allow rules for a pure-grant input; got:\n{te}"
    );
}

// ---------------------------------------------------------------------------
// (d) Good case: TeAllowable group with normal type + alpha perm
//
// Grounding: normal TeAllowable groups must NOT be over-declined by the guard.
// Source: f4 §1.2 anchor (logrotate_t -> shadow_t:file read).
//
// The predicate must return true ONLY for groups that are honestly representable.
// These tests ensure the guard does not over-decline valid groups.
// ---------------------------------------------------------------------------

/// d1: A clean TeAllowable group (no SID, no hex perm) MUST produce an allow rule
/// in emit_te. Kills an over-conservative impl that declines everything.
#[test]
fn d1_teallowable_normal_group_emit_te_produces_allow() {
    let groups = [make_group_direct(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let te = emit_te(&groups, Some("test_good_d1"));

    // Must emit the allow rule (the predicate must not over-decline).
    assert!(
        te.contains("allow logrotate_t shadow_t:file read;"),
        "d1: emit_te MUST emit 'allow logrotate_t shadow_t:file read;' for a clean \
         TeAllowable group (no SID, no hex perm); got:\n{te}"
    );
}

/// d2: A clean TeAllowable group MUST produce a suggested allow in render_human.
/// Kills an over-conservative impl that declines all TeAllowable groups.
#[test]
fn d2_teallowable_normal_group_triage_suggests_allow() {
    let groups = [make_group_direct(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let out = render_human(&groups);

    assert!(
        out.contains("allow logrotate_t shadow_t:file read;"),
        "d2: render_human MUST suggest 'allow logrotate_t shadow_t:file read;' for a \
         clean TeAllowable group; got:\n{out}"
    );
    assert!(
        out.contains("Suggested fix:"),
        "d2: render_human MUST include 'Suggested fix:' for a clean TeAllowable group; \
         got:\n{out}"
    );
}

/// d3: A clean TeAllowable group MUST have a suggested_rule in build_report.
#[test]
fn d3_teallowable_normal_group_build_report_suggests_allow() {
    let groups = [make_group_direct(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::TeAllowable,
    )];

    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("d3: serialize");

    assert!(
        json.contains("allow logrotate_t shadow_t:file read;"),
        "d3: build_report JSON MUST contain 'allow logrotate_t shadow_t:file read;' \
         for a clean TeAllowable group; got:\n{json}"
    );
}

/// d4: Multi-perm TeAllowable group (logrotate_t -> shadow_t:file { read getattr }).
/// The guard must not over-decline multi-perm groups when ALL perms are alpha.
#[test]
fn d4_teallowable_multi_perm_all_alpha_emit_te_produces_allow() {
    let groups = [make_group_direct(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
        DenialKind::TeAllowable,
    )];

    let te = emit_te(&groups, Some("test_good_multi_d4"));

    // BTreeSet sort: "getattr" < "read" -> brace form "{ getattr read }".
    assert!(
        te.contains("allow logrotate_t shadow_t:file { getattr read };"),
        "d4: emit_te MUST emit the multi-perm allow rule for a clean TeAllowable group \
         with all-alpha perms; got:\n{te}"
    );
}

/// d5: End-to-end parse -> group -> emit_te for a normal denied record.
/// Confirms the guard does not break the happy path via the full pipeline.
#[test]
fn d5_normal_denied_record_end_to_end_emit_te() {
    use rulesteward_selinux::parse_avc;
    // A real-shaped enforcing denial (the f4 §1.2 anchor record form).
    let line = "type=AVC msg=audit(1780438805.959:23904): avc:  denied  { read } for  \
                pid=14601 comm=\"mycat\" name=\"data\" dev=\"vda4\" ino=109061505 \
                scontext=system_u:system_r:logrotate_t:s0 \
                tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";

    let denials = parse_avc(line).expect("d5: parse must succeed");
    let groups = group_denials(&denials);
    assert_eq!(groups.len(), 1, "d5: one denial -> one group");
    assert_eq!(
        groups[0].kind,
        DenialKind::TeAllowable,
        "d5: floor must classify logrotate_t->shadow_t:file as TeAllowable"
    );

    let te = emit_te(&groups, Some("test_e2e_d5"));

    assert!(
        te.contains("allow logrotate_t shadow_t:file read;"),
        "d5: end-to-end emit_te MUST produce the allow for a normal enforcing denial; \
         got:\n{te}"
    );
}

// ---------------------------------------------------------------------------
// Invariant: Permissive kind is UNCHANGED by the guard
//
// OWNER DECISION C / spec: "PERMISSIVE IS OUT OF SCOPE" for is_te_representable.
// emit_te STILL skips Permissive (locked invariant 6).
// triage STILL emits Permissive-with-a-banner (the 2026-06-05 reversal).
// The guard must NOT change either of these behaviors.
// ---------------------------------------------------------------------------

/// p1: A Permissive group must still be SKIPPED by emit_te (invariant 6).
/// The guard must not accidentally change Permissive handling.
#[test]
fn p1_permissive_group_emit_te_still_skips() {
    let groups = [make_group_direct(
        "httpd_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::Permissive,
    )];

    let te = emit_te(&groups, Some("test_perm_p1"));

    // Permissive still skipped (invariant 6 - unchanged by this guard).
    assert!(
        !te.contains("allow httpd_t shadow_t:file read;")
            && !te.contains("allow httpd_t shadow_t:file { read };"),
        "p1: emit_te must STILL skip Permissive groups (invariant 6; Permissive is \
         out of scope for is_te_representable per OWNER DECISION C); got:\n{te}"
    );
}

/// p2: A Permissive group must still produce a suggested allow in render_human
/// (the 2026-06-05 reversal). The guard must not break this.
#[test]
fn p2_permissive_group_triage_still_suggests_with_banner() {
    let groups = [make_group_direct(
        "httpd_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::Permissive,
    )];

    let out = render_human(&groups);

    // Permissive triage still emits allow + banner (2026-06-05 reversal).
    assert!(
        out.contains("allow httpd_t shadow_t:file read;")
            || out.contains("allow httpd_t shadow_t:file { read };"),
        "p2: render_human MUST still suggest allow for Permissive groups \
         (2026-06-05 reversal; Permissive is out of scope for the guard); got:\n{out}"
    );
    assert!(
        out.contains("PERMISSIVE MODE:"),
        "p2: render_human MUST still emit the PERMISSIVE MODE: banner for Permissive \
         groups (the 2026-06-05 reversal); got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// (e) Empty perm set: a group with NO denied perms is NOT TE-representable
//
// Grounding: same uncompilable-.te class as the SID (D1/D2) and hex (D3) cases.
// A group with an empty perm set would emit `allow src tgt:cls ;` (the perm
// formatter yields the empty string for an empty set) AND a malformed
// `class cls ;` require line. checkmodule rejects both ("syntax error at token
// ';'"). The real-world source is an empty-brace AVC record `avc: denied {  }`
// (the kernel can emit a zero-perm brace; split_ascii_whitespace over the empty
// brace body yields no tokens, so perms is empty after parse+group).
//
// The bug: `is_te_representable`'s perm gate was
// `perms.iter().any(|p| <non-alpha first char>)`; `.any()` over an EMPTY set is
// `false`, so the gate never fired and a TeAllowable empty-perm group was wrongly
// declared representable. The fix declines when `group.perms.is_empty()`.
//
// Contract (mirrors the SID/hex cases):
// - emit_te must NOT emit any `allow ` line for the empty-perm group
// - emit_te MUST emit a decline comment (not be silently empty)
// - triage render_human must NOT produce a "Suggested fix:" / allow for it
// - triage build_report JSON must NOT contain an allow for it
// ---------------------------------------------------------------------------

/// e1 (direct): a TeAllowable group with an EMPTY perm set must be DECLINED.
/// emit_te must emit NO allow line (and specifically not the malformed
/// `allow logrotate_t shadow_t:file ;`), must emit a decline comment, and triage
/// (human + JSON) must not suggest any allow for it.
#[test]
fn e1_empty_perm_group_declines_everywhere() {
    let groups = [make_group_direct(
        "logrotate_t",
        "shadow_t",
        "file",
        &[], // empty perm set
        DenialKind::TeAllowable,
    )];

    // -- emit_te: no allow line at all, and a decline comment present ---------
    let te = emit_te(&groups, Some("test_empty_perm_e1"));
    assert!(
        !te.lines().any(|l| l.trim_start().starts_with("allow ")),
        "e1: emit_te must emit NO allow line for an empty-perm group (the malformed \
         `allow logrotate_t shadow_t:file ;` is rejected by checkmodule: 'syntax error \
         at token ;'); got:\n{te}"
    );
    assert!(
        !te.contains("allow logrotate_t shadow_t"),
        "e1: emit_te must NOT emit any allow for the empty-perm logrotate_t -> shadow_t \
         group; got:\n{te}"
    );
    let has_decline_comment = te.lines().any(|l| l.trim_start().starts_with('#'));
    assert!(
        has_decline_comment,
        "e1: emit_te must emit a decline comment for the empty-perm group (mirroring the \
         SID/hex decline; the output must not be silently empty); got:\n{te}"
    );

    // -- render_human: no Suggested fix / no allow for the empty-perm group ---
    let out = render_human(&groups);
    assert!(
        !out.contains("Suggested fix:"),
        "e1: render_human must NOT produce a 'Suggested fix:' for an empty-perm group \
         (it is not TE-representable); got:\n{out}"
    );
    assert!(
        !out.contains("allow logrotate_t shadow_t"),
        "e1: render_human must NOT suggest any allow for the empty-perm group; got:\n{out}"
    );

    // -- build_report JSON: no allow for the empty-perm group -----------------
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("e1: TriageReport must serialize");
    assert!(
        !json.contains("allow logrotate_t shadow_t"),
        "e1: build_report JSON must NOT contain an allow for the empty-perm group; got:\n{json}"
    );
}

/// e2 (end-to-end): an empty-brace AVC line (`avc: denied {  }`) parses into a
/// group with an empty perm set; the full parse -> group -> emit/triage pipeline
/// must decline it exactly as e1's direct group does. This pins that the real
/// record path (not just a hand-built group) is covered.
#[test]
fn e2_empty_brace_avc_line_end_to_end_declines() {
    // An empty perm brace: the kernel form `avc: denied {  } for ...`. After
    // parse+group the perm set is empty and the floor classifies it TeAllowable
    // (system_r -> object_r, no level mismatch).
    let line = "type=AVC msg=audit(1780438805.959:23999): avc:  denied  {  } for  \
                pid=14601 comm=\"mycat\" name=\"data\" dev=\"vda4\" ino=109061505 \
                scontext=system_u:system_r:logrotate_t:s0 \
                tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";

    let groups = parse_and_group(line);
    assert!(
        !groups.is_empty(),
        "e2: empty-brace AVC line must parse into at least one group"
    );
    assert!(
        groups.iter().all(|g| g.perms.is_empty()),
        "e2: the parsed group(s) must have an empty perm set (empty brace -> no perm \
         tokens); got perms: {:?}",
        groups.iter().map(|g| &g.perms).collect::<Vec<_>>()
    );
    assert_eq!(
        groups[0].kind,
        DenialKind::TeAllowable,
        "e2: an enforcing empty-brace denial floors to TeAllowable (system_r -> object_r, \
         no level mismatch); the empty-perm guard - not the kind - must decline it"
    );

    // emit_te: no allow line, decline comment present.
    let te = emit_te(&groups, Some("test_empty_brace_e2"));
    assert!(
        !te.lines().any(|l| l.trim_start().starts_with("allow ")),
        "e2: end-to-end emit_te must emit NO allow line for an empty-brace AVC record; \
         got:\n{te}"
    );
    assert!(
        te.lines().any(|l| l.trim_start().starts_with('#')),
        "e2: end-to-end emit_te must emit a decline comment for the empty-perm group; \
         got:\n{te}"
    );

    // triage: no suggested allow.
    let out = render_human(&groups);
    assert!(
        !out.contains("Suggested fix:") && !out.contains("allow logrotate_t shadow_t"),
        "e2: end-to-end render_human must NOT suggest any allow for an empty-brace denial; \
         got:\n{out}"
    );
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("e2: TriageReport must serialize");
    assert!(
        !json.contains("allow logrotate_t shadow_t"),
        "e2: end-to-end build_report JSON must NOT contain an allow for the empty-perm group; \
         got:\n{json}"
    );
}
