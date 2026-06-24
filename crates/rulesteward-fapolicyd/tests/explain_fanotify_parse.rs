//! RED barrier tests: kernel FANOTIFY / audit record parsing (#73, #75).
//!
//! Grounding: f1 s3.2 (kernel record layout, hex fan_info, trust clamp).
//!
//! Every assertion below traces to a cited primary source (grounding doc / kernel
//! source). Tests are written adversarially: a wrong impl that misreads fan_info
//! as decimal, fails to clamp trust, or misidentifies the era must fail.

// Section-reference notation (e.g. "s3.2") and format strings (e.g. "%X") in
// doc comments trigger doc_markdown; allow it in this test file.
#![allow(clippy::doc_markdown)]
// Test helpers use rule1/rule2/rules in the same scope; clippy::similar_names
// does not improve readability here.
#![allow(clippy::similar_names)]

use rulesteward_fapolicyd::{ParseError, TrustVal, parse_audit_event, parse_fanotify_record};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a fixture from the `tests/fixtures/explain/` directory.
fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/explain")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

// ---------------------------------------------------------------------------
// §73 / §3.2: FanotifyRecord parse - Era2 (fan_type=1, hex fan_info)
// ---------------------------------------------------------------------------

/// Grounding: f1 §3.2 worked example.
/// `fan_info=3137` in the record is HEX. 0x3137 = 12599 decimal.
/// A decimal-reading impl would produce 3137, not 12599 - this test kills it.
#[test]
fn era2_fan_info_is_hex_not_decimal() {
    // Real-world example from f1 §3.2 (linux-audit list).
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=3137 subj_trust=3 obj_trust=5";
    let rec = parse_fanotify_record(line).expect("should parse Era2 line");
    // fan_info=3137 (hex) = 0x3137 = 12599 decimal.
    // A wrong impl that parses fan_info as decimal returns 3137.
    assert_eq!(
        rec.fan_info, 12599,
        "fan_info=3137 (hex) must decode to 12599 decimal, not 3137"
    );
    assert_eq!(rec.fan_type, 1, "fan_type must be 1 for Era2");
    assert_eq!(rec.resp, 2, "resp=2 is FAN_DENY");
}

/// Era2 rule_number() returns Some(fan_info) when fan_type==1.
#[test]
fn era2_rule_number_is_some() {
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=3137 subj_trust=1 obj_trust=0";
    let rec = parse_fanotify_record(line).expect("should parse");
    assert_eq!(
        rec.rule_number(),
        Some(12599),
        "rule_number() must decode hex fan_info to decimal"
    );
}

/// Era2 with fan_info=1 (the ausearch fixture: rule 1 matched).
/// Hex 1 == decimal 1; simple case but verifies the parse path works for small values.
#[test]
fn era2_fan_info_1_rule_number_is_1() {
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=1 subj_trust=1 obj_trust=0";
    let rec = parse_fanotify_record(line).expect("should parse");
    assert_eq!(rec.rule_number(), Some(1));
    assert!(rec.is_deny());
}

// ---------------------------------------------------------------------------
// §73 / §3.2: FanotifyRecord parse - Era1 (fan_type=0, no rule number)
// ---------------------------------------------------------------------------

/// Era1 records have fan_type=0 and fan_info=0. rule_number() must be None.
#[test]
fn era1_rule_number_is_none() {
    let line = "type=FANOTIFY msg=audit(1600385000.000:100): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2";
    let rec = parse_fanotify_record(line).expect("should parse Era1 line");
    assert_eq!(rec.fan_type, 0, "fan_type must be 0 for Era1");
    assert_eq!(
        rec.rule_number(),
        None,
        "Era1 must have no rule number (fan_type=0)"
    );
    assert!(rec.is_deny(), "resp=2 is FAN_DENY");
}

// ---------------------------------------------------------------------------
// §73 / §3.2: Trust value clamping
// ---------------------------------------------------------------------------

/// f1 §3.2: values outside {0,1,2} must be clamped to Unknown.
/// The real-world example has subj_trust=3 obj_trust=5 (old kernel).
/// An unclamped impl would return a garbage value; this test kills it.
#[test]
fn trust_out_of_range_clamped_to_unknown() {
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=3137 subj_trust=3 obj_trust=5";
    let rec = parse_fanotify_record(line).expect("should parse with out-of-range trust");
    assert_eq!(
        rec.subj_trust,
        TrustVal::Unknown,
        "subj_trust=3 must clamp to Unknown"
    );
    assert_eq!(
        rec.obj_trust,
        TrustVal::Unknown,
        "obj_trust=5 must clamp to Unknown"
    );
}

/// trust=0 is No, trust=1 is Yes, trust=2 is Unknown.
#[test]
fn trust_values_0_1_2_decode_correctly() {
    // subj_trust=0 obj_trust=1
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=1 subj_trust=0 obj_trust=1";
    let rec = parse_fanotify_record(line).expect("should parse");
    assert_eq!(rec.subj_trust, TrustVal::No, "subj_trust=0 is No");
    assert_eq!(rec.obj_trust, TrustVal::Yes, "obj_trust=1 is Yes");

    // subj_trust=2
    let line2 = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2";
    let rec2 = parse_fanotify_record(line2).expect("should parse");
    assert_eq!(
        rec2.subj_trust,
        TrustVal::Unknown,
        "subj_trust=2 is Unknown"
    );
}

/// TrustVal::from_raw matches the above semantics directly.
#[test]
fn trust_val_from_raw_covers_all_variants() {
    assert_eq!(TrustVal::from_raw(0), TrustVal::No);
    assert_eq!(TrustVal::from_raw(1), TrustVal::Yes);
    assert_eq!(TrustVal::from_raw(2), TrustVal::Unknown);
    assert_eq!(TrustVal::from_raw(3), TrustVal::Unknown);
    assert_eq!(TrustVal::from_raw(99), TrustVal::Unknown);
}

/// TrustVal::label() returns the correct strings used in explain output (f1 §4.2).
#[test]
fn trust_val_label_matches_spec() {
    assert_eq!(TrustVal::No.label(), "no");
    assert_eq!(TrustVal::Yes.label(), "yes");
    assert_eq!(TrustVal::Unknown.label(), "unknown");
}

// ---------------------------------------------------------------------------
// §73 / §3.2: is_deny
// ---------------------------------------------------------------------------

/// resp=1 is FAN_ALLOW; is_deny() must be false.
#[test]
fn fan_allow_is_not_deny() {
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=1 fan_type=1 fan_info=1 subj_trust=1 obj_trust=1";
    let rec = parse_fanotify_record(line).expect("should parse allow record");
    assert!(!rec.is_deny(), "resp=1 (FAN_ALLOW) must not be is_deny()");
}

// ---------------------------------------------------------------------------
// §73 / §3.2: Parse errors
// ---------------------------------------------------------------------------

/// Missing fan_info must be an error, not a silent default.
#[test]
fn malformed_missing_fan_info_is_error() {
    let line =
        "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 subj_trust=1 obj_trust=0";
    assert!(
        matches!(
            parse_fanotify_record(line),
            Err(ParseError::MalformedRecord(_))
        ),
        "missing fan_info must be MalformedRecord"
    );
}

/// A line with no FANOTIFY record must return NoFanotifyRecord.
#[test]
fn non_fanotify_line_returns_no_record_error() {
    let line = "type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=257";
    assert!(
        matches!(
            parse_fanotify_record(line),
            Err(ParseError::NoFanotifyRecord)
        ),
        "non-FANOTIFY line must be NoFanotifyRecord"
    );
}

/// Empty input is an error.
#[test]
fn empty_input_is_no_fanotify_record() {
    assert!(matches!(
        parse_fanotify_record(""),
        Err(ParseError::NoFanotifyRecord)
    ));
}

// ---------------------------------------------------------------------------
// §75: Fixture-based parse tests
// ---------------------------------------------------------------------------

/// Era2 bare fixture: parse the single-line fixture file.
#[test]
fn fixture_era2_bare_parses() {
    let input = fixture("era2_bare.txt");
    let rec = parse_fanotify_record(input.trim()).expect("era2_bare fixture must parse");
    // fan_info=3137 (hex) = 12599
    assert_eq!(rec.fan_info, 12599);
    assert_eq!(rec.fan_type, 1);
    assert_eq!(rec.resp, 2);
    assert_eq!(rec.subj_trust, TrustVal::Yes); // subj_trust=1
    assert_eq!(rec.obj_trust, TrustVal::No); // obj_trust=0
}

/// Era1 bare fixture: fan_type=0 bare line.
#[test]
fn fixture_era1_bare_parses() {
    let input = fixture("era1_bare.txt");
    let rec = parse_fanotify_record(input.trim()).expect("era1_bare fixture must parse");
    assert_eq!(rec.fan_type, 0);
    assert_eq!(rec.fan_info, 0);
    assert_eq!(rec.rule_number(), None);
    assert_eq!(rec.subj_trust, TrustVal::Unknown); // subj_trust=2
    assert_eq!(rec.obj_trust, TrustVal::Unknown); // obj_trust=2
}

// ---------------------------------------------------------------------------
// §73 / §3.4: AuditEvent parse (ausearch-grouped blocks)
// ---------------------------------------------------------------------------

/// Bare FANOTIFY-only line parses into an AuditEvent with None companion fields.
#[test]
fn bare_fanotify_line_gives_none_companion_fields() {
    let line = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=1 fan_info=1 subj_trust=1 obj_trust=0";
    let event = parse_audit_event(line).expect("bare line must parse as AuditEvent");
    assert_eq!(event.fanotify.fan_type, 1);
    assert!(event.pid.is_none(), "no SYSCALL record -> pid is None");
    assert!(event.exe.is_none(), "no SYSCALL record -> exe is None");
    assert!(event.path.is_none(), "no PATH record -> path is None");
    assert!(event.perm.is_none(), "no SYSCALL record -> perm is None");
    assert_eq!(event.timestamp, "1600385147.372:590");
}

/// Ausearch-grouped Era2 block: companion records are extracted correctly.
///
/// Grounding: f1 §3.4 - pid/exe come from SYSCALL, path from PATH record.
#[test]
fn fixture_era2_ausearch_extracts_companion_fields() {
    let input = fixture("era2_ausearch.txt");
    let event = parse_audit_event(&input).expect("era2_ausearch fixture must parse");

    // FANOTIFY fields
    assert_eq!(event.fanotify.fan_type, 1);
    assert_eq!(event.fanotify.fan_info, 1); // fan_info=1 (hex 1 = decimal 1)
    assert_eq!(event.fanotify.resp, 2);

    // Companion SYSCALL fields (f1 §3.4)
    assert_eq!(event.pid, Some(52), "pid from SYSCALL record");
    assert_eq!(
        event.exe.as_deref(),
        Some("/usr/bin/coreutils"),
        "exe from SYSCALL record"
    );
    // auid=4294967295 (u32::MAX sentinel "not set") -> stored as None
    assert_eq!(
        event.auid, None,
        "auid=4294967295 sentinel must be stored as None"
    );

    // Companion PATH fields
    assert_eq!(
        event.path.as_deref(),
        Some("/etc/hostname"),
        "path from PATH record name= field"
    );

    // Timestamp
    assert_eq!(event.timestamp, "1600385147.372:590");
}

/// Ausearch-grouped Era1 block: fan_type=0, no rule number.
#[test]
fn fixture_era1_ausearch_extracts_companion_fields() {
    let input = fixture("era1_ausearch.txt");
    let event = parse_audit_event(&input).expect("era1_ausearch fixture must parse");

    assert_eq!(event.fanotify.fan_type, 0);
    assert_eq!(event.fanotify.rule_number(), None);
    assert_eq!(event.pid, Some(51));
    assert_eq!(event.exe.as_deref(), Some("/usr/bin/coreutils"));
    assert_eq!(event.path.as_deref(), Some("/etc/hostname"));
}

/// Input with no FANOTIFY line returns NoFanotifyRecord.
#[test]
fn ausearch_block_with_no_fanotify_is_error() {
    let input = "type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=257 pid=52 exe=/usr/bin/cat\n\
                 type=PATH msg=audit(1600385147.372:590): name=/etc/passwd\n";
    assert!(
        matches!(parse_audit_event(input), Err(ParseError::NoFanotifyRecord)),
        "block without FANOTIFY line must return NoFanotifyRecord"
    );
}

/// Ausearch separator lines (----) must not cause parse errors.
#[test]
fn ausearch_separator_line_is_tolerated() {
    let input = "----\n\
        type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2\n";
    let event = parse_audit_event(input).expect("separator line must be tolerated");
    assert_eq!(event.fanotify.fan_type, 0);
}

/// auid=4294967295 (the sentinel for "not set", stored as `-1` in the kernel,
/// cast to u32) must be stored as `None`, not `Some(4294967295)`.
///
/// Grounding: Linux audit sentinel value; auid is set to -1 (as u32 = u32::MAX)
/// when there is no audit session (e.g., a daemon without a login session).
#[test]
fn auid_sentinel_stored_as_none() {
    let input = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2\n\
        type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=257 success=no exit=-13 a0=1 a1=2 a2=3 a3=4 items=1 ppid=1 pid=52 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm=cat exe=/usr/bin/cat key=(null)\n";
    let event = parse_audit_event(input).expect("must parse");
    assert_eq!(
        event.auid, None,
        "auid=4294967295 sentinel must be None, not Some(4294967295)"
    );
}

/// execve syscall (syscall=59) must produce Perm::Execute.
///
/// Grounding: f1 §5.2 - "execve -> execute, else open". Syscall 59 is execve
/// on x86_64.
#[test]
fn execve_syscall_gives_execute_perm() {
    use rulesteward_fapolicyd::ast::Perm;
    let input = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2\n\
        type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=59 success=no exit=-13 a0=1 a1=2 a2=3 a3=4 items=1 ppid=1 pid=52 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=bash exe=/usr/bin/bash key=(null)\n";
    let event = parse_audit_event(input).expect("must parse");
    assert_eq!(
        event.perm,
        Some(Perm::Execute),
        "syscall=59 (execve) must map to Perm::Execute"
    );
}

/// Non-execve syscall (e.g. syscall=257 = openat) must produce Perm::Open.
#[test]
fn non_execve_syscall_gives_open_perm() {
    use rulesteward_fapolicyd::ast::Perm;
    let input = "type=FANOTIFY msg=audit(1600385147.372:590): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2\n\
        type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=257 success=no exit=-13 a0=1 a1=2 a2=3 a3=4 items=1 ppid=1 pid=52 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=cat exe=/usr/bin/cat key=(null)\n";
    let event = parse_audit_event(input).expect("must parse");
    assert_eq!(
        event.perm,
        Some(Perm::Open),
        "syscall=257 (openat) must map to Perm::Open"
    );
}

// ---------------------------------------------------------------------------
// Differential corpus: real captured FANOTIFY records from Rocky 9 and 10
// ---------------------------------------------------------------------------
//
// Corpus lives in crates/rulesteward-cli/tests/corpus/explain/fanotify/.
//
// Rocky 8 GAP: kernel 4.18 (RHEL 8 base) does NOT emit FANOTIFY audit
// events (type 1331). fapolicyd 1.3.2 on Rocky 8.10 enforces denials via
// fanotify but no audit record is written. Verified on a live Rocky 8.10 VM:
// `grep -a 'type=FANOTIFY' /var/log/audit/audit.log` returned 0 matches
// after confirmed execution denials (exit=126). The corpus directory for
// rocky8 intentionally contains no FANOTIFY records. These tests cover only
// Rocky 9 and Rocky 10, where FANOTIFY audit records are emitted.
//
// Capture note: `ausearch -m FANOTIFY` returns `<no matches>` on Rocky 9.8
// (audit 3.1.5) and Rocky 10.2 (audit 4.0.3) even when records exist in
// /var/log/audit/audit.log. The working capture command is:
//   sudo grep -a 'type=FANOTIFY' /var/log/audit/audit.log
// See corpus/*/README.md for full capture details.

/// Load a FANOTIFY record line from a real-captured corpus fixture file.
///
/// The corpus fixture files contain comment lines (starting with `#`) and
/// blank lines interspersed with real audit log lines. This helper extracts
/// the non-comment, non-empty lines -- each one is a real `type=FANOTIFY`
/// record line as captured from the live system.
fn corpus_fanotify_lines(rel_path: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-cli/tests/corpus/explain/fanotify")
        .join(rel_path);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("corpus fixture {rel_path}: {e}"));
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .map(String::from)
        .collect()
}

/// Assert the exact field decoding for a single real captured FANOTIFY record.
///
/// All records captured in this session had the same values:
///   resp=2 fan_type=1 fan_info=D subj_trust=2 obj_trust=0
///
/// Assertions:
/// - `resp=2` -> `is_deny()` is true (FAN_DENY = 2)
/// - `fan_type=1` -> Era2 (rule number present)
/// - `fan_info=D` (hex) = 0xD = 13 decimal -> `rule_number() == Some(13)`.
///   A decimal-reading mutant would decode 'D' as a parse error or 13 (same
///   here); the hex-specific kill comes from `era2_fan_info_is_hex_not_decimal`
///   using `fan_info=3137`. This assertion locks the specific value on real
///   corpus records so any regression in the hex path surfaces here too.
/// - `subj_trust=2` -> `TrustVal::Unknown`
/// - `obj_trust=0` -> `TrustVal::No`
fn assert_real_record_decodes_correctly(line: &str, context: &str) {
    let rec = parse_fanotify_record(line)
        .unwrap_or_else(|e| panic!("{context}: parse_fanotify_record failed: {e}"));

    assert!(
        rec.is_deny(),
        "{context}: resp=2 must decode as is_deny()=true"
    );
    assert_eq!(rec.resp, 2, "{context}: resp field must be 2 (FAN_DENY)");
    assert_eq!(rec.fan_type, 1, "{context}: fan_type=1 must be Era2");
    // fan_info=D is HEX. 0xD = 13 decimal. A decimal parse mutant would fail
    // to parse the non-numeric 'D' character -- the parser would return an
    // error rather than a wrong value, but this assertion locks that the
    // HEX parse succeeds and produces 13.
    assert_eq!(
        rec.fan_info, 13,
        "{context}: fan_info=D (hex) must decode to 13 decimal, not fail or produce another value"
    );
    assert_eq!(
        rec.rule_number(),
        Some(13),
        "{context}: Era2 rule_number() must be Some(13) for fan_info=D (0xD)"
    );
    assert_eq!(
        rec.subj_trust,
        TrustVal::Unknown,
        "{context}: subj_trust=2 must decode as TrustVal::Unknown"
    );
    assert_eq!(
        rec.obj_trust,
        TrustVal::No,
        "{context}: obj_trust=0 must decode as TrustVal::No"
    );
}

/// Rocky 9 corpus: both real captured records decode with the expected fields.
///
/// Corpus: crates/rulesteward-cli/tests/corpus/explain/fanotify/rocky9/ausearch.txt
/// System: Rocky Linux 9.8, audit 3.1.5, fapolicyd 1.4.5
/// Capture method: grep -a 'type=FANOTIFY' /var/log/audit/audit.log
#[test]
fn corpus_rocky9_records_decode_correctly() {
    let lines = corpus_fanotify_lines("rocky9/ausearch.txt");
    assert_eq!(
        lines.len(),
        2,
        "rocky9 corpus must contain exactly 2 real FANOTIFY records"
    );
    for (i, line) in lines.iter().enumerate() {
        assert_real_record_decodes_correctly(line, &format!("rocky9 record[{i}]"));
    }
}

/// Rocky 10 corpus: both real captured records decode with the expected fields.
///
/// Corpus: crates/rulesteward-cli/tests/corpus/explain/fanotify/rocky10/ausearch.txt
/// System: Rocky Linux 10.2, audit 4.0.3, fapolicyd 1.4.5
/// Capture method: grep -a 'type=FANOTIFY' /var/log/audit/audit.log
#[test]
fn corpus_rocky10_records_decode_correctly() {
    let lines = corpus_fanotify_lines("rocky10/ausearch.txt");
    assert_eq!(
        lines.len(),
        2,
        "rocky10 corpus must contain exactly 2 real FANOTIFY records"
    );
    for (i, line) in lines.iter().enumerate() {
        assert_real_record_decodes_correctly(line, &format!("rocky10 record[{i}]"));
    }
}

/// Differential: Rocky 9 (audit 3.1.5) and Rocky 10 (audit 4.0.3) produce
/// structurally identical FANOTIFY records.
///
/// This test locks that the FANOTIFY record format is stable across audit
/// versions: a parse change that decodes records differently on different
/// audit versions would break this test even if the per-version tests pass
/// individually.
///
/// (The captured timestamps and serials differ -- those are per-event -- but
/// the decoded field VALUES for resp/fan_type/fan_info/subj_trust/obj_trust
/// are identical because the same fapolicyd rule fired on both systems.)
#[test]
fn corpus_rocky9_and_rocky10_decode_identically() {
    let lines9 = corpus_fanotify_lines("rocky9/ausearch.txt");
    let lines10 = corpus_fanotify_lines("rocky10/ausearch.txt");

    assert!(
        !lines9.is_empty(),
        "rocky9 corpus must have at least one record"
    );
    assert!(
        !lines10.is_empty(),
        "rocky10 corpus must have at least one record"
    );

    // Parse one record from each system and compare the decoded fields.
    let rec9 = parse_fanotify_record(&lines9[0]).expect("rocky9 first record must parse");
    let rec10 = parse_fanotify_record(&lines10[0]).expect("rocky10 first record must parse");

    // The records must decode to the same struct (excluding timestamp which
    // is per-event). FanotifyRecord derives PartialEq.
    assert_eq!(
        rec9, rec10,
        "FANOTIFY record format must be identical across audit 3.1.5 (rocky9) and 4.0.3 (rocky10)"
    );
}

/// Rocky 8 gap: kernel 4.18 does not emit FANOTIFY audit events.
///
/// This test documents the gap rather than exercising records: if the corpus
/// file is ever updated with real rocky8 FANOTIFY records (i.e., a future
/// RHEL 8 backport adds kernel support), this test will fail loudly and the
/// developer must update the differential tests above to cover rocky8.
#[test]
fn corpus_rocky8_has_no_fanotify_records_kernel_4_18_gap() {
    let lines = corpus_fanotify_lines("rocky8/ausearch.txt");
    assert!(
        lines.is_empty(),
        "rocky8 corpus must contain NO FANOTIFY records (kernel 4.18 gap). \
        If this fails, the rocky8 VM now emits FANOTIFY events -- update the \
        differential tests to cover rocky8 too."
    );
}
