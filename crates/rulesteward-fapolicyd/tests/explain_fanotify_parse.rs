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
