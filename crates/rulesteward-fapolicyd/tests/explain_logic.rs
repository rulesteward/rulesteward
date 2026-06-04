//! RED barrier tests: explain rule lookup + replay fallback (#74).
//!
//! Grounding: f1 s3.4 / s4.2 / s5.1 / s5.2.
//!
//! Tests cover:
//! - Era2 rule lookup by index from hex fan_info.
//! - Exit-2 condition: rule number out of range.
//! - Era1 replay fallback via the frozen evaluate() core (#67).
//! - ReplayNoMatch when no deny rule matches.
//! - is_deny_decision() correctness.
//! - rule_text() formatting.
//! - render_human() output shape.
//! - JSON serialization shape (kind="explain").

// Section-reference notation in doc comments triggers doc_markdown; allow it
// in this test file.
#![allow(clippy::doc_markdown)]
// Test helpers use rule1/rule2/rules in the same scope.
#![allow(clippy::similar_names)]

use rulesteward_fapolicyd::{
    ExplainError, ExplainResult, MatchedBy, SetTable,
    ast::{Attr, AttrValue, Decision, Perm, Rule, SyntaxFlavor},
    explain_event,
    fanotify::{AuditEvent, FanotifyRecord, TrustVal},
    is_deny_decision, render_human, rule_text,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn span() -> std::ops::Range<usize> {
    0..0
}

fn kv(key: &str, value: &str) -> Attr {
    Attr::Kv {
        key: key.to_string(),
        value: AttrValue::Str(value.to_string()),
        span: span(),
    }
}

/// Build a minimal Rule.
fn make_rule(
    decision: Decision,
    perm: Option<Perm>,
    subject: Vec<Attr>,
    object: Vec<Attr>,
) -> Rule {
    Rule {
        decision,
        perm,
        subject,
        object,
        syntax: SyntaxFlavor::Modern,
        line: 1,
        span: span(),
    }
}

/// Build a minimal deny-all execute rule: `deny_audit perm=execute all : all`
fn deny_execute_all() -> Rule {
    make_rule(
        Decision::DenyAudit,
        Some(Perm::Execute),
        vec![Attr::All],
        vec![Attr::All],
    )
}

/// Build an allow-all open rule: `allow perm=open all : all`
fn allow_open_all() -> Rule {
    make_rule(
        Decision::Allow,
        Some(Perm::Open),
        vec![Attr::All],
        vec![Attr::All],
    )
}

/// Build a deny-all open rule.
fn deny_open_all() -> Rule {
    make_rule(
        Decision::DenyAudit,
        Some(Perm::Open),
        vec![Attr::All],
        vec![Attr::All],
    )
}

/// Build an Era2 AuditEvent with the given fan_info (already decimal).
fn era2_event(fan_info_decimal: u32, exe: Option<&str>, path: Option<&str>) -> AuditEvent {
    AuditEvent {
        fanotify: FanotifyRecord {
            resp: 2,
            fan_type: 1,
            fan_info: fan_info_decimal,
            subj_trust: TrustVal::Yes,
            obj_trust: TrustVal::No,
        },
        pid: Some(52),
        auid: None,
        exe: exe.map(String::from),
        path: path.map(String::from),
        perm: Some(Perm::Execute),
        timestamp: "1600385147.372:590".to_string(),
    }
}

/// Build an Era1 AuditEvent (fan_type=0).
fn era1_event(exe: Option<&str>, path: Option<&str>, perm: Option<Perm>) -> AuditEvent {
    AuditEvent {
        fanotify: FanotifyRecord {
            resp: 2,
            fan_type: 0,
            fan_info: 0,
            subj_trust: TrustVal::Unknown,
            obj_trust: TrustVal::Unknown,
        },
        pid: Some(51),
        auid: None,
        exe: exe.map(String::from),
        path: path.map(String::from),
        perm,
        timestamp: "1600385000.000:100".to_string(),
    }
}

// ---------------------------------------------------------------------------
// is_deny_decision
// ---------------------------------------------------------------------------

/// All four deny variants must return true.
/// Grounding: f1 §1.5 "any rule with a deny in the keyword will deny access".
#[test]
fn is_deny_decision_all_deny_variants() {
    assert!(is_deny_decision(Decision::Deny));
    assert!(is_deny_decision(Decision::DenyAudit));
    assert!(is_deny_decision(Decision::DenySyslog));
    assert!(is_deny_decision(Decision::DenyLog));
}

/// Allow variants must NOT be deny.
#[test]
fn is_deny_decision_allow_variants_are_false() {
    assert!(!is_deny_decision(Decision::Allow));
    assert!(!is_deny_decision(Decision::AllowAudit));
    assert!(!is_deny_decision(Decision::AllowSyslog));
    assert!(!is_deny_decision(Decision::AllowLog));
}

// ---------------------------------------------------------------------------
// Era2: rule lookup by index (#74)
// ---------------------------------------------------------------------------

/// Era2 fan_info=1 -> rules[0] (1-based index 1 -> 0-based index 0).
///
/// Grounding: f1 §3.3 - `e->num + 1` makes it 1-based. Index 1 is the first rule.
#[test]
fn era2_rule_index_1_resolves_to_first_rule() {
    let rule1 = deny_execute_all();
    let rule2 = allow_open_all();
    let rules: Vec<&Rule> = vec![&rule1, &rule2];
    let sets = SetTable::default();

    // fan_info=1 (hex) = 1 (decimal) -> rule index 1 -> rules[0]
    let event = era2_event(1, Some("/usr/bin/curl"), Some("/tmp/payload"));
    let result = explain_event(&event, &rules, &sets).expect("should resolve rule 1");
    assert_eq!(result.rule_number, Some(1), "rule_number must be 1");
    assert_eq!(result.matched_by, MatchedBy::RuleNumber);
    // The decision must reflect rule 1 (DenyAudit)
    assert!(
        result.decision.contains("deny"),
        "decision must contain 'deny' for DenyAudit rule"
    );
}

/// Era2 fan_info=2 (hex) = 2 decimal -> rules[1] (0-based), the second rule.
#[test]
fn era2_rule_index_2_resolves_to_second_rule() {
    let rule1 = allow_open_all();
    let rule2 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1, &rule2];
    let sets = SetTable::default();

    let event = era2_event(2, Some("/usr/bin/curl"), Some("/tmp/payload"));
    let result = explain_event(&event, &rules, &sets).expect("should resolve rule 2");
    assert_eq!(result.rule_number, Some(2));
}

/// Era2 rule out of range (fan_info=5, only 2 rules): exit-2 condition.
///
/// Grounding: f1 §4.2 - "exit 2 on ... a rule number the supplied ruleset lacks;
/// message: record references rule N, ruleset has M; do NOT guess".
#[test]
fn era2_rule_out_of_range_returns_error() {
    let rule1 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    // fan_info=5 but only 1 rule in ruleset
    let event = era2_event(5, Some("/usr/bin/curl"), Some("/tmp/payload"));
    let err = explain_event(&event, &rules, &sets).expect_err("should be RuleOutOfRange");
    assert!(
        matches!(
            err,
            ExplainError::RuleOutOfRange {
                rule_ref: 5,
                ruleset_len: 1
            }
        ),
        "must report exact rule_ref=5 and ruleset_len=1, got: {err}"
    );
}

/// Era2 with an empty ruleset: rule_ref=1, ruleset_len=0.
#[test]
fn era2_rule_1_with_empty_ruleset_is_out_of_range() {
    let rules: Vec<&Rule> = vec![];
    let sets = SetTable::default();
    let event = era2_event(1, None, None);
    let err = explain_event(&event, &rules, &sets).expect_err("empty ruleset must error");
    assert!(matches!(
        err,
        ExplainError::RuleOutOfRange {
            rule_ref: 1,
            ruleset_len: 0
        }
    ));
}

/// Era2: the worked example from f1 §3.2. fan_info=3137 (hex) = 12599 decimal.
/// A ruleset with 12599 rules is impractical for testing, but we verify that
/// fan_info=0x3137 is correctly decoded before the bounds check. With a ruleset
/// of 1 rule, the error must cite rule_ref=12599 not rule_ref=3137.
#[test]
fn era2_hex_decode_reflected_in_error_message() {
    let rule1 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    // fan_info already stored decimal in the struct (the parser converted hex -> decimal)
    let event = era2_event(12599, None, None); // 0x3137
    let err = explain_event(&event, &rules, &sets).expect_err("should error");
    assert!(
        matches!(
            err,
            ExplainError::RuleOutOfRange {
                rule_ref: 12599,
                ..
            }
        ),
        "error must cite 12599 (decoded from hex 3137), not 3137"
    );
}

// ---------------------------------------------------------------------------
// Era1: replay fallback via evaluate() (#74)
// ---------------------------------------------------------------------------

/// Era1 with exe matching a deny-execute rule: replay must find the deny rule.
///
/// Grounding: f1 §3.4 - "REPLAY the §1 algorithm using the facts recovered from
/// the SYSCALL/PATH companion records (exe/path/perm/uid)".
#[test]
fn era1_replay_finds_deny_execute_rule() {
    let rule1 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    let event = era1_event(
        Some("/usr/bin/curl"),
        Some("/tmp/payload"),
        Some(Perm::Execute),
    );
    let result = explain_event(&event, &rules, &sets).expect("replay must find deny rule");
    assert_eq!(
        result.matched_by,
        MatchedBy::Replay,
        "Era1 must be matched_by=Replay"
    );
    // The rule number comes from the replay verdict (1-based index of the matched rule)
    assert_eq!(result.rule_number, Some(1), "replay matched rule 1");
    assert!(
        result.decision.contains("deny"),
        "replay result must show deny decision"
    );
}

/// Era1 replay: if all rules are allow rules and no deny matches, return ReplayNoMatch.
///
/// Grounding: f1 §4.2 - the replay reports "the first matching deny* rule";
/// if there is none, the explain command cannot explain the denial.
#[test]
fn era1_replay_no_deny_rule_returns_error() {
    let rule1 = allow_open_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    let event = era1_event(Some("/usr/bin/curl"), Some("/tmp/x"), Some(Perm::Open));
    let err = explain_event(&event, &rules, &sets).expect_err("no deny rule -> ReplayNoMatch");
    assert!(
        matches!(err, ExplainError::ReplayNoMatch),
        "must be ReplayNoMatch, got: {err}"
    );
}

/// Era1 replay with an empty ruleset: no deny match.
#[test]
fn era1_replay_empty_ruleset_is_no_match() {
    let rules: Vec<&Rule> = vec![];
    let sets = SetTable::default();
    let event = era1_event(Some("/usr/bin/x"), Some("/etc/y"), Some(Perm::Open));
    assert!(matches!(
        explain_event(&event, &rules, &sets),
        Err(ExplainError::ReplayNoMatch)
    ));
}

/// Era1 replay with deny-open-all: finds the rule even without exe/path companion facts.
/// Grounding: f1 §1.4 - absent facts widen the match (None on a field is skipped).
#[test]
fn era1_replay_absent_facts_widen_match() {
    let rule1 = deny_open_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    // No exe, no path, perm=Open
    let event = era1_event(None, None, Some(Perm::Open));
    let result = explain_event(&event, &rules, &sets).expect("absent facts must widen to match");
    assert_eq!(result.matched_by, MatchedBy::Replay);
    assert_eq!(result.rule_number, Some(1));
}

/// Era1 replay: first deny rule in a mixed list is selected, not an allow that matched.
///
/// Grounding: f1 §3.4 - "report the first matching deny* rule".
/// The evaluate() core finds the first matching rule regardless of decision.
/// The explain replay skips allow matches and returns the first deny match.
///
/// Ruleset: [allow all open, deny all open] - the allow matches first.
/// The replay must skip the allow and find the deny.
///
/// NOTE: This tests explain's responsibility to find the first DENY,
/// not just the first match. The evaluate() core returns the first match
/// (which may be allow); explain must walk past allow verdicts.
#[test]
fn era1_replay_skips_allow_rules_to_find_deny() {
    let allow_rule = allow_open_all(); // rule 1
    let deny_rule = deny_open_all(); // rule 2
    let rules: Vec<&Rule> = vec![&allow_rule, &deny_rule];
    let sets = SetTable::default();

    // With perm=open: allow_open_all matches first, then deny_open_all.
    // The replay must return the deny rule (rule 2), labeled matched_by=Replay.
    //
    // Note: The spec says "report the first matching deny* rule" - so we scan
    // for the first deny, not just the first match.
    let event = era1_event(None, None, Some(Perm::Open));
    let result = explain_event(&event, &rules, &sets)
        .expect("must find deny rule even when allow matches first");
    assert_eq!(result.matched_by, MatchedBy::Replay);
    // The deny rule is rule 2 (1-based)
    assert_eq!(
        result.rule_number,
        Some(2),
        "replay must find rule 2 (the deny)"
    );
}

// ---------------------------------------------------------------------------
// ExplainResult fields
// ---------------------------------------------------------------------------

/// The exe, path, pid, auid fields from the AuditEvent propagate to ExplainResult.
#[test]
fn explain_result_carries_companion_fields() {
    let rule1 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    let event = AuditEvent {
        fanotify: FanotifyRecord {
            resp: 2,
            fan_type: 1,
            fan_info: 1,
            subj_trust: TrustVal::Yes,
            obj_trust: TrustVal::No,
        },
        pid: Some(99),
        auid: Some(1000),
        exe: Some("/usr/bin/curl".to_string()),
        path: Some("/tmp/payload".to_string()),
        perm: Some(Perm::Execute),
        timestamp: "1600385147.372:590".to_string(),
    };
    let result = explain_event(&event, &rules, &sets).expect("should explain");
    assert_eq!(result.exe.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(result.path.as_deref(), Some("/tmp/payload"));
    assert_eq!(result.pid, Some(99));
    assert_eq!(result.auid, Some(1000));
}

/// subj_trust and obj_trust labels are propagated from the FanotifyRecord.
#[test]
fn explain_result_trust_labels_match_record() {
    let rule1 = deny_execute_all();
    let rules: Vec<&Rule> = vec![&rule1];
    let sets = SetTable::default();

    let event = AuditEvent {
        fanotify: FanotifyRecord {
            resp: 2,
            fan_type: 1,
            fan_info: 1,
            subj_trust: TrustVal::Yes, // label = "yes"
            obj_trust: TrustVal::No,   // label = "no"
        },
        pid: None,
        auid: None,
        exe: None,
        path: None,
        perm: Some(Perm::Execute),
        timestamp: "1600385147.372:590".to_string(),
    };
    let result = explain_event(&event, &rules, &sets).expect("should explain");
    assert_eq!(result.subj_trust, "yes");
    assert_eq!(result.obj_trust, "no");
}

// ---------------------------------------------------------------------------
// rule_text formatting
// ---------------------------------------------------------------------------

/// deny_audit perm=execute all : all
#[test]
fn rule_text_deny_audit_execute_all_all() {
    let rule = deny_execute_all();
    let text = rule_text(&rule);
    // Must contain the decision keyword and the perm
    assert!(
        text.contains("deny_audit"),
        "rule_text must contain decision: got {text:?}"
    );
    assert!(
        text.contains("execute"),
        "rule_text must contain perm: got {text:?}"
    );
    // Must contain the colon separator between subject and object sides
    assert!(text.contains(':'), "rule_text must contain ':' separator");
}

/// allow perm=open all : all
#[test]
fn rule_text_allow_open_all_all() {
    let rule = allow_open_all();
    let text = rule_text(&rule);
    assert!(text.contains("allow"), "got: {text:?}");
    assert!(
        text.contains("open") || text.contains("perm"),
        "got: {text:?}"
    );
}

/// A rule with exe= attribute must include it in the text.
#[test]
fn rule_text_includes_exe_attribute() {
    let rule = make_rule(
        Decision::DenyAudit,
        Some(Perm::Execute),
        vec![kv("exe", "/usr/bin/curl")],
        vec![Attr::All],
    );
    let text = rule_text(&rule);
    assert!(
        text.contains("/usr/bin/curl"),
        "rule_text must include exe value: got {text:?}"
    );
}

// ---------------------------------------------------------------------------
// render_human output shape
// ---------------------------------------------------------------------------

/// Human output for an Era2 result must include "DENIED" (or "denied"), the exe,
/// and the rule number (f1 §4.2 format).
#[test]
fn render_human_era2_contains_key_fields() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(1),
        rule_text: "deny_audit perm=execute all : all".to_string(),
        matched_by: MatchedBy::RuleNumber,
        exe: Some("/usr/bin/curl".to_string()),
        path: Some("/tmp/payload".to_string()),
        perm: Some("execute".to_string()),
        pid: Some(52),
        auid: None,
        subj_trust: "yes".to_string(),
        obj_trust: "no".to_string(),
        uncertain: None,
    };
    let out = render_human(&result);
    // Must mention denial and the exe
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains("denied") || out_lower.contains("deny"),
        "human output must mention denial: got {out:?}"
    );
    assert!(
        out.contains("/usr/bin/curl"),
        "human output must include exe: got {out:?}"
    );
    assert!(
        out.contains('1') || out.contains("rule 1") || out.contains("rule"),
        "human output must reference the rule number: got {out:?}"
    );
    // f1 §4.2: must mention subject trust and object trust
    assert!(
        out.contains("yes") || out.contains("subject trust"),
        "human output must include trust info: got {out:?}"
    );
}

/// Human output for an Era1 replay result must include the "replay" caveat
/// (f1 §4.2: "rule number not in record; matched by replay").
#[test]
fn render_human_era1_replay_includes_caveat() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(2),
        rule_text: "deny_audit perm=open all : all".to_string(),
        matched_by: MatchedBy::Replay,
        exe: Some("/usr/bin/cat".to_string()),
        path: Some("/etc/hostname".to_string()),
        perm: Some("open".to_string()),
        pid: Some(51),
        auid: None,
        subj_trust: "unknown".to_string(),
        obj_trust: "unknown".to_string(),
        uncertain: None,
    };
    let out = render_human(&result);
    let out_lower = out.to_lowercase();
    // Must include some form of the replay caveat
    assert!(
        out_lower.contains("replay") || out_lower.contains("rule number not in record"),
        "human output for Era1 must mention replay: got {out:?}"
    );
}

/// Human output must include the uncertain reason when present (f1 §2.3 / §5.1).
#[test]
fn render_human_includes_uncertain_reason() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(3),
        rule_text: "deny_audit perm=execute all : all".to_string(),
        matched_by: MatchedBy::Replay,
        exe: None,
        path: None,
        perm: None,
        pid: None,
        auid: None,
        subj_trust: "unknown".to_string(),
        obj_trust: "unknown".to_string(),
        uncertain: Some("possible match at rule 2: pattern= not evaluable".to_string()),
    };
    let out = render_human(&result);
    assert!(
        out.contains("uncertain") || out.contains("possible match"),
        "human output must include uncertain reason: got {out:?}"
    );
}

// ---------------------------------------------------------------------------
// JSON serialization shape (#62 envelope)
// ---------------------------------------------------------------------------

/// ExplainResult serializes with the correct field names for the JSON envelope.
///
/// Grounding: f1 §4.2 JSON shape + issue #62 envelope contract.
/// The impl uses render_envelope("explain", 1, &payload) from the CLI layer;
/// this test verifies the payload struct itself serializes the correct keys.
#[test]
fn explain_result_serializes_correct_field_names() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(1),
        rule_text: "deny_audit perm=execute all : all".to_string(),
        matched_by: MatchedBy::RuleNumber,
        exe: Some("/usr/bin/curl".to_string()),
        path: Some("/tmp/x".to_string()),
        perm: Some("execute".to_string()),
        pid: Some(52),
        auid: Some(1000),
        subj_trust: "yes".to_string(),
        obj_trust: "no".to_string(),
        uncertain: None,
    };
    let json = serde_json::to_string(&result).expect("must serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("must parse back");

    // Verify required field names (snake_case by convention)
    assert!(v["decision"].is_string(), "decision field required");
    assert!(v["rule_number"].is_number(), "rule_number field required");
    assert!(v["rule_text"].is_string(), "rule_text field required");
    assert!(v["matched_by"].is_string(), "matched_by field required");
    assert!(v["subj_trust"].is_string(), "subj_trust field required");
    assert!(v["obj_trust"].is_string(), "obj_trust field required");

    // Verify values
    assert_eq!(v["decision"], "deny");
    assert_eq!(v["rule_number"], 1);
    assert_eq!(v["matched_by"], "rule_number"); // serde rename_all snake_case
}

/// matched_by=Replay serializes as "replay" (snake_case).
#[test]
fn matched_by_replay_serializes_as_snake_case() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(1),
        rule_text: "deny_audit perm=open all : all".to_string(),
        matched_by: MatchedBy::Replay,
        exe: None,
        path: None,
        perm: None,
        pid: None,
        auid: None,
        subj_trust: "unknown".to_string(),
        obj_trust: "unknown".to_string(),
        uncertain: None,
    };
    let json = serde_json::to_string(&result).expect("must serialize");
    assert!(
        json.contains("\"replay\""),
        "MatchedBy::Replay must serialize as \"replay\": {json}"
    );
}

/// uncertain=None serializes as null or is omitted (both are acceptable tolerant-reader behavior).
/// The field must not be missing when Some.
#[test]
fn uncertain_some_is_present_in_json() {
    let result = ExplainResult {
        decision: "deny".to_string(),
        rule_number: Some(1),
        rule_text: "deny_audit perm=open all : all".to_string(),
        matched_by: MatchedBy::Replay,
        exe: None,
        path: None,
        perm: None,
        pid: None,
        auid: None,
        subj_trust: "unknown".to_string(),
        obj_trust: "unknown".to_string(),
        uncertain: Some("possible match at rule 1: pattern= not evaluable".to_string()),
    };
    let json = serde_json::to_string(&result).expect("must serialize");
    assert!(
        json.contains("uncertain"),
        "uncertain field must be present when Some: {json}"
    );
    assert!(
        json.contains("pattern="),
        "uncertain reason must appear in JSON: {json}"
    );
}
