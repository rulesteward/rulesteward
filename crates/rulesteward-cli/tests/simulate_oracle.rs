//! Data-driven oracle test for `rulesteward fapolicyd simulate`.
//!
//! Iterates every vendored scenario in `tests/corpus/simulate/` (81 total:
//! 36 happy-path + 42 adversarial + 3 neutral) and asserts the binary's
//! predicted decision and matched rule number against ground truth captured
//! from real fapolicyd (`--debug --permissive dec=` lines).
//!
//! Oracle source: `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/`
//! Vendored timestamp: 20260603T065853Z
//!
//! ## State: GREEN
//!
//! `simulate::run()` is fully implemented; all 81 scenarios below pass against
//! the vendored real-fapolicyd ground truth.
//!
//! ## JSON schema frozen by this file
//!
//! The oracle loop calls `--format json` and asserts these top-level fields:
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "kind": "simulate",
//!   "results": [
//!     {
//!       "verdict": "Decisive" | "Possible" | "NoMatch",
//!       "decision": "allow" | "deny",
//!       "matchedRule": <integer> | null,
//!       "source": "rule" | "fallthrough",
//!       "confidenceNote": "<string>"
//!     }
//!   ],
//!   "summary": { "total": <u>, "decisive": <u>, "possible": <u>, "noMatch": <u> }
//! }
//! ```
//!
//! ## Workload schema (frozen by new adversarial scenarios, session 5a follow-up)
//!
//! The JSON workload object now supports separate per-side trust overrides:
//!
//! ```json
//! {
//!   "exe": "<path>",
//!   "path": "<path>",
//!   "perm": "open" | "execute" | "any",
//!   "subjTrust": true | false | null,
//!   "objTrust": true | false | null,
//!   "trust": true | false | null
//! }
//! ```
//!
//! - `subjTrust` / `objTrust`: when present, set subject-side and object-side
//!   trust independently. These override `trust` for their respective side.
//! - `trust`: symmetric shorthand - when present and the corresponding
//!   `subjTrust` / `objTrust` is absent, sets both sides to the same value.
//!   This is the existing behavior (backwards-compatible).
//! - All three are optional; absent means `Trust::Unknown` for that side.
//!
//! - `verdict` = 3-state: `"Decisive"` (no unevaluable rule above the match),
//!   `"Possible"` (an unevaluable rule sits above the match - pattern=, ftype=
//!   without a supplied ftype, trust= without a trust DB), or `"NoMatch"`
//!   (fallthrough with no unevaluable rules encountered).
//! - `decision` = `"allow"` when any Allow* variant fires or on fallthrough;
//!   `"deny"` when any Deny* variant fires.
//! - `matchedRule` = 1-based rule number of the decisive rule, or `null` on
//!   fallthrough.
//! - `source` = `"rule"` when a rule matched, `"fallthrough"` on implicit allow.
//! - `confidenceNote` = human string; tests only assert presence, not exact text.
//!
//! ## What wrong impls these tests catch
//!
//! Each scenario in the corpus was designed to trap a specific wrong impl (see
//! `INDEX.md`). The assertions here are:
//! - Decision (`allow`/`deny`) catches OR-vs-AND confusion, prefix-vs-exact
//!   confusion, default-perm mishandling, trust defaults, execdirs/systemdirs
//!   expansion, set-ref resolution, first-match order.
//! - Rule number catches first-match vs last-match, within-file order,
//!   cross-file lexical order.
//! - 3-state verdict catches silent certainty on pattern=, ftype=, trust= cases.
//! - Floor guard (`count >= 81`) catches silent corpus-load failure.

use assert_cmd::Command;
use std::path::PathBuf;

/// Locate the vendored corpus root via `CARGO_MANIFEST_DIR`.
fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("simulate")
}

/// Load `expected.json` for a scenario.
fn load_expected(class: &str, id: &str) -> serde_json::Value {
    let path = corpus_root().join(class).join(id).join("expected.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read expected.json for {class}/{id}: {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid expected.json for {class}/{id}: {e}"))
}

/// Map `expected.decision` string ("allow" / "deny") to the canonical form
/// the simulate output uses. The Decision enum has 8 variants; all Allow* map
/// to "allow" and all Deny* map to "deny". The oracle uses these two strings.
fn canonical_verdict(decision: &str) -> &str {
    match decision {
        "allow" | "deny" => decision,
        other => panic!("unexpected decision in expected.json: {other}"),
    }
}

/// Determine expected 3-state verdict from `expected.json`.
/// - `confidence == "uncertain"` -> `"Possible"` (an unevaluable rule sits above)
/// - `source == "fallthrough"` AND no uncertainty -> `"NoMatch"`
/// - Otherwise -> `"Decisive"`
fn expected_3state(exp: &serde_json::Value) -> &'static str {
    let confidence = exp["confidence"].as_str().unwrap_or("decisive");
    let source = exp["source"].as_str().unwrap_or("rule");
    if confidence == "uncertain" {
        "Possible"
    } else if source == "fallthrough" {
        "NoMatch"
    } else {
        "Decisive"
    }
}

/// One oracle scenario: run the binary and assert decision + rule + 3-state.
#[allow(clippy::too_many_lines)]
fn assert_scenario(class: &str, id: &str) {
    let corpus = corpus_root();
    let rules_dir = corpus.join(class).join(id).join("rules.d");
    let workload = corpus.join(class).join(id).join("workload.json");
    let exp = load_expected(class, id);

    // Run: `rulesteward fapolicyd simulate --rules <dir> --workload <file> --format json`
    let output = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary must be buildable")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run binary for {class}/{id}: {e}"));

    // In RED state (todo!() stub) the binary exits 101 (panic). Every assertion
    // below will fail. That is the correct TDD state.
    let stdout = String::from_utf8_lossy(&output.stdout);

    // --- Envelope assertions ---
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{class}/{id}: output is not valid JSON (exit {}): {e}\nstdout: {stdout}",
            output.status.code().unwrap_or(-1)
        )
    });

    assert_eq!(
        json["schemaVersion"],
        serde_json::json!(1),
        "{class}/{id}: schemaVersion must be 1"
    );
    assert_eq!(
        json["kind"],
        serde_json::json!("simulate"),
        "{class}/{id}: kind must be 'simulate'"
    );

    // --- Results array ---
    let results = json["results"]
        .as_array()
        .unwrap_or_else(|| panic!("{class}/{id}: JSON must have a 'results' array, got: {json}"));
    assert!(
        !results.is_empty(),
        "{class}/{id}: results array must be non-empty"
    );
    let result = &results[0];

    // --- Decision (allow / deny) ---
    let expected_decision = canonical_verdict(exp["decision"].as_str().unwrap_or_default());
    let actual_decision = result["decision"].as_str().unwrap_or("<missing>");
    assert_eq!(
        actual_decision, expected_decision,
        "{class}/{id}: expected decision={expected_decision} but got decision={actual_decision}"
    );

    // --- 3-state verdict ---
    let expected_state = expected_3state(&exp);
    let actual_verdict = result["verdict"].as_str().unwrap_or("<missing>");
    assert_eq!(
        actual_verdict, expected_state,
        "{class}/{id}: expected verdict={expected_state} but got verdict={actual_verdict}"
    );

    // --- Matched rule number (when present in expected.json) ---
    match exp["rule_number"] {
        serde_json::Value::Null => {
            // Fallthrough or pattern-only: matchedRule must be null.
            assert!(
                result["matchedRule"].is_null(),
                "{class}/{id}: expected matchedRule=null (fallthrough) but got {}",
                result["matchedRule"]
            );
        }
        serde_json::Value::Number(ref n) => {
            let expected_rule = n.as_u64().expect("rule_number must be u64");
            let actual_rule = result["matchedRule"].as_u64().unwrap_or_else(|| {
                panic!(
                    "{class}/{id}: expected matchedRule={expected_rule} but got {}",
                    result["matchedRule"]
                )
            });
            assert_eq!(
                actual_rule, expected_rule,
                "{class}/{id}: expected matchedRule={expected_rule} but got matchedRule={actual_rule}"
            );
        }
        ref other => panic!("{class}/{id}: unexpected rule_number type in expected.json: {other}"),
    }

    // --- Source (rule / fallthrough) ---
    let expected_source = exp["source"].as_str().unwrap_or("rule");
    let actual_source = result["source"].as_str().unwrap_or("<missing>");
    assert_eq!(
        actual_source, expected_source,
        "{class}/{id}: expected source={expected_source} but got source={actual_source}"
    );

    // --- Summary counts sanity ---
    let summary = json["summary"]
        .as_object()
        .unwrap_or_else(|| panic!("{class}/{id}: JSON must have a 'summary' object"));
    assert!(
        summary.contains_key("total"),
        "{class}/{id}: summary must have 'total'"
    );
    assert!(
        summary.contains_key("decisive"),
        "{class}/{id}: summary must have 'decisive'"
    );
    assert!(
        summary.contains_key("possible"),
        "{class}/{id}: summary must have 'possible'"
    );
    assert!(
        summary.contains_key("noMatch"),
        "{class}/{id}: summary must have 'noMatch'"
    );
    let total = summary["total"].as_u64().unwrap_or(0);
    assert!(total >= 1, "{class}/{id}: summary.total must be >= 1");
}

/// Run every vendored scenario and verify the oracle.
///
/// The floor guard `count >= 81` catches a silent corpus-load failure where the
/// directory walk returns 0 scenarios but all tests trivially "pass".
#[test]
fn oracle_all_81_scenarios() {
    let corpus = corpus_root();
    let mut count = 0usize;

    for class in &["happy-path", "adversarial", "neutral"] {
        let class_dir = corpus.join(class);
        let mut entries: Vec<_> = std::fs::read_dir(&class_dir)
            .unwrap_or_else(|e| panic!("cannot read corpus/{class}: {e}"))
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .collect();
        // Deterministic order within each class for reproducible failure output.
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            let id = entry.file_name().to_string_lossy().into_owned();
            assert_scenario(class, &id);
            count += 1;
        }
    }

    assert!(
        count >= 81,
        "corpus floor: expected >= 81 scenarios but only found {count}; \
         check that the corpus was vendored correctly under tests/corpus/simulate/"
    );
}

// ---------------------------------------------------------------------------
// Class-level oracle sub-tests (per-class coverage, easier to triage)
// ---------------------------------------------------------------------------

/// Run all happy-path scenarios (36 positive controls).
#[test]
fn oracle_happy_path_class() {
    let corpus = corpus_root().join("happy-path");
    let mut count = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&corpus)
        .expect("happy-path dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let id = entry.file_name().to_string_lossy().into_owned();
        assert_scenario("happy-path", &id);
        count += 1;
    }
    assert!(
        count >= 36,
        "expected >= 36 happy-path scenarios, found {count}"
    );
}

/// Run all adversarial scenarios (42 wrong-impl traps).
#[test]
fn oracle_adversarial_class() {
    let corpus = corpus_root().join("adversarial");
    let mut count = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&corpus)
        .expect("adversarial dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let id = entry.file_name().to_string_lossy().into_owned();
        assert_scenario("adversarial", &id);
        count += 1;
    }
    assert!(
        count >= 42,
        "expected >= 42 adversarial scenarios, found {count}"
    );
}

/// Run all neutral scenarios (3 dialect / format edge cases).
#[test]
fn oracle_neutral_class() {
    let corpus = corpus_root().join("neutral");
    let mut count = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&corpus)
        .expect("neutral dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let id = entry.file_name().to_string_lossy().into_owned();
        assert_scenario("neutral", &id);
        count += 1;
    }
    assert!(count >= 3, "expected >= 3 neutral scenarios, found {count}");
}

// ---------------------------------------------------------------------------
// Targeted trap assertions (wrong-impl specific, strongest constraints)
// ---------------------------------------------------------------------------

/// first-match semantics: the FIRST matching rule wins, not the last.
/// A wrong impl that scans for any deny, or uses last-match, gets rule# wrong.
#[test]
fn firstmatch_rule_number_is_first_match() {
    assert_scenario("adversarial", "firstmatch-rule-number-is-first");
}

/// fallthrough with an empty ruleset must be ALLOW with source=fallthrough,
/// not an error and not DENY. `rule_number` must be null.
#[test]
fn empty_ruleset_fallthrough_is_allow_not_deny() {
    assert_scenario("adversarial", "empty-ruleset-all-fallthrough");
    assert_scenario("adversarial", "fallthrough-empty-ruleset-allow");
    assert_scenario("adversarial", "fallthrough-execute-no-match-allow");
}

/// AND semantics: ALL subject fields must match; OR-ing them fires wrongly.
#[test]
fn and_semantics_all_fields_required() {
    assert_scenario("adversarial", "and-object-one-fails");
    assert_scenario("adversarial", "and-subject-one-fails");
    assert_scenario("adversarial", "and-cross-subject-object-one-fails");
    assert_scenario("happy-path", "and-object-both-match");
    assert_scenario("happy-path", "and-subject-both-match");
}

/// exe= is EXACT membership: prefix or substring match is wrong.
#[test]
fn exe_exact_not_prefix() {
    assert_scenario("adversarial", "exe-exact-no-substring");
}

/// path= is EXACT: an impl treating it as dir-prefix would wrongly deny.
#[test]
fn path_exact_not_prefix() {
    assert_scenario("adversarial", "path-exact-no-substring");
}

/// dir= subject is PREFIX: an impl doing exact match would miss.
#[test]
fn dir_subject_is_prefix_match() {
    assert_scenario("happy-path", "dir-prefix-subject-match");
    assert_scenario("adversarial", "dir-prefix-subject-no-match");
}

/// odir= object is PREFIX: an impl doing exact match would miss.
#[test]
fn odir_object_is_prefix_match() {
    assert_scenario("happy-path", "odir-prefix-object-match");
    assert_scenario("adversarial", "odir-prefix-object-no-match");
}

/// comm= is EXACT: prefix/substring match is wrong.
#[test]
fn comm_exact_not_prefix() {
    assert_scenario("happy-path", "comm-exact-match");
    assert_scenario("adversarial", "comm-exact-no-match");
}

/// device= is EXACT.
#[test]
fn device_exact_match() {
    assert_scenario("happy-path", "device-exact-match-deny");
    assert_scenario("adversarial", "device-exact-no-match");
}

/// perm=any matches both open and execute; missing perm= defaults to open.
#[test]
fn perm_semantics_any_and_default_open() {
    assert_scenario("happy-path", "perm-any-matches-open");
    assert_scenario("adversarial", "perm-default-is-open");
    assert_scenario("happy-path", "perm-default-open-matches-open");
    assert_scenario("adversarial", "perm-mismatch-execute-rule-open-access");
    assert_scenario("adversarial", "perm-mismatch-open-rule-execute-access");
}

/// Set references: `%set` names must be resolved to their member lists.
#[test]
fn set_membership_resolves() {
    assert_scenario("adversarial", "set-membership-exe-resolves");
    assert_scenario("adversarial", "set-membership-exe-not-in-set");
}

/// execdirs / systemdirs macro expansion (prefix list, not a literal keyword).
#[test]
fn execdirs_systemdirs_macro_expansion() {
    assert_scenario("happy-path", "execdirs-macro-subject-match");
    assert_scenario("adversarial", "execdirs-macro-subject-no-match");
    assert_scenario("adversarial", "systemdirs-macro-includes-etc");
}

/// `exe=untrusted` is a TRUST MACRO, not a literal exe path (#126). NOTE the
/// grounded correction: `exe=untrusted` is the ONLY exe trust macro; `exe=trusted`
/// is a LITERAL exe-path compare (real fapolicyd has no `trusted` macro - f1 §1.4
/// line ~164 / `rules.c:1443-1463` (fapolicyd 1.4.5)). The literal `exe=trusted` semantics are pinned
/// by the inline `exe_trusted_is_literal_not_a_trust_macro` unit test in
/// `crates/rulesteward-fapolicyd/src/evaluate.rs`; the corpus scenarios below cover
/// only `exe=untrusted`.
///
/// Re-vendored from NFS in this feature (the two scenarios dropped in session 5a).
/// Oracle source: real fapolicyd 1.4.5 (el9/el10) `dec=` capture, in each
/// scenario's NFS `manifest.json`/`validation.log`. The vendored `expected.json`
/// reflects the modern (fapolicyd >= 1.4.x) macro semantics:
///
/// - `exe-untrusted-macro-match`: subject `/tmp/payload` is NOT trusted
///   (`trust: false`); rule 1 `deny_audit exe=untrusted : all` MUST fire ->
///   `decision=deny, matchedRule=1`. Oracle `dec_line`:
///   `rule=1 dec=deny_audit perm=open ... exe=/tmp/payload : ... trust=0`.
/// - `exe-untrusted-macro-trusted-no-match`: subject `/usr/bin/cat` IS trusted
///   (`trust: true`); rule 1 must NOT fire (the macro is inverted), so the event
///   falls through to rule 2 `allow` -> `decision=allow, matchedRule=2`. Oracle
///   `dec_line`: `rule=2 dec=allow ... : ... trust=0`.
///
/// RED until #126: the frozen `evaluate()` `"exe" =>` arm calls
/// `exact_string_match`, so `exe=untrusted` is compared as the literal string
/// `"untrusted"` against the exe path. For the match scenario that yields
/// `NoMatch` -> fallthrough to rule 2 allow (WRONG: oracle says deny rule 1).
/// (The trusted scenario passes for the WRONG reason today - exact-string
/// `NoMatch` -> fallthrough to rule 2 allow happens to coincide with the oracle;
/// the focused `exe_*_macro_*` unit tests inline in
/// `crates/rulesteward-fapolicyd/src/evaluate.rs` pin the macro semantics
/// directly so a wrong impl cannot satisfy both.)
///
/// NOTE (documented for the impl's `--help`): the macro is fapolicyd >= 1.4.x
/// only; on 1.3.2 it is INERT (the el8 oracle shows rule 1 NOT firing even for
/// an untrusted exe). The vendored corpus pins the modern (>= 1.4) behavior.
#[test]
fn exe_trust_macro_scenarios() {
    assert_scenario("adversarial", "exe-untrusted-macro-match");
    assert_scenario("adversarial", "exe-untrusted-macro-trusted-no-match");
}

/// uid= and gid= use SET INTERSECTION semantics, not exact equality.
#[test]
fn uid_gid_set_intersection() {
    assert_scenario("happy-path", "uid-intersection-single-match");
    assert_scenario("adversarial", "uid-intersection-no-overlap");
    assert_scenario("happy-path", "gid-intersection-match");
    assert_scenario("adversarial", "gid-intersection-no-overlap");
    assert_scenario("happy-path", "uid-root-zero-deny");
    assert_scenario("adversarial", "uid-zero-not-falsey-skip");
}

/// uid=0 must NOT be treated as falsey / unset.
#[test]
fn uid_zero_is_not_falsey() {
    assert_scenario("happy-path", "uid-root-zero-deny");
    assert_scenario("adversarial", "uid-zero-not-falsey-skip");
}

/// trust= subject checks subject trust; trust= object checks object trust.
/// trust=0 is the No variant; trust=1 is the Yes variant.
#[test]
fn trust_subject_vs_object_distinct() {
    assert_scenario("happy-path", "trust-subject-one-match");
    assert_scenario("happy-path", "trust-object-zero-deny");
    assert_scenario("adversarial", "trust-subject-zero-no-match");
}

/// `subjTrust` + `objTrust` INDEPENDENT: a workload expressing trusted subject opening
/// an untrusted object MUST hit `deny_audit trust=1 : trust=0`.
///
/// The canonical fapolicyd pattern for denying trusted processes accessing untrusted
/// files is `deny_audit perm=open trust=1 : trust=0`. An impl that collapses a
/// single `trust` workload field onto BOTH sides of the evaluation cannot fire this
/// rule (setting `trust=true` gives `subj_trust=Yes, obj_trust=Yes`; the object side
/// then fails `trust=0` and the rule is skipped). The fix requires separate
/// `subjTrust` / `objTrust` workload fields so the two sides can be set
/// independently. (Bug found by impl-aware adversarial review, session 5a follow-up.)
///
/// The frozen `evaluate()` DOES evaluate them independently:
/// - `eval_subject_field("trust", ...)` reads `facts.subj_trust`
/// - `eval_object_field("trust", ...)` reads `facts.obj_trust`
///
/// This is a `simulate` command bug, NOT an `evaluate()` bug.
///
/// Expected (derived from `evaluate()` with `subj_trust=Yes, obj_trust=No`):
/// `decision=deny, full_decision_keyword=deny_audit, rule_number=1,`
/// `source=rule, confidence=decisive`.
#[test]
fn both_sided_trust_killing_scenario() {
    assert_scenario("adversarial", "trust-subject-vs-object-distinct");
}

/// `resolved_exe` OVER `exe`: when `resolved_exe` is present in the workload, it
/// REPLACES `exe` for rule matching. A rule matching `/usr/bin/coreutils` must
/// fire even when the workload's `exe` field is `/usr/bin/cat`, because
/// `resolved_exe` is the canonical executable identity fapolicyd uses.
///
/// This pins the `resolved_exe`-over-`exe` preference in `parse_json_object`
/// (simulate.rs lines 116-121). Previously, no corpus scenario distinguished
/// `exe` from `resolved_exe` - a wrong impl that ignored `resolved_exe` would
/// always pass the existing corpus.
///
/// Expected (derived from `evaluate()` with `exe=/usr/bin/coreutils`):
/// `decision=deny, full_decision_keyword=deny_audit, rule_number=1,`
/// `source=rule, confidence=decisive`.
#[test]
fn exe_resolved_pins_resolved_over_raw_exe() {
    assert_scenario("adversarial", "exe-resolved-distinct");
}

/// ftype=any always matches, even when ftype is absent from the workload.
#[test]
fn ftype_any_always_matches() {
    assert_scenario("happy-path", "ftype-any-always-matches");
    assert_scenario("adversarial", "ftype-any-matches-absent-ftype");
}

/// ftype= exact (non-any): mismatch must not match; absent ftype -> `NotEvaluable`
/// (downgrade to Possible).
#[test]
fn ftype_exact_and_absent_evaluability() {
    assert_scenario("adversarial", "ftype-exact-mismatch");
    assert_scenario("adversarial", "ftype-non-evaluable-uncertain");
}

/// pattern= is runtime-only: an impl treating it as never-match (silent `NoMatch`)
/// hides a possible runtime DENY. Must report Possible, not Decisive.
#[test]
fn pattern_rule_is_not_evaluable_not_silent_no_match() {
    // Possible uncertain + allow via rule 2
    assert_scenario("adversarial", "pattern-rule-not-evaluable");
    // Possible uncertain + fallthrough (only rule is pattern=)
    assert_scenario("adversarial", "pattern-rule-only-fallthrough");
}

/// trust= without a trust DB is `NotEvaluable`: must downgrade to Possible.
/// An impl that defaults trust to 0 or 1 produces false certainty.
#[test]
fn trust_unknown_downgrades_to_possible() {
    assert_scenario("adversarial", "trust-unknown-downgrades-confidence");
}

/// All 8 decision keywords (allow/deny variants) must be recognized correctly.
/// A suffix (_audit, _syslog, _log) must NOT change the allow/deny verdict.
#[test]
fn all_decision_keywords_recognized() {
    assert_scenario("happy-path", "decision-allow-keyword");
    assert_scenario("happy-path", "decision-allow-audit-keyword");
    assert_scenario("happy-path", "decision-allow-log-keyword");
    assert_scenario("happy-path", "decision-allow-syslog-keyword");
    assert_scenario("happy-path", "decision-deny-keyword");
    assert_scenario("happy-path", "decision-deny-audit-keyword");
    assert_scenario("happy-path", "decision-deny-log-keyword");
    assert_scenario("happy-path", "decision-deny-syslog-keyword");
}

/// multi-file ruleset: files are loaded in LEXICAL (fagenrules ls -v) order.
/// Non-deterministic directory-iteration order is wrong.
#[test]
fn multifile_lexical_load_order() {
    assert_scenario("adversarial", "multifile-lexical-order-00-before-50");
    assert_scenario("adversarial", "multifile-lexical-order-deny-first-file");
    assert_scenario("adversarial", "multifile-three-files-middle-wins");
}

/// filehash / sha256hash matching: absent hash -> widen (match); present hash
/// -> exact. An impl confusing "object present, hash missing" with "no object"
/// would wrongly allow.
#[test]
fn filehash_matching_semantics() {
    assert_scenario("happy-path", "filehash-exact-match-allow");
    assert_scenario("adversarial", "filehash-missing-object-present-deny");
}

/// Comment and blank lines in rules files must be silently skipped.
/// Rule numbering starts at 1 for the first actual rule.
#[test]
fn comment_and_blank_lines_ignored_in_rule_counting() {
    assert_scenario("neutral", "comment-and-blank-lines-ignored");
}

/// absent-fact semantics: a rule field whose corresponding workload fact is
/// absent is SKIPPED (widening), not failed.
#[test]
fn absent_fact_widens_match() {
    assert_scenario("adversarial", "absent-fact-all-skipped-but-perm");
    assert_scenario("adversarial", "absent-fact-ftype-skips");
    assert_scenario("adversarial", "absent-fact-uid-skips");
}
