//! Attribute-value validation lint passes. Currently fapd-E02 (invalid
//! attribute value). Future codes that validate the SHAPE of an
//! attribute value (vs the key's existence or the value's macro-ref
//! status) land here.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};

use super::anchored;

/// Run every validation lint pass over `entries` and return the merged
/// diagnostics.
pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    e02(entries, file)
}

/// Validation category for an attribute key whose value shape we care
/// about for fapd-E02. Anything not represented here is out of fapd-E02's
/// scope (covered by fapd-E01 if the key is unknown, or simply not
/// value-checked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E02Category {
    /// `uid`, `gid`, `auid`, `pid`, `ppid`, `sessionid` - accept a u32
    /// decimal, a name token (alnum / `_` / `-`), or the literal `unset`.
    NumericId,
    /// `filehash`, `sha256hash` - accept 32 (MD5), 40 (SHA1), 64 (SHA256),
    /// or 128 (SHA512) ASCII hex chars. 32/40-hex are valid but weak (fapd-W11).
    HashDigest,
}

/// Look up `key` in the fapd-E02 / fapd-W11 validation table. Returns `None`
/// if the key is out of scope (either unknown - fapd-E01 territory - or
/// known but with no value-shape we lint).
fn classify_e02_key(key: &str) -> Option<E02Category> {
    match key {
        "uid" | "gid" | "auid" | "pid" | "ppid" | "sessionid" => Some(E02Category::NumericId),
        "filehash" | "sha256hash" => Some(E02Category::HashDigest),
        _ => None,
    }
}

/// Verdict for a hash-attribute value (`filehash=` / `sha256hash=`).
enum HashVerdict {
    /// 64-hex (SHA256) or 128-hex (SHA512): strong digest, no diagnostic.
    Ok,
    /// 32-hex (MD5) or 40-hex (SHA1): valid length, weak algorithm -> fapd-W11.
    Weak(&'static str),
    /// Wrong shape -> fapd-E02 (detail is the second half of the message).
    Invalid(String),
}

/// Classify a hash-attribute value into Ok/Weak/Invalid for the fapd-E02/W11
/// split. Upstream fapolicyd dispatches on digest length (32/40/64/128) and
/// accepts all four as `file_hash_alg_fast` candidates; `RuleSteward` mirrors
/// this by accepting the same four lengths as syntactically valid, then
/// warning on the weak algorithms (MD5 at 32-hex, SHA1 at 40-hex).
fn classify_hash_value(value: &AttrValue) -> HashVerdict {
    match value {
        AttrValue::Int(_) => {
            HashVerdict::Invalid("expected 32/40/64/128 hex chars, got numeric value".into())
        }
        AttrValue::Str(s) => {
            if !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return HashVerdict::Invalid(
                    "expected a hex digest, contains non-hex character".into(),
                );
            }
            let n = s.chars().count();
            if n == 64 || n == 128 {
                HashVerdict::Ok
            } else if let Some(alg) = crate::trustdb::weak_digest_algorithm(s) {
                // 32-hex (MD5) / 40-hex (SHA1): valid length, weak algorithm.
                HashVerdict::Weak(alg)
            } else {
                HashVerdict::Invalid(format!(
                    "expected 32, 40, 64, or 128 hex chars, got {n} chars"
                ))
            }
        }
        // SetRef is filtered out before reaching this fn.
        AttrValue::SetRef(_) => HashVerdict::Ok,
    }
}

/// Predicate: does this Str value look like a valid name-form `NumericId`?
/// Names are `unset` or any non-empty sequence of alnum / `_` / `-`.
fn is_valid_numeric_id_name(s: &str) -> bool {
    if s == "unset" {
        return true;
    }
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// fapd-E02 / fapd-W11 - attribute value validation. Per-attribute scan;
/// emits fapd-E02 (Error) for invalid values, fapd-W11 (Warning) for
/// valid-but-weak hash digests. `SetRef` values (macros) are skipped -
/// they are checked by fapd-E03/fapd-E04/fapd-E05 in later milestones.
///
/// Span is the enclosing rule's span (per-attribute spans deferred per
/// spec §3f).
fn e02(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value, .. } = attr else {
                continue;
            };
            if let AttrValue::SetRef(_) = value {
                // Macro refs are fapd-E03/fapd-E04/fapd-E05's concern, not fapd-E02's.
                continue;
            }
            let Some(category) = classify_e02_key(key) else {
                continue;
            };
            match category {
                E02Category::NumericId => {
                    if let Some(detail) = e02_failure_detail(category, value) {
                        diags.push(anchored(
                            Severity::Error,
                            "fapd-E02",
                            r.span.clone(),
                            format!("invalid value for `{key}=`: {detail}"),
                            file,
                            r.line,
                        ));
                    }
                }
                E02Category::HashDigest => match classify_hash_value(value) {
                    HashVerdict::Ok => {}
                    HashVerdict::Invalid(detail) => diags.push(anchored(
                        Severity::Error,
                        "fapd-E02",
                        r.span.clone(),
                        format!("invalid value for `{key}=`: {detail}"),
                        file,
                        r.line,
                    )),
                    HashVerdict::Weak(alg) => diags.push(anchored(
                        Severity::Warning,
                        "fapd-W11",
                        r.span.clone(),
                        format!(
                            "weak hash algorithm for `{key}=`: {alg}; prefer SHA256 (64-hex) or SHA512 (128-hex)"
                        ),
                        file,
                        r.line,
                    )),
                },
            }
        }
    }
    diags
}

/// Returns `Some(detail)` when `value` fails the validation for `category`,
/// or `None` when it passes.
///
/// For `NumericId`: checks u32 range and name-form validity.
/// For `HashDigest`: always returns `None` (the `HashDigest` branch of the
/// main validation loop calls `classify_hash_value` directly and may emit
/// either fapd-E02 or fapd-W11 depending on the verdict).
fn e02_failure_detail(category: E02Category, value: &AttrValue) -> Option<String> {
    match (category, value) {
        // NumericId - Int branch: must fit in u32 (0..=u32::MAX).
        (E02Category::NumericId, AttrValue::Int(n)) => {
            if (0..=i64::from(u32::MAX)).contains(n) {
                None
            } else {
                Some("expected u32 decimal, name, or `unset`".to_string())
            }
        }
        // NumericId - Str branch: must be `unset` or name-form.
        (E02Category::NumericId, AttrValue::Str(s)) => {
            if is_valid_numeric_id_name(s) {
                None
            } else {
                Some("expected u32 decimal, name, or `unset`".to_string())
            }
        }
        // HashDigest is handled by classify_hash_value in the main loop.
        (E02Category::HashDigest, _) | (_, AttrValue::SetRef(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AttrValue, Decision};
    use crate::lints::testkit::{kv, modern_rule, p};

    // -----------------------------------------------------------------
    // fapd-E02 helper-level unit tests. Snapshot tests cover the integrated
    // behavior; these tests pin the individual predicates so a mutant
    // in (say) the Hex64 length check dies even without a corpus run.
    // -----------------------------------------------------------------

    #[test]
    fn e02_classify_numeric_id_keys() {
        for key in ["uid", "gid", "auid", "pid", "ppid", "sessionid"] {
            assert_eq!(
                classify_e02_key(key),
                Some(E02Category::NumericId),
                "key {key} must be classified as NumericId",
            );
        }
    }

    #[test]
    fn e02_classify_hash_keys_are_in_scope() {
        // `filehash` and `sha256hash` are hash-digest keys -> classify_e02_key
        // must return Some(...) (any variant, not None). The specific variant
        // name changes from Hex64 -> HashDigest in CLEAN-3a; this test targets
        // the behavior that the key IS classified (not out-of-scope), which is
        // stable across the rename.
        assert!(
            classify_e02_key("filehash").is_some(),
            "filehash must be classified by the E02/W11 validator",
        );
        assert!(
            classify_e02_key("sha256hash").is_some(),
            "sha256hash must be classified by the E02/W11 validator",
        );
    }

    #[test]
    fn e02_classify_out_of_scope_returns_none() {
        // `exe` and `path` are known attrs but fapd-E02 doesn't validate their
        // values (they accept arbitrary path strings).
        assert_eq!(classify_e02_key("exe"), None);
        assert_eq!(classify_e02_key("path"), None);
        // Unknown attrs are also None (fapd-E01's job to flag).
        assert_eq!(classify_e02_key("xyz"), None);
    }

    #[test]
    fn e02_numeric_id_int_accepts_u32_range_inclusive() {
        // Boundary: 0, u32::MAX both pass; u32::MAX + 1 fails.
        assert!(e02_failure_detail(E02Category::NumericId, &AttrValue::Int(0)).is_none());
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Int(i64::from(u32::MAX)))
                .is_none()
        );
        assert!(
            e02_failure_detail(
                E02Category::NumericId,
                &AttrValue::Int(i64::from(u32::MAX) + 1)
            )
            .is_some()
        );
    }

    #[test]
    fn e02_numeric_id_int_rejects_negative() {
        assert!(e02_failure_detail(E02Category::NumericId, &AttrValue::Int(-1)).is_some());
        assert!(e02_failure_detail(E02Category::NumericId, &AttrValue::Int(-5)).is_some());
    }

    #[test]
    fn e02_numeric_id_str_accepts_name_and_unset() {
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Str("root".into())).is_none()
        );
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Str("unset".into())).is_none()
        );
        assert!(
            e02_failure_detail(
                E02Category::NumericId,
                &AttrValue::Str("nobody-user_1".into())
            )
            .is_none()
        );
    }

    #[test]
    fn e02_numeric_id_str_rejects_special_chars_and_empty() {
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Str(String::new())).is_some()
        );
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Str("bad name".into()))
                .is_some()
        );
        assert!(
            e02_failure_detail(E02Category::NumericId, &AttrValue::Str("bad@name".into()))
                .is_some()
        );
    }

    #[test]
    fn e02_hash_accepts_canonical_64_hex_both_cases() {
        // Renamed from e02_hex64_accepts_canonical_64_hex_both_cases.
        // After CLEAN-3a the variant is HashDigest; use classify_hash_value instead.
        // This test is a CLEAN-2 preservation anchor (GREEN before and after CLEAN-3a).
        let lower = "0123456789abcdef".repeat(4);
        let upper = "0123456789ABCDEF".repeat(4);
        let mixed = "AbCdEf0123456789".repeat(4);
        for s in [&lower, &upper, &mixed] {
            assert_eq!(s.len(), 64);
            // 64-hex is a strong digest (SHA256) -> HashVerdict::Ok -> NO diagnostic at all.
            // This assertion guards against a wrong impl that classifies 64-hex as
            // Weak -> fapd-W11: a valid SHA256 hash must produce neither E02 nor W11.
            let diags = walk(
                &[modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![],
                    vec![kv("filehash", s)],
                )],
                &p(),
            );
            assert!(
                diags.is_empty(),
                "valid 64-hex (SHA256) must produce NO diagnostic at all (no fapd-E02, no fapd-W11): {diags:?}",
            );
        }
    }

    #[test]
    fn e02_hash_rejects_off_length_neither_weak_nor_strong() {
        // Renamed from e02_hex64_rejects_wrong_length.
        // 63 and 65 chars are not in {32,40,64,128} -> fapd-E02.
        // After CLEAN-3a these must still fire E02 (the off-length branch).
        // RED until the implementation replaces the Hex64/len!=64 branch with
        // the new HashVerdict classifier. 63 fires E02 today (len!=64); 65 too.
        // After implementation, 63/65 remain E02 (not in {32,40,64,128}).
        // The test is GREEN today for 63/65 alone; but the whole test module
        // will be RED once e02_hash_accepts_canonical_64_hex_both_cases and
        // e02_classify_hash_digest_keys are written above.
        let s63 = "a".repeat(63);
        let s65 = "a".repeat(65);
        let diags63 = walk(
            &[modern_rule(
                1,
                Decision::Allow,
                None,
                vec![],
                vec![kv("filehash", &s63)],
            )],
            &p(),
        );
        let diags65 = walk(
            &[modern_rule(
                1,
                Decision::Allow,
                None,
                vec![],
                vec![kv("filehash", &s65)],
            )],
            &p(),
        );
        assert!(
            diags63.iter().any(|d| d.code.as_ref() == "fapd-E02"),
            "63-hex must produce fapd-E02: {diags63:?}",
        );
        assert!(
            diags65.iter().any(|d| d.code.as_ref() == "fapd-E02"),
            "65-hex must produce fapd-E02: {diags65:?}",
        );
    }

    #[test]
    fn e02_hash_rejects_non_hex_char_at_correct_length() {
        // Renamed from e02_hex64_rejects_non_hex_char_at_correct_length.
        // 64 chars long but one is non-hex -> fapd-E02 (non-hex check remains
        // after CLEAN-3a). Preservation anchor: must still fire E02.
        let mut s = "a".repeat(63);
        s.push('z');
        assert_eq!(s.len(), 64);
        let diags = walk(
            &[modern_rule(
                1,
                Decision::Allow,
                None,
                vec![],
                vec![kv("filehash", &s)],
            )],
            &p(),
        );
        let e02 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E02")
            .expect("64 non-hex chars must produce fapd-E02");
        assert!(
            e02.message.contains("non-hex"),
            "E02 message for non-hex at correct length must mention non-hex: {}",
            e02.message,
        );
    }

    #[test]
    fn e02_hash_rejects_int_value() {
        // Renamed from e02_hex64_rejects_int_value.
        // A numeric `filehash=12345` parses as Int; never valid as a hash.
        // After CLEAN-3a this must still fire E02 (Int branch is unchanged).
        let diags = walk(
            &[modern_rule(
                1,
                Decision::Allow,
                None,
                vec![],
                vec![Attr::Kv {
                    key: "filehash".into(),
                    value: AttrValue::Int(12_345),
                    span: 0..0,
                }],
            )],
            &p(),
        );
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-E02"),
            "numeric filehash value must produce fapd-E02: {diags:?}",
        );
    }

    #[test]
    fn e02_walker_emits_one_diag_per_offending_attribute() {
        // Two offenders in one rule -> two fapd-E02 diagnostics, both with
        // the same span (rule-level). Updated to call walk() (public interface)
        // so the test remains valid after CLEAN-3a renames/reorganizes internals.
        // filehash=abc is 3 chars -> off-length (not in {32,40,64,128}) -> E02.
        let entries = vec![modern_rule(
            7,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(-1),
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::Str("abc".into()),
                span: 0..0,
            }],
        )];
        let diags = walk(&entries, &p());
        assert_eq!(diags.len(), 2, "expected one diagnostic per offender");
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E02"));
        assert!(diags.iter().all(|d| d.severity == Severity::Error));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn e02_walker_skips_set_ref_values() {
        // Macro reference - never an fapd-E02 concern regardless of key.
        // Updated to call walk() (public interface).
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::SetRef("my_uids".into()),
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::SetRef("my_hashes".into()),
                span: 0..0,
            }],
        )];
        let diags = walk(&entries, &p());
        assert!(
            diags.is_empty(),
            "SetRef values are fapd-E03/fapd-E04/fapd-E05's concern, not fapd-E02: {diags:?}",
        );
    }

    // -----------------------------------------------------------------
    // CLEAN-3a: RED barrier tests for fapd-E02 widen + new fapd-W11
    //
    // Three of the four tests below are RED today (assertion failures):
    //   - e02_accepts_128_hex_sha512:  current len!=64 check fires E02 on 128.
    //   - w11_warns_on_md5_length_not_e02: W11 does not exist; E02 fires on 32.
    //   - w11_warns_on_sha1_length:    W11 does not exist; E02 fires on 40.
    //
    // Note on e02_still_errors_on_off_length_and_non_hex: this test is GREEN
    // today (current code fires E02 for both 50-hex and 64-non-hex). The original
    // plan claimed the 64-non-hex case was RED, but that is incorrect: the current
    // code checks length FIRST (fires on 50 since 50!=64) and non-hex SECOND
    // (fires on 64 non-hex since z is not a hex digit). This test is therefore a
    // PRESERVATION ANCHOR, not a RED barrier. It is included to prevent the
    // CLEAN-3a implementation from accidentally accepting malformed values.
    // The RED state of the module comes from the three assertion failures above.
    // -----------------------------------------------------------------

    #[test]
    fn e02_accepts_128_hex_sha512() {
        // 128 lowercase-hex is a valid SHA512 digest -> must NOT fire fapd-E02.
        // RED today: current len!=64 check fires E02 on 128.
        // Ideally yields no diagnostic at all (no W11 for strong digests).
        let v = "a".repeat(128);
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![],
            vec![kv("filehash", &v)],
        )];
        let diags = walk(&entries, &p());
        assert!(
            diags.iter().all(|d| d.code.as_ref() != "fapd-E02"),
            "128-hex SHA512 must not fire fapd-E02 (strong digest); got: {diags:?}",
        );
        assert!(
            diags.is_empty(),
            "strong SHA512 digest must yield no diagnostic at all; got: {diags:?}",
        );
    }

    #[test]
    fn w11_warns_on_md5_length_not_e02() {
        // 32 lowercase-hex is a valid MD5 digest -> weak digest -> fapd-W11 Warning.
        // Must NOT fire fapd-E02.
        // RED today: W11 does not exist; E02 fires on 32-hex (len!=64).
        let v = "a".repeat(32);
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![],
            vec![kv("filehash", &v)],
        )];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "MD5-length digest must yield exactly one diagnostic (fapd-W11); got: {diags:?}",
        );
        assert_eq!(
            diags[0].code.as_ref(),
            "fapd-W11",
            "MD5-length digest must produce fapd-W11, not {:?}",
            diags[0].code,
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W11 must have Warning severity; got {:?}",
            diags[0].severity,
        );
        assert!(
            diags[0].message.contains("MD5"),
            "fapd-W11 message must mention MD5; got: {}",
            diags[0].message,
        );
        assert!(
            !diags[0].message.contains("SHA1"),
            "fapd-W11 for MD5-length must NOT mention SHA1 (algo-specificity guard); got: {}",
            diags[0].message,
        );
        assert!(
            diags.iter().all(|d| d.code.as_ref() != "fapd-E02"),
            "MD5-length digest must not fire fapd-E02; got: {diags:?}",
        );
    }

    #[test]
    fn w11_warns_on_sha1_length() {
        // 40 lowercase-hex is a valid SHA1 digest -> weak digest -> fapd-W11 Warning.
        // Must NOT fire fapd-E02.
        // RED today: W11 does not exist; E02 fires on 40-hex (len!=64).
        let v = "a".repeat(40);
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![],
            vec![kv("filehash", &v)],
        )];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "SHA1-length digest must yield exactly one diagnostic (fapd-W11); got: {diags:?}",
        );
        assert_eq!(
            diags[0].code.as_ref(),
            "fapd-W11",
            "SHA1-length digest must produce fapd-W11, not {:?}",
            diags[0].code,
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W11 must have Warning severity; got {:?}",
            diags[0].severity,
        );
        assert!(
            diags[0].message.contains("SHA1"),
            "fapd-W11 message must mention SHA1; got: {}",
            diags[0].message,
        );
        assert!(
            !diags[0].message.contains("MD5"),
            "fapd-W11 for SHA1-length must NOT mention MD5 (algo-specificity guard); got: {}",
            diags[0].message,
        );
        assert!(
            diags.iter().all(|d| d.code.as_ref() != "fapd-E02"),
            "SHA1-length digest must not fire fapd-E02; got: {diags:?}",
        );
    }

    #[test]
    fn e02_still_errors_on_off_length_and_non_hex() {
        // Preservation anchor: malformed digests must still produce fapd-E02.
        //   - filehash with 50 hex chars: not in {32,40,64,128} -> E02.
        //   - filehash with 64 non-hex chars (`z`): right length, not hex -> E02.
        // Note: this test is GREEN today (current code already fires E02 for both
        // cases). It is included to prevent the CLEAN-3a implementation from
        // accidentally widening acceptance to cover malformed values.
        let bad_len_entry = modern_rule(
            1,
            Decision::Allow,
            None,
            vec![],
            vec![kv("filehash", &"a".repeat(50))],
        );
        let non_hex_entry = modern_rule(
            2,
            Decision::Allow,
            None,
            vec![],
            vec![kv("filehash", &"z".repeat(64))],
        );
        let diags = walk(&[bad_len_entry, non_hex_entry], &p());
        let e02_count = diags
            .iter()
            .filter(|d| d.code.as_ref() == "fapd-E02")
            .count();
        assert_eq!(
            e02_count, 2,
            "both 50-hex (off-length) and 64-non-hex (non-hex) must produce fapd-E02 each; \
             got {e02_count} fapd-E02 diagnostics: {diags:?}",
        );
    }
}
