//! Attribute-value validation lint passes. Currently fapd-E02 (invalid
//! attribute value). Future codes that validate the SHAPE of an
//! attribute value (vs the key's existence or the value's macro-ref
//! status) land here.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};

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
    /// `filehash`, `sha256hash` - require exactly 64 ASCII hex chars.
    Hex64,
}

/// Look up `key` in the fapd-E02 validation table. Returns `None` if the key
/// is out of scope for fapd-E02 (either unknown - fapd-E01 territory - or
/// known but with no value-shape we lint).
fn classify_e02_key(key: &str) -> Option<E02Category> {
    match key {
        "uid" | "gid" | "auid" | "pid" | "ppid" | "sessionid" => Some(E02Category::NumericId),
        "filehash" | "sha256hash" => Some(E02Category::Hex64),
        _ => None,
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

/// fapd-E02 - invalid attribute value. Per-attribute scan; emits one
/// diagnostic per offending `Attr::Kv`. `SetRef` values (macros) are skipped -
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
            let Some(detail) = e02_failure_detail(category, value) else {
                continue;
            };
            diags.push(
                Diagnostic::new(
                    Severity::Error,
                    "fapd-E02",
                    r.span.clone(),
                    format!("invalid value for `{key}=`: {detail}"),
                    file,
                    r.line,
                    1,
                )
                .with_source_id(file.display().to_string()),
            );
        }
    }
    diags
}

/// Predicate adapter: returns `Some(detail)` when `value` fails the
/// validation for `category`, or `None` when it passes. The returned
/// detail string is the second half of the user-facing message; it
/// names the specific reason the value was rejected.
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
        // Hex64 - Int branch: numeric values are never valid hash values
        // (a parser-`Int` filehash means the user typed only digits, which
        // can't reach 64 characters in any realistic scenario, but is
        // still wrong-shape).
        (E02Category::Hex64, AttrValue::Int(_)) => {
            Some("expected 64 hex chars, got numeric value".to_string())
        }
        // Hex64 - Str branch: 64 chars, all ASCII hex.
        (E02Category::Hex64, AttrValue::Str(s)) => {
            let len = s.chars().count();
            if len != 64 {
                Some(format!("expected 64 hex chars, got {len} chars"))
            } else if !s.chars().all(|c| c.is_ascii_hexdigit()) {
                Some("expected 64 hex chars, contains non-hex character".to_string())
            } else {
                None
            }
        }
        // SetRef is filtered out before reaching this fn.
        (_, AttrValue::SetRef(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AttrValue, Decision};
    use crate::lints::testkit::{modern_rule, p};

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
    fn e02_classify_hex64_keys() {
        assert_eq!(classify_e02_key("filehash"), Some(E02Category::Hex64));
        assert_eq!(classify_e02_key("sha256hash"), Some(E02Category::Hex64));
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
    fn e02_hex64_accepts_canonical_64_hex_both_cases() {
        let lower = "0123456789abcdef".repeat(4);
        let upper = "0123456789ABCDEF".repeat(4);
        let mixed = "AbCdEf0123456789".repeat(4);
        for s in [lower, upper, mixed] {
            assert_eq!(s.len(), 64);
            assert!(
                e02_failure_detail(E02Category::Hex64, &AttrValue::Str(s.clone())).is_none(),
                "valid hex64 must pass: {s}",
            );
        }
    }

    #[test]
    fn e02_hex64_rejects_wrong_length() {
        // 63 and 65 both fail. 0 also fails (the parser actually rejects
        // empty values, but the predicate is defensive).
        let s63 = "a".repeat(63);
        let s65 = "a".repeat(65);
        assert!(e02_failure_detail(E02Category::Hex64, &AttrValue::Str(s63)).is_some());
        assert!(e02_failure_detail(E02Category::Hex64, &AttrValue::Str(s65)).is_some());
    }

    #[test]
    fn e02_hex64_rejects_non_hex_char_at_correct_length() {
        // 64 chars long but one is non-hex.
        let mut s = "a".repeat(63);
        s.push('z');
        assert_eq!(s.len(), 64);
        let detail =
            e02_failure_detail(E02Category::Hex64, &AttrValue::Str(s)).expect("must reject");
        assert!(
            detail.contains("non-hex"),
            "wrong reason for non-hex at correct length: {detail}",
        );
    }

    #[test]
    fn e02_hex64_rejects_int_value() {
        // A numeric `filehash=12345` parses as Int; never valid as a hash.
        assert!(e02_failure_detail(E02Category::Hex64, &AttrValue::Int(12_345)).is_some());
    }

    #[test]
    fn e02_walker_emits_one_diag_per_offending_attribute() {
        // Two offenders in one rule -> two fapd-E02 diagnostics, both with
        // the same span (rule-level).
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
        let diags = e02(&entries, &p());
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
        let diags = e02(&entries, &p());
        assert!(
            diags.is_empty(),
            "SetRef values are fapd-E03/fapd-E04/fapd-E05's concern, not fapd-E02: {diags:?}",
        );
    }
}
