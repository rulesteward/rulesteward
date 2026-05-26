//! AST-driven lint passes - walk `&[Entry]` once and emit diagnostics for
//! F03 (mixed-syntax), E01 (unknown attribute), E02 (invalid attribute
//! value), and W02 (broad allow on execute).
//!
//! Spans on emitted diagnostics are file-relative byte ranges lifted from
//! `Rule.span` (set by the parser in session 3a). `source_id` is set to
//! `file.display().to_string()` on every rule-level diagnostic so ariadne
//! can key its Source cache.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
use crate::attrs;

/// Run F03, E01, E02, and W02 over `entries` and return the merged diagnostics.
pub fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if let Some(d) = f03(entries, file) {
        out.push(d);
    }
    out.extend(e01(entries, file));
    out.extend(e02(entries, file));
    out.extend(w02(entries, file));
    out
}

/// F03 - both `SyntaxFlavor::Modern` and `SyntaxFlavor::Legacy` present in
/// the same file. Reported on the line where the SECOND flavor first
/// appears (whichever it is).
fn f03<'e>(entries: &'e [Entry], file: &Path) -> Option<Diagnostic> {
    let mut first_modern: Option<&'e Rule> = None;
    let mut first_legacy: Option<&'e Rule> = None;
    for entry in entries {
        if let Entry::Rule(r) = entry {
            match r.syntax {
                SyntaxFlavor::Modern => {
                    first_modern.get_or_insert(r);
                }
                SyntaxFlavor::Legacy => {
                    first_legacy.get_or_insert(r);
                }
            }
        }
    }
    match (first_modern, first_legacy) {
        (Some(m), Some(l)) => {
            // The trigger is the rule with the higher line number (i.e. the
            // second flavor to appear).
            let trigger = if m.line >= l.line { m } else { l };
            Some(
                Diagnostic::new(
                    Severity::Fatal,
                    "F03",
                    trigger.span.clone(),
                    "file mixes modern (`:`) and legacy (no `:`) rule syntaxes - pick one",
                    file,
                    trigger.line,
                    1,
                )
                .with_source_id(file.display().to_string()),
            )
        }
        _ => None,
    }
}

/// E01 - attribute key not in `attrs::is_known`. Emitted once per offending
/// attribute (so a rule with two unknown keys yields two diagnostics).
fn e01(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        if let Entry::Rule(r) = entry {
            for attr in r.subject.iter().chain(r.object.iter()) {
                if let Attr::Kv { key, .. } = attr
                    && !attrs::is_known(key)
                {
                    diags.push(
                        Diagnostic::new(
                            Severity::Error,
                            "E01",
                            r.span.clone(),
                            format!("unknown attribute `{key}`"),
                            file,
                            r.line,
                            1,
                        )
                        .with_source_id(file.display().to_string()),
                    );
                }
            }
        }
    }
    diags
}

/// Validation category for an attribute key whose value shape we care
/// about for E02. Anything not represented here is out of E02's scope
/// (covered by E01 if the key is unknown, or simply not value-checked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E02Category {
    /// `uid`, `gid`, `auid`, `pid`, `ppid`, `sessionid` - accept a u32
    /// decimal, a name token (alnum / `_` / `-`), or the literal `unset`.
    NumericId,
    /// `filehash`, `sha256hash` - require exactly 64 ASCII hex chars.
    Hex64,
}

/// Look up `key` in the E02 validation table. Returns `None` if the key
/// is out of scope for E02 (either unknown - E01 territory - or known
/// but with no value-shape we lint).
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

/// E02 - invalid attribute value. Per-attribute scan; emits one diagnostic
/// per offending `Attr::Kv`. `SetRef` values (macros) are skipped - they are
/// checked by E03/E04/E05 in later milestones.
///
/// Span is the enclosing rule's span (per-attribute spans deferred per
/// spec §3f).
fn e02(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value } = attr else {
                continue;
            };
            if let AttrValue::SetRef(_) = value {
                // Macro refs are E03/E04/E05's concern, not E02's.
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
                    "E02",
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

/// W02 - broad allow on execute. Fires when the decision is one of the
/// `allow_*` family AND `perm` is `Execute` or `Any` AND both subject and
/// object are exactly `[Attr::All]`.
fn w02(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        let is_allow_class = matches!(
            r.decision,
            Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog
        );
        let is_execute_or_any = matches!(r.perm, Some(Perm::Execute | Perm::Any));
        let subject_is_all = matches!(r.subject.as_slice(), [Attr::All]);
        let object_is_all = matches!(r.object.as_slice(), [Attr::All]);

        if is_allow_class && is_execute_or_any && subject_is_all && object_is_all {
            diags.push(
                Diagnostic::new(
                    Severity::Warning,
                    "W02",
                    r.span.clone(),
                    "broad allow on execute (subject=all, object=all) - every binary on the system can run",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AttrValue, Rule};
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/tmp/test.rules")
    }

    fn modern_rule(
        line: usize,
        decision: Decision,
        perm: Option<Perm>,
        subj: Vec<Attr>,
        obj: Vec<Attr>,
    ) -> Entry {
        Entry::Rule(Rule {
            decision,
            perm,
            subject: subj,
            object: obj,
            syntax: SyntaxFlavor::Modern,
            line,
            span: rulesteward_core::span(0, 0),
        })
    }

    fn legacy_rule(
        line: usize,
        decision: Decision,
        perm: Option<Perm>,
        subj: Vec<Attr>,
        obj: Vec<Attr>,
    ) -> Entry {
        Entry::Rule(Rule {
            decision,
            perm,
            subject: subj,
            object: obj,
            syntax: SyntaxFlavor::Legacy,
            line,
            span: rulesteward_core::span(0, 0),
        })
    }

    #[test]
    fn f03_silent_when_only_modern() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![Attr::All],
        )];
        assert!(f03(&entries, &p()).is_none());
    }

    #[test]
    fn f03_fires_when_both_flavors_present() {
        let entries = vec![
            modern_rule(1, Decision::Allow, None, vec![Attr::All], vec![Attr::All]),
            legacy_rule(
                3,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "uid".into(),
                    value: AttrValue::Int(0),
                }],
                vec![Attr::Kv {
                    key: "path".into(),
                    value: AttrValue::Str("/x".into()),
                }],
            ),
        ];
        let d = f03(&entries, &p()).expect("F03 fires");
        assert_eq!(d.code.as_ref(), "F03");
        assert_eq!(d.line, 3);
        assert_eq!(d.source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn e01_fires_per_unknown_attribute() {
        let entries = vec![modern_rule(
            5,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "bogus_subj".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "bogus_obj".into(),
                value: AttrValue::Str("/x".into()),
            }],
        )];
        let diags = e01(&entries, &p());
        assert_eq!(diags.len(), 2);
        assert!(diags.iter().all(|d| d.code.as_ref() == "E01"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn w02_fires_on_canonical_allow_execute_all_all() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let diags = w02(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "W02");
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn w02_fires_on_allow_audit_variant() {
        let entries = vec![modern_rule(
            1,
            Decision::AllowAudit,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let diags = w02(&entries, &p());
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn w02_silent_when_deny() {
        let entries = vec![modern_rule(
            1,
            Decision::Deny,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        assert!(w02(&entries, &p()).is_empty());
    }

    #[test]
    fn w02_silent_when_perm_is_open() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        )];
        assert!(w02(&entries, &p()).is_empty());
    }

    #[test]
    fn w02_silent_when_subject_not_all() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            Some(Perm::Execute),
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::All],
        )];
        assert!(w02(&entries, &p()).is_empty());
    }

    // -----------------------------------------------------------------
    // E02 helper-level unit tests. Snapshot tests cover the integrated
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
        // `exe` and `path` are known attrs but E02 doesn't validate their
        // values (they accept arbitrary path strings).
        assert_eq!(classify_e02_key("exe"), None);
        assert_eq!(classify_e02_key("path"), None);
        // Unknown attrs are also None (E01's job to flag).
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
        // Two offenders in one rule -> two E02 diagnostics, both with
        // the same span (rule-level).
        let entries = vec![modern_rule(
            7,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(-1),
            }],
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::Str("abc".into()),
            }],
        )];
        let diags = e02(&entries, &p());
        assert_eq!(diags.len(), 2, "expected one diagnostic per offender");
        assert!(diags.iter().all(|d| d.code.as_ref() == "E02"));
        assert!(diags.iter().all(|d| d.severity == Severity::Error));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn e02_walker_skips_set_ref_values() {
        // Macro reference - never an E02 concern regardless of key.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::SetRef("my_uids".into()),
            }],
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::SetRef("my_hashes".into()),
            }],
        )];
        let diags = e02(&entries, &p());
        assert!(
            diags.is_empty(),
            "SetRef values are E03/E04/E05's concern, not E02: {diags:?}",
        );
    }
}
