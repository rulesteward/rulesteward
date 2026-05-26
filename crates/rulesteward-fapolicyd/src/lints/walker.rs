//! AST-driven lint passes - walk `&[Entry]` once and emit diagnostics for
//! F03 (mixed-syntax), E01 (unknown attribute), E02 (invalid attribute
//! value), E03 (undefined macro reference), E04 (macro reference in
//! `trust=`/`pattern=`), E05 (macro values of mixed type), W02 (broad
//! allow on execute), and W07 (deprecated `sha256hash=` attribute name).
//!
//! Spans on emitted diagnostics are file-relative byte ranges lifted from
//! `Rule.span` (set by the parser in session 3a). `source_id` is set to
//! `file.display().to_string()` on every rule-level diagnostic so ariadne
//! can key its Source cache.

use std::collections::HashSet;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
use crate::attrs;

/// Run F03, E01, E02, E03, E04, E05, W02, and W07 over `entries` and return
/// the merged diagnostics.
pub fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if let Some(d) = f03(entries, file) {
        out.push(d);
    }
    out.extend(e01(entries, file));
    out.extend(e02(entries, file));
    out.extend(e03(entries, file));
    out.extend(e04(entries, file));
    out.extend(e05(entries, file));
    out.extend(w02(entries, file));
    out.extend(w07(entries, file));
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

/// E03 - macro reference to an undefined `%setname`. Single-pass walk over
/// `entries` in source order, maintaining a `HashSet<String>` of macro names
/// seen so far. For each `Attr::Kv` with `AttrValue::SetRef(name)`, emit E03
/// if `name` is not yet in the set. This naturally enforces "definition above
/// reference" - a forward reference fires E03 because the definition has not
/// been inserted yet when the single-pass walk checks the reference.
///
/// `AttrValue::Int(_)` and `AttrValue::Str(_)` are skipped (the `let-else`
/// filters them out); only `AttrValue::SetRef(_)` participates.
///
/// Span is the enclosing rule's span (per-attribute spans deferred per
/// spec §3f).
fn e03(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut defined: HashSet<String> = HashSet::new();
    for entry in entries {
        match entry {
            Entry::SetDefinition { name, .. } => {
                defined.insert(name.clone());
            }
            Entry::Rule(r) => {
                for attr in r.subject.iter().chain(r.object.iter()) {
                    let Attr::Kv {
                        value: AttrValue::SetRef(name),
                        ..
                    } = attr
                    else {
                        continue;
                    };
                    if !defined.contains(name) {
                        diags.push(
                            Diagnostic::new(
                                Severity::Error,
                                "E03",
                                r.span.clone(),
                                format!("undefined macro reference `%{name}`"),
                                file,
                                r.line,
                                1,
                            )
                            .with_source_id(file.display().to_string()),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    diags
}

/// E04 - macro reference (`%setname`) in a `trust=` or `pattern=` attribute
/// value. fapolicyd does NOT substitute macros for these two attributes
/// regardless of whether the macro is defined, so any such reference is a
/// silent no-op at runtime. Independent of E03: a rule like
/// `trust=%undefined` fires BOTH E03 (undefined macro) and E04 (macro in
/// trust=) - the membership check in E03 and the key check in E04 operate
/// on the same `Attr::Kv` without interfering with each other.
///
/// `AttrValue::Int(_)` and `AttrValue::Str(_)` are skipped (the `let-else`
/// filters them out); only `AttrValue::SetRef(_)` participates.
///
/// Span is the enclosing rule's span (per-attribute spans deferred per
/// spec §3f).
fn e04(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv {
                key,
                value: AttrValue::SetRef(name),
            } = attr
            else {
                continue;
            };
            if key == "trust" || key == "pattern" {
                diags.push(
                    Diagnostic::new(
                        Severity::Error,
                        "E04",
                        r.span.clone(),
                        format!(
                            "macro reference `%{name}` not supported in `{key}=` (fapolicyd does not substitute macros here)"
                        ),
                        file,
                        r.line,
                        1,
                    )
                    .with_source_id(file.display().to_string()),
                );
            }
        }
    }
    diags
}

/// E05 - macro values of mixed type. For each `Entry::SetDefinition`,
/// classify each value as numeric (parses as `i64`) or string (everything
/// else). Emit one E05 diagnostic per offending set definition whose values
/// contain BOTH kinds. Single-value sets are trivially homogeneous; all-
/// numeric and all-string sets are silent. Independent of E03/E04: the set
/// definition pass runs over `Entry::SetDefinition` only, while E03/E04
/// inspect `Entry::Rule` attrs.
///
/// Numeric classification uses `str::parse::<i64>()`, which accepts signed
/// integers (`-5`), unsigned (`42`), and leading-zero ints (`01` -> 1).
/// Everything else (paths, identifiers, mixed alpha-numeric) is treated as
/// string.
fn e05(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::SetDefinition {
            name,
            values,
            line,
            span,
        } = entry
        else {
            continue;
        };
        let mut has_numeric = false;
        let mut has_string = false;
        for v in values {
            if v.parse::<i64>().is_ok() {
                has_numeric = true;
            } else {
                has_string = true;
            }
            if has_numeric && has_string {
                break;
            }
        }
        if has_numeric && has_string {
            diags.push(
                Diagnostic::new(
                    Severity::Error,
                    "E05",
                    span.clone(),
                    format!("macro `%{name}` mixes numeric and string values"),
                    file,
                    *line,
                    1,
                )
                .with_source_id(file.display().to_string()),
            );
        }
    }
    diags
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

/// W07 - deprecated `sha256hash=` attribute name. fapolicyd 1.4.2 introduced
/// `filehash=` as the canonical name for the same SHA-256 hex digest; the
/// older `sha256hash=` still parses but is no longer the preferred spelling.
/// Per-attribute scan: emit one W07 (`Severity::Warning`, not Error) for
/// each `Attr::Kv` whose key is literally `sha256hash`. A rule with two
/// such attrs emits two W07s. The value is NOT inspected here - value-
/// shape validation (64 hex chars) is E02's concern and runs independently.
fn w07(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, .. } = attr else {
                continue;
            };
            if key == "sha256hash" {
                diags.push(
                    Diagnostic::new(
                        Severity::Warning,
                        "W07",
                        r.span.clone(),
                        "deprecated attribute name `sha256hash=`; use `filehash=` instead (fapolicyd 1.4.2+)".to_string(),
                        file,
                        r.line,
                        1,
                    )
                    .with_source_id(file.display().to_string()),
                );
            }
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

    // -----------------------------------------------------------------
    // E03 helper-level unit tests. Pins the single-pass walker so each
    // branch (defined-before, defined-after, Str-with-%, Int, multiple
    // undefined refs in one rule) is exercised independently of the
    // snapshot suite. A mutant that swaps `!defined.contains(name)` for
    // `defined.contains(name)`, or moves the `defined.insert(name)` from
    // before the rule-check to after, will die here.
    // -----------------------------------------------------------------

    fn setdef(line: usize, name: &str) -> Entry {
        Entry::SetDefinition {
            name: name.to_string(),
            values: vec!["foo".to_string()],
            line,
            span: rulesteward_core::span(0, 0),
        }
    }

    #[test]
    fn e03_emits_when_ref_undefined() {
        // No definitions; a single SetRef on the subject side fires E03.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::SetRef("nope".into()),
            }],
            vec![Attr::All],
        )];
        let diags = e03(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "E03");
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(
            diags[0].message.contains("nope"),
            "message must name the undefined macro: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn e03_silent_when_ref_defined_first() {
        // Definition on entry index 0, reference on entry index 1.
        let entries = vec![
            setdef(1, "langs"),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "uid".into(),
                    value: AttrValue::SetRef("langs".into()),
                }],
                vec![Attr::All],
            ),
        ];
        let diags = e03(&entries, &p());
        assert!(
            diags.is_empty(),
            "definition above reference must silence E03: {diags:?}",
        );
    }

    #[test]
    fn e03_fires_on_forward_reference() {
        // Reference on entry index 0, definition on entry index 1.
        // The single-pass walk has NOT yet seen the definition when it
        // checks the reference, so E03 fires. Pins the forward-ref
        // decision (spec §4 Task 2).
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "uid".into(),
                    value: AttrValue::SetRef("langs".into()),
                }],
                vec![Attr::All],
            ),
            setdef(2, "langs"),
        ];
        let diags = e03(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "forward reference must fire E03 (definition below reference): {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "E03");
    }

    #[test]
    fn e03_skips_str_value_with_percent() {
        // The parser produces `AttrValue::Str` for `path=/var/%foo/x`
        // because the leading char is not `%`. E03 must skip Str values
        // even if they contain a literal `%`.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "path".into(),
                value: AttrValue::Str("/var/%foo/bar".into()),
            }],
        )];
        let diags = e03(&entries, &p());
        assert!(
            diags.is_empty(),
            "Str values are never E03's concern, even if they contain `%`: {diags:?}",
        );
    }

    #[test]
    fn e03_skips_int_value() {
        // `uid=0` is `AttrValue::Int(0)`; E03 only checks SetRef.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::All],
        )];
        let diags = e03(&entries, &p());
        assert!(
            diags.is_empty(),
            "Int values are never E03's concern: {diags:?}",
        );
    }

    #[test]
    fn e03_walker_emits_one_diag_per_undefined_ref() {
        // A single rule with TWO undefined SetRef attributes -> 2 diags.
        let entries = vec![modern_rule(
            3,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::SetRef("undef_a".into()),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::SetRef("undef_b".into()),
            }],
        )];
        let diags = e03(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one E03 per undefined ref in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "E03"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn e03_walker_skips_str_and_int_keeps_only_undefined_setrefs() {
        // Mixed rule: Str, Int, defined SetRef, undefined SetRef.
        // Only the undefined SetRef should fire.
        let entries = vec![
            setdef(1, "ok_macro"),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![
                    Attr::Kv {
                        key: "uid".into(),
                        value: AttrValue::Int(0),
                    },
                    Attr::Kv {
                        key: "auid".into(),
                        value: AttrValue::SetRef("ok_macro".into()),
                    },
                ],
                vec![
                    Attr::Kv {
                        key: "path".into(),
                        value: AttrValue::Str("/etc/passwd".into()),
                    },
                    Attr::Kv {
                        key: "exe".into(),
                        value: AttrValue::SetRef("bad_macro".into()),
                    },
                ],
            ),
        ];
        let diags = e03(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "only the undefined SetRef should fire: {diags:?}"
        );
        assert!(diags[0].message.contains("bad_macro"));
    }

    // -----------------------------------------------------------------
    // E04 helper-level unit tests. Pins the per-attribute walker so each
    // branch (trust/pattern key, SetRef value, non-SetRef value, other
    // key, multi-offender rule, independence from macro definitions)
    // is exercised independently of the snapshot suite. A mutant that
    // swaps the key comparison (e.g. `==` -> `!=`), broadens the key
    // set to include unrelated attrs, or only matches on SetRef without
    // checking the key dies here.
    // -----------------------------------------------------------------

    #[test]
    fn e04_emits_on_trust_setref() {
        // `trust=%mac` -> 1 E04 diagnostic naming the macro and the key.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "trust".into(),
                value: AttrValue::SetRef("mac".into()),
            }],
        )];
        let diags = e04(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "E04");
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(
            diags[0].message.contains("mac"),
            "message must name the macro: {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("trust"),
            "message must name the offending attribute key: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn e04_emits_on_pattern_setref() {
        // `pattern=%mac` -> 1 E04 diagnostic naming the macro and the key.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "pattern".into(),
                value: AttrValue::SetRef("mac".into()),
            }],
        )];
        let diags = e04(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "E04");
        assert!(
            diags[0].message.contains("pattern"),
            "message must name the offending attribute key: {}",
            diags[0].message,
        );
    }

    #[test]
    fn e04_silent_on_path_setref() {
        // `path=%mac` is NOT an E04 offender; only `trust`/`pattern` qualify.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "path".into(),
                value: AttrValue::SetRef("mac".into()),
            }],
        )];
        let diags = e04(&entries, &p());
        assert!(
            diags.is_empty(),
            "path= is not in the trust/pattern set; E04 must not fire: {diags:?}",
        );
    }

    #[test]
    fn e04_silent_on_trust_str_value() {
        // `trust=somestring` (parsed as Str, not SetRef) is not an E04 offender.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![Attr::Kv {
                key: "trust".into(),
                value: AttrValue::Str("yes".into()),
            }],
        )];
        let diags = e04(&entries, &p());
        assert!(
            diags.is_empty(),
            "Str values are never E04's concern: {diags:?}",
        );
    }

    #[test]
    fn e04_silent_on_trust_int_value() {
        // `trust=1` (parsed as Int) is not an E04 offender either.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![Attr::Kv {
                key: "trust".into(),
                value: AttrValue::Int(1),
            }],
        )];
        let diags = e04(&entries, &p());
        assert!(
            diags.is_empty(),
            "Int values are never E04's concern: {diags:?}",
        );
    }

    #[test]
    fn e04_walker_emits_one_per_offending_attr() {
        // A rule with `trust=%a` AND `pattern=%b` -> 2 E04 diagnostics.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "trust".into(),
                value: AttrValue::SetRef("a".into()),
            }],
            vec![Attr::Kv {
                key: "pattern".into(),
                value: AttrValue::SetRef("b".into()),
            }],
        )];
        let diags = e04(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one E04 per offending attr in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "E04"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn e04_walker_independent_of_definitions() {
        // E04 fires on `trust=%foo` whether or not `%foo` is defined.
        // (The defined-above-reference machinery is E03's concern;
        // E04 only cares about the key + SetRef value pairing.)
        let defined_entries = vec![
            setdef(1, "foo"),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![Attr::Kv {
                    key: "trust".into(),
                    value: AttrValue::SetRef("foo".into()),
                }],
            ),
        ];
        let undefined_entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![Attr::Kv {
                key: "trust".into(),
                value: AttrValue::SetRef("foo".into()),
            }],
        )];
        assert_eq!(
            e04(&defined_entries, &p()).len(),
            1,
            "E04 must fire on `trust=%foo` even when `%foo` is defined above",
        );
        assert_eq!(
            e04(&undefined_entries, &p()).len(),
            1,
            "E04 must fire on `trust=%foo` when `%foo` is undefined",
        );
    }

    // -----------------------------------------------------------------
    // E05 helper-level unit tests. Pin the per-SetDefinition walker so
    // every branch (mixed -> fire, all-numeric -> silent, all-string ->
    // silent, single-value -> silent, leading-zero -> numeric, walker
    // skips Rule entries, multi-set independence) is exercised
    // independently of the snapshot + proptest suites. A mutant that
    // swaps the `has_numeric && has_string` predicate, drops the
    // `i64::parse` classification, or fires on Rule entries dies here.
    // -----------------------------------------------------------------

    fn setdef_with_values(line: usize, name: &str, values: &[&str]) -> Entry {
        Entry::SetDefinition {
            name: name.to_string(),
            values: values.iter().map(|s| (*s).to_string()).collect(),
            line,
            span: rulesteward_core::span(0, 0),
        }
    }

    #[test]
    fn e05_emits_on_mixed_int_and_string() {
        // `%mymacro=1,2,foo,3` -> 1 E05 naming the macro.
        let entries = vec![setdef_with_values(1, "mymacro", &["1", "2", "foo", "3"])];
        let diags = e05(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "E05");
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(
            diags[0].message.contains("mymacro"),
            "message must name the macro: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn e05_silent_on_all_numeric() {
        // `%mymacro=1,2,3,4` -> all values parse as i64; no E05.
        let entries = vec![setdef_with_values(1, "mymacro", &["1", "2", "3", "4"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "all-numeric set must produce no E05: {diags:?}"
        );
    }

    #[test]
    fn e05_silent_on_all_string() {
        // `%mymacro=/bin/bash,/usr/bin/zsh` -> all values are strings; no E05.
        let entries = vec![setdef_with_values(
            1,
            "mymacro",
            &["/bin/bash", "/usr/bin/zsh"],
        )];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "all-string set must produce no E05: {diags:?}"
        );
    }

    #[test]
    fn e05_silent_on_single_value() {
        // `%mymacro=42` -> 1 value is trivially homogeneous; no E05.
        // Pins the boundary case: a single value can't be mixed.
        let entries = vec![setdef_with_values(1, "mymacro", &["42"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "single-value set must produce no E05: {diags:?}"
        );
    }

    #[test]
    fn e05_treats_leading_zero_as_numeric() {
        // `%mymacro=01,02,03` -> `parse::<i64>()` accepts "01" -> 1, etc.
        // All values are numeric; no E05. Pins the classification rule:
        // numeric = parses as i64, not "looks like a literal digit string".
        let entries = vec![setdef_with_values(1, "mymacro", &["01", "02", "03"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "leading-zero values must classify as numeric (no E05): {diags:?}",
        );
    }

    #[test]
    fn e05_walker_skips_non_setdefinition_entries() {
        // A Rule entry (no SetDefinition involved) must never fire E05.
        // Kills a mutation that fires E05 on every Entry regardless of variant.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "path".into(),
                value: AttrValue::Str("/etc/passwd".into()),
            }],
        )];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "Rule entries are not E05's concern: {diags:?}",
        );
    }

    #[test]
    fn e05_walker_emits_one_per_mixed_setdefinition() {
        // Two mixed sets in the same file -> 2 E05 diagnostics, one per
        // SetDefinition. Kills a mutation that deduplicates by name or
        // short-circuits after the first hit.
        let entries = vec![
            setdef_with_values(1, "first", &["1", "alpha"]),
            setdef_with_values(2, "second", &["beta", "2"]),
        ];
        let diags = e05(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one E05 per mixed SetDefinition: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "E05"));
        assert!(diags.iter().any(|d| d.message.contains("first")));
        assert!(diags.iter().any(|d| d.message.contains("second")));
    }

    // -----------------------------------------------------------------
    // W07 helper-level unit tests. Pin the per-attribute walker so each
    // branch (sha256hash hit, filehash silent, multi-fire in one rule,
    // key-only check ignoring value shape, severity is Warning not Error,
    // SetDefinition skipped) is exercised independently of the snapshot +
    // proptest suites. A mutant that flips the key comparison, drops the
    // Severity, broadens the key match (e.g. matching any *hash* key),
    // or fires on Entry::SetDefinition dies here.
    // -----------------------------------------------------------------

    /// 64-char canonical hex for use in W07 unit tests. W07 ignores the
    /// value but using realistic content keeps the tests readable.
    const HEX64: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    #[test]
    fn w07_emits_on_sha256hash_attr() {
        // `sha256hash=<64hex>` -> 1 W07 with Severity::Warning.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::Str("/foo".into()),
            }],
        )];
        let diags = w07(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "W07");
        assert!(
            diags[0].message.contains("sha256hash"),
            "message must name the deprecated attribute: {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("filehash"),
            "message must recommend the replacement attribute: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn w07_silent_on_filehash_attr() {
        // `filehash=<64hex>` is the modern canonical spelling; no W07.
        // Kills a mutation that broadens the key match to "any *hash key"
        // or inverts the key comparison.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::Str(HEX64.into()),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::Str("/foo".into()),
            }],
        )];
        let diags = w07(&entries, &p());
        assert!(
            diags.is_empty(),
            "filehash= is the modern spelling; W07 must not fire: {diags:?}",
        );
    }

    #[test]
    fn w07_walker_emits_one_per_offending_attr() {
        // A rule with TWO `sha256hash=` attrs (one subject, one object) ->
        // 2 W07 diagnostics. Kills a mutation that deduplicates by rule or
        // short-circuits after the first hit per rule.
        let entries = vec![modern_rule(
            5,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
            }],
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
            }],
        )];
        let diags = w07(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one W07 per offending attr in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "W07"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn w07_ignores_value_only_matches_key() {
        // W07 fires on the attribute NAME regardless of value shape; even
        // a clearly-invalid hash (a 3-char string, an Int, a SetRef) fires
        // W07. Value-shape validation is E02's concern, not W07's.
        // Kills a mutation that adds value validation to W07.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::Str("abc".into()), // bogus 3-char value
                }],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::Int(12_345), // numeric value
                }],
                vec![Attr::All],
            ),
            modern_rule(
                3,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::SetRef("my_hashes".into()), // macro ref
                }],
                vec![Attr::All],
            ),
        ];
        let diags = w07(&entries, &p());
        assert_eq!(
            diags.len(),
            3,
            "W07 fires on the key regardless of value shape (Str/Int/SetRef): {diags:?}",
        );
    }

    #[test]
    fn w07_severity_is_warning() {
        // Pin severity = Warning (not Error). Kills a mutation that
        // upgrades W07 to Error or downgrades to a non-Warning variant.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
            }],
            vec![Attr::All],
        )];
        let diags = w07(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "W07 must be Severity::Warning (not Error/Fatal/Info/Hint)",
        );
    }

    #[test]
    fn w07_walker_silent_on_setdefinition() {
        // SetDefinition entries (`%mymacro=...`) are never inspected by
        // W07; the walker only looks at Entry::Rule. Kills a mutation
        // that fires W07 on any Entry containing the string "sha256hash"
        // (e.g. a SetDefinition with that literal name).
        let entries = vec![Entry::SetDefinition {
            name: "sha256hash".to_string(),
            values: vec!["1".to_string(), "2".to_string()],
            line: 1,
            span: rulesteward_core::span(0, 0),
        }];
        let diags = w07(&entries, &p());
        assert!(
            diags.is_empty(),
            "SetDefinition entries are never W07's concern: {diags:?}",
        );
    }
}
