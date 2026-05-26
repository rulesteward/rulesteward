//! Deprecated-attribute-name lint passes. Currently W07 (`sha256hash=`
//! is deprecated; use `filehash=` instead). Future deprecated-attr-name
//! warnings land here.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, Entry};

/// Run every deprecation lint pass over `entries` and return the merged
/// diagnostics.
pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    w07(entries, file)
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
            // Case-sensitive: only the lowercase form fires W07. Uppercase
            // variants like `Sha256Hash=` or `SHA256HASH=` are reported by E01
            // (unknown attribute) since fapolicyd's parser is case-sensitive
            // on attribute names. Confirmed via E01__sha256hash-uppercase trap.
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
    use crate::ast::{AttrValue, Decision, Perm, Rule, SyntaxFlavor};
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
