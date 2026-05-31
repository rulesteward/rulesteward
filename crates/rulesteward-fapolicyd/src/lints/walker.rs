//! AST-driven lint passes - walk `&[Entry]` once and emit diagnostics for
//! fapd-F03 (mixed-syntax), fapd-E01 (unknown attribute), and fapd-W02
//! (broad allow on execute).
//!
//! Spans on emitted diagnostics are file-relative byte ranges lifted from
//! `Rule.span` (set by the parser in session 3a). `source_id` is set to
//! `file.display().to_string()` on every rule-level diagnostic so ariadne
//! can key its Source cache.
//!
//! Sibling lint modules cover related families: `validation` (fapd-E02),
//! `macros` (fapd-E03/fapd-E04/fapd-E05), `deprecation` (fapd-W07).

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, Decision, Entry, Perm, Rule, SyntaxFlavor};
use crate::attrs;

/// Run fapd-F03, fapd-E01, and fapd-W02 over `entries` and return the merged
/// diagnostics.
pub fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if let Some(d) = f03(entries, file) {
        out.push(d);
    }
    out.extend(e01(entries, file));
    out.extend(w02(entries, file));
    out
}

/// fapd-F03 - both `SyntaxFlavor::Modern` and `SyntaxFlavor::Legacy` present in
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
                    "fapd-F03",
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

/// fapd-E01 - attribute key not in `attrs::is_known`. Emitted once per offending
/// attribute (so a rule with two unknown keys yields two diagnostics).
fn e01(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        if let Entry::Rule(r) = entry {
            for attr in r.subject.iter().chain(r.object.iter()) {
                if let Attr::Kv {
                    key,
                    span: attr_span,
                    ..
                } = attr
                    && !attrs::is_known(key)
                {
                    // Point the caret at the offending `key=value` attribute,
                    // not at the whole rule. Column is 1-based: byte offset of
                    // the attribute from the start of the rule line, plus 1.
                    // This assumes the rule starts at column 1 (true for all
                    // fapolicyd rules; an indented rule would diverge).
                    let col = attr_span.start - r.span.start + 1;
                    diags.push(
                        Diagnostic::new(
                            Severity::Error,
                            "fapd-E01",
                            attr_span.clone(),
                            format!("unknown attribute `{key}`"),
                            file,
                            r.line,
                            col,
                        )
                        .with_source_id(file.display().to_string()),
                    );
                }
            }
        }
    }
    diags
}

/// fapd-W02 - broad allow on execute. Fires when the decision is one of the
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
                    "fapd-W02",
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
                    span: 0..0,
                }],
                vec![Attr::Kv {
                    key: "path".into(),
                    value: AttrValue::Str("/x".into()),
                    span: 0..0,
                }],
            ),
        ];
        let d = f03(&entries, &p()).expect("fapd-F03 fires");
        assert_eq!(d.code.as_ref(), "fapd-F03");
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
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "bogus_obj".into(),
                value: AttrValue::Str("/x".into()),
                span: 0..0,
            }],
        )];
        let diags = e01(&entries, &p());
        assert_eq!(diags.len(), 2);
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E01"));
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
        assert_eq!(diags[0].code.as_ref(), "fapd-W02");
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
                span: 0..0,
            }],
            vec![Attr::All],
        )];
        assert!(w02(&entries, &p()).is_empty());
    }

    // RED test for 3f: fapd-E01 caret must point at the offending attribute,
    // not the whole rule.
    //
    // Fixture (notional source line, byte offsets):
    //   "allow uid=0 badkey=foo : all\n"
    //    ^           ^         ^
    //    byte 0      byte 12   byte 22
    //
    // rule.span  = 0..28  (the full rule)
    // uid=0 attr = 0..0   (valid, placeholder span is fine - not the lint target)
    // badkey=foo  = 12..22 (unknown key, the offending attr)
    //
    // After 3f impl:
    //   e01 reads attr.span from Attr::Kv and emits Diagnostic { span: 12..22, column: 13 }.
    //
    // Today (placeholder spans + rule-level span in e01):
    //   e01 emits Diagnostic { span: 0..28, column: 1 }.
    //   -> test is RED.
    //
    // The test asserts EXACT byte range (12..22) and column (13 = 1-based position
    // of byte 12 on a line that starts at byte 0: 12 bytes before it -> col 13).
    // Neither "use rule span (0..28)" nor "use 0..0 placeholder" passes.
    #[test]
    fn e01_caret_points_at_offending_attribute_not_rule_start() {
        // Construct a rule whose span covers bytes 0..28 (the whole rule line).
        // Subject: one valid attr (uid=0) with a placeholder span.
        // Object: one UNKNOWN attr (badkey=foo) with a precise span at bytes 12..22.
        // Column 13 = byte 12 on a line starting at byte 0 (1-based: 12+1 = 13).
        let rule_span = 0..28usize;
        let attr_span = 12..22usize; // "badkey=foo" within the fixture string
        let expected_col = 13usize; // 1 + 12 bytes before the attr on its line

        let entries = vec![Entry::Rule(Rule {
            decision: Decision::Allow,
            perm: None,
            subject: vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
                span: 0..0, // valid attr; placeholder span is intentional
            }],
            object: vec![Attr::Kv {
                key: "badkey".into(), // unknown - triggers fapd-E01
                value: AttrValue::Str("foo".into()),
                span: attr_span.clone(),
            }],
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: rule_span.clone(),
        })];

        let diags = e01(&entries, &p());
        assert_eq!(diags.len(), 1, "exactly one fapd-E01 diagnostic");
        let d = &diags[0];
        assert_eq!(d.code.as_ref(), "fapd-E01");

        // The span must be the ATTRIBUTE span, not the rule span.
        // Today e01 emits r.span (0..28); this assertion is RED.
        assert_eq!(
            d.span, attr_span,
            "fapd-E01 span must point at the offending attribute (12..22), \
             not the whole rule (0..28)"
        );

        // The column must correspond to the attribute's byte offset within
        // its source line. Column is 1-based: byte 12 from line-start -> col 13.
        // Today e01 hardcodes column 1; this assertion is also RED.
        assert_eq!(
            d.column, expected_col,
            "fapd-E01 column must be 13 (byte 12 from line start, 1-based), \
             not 1 (rule start)"
        );
    }
}
