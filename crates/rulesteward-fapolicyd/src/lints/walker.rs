//! AST-driven lint passes - walk `&[Entry]` once and emit diagnostics for
//! F03 (mixed-syntax), E01 (unknown attribute), and W02 (broad allow on
//! execute).
//!
//! KNOWN LIMITATION (session 3+): the `span` field on diagnostics emitted
//! here is hard-coded to `0..0`. The AST (see `crate::ast`) does not carry
//! byte-range spans for individual attributes/rules, so the walker has no
//! source-position handle to thread through. Per plan §1.3 this was a
//! deliberate Session-2a deferral; a future change will add `Range<usize>`
//! span fields on `Rule` and `Attr` so `ariadne` can underline the
//! offending region.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, Decision, Entry, Perm, SyntaxFlavor};
use crate::attrs;

/// Run F03, E01, and W02 over `entries` and return the merged diagnostics.
pub fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if let Some(d) = f03(entries, file) {
        out.push(d);
    }
    out.extend(e01(entries, file));
    out.extend(w02(entries, file));
    out
}

/// F03 - both `SyntaxFlavor::Modern` and `SyntaxFlavor::Legacy` present in
/// the same file. Reported on the line where the SECOND flavor first
/// appears (whichever it is).
fn f03(entries: &[Entry], file: &Path) -> Option<Diagnostic> {
    let mut first_modern: Option<usize> = None;
    let mut first_legacy: Option<usize> = None;
    for entry in entries {
        if let Entry::Rule(r) = entry {
            match r.syntax {
                SyntaxFlavor::Modern => {
                    first_modern.get_or_insert(r.line);
                }
                SyntaxFlavor::Legacy => {
                    first_legacy.get_or_insert(r.line);
                }
            }
        }
    }
    match (first_modern, first_legacy) {
        (Some(m), Some(l)) => {
            let trigger_line = m.max(l);
            Some(Diagnostic::new(
                Severity::Fatal,
                "F03",
                0..0,
                "file mixes modern (`:`) and legacy (no `:`) rule syntaxes - pick one",
                file,
                trigger_line,
                1,
            ))
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
                    diags.push(Diagnostic::new(
                        Severity::Error,
                        "E01",
                        0..0,
                        format!("unknown attribute `{key}`"),
                        file,
                        r.line,
                        1,
                    ));
                }
            }
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
            diags.push(Diagnostic::new(
                Severity::Warning,
                "W02",
                0..0,
                "broad allow on execute (subject=all, object=all) - every binary on the system can run",
                file,
                r.line,
                1,
            ));
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
}
