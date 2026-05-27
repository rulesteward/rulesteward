//! Macro-related lint passes. Currently fapd-E03 (undefined macro
//! reference), fapd-E04 (macro reference in `trust=`/`pattern=`), fapd-E05
//! (macro values of mixed type). Future macro-system checks land
//! here.

use std::collections::HashSet;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};

/// Run every macro-related lint pass over `entries` and return the
/// merged diagnostics.
pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    out.extend(e03(entries, file));
    out.extend(e04(entries, file));
    out.extend(e05(entries, file));
    out
}

/// fapd-E03 - macro reference to an undefined `%setname`. Single-pass walk
/// over `entries` in source order, maintaining a `HashSet<String>` of macro
/// names seen so far. For each `Attr::Kv` with `AttrValue::SetRef(name)`, emit
/// fapd-E03 if `name` is not yet in the set. This naturally enforces "definition
/// above reference" - a forward reference fires fapd-E03 because the definition
/// has not been inserted yet when the single-pass walk checks the reference.
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
                                "fapd-E03",
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

/// fapd-E04 - macro reference (`%setname`) in a `trust=` or `pattern=`
/// attribute value. fapolicyd does NOT substitute macros for these two
/// attributes regardless of whether the macro is defined, so any such
/// reference is a silent no-op at runtime. Independent of fapd-E03: a rule
/// like `trust=%undefined` fires BOTH fapd-E03 (undefined macro) and
/// fapd-E04 (macro in trust=) - the membership check in fapd-E03 and the
/// key check in fapd-E04 operate on the same `Attr::Kv` without interfering
/// with each other.
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
                        "fapd-E04",
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

/// fapd-E05 - macro values of mixed type. For each `Entry::SetDefinition`,
/// classify each value as numeric (parses as `i64`) or string (everything
/// else). Emit one fapd-E05 diagnostic per offending set definition whose
/// values contain BOTH kinds. Single-value sets are trivially homogeneous;
/// all-numeric and all-string sets are silent. Independent of fapd-E03/
/// fapd-E04: the set definition pass runs over `Entry::SetDefinition` only,
/// while fapd-E03/fapd-E04 inspect `Entry::Rule` attrs.
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
                    "fapd-E05",
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
    // fapd-E03 helper-level unit tests. Pins the single-pass walker so each
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
        // No definitions; a single SetRef on the subject side fires fapd-E03.
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
        assert_eq!(diags[0].code.as_ref(), "fapd-E03");
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
            "definition above reference must silence fapd-E03: {diags:?}",
        );
    }

    #[test]
    fn e03_fires_on_forward_reference() {
        // Reference on entry index 0, definition on entry index 1.
        // The single-pass walk has NOT yet seen the definition when it
        // checks the reference, so fapd-E03 fires. Pins the forward-ref
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
            "forward reference must fire fapd-E03 (definition below reference): {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-E03");
    }

    #[test]
    fn e03_skips_str_value_with_percent() {
        // The parser produces `AttrValue::Str` for `path=/var/%foo/x`
        // because the leading char is not `%`. fapd-E03 must skip Str values
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
            "Str values are never fapd-E03's concern, even if they contain `%`: {diags:?}",
        );
    }

    #[test]
    fn e03_skips_int_value() {
        // `uid=0` is `AttrValue::Int(0)`; fapd-E03 only checks SetRef.
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
            "Int values are never fapd-E03's concern: {diags:?}",
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
            "expected one fapd-E03 per undefined ref in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E03"));
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
    // fapd-E04 helper-level unit tests. Pins the per-attribute walker so
    // each branch (trust/pattern key, SetRef value, non-SetRef value,
    // other key, multi-offender rule, independence from macro definitions)
    // is exercised independently of the snapshot suite. A mutant that
    // swaps the key comparison (e.g. `==` -> `!=`), broadens the key
    // set to include unrelated attrs, or only matches on SetRef without
    // checking the key dies here.
    // -----------------------------------------------------------------

    #[test]
    fn e04_emits_on_trust_setref() {
        // `trust=%mac` -> 1 fapd-E04 diagnostic naming the macro and the key.
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
        assert_eq!(diags[0].code.as_ref(), "fapd-E04");
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
        // `pattern=%mac` -> 1 fapd-E04 diagnostic naming the macro and the key.
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
        assert_eq!(diags[0].code.as_ref(), "fapd-E04");
        assert!(
            diags[0].message.contains("pattern"),
            "message must name the offending attribute key: {}",
            diags[0].message,
        );
    }

    #[test]
    fn e04_silent_on_path_setref() {
        // `path=%mac` is NOT an fapd-E04 offender; only `trust`/`pattern` qualify.
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
            "path= is not in the trust/pattern set; fapd-E04 must not fire: {diags:?}",
        );
    }

    #[test]
    fn e04_silent_on_trust_str_value() {
        // `trust=somestring` (parsed as Str, not SetRef) is not an fapd-E04 offender.
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
            "Str values are never fapd-E04's concern: {diags:?}",
        );
    }

    #[test]
    fn e04_silent_on_trust_int_value() {
        // `trust=1` (parsed as Int) is not an fapd-E04 offender either.
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
            "Int values are never fapd-E04's concern: {diags:?}",
        );
    }

    #[test]
    fn e04_walker_emits_one_per_offending_attr() {
        // A rule with `trust=%a` AND `pattern=%b` -> 2 fapd-E04 diagnostics.
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
            "expected one fapd-E04 per offending attr in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E04"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn e04_walker_independent_of_definitions() {
        // fapd-E04 fires on `trust=%foo` whether or not `%foo` is defined.
        // (The defined-above-reference machinery is fapd-E03's concern;
        // fapd-E04 only cares about the key + SetRef value pairing.)
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
            "fapd-E04 must fire on `trust=%foo` even when `%foo` is defined above",
        );
        assert_eq!(
            e04(&undefined_entries, &p()).len(),
            1,
            "fapd-E04 must fire on `trust=%foo` when `%foo` is undefined",
        );
    }

    // -----------------------------------------------------------------
    // fapd-E05 helper-level unit tests. Pin the per-SetDefinition walker
    // so every branch (mixed -> fire, all-numeric -> silent, all-string ->
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
        // `%mymacro=1,2,foo,3` -> 1 fapd-E05 naming the macro.
        let entries = vec![setdef_with_values(1, "mymacro", &["1", "2", "foo", "3"])];
        let diags = e05(&entries, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "fapd-E05");
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
        // `%mymacro=1,2,3,4` -> all values parse as i64; no fapd-E05.
        let entries = vec![setdef_with_values(1, "mymacro", &["1", "2", "3", "4"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "all-numeric set must produce no fapd-E05: {diags:?}"
        );
    }

    #[test]
    fn e05_silent_on_all_string() {
        // `%mymacro=/bin/bash,/usr/bin/zsh` -> all values are strings; no fapd-E05.
        let entries = vec![setdef_with_values(
            1,
            "mymacro",
            &["/bin/bash", "/usr/bin/zsh"],
        )];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "all-string set must produce no fapd-E05: {diags:?}"
        );
    }

    #[test]
    fn e05_silent_on_single_value() {
        // `%mymacro=42` -> 1 value is trivially homogeneous; no fapd-E05.
        // Pins the boundary case: a single value can't be mixed.
        let entries = vec![setdef_with_values(1, "mymacro", &["42"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "single-value set must produce no fapd-E05: {diags:?}"
        );
    }

    #[test]
    fn e05_treats_leading_zero_as_numeric() {
        // `%mymacro=01,02,03` -> `parse::<i64>()` accepts "01" -> 1, etc.
        // All values are numeric; no fapd-E05. Pins the classification rule:
        // numeric = parses as i64, not "looks like a literal digit string".
        let entries = vec![setdef_with_values(1, "mymacro", &["01", "02", "03"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "leading-zero values must classify as numeric (no fapd-E05): {diags:?}",
        );
    }

    #[test]
    fn e05_walker_skips_non_setdefinition_entries() {
        // A Rule entry (no SetDefinition involved) must never fire fapd-E05.
        // Kills a mutation that fires fapd-E05 on every Entry regardless of variant.
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
            "Rule entries are not fapd-E05's concern: {diags:?}",
        );
    }

    #[test]
    fn e05_walker_emits_one_per_mixed_setdefinition() {
        // Two mixed sets in the same file -> 2 fapd-E05 diagnostics, one per
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
            "expected one fapd-E05 per mixed SetDefinition: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E05"));
        assert!(diags.iter().any(|d| d.message.contains("first")));
        assert!(diags.iter().any(|d| d.message.contains("second")));
    }
}
