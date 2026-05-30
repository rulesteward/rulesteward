//! Macro-related lint passes. Currently fapd-E03 (undefined macro
//! reference), fapd-E04 (macro reference in `trust=`/`pattern=`), fapd-E05
//! (integer-typed set with an overflowing value), fapd-S02 (macro definition
//! not at file top). Future macro-system checks land here.

use std::collections::HashSet;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};

/// Run every macro-related lint pass over `entries` and return the
/// merged diagnostics. `earlier` is the set of macro names defined in
/// earlier-loading files (cross-file scope for fapd-E03; `None` = per-file
/// resolution); `single_file` selects fapd-W09 over fapd-E03 for an unresolved
/// reference in single-file `--file` mode. Only fapd-E03 consults these;
/// fapd-E04/E05/S02 are independent of macro definedness and ignore them.
pub(crate) fn walk(
    entries: &[Entry],
    file: &Path,
    earlier: Option<&HashSet<String>>,
    single_file: bool,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    out.extend(e03(entries, file, earlier, single_file));
    out.extend(e04(entries, file));
    out.extend(e05(entries, file));
    out.extend(s02(entries, file));
    out
}

/// fapd-E03 / fapd-W09 - macro reference to an undefined `%setname`.
///
/// Implements cross-file define-before-use + single-file W09 downgrade:
///
/// - `earlier`: macro names defined in strictly-earlier-loading `rules.d/`
///   files. Seeded into `defined` before the walk so that a reference to a
///   macro defined in an earlier file is silent (the concatenated load-order
///   stream already saw the definition). `None` = per-file resolution only.
///
/// - `single_file`: when `true` (CLI `--file` mode), a reference to a macro
///   that is NOT defined anywhere in this file becomes fapd-W09 (Warning)
///   instead of fapd-E03, because an unseen sibling file might define it.
///   A within-file FORWARD reference stays fapd-E03: the definition IS present
///   in the file (just below the use), so the violation is certain.
///
/// Single-pass walk: `defined` starts as a clone of `earlier` (empty when
/// `None`) and grows as `SetDefinitions` are encountered. At each `SetRef`:
///   1. `defined.contains(name)` -> in scope (earlier file or earlier line) -> silent.
///   2. `all_local.contains(name)` -> within-file forward ref -> fapd-E03 always.
///   3. `single_file` and name not in `all_local` -> fapd-W09.
///   4. otherwise -> fapd-E03.
///
/// `AttrValue::Int(_)` and `AttrValue::Str(_)` are skipped (the `let-else`
/// filters them out); only `AttrValue::SetRef(_)` participates.
///
/// Span is the enclosing rule's span (per-attribute spans deferred per spec §3f).
fn e03(
    entries: &[Entry],
    file: &Path,
    earlier: Option<&HashSet<String>>,
    single_file: bool,
) -> Vec<Diagnostic> {
    // Seed the running set from `earlier` (macros defined in earlier-loading files).
    let mut defined: HashSet<String> = earlier.cloned().unwrap_or_default();
    // Precompute ALL macro names defined anywhere in THIS file (for the W09-vs-E03 split).
    // A within-file forward reference has `all_local.contains(name)` == true even when
    // the single-pass walk hasn't reached the SetDefinition yet.
    let all_local: HashSet<&str> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::SetDefinition { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let mut diags = Vec::new();
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
                    if defined.contains(name) {
                        // Defined in an earlier file (via seed) or earlier line -> silent.
                        continue;
                    }
                    // Unresolved at this point in the single-pass walk.
                    if single_file && !all_local.contains(name.as_str()) {
                        // Single-file mode and macro is absent from the whole file:
                        // it may be defined in an unseen sibling -> W09 (Warning).
                        diags.push(
                            Diagnostic::new(
                                Severity::Warning,
                                "fapd-W09",
                                r.span.clone(),
                                format!(
                                    "macro reference `%{name}` not defined in this file \
                                     (may be defined in a sibling rules.d/ file; \
                                     lint the directory to resolve)"
                                ),
                                file,
                                r.line,
                                1,
                            )
                            .with_source_id(file.display().to_string()),
                        );
                    } else {
                        // Either directory mode, or a within-file forward reference
                        // (defined below in this file) in single-file mode: E03.
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

/// A fapolicyd integer literal: plain ASCII digits (no sign) that fit in `i64`.
/// fapolicyd types a set by its first value and stores INT sets as `i64`; a value
/// with a leading sign is a STRING, and an all-digit value exceeding `i64::MAX`
/// fails fapolicyd's conversion ("Error converting val").
fn is_fap_int(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<i64>().is_ok()
}

/// A value that fapolicyd's type-inference reads as "looks like an integer"
/// (all ASCII digits). Used to decide the SET's type from its first value;
/// an all-digit-but-overflowing first value still types the set INT (and then
/// fails conversion, which `is_fap_int` catches per-value).
fn looks_int(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

/// fapd-E05 - integer-typed set containing an all-digit value that overflows
/// `i64`. fapolicyd set-type validity is version-divergent: 1.3.2 rejects
/// overflow values in INT-typed sets; 1.4.3 accepts everything; 1.4.5 types a
/// set INT only if ALL values are valid i64. Because the linter cannot know the
/// target version, fapd-E05 fires ONLY on the one genuinely non-portable case:
/// a set whose first value is all-ASCII-digits (INT-typed) and that contains an
/// all-digit value exceeding `i64::MAX` (rejected by 1.3.2 and 1.4.5; only
/// 1.4.3 is lenient).
///
/// Type-mix (a non-digit member in an INT-typed set) is intentionally NOT
/// flagged here because its validity depends on the attribute and target version
/// - it is tracked as a future usage/version-aware check.
///
/// STRING-typed sets (first value is not all-ASCII-digits) are always silent.
/// Independent of fapd-E03/fapd-E04: operates on `Entry::SetDefinition` only.
/// One diagnostic per offending set, at the first overflowing value found.
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
        // Empty value lists cannot be typed; skip.
        let Some(first) = values.first() else {
            continue;
        };
        // Set type is determined by the first value.
        // If not all-digits, this is a STRING set; nothing to check.
        if !looks_int(first) {
            continue;
        }
        // Overflow-only policy: fire ONLY on an all-digit value that exceeds i64
        // (non-portable: rejected by fapolicyd 1.3.2 and 1.4.5; 1.4.3 is lenient).
        // Type-mix (a non-digit member) is version-divergent and intentionally NOT
        // flagged here - tracked as a future usage/version-aware check.
        for bad in values {
            if looks_int(bad) && !is_fap_int(bad) {
                diags.push(
                    Diagnostic::new(
                        Severity::Error,
                        "fapd-E05",
                        span.clone(),
                        format!("integer-typed set `%{name}` contains value `{bad}` that exceeds the maximum integer (fapolicyd stores set integers as i64)"),
                        file,
                        *line,
                        1,
                    )
                    .with_source_id(file.display().to_string()),
                );
                break; // one diagnostic per set
            }
        }
    }
    diags
}

/// fapd-S02 - macro `%name=` set definition that appears AFTER the first rule
/// in the file. fapolicyd imposes no order constraint between macros and rules
/// (macros pre-expand before rules load), so this is purely a Style/readability
/// concern: definitions read most clearly when they sit at the top of the file,
/// above the rules that may reference them.
///
/// Single-pass walk maintaining `seen_rule`. The "file top" window is closed
/// ONLY by the first `Entry::Rule`. Comments and blank lines do NOT close the
/// window - this matches fapolicyd's own shipped rules.d/ conventions, where a
/// header comment block (and blank separators) commonly precede the macro
/// definitions. Other macro definitions before the first rule are tolerated
/// too. After the first rule is seen, every subsequent `SetDefinition` emits
/// one fapd-S02 at its own span/line.
fn s02(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    // `seen_rule` starts false and is closed exactly once, by the first
    // `Entry::Rule`. Comments and blanks intentionally fall through the
    // `_ => {}` arm so they never close the window.
    let mut seen_rule = false;
    for entry in entries {
        match entry {
            Entry::Rule(_) => seen_rule = true,
            Entry::SetDefinition {
                name, line, span, ..
            } if seen_rule => {
                diags.push(
                    Diagnostic::new(
                        Severity::Style,
                        "fapd-S02",
                        span.clone(),
                        format!("macro `%{name}` defined after the first rule (move to file top)"),
                        file,
                        *line,
                        1,
                    )
                    .with_source_id(file.display().to_string()),
                );
            }
            _ => {}
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
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
        let diags = e03(&entries, &p(), None, false);
        assert_eq!(
            diags.len(),
            1,
            "only the undefined SetRef should fire: {diags:?}"
        );
        assert!(diags[0].message.contains("bad_macro"));
    }

    // -----------------------------------------------------------------
    // B.1 - Cross-file and single-file mode barrier tests for fapd-E03/fapd-W09.
    //
    // These tests call `e03` with the 4-arg signature introduced in the frozen
    // foundation. They will be RED against the current frozen foundation because
    // `e03` ignores `_earlier` and `_single_file`. After the implement phase lands
    // the real logic, they must turn GREEN.
    //
    // Test plan:
    //   B.1.1 - earlier-file def suppresses E03
    //   B.1.2 - within-file forward ref still E03 with empty earlier set
    //   B.1.3 - single-file undefined-anywhere -> W09
    //   B.1.4 - single-file within-file forward ref stays E03
    // -----------------------------------------------------------------

    #[test]
    fn e03_earlier_file_def_suppresses_error() {
        // A rule referencing `%langs` with NO local definition, but `earlier`
        // contains "langs" (from an earlier-loading file). In directory mode
        // (`single_file=false`) this MUST produce ZERO diagnostics: the macro is
        // in scope via the earlier-file context.
        //
        // RED against the frozen foundation: `e03` ignores `_earlier`, so it fires
        // fapd-E03 unconditionally for any undefined local reference.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::SetRef("langs".into()),
            }],
        )];
        let mut earlier_set = std::collections::HashSet::new();
        earlier_set.insert("langs".to_string());
        let diags = e03(&entries, &p(), Some(&earlier_set), false);
        assert!(
            diags.is_empty(),
            "a macro defined in an earlier-loading file (in `earlier`) must \
             suppress fapd-E03 in directory mode: {diags:?}",
        );
    }

    #[test]
    fn e03_within_file_forward_ref_still_errors_with_empty_earlier() {
        // Rule references `%local` (line 1), then a SetDefinition of `local`
        // appears below it (line 2). `earlier` is an EMPTY set (not None).
        // In directory mode (`single_file=false`) this MUST fire exactly 1 fapd-E03:
        // the macro IS in this file, but below the reference (forward ref).
        //
        // RED against the frozen foundation: `e03` ignores `_earlier` and treats
        // this the same as the pre-existing forward-reference case (already
        // covered by `e03_fires_on_forward_reference`), so this is actually GREEN
        // in the existing code. However, the test pins that passing an empty-set
        // `earlier` does not accidentally suppress the error (a mutation of `None`
        // vs `Some(&empty)` must not change behavior for forward refs).
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "uid".into(),
                    value: AttrValue::Int(0),
                }],
                vec![Attr::Kv {
                    key: "exe".into(),
                    value: AttrValue::SetRef("local".into()),
                }],
            ),
            setdef(2, "local"),
        ];
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let diags = e03(&entries, &p(), Some(&empty), false);
        assert_eq!(
            diags.len(),
            1,
            "within-file forward reference with an empty `earlier` set \
             must still fire fapd-E03: {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-E03");
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn e03_single_file_undefined_anywhere_emits_w09_not_e03() {
        // Single-file mode (`single_file=true`, `earlier=None`): a reference to
        // `%nope` with no local definition anywhere in the file. Because we cannot
        // tell whether the macro is defined in a sibling file we have not seen, the
        // correct code is fapd-W09 (Warning), NOT fapd-E03.
        //
        // RED against the frozen foundation: `e03` ignores `_single_file` and emits
        // fapd-E03 (Error) for any undefined reference, whether single-file or not.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::SetRef("nope".into()),
            }],
        )];
        let diags = e03(&entries, &p(), None, true);
        assert_eq!(
            diags.len(),
            1,
            "single-file mode with undefined macro must produce exactly 1 diagnostic: {diags:?}",
        );
        assert_eq!(
            diags[0].code.as_ref(),
            "fapd-W09",
            "single-file undefined-anywhere must emit fapd-W09 (not fapd-E03): {diags:?}",
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W09 must have Warning severity: {diags:?}",
        );
    }

    #[test]
    fn e03_single_file_within_file_forward_ref_stays_e03() {
        // Single-file mode (`single_file=true`, `earlier=None`): a reference to
        // `%fwd` on line 1, then a SetDefinition of `fwd` on line 2. The macro IS
        // defined in this file, just below the reference. This is a within-file
        // forward reference, which remains fapd-E03 even in single-file mode (we
        // CAN see the definition; the violation is certain).
        //
        // RED against the frozen foundation: `e03` ignores `_single_file`, so it
        // already emits fapd-E03 here (same as directory mode). But the test is
        // still valuable as a mutation-killing pin: an implementation that upgrades
        // ALL single-file undefined refs to W09 (including forward refs) would fail
        // here.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "uid".into(),
                    value: AttrValue::Int(0),
                }],
                vec![Attr::Kv {
                    key: "exe".into(),
                    value: AttrValue::SetRef("fwd".into()),
                }],
            ),
            setdef(2, "fwd"),
        ];
        let diags = e03(&entries, &p(), None, true);
        assert_eq!(
            diags.len(),
            1,
            "single-file within-file forward reference must still fire fapd-E03: {diags:?}",
        );
        assert_eq!(
            diags[0].code.as_ref(),
            "fapd-E03",
            "within-file forward ref stays fapd-E03 even in single-file mode: {diags:?}",
        );
        assert_eq!(diags[0].severity, Severity::Error);
    }

    // -----------------------------------------------------------------
    // B.2 - GAP 1 (adversarial-reviewer finding): non-empty `earlier` that
    // does NOT contain the referenced name must still fire fapd-E03.
    //
    // Kills a wrong impl that suppresses E03 whenever `earlier` is non-empty
    // regardless of whether the specific name is present.
    //
    // This test is GREEN against the frozen foundation (which ignores `earlier`
    // entirely, so E03 always fires for any undefined reference). It is a
    // regression pin: the implement phase must keep it green, because a
    // correct impl must check name membership, not just presence of a
    // non-empty set.
    // -----------------------------------------------------------------

    #[test]
    fn e03_directory_mode_nonmatching_earlier_still_errors() {
        // earlier={langs} but the rule references %other (NOT in the set) ->
        // directory mode must still fire exactly one fapd-E03. A wrong impl that
        // suppresses E03 whenever `earlier` is non-empty (ignoring the name) fails here.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::SetRef("other".into()),
            }],
        )];
        let mut earlier = std::collections::HashSet::new();
        earlier.insert("langs".to_string());
        let diags = e03(&entries, &p(), Some(&earlier), false);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "fapd-E03");
        assert_eq!(diags[0].severity, Severity::Error);
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
    // under the OVERFLOW-ONLY policy:
    //
    // - INT-typed set (first value all-ASCII-digits) fires ONLY if an
    //   all-digit member exceeds i64::MAX. Non-digit members (type-mix)
    //   are intentionally NOT flagged (version-divergent; future work).
    // - STRING-typed set (first value not all-ASCII-digits) is always
    //   silent regardless of later values.
    //
    // Mutations killed by this suite:
    // - swapping the `looks_int(first)` gate (fires on string-first sets)
    // - dropping the `looks_int(bad)` guard (fires on type-mix members)
    // - dropping the `is_fap_int` per-value check (misses overflow)
    // - using `parse::<i64>()` to determine set type (treats "-5" as INT)
    // - firing on Rule entries instead of only SetDefinition
    // - emitting more than one diagnostic per set
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
    fn e05_string_first_set_does_not_fire() {
        // `%s=abc,1` -> STRING-typed (first value "abc" is not all-digits);
        // fapolicyd accepts this with "Loaded 2 rules". E05 must NOT fire.
        // This was the false positive in the old symmetric-mix check.
        let entries = vec![setdef_with_values(1, "s", &["abc", "1"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "string-first set must not fire fapd-E05: {diags:?}",
        );
    }

    #[test]
    fn e05_int_set_with_string_member_does_not_fire() {
        // `%s=1,abc` -> INT-typed (first value "1" is all-digits), but "abc"
        // is a non-digit (type-mix) member. Under the overflow-only policy,
        // type-mix is intentionally NOT flagged (version-divergent; future
        // work). fapd-E05 must NOT fire here.
        let entries = vec![setdef_with_values(1, "s", &["1", "abc"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "type-mix (non-digit member in INT set) must not fire fapd-E05: {diags:?}",
        );
    }

    #[test]
    fn e05_int_set_with_overflow_member_fires() {
        // `%s=123,99999999999999999999` -> INT-typed; the 20-digit value
        // overflows i64::MAX. fapolicyd: "Error converting val".
        // fapd-E05 must fire with an "exceeds the maximum integer" message.
        let entries = vec![setdef_with_values(1, "s", &["123", "99999999999999999999"])];
        let diags = e05(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "INT-set with overflow member must fire fapd-E05: {diags:?}"
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-E05");
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(
            diags[0].message.contains("exceeds the maximum integer"),
            "overflow message must say 'exceeds the maximum integer': {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("99999999999999999999"),
            "message must name the offending value: {}",
            diags[0].message,
        );
    }

    #[test]
    fn e05_string_first_with_overflow_does_not_fire() {
        // `%s=abc,99999999999999999999` -> STRING-typed (first value "abc" is
        // not all-digits); fapd-E05 must NOT fire even though a later member
        // looks like an overflowing integer. The big-digit value is simply a
        // string member in a STRING-typed set.
        let entries = vec![setdef_with_values(1, "s", &["abc", "99999999999999999999"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "string-first set must not fire fapd-E05 even with a large-digit member: {diags:?}",
        );
    }

    #[test]
    fn e05_homogeneous_int_does_not_fire() {
        // `%s=1,2,3` -> INT-typed, all values valid; no fapd-E05.
        let entries = vec![setdef_with_values(1, "s", &["1", "2", "3"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "homogeneous INT set must not fire fapd-E05: {diags:?}",
        );
    }

    #[test]
    fn e05_homogeneous_string_does_not_fire() {
        // `%s=text/plain,text/x-c` -> STRING-typed; no fapd-E05.
        let entries = vec![setdef_with_values(1, "s", &["text/plain", "text/x-c"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "homogeneous STRING set must not fire fapd-E05: {diags:?}",
        );
    }

    #[test]
    fn e05_single_overflow_value_fires() {
        // `%s=99999999999999999999` -> INT-typed (all digits, single value),
        // but the sole value overflows i64::MAX. fapd-E05 fires.
        let entries = vec![setdef_with_values(1, "s", &["99999999999999999999"])];
        let diags = e05(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "single overflow value must fire fapd-E05: {diags:?}"
        );
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(diags[0].message.contains("exceeds the maximum integer"));
    }

    #[test]
    fn e05_negative_first_is_string_set() {
        // `%s=-5,abc` -> STRING-typed (leading sign; "-5" is not all-ASCII-
        // digits); fapolicyd treats it as a string. No fapd-E05 regardless
        // of later values.
        let entries = vec![setdef_with_values(1, "s", &["-5", "abc"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "negative-first value is STRING-typed; fapd-E05 must not fire: {diags:?}",
        );
    }

    #[test]
    fn e05_i64_max_ok() {
        // `%s=9223372036854775807,1` -> i64::MAX is valid; no fapd-E05.
        let entries = vec![setdef_with_values(1, "s", &["9223372036854775807", "1"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "i64::MAX is a valid integer; fapd-E05 must not fire: {diags:?}",
        );
    }

    #[test]
    fn e05_i64_max_plus_one_fires() {
        // `%s=9223372036854775808` -> i64::MAX+1, overflows; fapd-E05.
        let entries = vec![setdef_with_values(1, "s", &["9223372036854775808"])];
        let diags = e05(&entries, &p());
        assert_eq!(diags.len(), 1, "i64::MAX+1 must fire fapd-E05: {diags:?}");
        assert!(diags[0].message.contains("exceeds the maximum integer"));
    }

    // --- retained tests updated for new semantics ---

    #[test]
    fn e05_int_set_with_multi_string_members_does_not_fire() {
        // `%mymacro=1,2,foo,3` -> INT-typed, "foo" is a non-digit (type-mix)
        // member. Under the overflow-only policy, type-mix is intentionally NOT
        // flagged (version-divergent; future work). fapd-E05 must NOT fire.
        let entries = vec![setdef_with_values(1, "mymacro", &["1", "2", "foo", "3"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "type-mix (non-digit members in INT set) must not fire fapd-E05: {diags:?}",
        );
    }

    #[test]
    fn e05_silent_on_single_int_value() {
        // `%mymacro=42` -> INT-typed single value; valid; no fapd-E05.
        let entries = vec![setdef_with_values(1, "mymacro", &["42"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "single valid integer value must produce no fapd-E05: {diags:?}"
        );
    }

    #[test]
    fn e05_leading_zero_is_int_typed() {
        // `%mymacro=01,02,03` -> INT-typed (all digits), all values parse as
        // i64; no fapd-E05. Leading zeros fit in i64 via normal decimal parse.
        let entries = vec![setdef_with_values(1, "mymacro", &["01", "02", "03"])];
        let diags = e05(&entries, &p());
        assert!(
            diags.is_empty(),
            "leading-zero values are INT-typed and valid (no fapd-E05): {diags:?}",
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
    fn e05_walker_emits_one_per_int_typed_overflow_setdefinition() {
        // Two INT-typed sets each with an overflow member -> 2 fapd-E05.
        // Kills a mutation that deduplicates by name or short-circuits.
        // Both sets start with an integer (all-digits) so both are INT-typed.
        let entries = vec![
            setdef_with_values(1, "first", &["1", "99999999999999999999"]),
            setdef_with_values(2, "second", &["2", "99999999999999999998"]),
        ];
        let diags = e05(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one fapd-E05 per overflow INT SetDefinition: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-E05"));
        assert!(diags.iter().any(|d| d.message.contains("first")));
        assert!(diags.iter().any(|d| d.message.contains("second")));
    }

    #[test]
    fn e05_only_one_diag_per_set_stops_at_first_overflow() {
        // INT-typed set with TWO overflow values -> still only 1 fapd-E05 (first).
        let entries = vec![setdef_with_values(
            1,
            "multi",
            &["1", "99999999999999999999", "99999999999999999998"],
        )];
        let diags = e05(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "only one fapd-E05 per set even with multiple overflow values: {diags:?}",
        );
        assert!(
            diags[0].message.contains("99999999999999999999"),
            "stops at first overflow value: {}",
            diags[0].message,
        );
    }

    // -----------------------------------------------------------------
    // fapd-S02 helper-level unit tests. Pin the single-pass `seen_rule`
    // walker so every branch (macro-before-rule -> silent, macro-after-rule
    // -> fire, comment does not close the window, blank does not close the
    // window, partial - only post-rule macros fire, one diag per offending
    // macro) is exercised independently of the snapshot + proptest suites.
    // A mutant that flips the `seen_rule` check, forgets to set `seen_rule`
    // on Rule, or flips it on Comment/Blank dies here.
    // -----------------------------------------------------------------

    fn comment(line: usize) -> Entry {
        Entry::Comment {
            text: " header".to_string(),
            line,
        }
    }

    fn blank(line: usize) -> Entry {
        Entry::Blank { line }
    }

    fn allow_all_rule(line: usize) -> Entry {
        modern_rule(
            line,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![Attr::All],
        )
    }

    #[test]
    fn s02_emits_when_macro_after_rule() {
        // Rule on line 1, macro definition on line 2 -> 1 fapd-S02 at line 2.
        let entries = vec![allow_all_rule(1), setdef(2, "trusted")];
        let diags = s02(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "macro after a rule must fire fapd-S02: {diags:?}"
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-S02");
        assert_eq!(diags[0].severity, Severity::Style);
        assert_eq!(diags[0].line, 2);
        assert!(
            diags[0].message.contains("trusted"),
            "message must name the macro: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn s02_silent_when_macro_before_rule() {
        // Macro definition on line 1, rule on line 2 -> no fapd-S02.
        let entries = vec![setdef(1, "trusted"), allow_all_rule(2)];
        let diags = s02(&entries, &p());
        assert!(
            diags.is_empty(),
            "a macro defined before the first rule must not fire fapd-S02: {diags:?}",
        );
    }

    #[test]
    fn s02_comment_does_not_close_the_window() {
        // A leading comment must NOT close the file-top window. The macro is
        // still before the first rule, so no fapd-S02.
        let entries = vec![comment(1), setdef(2, "trusted"), allow_all_rule(3)];
        let diags = s02(&entries, &p());
        assert!(
            diags.is_empty(),
            "a comment before the first rule must not close the window: {diags:?}",
        );
    }

    #[test]
    fn s02_blank_does_not_close_the_window() {
        // Blank lines must NOT close the file-top window either.
        let entries = vec![blank(1), setdef(2, "trusted"), blank(3), allow_all_rule(4)];
        let diags = s02(&entries, &p());
        assert!(
            diags.is_empty(),
            "blank lines before the first rule must not close the window: {diags:?}",
        );
    }

    #[test]
    fn s02_fires_only_on_post_rule_macros() {
        // Macro on line 1 (before rule = OK), rule on line 2, macro on line 3
        // (after rule = fapd-S02). Exactly one fapd-S02, at line 3.
        let entries = vec![setdef(1, "first"), allow_all_rule(2), setdef(3, "second")];
        let diags = s02(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "only the post-rule macro must fire fapd-S02: {diags:?}",
        );
        assert_eq!(diags[0].line, 3);
        // The diagnostic names the offending (post-rule) macro `%second`, not
        // the OK (pre-rule) macro `%first`. The message phrase "the first
        // rule" contains the substring "first", so we match on the macro
        // sigil form `%first` / `%second` to disambiguate.
        assert!(diags[0].message.contains("%second"));
        assert!(!diags[0].message.contains("%first"));
    }

    #[test]
    fn s02_emits_one_diag_per_post_rule_macro() {
        // One rule followed by THREE macro definitions -> 3 fapd-S02
        // diagnostics, one per definition. Kills a mutant that emits only
        // the first (e.g. a `break`/`return` after the first hit).
        let entries = vec![
            allow_all_rule(1),
            setdef(2, "a"),
            setdef(3, "b"),
            setdef(4, "c"),
        ];
        let diags = s02(&entries, &p());
        assert_eq!(
            diags.len(),
            3,
            "expected one fapd-S02 per post-rule macro: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-S02"));
        assert!(diags.iter().all(|d| d.severity == Severity::Style));
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![2, 3, 4]);
    }

    #[test]
    fn s02_silent_with_no_rules() {
        // A file of only macro definitions (no rule) never fires fapd-S02:
        // the window is never closed. Kills a mutant that flips the initial
        // `seen_rule` to `true`.
        let entries = vec![setdef(1, "a"), setdef(2, "b")];
        let diags = s02(&entries, &p());
        assert!(
            diags.is_empty(),
            "no rule means the window never closes; no fapd-S02: {diags:?}",
        );
    }

    // -----------------------------------------------------------------
    // Layer-2 property tests for `looks_int` and `is_fap_int`.
    //
    // Properties:
    // 1. All-digit strings always satisfy `looks_int`.
    // 2. Any string with a non-digit prefix does NOT satisfy `looks_int`.
    // 3. `is_fap_int(v)` implies `looks_int(v)` (is_fap_int is strictly
    //    narrower - no is_fap_int-true value can fail looks_int).
    // 4. For all-digit strings, `is_fap_int(v) == v.parse::<i64>().is_ok()`
    //    (is_fap_int is exactly "all-digit AND fits i64").
    //
    // These properties kill mutants on the predicate bodies that unit tests
    // hit only at specific boundary values.
    // -----------------------------------------------------------------

    mod proptest_classifiers {
        use super::super::{is_fap_int, looks_int};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            // Property 1: all-digit strings of 1..40 digits always satisfy
            // `looks_int`. A mutant that inverts the `all(|b| b.is_ascii_digit())`
            // predicate will fail here for any generated digit string.
            #[test]
            fn looks_int_true_for_all_digit_strings(s in "[0-9]{1,40}") {
                prop_assert!(
                    looks_int(&s),
                    "all-digit string `{s}` must satisfy looks_int"
                );
            }

            // Property 2: prepending a non-digit ASCII letter makes looks_int
            // return false. Tests the "any non-digit -> false" path for every
            // generated digit suffix and every ASCII letter prefix.
            #[test]
            fn looks_int_false_when_leading_non_digit(
                prefix in "[a-zA-Z_\\-]",
                suffix in "[0-9]{0,20}"
            ) {
                let s = format!("{prefix}{suffix}");
                prop_assert!(
                    !looks_int(&s),
                    "string `{s}` with non-digit prefix must fail looks_int"
                );
            }

            // Property 3: is_fap_int implies looks_int. For any string, if
            // is_fap_int returns true then looks_int must also return true.
            // Tests the subset relationship between the two predicates.
            #[test]
            fn is_fap_int_implies_looks_int(s in "[0-9]{1,42}") {
                if is_fap_int(&s) {
                    prop_assert!(
                        looks_int(&s),
                        "is_fap_int({s}) returned true but looks_int returned false"
                    );
                }
            }

            // Property 4: for all-digit strings, is_fap_int agrees exactly with
            // parse::<i64>().is_ok(). This pins the i64-boundary semantics: a
            // value with one digit more than i64::MAX (19 digits > 9223372036854775807)
            // should return false; a valid i64 value should return true. Mutants
            // that drop the `parse::<i64>().is_ok()` clause or change the parse type
            // (e.g. u64) fail here.
            #[test]
            fn is_fap_int_matches_i64_parse_for_digit_strings(s in "[0-9]{1,25}") {
                let expected = s.parse::<i64>().is_ok();
                let got = is_fap_int(&s);
                prop_assert_eq!(got, expected,
                    "is_fap_int result mismatch for s={}; expected {} from i64 parse",
                    s, expected);
            }
        }
    }
}
