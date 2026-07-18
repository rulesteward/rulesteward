//! RED barrier tests for the legacy-grammar `exe_dir=`/`exe_type=` false-
//! Fatal (issue #546, ATL round 2 MISS 2, impl-AWARE adversarial review
//! 2026-07-18).
//!
//! Ground truth: upstream fapolicyd's `subject-attr.c` table1 (the LEGACY/
//! ORIG-format subject attribute table, distinct from the MODERN table2)
//! DOES list `EXE_DIR`/`EXE_TYPE`. Live-verified 2026-07-18 on BOTH
//! fapolicyd 1.3.2 and 1.4.5:
//! (1) LEGACY `allow exe_dir=/usr/bin/ trust=1` -> "Loaded 1 rules" (clean)
//! on both versions. (2) LEGACY `allow exe_type=application/x-executable
//! trust=1` -> "Loaded 1 rules" (clean) on both versions. (3) MODERN
//! `allow exe_dir=/usr/bin/ : all` -> "Field type (`exe_dir`) is unknown in
//! line 2" on both versions (unaffected - see the existing
//! `tests/corpus/traps/fapd-E01/exe-dir-unknown.rules` /
//! `exe-type-unknown.rules` modern-format controls, deliberately not
//! touched by this change).
//!
//! Today: `parser::grammar::legacy_classify("exe_dir"/"exe_type")` returns
//! `None` (the OLD, modern-only grounding this round re-corrects - see
//! `legacy_classify_exe_dir_and_exe_type_are_subject_anchors` in
//! `grammar.rs`), so the landed per-token `positional_split` (#546) rejects
//! the whole rule with "legacy rule references unknown or legacy-illegal
//! attribute" - surfacing as fapd-F01 Fatal (a NEW false-positive
//! introduced by the #546 fix; pre-#546 this merely mis-warned via a
//! different code path). Even once the parser is fixed, `lints::walker::e01`
//! ALSO needs to become flavor-aware: it currently gates on
//! `attrs::is_known(key)` unconditionally (ignoring `Rule.syntax`), and
//! `attrs::is_known("exe_dir")` is (correctly, for the MODERN table)
//! `false`, so a parser-only fix would still leave a spurious fapd-E01
//! "unknown attribute" on these legacy rules. The full-lint tests below
//! are RED for both reasons today and will only go green once both
//! `legacy_classify` and `e01` are fixed.

use std::path::Path;

use rulesteward_fapolicyd::{Attr, Entry, SyntaxFlavor, lint, parse_rules_file};

/// (a)/(c): a legacy `exe_dir=`/`exe_type=` rule must parse successfully,
/// with the attribute correctly classified subject-side and the rule
/// tagged `SyntaxFlavor::Legacy`.
#[test]
fn legacy_exe_dir_parses_with_exe_dir_on_subject_side() {
    let file = Path::new("legacy-exe-dir.rules");
    let src = "allow exe_dir=/usr/bin/ trust=1\n";
    let entries = parse_rules_file(src, file).unwrap_or_else(|d| {
        panic!(
            "daemon-valid legacy rule `{src}` must parse (live-verified: \
             loads clean on fapolicyd 1.3.2 and 1.4.5); got diagnostics: {d:?}"
        )
    });
    assert_eq!(entries.len(), 1, "expected exactly one entry");
    let Entry::Rule(r) = &entries[0] else {
        panic!("expected an Entry::Rule, got {:?}", entries[0]);
    };
    assert_eq!(r.syntax, SyntaxFlavor::Legacy);
    assert_eq!(
        r.subject.len(),
        1,
        "exe_dir must land in the subject list; got {:?}",
        r.subject
    );
    assert!(
        matches!(&r.subject[0], Attr::Kv { key, .. } if key == "exe_dir"),
        "subject[0] must be exe_dir; got {:?}",
        r.subject[0]
    );
    assert_eq!(
        r.object.len(),
        1,
        "trust must land in the object list; got {:?}",
        r.object
    );
    assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "trust"));
}

#[test]
fn legacy_exe_type_parses_with_exe_type_on_subject_side() {
    let file = Path::new("legacy-exe-type.rules");
    let src = "allow exe_type=application/x-executable trust=1\n";
    let entries = parse_rules_file(src, file).unwrap_or_else(|d| {
        panic!(
            "daemon-valid legacy rule `{src}` must parse (live-verified: \
             loads clean on fapolicyd 1.3.2 and 1.4.5); got diagnostics: {d:?}"
        )
    });
    assert_eq!(entries.len(), 1, "expected exactly one entry");
    let Entry::Rule(r) = &entries[0] else {
        panic!("expected an Entry::Rule, got {:?}", entries[0]);
    };
    assert_eq!(r.syntax, SyntaxFlavor::Legacy);
    assert_eq!(
        r.subject.len(),
        1,
        "exe_type must land in the subject list; got {:?}",
        r.subject
    );
    assert!(
        matches!(&r.subject[0], Attr::Kv { key, .. } if key == "exe_type"),
        "subject[0] must be exe_type; got {:?}",
        r.subject[0]
    );
    assert_eq!(r.object.len(), 1);
    assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "trust"));
}

/// (b): the FULL lint pipeline (parse + walk) must emit neither fapd-F01
/// (the parse-level false-Fatal) nor fapd-E01 (the walker-level false
/// "unknown attribute", since `attrs::is_known` doesn't know about
/// `Rule.syntax`) for the daemon-valid legacy `exe_dir` rule.
#[test]
fn legacy_exe_dir_full_lint_emits_no_f01_no_e01() {
    let file = Path::new("legacy-exe-dir.rules");
    let src = "allow exe_dir=/usr/bin/ trust=1\n";
    let entries = parse_rules_file(src, file)
        .unwrap_or_else(|d| panic!("must parse cleanly (see the parse-level test above): {d:?}"));
    let diags = lint(&entries, src, file);
    assert!(
        !diags.iter().any(|d| d.code.as_ref() == "fapd-F01"),
        "a daemon-valid legacy rule must not be Fatal-rejected; got {diags:?}"
    );
    assert!(
        !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
        "exe_dir is a legal LEGACY subject attr and must not be flagged \
         unknown by fapd-E01 (attrs::is_known models the MODERN table \
         only - e01 must consult Rule.syntax for exe_dir/exe_type); \
         got {diags:?}"
    );
}

#[test]
fn legacy_exe_type_full_lint_emits_no_f01_no_e01() {
    let file = Path::new("legacy-exe-type.rules");
    let src = "allow exe_type=application/x-executable trust=1\n";
    let entries = parse_rules_file(src, file)
        .unwrap_or_else(|d| panic!("must parse cleanly (see the parse-level test above): {d:?}"));
    let diags = lint(&entries, src, file);
    assert!(
        !diags.iter().any(|d| d.code.as_ref() == "fapd-F01"),
        "a daemon-valid legacy rule must not be Fatal-rejected; got {diags:?}"
    );
    assert!(
        !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
        "exe_type is a legal LEGACY subject attr and must not be flagged \
         unknown by fapd-E01; got {diags:?}"
    );
}

/// (e) Negative control: the legacy leniency for `exe_dir`/`exe_type`
/// extends ONLY to those two names - a genuinely unknown attribute (not in
/// EITHER the modern or the legacy table) must still be rejected as a
/// legacy-illegal token, exactly as today. Must PASS both before and after
/// the implementer's fix (pins that the fix doesn't become a blanket
/// "anything goes" fallback for the legacy dialect).
#[test]
fn legacy_rule_with_genuinely_unknown_attr_still_errors() {
    let file = Path::new("legacy-bogus.rules");
    let src = "allow bogus=1 trust=1\n";
    let result = parse_rules_file(src, file);
    assert!(
        result.is_err(),
        "`bogus` is unknown to both the modern and legacy attribute tables \
         and must still be rejected; got {result:?}"
    );
}
