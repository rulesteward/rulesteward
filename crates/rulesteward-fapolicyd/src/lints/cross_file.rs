//! Cross-`rules.d/` lints: fapd-W04 (ordering), fapd-C01 (filename convention),
//! fapd-C02 (cross-file duplicate), and fapd-W10 (cross-file allow-then-deny
//! shadow). Run AFTER per-file lints, over all files in fagenrules load order.
use std::path::PathBuf;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use super::subsume::{MacroMap, build_macro_map, shadows};
use crate::ast::{Attr, AttrValue, Decision, Entry, Rule};

fn is_allow(d: Decision) -> bool {
    matches!(
        d,
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog
    )
}
fn is_deny(d: Decision) -> bool {
    matches!(
        d,
        Decision::Deny | Decision::DenyAudit | Decision::DenySyslog | Decision::DenyLog
    )
}

/// Global macro map across all files in load order (last definition wins),
/// modeling the post-`fagenrules` concatenated stream where a `%set` defined in
/// an earlier file is in scope in later files. (Verified against the fagenrules
/// concatenation source: it cats all rules.d files into one compiled.rules with
/// no per-file scope boundary.)
fn build_global_macro_map(files: &[(PathBuf, Vec<Entry>)]) -> MacroMap {
    let mut map = MacroMap::new();
    for (_path, entries) in files {
        map.extend(build_macro_map(entries));
    }
    map
}

/// fapd-W04: an `allow` rule is unreachable because a deny in an EARLIER-LOADING
/// file subsumes it. Same-file pairs are fapd-W01's job and are excluded via the
/// `af < bf` file-index guard. One W04 per dead allow (anchored to the first
/// earlier-file deny that shadows it).
pub(crate) fn w04(files: &[(PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let macro_map = build_global_macro_map(files);
    let mut scoped: Vec<(usize, &PathBuf, &Rule)> = Vec::new();
    for (fi, (path, entries)) in files.iter().enumerate() {
        for e in entries {
            if let Entry::Rule(r) = e {
                scoped.push((fi, path, r));
            }
        }
    }
    let mut diags = Vec::new();
    for j in 0..scoped.len() {
        let (bf, bpath, b) = scoped[j];
        if !is_allow(b.decision) {
            continue;
        }
        for &(af, apath, a) in scoped.iter().take(j) {
            if af < bf && is_deny(a.decision) && shadows(a, b, &macro_map) {
                diags.push(anchored(
                    Severity::Warning,
                    "fapd-W04",
                    b.span.clone(),
                    format!(
                        "allow rule unreachable: shadowed by the broader deny in {} on line {}",
                        apath.display(),
                        a.line,
                    ),
                    bpath.as_path(),
                    b.line,
                ));
                break;
            }
        }
    }
    diags
}

/// Canonical, macro-expanded, order-insensitive form of one attribute value.
/// A `SetRef` is expanded to its sorted member strings; a literal renders to its
/// single string token (`Int(0)` -> `"0"`), so `uid=%admins` (={0}) and `uid=0`
/// produce the SAME canonical form. The result is a SORTED `Vec<String>` so two
/// equal-but-differently-ordered sets compare equal.
fn canonical_value(value: &AttrValue, macro_map: &MacroMap) -> Vec<String> {
    let mut members = match value {
        AttrValue::SetRef(name) => macro_map.get(name).cloned().unwrap_or_default(),
        AttrValue::Str(s) => vec![s.clone()],
        AttrValue::Int(n) => vec![n.to_string()],
    };
    members.sort();
    members
}

/// Canonical, order-insensitive, macro-expanded form of one predicate side
/// (subject or object). `[Attr::All]` is its own distinct sentinel; otherwise a
/// list of `Attr::Kv` becomes a SORTED `Vec<(key, canonical_value)>`. Sorting by
/// the whole `(key, value)` tuple makes the comparison insensitive to the order
/// the attributes appear in the rule (a predicate list is a conjunction, so
/// order is insignificant). Returns `None` for any shape we do not treat as
/// comparable (an empty side, or a list mixing `Attr::All` with `Kv`s), which
/// makes those rules never compare equal under [`predicate_sides_equal`].
fn canonical_side(attrs: &[Attr], macro_map: &MacroMap) -> Option<CanonicalSide> {
    if attrs == [Attr::All] {
        return Some(CanonicalSide::All);
    }
    let mut pairs = Vec::with_capacity(attrs.len());
    for attr in attrs {
        match attr {
            Attr::Kv { key, value, .. } => {
                pairs.push((key.clone(), canonical_value(value, macro_map)));
            }
            // A bare `Attr::All` mixed with other attrs, or any other shape, is
            // not a form we treat as a comparable predicate set.
            Attr::All => return None,
        }
    }
    if pairs.is_empty() {
        return None;
    }
    pairs.sort();
    Some(CanonicalSide::Kvs(pairs))
}

/// Canonical form of one predicate side, used only for equality comparison.
#[derive(PartialEq, Eq)]
enum CanonicalSide {
    /// The `all` keyword on this side (matches everything).
    All,
    /// A sorted list of `(key, sorted-expanded-values)` pairs.
    Kvs(Vec<(String, Vec<String>)>),
}

/// True iff rules `a` and `b` have AST-EQUAL match predicates (perm + subject +
/// object), comparing macro-expanded values order-insensitively. This is strict
/// EQUALITY, not subsumption: `allow all : all` does NOT equal
/// `allow uid=0 : path=/x`. Used by both fapd-C02 (with an added decision-equal
/// check) and fapd-W10 (with an added allow-then-deny decision check).
fn predicate_sides_equal(a: &Rule, b: &Rule, macro_map: &MacroMap) -> bool {
    if a.perm != b.perm {
        return false;
    }
    sides_equal(&a.subject, &b.subject, macro_map) && sides_equal(&a.object, &b.object, macro_map)
}

/// Equality of one predicate side. A side whose canonical form is `None` (an
/// empty or mixed-shape list we do not treat as comparable) is never equal to
/// anything, including another `None`.
fn sides_equal(a: &[Attr], b: &[Attr], macro_map: &MacroMap) -> bool {
    match (canonical_side(a, macro_map), canonical_side(b, macro_map)) {
        (Some(ca), Some(cb)) => ca == cb,
        _ => false,
    }
}

/// fapd-C02 (Convention): a CROSS-FILE DUPLICATE rule. Two rules in DIFFERENT
/// rules.d files are AST-equal (same decision, same perm, same subject attrs,
/// same object attrs, with `SetRef` macros expanded via the global macro map and
/// attribute order treated as insignificant within a side). The later-loading
/// copy is redundant; the diagnostic is anchored at the LATER rule and names the
/// earlier file and line in prose (the zero-core-change pattern fapd-W04 uses).
///
/// Reuses `build_global_macro_map` and `scoped_rules`; the match test is
/// `predicate_sides_equal` (strict AST-equality, NOT `subsume::shadows`
/// subsumption), so it never double-fires with fapd-W04.
pub(crate) fn c02(files: &[(PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let macro_map = build_global_macro_map(files);
    let scoped = scoped_rules(files);
    let mut diags = Vec::new();
    for j in 0..scoped.len() {
        let (bf, bpath, b) = scoped[j];
        for &(af, apath, a) in scoped.iter().take(j) {
            // Cross-file only (same-file dups are fapd-W01), SAME decision, and
            // AST-equal match predicates (NOT subsumption).
            if af < bf && a.decision == b.decision && predicate_sides_equal(a, b, &macro_map) {
                diags.push(anchored(
                    Severity::Convention,
                    "fapd-C02",
                    b.span.clone(),
                    format!(
                        "duplicate rule: identical to the rule in {} on line {}",
                        apath.display(),
                        a.line,
                    ),
                    bpath.as_path(),
                    b.line,
                ));
                break;
            }
        }
    }
    diags
}

/// fapd-W10 (Warning): a CROSS-FILE DECISION-SHADOW. Two rules in different files
/// have AST-equal MATCH predicates (perm + subject + object) but a conflicting
/// outcome where the later is unreachable (first match wins). SCOPED TO
/// allow-then-deny ONLY (earlier file `allow`, later file `deny`); the
/// deny-then-allow direction is fapd-W04, so W10 and W04 never double-fire.
///
/// Reuses `build_global_macro_map`, `scoped_rules`, and `is_allow`/`is_deny`; the
/// match test is `predicate_sides_equal` (strict AST-equality, NOT
/// `subsume::shadows`), gated to earlier-allow then later-deny.
pub(crate) fn w10(files: &[(PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let macro_map = build_global_macro_map(files);
    let scoped = scoped_rules(files);
    let mut diags = Vec::new();
    for j in 0..scoped.len() {
        let (bf, bpath, b) = scoped[j];
        // W10 is scoped to allow-then-deny ONLY: the LATER rule must be a deny.
        if !is_deny(b.decision) {
            continue;
        }
        for &(af, apath, a) in scoped.iter().take(j) {
            // Cross-file only, earlier rule is an allow, AST-equal match
            // predicates (NOT subsumption). deny-then-allow is fapd-W04's job.
            if af < bf && is_allow(a.decision) && predicate_sides_equal(a, b, &macro_map) {
                diags.push(anchored(
                    Severity::Warning,
                    "fapd-W10",
                    b.span.clone(),
                    format!(
                        "deny rule unreachable: the allow with the same match predicates in {} on line {} already matched and terminated evaluation",
                        apath.display(),
                        a.line,
                    ),
                    bpath.as_path(),
                    b.line,
                ));
                break;
            }
        }
    }
    diags
}

/// Flatten all files into `(file_index, path, &Rule)` in load order, skipping
/// non-rule entries. Shared by the cross-file equal-predicate passes (C02, W10).
fn scoped_rules(files: &[(PathBuf, Vec<Entry>)]) -> Vec<(usize, &PathBuf, &Rule)> {
    let mut scoped = Vec::new();
    for (fi, (path, entries)) in files.iter().enumerate() {
        for e in entries {
            if let Entry::Rule(r) = e {
                scoped.push((fi, path, r));
            }
        }
    }
    scoped
}

/// True iff `name` begins with exactly two ASCII digits then a hyphen (the
/// upstream rules.d tier convention: 10-, 20-, 30-, ..., 90-, 95-).
fn has_tier_prefix(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b'-'
}

/// fapd-C01: a rules.d filename does not follow the `NN-` numeric-prefix
/// convention. File-level finding (no source byte range), like fapd-F02.
pub(crate) fn c01(files: &[(PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for (path, _entries) in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !has_tier_prefix(name) {
            diags.push(Diagnostic::new(
                Severity::Convention,
                "fapd-C01",
                0..0,
                "rules.d filename does not follow the NN- numeric-prefix convention (e.g. 10-, 20-, 30-); fagenrules load order may be unexpected",
                path.as_path(),
                0,
                0,
            ));
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, Decision, Perm};
    use crate::lints::testkit::{kv, kv_int, kv_ref, modern_rule, set_def};
    use rulesteward_core::Severity;

    #[test]
    fn deny_all_in_earlier_file_shadows_later_allow() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let d = w04(&files);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code.as_ref(), "fapd-W04");
        assert_eq!(d[0].severity, Severity::Warning);
        assert!(d[0].file.ends_with("50-allow.rules"));
        assert!(d[0].message.contains("10-deny.rules"));
        assert_eq!(d[0].source_id.as_deref(), Some("rules.d/50-allow.rules"));
    }
    #[test]
    fn allow_then_deny_does_not_fire() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/90-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
        ];
        assert!(w04(&files).is_empty());
    }
    #[test]
    fn same_file_pair_is_w01_not_w04() {
        let files = vec![(
            PathBuf::from("rules.d/10-x.rules"),
            vec![
                modern_rule(1, Decision::Deny, None, vec![Attr::All], vec![Attr::All]),
                modern_rule(
                    2,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
            ],
        )];
        assert!(w04(&files).is_empty());
    }
    #[test]
    fn cross_file_dir_prefix_deny_shadows_allow() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![kv("dir", "/usr/")],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![Attr::All],
                    vec![kv("path", "/usr/bin/ls")],
                )],
            ),
        ];
        assert_eq!(w04(&files).len(), 1);
    }
    #[test]
    fn cross_file_macro_defined_earlier_is_in_scope() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![
                    set_def(1, "admins", &["0", "1000"]),
                    modern_rule(
                        2,
                        Decision::Deny,
                        None,
                        vec![kv_ref("uid", "admins")],
                        vec![Attr::All],
                    ),
                ],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![Attr::All],
                )],
            ),
        ];
        assert_eq!(w04(&files).len(), 1);
    }
    #[test]
    fn unrelated_cross_file_rules_do_not_fire() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![kv("path", "/usr/bin/foo")],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![Attr::All],
                    vec![kv("path", "/usr/bin/bar")],
                )],
            ),
        ];
        assert!(w04(&files).is_empty());
    }

    #[test]
    fn missing_prefix_fires_c01() {
        let files = vec![(PathBuf::from("rules.d/myapp.rules"), vec![])];
        let d = c01(&files);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, "fapd-C01");
        assert_eq!(d[0].severity, Severity::Convention);
        assert!(d[0].file.ends_with("myapp.rules"));
        assert!(d[0].source_id.is_none());
    }
    #[test]
    fn one_and_three_digit_prefixes_fire() {
        let files = vec![
            (PathBuf::from("rules.d/5-foo.rules"), vec![]),
            (PathBuf::from("rules.d/100-bar.rules"), vec![]),
        ];
        assert_eq!(c01(&files).len(), 2);
    }
    #[test]
    fn conventional_two_digit_prefix_passes() {
        let files = vec![
            (PathBuf::from("rules.d/10-a.rules"), vec![]),
            (PathBuf::from("rules.d/50-myapp.rules"), vec![]),
            (PathBuf::from("rules.d/95-z.rules"), vec![]),
        ];
        assert!(c01(&files).is_empty());
    }
    #[test]
    fn has_tier_prefix_boundaries() {
        assert!(has_tier_prefix("10-x"));
        assert!(!has_tier_prefix("5-x"));
        assert!(!has_tier_prefix("100-x"));
        assert!(!has_tier_prefix("ab-x"));
        assert!(!has_tier_prefix("10"));
    }

    #[test]
    fn deny_shadowed_by_earlier_deny_does_not_fire_w04() {
        // W04 flags only unreachable ALLOWs. A deny shadowed by an earlier
        // broader deny is NOT a W04 (nothing "allowed" became dead). This pins
        // the `is_allow(b.decision)` guard: with is_allow mutated to always-true,
        // the shadowed deny below would wrongly fire W04.
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/50-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            w04(&files).is_empty(),
            "a deny shadowed by an earlier deny must not fire W04: {:?}",
            w04(&files)
        );
    }

    // -----------------------------------------------------------------------
    // fapd-C02 - cross-file DUPLICATE (same decision + same match predicates).
    // -----------------------------------------------------------------------

    fn codes(diags: &[Diagnostic]) -> std::collections::HashSet<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    #[test]
    fn c02_fires_on_byte_identical_allow_dup() {
        // Two files, byte-identical `allow uid=0 : path=/x`. The later copy is a
        // redundant cross-file duplicate -> exactly one fapd-C02, anchored at the
        // LATER rule and naming the earlier file in prose.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let d = c02(&files);
        assert_eq!(d.len(), 1, "exactly one C02 for the later duplicate: {d:?}");
        assert_eq!(d[0].code.as_ref(), "fapd-C02");
        assert_eq!(d[0].severity, Severity::Convention);
        // Anchored at the LATER file (30-b), naming the EARLIER file (20-a).
        assert!(
            d[0].file.ends_with("30-b.rules"),
            "C02 anchors the later copy: {:?}",
            d[0].file
        );
        assert!(
            d[0].message.contains("20-a.rules"),
            "C02 prose names the earlier file: {}",
            d[0].message
        );
        assert_eq!(d[0].source_id.as_deref(), Some("rules.d/30-b.rules"));
    }

    #[test]
    fn c02_fires_on_byte_identical_deny_dup() {
        // Mirror of the allow case for deny->deny: same-decision dup still fires
        // C02 (the duplicate is redundant regardless of allow vs deny).
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Execute),
                    vec![Attr::All],
                    vec![kv("ftype", "text/x-php")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Execute),
                    vec![Attr::All],
                    vec![kv("ftype", "text/x-php")],
                )],
            ),
        ];
        let d = c02(&files);
        assert_eq!(d.len(), 1, "deny->deny dup fires one C02: {d:?}");
        assert_eq!(d[0].code.as_ref(), "fapd-C02");
        assert!(d[0].file.ends_with("30-b.rules"));
        assert!(d[0].message.contains("20-a.rules"));
    }

    #[test]
    fn c02_fires_when_macro_ref_equals_expansion() {
        // Earlier file: `%admins=0` then `allow uid=%admins : all`.
        // Later file:   `allow uid=0 : all`.
        // With the macro expanded, the predicate sets are EQUAL -> C02. A wrong
        // impl that compares raw AST (SetRef vs Int) without expanding the macro
        // map would MISS this and fail.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![
                    set_def(1, "admins", &["0"]),
                    modern_rule(
                        2,
                        Decision::Allow,
                        None,
                        vec![kv_ref("uid", "admins")],
                        vec![Attr::All],
                    ),
                ],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![Attr::All],
                )],
            ),
        ];
        let d = c02(&files);
        assert_eq!(
            d.len(),
            1,
            "uid=%admins (={{0}}) equals uid=0 after expansion -> C02: {d:?}"
        );
        assert_eq!(d[0].code.as_ref(), "fapd-C02");
        assert!(d[0].file.ends_with("30-b.rules"));
    }

    #[test]
    fn c02_is_order_insensitive_on_attrs() {
        // Same predicate SET, different attribute ORDER across the two files.
        // A rule's predicate list is a conjunction, so order is insignificant;
        // C02 must still fire. A wrong impl using `Vec`-equality (order-sensitive)
        // would MISS this and fail.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0), kv_int("gid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    // gid before uid - reversed order, same set.
                    vec![kv_int("gid", 0), kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let d = c02(&files);
        assert_eq!(
            d.len(),
            1,
            "reordered-but-equal attr sets are a duplicate -> C02: {d:?}"
        );
        assert_eq!(d[0].code.as_ref(), "fapd-C02");
    }

    #[test]
    fn c02_does_not_fire_on_same_file_pair() {
        // Two identical rules in the SAME file are fapd-W01's job (within-file),
        // never C02. A wrong impl missing the cross-file (different-file) guard
        // would wrongly fire here.
        let files = vec![(
            PathBuf::from("rules.d/20-a.rules"),
            vec![
                modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
                modern_rule(
                    2,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
            ],
        )];
        assert!(
            c02(&files).is_empty(),
            "same-file duplicate is W01, not C02: {:?}",
            c02(&files)
        );
    }

    #[test]
    fn c02_does_not_fire_on_distinct_decisions() {
        // allow-then-deny with equal predicates is a SHADOW (W10), not a
        // duplicate. C02 requires the SAME decision; a wrong impl ignoring the
        // decision-equality guard would wrongly emit C02 here.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            c02(&files).is_empty(),
            "different decisions are W10, not a C02 duplicate: {:?}",
            c02(&files)
        );
    }

    #[test]
    fn c02_does_not_fire_on_subsumption_not_equality() {
        // EQUALITY-vs-SUBSUMPTION boundary. Earlier file `allow all : all`
        // STRICTLY SUBSUMES the later `allow uid=0 : path=/x` (same decision),
        // but the two rules are NOT AST-equal. C02 is a DUPLICATE check
        // (AST-equality), not a shadow check (subsumption). It must NOT fire.
        //
        // This is the adversarial pin: a wrong impl defined as
        // `same_decision && shadows(earlier, later)` (subsumption via
        // `subsume::shadows`, which the stub doc steers toward) would WRONGLY
        // emit C02 here, because `shadows(allow_all_all, allow_uid0_pathx)` is
        // true. The correct AST-equality impl passes (no C02). The empty stub
        // also passes, so this test does NOT change RED status.
        //
        // This relationship is a W01/W04-style subsumption, not a duplicate:
        // W04 covers the deny-then-allow direction; an allow-subsumes-later-
        // allow within load order is at most a W01 same-file concern, never a
        // cross-file C02 duplicate. So neither C02 nor W10 nor W04 fires here.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            c02(&files).is_empty(),
            "earlier `allow all : all` strictly SUBSUMES but is not AST-equal to \
             the later `allow uid=0 : path=/x`; C02 is equality not subsumption, \
             so it must NOT fire: {:?}",
            c02(&files)
        );
        // Belt-and-braces: the same subsumption pair must not leak into the
        // other two cross-file codes via the aggregator either.
        let diags = crate::lints::lint_cross_file(&files);
        let c = codes(&diags);
        assert!(
            !c.contains("fapd-C02"),
            "no C02 on allow-subsumes-allow (subsumption, not equality)"
        );
        assert!(
            !c.contains("fapd-W10"),
            "no W10 on a same-decision (allow-allow) pair"
        );
        assert!(
            !c.contains("fapd-W04"),
            "no W04 on allow-then-allow (W04 is deny-then-allow)"
        );
    }

    #[test]
    fn c02_does_not_fire_on_unrelated_rules() {
        // Genuinely different predicates -> neither a duplicate nor a shadow.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/usr/bin/foo")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/usr/bin/bar")],
                )],
            ),
        ];
        assert!(
            c02(&files).is_empty(),
            "distinct path predicates are not a duplicate: {:?}",
            c02(&files)
        );
    }

    // -----------------------------------------------------------------------
    // fapd-W10 - cross-file allow-then-deny DECISION-SHADOW (later is dead).
    // -----------------------------------------------------------------------

    #[test]
    fn w10_fires_on_allow_then_deny_same_match() {
        // Earlier file `allow`, later file `deny` with EQUAL match predicates:
        // the deny is unreachable (first match wins) -> exactly one W10,
        // anchored at the later (dead) deny, naming the earlier allow's file.
        let files = vec![
            (
                PathBuf::from("rules.d/20-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let d = w10(&files);
        assert_eq!(
            d.len(),
            1,
            "allow-then-deny same-match fires one W10: {d:?}"
        );
        assert_eq!(d[0].code.as_ref(), "fapd-W10");
        assert_eq!(d[0].severity, Severity::Warning);
        assert!(
            d[0].file.ends_with("30-deny.rules"),
            "W10 anchors the later dead deny: {:?}",
            d[0].file
        );
        assert!(
            d[0].message.contains("20-allow.rules"),
            "W10 prose names the earlier allow's file: {}",
            d[0].message
        );
        assert_eq!(d[0].source_id.as_deref(), Some("rules.d/30-deny.rules"));
    }

    #[test]
    fn w10_does_not_fire_on_deny_then_allow() {
        // deny-then-allow is fapd-W04's direction. W10 is SCOPED to
        // allow-then-deny ONLY, so it must NOT fire here (no double-fire with
        // W04). A wrong impl that is direction-agnostic would wrongly emit W10.
        let files = vec![
            (
                PathBuf::from("rules.d/20-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            w10(&files).is_empty(),
            "deny-then-allow is W04's job, not W10: {:?}",
            w10(&files)
        );
    }

    #[test]
    fn w10_does_not_fire_on_same_file_pair() {
        // An allow then a deny in the SAME file is within-file reachability
        // (fapd-W01), not the cross-file W10.
        let files = vec![(
            PathBuf::from("rules.d/20-x.rules"),
            vec![
                modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
                modern_rule(
                    2,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
            ],
        )];
        assert!(
            w10(&files).is_empty(),
            "same-file allow-then-deny is W01, not W10: {:?}",
            w10(&files)
        );
    }

    #[test]
    fn w10_does_not_fire_on_allow_then_allow() {
        // Equal-predicate allow-then-allow is a DUPLICATE (C02), not a shadow.
        // W10 requires a conflicting allow-vs-deny outcome.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            w10(&files).is_empty(),
            "allow-then-allow is a C02 duplicate, not a W10 shadow: {:?}",
            w10(&files)
        );
    }

    #[test]
    fn w10_does_not_fire_on_subsumption_not_equality() {
        // EQUALITY-vs-SUBSUMPTION boundary for W10. Earlier file `allow all : all`,
        // later file `deny uid=0 : path=/x`. The decisions DO conflict
        // (allow -> deny), and the earlier allow STRICTLY SUBSUMES the later deny,
        // but the MATCH predicates are NOT equal. Per the locked design, W10 is
        // an EQUAL-match allow-then-deny shadow ONLY. It must NOT fire on mere
        // subsumption.
        //
        // The adversarial pin: a wrong impl defined as
        // `is_allow(earlier) && is_deny(later) && shadows(earlier, later)`
        // (subsumption via `subsume::shadows`) would WRONGLY emit W10 here,
        // because `shadows(allow_all_all, deny_uid0_pathx)` is true. The correct
        // EQUAL-match impl passes (no W10). The empty stub also passes, so this
        // test does NOT change RED status.
        //
        // (Per the locked design W10 is equal-match allow->deny only, so this
        // allow-subsumes-later-deny case is intentionally NOT flagged by any
        // cross-file code; it is not a gap.)
        let files = vec![
            (
                PathBuf::from("rules.d/20-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/30-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        assert!(
            w10(&files).is_empty(),
            "earlier `allow all : all` SUBSUMES but is not equal to the later \
             `deny uid=0 : path=/x`; W10 requires EQUAL match predicates, not \
             subsumption, so it must NOT fire: {:?}",
            w10(&files)
        );
        // Belt-and-braces via the aggregator: the subsumption pair must not leak
        // into W10 (nor masquerade as a C02 duplicate; decisions differ).
        let diags = crate::lints::lint_cross_file(&files);
        let c = codes(&diags);
        assert!(
            !c.contains("fapd-W10"),
            "no W10 on allow-subsumes-deny (subsumption, not equal match)"
        );
        assert!(
            !c.contains("fapd-C02"),
            "no C02 on conflicting decisions (allow vs deny)"
        );
    }

    #[test]
    fn w10_does_not_fire_on_unrelated_rules() {
        // Different predicates -> the deny is reachable, no shadow.
        let files = vec![
            (
                PathBuf::from("rules.d/20-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/usr/bin/foo")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/usr/bin/bar")],
                )],
            ),
        ];
        assert!(
            w10(&files).is_empty(),
            "distinct predicates: deny is reachable, no W10: {:?}",
            w10(&files)
        );
    }

    // -----------------------------------------------------------------------
    // Non-overlap + aggregator wiring: the three cross-file equal-predicate
    // codes (C02 / W04 / W10) must NEVER double-fire on the same pair, and
    // `lint_cross_file` must surface C02 and W10 end to end.
    // -----------------------------------------------------------------------

    #[test]
    fn aggregator_surfaces_c02_on_allow_dup() {
        // End-to-end: lint_cross_file must reach the new C02 pass.
        let files = vec![
            (
                PathBuf::from("rules.d/20-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let diags = crate::lints::lint_cross_file(&files);
        let c = codes(&diags);
        assert!(
            c.contains("fapd-C02"),
            "lint_cross_file reaches C02: {diags:?}"
        );
        // A duplicate (same decision) is NOT a W10 shadow and NOT a W04.
        assert!(
            !c.contains("fapd-W10"),
            "no W10 on a same-decision dup: {diags:?}"
        );
        assert!(
            !c.contains("fapd-W04"),
            "no W04 on a same-decision dup: {diags:?}"
        );
    }

    #[test]
    fn aggregator_surfaces_w10_on_allow_then_deny() {
        // End-to-end: lint_cross_file must reach the new W10 pass, and the
        // allow-then-deny pair must NOT also trigger W04 (that is deny-then-allow)
        // or C02 (that is same-decision). Locks the full non-overlap table.
        let files = vec![
            (
                PathBuf::from("rules.d/20-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let diags = crate::lints::lint_cross_file(&files);
        let c = codes(&diags);
        assert!(
            c.contains("fapd-W10"),
            "lint_cross_file reaches W10: {diags:?}"
        );
        assert!(
            !c.contains("fapd-C02"),
            "no C02 on conflicting decisions: {diags:?}"
        );
        assert!(
            !c.contains("fapd-W04"),
            "no W04 on allow-then-deny: {diags:?}"
        );
    }

    #[test]
    fn deny_then_allow_is_w04_only_not_w10_not_c02() {
        // The third row of the non-overlap table: deny-then-allow equal-match is
        // fapd-W04 EXCLUSIVELY. Locks that adding C02/W10 did not disturb W04 and
        // that neither new code poaches W04's direction.
        let files = vec![
            (
                PathBuf::from("rules.d/20-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/30-allow.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let diags = crate::lints::lint_cross_file(&files);
        let c = codes(&diags);
        assert!(c.contains("fapd-W04"), "deny-then-allow is W04: {diags:?}");
        assert!(
            !c.contains("fapd-W10"),
            "deny-then-allow is not W10: {diags:?}"
        );
        assert!(
            !c.contains("fapd-C02"),
            "deny-then-allow is not a C02 dup: {diags:?}"
        );
    }

    #[test]
    fn lint_cross_file_emits_both_w04_and_c01() {
        // file 0 `10-deny.rules`: `deny all : all` (terminal, shadows everything later).
        // file 1 `badname.rules`: `allow uid=0 : all` -> unreachable (fapd-W04) AND
        //   the filename lacks the NN- prefix (fapd-C01). One lint_cross_file call
        //   must surface BOTH codes.
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/badname.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![Attr::All],
                )],
            ),
        ];
        let diags = crate::lints::lint_cross_file(&files);
        let codes: std::collections::HashSet<&str> =
            diags.iter().map(|d| d.code.as_ref()).collect();
        assert!(
            codes.contains("fapd-W04"),
            "expected fapd-W04 (badname's allow shadowed by 10-deny's `deny all : all`): {diags:?}"
        );
        assert!(
            codes.contains("fapd-C01"),
            "expected fapd-C01 (badname.rules lacks the NN- prefix): {diags:?}"
        );
    }
}
