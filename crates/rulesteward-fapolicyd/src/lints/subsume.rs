//! Shared rule-subsumption engine behind fapd-W01 (within-file, `reachability`)
//! and fapd-W04 (cross-file, `cross_file`): predicate/perm/dir-prefix coverage.

use std::collections::HashMap;

use crate::ast::{Attr, AttrValue, Perm, Rule};

/// File-scoped expansion of `%name=` set definitions: name -> the raw value
/// strings fapolicyd would substitute. Built once per file. Macro-of-macro is
/// impossible by construction (`SetDefinition.values` is `Vec<String>`, never
/// `AttrValue`), so a single flat map is exact.
pub(crate) type MacroMap = HashMap<String, Vec<String>>;

/// Build the file-scoped macro map from every `Entry::SetDefinition`. A later
/// redefinition of the same name overwrites the earlier one (last-wins),
/// mirroring fapolicyd's behavior where the final definition is the one in
/// effect.
pub(crate) fn build_macro_map(entries: &[crate::ast::Entry]) -> MacroMap {
    let mut map = MacroMap::new();
    for entry in entries {
        if let crate::ast::Entry::SetDefinition { name, values, .. } = entry {
            map.insert(name.clone(), values.clone());
        }
    }
    map
}

/// Whether earlier rule `a` shadows later rule `b`: every event `b` matches is
/// also matched by `a` (perm, subject, and object all subsumed).
///
/// No decision-kind gate: fapolicyd treats every decision as terminal (a
/// matched rule ends evaluation per `rules.c:eval_action`), so an earlier rule
/// whose predicates subsume B's makes B unreachable regardless of A's decision.
/// If a non-terminal decision is ever added to the spec, this fn must gain a
/// terminal-check on `a` (only a terminal rule ends evaluation and shadows).
pub(crate) fn shadows(a: &Rule, b: &Rule, macro_map: &MacroMap) -> bool {
    subsumes_perm(a.perm, b.perm)
        && subsumes_predicate_list(&a.subject, &b.subject, macro_map)
        && subsumes_predicate_list(&a.object, &b.object, macro_map)
}

/// Mechanism 2: `a_perm` subsumes `b_perm` iff `a` imposes no stricter perm
/// constraint than `b`. `None` (no `perm=` clause) and `Some(Perm::Any)` match
/// any perm; otherwise the perms must be equal.
fn subsumes_perm(a_perm: Option<Perm>, b_perm: Option<Perm>) -> bool {
    match a_perm {
        None | Some(Perm::Any) => true,
        Some(p) => Some(p) == b_perm,
    }
}

/// Mechanism 3: A's predicate list subsumes B's iff every constraint A imposes
/// is at-least-as-loose as a matching constraint in B.
///
/// Sub-mechanism 3a (`Attr::All` shortcut): if A is exactly `[Attr::All]`, it
/// matches any event on this side, so it subsumes any non-empty B.
///
/// Sub-mechanism 3b (literal-equal subset): otherwise, for each
/// `Attr::Kv { key, value }` in A, B must contain an `Attr::Kv` with the same
/// key whose value A subsumes.
fn subsumes_predicate_list(a_attrs: &[Attr], b_attrs: &[Attr], macro_map: &MacroMap) -> bool {
    if a_attrs == [Attr::All] {
        return !b_attrs.is_empty();
    }
    a_attrs
        .iter()
        .all(|a_attr| subsumes_attr(a_attr, b_attrs, macro_map))
}

/// Whether the single A-side constraint `a_attr` is covered by some constraint
/// in `b_attrs`. Covers two cases:
///
/// - same-key value subsume (Mechanism 3b/3c).
/// - cross-attribute `dir=` prefix hierarchy (Mechanism 3d): a `dir=` in A can
///   cover a `path=` (object side) or `exe=` (subject side) in B.
fn subsumes_attr(a_attr: &Attr, b_attrs: &[Attr], macro_map: &MacroMap) -> bool {
    let Attr::Kv { key, value } = a_attr else {
        return false;
    };
    b_attrs.iter().any(|b_attr| {
        let Attr::Kv {
            key: b_key,
            value: b_value,
        } = b_attr
        else {
            return false;
        };
        if key == b_key && subsumes_value(value, b_value, macro_map) {
            return true;
        }
        // Mechanism 3d: a `dir=` prefix in A covers `path=`/`exe=` in B.
        key == "dir"
            && (b_key == "path" || b_key == "exe")
            && dir_prefix_covers(value, b_value, macro_map)
    })
}

/// Mechanism 3d (cross-attribute `dir=` prefix hierarchy).
///
/// Whether a `dir=` value `prefix_av` covers a `path=`/`exe=` value
/// `target_av`. fapolicyd's `dir=` matching uses
/// `strncmp(prefix, candidate, prefix_len)` per `attr-sets.c:124-129`; it is
/// NOT slash-bounded. The man page `fapolicyd.rules(5):128-129` warns users to
/// end `dir=` values with `/`. fapd-W01 mimics fapolicyd's actual behavior; a
/// future fapd-W08 will lint the missing-trailing-slash footgun.
///
/// If A's `dir` value is a `SetRef`, it expands to multiple prefixes via the
/// macro map; A covers B if ANY expanded prefix is a byte-prefix of B's value.
/// A `SetRef` on B's side cannot be a filesystem path, so it never matches.
fn dir_prefix_covers(prefix_av: &AttrValue, target_av: &AttrValue, macro_map: &MacroMap) -> bool {
    // A SetRef target is not a concrete path; no prefix relationship.
    if matches!(target_av, AttrValue::SetRef(_)) {
        return false;
    }
    let target = value_as_string(target_av);
    dir_prefixes(prefix_av, macro_map)
        .iter()
        .any(|prefix| target.starts_with(prefix.as_str()))
}

/// Expand a `dir=` value to the concrete prefix strings it represents. A
/// literal yields a single prefix; a `SetRef` yields its expanded members.
fn dir_prefixes(prefix_av: &AttrValue, macro_map: &MacroMap) -> Vec<String> {
    match prefix_av {
        AttrValue::SetRef(name) => expand_set(name, macro_map),
        other => vec![value_as_string(other)],
    }
}

/// Mechanism 3c (macro expansion, bidirectional): whether `a_value` subsumes
/// `b_value`, expanding any `SetRef` via `macro_map`. An undefined `SetRef`
/// expands to the empty set.
///
/// - both `SetRef`: A subsumes B iff B's set is a subset of A's set.
/// - A `SetRef`, B literal: A subsumes B iff B's literal is a member of A's set.
/// - B `SetRef`, A literal: A subsumes B iff every member of B's set equals A
///   (a single-element B-set whose member is A).
/// - neither: literal equality.
fn subsumes_value(a_value: &AttrValue, b_value: &AttrValue, macro_map: &MacroMap) -> bool {
    match (a_value, b_value) {
        (AttrValue::SetRef(a_set), AttrValue::SetRef(b_set)) => {
            let a_members = expand_set(a_set, macro_map);
            expand_set(b_set, macro_map)
                .iter()
                .all(|m| a_members.contains(m))
        }
        (AttrValue::SetRef(a_set), b_lit) => {
            expand_set(a_set, macro_map).contains(&value_as_string(b_lit))
        }
        (a_lit, AttrValue::SetRef(b_set)) => {
            let a_str = value_as_string(a_lit);
            let b_members = expand_set(b_set, macro_map);
            !b_members.is_empty() && b_members.iter().all(|m| *m == a_str)
        }
        (a_lit, b_lit) => a_lit == b_lit,
    }
}

/// Expand a set name to its member strings via `macro_map`. An undefined name
/// yields an empty set (fapolicyd substitutes nothing for an unknown macro).
fn expand_set(name: &str, macro_map: &MacroMap) -> Vec<String> {
    macro_map.get(name).cloned().unwrap_or_default()
}

/// Render a literal `AttrValue` to the string form used for macro-member
/// comparison. `SetDefinition.values` are stored as the raw token strings, so
/// an `Int(0)` literal must compare against the string `"0"`. `SetRef` should
/// never reach here (callers route it through `expand_set`), but we render its
/// name as a defensive fallback.
fn value_as_string(value: &AttrValue) -> String {
    match value {
        AttrValue::Str(s) => s.clone(),
        AttrValue::Int(n) => n.to_string(),
        AttrValue::SetRef(name) => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, AttrValue, Perm};

    /// An empty macro map for helper tests that exercise no `%name=` sets.
    fn no_macros() -> MacroMap {
        MacroMap::new()
    }

    fn kv(key: &str, value: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Str(value.to_string()),
        }
    }

    fn kv_int(key: &str, value: i64) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Int(value),
        }
    }

    fn kv_ref(key: &str, set: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::SetRef(set.to_string()),
        }
    }

    fn setdef(line: usize, name: &str, values: &[&str]) -> crate::ast::Entry {
        crate::ast::Entry::SetDefinition {
            name: name.to_string(),
            values: values.iter().map(|s| (*s).to_string()).collect(),
            line,
            span: rulesteward_core::span(0, 0),
        }
    }

    // --- subsumes_perm (Mechanism 2) ---

    #[test]
    fn perm_none_subsumes_anything() {
        // A imposes no perm constraint -> covers every B perm.
        assert!(subsumes_perm(None, None));
        assert!(subsumes_perm(None, Some(Perm::Execute)));
        assert!(subsumes_perm(None, Some(Perm::Open)));
        assert!(subsumes_perm(None, Some(Perm::Any)));
    }

    #[test]
    fn perm_any_subsumes_anything() {
        assert!(subsumes_perm(Some(Perm::Any), None));
        assert!(subsumes_perm(Some(Perm::Any), Some(Perm::Execute)));
        assert!(subsumes_perm(Some(Perm::Any), Some(Perm::Open)));
    }

    #[test]
    fn perm_specific_only_subsumes_equal() {
        // A=execute only covers B=execute; not None, not Open, not Any.
        assert!(subsumes_perm(Some(Perm::Execute), Some(Perm::Execute)));
        assert!(!subsumes_perm(Some(Perm::Execute), None));
        assert!(!subsumes_perm(Some(Perm::Execute), Some(Perm::Open)));
        assert!(!subsumes_perm(Some(Perm::Execute), Some(Perm::Any)));
    }

    // --- subsumes_value (Mechanism 3b literal-equal) ---

    #[test]
    fn attr_value_literal_equal_subsumes() {
        assert!(subsumes_value(
            &AttrValue::Str("/bin/sh".into()),
            &AttrValue::Str("/bin/sh".into()),
            &no_macros(),
        ));
        assert!(subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::Int(0),
            &no_macros()
        ));
    }

    #[test]
    fn attr_value_literal_inequal_does_not_subsume() {
        assert!(!subsumes_value(
            &AttrValue::Str("/usr/bin/foo".into()),
            &AttrValue::Str("/usr/bin/bar".into()),
            &no_macros(),
        ));
        assert!(!subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::Int(1),
            &no_macros()
        ));
    }

    // --- subsumes_predicate_list (Mechanism 3) ---

    #[test]
    fn predicate_list_literal_equal_subset_subsumes() {
        // A=[uid=0] subsumes B=[uid=0] (same key, equal value).
        let a = vec![kv_int("uid", 0)];
        let b = vec![kv_int("uid", 0)];
        assert!(subsumes_predicate_list(&a, &b, &no_macros()));
    }

    #[test]
    fn predicate_list_extra_a_constraint_blocks_subsume() {
        // A=[uid=0, gid=0] requires B to satisfy BOTH; B=[uid=0] is missing
        // gid -> A does not subsume B (A is narrower).
        let a = vec![kv_int("uid", 0), kv_int("gid", 0)];
        let b = vec![kv_int("uid", 0)];
        assert!(!subsumes_predicate_list(&a, &b, &no_macros()));
    }

    #[test]
    fn predicate_list_differing_value_blocks_subsume() {
        let a = vec![kv("path", "/usr/bin/foo")];
        let b = vec![kv("path", "/usr/bin/bar")];
        assert!(!subsumes_predicate_list(&a, &b, &no_macros()));
    }

    #[test]
    fn value_subsume_setref_covers_literal_member() {
        // A=SetRef{0,1000} subsumes literal Int(0) and Int(1000), not Int(7).
        let map = build_macro_map(&[setdef(1, "admins", &["0", "1000"])]);
        assert!(subsumes_value(
            &AttrValue::SetRef("admins".into()),
            &AttrValue::Int(0),
            &map
        ));
        assert!(subsumes_value(
            &AttrValue::SetRef("admins".into()),
            &AttrValue::Int(1000),
            &map
        ));
        assert!(!subsumes_value(
            &AttrValue::SetRef("admins".into()),
            &AttrValue::Int(7),
            &map
        ));
    }

    #[test]
    fn value_subsume_setref_to_setref_superset() {
        // A's set must be a superset of B's set.
        let map = build_macro_map(&[
            setdef(1, "big", &["a", "b", "c"]),
            setdef(2, "small", &["a", "b"]),
        ]);
        assert!(subsumes_value(
            &AttrValue::SetRef("big".into()),
            &AttrValue::SetRef("small".into()),
            &map
        ));
        assert!(!subsumes_value(
            &AttrValue::SetRef("small".into()),
            &AttrValue::SetRef("big".into()),
            &map
        ));
    }

    #[test]
    fn value_subsume_undefined_setref_is_empty_set() {
        // An undefined SetRef expands to the empty set: as A it covers nothing.
        let map = build_macro_map(&[]);
        assert!(!subsumes_value(
            &AttrValue::SetRef("ghost".into()),
            &AttrValue::Int(0),
            &map
        ));
    }

    #[test]
    fn value_subsume_literal_a_covers_singleton_b_set() {
        // A literal `uid=0` subsumes a SetRef B whose expansion is exactly
        // {0}: every member of B equals A, so the narrower-looking B-set is
        // actually identical to A. (Mechanism 3c "B SetRef, A literal" case.)
        let map = build_macro_map(&[setdef(1, "justzero", &["0"])]);
        assert!(subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::SetRef("justzero".into()),
            &map
        ));
    }

    #[test]
    fn value_subsume_literal_a_does_not_cover_multimember_b_set() {
        // A literal `uid=0` does NOT subsume a SetRef B = {0,1000}: B can match
        // uid=1000 which A (only uid=0) cannot. Kills the `&& -> ||` mutant
        // (non-empty AND not-all-equal must stay false) and the `== -> !=`
        // mutant (0 == 1000 is false, so `all(== )` is false here).
        let map = build_macro_map(&[setdef(1, "admins", &["0", "1000"])]);
        assert!(!subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::SetRef("admins".into()),
            &map
        ));
    }

    #[test]
    fn value_subsume_literal_a_does_not_cover_empty_b_set() {
        // A literal `uid=0` does NOT subsume an undefined (empty) SetRef B.
        // An empty B-set vacuously satisfies `all(== )`, so without the
        // non-empty guard the result would wrongly be true. Kills the
        // `delete !` mutant on the `!b_members.is_empty()` guard.
        let map = build_macro_map(&[]);
        assert!(!subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::SetRef("ghost".into()),
            &map
        ));
    }

    #[test]
    fn value_subsume_literal_a_mismatch_singleton_b_set() {
        // A literal `uid=0` does NOT subsume a singleton SetRef B = {7}.
        // Reinforces the `== -> !=` kill: 0 == 7 is false -> not covered.
        let map = build_macro_map(&[setdef(1, "seven", &["7"])]);
        assert!(!subsumes_value(
            &AttrValue::Int(0),
            &AttrValue::SetRef("seven".into()),
            &map
        ));
    }

    #[test]
    fn dir_does_not_cross_to_unrelated_keys() {
        // A `dir=` only covers `path=`/`exe=` cross-attribute. It must NOT
        // cover, say, a `uid=` or `comm=` in B. Guards against a mutant that
        // widens the cross-attribute key set.
        let map = no_macros();
        // dir vs comm (subject) -> no cross.
        assert!(!subsumes_attr(
            &kv("dir", "/usr/"),
            &[kv("comm", "/usr/bin/ls")],
            &map
        ));
        // dir vs device (object) -> no cross.
        assert!(!subsumes_attr(
            &kv("dir", "/dev/"),
            &[kv("device", "/dev/sda")],
            &map
        ));
    }

    #[test]
    fn dir_prefix_covers_object_path_with_setref_dir() {
        // A's dir is a SetRef expanding to multiple prefixes; ANY covering
        // prefix is enough.
        let map = build_macro_map(&[setdef(1, "bindirs", &["/opt/", "/usr/bin/"])]);
        let a = kv_ref("dir", "bindirs");
        let b = vec![kv("path", "/usr/bin/ls")];
        assert!(subsumes_attr(&a, &b, &map));
    }

    #[test]
    fn predicate_list_all_shortcut_subsumes_nonempty() {
        // A=[Attr::All] subsumes any non-empty B.
        assert!(subsumes_predicate_list(
            &[Attr::All],
            &[kv("path", "/bin/sh")],
            &no_macros()
        ));
        assert!(subsumes_predicate_list(
            &[Attr::All],
            &[kv_int("uid", 0)],
            &no_macros()
        ));
    }

    #[test]
    fn predicate_list_all_shortcut_only_when_a_is_exactly_all() {
        // A=[uid=0, Attr::All] is NOT the All shortcut (it has an extra
        // constraint). It must fall through to literal-equal which finds no
        // matching uid in B=[path=...] -> no subsume. Guards against a mutant
        // that treats "contains Attr::All" as the shortcut.
        let a = vec![kv_int("uid", 0), Attr::All];
        let b = vec![kv("path", "/bin/sh")];
        assert!(!subsumes_predicate_list(&a, &b, &no_macros()));
    }
}
