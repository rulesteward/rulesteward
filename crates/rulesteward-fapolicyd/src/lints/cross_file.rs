//! Cross-`rules.d/` lints: fapd-W04 (ordering) + fapd-C01 (filename convention).
//! Run AFTER per-file lints, over all files in fagenrules load order.
use std::path::PathBuf;

use rulesteward_core::{Diagnostic, Severity};

use super::subsume::{MacroMap, build_macro_map, shadows};
use crate::ast::{Decision, Entry, Rule};

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
                diags.push(
                    Diagnostic::new(
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
                        1,
                    )
                    .with_source_id(bpath.display().to_string()),
                );
                break;
            }
        }
    }
    diags
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
    use crate::ast::{Attr, AttrValue, Decision, Perm, Rule, SyntaxFlavor};
    use rulesteward_core::Severity;

    fn rule(
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
    fn setdef(line: usize, name: &str, values: &[&str]) -> Entry {
        Entry::SetDefinition {
            name: name.to_string(),
            values: values.iter().map(|s| (*s).to_string()).collect(),
            line,
            span: rulesteward_core::span(0, 0),
        }
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

    #[test]
    fn deny_all_in_earlier_file_shadows_later_allow() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![rule(
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
                vec![rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/90-deny.rules"),
                vec![rule(
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
                rule(1, Decision::Deny, None, vec![Attr::All], vec![Attr::All]),
                rule(
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
                vec![rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![kv("dir", "/usr/")],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![rule(
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
                    setdef(1, "admins", &["0", "1000"]),
                    rule(
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
                vec![rule(
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
                vec![rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![kv("path", "/usr/bin/foo")],
                )],
            ),
            (
                PathBuf::from("rules.d/50-allow.rules"),
                vec![rule(
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
                vec![rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/50-deny.rules"),
                vec![rule(
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

    #[test]
    fn lint_cross_file_emits_both_w04_and_c01() {
        // file 0 `10-deny.rules`: `deny all : all` (terminal, shadows everything later).
        // file 1 `badname.rules`: `allow uid=0 : all` -> unreachable (fapd-W04) AND
        //   the filename lacks the NN- prefix (fapd-C01). One lint_cross_file call
        //   must surface BOTH codes.
        let files = vec![
            (
                PathBuf::from("rules.d/10-deny.rules"),
                vec![rule(
                    1,
                    Decision::Deny,
                    None,
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/badname.rules"),
                vec![rule(
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
