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
}
