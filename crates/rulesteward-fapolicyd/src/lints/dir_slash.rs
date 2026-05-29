//! fapd-W08 - a `dir=` value missing its trailing slash. fapolicyd matches
//! `dir=` by byte-prefix (non-slash-bounded `strncmp`, attr-sets.c:124-129),
//! so `dir=/usr/bin` also matches `/usr/binary`. fapolicyd.rules(5):128-129
//! recommends ending `dir=` values with `/`. Only literal string values are
//! checked; `%setref` dirs are skipped (expansion is not a static path here).
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};

pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for e in entries {
        let Entry::Rule(r) = e else {
            continue;
        };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value } = attr else {
                continue;
            };
            if key != "dir" {
                continue;
            }
            let AttrValue::Str(s) = value else {
                continue;
            };
            if !s.ends_with('/') {
                diags.push(
                    Diagnostic::new(
                        Severity::Warning,
                        "fapd-W08",
                        r.span.clone(),
                        format!(
                            "`dir={s}` has no trailing slash; fapolicyd matches by byte-prefix, so it can over-match siblings - end the value with `/`"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, AttrValue, Decision, Perm, Rule, SyntaxFlavor};
    use rulesteward_core::Severity;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/tmp/test.rules")
    }
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
    fn kv(key: &str, value: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Str(value.to_string()),
        }
    }
    fn kv_ref(key: &str, set: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::SetRef(set.to_string()),
        }
    }

    #[test]
    fn dir_without_trailing_slash_fires() {
        let e = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "/usr/bin")],
        )];
        let d = walk(&e, &p());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, "fapd-W08");
        assert_eq!(d[0].severity, Severity::Warning);
        assert!(d[0].message.contains("/usr/bin"));
    }
    #[test]
    fn dir_with_trailing_slash_passes() {
        let e = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "/usr/bin/")],
        )];
        assert!(walk(&e, &p()).is_empty());
    }
    #[test]
    fn fires_on_subject_and_object_sides_independently() {
        let e = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![kv("dir", "/a")],
            vec![kv("dir", "/b")],
        )];
        assert_eq!(walk(&e, &p()).len(), 2);
    }
    #[test]
    fn non_dir_attrs_and_setref_dirs_are_ignored() {
        let e = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![kv("path", "/usr/bin")],
            vec![kv_ref("dir", "somedirs")],
        )];
        assert!(walk(&e, &p()).is_empty());
    }
}
