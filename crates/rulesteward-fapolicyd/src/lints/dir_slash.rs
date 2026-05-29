//! fapd-W08 - a `dir=` value missing its trailing slash. fapolicyd matches
//! `dir=` by byte-prefix (non-slash-bounded `strncmp`, attr-sets.c:124-129),
//! so `dir=/usr/bin` also matches `/usr/binary`. fapolicyd.rules(5):128-129
//! recommends ending `dir=` values with `/`. Both literal string values and
//! `%setref` expansions are checked; an undefined macro emits nothing (fapd-E03
//! owns undefined-macro reporting).
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};
use crate::lints::subsume::build_macro_map;

pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let macro_map = build_macro_map(entries);
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
            match value {
                AttrValue::Str(s) => {
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
                AttrValue::SetRef(name) => {
                    // Look up the macro. If undefined, emit nothing - fapd-E03
                    // owns undefined-macro reporting.
                    if let Some(values) = macro_map.get(name) {
                        for v in values {
                            if !v.ends_with('/') {
                                diags.push(
                                    Diagnostic::new(
                                        Severity::Warning,
                                        "fapd-W08",
                                        r.span.clone(),
                                        format!(
                                            "dir set `%{name}` value `{v}` has no trailing slash; fapolicyd matches by byte-prefix, so it can over-match siblings - end the value with `/`"
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
                }
                AttrValue::Int(_) => {
                    // Integer dir values are not filesystem paths; skip.
                }
            }
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
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

    fn set_def(name: &str, values: &[&str]) -> Entry {
        Entry::SetDefinition {
            name: name.to_string(),
            values: values.iter().map(|s| s.to_string()).collect(),
            line: 1,
            span: rulesteward_core::span(0, 0),
        }
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

    // --- existing tests (regression guards) ---

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
    fn non_dir_attrs_are_ignored() {
        let e = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![kv("path", "/usr/bin")],
            vec![kv("exe", "/usr/sbin/foo")],
        )];
        assert!(walk(&e, &p()).is_empty());
    }

    // --- new SetRef tests ---

    #[test]
    fn w08_fires_on_setref_dir_without_slash() {
        // %appdirs=/opt/app (no slash), used as dir=%appdirs
        let entries = vec![
            set_def("appdirs", &["/opt/app"]),
            rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv_ref("dir", "appdirs")],
            ),
        ];
        let d = walk(&entries, &p());
        assert!(
            d.iter().any(|x| x.code.as_ref() == "fapd-W08"),
            "expected fapd-W08 but got: {d:?}"
        );
    }

    #[test]
    fn w08_silent_on_setref_dir_with_slash() {
        // %appdirs=/opt/app/ -> no warning
        let entries = vec![
            set_def("appdirs", &["/opt/app/"]),
            rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv_ref("dir", "appdirs")],
            ),
        ];
        assert!(walk(&entries, &p()).is_empty());
    }

    #[test]
    fn w08_setref_multiple_values_warns_each_slashless() {
        // %dirs=/opt/a,/opt/b/,/opt/c -> warns on /opt/a and /opt/c (2 diags)
        let entries = vec![
            set_def("dirs", &["/opt/a", "/opt/b/", "/opt/c"]),
            rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv_ref("dir", "dirs")],
            ),
        ];
        let d = walk(&entries, &p());
        assert_eq!(
            d.iter().filter(|x| x.code.as_ref() == "fapd-W08").count(),
            2,
            "expected 2 fapd-W08 diags but got: {d:?}"
        );
    }

    #[test]
    fn w08_undefined_setref_emits_nothing() {
        // dir=%missing with no definition -> W08 emits nothing (fapd-E03 owns undefined)
        let entries = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv_ref("dir", "missing")],
        )];
        assert!(walk(&entries, &p()).is_empty());
    }

    #[test]
    fn w08_literal_str_still_fires() {
        // regression guard: literal str path without trailing slash still triggers
        let entries = vec![rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "/usr/lib64")],
        )];
        assert_eq!(walk(&entries, &p()).len(), 1);
    }
}
