//! fapd-W08 - a `dir=` value missing its trailing slash. fapolicyd matches
//! `dir=` by byte-prefix (non-slash-bounded `strncmp`, attr-sets.c:124-129),
//! so `dir=/usr/bin` also matches `/usr/binary`. fapolicyd.rules(5):128-129
//! recommends ending `dir=` values with `/`. Both literal string values and
//! `%setref` expansions are checked; an undefined macro emits nothing (fapd-E03
//! owns undefined-macro reporting).
//!
//! The three documented `dir=` keyword values (`execdirs`, `systemdirs`,
//! `untrusted`) are NOT filesystem paths and are exempt from this check - see
//! `DIR_KEYWORDS`.
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Entry};
use crate::lints::subsume::build_macro_map;

/// fapolicyd's documented non-path `dir=` keyword values. These are not paths,
/// so the "missing trailing slash" advice (fapd-W08) does not apply - appending
/// `/` would turn the keyword into a literal path and change the rule's meaning.
/// (man fapolicyd.rules: "3 keywords that dir supports: execdirs, systemdirs, untrusted".)
const DIR_KEYWORDS: [&str; 3] = ["execdirs", "systemdirs", "untrusted"];

pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let macro_map = build_macro_map(entries);
    let mut diags = Vec::new();
    for e in entries {
        let Entry::Rule(r) = e else {
            continue;
        };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value, .. } = attr else {
                continue;
            };
            if key != "dir" {
                continue;
            }
            match value {
                AttrValue::Str(s) => {
                    // Skip the three documented dir= keywords; they are not
                    // paths and adding a trailing slash would change their
                    // meaning entirely.
                    if DIR_KEYWORDS.contains(&s.as_str()) {
                        continue;
                    }
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
                            // Skip keyword values that may legitimately appear
                            // in a set used as a dir= operand.
                            if DIR_KEYWORDS.contains(&v.as_str()) {
                                continue;
                            }
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
    use crate::ast::{Attr, Decision};
    use crate::lints::testkit::{kv, kv_ref, modern_rule, p, set_def};
    use rulesteward_core::Severity;

    // --- existing tests (regression guards) ---

    #[test]
    fn dir_without_trailing_slash_fires() {
        let e = vec![modern_rule(
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
        let e = vec![modern_rule(
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
        let e = vec![modern_rule(
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
        let e = vec![modern_rule(
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
            set_def(1, "appdirs", &["/opt/app"]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv_ref("dir", "appdirs")],
            ),
        ];
        let d = walk(&entries, &p());
        assert_eq!(
            d.iter().filter(|x| x.code.as_ref() == "fapd-W08").count(),
            1,
            "expected exactly one fapd-W08 for the single slash-less setref value, got: {d:?}"
        );
    }

    #[test]
    fn w08_silent_on_setref_dir_with_slash() {
        // %appdirs=/opt/app/ -> no warning
        let entries = vec![
            set_def(1, "appdirs", &["/opt/app/"]),
            modern_rule(
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
            set_def(1, "dirs", &["/opt/a", "/opt/b/", "/opt/c"]),
            modern_rule(
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
        let entries = vec![modern_rule(
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
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "/usr/lib64")],
        )];
        assert_eq!(walk(&entries, &p()).len(), 1);
    }

    // --- dir= keyword exemption tests ---

    #[test]
    fn w08_silent_on_dir_keyword_execdirs() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "execdirs")],
        )];
        assert!(
            walk(&entries, &p()).is_empty(),
            "execdirs is a keyword, not a path"
        );
    }

    #[test]
    fn w08_silent_on_all_three_dir_keywords_both_sides() {
        // execdirs/systemdirs/untrusted on subject and/or object dir= -> no W08
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv("dir", "execdirs")],
                vec![kv("dir", "systemdirs")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv("dir", "untrusted")],
            ),
        ];
        assert!(walk(&entries, &p()).is_empty());
    }

    #[test]
    fn w08_silent_on_setref_expanding_to_all_three_keywords() {
        // %d=execdirs,systemdirs,untrusted ; dir=%d -> no W08 for any keyword.
        // Kills a mutant on the DIR_KEYWORDS slot for systemdirs or untrusted
        // that is only exercised through the SetRef branch.
        let entries = vec![
            set_def(1, "d", &["execdirs", "systemdirs", "untrusted"]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::All],
                vec![kv_ref("dir", "d")],
            ),
        ];
        assert!(
            walk(&entries, &p()).is_empty(),
            "a set expanding to dir= keywords (execdirs/systemdirs/untrusted) must not trigger W08"
        );
    }

    #[test]
    fn w08_still_fires_on_real_path_without_slash() {
        // regression guard: a real path (not a keyword) still fires
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "/usr/lib64")],
        )];
        assert_eq!(
            walk(&entries, &p())
                .iter()
                .filter(|d| d.code == "fapd-W08")
                .count(),
            1
        );
    }

    #[test]
    fn w08_keyword_with_slash_is_treated_as_path_no_panic() {
        // sanity: dir=execdirs/ is NOT one of the exact keywords (it has a trailing
        // slash) so it is treated as a path; it ends with slash so no W08 anyway.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("dir", "execdirs/")],
        )];
        // Ends with slash -> passes, and importantly doesn't panic
        assert!(walk(&entries, &p()).is_empty());
    }
}
