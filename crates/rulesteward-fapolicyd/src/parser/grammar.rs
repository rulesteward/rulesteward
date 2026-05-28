//! chumsky 0.13 combinators for the fapolicyd rule grammar.
//!
//! Two top-level productions:
//! * [`modern_rule`]  - `decision [perm=X] subj : obj`
//! * [`legacy_rule`]  - `decision [perm=X] subj... obj...` (no colon;
//!   subject/object split positionally via the internal `legacy_classify`).
//!
//! Plus [`set_definition`] for `%name=val1,val2`. Every named production
//! carries a `.labelled(...)` so chumsky's expected-token list surfaces
//! operator-facing names in fapd-F01 diagnostics rather than raw character
//! classes.

use chumsky::extra;
use chumsky::prelude::*;

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
use crate::attrs::AttrSide;

fn decision_kw<'a>() -> impl Parser<'a, &'a str, Decision, extra::Err<Rich<'a, char>>> + Clone {
    choice((
        just("allow_audit").to(Decision::AllowAudit),
        just("allow_syslog").to(Decision::AllowSyslog),
        just("allow_log").to(Decision::AllowLog),
        just("deny_audit").to(Decision::DenyAudit),
        just("deny_syslog").to(Decision::DenySyslog),
        just("deny_log").to(Decision::DenyLog),
        just("allow").to(Decision::Allow),
        just("deny").to(Decision::Deny),
    ))
    .labelled("decision keyword")
}

fn perm_value<'a>() -> impl Parser<'a, &'a str, Perm, extra::Err<Rich<'a, char>>> + Clone {
    choice((
        just("execute").to(Perm::Execute),
        just("open").to(Perm::Open),
        just("any").to(Perm::Any),
    ))
    .labelled("perm value")
}

fn ident<'a>() -> impl Parser<'a, &'a str, String, extra::Err<Rich<'a, char>>> + Clone {
    any()
        .filter(|c: &char| c.is_ascii_alphabetic() || *c == '_')
        .then(
            any()
                .filter(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
                .repeated(),
        )
        .to_slice()
        .map(|s: &str| s.to_string())
        .labelled("identifier")
}

/// Set name (`%name`), matching fapolicyd's `parse_set_name`: any run of
/// ASCII alphanumeric or `_` characters. Unlike [`ident`], a leading digit is
/// allowed (`%1abc`), and there is no length cap. Distinct from `ident` so
/// attribute-key parsing keeps its leading-letter rule.
fn set_name<'a>() -> impl Parser<'a, &'a str, String, extra::Err<Rich<'a, char>>> + Clone {
    any()
        .filter(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
        .repeated()
        .at_least(1)
        .to_slice()
        .map(|s: &str| s.to_string())
        .labelled("set name")
}

fn attr_value<'a>() -> impl Parser<'a, &'a str, AttrValue, extra::Err<Rich<'a, char>>> + Clone {
    // SetRef branch is unambiguous (starts with `%`). The rest captures any
    // contiguous non-ws non-`:` slug as one token, then post-classifies it
    // via `parse::<i64>()`. Capturing-then-classifying eliminates a
    // chumsky-backtracking trap on values like `0a` where the eager int
    // combinator would consume `0` and leave `a` unparseable.
    choice((
        just('%')
            .ignore_then(set_name())
            .map(AttrValue::SetRef)
            .labelled("set reference"),
        any()
            .filter(|c: &char| !c.is_whitespace() && *c != ':')
            .repeated()
            .at_least(1)
            .to_slice()
            .map(|s: &str| {
                s.parse::<i64>()
                    .map_or_else(|_| AttrValue::Str(s.to_string()), AttrValue::Int)
            })
            .labelled("integer or string value"),
    ))
    .labelled("attribute value")
}

fn attr<'a>() -> impl Parser<'a, &'a str, Attr, extra::Err<Rich<'a, char>>> + Clone {
    let attr_kv = ident()
        .then_ignore(just('='))
        .then(attr_value())
        .map(|(key, value)| Attr::Kv { key, value });
    let attr_all = just("all").to(Attr::All);
    attr_all.or(attr_kv).labelled("attribute")
}

fn ws1<'a>() -> impl Parser<'a, &'a str, (), extra::Err<Rich<'a, char>>> + Clone {
    one_of(" \t").repeated().at_least(1).ignored()
}

fn ws0<'a>() -> impl Parser<'a, &'a str, (), extra::Err<Rich<'a, char>>> + Clone {
    one_of(" \t").repeated().ignored()
}

fn perm_clause<'a>() -> impl Parser<'a, &'a str, Perm, extra::Err<Rich<'a, char>>> + Clone {
    just("perm=").ignore_then(perm_value())
}

pub fn modern_rule<'a>() -> impl Parser<'a, &'a str, Entry, extra::Err<Rich<'a, char>>> {
    let attr_list = attr()
        .separated_by(ws1())
        .at_least(1)
        .collect::<Vec<Attr>>();

    ws0()
        .ignore_then(decision_kw())
        .then(ws1().ignore_then(perm_clause()).or_not())
        .then_ignore(ws1())
        .then(attr_list.clone())
        .then_ignore(ws0())
        .then_ignore(just(':').labelled("colon separator"))
        .then_ignore(ws0())
        .then(attr_list)
        .then_ignore(ws0())
        .then_ignore(end())
        .map_with(|(((decision, perm), subject), object), e| {
            let s = e.span();
            Entry::Rule(Rule {
                decision,
                perm,
                subject,
                object,
                syntax: SyntaxFlavor::Modern,
                line: 0,
                span: s.start..s.end,
            })
        })
}

pub fn legacy_rule<'a>() -> impl Parser<'a, &'a str, Entry, extra::Err<Rich<'a, char>>> {
    let attr_list = attr()
        .separated_by(ws1())
        .at_least(1)
        .collect::<Vec<Attr>>();

    ws0()
        .ignore_then(decision_kw())
        .then(ws1().ignore_then(perm_clause()).or_not())
        .then_ignore(ws1())
        .then(attr_list)
        .then_ignore(ws0())
        .then_ignore(end())
        .try_map(|((decision, perm), attrs_flat), span| {
            let (subject, object) =
                positional_split(&attrs_flat).map_err(|msg| Rich::custom(span, msg))?;
            Ok(Entry::Rule(Rule {
                decision,
                perm,
                subject,
                object,
                syntax: SyntaxFlavor::Legacy,
                line: 0,
                span: span.start..span.end,
            }))
        })
}

pub fn set_definition<'a>() -> impl Parser<'a, &'a str, Entry, extra::Err<Rich<'a, char>>> {
    let set_value = any()
        .filter(|c: &char| !c.is_whitespace() && *c != ',')
        .repeated()
        .at_least(1)
        .to_slice()
        .map(|s: &str| s.to_string())
        .labelled("set value");

    ws0()
        .ignore_then(just('%'))
        .ignore_then(set_name())
        .then_ignore(just('='))
        .then(
            set_value
                .separated_by(just(','))
                .at_least(1)
                .collect::<Vec<String>>(),
        )
        .then_ignore(ws0())
        .then_ignore(end())
        .map_with(|(name, values), e| {
            let s = e.span();
            Entry::SetDefinition {
                name,
                values,
                line: 0,
                span: s.start..s.end,
            }
        })
        .labelled("set definition")
}

/// Legacy-flavor attribute classification for the positional split.
///
/// This is intentionally different from `attrs::classify`, which is
/// flavor-agnostic (modern dialect). In the legacy ORIG format:
///
/// * `dir`, `ftype`, `trust` are object-only (in modern they are `Either`).
/// * `gid`, `ppid` are illegal on the legacy subject side and are NOT valid
///   split anchors (return `None`).
///
/// Source: R2-audit-grammar.md "Subject attributes (legacy ORIG format)" and
/// "Object attributes" sections.
fn legacy_classify(name: &str) -> Option<AttrSide> {
    match name {
        // Subject-only in legacy (`pattern` is subject-only in both flavors)
        "auid" | "uid" | "sessionid" | "pid" | "comm" | "exe" | "exe_dir" | "exe_type"
        | "pattern" => Some(AttrSide::Subject),
        // Object-only in legacy (dir/ftype/trust differ from modern's Either)
        "path" | "device" | "filehash" | "sha256hash" | "dir" | "ftype" | "trust" => {
            Some(AttrSide::Object)
        }
        // Valid on either side in both flavors
        "all" => Some(AttrSide::Either),
        // Unknown attribute, or legacy-illegal attrs (gid, ppid) - not a valid split anchor
        _ => None,
    }
}

/// Split a flat legacy-syntax attribute list into `(subject, object)` using
/// the legacy-specific attribute classifier. The first object-only attribute
/// marks the switch point.
///
/// Uses `legacy_classify` (not `attrs::classify`) so that `dir`, `ftype`, and
/// `trust` correctly serve as object-side anchors in the legacy dialect.
fn positional_split(attrs_flat: &[Attr]) -> Result<(Vec<Attr>, Vec<Attr>), String> {
    let switch_at = attrs_flat
        .iter()
        .position(|a| {
            matches!(a, Attr::Kv { key, .. } if matches!(legacy_classify(key), Some(AttrSide::Object)))
        })
        .ok_or_else(|| "legacy rule has no object-only attribute to split on".to_string())?;

    let subject: Vec<Attr> = attrs_flat[..switch_at].to_vec();
    let object: Vec<Attr> = attrs_flat[switch_at..].to_vec();
    if subject.is_empty() {
        return Err("legacy rule has no subject attributes before the object split".to_string());
    }
    Ok((subject, object))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_simple_allow_uid_to_all() {
        let parsed = modern_rule()
            .parse("allow uid=0 : all")
            .into_result()
            .expect("parses");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.decision, Decision::Allow);
            assert_eq!(r.syntax, SyntaxFlavor::Modern);
            assert_eq!(r.subject.len(), 1);
            assert_eq!(r.object, vec![Attr::All]);
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn modern_rejects_missing_colon() {
        let result = modern_rule().parse("allow uid=0 all").into_result();
        assert!(result.is_err(), "missing colon must fail modern");
    }

    #[test]
    fn legacy_simple_subject_object_split() {
        let parsed = legacy_rule()
            .parse("allow uid=0 path=/usr/bin/sh")
            .into_result()
            .expect("legacy parses");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.syntax, SyntaxFlavor::Legacy);
            assert_eq!(r.subject.len(), 1);
            assert_eq!(r.object.len(), 1);
            assert!(matches!(&r.subject[0], Attr::Kv { key, .. } if key == "uid"));
            assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "path"));
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rejects_when_no_object_attr_present() {
        // No object-only attr → split fails → diagnostic.
        let result = legacy_rule().parse("allow uid=0 uid=1").into_result();
        assert!(
            result.is_err(),
            "no object-only attr must fail legacy split"
        );
    }

    #[test]
    fn set_definition_parses_name_and_values() {
        let parsed = set_definition()
            .parse("%langs=ruby,perl,bash")
            .into_result()
            .expect("set def parses");
        if let Entry::SetDefinition { name, values, .. } = parsed {
            assert_eq!(name, "langs");
            assert_eq!(values, vec!["ruby", "perl", "bash"]);
        } else {
            panic!("expected SetDefinition");
        }
    }

    #[test]
    fn set_definition_accepts_leading_digit_name() {
        // fapolicyd's parse_set_name validates chars as isalnum||'_' with no
        // leading-letter requirement, so `%1abc` is a valid set name.
        let parsed = set_definition()
            .parse("%1abc=foo,bar")
            .into_result()
            .expect("leading-digit set name must parse");
        if let Entry::SetDefinition { name, .. } = parsed {
            assert_eq!(name, "1abc");
        } else {
            panic!("expected SetDefinition");
        }
    }

    #[test]
    fn set_ref_accepts_leading_digit_name() {
        // A `%name` value with a leading-digit set name must parse as a
        // SetRef, not fall through to a literal Str("%1abc").
        let parsed = modern_rule()
            .parse("allow uid=%1abc : all")
            .into_result()
            .expect("rule with leading-digit set ref must parse");
        if let Entry::Rule(r) = parsed {
            assert!(
                matches!(&r.subject[0], Attr::Kv { value: AttrValue::SetRef(s), .. } if s == "1abc"),
                "uid value should be SetRef(\"1abc\"), got {:?}",
                r.subject[0]
            );
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn positional_split_at_first_object_only() {
        let attrs_flat = vec![
            Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            },
            Attr::Kv {
                key: "path".into(),
                value: AttrValue::Str("/x".into()),
            },
        ];
        let (subject, object) = positional_split(&attrs_flat).expect("splits");
        assert_eq!(subject.len(), 1);
        assert_eq!(object.len(), 1);
    }

    #[test]
    fn positional_split_errors_when_object_attr_first() {
        let attrs_flat = vec![Attr::Kv {
            key: "path".into(),
            value: AttrValue::Str("/x".into()),
        }];
        // Subject would be empty - error.
        assert!(positional_split(&attrs_flat).is_err());
    }

    #[test]
    fn modern_rule_captures_full_body_span() {
        let body = "allow perm=execute uid=0 : path=/usr/bin/foo";
        let parsed = modern_rule().parse(body).into_result().expect("parses");
        if let Entry::Rule(r) = parsed {
            // The grammar yields a LINE-RELATIVE span here (full file fixup
            // happens in parser/mod.rs). For this single-rule body parsed
            // standalone, span should cover the entire input.
            assert_eq!(r.span.start, 0);
            assert_eq!(r.span.end, body.len());
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_captures_full_body_span() {
        let body = "allow uid=0 path=/usr/bin/sh";
        let parsed = legacy_rule()
            .parse(body)
            .into_result()
            .expect("legacy parses");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.span.start, 0);
            assert_eq!(r.span.end, body.len());
        } else {
            panic!("expected Rule");
        }
    }

    // --- legacy_classify unit tests (one per truth-table row) ---

    #[test]
    fn legacy_classify_uid_is_subject() {
        assert_eq!(legacy_classify("uid"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_auid_is_subject() {
        assert_eq!(legacy_classify("auid"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_sessionid_is_subject() {
        assert_eq!(legacy_classify("sessionid"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_pid_is_subject() {
        assert_eq!(legacy_classify("pid"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_comm_is_subject() {
        assert_eq!(legacy_classify("comm"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_exe_is_subject() {
        assert_eq!(legacy_classify("exe"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_exe_dir_is_subject() {
        assert_eq!(legacy_classify("exe_dir"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_exe_type_is_subject() {
        assert_eq!(legacy_classify("exe_type"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_gid_is_illegal_in_legacy() {
        // gid is legal in modern subject; illegal in legacy - not a split anchor.
        assert_eq!(legacy_classify("gid"), None);
    }

    #[test]
    fn legacy_classify_ppid_is_illegal_in_legacy() {
        // ppid is legal in modern subject; illegal in legacy - not a split anchor.
        assert_eq!(legacy_classify("ppid"), None);
    }

    #[test]
    fn legacy_classify_path_is_object() {
        assert_eq!(legacy_classify("path"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_device_is_object() {
        assert_eq!(legacy_classify("device"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_filehash_is_object() {
        assert_eq!(legacy_classify("filehash"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_sha256hash_is_object() {
        assert_eq!(legacy_classify("sha256hash"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_trust_is_object_in_legacy() {
        // Key variance from modern: trust is Either in modern, Object-only in legacy.
        // This locks the fix for the positional_split bug.
        assert_eq!(legacy_classify("trust"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_dir_is_object_in_legacy() {
        // Key variance from modern: dir is Either in modern, Object-only in legacy.
        assert_eq!(legacy_classify("dir"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_ftype_is_object_in_legacy() {
        // Key variance from modern: ftype is Either in modern, Object-only in legacy.
        assert_eq!(legacy_classify("ftype"), Some(AttrSide::Object));
    }

    #[test]
    fn legacy_classify_all_is_either() {
        assert_eq!(legacy_classify("all"), Some(AttrSide::Either));
    }

    #[test]
    fn legacy_classify_pattern_is_subject() {
        // pattern is subject-only in BOTH flavors: the C subject tables
        // (table1 ORIG + table2) contain PATTERN; object-attr.c does not.
        assert_eq!(legacy_classify("pattern"), Some(AttrSide::Subject));
    }

    #[test]
    fn legacy_classify_unknown_returns_none() {
        assert_eq!(legacy_classify("bogus_attr"), None);
        assert_eq!(legacy_classify(""), None);
    }

    // --- legacy_rule integration tests for dir/ftype/trust as object anchors ---

    #[test]
    fn legacy_rule_with_trust_as_object_anchor_parses() {
        // Before Task 5's fix: trust was classified as Either, so positional_split
        // could not find an object-only attribute to anchor the legacy subject/object
        // split. The rule failed to parse. After Task 5: trust is legacy-classified
        // as Object, so the split fires correctly.
        let parsed = legacy_rule()
            .parse("allow uid=0 trust=1")
            .into_result()
            .expect("legacy rule with trust as object anchor must parse");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.syntax, SyntaxFlavor::Legacy);
            assert_eq!(r.subject.len(), 1, "subject side should contain uid=0");
            assert_eq!(r.object.len(), 1, "object side should contain trust=1");
            assert!(
                matches!(&r.subject[0], Attr::Kv { key, .. } if key == "uid"),
                "subject[0] should be uid, got {:?}",
                r.subject[0]
            );
            assert!(
                matches!(&r.object[0], Attr::Kv { key, .. } if key == "trust"),
                "object[0] should be trust, got {:?}",
                r.object[0]
            );
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_with_dir_as_object_anchor_parses() {
        // dir is object-only in legacy; verify it anchors the split correctly.
        let parsed = legacy_rule()
            .parse("allow uid=0 dir=/usr")
            .into_result()
            .expect("legacy rule with dir as object anchor must parse");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.syntax, SyntaxFlavor::Legacy);
            assert!(
                matches!(&r.object[0], Attr::Kv { key, .. } if key == "dir"),
                "object[0] should be dir, got {:?}",
                r.object[0]
            );
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_with_ftype_as_object_anchor_parses() {
        // ftype is object-only in legacy; verify it anchors the split correctly.
        let parsed = legacy_rule()
            .parse("allow uid=0 ftype=application/x-executable")
            .into_result()
            .expect("legacy rule with ftype as object anchor must parse");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.syntax, SyntaxFlavor::Legacy);
            assert!(
                matches!(&r.object[0], Attr::Kv { key, .. } if key == "ftype"),
                "object[0] should be ftype, got {:?}",
                r.object[0]
            );
        } else {
            panic!("expected Rule");
        }
    }
}
