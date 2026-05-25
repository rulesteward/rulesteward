//! chumsky 0.13 combinators for the fapolicyd rule grammar.
//!
//! Two top-level productions:
//! * [`modern_rule`]  - `decision [perm=X] subj : obj`
//! * [`legacy_rule`]  - `decision [perm=X] subj... obj...` (no colon;
//!   subject/object split positionally via [`crate::attrs::classify`]).
//!
//! Plus [`set_definition`] for `%name=val1,val2`. Every named production
//! carries a `.labelled(...)` so chumsky's expected-token list surfaces
//! operator-facing names in F01 diagnostics rather than raw character
//! classes.

use chumsky::extra;
use chumsky::prelude::*;

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
use crate::attrs::{self, AttrSide};

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

fn attr_value<'a>() -> impl Parser<'a, &'a str, AttrValue, extra::Err<Rich<'a, char>>> + Clone {
    // SetRef branch is unambiguous (starts with `%`). The rest captures any
    // contiguous non-ws non-`:` slug as one token, then post-classifies it
    // via `parse::<i64>()`. Capturing-then-classifying eliminates a
    // chumsky-backtracking trap on values like `0a` where the eager int
    // combinator would consume `0` and leave `a` unparseable.
    choice((
        just('%')
            .ignore_then(ident())
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
        .map(|(((decision, perm), subject), object)| {
            Entry::Rule(Rule {
                decision,
                perm,
                subject,
                object,
                syntax: SyntaxFlavor::Modern,
                line: 0,
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
        .ignore_then(ident())
        .then_ignore(just('='))
        .then(
            set_value
                .separated_by(just(','))
                .at_least(1)
                .collect::<Vec<String>>(),
        )
        .then_ignore(ws0())
        .then_ignore(end())
        .map(|(name, values)| Entry::SetDefinition {
            name,
            values,
            line: 0,
        })
        .labelled("set definition")
}

/// Split a flat legacy-syntax attribute list into `(subject, object)` using
/// the attribute-name classifier from `attrs.rs`. The first object-only
/// attribute marks the switch point.
fn positional_split(attrs_flat: &[Attr]) -> Result<(Vec<Attr>, Vec<Attr>), String> {
    let switch_at = attrs_flat
        .iter()
        .position(|a| {
            matches!(a, Attr::Kv { key, .. } if matches!(attrs::classify(key), Some(AttrSide::Object)))
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
}
