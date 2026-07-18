//! chumsky 0.13 combinators for the fapolicyd rule grammar.
//!
//! Two top-level productions:
//! * [`modern_rule`]  - `decision [perm=X] subj : obj`
//! * [`legacy_rule`]  - `decision subj... obj...` (no colon; `perm=` is
//!   colon-format-only and is rejected here; subject/object split
//!   positionally via the internal `legacy_classify`).
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
///
/// The `.at_least(1)` is a DELIBERATE divergence: fapolicyd's `parse_set_name`
/// accepts an empty name (`%=...` yields a set literally named ""), but we
/// reject it as a near-certain typo. Do not "fix" this toward fapolicyd's
/// accept-empty behavior.
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
        .map_with(|(key, value), e| {
            // Capture the line-relative byte range of the full `key=value`
            // token. `fixup_entry` in parser/mod.rs will shift this by
            // `body_start_in_file` to make it file-relative, matching the
            // convention used for Rule.span and SetDefinition.span.
            let s = e.span();
            Attr::Kv {
                key,
                value,
                span: s.start..s.end,
            }
        });
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
        .then_ignore(ws1())
        .then(attr_list)
        .then_ignore(ws0())
        .then_ignore(end())
        .try_map(|(decision, attrs_flat), span| {
            // perm= is only valid in colon-format (modern) rules. fapolicyd
            // rules.c:957-965 gates the perm field on RULE_FMT_COLON; the
            // no-colon legacy format rejects it with
            // "ERROR: Field type (perm) is unknown in line N".
            // Reject here so the caller sees a parse=err (fapd-F01), not a
            // silent fail-open parse=ok with perm treated as an unknown attr.
            // (parser/mod.rs tries modern first and, on dual-failure, surfaces
            // the modern "expected colon" diagnostic, so this custom message is
            // a defense-in-depth label rather than the user-facing text; the
            // EFFECT - a Fatal fapd-F01 reject - is what the legacy-perm tests pin.)
            if attrs_flat
                .iter()
                .any(|a| matches!(a, Attr::Kv { key, .. } if key == "perm"))
            {
                return Err(Rich::custom(
                    span,
                    "perm= is not valid in legacy (no-colon) rules; \
                     use colon-format: decision [perm=X] subject : object",
                ));
            }
            let (subject, object) =
                positional_split(&attrs_flat).map_err(|msg| Rich::custom(span, msg))?;
            Ok(Entry::Rule(Rule {
                decision,
                perm: None,
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
        // Subject-only in legacy (`pattern` is subject-only in both flavors).
        // `exe_dir`/`exe_type` are NOT here: fapolicyd 1.3.2/1.4.3/1.4.5 all reject
        // them, so they fall through to `None` and fapd-E01 flags them (matching the
        // daemon) rather than being silently accepted as legacy anchors.
        "auid" | "uid" | "sessionid" | "pid" | "comm" | "exe" | "pattern" => {
            Some(AttrSide::Subject)
        }
        // Object-only in legacy (dir/ftype/trust differ from modern's Either)
        "path" | "device" | "filehash" | "sha256hash" | "mode" | "dir" | "ftype" | "trust" => {
            Some(AttrSide::Object)
        }
        // Valid on either side in both flavors
        "all" => Some(AttrSide::Either),
        // Unknown attribute, or legacy-illegal attrs (gid, ppid) - not a valid split anchor
        _ => None,
    }
}

/// Split a flat legacy-syntax attribute list into `(subject, object)` using
/// the legacy-specific attribute classifier, one token at a time and
/// order-INDEPENDENT (issue #546) - matching upstream fapolicyd's `nv_split`
/// (`rules.c:922-1027` v1.4.5 / `rules.c:784-892` v1.3.2): each `key=value`
/// token is classified individually via a name->side lookup with no
/// positional ordering constraint, and a legacy-illegal or unknown name (e.g.
/// `gid`) errors immediately regardless of what follows.
///
/// A bare `all` token (`Attr::All`, never `Attr::Kv` - see `attr()`'s
/// `attr_all` branch) is not itself named, so it routes by the RUNNING
/// subject/object counts at the point it is encountered, exactly like
/// upstream: subject if nothing has been classified subject yet, else object
/// if nothing has been classified object yet, else an error (both sides
/// already populated). `legacy_classify`'s `Either` case (only ever "all",
/// which the parser never produces as a `Kv`) is routed the same way for
/// defense in depth, though it is unreachable in practice.
///
/// Uses `legacy_classify` (not `attrs::classify`) so that `dir`, `ftype`, and
/// `trust` correctly serve as object-side anchors in the legacy dialect. Does
/// NOT change `legacy_classify`'s truth table.
fn positional_split(attrs_flat: &[Attr]) -> Result<(Vec<Attr>, Vec<Attr>), String> {
    let mut subject: Vec<Attr> = Vec::new();
    let mut object: Vec<Attr> = Vec::new();

    for a in attrs_flat {
        match a {
            Attr::Kv { key, .. } => match legacy_classify(key) {
                Some(AttrSide::Subject) => subject.push(a.clone()),
                Some(AttrSide::Object) => object.push(a.clone()),
                Some(AttrSide::Either) => route_by_running_count(a, &mut subject, &mut object)?,
                None => {
                    return Err(format!(
                        "legacy rule references unknown or legacy-illegal attribute `{key}`"
                    ));
                }
            },
            Attr::All => route_by_running_count(a, &mut subject, &mut object)?,
        }
    }

    if subject.is_empty() {
        return Err("legacy rule has no subject attribute".to_string());
    }
    if object.is_empty() {
        return Err("legacy rule has no object attribute".to_string());
    }
    Ok((subject, object))
}

/// Route an unnamed-side token (`Attr::All`, or in principle `Either`) to
/// whichever side is still empty, matching upstream `nv_split`'s
/// `s_count == 0` / `o_count == 0` running-count check: subject if the
/// subject side has nothing yet, else object if the object side has nothing
/// yet, else an error (both sides already populated - a case no frozen test
/// exercises, since it requires three-plus unnamed tokens in one rule).
fn route_by_running_count(
    a: &Attr,
    subject: &mut Vec<Attr>,
    object: &mut Vec<Attr>,
) -> Result<(), String> {
    if subject.is_empty() {
        subject.push(a.clone());
    } else if object.is_empty() {
        object.push(a.clone());
    } else {
        return Err(
            "legacy rule has a bare `all` attribute that cannot be classified: \
             both subject and object sides are already populated"
                .to_string(),
        );
    }
    Ok(())
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
                span: 0..0,
            },
            Attr::Kv {
                key: "path".into(),
                value: AttrValue::Str("/x".into()),
                span: 0..0,
            },
        ];
        let (subject, object) = positional_split(&attrs_flat).expect("splits");
        assert_eq!(subject.len(), 1);
        assert_eq!(object.len(), 1);
    }

    #[test]
    fn positional_split_errors_when_no_subject_attr_present_at_all() {
        // RE-GROUNDED 2026-07-17 (issue #546). This test used to be named
        // `positional_split_errors_when_object_attr_first` and its name
        // implied fapolicyd rejects a legacy rule merely because an
        // object-side attribute appears BEFORE a subject-side one
        // positionally - WRONG. Upstream fapolicyd's `nv_split`
        // (`rules.c:922-1027` v1.4.5, `rules.c:784-892` v1.3.2, cited in the
        // 2026-07-17 audit lane report Finding F2) classifies each token
        // INDEPENDENTLY via a name->side lookup with NO positional ordering
        // constraint at all: `allow mode=0755 uid=0` (object-attr `mode`
        // BEFORE subject-attr `uid`) loads clean on both live daemon
        // versions (reproduced 2026-07-17 05:01-05:02 UTC; see
        // `positional_split_classifies_object_first_order_independent`
        // below, which is the actual regression test for that claim). What
        // THIS fixture still correctly pins - the only part of the old test
        // that survives the order-independence fix - is that a legacy attr
        // list with NO subject-side attribute ANYWHERE (not merely "object
        // first") has nothing to assign to the subject side and must still
        // error, matching upstream's `finish_up` "Subject is missing" check
        // (`rules.c` ~1016-1026, already cited in the audit's Finding F1
        // evidence for the modern grammar's equivalent check).
        let attrs_flat = vec![Attr::Kv {
            key: "path".into(),
            value: AttrValue::Str("/x".into()),
            span: 0..0,
        }];
        assert!(
            positional_split(&attrs_flat).is_err(),
            "a legacy attr list with only an object-side attr (no subject \
             attr at all) must still error, independent of ordering"
        );
    }

    #[test]
    fn positional_split_classifies_object_first_order_independent() {
        // The actual #546 regression. `mode` (object-only) appears BEFORE
        // `uid` (subject-only). Grounded exactly as above: `nv_split` has no
        // positional constraint, and the live daemon loads
        // `allow mode=0755 uid=0` clean on both fapolicyd 1.3.2 and 1.4.5
        // (audit lane report 2026-07-17 Finding F2).
        //
        // Today: `positional_split`'s `.position()` search finds `mode` (the
        // first Object-classified attr) at index 0, so
        // `subject = attrs_flat[..0]` is EMPTY -> errors "legacy rule has no
        // subject attributes before the object split" - RED (a daemon-valid
        // rule is wrongly rejected as fapd-F01 Fatal).
        let attrs_flat = vec![
            Attr::Kv {
                key: "mode".into(),
                value: AttrValue::Str("0755".into()),
                span: 0..0,
            },
            Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
                span: 0..0,
            },
        ];
        let (subject, object) = positional_split(&attrs_flat).expect(
            "legacy split must be order-independent per nv_split; \
             mode-before-uid must still split correctly (#546)",
        );
        assert_eq!(
            subject.len(),
            1,
            "subject must contain only uid; got {subject:?}"
        );
        assert!(matches!(&subject[0], Attr::Kv { key, .. } if key == "uid"));
        assert_eq!(
            object.len(),
            1,
            "object must contain only mode; got {object:?}"
        );
        assert!(matches!(&object[0], Attr::Kv { key, .. } if key == "mode"));
    }

    // --- bare `all` placement corollary (#546 F2, resolves the audit's
    // [UNVERIFIED] item). Grounded 2026-07-17 via a direct fetch of
    // raw.githubusercontent.com/linux-application-whitelisting/fapolicyd/
    // v1.4.5/src/library/rules.c: a bare `all` token is NOT classified by
    // subj_name_to_val/obj_name_to_val at all - it is routed by the RUNNING
    // s_count/o_count at the point it is encountered:
    //   } else if (strcmp(ptr, "all") == 0) {
    //       if (n->s_count == 0) { type = ALL_SUBJ; assign_subject(...); }
    //       else if (n->o_count == 0) { type = ALL_OBJ; assign_object(...); }
    // This matches the audit's own citation (rules.c:997-1008) for the same
    // s_count==0-then-subject / o_count==0-then-object rule.

    #[test]
    fn positional_split_all_after_a_subject_attr_becomes_object_side() {
        // After `uid=0` has already been classified subject (s_count=1), a
        // later bare `all` token has s_count!=0, so it falls to the
        // o_count==0 branch and becomes the OBJECT side.
        //
        // Today: `positional_split`'s Object-anchor search only matches
        // `Attr::Kv` (the `matches!(a, Attr::Kv { .. } if ...)` guard above),
        // so a bare `Attr::All` can NEVER be the switch anchor; with `all` as
        // the only Object-shaped candidate here, no anchor is found at all
        // and the whole split errors "no object-only attribute to split on"
        // - RED (a daemon-valid rule is wrongly rejected).
        let attrs_flat = vec![
            Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
                span: 0..0,
            },
            Attr::All,
        ];
        let (subject, object) = positional_split(&attrs_flat).expect(
            "`uid=0 all` must split: uid->subject, then all \
             (s_count!=0, o_count==0)->object (#546 corollary)",
        );
        assert_eq!(
            subject,
            vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
                span: 0..0,
            }]
        );
        assert_eq!(object, vec![Attr::All]);
    }

    #[test]
    fn positional_split_all_before_a_subject_attr_both_go_subject_and_split_errors() {
        // Companion control (same grounding as above): when `all` appears
        // FIRST, s_count==0 at that point, so `all` itself becomes SUBJECT
        // (ALL_SUBJ). The following `uid=0` is independently subject-
        // classified too, so the whole rule ends with s_count=2, o_count=0 -
        // upstream's `finish_up` rejects it ("Object is missing in line N",
        // `rules.c` ~1016-1026, already cited in Finding F2).
        //
        // Today's `positional_split` ALSO errors here (coincidentally, for
        // the unrelated "no Kv-classified object anchor found" reason,
        // since `Attr::All` is invisible to its anchor search) - this must
        // remain an error after the fix too. Pinning control, not RED.
        let attrs_flat = vec![
            Attr::All,
            Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
                span: 0..0,
            },
        ];
        let err = positional_split(&attrs_flat).expect_err(
            "`all uid=0` must still fail: both tokens route to subject (all: \
             s_count==0; uid: subject-only), leaving zero object attrs - \
             matching upstream's 'Object is missing' rejection",
        );
        // Adversarial review Concern 5: pin the ROUTING REASON, not just
        // is_err(), so a wrong impl that rejects this input for the WRONG
        // reason (e.g. reports a missing-subject error, or a generic
        // parse-failure unrelated to the object side) is still caught. Every
        // existing error message in this module already names "subject" or
        // "object" explicitly (see the sibling messages above), so this is a
        // structural pin, not a hardcoded exact-string match.
        assert!(
            err.to_lowercase().contains("object"),
            "the rejection reason must name the OBJECT side as missing (both \
             `all` and `uid` classify subject, leaving object empty), not \
             some other cause; got error: {err:?}"
        );
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
    fn legacy_classify_exe_dir_and_exe_type_are_subject_anchors() {
        // RE-GROUNDED (ATL round 2 MISS 2, 2026-07-18). The prior version of
        // this test (`legacy_classify_exe_dir_and_exe_type_are_not_anchors`)
        // asserted `None`, citing "1.3.2/1.4.3/1.4.5 all reject
        // exe_dir/exe_type" (differential 2026-06-01) - that differential
        // tested ONLY the MODERN (colon) grammar. Upstream fapolicyd's
        // `subject-attr.c` table1 (the LEGACY/ORIG-format subject attribute
        // table) DOES list `EXE_DIR`/`EXE_TYPE` in BOTH 1.3.2 and 1.4.5;
        // they are unknown ONLY to the separate MODERN table (table2),
        // which is what `attrs::classify`/`attrs::SUBJECT_ONLY` correctly
        // models (that removal from `SUBJECT_ONLY` on 2026-05-29 stays
        // correct and is NOT touched here - see attrs.rs's refreshed note).
        //
        // Live-verified 2026-07-18 on BOTH fapolicyd 1.3.2 and 1.4.5:
        //   LEGACY `allow exe_dir=/usr/bin/ trust=1` -> "Loaded 1 rules"
        //     (clean) on both versions.
        //   LEGACY `allow exe_type=application/x-executable trust=1` ->
        //     "Loaded 1 rules" (clean) on both versions.
        //   MODERN `allow exe_dir=/usr/bin/ : all` -> "Field type (exe_dir)
        //     is unknown in line 2" on both versions (unaffected by this
        //     change - modern still goes through `attrs::classify`, not
        //     `legacy_classify`).
        //
        // `legacy_classify` must therefore route `exe_dir`/`exe_type` to
        // `Subject`, matching upstream `subj_name_to_val(ptr, RULE_FMT_ORIG)`.
        // Today (pre-fix) `legacy_classify` still returns `None` for both,
        // which makes the landed per-token `positional_split` (issue #546)
        // reject this daemon-VALID legacy rule outright as fapd-F01 Fatal -
        // a NEW false-positive introduced by the #546 fix (pre-#546 it
        // merely mis-warned via a different path). RED until
        // `legacy_classify` gains these two `Subject` entries.
        assert_eq!(legacy_classify("exe_dir"), Some(AttrSide::Subject));
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
    fn legacy_classify_mode_is_object() {
        // `mode` is an OBJECT-only attribute (differential 2026-06-01); in the
        // legacy (no-colon) dialect it serves as an object-side split anchor like
        // path/device.
        assert_eq!(legacy_classify("mode"), Some(AttrSide::Object));
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

    // --- legacy_rule() order-independence integration tests (issue #546) ---

    #[test]
    fn legacy_rule_mode_before_uid_order_independent() {
        // #546 Finding F2 (grounded, audit lane report 2026-07-17): `allow
        // mode=0755 uid=0` loads cleanly on live fapolicyd 1.3.2 and 1.4.5
        // even though the OBJECT-only `mode` attr appears BEFORE the
        // SUBJECT-only `uid` attr. Upstream `nv_split` classifies each token
        // independently (subj_name_to_val then obj_name_to_val,
        // `rules.c:922-1027` v1.4.5 / `:784-892` v1.3.2) with no ordering
        // constraint at all.
        //
        // Today: `positional_split` finds `mode` (the first Object-
        // classified attr) at index 0, so `subject = attrs_flat[..0]` is
        // empty -> errors "legacy rule has no subject attributes before the
        // object split" - RED (this daemon-valid rule fails to parse at all
        // today, surfacing as fapd-F01 Fatal).
        let parsed = legacy_rule()
            .parse("allow mode=0755 uid=0")
            .into_result()
            .expect("daemon-valid order-independent legacy rule must parse (#546)");
        if let Entry::Rule(r) = parsed {
            assert_eq!(r.subject.len(), 1, "subject must contain only uid");
            assert!(matches!(&r.subject[0], Attr::Kv { key, .. } if key == "uid"));
            assert_eq!(r.object.len(), 1, "object must contain only mode");
            assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "mode"));
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_interleaved_comm_trust_uid_classifies_each_token_independently() {
        // A THIRD attribute after the object anchor must not be swept into
        // the object bucket just because of its position. `comm` (subject-
        // only, legacy_classify_comm_is_subject) and `uid` (subject-only,
        // legacy_classify_uid_is_subject) sandwich `trust` (object-only-in-
        // legacy, legacy_classify_trust_is_object_in_legacy). Grounded by
        // composing two already-differential-grounded per-attribute
        // classifications with the general order-independence fact
        // (`nv_split`, same citation as above): if both per-attribute
        // classifications are correct AND classification is truly order-
        // independent, `uid` (appearing textually AFTER the object anchor
        // `trust`) must still land in subject, not object.
        //
        // Today: `positional_split` finds `trust` (the first Object-
        // classified attr) at index 1; subject = attrs[..1] = [comm];
        // object = attrs[1..] = [trust, uid] - `uid` is SILENTLY
        // misclassified into the object bucket. No error is raised at all
        // here, so this bug is invisible without an exact assertion on the
        // split contents - RED.
        let parsed = legacy_rule()
            .parse("allow comm=bash trust=1 uid=0")
            .into_result()
            .expect("legacy rule parses (positional_split never errors on this input)");
        if let Entry::Rule(r) = parsed {
            assert_eq!(
                r.subject.len(),
                2,
                "subject must contain comm AND uid, not just comm; got {:?}",
                r.subject
            );
            let subj_keys: Vec<&str> = r
                .subject
                .iter()
                .map(|a| match a {
                    Attr::Kv { key, .. } => key.as_str(),
                    Attr::All => "all",
                })
                .collect();
            assert!(subj_keys.contains(&"comm"), "got subject={subj_keys:?}");
            assert!(
                subj_keys.contains(&"uid"),
                "uid must be classified subject despite following the object \
                 anchor `trust` positionally; got subject={subj_keys:?}"
            );
            assert_eq!(r.object.len(), 1, "object must contain only trust");
            assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "trust"));
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_filehash_before_two_subject_attrs_order_independent() {
        // Same class of bug as `mode=0755 uid=0` (outright split failure)
        // but with a different object-anchor attribute (`filehash`, legacy-
        // object per legacy_classify_filehash_is_object) and TWO trailing
        // subject attrs (`uid`, `auid` - both legacy_classify_*_is_subject-
        // grounded) to confirm the fix handles more than a single trailing
        // subject token.
        let parsed = legacy_rule()
            .parse("allow filehash=deadbeef uid=0 auid=1000")
            .into_result()
            .expect("daemon-valid order-independent legacy rule must parse (#546)");
        if let Entry::Rule(r) = parsed {
            assert_eq!(
                r.subject.len(),
                2,
                "subject must contain uid and auid; got {:?}",
                r.subject
            );
            assert_eq!(
                r.object.len(),
                1,
                "object must contain only filehash; got {:?}",
                r.object
            );
            assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "filehash"));
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn legacy_rule_rejects_legacy_illegal_attr_even_with_a_valid_object_anchor() {
        // Negative control (#546 task item (c)): `gid` is legacy-illegal
        // (legacy_classify_gid_is_illegal_in_legacy, grounded in
        // R2-audit-grammar.md per this file's own module doc: "gid, ppid
        // are illegal on the legacy subject side... NOT valid split
        // anchors"). Matches upstream nv_split: a token unrecognized by BOTH
        // subj_name_to_val(format=ORIG) and obj_name_to_val immediately
        // errors ("Field type (gid) is unknown", return 3) - regardless of
        // whether a LATER token supplies a valid object anchor.
        //
        // Today: `positional_split`'s ONLY validity check is "does an
        // object-only Attr::Kv anchor exist anywhere" - `path` supplies that
        // anchor at index 2, so `gid` silently rides along in the subject
        // bucket with NO rejection at all. RED: this daemon-invalid rule
        // parses cleanly today.
        let result = legacy_rule()
            .parse("allow gid=100 uid=0 path=/bin/sh")
            .into_result();
        assert!(
            result.is_err(),
            "gid= is illegal in the legacy dialect and must reject the WHOLE \
             rule, even though `path` supplies a valid object anchor; \
             got {result:?}"
        );
    }
}
