//! fapolicyd rule evaluator - pure, side-effect-free.
//!
//! `evaluate` walks a load-ordered `&[Rule]` (first-match wins,
//! policy.c:1126-1134) and returns a `Verdict`. No IO, no filesystem access,
//! no daemon contact.
//!
//! The match semantics mirror §1 of
//! `.private-docs/f1-fapolicyd-simulate-explain-grounding.md` exactly.
//! Every comment below cites the upstream fapolicyd C source (HEAD 5a95ca2).
//!
//! Filled by Phase-0 Task P0.4 (issue #67).

use crate::ast::{Attr, AttrValue, Decision, Perm, Rule};
use crate::facts::{AccessFacts, FieldEval, RuleOutcome, SetTable, Trust};

// ---------------------------------------------------------------------------
// Verdict / Source
// ---------------------------------------------------------------------------

/// The outcome of walking the full ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The matched rule's decision, or `Allow` when the ruleset fell through
    /// (policy.c:1164: `else decision = ALLOW`).
    pub decision: Decision,
    /// 1-based rule number of the decisive rule, or `None` on fallthrough.
    pub matched_rule: Option<usize>,
    /// How the verdict was produced.
    pub source: Source,
    /// When a `PossibleMatch` rule appeared BEFORE the decisive rule, this
    /// carries a human-readable reason explaining which unevaluable construct
    /// was responsible (f1 §2.3, §5.1(g)).
    pub uncertain: Option<String>,
}

/// How a `Verdict` was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A decisive rule matched.
    Rule,
    /// No rule matched; the implicit fallthrough-Allow applies
    /// (policy.c:1164).
    Fallthrough,
}

// ---------------------------------------------------------------------------
// execdirs / systemdirs constants
// ---------------------------------------------------------------------------

/// `execdirs` prefix list from `check_dirs` / `dirs[]` in upstream
/// `src/library/rules.c`. Used for `dir=execdirs` / `odir=execdirs` matching.
/// (f1 §1.4, fapolicyd.rules.5)
const EXECDIRS: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/libexec/",
];

/// `systemdirs` = `execdirs` plus `/etc/`.
/// (f1 §1.4, fapolicyd.rules.5)
const SYSTEMDIRS: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/libexec/",
    "/etc/",
];

// ---------------------------------------------------------------------------
// Internal: perm check
// ---------------------------------------------------------------------------

/// `check_access` (rules.c:1340-1353): does the rule's perm match the event?
/// `None` means "no perm specified" -> defaults to `open` (man page:
/// "If none are given, then open is assumed").
fn check_access(rule_perm: Option<Perm>, facts_perm: Perm) -> bool {
    let rule_perm = rule_perm.unwrap_or(Perm::Open);
    match rule_perm {
        Perm::Any => true,
        Perm::Open => facts_perm == Perm::Open || facts_perm == Perm::Any,
        Perm::Execute => facts_perm == Perm::Execute || facts_perm == Perm::Any,
    }
}

// ---------------------------------------------------------------------------
// Internal: string set membership helpers
// ---------------------------------------------------------------------------

/// Collect the literal string values from an `AttrValue`.
/// For `Str(s)` returns a single-element slice; for `Int` / `SetRef` handled
/// separately; returns `None` when the value is not a bare string literal.
fn as_str_literal(value: &AttrValue) -> Option<&str> {
    match value {
        AttrValue::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Exact string membership: `fact_value` must appear in `rule_set`.
///
/// Handles both `AttrValue::Str` (single literal) and `AttrValue::SetRef`
/// (resolved against `sets`). Returns `NoMatch` when the set is undefined
/// (consistent with fapd-E03: an undefined set is a load-time error, but the
/// evaluator is lenient here to avoid crashing on ill-formed inputs).
fn exact_string_match(fact_value: &str, rule_value: &AttrValue, sets: &SetTable) -> FieldEval {
    match rule_value {
        AttrValue::Str(s) => {
            if s == fact_value {
                FieldEval::Match
            } else {
                FieldEval::NoMatch
            }
        }
        AttrValue::SetRef(name) => match sets.get(name) {
            Some(members) => {
                if members.iter().any(|m| m == fact_value) {
                    FieldEval::Match
                } else {
                    FieldEval::NoMatch
                }
            }
            None => FieldEval::NoMatch,
        },
        AttrValue::Int(_) => FieldEval::NoMatch,
    }
}

/// Integer set membership for uid/gid/auid/sessionid/pid/ppid.
/// The rule value may be `Int(n)` (single literal) or `SetRef` (resolved).
fn int_set_contains(fact_val_i64: i64, rule_value: &AttrValue, sets: &SetTable) -> bool {
    match rule_value {
        AttrValue::Int(n) => *n == fact_val_i64,
        AttrValue::SetRef(name) => match sets.get(name) {
            Some(members) => members
                .iter()
                .any(|m| m.parse::<i64>().ok().is_some_and(|n| n == fact_val_i64)),
            None => false,
        },
        AttrValue::Str(s) => {
            // A string literal like "0" or a name - try numeric parse first.
            s.parse::<i64>().ok().is_some_and(|n| n == fact_val_i64)
        }
    }
}

/// PREFIX match (`attr_set_check_pstr`, rules.c:412-446): the fact path matches
/// if ANY entry in `rule_value` is a strncmp-prefix of `fact_path`.
fn prefix_string_match(fact_path: &str, rule_value: &AttrValue, sets: &SetTable) -> FieldEval {
    let prefixes: Vec<&str> = match rule_value {
        AttrValue::Str(s) => {
            // Special keyword handling for execdirs / systemdirs
            match s.as_str() {
                "execdirs" => return prefix_from_list(fact_path, EXECDIRS),
                "systemdirs" => return prefix_from_list(fact_path, SYSTEMDIRS),
                // `untrusted` at this layer cannot be resolved statically
                // (requires trust DB); treat as NotEvaluable.
                "untrusted" => return FieldEval::NotEvaluable,
                other => vec![other],
            }
        }
        AttrValue::SetRef(name) => match sets.get(name) {
            Some(members) => {
                // Check for keywords inside a set
                for m in members {
                    if m == "execdirs" {
                        if prefix_from_list(fact_path, EXECDIRS) == FieldEval::Match {
                            return FieldEval::Match;
                        }
                    } else if m == "systemdirs" {
                        if prefix_from_list(fact_path, SYSTEMDIRS) == FieldEval::Match {
                            return FieldEval::Match;
                        }
                    } else if fact_path.starts_with(m.as_str()) {
                        return FieldEval::Match;
                    }
                }
                return FieldEval::NoMatch;
            }
            None => return FieldEval::NoMatch,
        },
        AttrValue::Int(_) => return FieldEval::NoMatch,
    };
    // Plain string literal (already expanded from the Str arm above)
    for prefix in prefixes {
        if fact_path.starts_with(prefix) {
            return FieldEval::Match;
        }
    }
    FieldEval::NoMatch
}

fn prefix_from_list(fact_path: &str, list: &[&str]) -> FieldEval {
    if list.iter().any(|prefix| fact_path.starts_with(*prefix)) {
        FieldEval::Match
    } else {
        FieldEval::NoMatch
    }
}

// ---------------------------------------------------------------------------
// Internal: uid/gid intersection helpers
// ---------------------------------------------------------------------------

/// `avl_intersection`-style uid match (rules.c:1391-1402): any fact uid in
/// the rule's uid set matches. Returns `FieldEval::Match` on any overlap.
fn uid_intersection_match(fact_uids: &[u32], rule_value: &AttrValue, sets: &SetTable) -> FieldEval {
    if fact_uids.is_empty() {
        // Absent fact: widen (rules.c:1376-1379).
        return FieldEval::Match;
    }
    for &fact_uid in fact_uids {
        if int_set_contains(i64::from(fact_uid), rule_value, sets) {
            return FieldEval::Match;
        }
    }
    FieldEval::NoMatch
}

/// gid intersection match (rules.c:1413-1417): any fact gid in the rule's gid set.
fn gid_intersection_match(fact_gids: &[u32], rule_value: &AttrValue, sets: &SetTable) -> FieldEval {
    if fact_gids.is_empty() {
        return FieldEval::Match;
    }
    for &fact_gid in fact_gids {
        if int_set_contains(i64::from(fact_gid), rule_value, sets) {
            return FieldEval::Match;
        }
    }
    FieldEval::NoMatch
}

// ---------------------------------------------------------------------------
// Internal: subject / object field evaluation
// ---------------------------------------------------------------------------

/// Evaluate an optional integer fact field against the rule value.
/// `None` means "fact absent" and widens (Match); `Some(v)` does a
/// set-membership check via `int_set_contains`.
fn eval_optional_int<T: Into<i64> + Copy>(
    fact: Option<T>,
    value: &AttrValue,
    sets: &SetTable,
) -> FieldEval {
    match fact {
        None => FieldEval::Match, // absent fact widens (rules.c:1376-1379)
        Some(v) => {
            if int_set_contains(v.into(), value, sets) {
                FieldEval::Match
            } else {
                FieldEval::NoMatch
            }
        }
    }
}

/// Evaluate trust field match for a given `Trust` value and rule `AttrValue`.
fn eval_trust_field(
    trust: Trust,
    value: &AttrValue,
    unknown_reason: &str,
) -> (FieldEval, Option<String>) {
    match trust {
        Trust::Unknown => (FieldEval::NotEvaluable, Some(unknown_reason.to_string())),
        Trust::Yes => {
            let fe = if as_str_literal(value).is_some_and(|s| s == "1")
                || matches!(value, AttrValue::Int(1))
            {
                FieldEval::Match
            } else {
                FieldEval::NoMatch
            };
            (fe, None)
        }
        Trust::No => {
            let fe = if as_str_literal(value).is_some_and(|s| s == "0")
                || matches!(value, AttrValue::Int(0))
            {
                FieldEval::Match
            } else {
                FieldEval::NoMatch
            };
            (fe, None)
        }
    }
}

/// Evaluate one subject-side attribute against the facts.
/// Returns `(FieldEval, Option<reason_string>)` where the reason is non-None
/// only for `NotEvaluable` cases.
fn eval_subject_field(
    key: &str,
    value: &AttrValue,
    sets: &SetTable,
    facts: &AccessFacts,
) -> (FieldEval, Option<String>) {
    match key {
        "uid" => (uid_intersection_match(&facts.uids, value, sets), None),
        "gid" => (gid_intersection_match(&facts.gids, value, sets), None),
        "auid" => (eval_optional_int(facts.auid, value, sets), None),
        "sessionid" => (eval_optional_int(facts.sessionid, value, sets), None),
        "pid" => (eval_optional_int(facts.pid, value, sets), None),
        "ppid" => (eval_optional_int(facts.ppid, value, sets), None),
        "exe" => match as_str_literal(value) {
            // #126: `exe=untrusted` is a TRUST MACRO - real fapolicyd has NO
            // symmetric `trusted` macro; only `untrusted` is special in the EXE
            // case (f1 grounding §1.4 ~line 164; upstream rules.c:1443-1463; live
            // fapolicyd 1.4.5). The macro evaluates against the SUBJECT trust
            // state, NOT the exe path. Reuse `eval_trust_field` so the
            // NotEvaluable/Match/NoMatch return shape (and the simulate confidence
            // downgrade on Unknown trust) matches the `trust=` arm exactly:
            //   - `untrusted` is equivalent to `trust=0` (match iff Trust::No)
            // `exe=trusted` is NOT a macro: it falls through to the literal
            // exe-path compare below (it matches only if the exe path is literally
            // the string "trusted", essentially never for a real path).
            Some("untrusted") => eval_trust_field(
                facts.subj_trust,
                &AttrValue::Int(0),
                "subj trust unknown (no trust DB)",
            ),
            // Any other value (incl. the literal "trusted", or a non-literal
            // SetRef/Int): literal exe path match.
            _ => match &facts.exe {
                None => (FieldEval::Match, None),
                Some(exe_path) => (exact_string_match(exe_path, value, sets), None),
            },
        },
        "comm" => match &facts.comm {
            None => (FieldEval::Match, None),
            Some(comm_val) => (exact_string_match(comm_val, value, sets), None),
        },
        "dir" => match &facts.exe {
            // Subject dir= matches against the exe path using prefix semantics.
            None => (FieldEval::Match, None), // absent exe widens
            Some(exe_path) => (prefix_string_match(exe_path, value, sets), None),
        },
        "pattern" => {
            // `pattern=` is a runtime ELF-access-pattern detector; cannot be
            // statically evaluated (f1 §2.3).
            let reason = match value {
                AttrValue::Str(s) => format!("pattern={s} is a runtime-only construct"),
                _ => "pattern= is a runtime-only construct".to_string(),
            };
            (FieldEval::NotEvaluable, Some(reason))
        }
        "trust" => eval_trust_field(facts.subj_trust, value, "subj trust unknown (no trust DB)"),
        // Any unknown attribute key: skip (widening) rather than crashing.
        _ => (FieldEval::Match, None),
    }
}

/// Evaluate one object-side attribute against the facts.
fn eval_object_field(
    key: &str,
    value: &AttrValue,
    sets: &SetTable,
    facts: &AccessFacts,
) -> (FieldEval, Option<String>) {
    match key {
        "path" => match &facts.path {
            None => (FieldEval::Match, None),
            Some(p) => (exact_string_match(p, value, sets), None),
        },
        "device" => match &facts.device {
            None => (FieldEval::Match, None),
            Some(d) => (exact_string_match(d, value, sets), None),
        },
        "sha256hash" | "filehash" => match &facts.sha256 {
            // #127: the object is PRESENT on disk but its hash could NOT be
            // computed (e.g. EACCES). FILE_HASH treats a hash-lookup error as a
            // denial (rules.c:1606-1611: "Treat errors as denial for file hash
            // lookups" -> `return 0`), so the constraint is `NoMatch` - DISTINCT
            // from object-absent. Pinned by
            // `filehash_present_but_unhashable_is_denied_not_widened`.
            None if facts.sha256_unhashable => (FieldEval::NoMatch, None),
            // Object ABSENT (no hash, not flagged unhashable): widen (skip), the
            // standard absent-fact behavior (rules.c:1572-1575).
            None => (FieldEval::Match, None),
            Some(h) => (exact_string_match(h, value, sets), None),
        },
        "ftype" => match &facts.ftype {
            None => {
                // ftype is absent / not statically known -> NotEvaluable (f1 §2.3).
                let reason = match value {
                    AttrValue::Str(s) if s == "any" => return (FieldEval::Match, None),
                    AttrValue::Str(s) => {
                        format!("ftype={s} cannot be evaluated without libmagic")
                    }
                    _ => "ftype cannot be statically evaluated".to_string(),
                };
                (FieldEval::NotEvaluable, Some(reason))
            }
            Some(ft) => {
                // ftype=any always matches (rules.c:1587-1591).
                let fe = match value {
                    AttrValue::Str(s) if s == "any" => FieldEval::Match,
                    _ => exact_string_match(ft, value, sets),
                };
                (fe, None)
            }
        },
        "dir" => {
            // Object odir= uses prefix match against the object path.
            match &facts.path {
                None => (FieldEval::Match, None),
                Some(p) => (prefix_string_match(p, value, sets), None),
            }
        }
        "trust" => eval_trust_field(facts.obj_trust, value, "obj trust unknown (no trust DB)"),
        _ => (FieldEval::Match, None),
    }
}

// ---------------------------------------------------------------------------
// Internal: evaluate one rule
// ---------------------------------------------------------------------------

/// Evaluate one rule against the facts. Returns `RuleOutcome` and, when the
/// outcome is `PossibleMatch`, a string describing the unevaluable construct.
fn eval_rule(rule: &Rule, sets: &SetTable, facts: &AccessFacts) -> (RuleOutcome, Option<String>) {
    // check_access (rules.c:1340-1353)
    if !check_access(rule.perm, facts.perm) {
        return (RuleOutcome::NoMatch, None);
    }

    let mut possible_reason: Option<String> = None;

    // check_subject: all subject attrs AND'ed (rules.c:1381-1517).
    for attr in &rule.subject {
        match attr {
            Attr::All => {
                // `all` on subject side always matches.
            }
            Attr::Kv { key, value, .. } => {
                let (fe, reason) = eval_subject_field(key, value, sets, facts);
                match fe {
                    FieldEval::Match => {}
                    FieldEval::NoMatch => return (RuleOutcome::NoMatch, None),
                    FieldEval::NotEvaluable => {
                        if possible_reason.is_none() {
                            possible_reason = reason;
                        }
                    }
                }
            }
        }
    }

    // check_object: all object attrs AND'ed (rules.c:1577-1664).
    for attr in &rule.object {
        match attr {
            Attr::All => {
                // `all` on object side always matches.
            }
            Attr::Kv { key, value, .. } => {
                let (fe, reason) = eval_object_field(key, value, sets, facts);
                match fe {
                    FieldEval::Match => {}
                    FieldEval::NoMatch => return (RuleOutcome::NoMatch, None),
                    FieldEval::NotEvaluable => {
                        if possible_reason.is_none() {
                            possible_reason = reason;
                        }
                    }
                }
            }
        }
    }

    if possible_reason.is_some() {
        (RuleOutcome::PossibleMatch, possible_reason)
    } else {
        (RuleOutcome::Decisive(rule.decision), None)
    }
}

// ---------------------------------------------------------------------------
// Public: evaluate
// ---------------------------------------------------------------------------

/// Walk the load-ordered rule slice and return a `Verdict`.
///
/// Implements the fapolicyd match loop from `process_event_with_source()`
/// (policy.c:1126-1164):
/// - First-match wins (policy.c:1126-1134).
/// - Fallthrough defaults to `Allow` (policy.c:1164).
/// - A `PossibleMatch` before the decisive rule is recorded in
///   `Verdict::uncertain`.
///
/// `rules` should contain only `Entry::Rule` items extracted from the parsed
/// `Vec<Entry>`. Pass a `SetTable` built from the same `Vec<Entry>` to ensure
/// `%set` references resolve correctly.
#[must_use]
pub fn evaluate(rules: &[Rule], sets: &SetTable, facts: &AccessFacts) -> Verdict {
    let mut uncertain: Option<String> = None;

    for (idx, rule) in rules.iter().enumerate() {
        let (outcome, reason) = eval_rule(rule, sets, facts);
        match outcome {
            RuleOutcome::Decisive(decision) => {
                return Verdict {
                    decision,
                    matched_rule: Some(idx + 1), // 1-based (policy.c:1155)
                    source: Source::Rule,
                    uncertain,
                };
            }
            RuleOutcome::PossibleMatch => {
                // Record the first unevaluable reason, keep walking.
                if uncertain.is_none() {
                    let rule_num = idx + 1;
                    let base = reason.unwrap_or_else(|| "unevaluable construct".to_string());
                    uncertain = Some(format!("possible match at rule {rule_num}: {base}"));
                }
            }
            RuleOutcome::NoMatch => {
                // This rule does not match; continue to the next.
            }
        }
    }

    // Fallthrough: policy.c:1164 `else decision = ALLOW`
    Verdict {
        decision: Decision::Allow,
        matched_rule: None,
        source: Source::Fallthrough,
        uncertain,
    }
}

// ---------------------------------------------------------------------------
// Tests (RED written first, then impl made them GREEN)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
    use crate::facts::{AccessFacts, SetTable};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn span() -> std::ops::Range<usize> {
        0..0
    }

    fn kv(key: &str, value: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Str(value.to_string()),
            span: span(),
        }
    }

    fn kv_int(key: &str, n: i64) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Int(n),
            span: span(),
        }
    }

    fn kv_ref(key: &str, set: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::SetRef(set.to_string()),
            span: span(),
        }
    }

    fn rule(decision: Decision, perm: Option<Perm>, subj: Vec<Attr>, obj: Vec<Attr>) -> Rule {
        Rule {
            decision,
            perm,
            subject: subj,
            object: obj,
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: rulesteward_core::span(0, 0),
        }
    }

    fn set_def(name: &str, values: &[&str]) -> Entry {
        Entry::SetDefinition {
            name: name.to_string(),
            values: values.iter().map(ToString::to_string).collect(),
            line: 1,
            span: rulesteward_core::span(0, 0),
        }
    }

    fn empty_sets() -> SetTable {
        SetTable::default()
    }

    // -----------------------------------------------------------------------
    // Mutation-hardening: the ftype=any absent-fact path + uncertain reason
    // text (kills the 6 evaluate.rs survivors the P0.4 mutation gate found).
    // -----------------------------------------------------------------------

    /// `ftype=any` matches even when the file type is statically unknown
    /// (facts.ftype absent): the rule is DECISIVE, not uncertain. Pins the
    /// `s == "any"` special-case guard in the absent-ftype branch
    /// (rules.c:1587-1591). Kills the `s == "any" -> false/!=` mutants.
    #[test]
    fn ftype_any_matches_when_facts_ftype_absent() {
        // deny perm=any all : ftype=any   (facts carry NO ftype -> None)
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("ftype", "any")],
        )];
        let facts = AccessFacts::new(Perm::Open); // ftype defaults to None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "ftype=any must MATCH an absent file type (any matches everything)"
        );
        assert_eq!(v.matched_rule, Some(1));
        assert!(
            v.uncertain.is_none(),
            "ftype=any against an absent ftype is decisive, not uncertain: {:?}",
            v.uncertain
        );
    }

    /// A non-`any` ftype against an absent file type is NOT statically evaluable
    /// -> the rule is a POSSIBLE (uncertain) match, never decisive. Contrast to
    /// the test above: together they pin the `s == "any"` guard (value + ==).
    /// The reason text must name the specific ftype value (kills the `Str(s)`
    /// reason-text arm mutant), and the message must carry the 1-based rule
    /// number (kills the `idx + 1 -> idx * 1` mutant).
    #[test]
    fn ftype_specific_is_uncertain_when_facts_ftype_absent() {
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv("ftype", "sysfs_t")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];
        let facts = AccessFacts::new(Perm::Open); // ftype = None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(v.decision, Decision::Allow, "the all:all rule decides");
        assert_eq!(v.matched_rule, Some(2));
        let reason = v
            .uncertain
            .as_deref()
            .expect("a specific ftype against an absent file type is uncertain");
        assert!(
            reason.contains("sysfs_t"),
            "the uncertain reason must name the specific ftype value: {reason}"
        );
        assert!(
            reason.contains("rule 1"),
            "the uncertain reason must carry the 1-based rule number of the possible match: {reason}"
        );
    }

    /// The `pattern=` uncertain reason names the specific pattern value (kills
    /// the `Str(s)` reason-text arm mutant in `eval_subject_field`).
    #[test]
    fn pattern_uncertain_reason_names_the_pattern_value() {
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv("pattern", "ld_so")],
                vec![Attr::All],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];
        let facts = AccessFacts::new(Perm::Open);
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(v.decision, Decision::Allow);
        let reason = v.uncertain.as_deref().expect("pattern= is uncertain");
        assert!(
            reason.contains("ld_so"),
            "the uncertain reason must name the specific pattern value: {reason}"
        );
    }

    // -----------------------------------------------------------------------
    // Mutation-hardening: the matcher-primitive boundaries (int_set_contains +
    // prefix_string_match SetRef/keyword paths - kills the `== -> !=` survivors).
    // -----------------------------------------------------------------------

    /// `uid=%set` resolves to numeric membership: a fact uid IN the set matches,
    /// one NOT in it does not. Kills the `n == fact_val` -> `!=` mutant in the
    /// `SetRef` arm of `int_set_contains`.
    #[test]
    fn uid_setref_numeric_membership_matches_and_rejects() {
        let sets = SetTable::from_entries(&[set_def("admins", &["0", "1000"])]);
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_ref("uid", "admins")],
            vec![Attr::All],
        )];
        let mut in_set = AccessFacts::new(Perm::Open);
        in_set.uids = vec![1000];
        assert_eq!(
            evaluate(&rules, &sets, &in_set).decision,
            Decision::Deny,
            "uid 1000 is a member of %admins -> rule matches"
        );
        let mut out_of_set = AccessFacts::new(Perm::Open);
        out_of_set.uids = vec![42];
        assert_eq!(
            evaluate(&rules, &sets, &out_of_set).decision,
            Decision::Allow,
            "uid 42 is NOT in %admins -> no match -> fallthrough Allow"
        );
    }

    /// A uid given as a numeric STRING literal (`AttrValue::Str("0")`, not Int)
    /// matches a fact uid of 0 and rejects 5. Kills the `n == fact_val` -> `!=`
    /// mutant in the `Str` arm of `int_set_contains`.
    #[test]
    fn uid_numeric_string_literal_matches_and_rejects() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("uid", "0")], // kv() builds AttrValue::Str("0")
            vec![Attr::All],
        )];
        let mut matching = AccessFacts::new(Perm::Open);
        matching.uids = vec![0];
        assert_eq!(
            evaluate(&rules, &empty_sets(), &matching).decision,
            Decision::Deny,
            "uid=\"0\" (string) matches fact uid 0"
        );
        let mut nonmatching = AccessFacts::new(Perm::Open);
        nonmatching.uids = vec![5];
        assert_eq!(
            evaluate(&rules, &empty_sets(), &nonmatching).decision,
            Decision::Allow,
            "uid=\"0\" (string) does NOT match fact uid 5"
        );
    }

    /// A `dir=%set` whose members include the `execdirs` keyword: a fact exe
    /// under an execdir (`/usr/`) matches; one outside (`/opt/`) does not. Kills
    /// the `m == "execdirs"` and `prefix_from_list(...) == Match` `!=` mutants.
    #[test]
    fn dir_setref_execdirs_keyword_matches_under_usr() {
        let sets = SetTable::from_entries(&[set_def("mydirs", &["execdirs"])]);
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_ref("dir", "mydirs")],
            vec![Attr::All],
        )];
        let mut under = AccessFacts::new(Perm::Open);
        under.exe = Some("/usr/bin/foo".to_string());
        assert_eq!(
            evaluate(&rules, &sets, &under).decision,
            Decision::Deny,
            "exe under an execdir (/usr/) matches dir=%{{execdirs}}"
        );
        let mut outside = AccessFacts::new(Perm::Open);
        outside.exe = Some("/opt/x".to_string());
        assert_eq!(
            evaluate(&rules, &sets, &outside).decision,
            Decision::Allow,
            "exe outside any execdir does not match"
        );
    }

    /// A `dir=%set` whose members include the `systemdirs` keyword (which adds
    /// `/etc/`, NOT covered by execdirs): a fact exe under `/etc/` matches. Kills
    /// the `m == "systemdirs"` and `prefix_from_list(...) == Match` `!=` mutants.
    #[test]
    fn dir_setref_systemdirs_keyword_matches_under_etc() {
        let sets = SetTable::from_entries(&[set_def("mydirs", &["systemdirs"])]);
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_ref("dir", "mydirs")],
            vec![Attr::All],
        )];
        let mut under = AccessFacts::new(Perm::Open);
        under.exe = Some("/etc/passwd".to_string());
        assert_eq!(
            evaluate(&rules, &sets, &under).decision,
            Decision::Deny,
            "exe under /etc/ (systemdirs-only) matches dir=%{{systemdirs}}"
        );
        let mut outside = AccessFacts::new(Perm::Open);
        outside.exe = Some("/opt/x".to_string());
        assert_eq!(
            evaluate(&rules, &sets, &outside).decision,
            Decision::Allow,
            "exe outside systemdirs does not match"
        );
    }

    // -----------------------------------------------------------------------
    // Semantic 1: first-match-wins (f1 §1.1, policy.c:1126)
    // -----------------------------------------------------------------------

    /// Two rules both match the facts; the FIRST in load order decides.
    /// (f1 §1.1, policy.c:1126-1134)
    #[test]
    fn first_match_wins_first_rule_decides() {
        let rules = vec![
            // Rule 1: deny perm=any all : all
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
            // Rule 2: allow perm=any all : all  (would also match, but comes after)
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];
        let facts = AccessFacts::new(Perm::Open);
        let verdict = evaluate(&rules, &empty_sets(), &facts);

        assert_eq!(verdict.decision, Decision::Deny, "first rule must win");
        assert_eq!(
            verdict.matched_rule,
            Some(1),
            "matched_rule must be 1-based index of first rule"
        );
        assert_eq!(verdict.source, Source::Rule);
        assert!(verdict.uncertain.is_none());
    }

    // -----------------------------------------------------------------------
    // Semantic 2: fallthrough = ALLOW (f1 §1.2, policy.c:1164)
    // -----------------------------------------------------------------------

    /// No rule matches -> `Allow` + `Fallthrough` + `matched_rule = None`.
    /// (f1 §1.2, policy.c:1164)
    #[test]
    fn fallthrough_when_no_rule_matches_is_allow() {
        // A rule constraining uid=999, but facts have uid=0 -> no match.
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("uid", 999)],
            vec![Attr::All],
        )];
        let mut facts = AccessFacts::new(Perm::Open);
        facts.uids = vec![0];

        let verdict = evaluate(&rules, &empty_sets(), &facts);

        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "fallthrough must be Allow (policy.c:1164)"
        );
        assert_eq!(
            verdict.matched_rule, None,
            "fallthrough has no matched_rule"
        );
        assert_eq!(verdict.source, Source::Fallthrough);
    }

    /// Empty ruleset -> fallthrough Allow.
    #[test]
    fn empty_ruleset_falls_through_to_allow() {
        let facts = AccessFacts::new(Perm::Execute);
        let verdict = evaluate(&[], &empty_sets(), &facts);
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.source, Source::Fallthrough);
        assert_eq!(verdict.matched_rule, None);
    }

    // -----------------------------------------------------------------------
    // Semantic 3: AND within subject (and within object) (f1 §1.3)
    // -----------------------------------------------------------------------

    /// Rule with TWO subject attrs matches ONLY if BOTH match.
    /// (f1 §1.3, "Each field is and'ed with others")
    #[test]
    fn and_within_subject_both_must_match() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            // subject: exe=/usr/bin/curl AND uid=0
            vec![kv("exe", "/usr/bin/curl"), kv_int("uid", 0)],
            vec![Attr::All],
        )];

        // Case A: exe matches but uid does not -> no match -> fallthrough Allow
        let mut facts_a = AccessFacts::new(Perm::Open);
        facts_a.exe = Some("/usr/bin/curl".to_string());
        facts_a.uids = vec![1000]; // uid 1000, rule wants 0
        let verdict_a = evaluate(&rules, &empty_sets(), &facts_a);
        assert_eq!(
            verdict_a.decision,
            Decision::Allow,
            "uid mismatch must prevent match"
        );

        // Case B: uid matches but exe does not -> no match -> fallthrough Allow
        let mut facts_b = AccessFacts::new(Perm::Open);
        facts_b.exe = Some("/usr/bin/wget".to_string());
        facts_b.uids = vec![0]; // uid 0, but exe wrong
        let verdict_b = evaluate(&rules, &empty_sets(), &facts_b);
        assert_eq!(
            verdict_b.decision,
            Decision::Allow,
            "exe mismatch must prevent match"
        );

        // Case C: both match -> Deny
        let mut facts_c = AccessFacts::new(Perm::Open);
        facts_c.exe = Some("/usr/bin/curl".to_string());
        facts_c.uids = vec![0];
        let verdict_c = evaluate(&rules, &empty_sets(), &facts_c);
        assert_eq!(
            verdict_c.decision,
            Decision::Deny,
            "both matching must produce Deny"
        );
    }

    // -----------------------------------------------------------------------
    // Semantic 4: absent fact WIDENS, does NOT fail the match (f1 §1.4)
    // -----------------------------------------------------------------------

    /// A rule constraining `uid=0` but the fact's uid vec is EMPTY (absent) ->
    /// the constraint is SKIPPED, so the rule can still match on its other
    /// constraints.
    /// (f1 §1.4, rules.c:1376-1379 "None must WIDEN not narrow")
    #[test]
    fn absent_uid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("uid", 0)], // constrains uid=0
            vec![Attr::All],
        )];

        // No uid supplied -> constraint skipped -> rule matches -> Deny
        let facts = AccessFacts::new(Perm::Open); // uids is empty Vec
        let verdict = evaluate(&rules, &empty_sets(), &facts);

        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "absent uid fact must widen (skip the constraint), not narrow"
        );
    }

    /// Absent exe fact also widens.
    #[test]
    fn absent_exe_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("exe", "/usr/bin/curl")],
            vec![Attr::All],
        )];

        // exe is None -> constraint skipped -> Deny
        let facts = AccessFacts::new(Perm::Open);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(verdict.decision, Decision::Deny, "absent exe must widen");
    }

    // -----------------------------------------------------------------------
    // Semantic 5: exact vs prefix matching (f1 §1.4)
    // -----------------------------------------------------------------------

    /// `dir=/usr/bin/` is a PREFIX constraint: matches `/usr/bin/foo` (prefix).
    /// `path=/usr/bin` is EXACT: does NOT match `/usr/bin/foo`.
    /// (f1 §1.4, `attr_set_check_pstr` for dir, `attr_set_check_str` for path)
    #[test]
    fn dir_prefix_matches_path_underneath() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            // object: dir=/usr/bin/  (prefix)
            vec![kv("dir", "/usr/bin/")],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/usr/bin/foo".to_string());
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "dir= prefix match must fire for /usr/bin/foo"
        );
    }

    #[test]
    fn path_exact_does_not_match_longer_path() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            // object: path=/usr/bin  (exact)
            vec![kv("path", "/usr/bin")],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/usr/bin/foo".to_string()); // longer -> no exact match
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "path= exact match must NOT fire for /usr/bin/foo"
        );
    }

    /// `execdirs` macro expands to the hardcoded prefix list from `check_dirs`.
    /// `/usr/bin/foo` starts with `/usr/` -> matches `execdirs`.
    #[test]
    fn execdirs_macro_matches_usr_bin_path() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("dir", "execdirs")],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/usr/bin/foo".to_string());
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "execdirs must match /usr/bin/foo (starts with /usr/)"
        );
    }

    /// `/etc/foo` is NOT in execdirs but IS in systemdirs.
    #[test]
    fn systemdirs_contains_etc_execdirs_does_not() {
        // execdirs rule: /etc/foo should NOT match
        let execdirs_rule = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("dir", "execdirs")],
        )];
        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/etc/passwd".to_string());
        let v1 = evaluate(&execdirs_rule, &empty_sets(), &facts);
        assert_eq!(
            v1.decision,
            Decision::Allow,
            "/etc/passwd must NOT match execdirs"
        );

        // systemdirs rule: /etc/foo SHOULD match
        let systemdirs_rule = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("dir", "systemdirs")],
        )];
        let v2 = evaluate(&systemdirs_rule, &empty_sets(), &facts);
        assert_eq!(
            v2.decision,
            Decision::Deny,
            "/etc/passwd must match systemdirs"
        );
    }

    // -----------------------------------------------------------------------
    // Semantic 6: pattern= / unknown ftype -> NotEvaluable -> uncertain
    // -----------------------------------------------------------------------

    /// A rule with `pattern=ld_so` above a decisive rule produces a verdict where
    /// the decisive rule's decision is reported and `verdict.uncertain` names the
    /// unevaluable construct (pattern=).
    /// (f1 §2.3, §5.1(g))
    #[test]
    fn pattern_rule_above_decisive_rule_produces_uncertain() {
        let rules = vec![
            // Rule 1: pattern=ld_so (NotEvaluable)
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv("pattern", "ld_so")],
                vec![Attr::All],
            ),
            // Rule 2: decisive allow all : all
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let facts = AccessFacts::new(Perm::Execute);
        let verdict = evaluate(&rules, &empty_sets(), &facts);

        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "decisive rule 2 must provide the decision"
        );
        assert_eq!(
            verdict.matched_rule,
            Some(2),
            "matched_rule must point to the decisive rule"
        );
        assert!(
            verdict.uncertain.is_some(),
            "uncertain must be set when a PossibleMatch precedes the decisive rule"
        );
        let reason = verdict.uncertain.unwrap();
        assert!(
            reason.contains("pattern"),
            "uncertain reason must name 'pattern', got: {reason}"
        );
    }

    // -----------------------------------------------------------------------
    // Semantic 7: SetRef resolution (f1 §5.1(f))
    // -----------------------------------------------------------------------

    /// `AttrValue::SetRef("foo")` matches iff the fact value is in set `foo`.
    /// (f1 §5.1(f), `evaluate` resolves `SetRef` against `SetTable`)
    #[test]
    fn setref_membership_match_and_nonmatch() {
        let entries = vec![set_def("trusted_bins", &["/usr/bin/a", "/usr/bin/b"])];
        let sets = SetTable::from_entries(&entries);

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_ref("exe", "trusted_bins")],
            vec![Attr::All],
        )];

        // Fact exe is IN the set -> match -> Deny
        let mut facts_in = AccessFacts::new(Perm::Open);
        facts_in.exe = Some("/usr/bin/a".to_string());
        let verdict_in = evaluate(&rules, &sets, &facts_in);
        assert_eq!(
            verdict_in.decision,
            Decision::Deny,
            "/usr/bin/a is in trusted_bins -> Deny"
        );

        // Fact exe is NOT in the set -> no match -> Allow (fallthrough)
        let mut facts_out = AccessFacts::new(Perm::Open);
        facts_out.exe = Some("/usr/bin/curl".to_string());
        let verdict_out = evaluate(&rules, &sets, &facts_out);
        assert_eq!(
            verdict_out.decision,
            Decision::Allow,
            "/usr/bin/curl not in trusted_bins -> fallthrough Allow"
        );
    }

    // -----------------------------------------------------------------------
    // Additional coverage: perm filtering
    // -----------------------------------------------------------------------

    /// Rule with `perm=execute` does NOT match an `open` event.
    #[test]
    fn perm_execute_does_not_match_open_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "execute rule must not match open event"
        );
    }

    /// Rule with `perm=any` matches both open and execute.
    #[test]
    fn perm_any_matches_open_and_execute() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![Attr::All],
        )];
        for event_perm in [Perm::Open, Perm::Execute] {
            let facts = AccessFacts::new(event_perm);
            let verdict = evaluate(&rules, &empty_sets(), &facts);
            assert_eq!(
                verdict.decision,
                Decision::Deny,
                "perm=any must match {event_perm:?} events"
            );
        }
    }

    /// Default perm (None on rule) is treated as `open`.
    #[test]
    fn default_perm_none_treated_as_open() {
        let rules = vec![rule(
            Decision::Deny,
            None, // no perm -> defaults to open
            vec![Attr::All],
            vec![Attr::All],
        )];

        // Open event: matches
        let verdict_open = evaluate(&rules, &empty_sets(), &AccessFacts::new(Perm::Open));
        assert_eq!(verdict_open.decision, Decision::Deny);

        // Execute event: does NOT match (default is open, not any)
        let verdict_exec = evaluate(&rules, &empty_sets(), &AccessFacts::new(Perm::Execute));
        assert_eq!(verdict_exec.decision, Decision::Allow);
    }

    // -----------------------------------------------------------------------
    // Additional coverage: 1-based rule numbering
    // -----------------------------------------------------------------------

    /// Second rule matches; `matched_rule` is 2 (1-based).
    #[test]
    fn matched_rule_is_one_based() {
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Execute), // won't match an Open event
                vec![Attr::All],
                vec![Attr::All],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Open),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];
        let facts = AccessFacts::new(Perm::Open);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.matched_rule,
            Some(2),
            "second rule -> matched_rule=2"
        );
    }

    // -----------------------------------------------------------------------
    // Additional coverage: SetTable::from_entries
    // -----------------------------------------------------------------------

    #[test]
    fn set_table_from_entries_ignores_rules_and_comments() {
        let entries = vec![
            set_def("s1", &["a", "b"]),
            Entry::Comment {
                text: "# hi".to_string(),
                line: 1,
            },
            set_def("s2", &["c"]),
        ];
        let table = SetTable::from_entries(&entries);
        assert!(table.get("s1").is_some());
        assert!(table.get("s2").is_some());
        assert!(table.get("nonexistent").is_none());
    }

    // -----------------------------------------------------------------------
    // check_access truth table (kills the `|| -> &&` surviving mutant)
    // The `||` -> `&&` mutation makes Open/Execute rules ALWAYS return false
    // (no single Perm value satisfies both sides of &&). A test that asserts
    // a perm=open rule MATCHES an open event, and a perm=execute rule MATCHES
    // an execute event, kills the mutant because the && form never matches.
    // -----------------------------------------------------------------------

    /// `perm=open` rule matches an `Open` event (direct match arm).
    /// This kills the `|| -> &&` mutant: with `&&`, `Open == Open && Open == Any`
    /// is `true && false` = false, so the rule would never match.
    #[test]
    fn check_access_open_rule_matches_open_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "perm=open rule must match an Open event"
        );
    }

    /// `perm=open` rule does NOT match an `Execute` event.
    #[test]
    fn check_access_open_rule_does_not_match_execute_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Execute);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "perm=open rule must NOT match an Execute event"
        );
    }

    /// `perm=execute` rule matches an `Execute` event (direct match arm).
    /// This kills the `|| -> &&` mutant on the Execute arm: with `&&`,
    /// `Execute == Execute && Execute == Any` = `true && false` = false.
    #[test]
    fn check_access_execute_rule_matches_execute_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Execute);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "perm=execute rule must match an Execute event"
        );
    }

    /// `perm=open` rule also matches a facts perm of `Any` (the second disjunct).
    /// Ensures that the `|| facts_perm == Perm::Any` branch in `check_access`
    /// is exercised.
    #[test]
    fn check_access_open_rule_matches_any_perm_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Any);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "perm=open rule must match a facts-perm=Any event"
        );
    }

    /// `perm=execute` rule also matches a facts perm of `Any`.
    #[test]
    fn check_access_execute_rule_matches_any_perm_event() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Any);
        let verdict = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "perm=execute rule must match a facts-perm=Any event"
        );
    }

    // -----------------------------------------------------------------------
    // Subject-field arm coverage
    // Each test pins one arm of eval_subject_field by asserting that a
    // constraint on that key BLOCKS a non-satisfying fact (kills delete-arm).
    // -----------------------------------------------------------------------

    /// `gid=` constraint matches a satisfying gid and blocks a non-satisfying one.
    #[test]
    fn gid_constraint_blocks_nonmatching_gid() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("gid", 1000)],
            vec![Attr::All],
        )];

        // Matching gid -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.gids = vec![1000];
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "gid=1000 must match facts gid=1000"
        );

        // Non-matching gid -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.gids = vec![999];
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "gid=1000 must NOT match facts gid=999"
        );
    }

    /// `auid=` constraint matches the correct auid and blocks others.
    #[test]
    fn auid_constraint_blocks_nonmatching_auid() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("auid", 42)],
            vec![Attr::All],
        )];

        // Matching auid -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.auid = Some(42);
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "auid=42 must match facts auid=42"
        );

        // Non-matching auid -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.auid = Some(99);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "auid=42 must NOT match facts auid=99"
        );
    }

    /// `sessionid=` constraint matches the correct session and blocks others.
    #[test]
    fn sessionid_constraint_blocks_nonmatching_sessionid() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("sessionid", 7)],
            vec![Attr::All],
        )];

        // Matching sessionid -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.sessionid = Some(7);
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "sessionid=7 must match facts sessionid=7"
        );

        // Non-matching sessionid -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.sessionid = Some(8);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "sessionid=7 must NOT match facts sessionid=8"
        );
    }

    /// `pid=` constraint matches the correct pid and blocks others.
    #[test]
    fn pid_constraint_blocks_nonmatching_pid() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("pid", 1234)],
            vec![Attr::All],
        )];

        // Matching pid -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.pid = Some(1234);
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "pid=1234 must match facts pid=1234"
        );

        // Non-matching pid -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.pid = Some(5678);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "pid=1234 must NOT match facts pid=5678"
        );
    }

    /// `ppid=` constraint matches the correct ppid and blocks others.
    #[test]
    fn ppid_constraint_blocks_nonmatching_ppid() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("ppid", 1)],
            vec![Attr::All],
        )];

        // Matching ppid -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.ppid = Some(1);
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(v.decision, Decision::Deny, "ppid=1 must match facts ppid=1");

        // Non-matching ppid -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.ppid = Some(2);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "ppid=1 must NOT match facts ppid=2"
        );
    }

    /// `comm=` constraint matches the correct comm string and blocks others.
    #[test]
    fn comm_constraint_blocks_nonmatching_comm() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("comm", "bash")],
            vec![Attr::All],
        )];

        // Matching comm -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.comm = Some("bash".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "comm=bash must match facts comm=bash"
        );

        // Non-matching comm -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.comm = Some("sh".to_string());
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "comm=bash must NOT match facts comm=sh"
        );
    }

    /// Subject `dir=` (exe-path prefix) constraint blocks a non-prefix exe path.
    #[test]
    fn subject_dir_constraint_blocks_nonmatching_exe_prefix() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("dir", "/usr/bin/")],
            vec![Attr::All],
        )];

        // Matching exe prefix -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.exe = Some("/usr/bin/curl".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "subject dir=/usr/bin/ must match exe=/usr/bin/curl"
        );

        // Non-matching exe prefix -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.exe = Some("/usr/sbin/sshd".to_string());
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "subject dir=/usr/bin/ must NOT match exe=/usr/sbin/sshd"
        );
    }

    /// Subject `trust=1` matches a trusted subject and blocks an untrusted one.
    #[test]
    fn subject_trust_constraint_blocks_nonmatching_trust() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("trust", "1")],
            vec![Attr::All],
        )];

        // Trusted subject -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "trust=1 rule must match a trusted subject"
        );

        // Untrusted subject (Trust::No) -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.subj_trust = Trust::No;
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "trust=1 rule must NOT match an untrusted subject"
        );
    }

    /// Subject `trust=0` matches an untrusted subject and blocks a trusted one.
    #[test]
    fn subject_trust_zero_constraint_blocks_trusted_subject() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("trust", "0")],
            vec![Attr::All],
        )];

        // Untrusted subject -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.subj_trust = Trust::No;
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "trust=0 rule must match an untrusted subject"
        );

        // Trusted subject -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.subj_trust = Trust::Yes;
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "trust=0 rule must NOT match a trusted subject"
        );
    }

    // -----------------------------------------------------------------------
    // Object-field arm coverage
    // Each test pins one arm of eval_object_field by asserting that a
    // constraint on that key BLOCKS a non-satisfying fact (kills delete-arm).
    // -----------------------------------------------------------------------

    /// `device=` constraint matches the correct device and blocks others.
    #[test]
    fn device_constraint_blocks_nonmatching_device() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("device", "/dev/sda")],
        )];

        // Matching device -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.device = Some("/dev/sda".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "device=/dev/sda must match facts device=/dev/sda"
        );

        // Non-matching device -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.device = Some("/dev/sdb".to_string());
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "device=/dev/sda must NOT match facts device=/dev/sdb"
        );
    }

    /// `sha256hash=` constraint matches the correct hash and blocks others.
    #[test]
    fn sha256hash_constraint_blocks_nonmatching_hash() {
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("sha256hash", &hash_a)],
        )];

        // Matching hash -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.sha256 = Some(hash_a.clone());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "sha256hash= must match on equal hash"
        );

        // Non-matching hash -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.sha256 = Some(hash_b);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "sha256hash= must NOT match on different hash"
        );
    }

    /// `filehash=` is an alias for `sha256hash=` - same arm, same semantics.
    #[test]
    fn filehash_alias_constraint_blocks_nonmatching_hash() {
        let hash_a = "c".repeat(64);
        let hash_b = "d".repeat(64);

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("filehash", &hash_a)],
        )];

        // Matching hash -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.sha256 = Some(hash_a.clone());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "filehash= must match on equal hash"
        );

        // Non-matching hash -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.sha256 = Some(hash_b);
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "filehash= must NOT match on different hash"
        );
    }

    /// Object `trust=1` matches a trusted object and blocks an untrusted one.
    #[test]
    fn object_trust_constraint_blocks_nonmatching_obj_trust() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("trust", "1")],
        )];

        // Trusted object -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.obj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "object trust=1 rule must match a trusted object"
        );

        // Untrusted object -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.obj_trust = Trust::No;
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "object trust=1 rule must NOT match an untrusted object"
        );
    }

    /// Object `dir=` (object-path prefix) constraint blocks a non-prefix object path.
    #[test]
    fn object_dir_constraint_blocks_nonmatching_obj_path_prefix() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("dir", "/etc/")],
        )];

        // Matching object path prefix -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.path = Some("/etc/passwd".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "object dir=/etc/ must match path=/etc/passwd"
        );

        // Non-matching object path -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.path = Some("/usr/bin/ls".to_string());
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "object dir=/etc/ must NOT match path=/usr/bin/ls"
        );
    }

    /// `ftype=` with a known ftype matches the correct type and blocks others.
    /// (Object-side arm; ftype=any handled separately by `ftype_any_always_matches`.)
    #[test]
    fn ftype_constraint_blocks_nonmatching_ftype() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("ftype", "application/x-executable")],
        )];

        // Matching ftype -> Deny
        let mut facts_match = AccessFacts::new(Perm::Open);
        facts_match.ftype = Some("application/x-executable".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_match);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "ftype=application/x-executable must match when ftype matches"
        );

        // Non-matching ftype -> fallthrough Allow
        let mut facts_nomatch = AccessFacts::new(Perm::Open);
        facts_nomatch.ftype = Some("text/plain".to_string());
        let v2 = evaluate(&rules, &empty_sets(), &facts_nomatch);
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "ftype=application/x-executable must NOT match ftype=text/plain"
        );
    }

    /// `ftype=any` always matches regardless of the actual ftype value.
    #[test]
    fn ftype_any_always_matches() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("ftype", "any")],
        )];

        // With a known ftype -> ftype=any still matches
        let mut facts_known = AccessFacts::new(Perm::Open);
        facts_known.ftype = Some("text/x-python".to_string());
        let v = evaluate(&rules, &empty_sets(), &facts_known);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "ftype=any must match even when ftype=text/x-python"
        );
    }

    // -----------------------------------------------------------------------
    // Absent-fact widening: optional int fields (auid/sessionid/pid/ppid)
    // -----------------------------------------------------------------------

    /// Absent `auid` fact widens (does not block the rule).
    #[test]
    fn absent_auid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("auid", 100)],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open); // auid = None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "absent auid must widen (skip constraint), not block the rule"
        );
    }

    /// Absent `sessionid` fact widens.
    #[test]
    fn absent_sessionid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("sessionid", 1)],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open); // sessionid = None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "absent sessionid must widen, not block the rule"
        );
    }

    /// Absent `pid` fact widens.
    #[test]
    fn absent_pid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("pid", 1)],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open); // pid = None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "absent pid must widen, not block the rule"
        );
    }

    /// Absent `ppid` fact widens.
    #[test]
    fn absent_ppid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("ppid", 1)],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open); // ppid = None
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "absent ppid must widen, not block the rule"
        );
    }

    /// Absent `gid` vec widens (same widening semantics as uid).
    #[test]
    fn absent_gid_fact_widens_not_narrows() {
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv_int("gid", 500)],
            vec![Attr::All],
        )];
        let facts = AccessFacts::new(Perm::Open); // gids = empty
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "absent gid (empty vec) must widen, not block the rule"
        );
    }

    // -----------------------------------------------------------------------
    // #126: `exe=untrusted` is the ONLY exe TRUST MACRO. `exe=trusted` is a
    // LITERAL exe-path compare, NOT a macro.
    //
    // Ground truth (real fapolicyd, f1 grounding §1.4 line ~164; upstream
    // `src/library/rules.c` EXE case `rules.c:1443-1463`; live fapolicyd 1.4.5):
    // the EXE switch does EXACT string membership PLUS exactly one special token,
    // the `untrusted` macro ("if the set contains `untrusted` AND the subject is
    // not in the trust DB, match immediately"). There is NO `trusted` macro;
    // `exe=trusted` compares the literal string "trusted" against the exe path.
    // Issue #126 wrongly assumed a symmetric `trusted` macro.
    //   - `exe=untrusted` matches IFF the subject is NOT trusted (`subj_trust=No`).
    //   - `subj_trust=Unknown` -> the `untrusted` macro is `NotEvaluable` (no
    //     trust DB consulted), so a rule carrying it produces `PossibleMatch`
    //     (downgrade), mirroring the existing `trust=` NotEvaluable behavior.
    //   - `exe=trusted` is a literal: it matches IFF the exe path equals the
    //     string "trusted" (essentially never for a real path).
    //
    // These pin the macro semantics DIRECTLY on `evaluate()`. A wrong impl that
    // treats `untrusted` as a literal exe path (the pre-#126 behavior:
    // `exact_string_match(exe_path, "untrusted")`) cannot pass the untrusted
    // tests; a wrong impl that treats `trusted` as a (symmetric) trust macro
    // cannot pass the literal `exe=trusted` test below.
    // -----------------------------------------------------------------------

    /// `exe=untrusted` FIRES for an untrusted subject (`subj_trust=No`).
    /// A literal-path impl compares the exe path against "untrusted" -> `NoMatch`
    /// -> the deny rule never fires -> this assertion fails. RED until #126.
    #[test]
    fn exe_untrusted_macro_matches_untrusted_subject() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("exe", "untrusted")],
            vec![Attr::All],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/tmp/payload".to_string());
        facts.subj_trust = Trust::No;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "exe=untrusted must FIRE the deny rule for an untrusted subject"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=No is decisive, not uncertain"
        );
    }

    /// `exe=untrusted` does NOT fire for a trusted subject (`subj_trust=Yes`):
    /// the deny rule is skipped and the ruleset falls through to Allow.
    /// An impl that ALWAYS fires `untrusted` (ignoring trust state) would wrongly
    /// deny here.
    #[test]
    fn exe_untrusted_macro_no_match_trusted_subject() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("exe", "untrusted")],
            vec![Attr::All],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/usr/bin/cat".to_string());
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "exe=untrusted must NOT fire for a trusted subject -> fallthrough Allow"
        );
        assert_eq!(v.source, Source::Fallthrough, "no rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=Yes makes the macro a decisive NoMatch, not uncertain"
        );
    }

    /// `exe=trusted` is a LITERAL exe-path compare, NOT a trust macro.
    ///
    /// Grounding: real fapolicyd has NO `trusted` macro - only `untrusted` is
    /// special in the EXE case (f1 §1.4 line ~164; upstream `rules.c:1443-1463`;
    /// live fapolicyd 1.4.5). So `exe=trusted` does EXACT string membership: it
    /// matches only if the exe path is literally the string "trusted".
    ///
    /// Rule 1 `deny_audit perm=any exe=trusted : all` then rule 2
    /// `allow perm=any all : all`. The subject's exe is `/usr/bin/coreutils` and
    /// `subj_trust=Yes`. Because "trusted" != "/usr/bin/coreutils", rule 1 does
    /// NOT fire (literal `NoMatch`); the verdict falls through to the rule-2 Allow.
    ///
    /// RED against the buggy macro impl: that impl treats `exe=trusted` as
    /// `trust=1`, so with `subj_trust=Yes` it fires the deny rule -> `Deny` at
    /// rule 1. This test asserts `Allow` at rule 2, so it fails until the bogus
    /// `trusted` macro branch is removed and `exe=trusted` falls through to the
    /// literal exe-path compare.
    #[test]
    fn exe_trusted_is_literal_not_a_trust_macro() {
        use crate::facts::Trust;

        let rules = vec![
            rule(
                Decision::DenyAudit,
                Some(Perm::Any),
                vec![kv("exe", "trusted")],
                vec![Attr::All],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/usr/bin/coreutils".to_string());
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "exe=trusted is a LITERAL path compare ('trusted' != '/usr/bin/coreutils'), \
             so the deny rule must NOT fire; the verdict is the rule-2 Allow. A wrong \
             impl that treats `trusted` as a trust macro would Deny here."
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "the decisive match is rule 2 (allow); the literal exe=trusted deny did not fire"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "a literal exe-path NoMatch is decisive, not uncertain"
        );
    }

    /// `exe=untrusted` with `subj_trust=Unknown` (no trust DB consulted) is
    /// `NotEvaluable`: the rule produces a `PossibleMatch` (downgrade), exactly
    /// like a `trust=` field without a trust DB. The ruleset then falls through
    /// to Allow but `uncertain` carries a reason. An impl that DEFAULTS the macro
    /// to fire (or to never-fire silently) loses this downgrade signal.
    #[test]
    fn exe_untrusted_macro_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv("exe", "untrusted")],
                vec![Attr::All],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/usr/bin/cat".to_string());
        facts.subj_trust = Trust::Unknown;
        let v = evaluate(&rules, &empty_sets(), &facts);
        // The unevaluable deny (rule 1) sits above the decisive allow (rule 2):
        // the verdict is the allow, but `uncertain` is recorded (downgrade).
        assert_eq!(
            v.decision,
            Decision::Allow,
            "rule 2 allow is the decisive match"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "the decisive rule is rule 2 (allow)"
        );
        assert!(
            v.uncertain.is_some(),
            "exe=untrusted with Unknown trust must downgrade to a Possible/uncertain verdict"
        );
    }
}
