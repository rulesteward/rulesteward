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

/// `true` when `value` is a `SetRef` whose resolved members contain the
/// `untrusted` macro token. Used by the EXE arm to decide whether the embedded
/// trust macro applies (f1 §1.4 line 164; rules.c:1443-1463).
fn set_contains_untrusted(value: &AttrValue, sets: &SetTable) -> bool {
    match value {
        AttrValue::SetRef(name) => sets
            .get(name)
            .is_some_and(|members| members.iter().any(|m| m == "untrusted")),
        _ => false,
    }
}

/// Evaluate `exe=<set>` when the set CONTAINS the `untrusted` macro token.
///
/// fapolicyd's EXE case OR-s the `untrusted` macro with exact string membership:
/// match IFF (subject is NOT trusted, via the macro) OR (the exe path is an
/// exact member of the set). The macro is the deciding factor only when no
/// literal member matched; in that case `Trust::Unknown` downgrades to
/// `NotEvaluable` exactly like the bare `exe=untrusted` arm.
///
/// Precondition: `set_contains_untrusted(value, sets)` is `true`.
fn eval_exe_setref_with_untrusted_macro(
    value: &AttrValue,
    sets: &SetTable,
    facts: &AccessFacts,
) -> (FieldEval, Option<String>) {
    // Literal exact-membership leg (independent of trust). An absent exe fact
    // widens (Match), the standard absent-fact behaviour.
    let literal = match &facts.exe {
        None => FieldEval::Match,
        Some(exe_path) => exact_string_match(exe_path, value, sets),
    };
    if literal == FieldEval::Match {
        return (FieldEval::Match, None);
    }
    // No literal member matched: the `untrusted` macro is the deciding factor.
    // Reuse `eval_trust_field` so Match/NoMatch/NotEvaluable (and the Unknown
    // downgrade reason) mirror the bare `exe=untrusted` arm exactly.
    eval_trust_field(
        facts.subj_trust,
        &AttrValue::Int(0),
        "subj trust unknown (no trust DB)",
    )
}

/// Evaluate `dir=<set>` when the set CONTAINS the `untrusted` macro token.
///
/// fapolicyd's DIR case OR-s the `untrusted` macro with PREFIX membership (the
/// standard `attr_set_check_pstr` semantics for the dir= field):
///   match IFF (set contains "untrusted" AND the process/file is NOT trusted,
///     via the macro)
///     OR
///   (the reference path is a PREFIX of a literal set member).
///
/// The macro is the deciding factor only when no literal prefix member matched;
/// in that case `Trust::Unknown` downgrades to `NotEvaluable`, mirroring
/// `eval_exe_setref_with_untrusted_macro` and the bare `dir=untrusted` arm.
///
/// This mirrors `eval_exe_setref_with_untrusted_macro` exactly, with
/// `prefix_string_match` used for the literal leg instead of `exact_string_match`
/// (dir= is a prefix match; exe= is an exact match).
///
/// Grounding: f1 §2.2 line 216 + f1 §1.4 line 166 (DIR subject: `EXE_DIR` field,
/// deprecated `untrusted` macro OR'd with prefix match); upstream rules.c dir=
/// case ~1490-1530 (SUBJECT) and ODIR case (OBJECT).
///
/// The helper is PARAMETERIZED over `ref_path` (the path to prefix-match: the
/// subject's exe for a subject-side `dir=`, or the object path for an
/// object-side `dir=`) and `trust` (the corresponding trust value).  This
/// allows BOTH the subject arm and the object arm to share one implementation.
///
/// Precondition: `set_contains_untrusted(value, sets)` is `true`.
fn eval_dir_setref_with_untrusted_macro(
    value: &AttrValue,
    sets: &SetTable,
    ref_path: Option<&str>,
    trust: Trust,
    unknown_reason: &str,
) -> (FieldEval, Option<String>) {
    // Literal prefix-membership leg (independent of trust). An absent path fact
    // widens (Match), the standard absent-fact behaviour.
    let literal = match ref_path {
        None => FieldEval::Match,
        Some(path) => prefix_string_match(path, value, sets),
    };
    if literal == FieldEval::Match {
        return (FieldEval::Match, None);
    }
    // No literal prefix member matched: the `untrusted` macro is the deciding
    // factor. Reuse `eval_trust_field` so Match/NoMatch/NotEvaluable (and the
    // Unknown downgrade reason) mirror the bare `dir=untrusted` arm exactly.
    eval_trust_field(trust, &AttrValue::Int(0), unknown_reason)
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
            // A SetRef whose resolved members CONTAIN the `untrusted` macro
            // token: real fapolicyd's EXE case OR-s the `untrusted` macro with
            // exact set membership (f1 §1.4 line 164; rules.c:1443-1463). So the
            // match is (set contains "untrusted" AND subject NOT trusted) OR
            // (exe path is an exact member). The macro path mirrors the bare
            // `exe=untrusted` Trust::Unknown -> NotEvaluable downgrade when it is
            // the deciding factor (no literal member matched).
            None if set_contains_untrusted(value, sets) => {
                eval_exe_setref_with_untrusted_macro(value, sets, facts)
            }
            // Any other value (incl. the literal "trusted", or a SetRef without
            // the `untrusted` token, or an Int): literal exe path match.
            _ => match &facts.exe {
                None => (FieldEval::Match, None),
                Some(exe_path) => (exact_string_match(exe_path, value, sets), None),
            },
        },
        "comm" => match &facts.comm {
            None => (FieldEval::Match, None),
            Some(comm_val) => (exact_string_match(comm_val, value, sets), None),
        },
        "dir" => match as_str_literal(value) {
            // `dir=untrusted` is a SUBJECT TRUST MACRO, mirroring `exe=untrusted`
            // (f1 §2.2 line 216; f1 §1.4 line 166: EXE_DIR field, the deprecated
            // `untrusted` macro OR'd with prefix match). It evaluates against the
            // SUBJECT trust state, NOT the exe path. Reuse `eval_trust_field` so
            // the NotEvaluable/Match/NoMatch return shape (and the Unknown downgrade
            // reason) mirrors the `exe=untrusted` arm and the `trust=` arm exactly:
            //   - `untrusted` is equivalent to `trust=0` (match iff Trust::No).
            Some("untrusted") => eval_trust_field(
                facts.subj_trust,
                &AttrValue::Int(0),
                "subj trust unknown (no trust DB)",
            ),
            // A SetRef whose resolved members CONTAIN the `untrusted` macro token:
            // real fapolicyd's DIR case OR-s the `untrusted` macro with PREFIX
            // membership (f1 §1.4 line 166; f1 §2.2 line 216). The macro path
            // mirrors the bare `dir=untrusted` Trust::Unknown -> NotEvaluable
            // downgrade when it is the deciding factor (no literal prefix matched).
            None if set_contains_untrusted(value, sets) => eval_dir_setref_with_untrusted_macro(
                value,
                sets,
                facts.exe.as_deref(),
                facts.subj_trust,
                "subj trust unknown (no trust DB)",
            ),
            // Any other value (a bare prefix literal, a SetRef without the
            // `untrusted` token, execdirs/systemdirs keywords, or an Int):
            // standard prefix match against the exe path.
            _ => match &facts.exe {
                None => (FieldEval::Match, None), // absent exe widens
                Some(exe_path) => (prefix_string_match(exe_path, value, sets), None),
            },
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
            // The `untrusted` macro is honoured against OBJECT trust
            // (`!is_obj_trusted(e)`) per upstream rules.c ODIR case; grounding:
            // f1 §1.4 line 174 (dir/odir object: same macro as subject dir) +
            // f1 §2.2 line 216 (trust-DB-dependent). This mirrors the subject-side
            // `dir=` arm exactly, substituting facts.path / facts.obj_trust for
            // facts.exe / facts.subj_trust.
            match as_str_literal(value) {
                // Bare `dir=untrusted` on the object side: the `untrusted` trust
                // macro fires IFF the object is NOT trusted. Reuse `eval_trust_field`
                // so the NotEvaluable/Match/NoMatch return shape (and the Unknown
                // downgrade reason) mirrors the subject-side `dir=untrusted` arm.
                Some("untrusted") => eval_trust_field(
                    facts.obj_trust,
                    &AttrValue::Int(0),
                    "obj trust unknown (no trust DB)",
                ),
                // A SetRef whose resolved members CONTAIN the `untrusted` macro
                // token: OR the macro (against obj_trust) with PREFIX membership
                // on the object path, using the shared parameterized helper.
                None if set_contains_untrusted(value, sets) => {
                    eval_dir_setref_with_untrusted_macro(
                        value,
                        sets,
                        facts.path.as_deref(),
                        facts.obj_trust,
                        "obj trust unknown (no trust DB)",
                    )
                }
                // Any other value (a bare prefix literal, a SetRef without the
                // `untrusted` token, execdirs/systemdirs keywords, or an Int):
                // standard prefix match against the object path.
                _ => match &facts.path {
                    None => (FieldEval::Match, None),
                    Some(p) => (prefix_string_match(p, value, sets), None),
                },
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
                            // Harden: synthesise a reason when the field evaluator
                            // returned None. A NotEvaluable with a None reason would
                            // otherwise slip through to Decisive(decision) below,
                            // masking the unevaluable constraint. After the object-side
                            // dir= fix the (NotEvaluable, None) path is unreachable for
                            // the dir= arm, but this guard prevents future regressions.
                            possible_reason =
                                Some(reason.unwrap_or_else(|| {
                                    format!("{key} is not statically evaluable")
                                }));
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
                            // Harden: synthesise a reason when the field evaluator
                            // returned None (same defence as the subject loop above).
                            possible_reason =
                                Some(reason.unwrap_or_else(|| {
                                    format!("{key} is not statically evaluable")
                                }));
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

    // -----------------------------------------------------------------------
    // #126 round-3: `exe=<SET>` where the set CONTAINS the `untrusted` macro
    // token. Real fapolicyd resolves `exe=%apps` via `attr_set_check_str`, and
    // the EXE case ALSO honours the `untrusted` macro when the SET contains it
    // (f1 grounding §1.4 line 164: "EXACT string membership ... plus the
    // `untrusted` macro: if the set contains `untrusted` AND the subject is not
    // in the trust DB, match immediately"; upstream rules.c:1443-1463). So the
    // EXE match for a set is: (set contains "untrusted" AND subject NOT trusted)
    // OR (exe path is an EXACT member of the set). The macro path mirrors the
    // bare-literal `exe=untrusted` behaviour, INCLUDING the Trust::Unknown ->
    // NotEvaluable downgrade when the macro is the deciding factor.
    //
    // Pre-round-3 the exe arm fell to `exact_string_match` for any SetRef, which
    // does literal set membership ONLY - it never honours the embedded macro, so
    // it MISSES the macro fire. These pin the OR-ed semantics on `evaluate()`.
    // -----------------------------------------------------------------------

    /// Set `%apps = untrusted,/usr/bin/foo`, rule `exe=%apps`, subject is
    /// untrusted and its exe is NOT a literal member -> the embedded `untrusted`
    /// macro must FIRE (set contains "untrusted" AND `subj_trust=No`). A
    /// literal-set-membership-only impl returns `NoMatch` and never denies. RED
    /// until the `SetRef` macro path lands.
    #[test]
    fn exe_setref_with_untrusted_member_fires_for_untrusted_subject() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("apps", &["untrusted", "/usr/bin/foo"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("exe", "apps")],
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
        facts.exe = Some("/tmp/payload".to_string());
        facts.subj_trust = Trust::No;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "set %apps contains the `untrusted` macro and the subject is untrusted: \
             the deny rule must FIRE via the macro, not fall through to literal membership"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=No is decisive, not uncertain"
        );
    }

    /// Same `%apps = untrusted,/usr/bin/foo`, but the subject IS trusted and its
    /// exe is NOT a literal member: the macro must NOT fire (trusted) AND there
    /// is no literal membership match -> the deny rule is skipped and the
    /// ruleset falls through to the rule-2 Allow. An impl that fires the macro
    /// regardless of trust state would wrongly Deny here.
    #[test]
    fn exe_setref_with_untrusted_member_no_fire_for_trusted_subject() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("apps", &["untrusted", "/usr/bin/foo"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("exe", "apps")],
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
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "trusted subject + exe not a literal member: macro does NOT fire and there is \
             no literal match, so the deny rule is skipped and the verdict is the rule-2 Allow"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (allow) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=Yes + literal NoMatch is decisive, not uncertain"
        );
    }

    /// Same `%apps = untrusted,/usr/bin/foo`, subject trust Unknown, exe not a
    /// literal member: the embedded `untrusted` macro is the deciding factor and
    /// trust is unknown -> `NotEvaluable` downgrade (mirrors the bare-literal
    /// `exe=untrusted` Unknown behaviour). The deny rule (rule 1) downgrades to
    /// a possible match; the verdict is the rule-2 Allow but `uncertain` is set.
    /// An impl that resolves the `SetRef` to literal membership only would return
    /// a DECISIVE `NoMatch` (`uncertain=None`), losing the downgrade.
    #[test]
    fn exe_setref_with_untrusted_member_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("apps", &["untrusted", "/usr/bin/foo"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("exe", "apps")],
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
        let v = evaluate(&rules, &sets, &facts);
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
            "exe=%apps (set contains `untrusted`) with Unknown trust and no literal match \
             must downgrade to an uncertain verdict, mirroring bare exe=untrusted"
        );
    }

    /// Same `%apps = untrusted,/usr/bin/foo`, but the subject's exe IS a literal
    /// member (`/usr/bin/foo`): the EXACT-membership path matches regardless of
    /// trust state (here subject is TRUSTED). This pins that literal membership
    /// is OR-ed independently of the macro - the macro never fires for a trusted
    /// subject, yet the literal match still denies.
    #[test]
    fn exe_setref_literal_member_matches_regardless_of_trust() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("apps", &["untrusted", "/usr/bin/foo"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("exe", "apps")],
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
        facts.exe = Some("/usr/bin/foo".to_string());
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "exe `/usr/bin/foo` is an EXACT member of %apps: the literal-membership path \
             matches independently of trust (subject is trusted, the macro does NOT fire)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(
            v.source,
            Source::Rule,
            "a decisive literal-membership match"
        );
        assert!(
            v.uncertain.is_none(),
            "an exact literal-membership match is decisive, not uncertain"
        );
    }

    // -----------------------------------------------------------------------
    // #126 round-3 regression pin: literal member in a set containing the
    // `untrusted` macro is decisive even when `subj_trust=Unknown`.
    //
    // The four existing `exe_setref_*` tests above do NOT cover the combination
    // of (a) literal exact-member hit AND (b) Unknown trust in the same call.
    // A wrong impl that short-circuits to `eval_trust_field` BEFORE checking
    // literal membership (i.e. checks the `untrusted` macro leg first and
    // returns `NotEvaluable` on Unknown trust before ever testing the literal
    // `exe_path in members` leg) would produce `PossibleMatch`/uncertain here
    // instead of the decisive `Match` the correct impl returns.
    //
    // Ground truth (f1 §1.4 line 164; rules.c:1443-1463): the EXE switch does
    // EXACT string membership FIRST, then the `untrusted` macro only when no
    // literal member matched. Exact set membership is trust-independent: the
    // literal leg fires regardless of trust state.
    // -----------------------------------------------------------------------

    /// Set `%apps = {"untrusted", "/usr/bin/foo"}`, rule 1 `deny perm=any exe=%apps
    /// : all`, rule 2 `allow perm=any all : all`. The subject's exe IS an exact
    /// member (`/usr/bin/foo`) but `subj_trust=Unknown`.
    ///
    /// Expected: decisive Deny at rule 1. The literal-membership leg must fire
    /// BEFORE the `untrusted` macro leg; trust state is irrelevant when a literal
    /// member already matched.
    ///
    /// A wrong impl that evaluates the `untrusted` macro first returns
    /// `NotEvaluable` (because `subj_trust=Unknown`), upgrades rule 1 to
    /// `PossibleMatch`, then falls through to the rule-2 Allow - asserting
    /// `uncertain.is_some()` and `decision=Allow`, which would FAIL this test.
    #[test]
    fn exe_setref_literal_member_decisive_even_with_unknown_trust() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("apps", &["untrusted", "/usr/bin/foo"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("exe", "apps")],
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
        facts.exe = Some("/usr/bin/foo".to_string()); // exact member of %apps
        facts.subj_trust = Trust::Unknown; // trust DB not consulted

        let v = evaluate(&rules, &sets, &facts);

        // Literal exact-membership is trust-independent: the Deny must be decisive.
        assert_eq!(
            v.decision,
            Decision::Deny,
            "exe=/usr/bin/foo is an exact member of %apps: the deny rule must fire \
             decisively even when subj_trust=Unknown (literal membership checks trust \
             state only when NO literal member matched)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "exact literal-membership match is decisive, not uncertain: {:?}",
            v.uncertain
        );
    }

    // -----------------------------------------------------------------------
    // #127: present-but-unhashable => NoMatch at the EVALUATOR layer,
    // uid-independent (root-safe regression pin).
    //
    // The existing `filehash_present_but_unhashable_is_denied_not_widened`
    // integration test (simulate_trustdb_resolution.rs ~490) constructs the
    // `sha256_unhashable=true` path via `chmod 000` + the real simulate binary.
    // That test SELF-SKIPS when the test runner is root (uid=0), because
    // `chmod 000` has no effect under DAC bypass. The self-hosted CI runners
    // ARE root. This leaves the evaluator's `None if sha256_unhashable => NoMatch`
    // arm unpinned in that environment.
    //
    // These two unit tests build `AccessFacts` DIRECTLY (no filesystem, no
    // chmod), so they fire regardless of uid. They pin the arm at the evaluator
    // layer, orthogonal to the integration test which pins the end-to-end CLI
    // path (non-root environments).
    //
    // Ground truth: rules.c:1606-1611 FILE_HASH error-as-denial (`return 0`);
    // rules.c:1572-1575 object-absent skip/widen. f1 grounding §1.4 sha256hash row.
    // -----------------------------------------------------------------------

    /// Present-but-unhashable object: the `sha256hash=` constraint yields
    /// `NoMatch` (error-as-denial, rules.c:1606-1611), so the `allow` rule does
    /// NOT fire and the verdict falls through to the `deny_audit` catch-all.
    ///
    /// `sha256=None, sha256_unhashable=true` is DISTINCT from the absent-object
    /// case (`sha256=None, sha256_unhashable=false`) which WIDENS to Match.
    /// This test pins the `sha256_unhashable=true` -> `NoMatch` arm of
    /// `eval_object_field` without touching the filesystem.
    #[test]
    fn unhashable_object_yields_nomatch_at_evaluator_layer() {
        // Rule 1: allow perm=open all : sha256hash=<64 zeros>
        // Rule 2: deny_audit perm=any all : all
        let all_zeros = "0".repeat(64);
        let rules = vec![
            rule(
                Decision::Allow,
                Some(Perm::Open),
                vec![Attr::All],
                vec![kv("sha256hash", &all_zeros)],
            ),
            rule(
                Decision::DenyAudit,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        // AccessFacts built directly: present file whose hash could not be computed.
        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/x".to_string());
        facts.sha256 = None;
        facts.sha256_unhashable = true; // present-but-unhashable

        let v = evaluate(&rules, &empty_sets(), &facts);

        // The sha256hash= constraint must yield NoMatch (not Match/widen), so rule 1
        // allow does NOT fire and rule 2 deny_audit is the decisive match.
        assert_eq!(
            v.decision,
            Decision::DenyAudit,
            "present-but-unhashable object: sha256hash= must be NoMatch (error-as-denial \
             per rules.c:1606-1611), rule 1 allow must NOT fire, rule 2 deny_audit decides"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (deny_audit catch-all) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "sha256_unhashable is a decisive NoMatch, not uncertain"
        );
    }

    /// Absent object (`sha256=None`, `sha256_unhashable=false`) WIDENS to Match:
    /// the `sha256hash=` constraint is SKIPPED (rules.c:1572-1575), so the
    /// `allow` rule fires.
    ///
    /// This is the contrast case for `unhashable_object_yields_nomatch_at_evaluator_layer`:
    /// together they pin the absent(false)-vs-unhashable(true) distinction at the
    /// evaluator layer, uid-independent.
    #[test]
    fn absent_object_hash_widens_sha256hash_constraint() {
        let all_zeros = "0".repeat(64);
        let rules = vec![
            rule(
                Decision::Allow,
                Some(Perm::Open),
                vec![Attr::All],
                vec![kv("sha256hash", &all_zeros)],
            ),
            rule(
                Decision::DenyAudit,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        // AccessFacts: sha256 absent AND sha256_unhashable=false (object simply absent).
        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/x".to_string());
        facts.sha256 = None;
        facts.sha256_unhashable = false; // truly absent, not unhashable

        let v = evaluate(&rules, &empty_sets(), &facts);

        // Absent fact widens: sha256hash= constraint is skipped (Match), so rule 1
        // allow fires.
        assert_eq!(
            v.decision,
            Decision::Allow,
            "absent sha256 (sha256_unhashable=false) must WIDEN the sha256hash= constraint \
             (rules.c:1572-1575 skip/widen), so rule 1 allow fires"
        );
        assert_eq!(
            v.matched_rule,
            Some(1),
            "rule 1 (allow) fires because the absent sha256 widens the sha256hash= constraint"
        );
        assert_eq!(v.source, Source::Rule, "rule 1 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "absent-object widening is decisive, not uncertain"
        );
    }

    // -----------------------------------------------------------------------
    // #136: bare `dir=untrusted` is the DIR-field TRUST MACRO (full exe= parity).
    //
    // Ground truth (f1 grounding §2.2 line 216; upstream rules.c dir= case;
    // fapolicyd >=1.4.x): like `exe=untrusted`, a bare `dir=untrusted` value
    // in the SUBJECT dir= field is the trust macro, NOT a literal prefix to
    // compare against the exe path. It matches IFF the subject is NOT trusted
    // (`subj_trust=No`); `subj_trust=Yes` -> NoMatch (no fire); and
    // `subj_trust=Unknown` downgrades to NotEvaluable (same as exe=untrusted
    // and trust=0).
    //
    // On CURRENT code the dir= arm falls through to `prefix_string_match`,
    // which for the bare `Str("untrusted")` case returns `NotEvaluable`
    // unconditionally (prefix_string_match:L162: the `"untrusted"` branch
    // returns `FieldEval::NotEvaluable` regardless of trust state). So:
    //   - `subj_trust=No` -> currently NotEvaluable (should be Match/Deny) RED
    //   - `subj_trust=Yes` -> currently NotEvaluable (should be NoMatch/Allow)
    //     the current verdict is uncertain Allow; the test expects decisive Allow
    //   - `subj_trust=Unknown` -> currently NotEvaluable (correct outcome,
    //     wrong reason - the current impl has no trust DB consultation, so the
    //     reason string differs from the expected but the overall verdict is
    //     the same; this test asserts uncertain.is_some() which IS currently
    //     true, but the fix must preserve it with proper trust-DB reasoning)
    //
    // The No and Yes cases are definitively RED on current code.
    // -----------------------------------------------------------------------

    /// `dir=untrusted` FIRES for an untrusted subject (`subj_trust=No`).
    ///
    /// Ground truth: f1 grounding §2.2 line 216; in fapolicyd 1.4.x and later
    /// the dir= arm treats `untrusted` as the SUBJECT trust macro (same as
    /// `exe=untrusted`). It matches IFF the subject is NOT in the trust DB.
    ///
    /// Current code: `prefix_string_match` returns `NotEvaluable` for a bare
    /// `dir=untrusted` value regardless of trust state (`prefix_string_match`
    /// line ~162). So the deny rule becomes a `PossibleMatch`; the ruleset falls
    /// through to the allow -> verdict is Allow. This assertion (`Deny`) is RED.
    #[test]
    fn dir_untrusted_macro_matches_untrusted_subject() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("dir", "untrusted")],
            vec![Attr::All],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/home/user/payload".to_string());
        facts.subj_trust = Trust::No;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "dir=untrusted must FIRE the deny rule for an untrusted subject (trust macro, \
             not a literal prefix compare)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=No is decisive, not uncertain"
        );
    }

    /// `dir=untrusted` does NOT fire for a trusted subject (`subj_trust=Yes`).
    ///
    /// Ground truth: same as above (f1 §2.2 line 216). When the subject IS
    /// trusted, the `untrusted` macro is a decisive `NoMatch` -> the deny rule
    /// is skipped -> fallthrough Allow, uncertain=None.
    ///
    /// Current code: `prefix_string_match` returns `NotEvaluable` for bare
    /// `dir=untrusted`, so the deny rule becomes a `PossibleMatch`; the verdict
    /// is the allow rule but `uncertain` is set. This test asserts
    /// `uncertain.is_none()` (a decisive `NoMatch`, not uncertain). RED on
    /// current code because `NotEvaluable` sets `uncertain`.
    #[test]
    fn dir_untrusted_macro_no_match_trusted_subject() {
        use crate::facts::Trust;

        // Single deny rule (no allow fallback): if the deny fires wrongly we get
        // Deny; if it correctly doesn't fire we get the implicit fallthrough Allow.
        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![kv("dir", "untrusted")],
            vec![Attr::All],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.exe = Some("/usr/bin/cat".to_string());
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "dir=untrusted must NOT fire for a trusted subject -> fallthrough Allow"
        );
        assert_eq!(v.source, Source::Fallthrough, "no rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=Yes makes the macro a decisive NoMatch, not uncertain"
        );
    }

    /// `dir=untrusted` with `subj_trust=Unknown` is `NotEvaluable` (no trust DB).
    ///
    /// Ground truth: same as exe=untrusted Unknown (f1 §2.2 line 216; the
    /// simulate confidence-downgrade on Unknown trust applies to the dir= macro
    /// just as it does for exe= and trust=). The deny rule downgrades to a
    /// `PossibleMatch`; the verdict is the rule-2 Allow but `uncertain` is set.
    ///
    /// Current code ALSO returns `NotEvaluable` via `prefix_string_match` for
    /// bare `dir=untrusted` when trust is Unknown (though for the wrong reason -
    /// it never consults trust state at all). The overall outcome (uncertain=Some)
    /// is currently correct but must remain so after the fix switches to the
    /// proper trust-state-aware path.
    #[test]
    fn dir_untrusted_macro_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv("dir", "untrusted")],
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
            "dir=untrusted with Unknown trust must downgrade to an uncertain verdict, \
             mirroring exe=untrusted (f1 §2.2 line 216)"
        );
    }

    // -----------------------------------------------------------------------
    // #136: `dir=%set` where the set CONTAINS the `untrusted` macro token.
    //
    // This is the DIR-field analogue of the EXE SetRef fix landed in PR #135
    // (issue #126). Real fapolicyd's DIR case also honours the `untrusted`
    // macro when a %set contains it (f1 §1.4 line 166: the EXE_DIR dir=
    // subject field uses prefix match AND honours the deprecated `untrusted`
    // macro; f1 §2.2 line 216: dir=untrusted is trust-DB-dependent). So the
    // DIR match for a set containing `untrusted` is:
    //   (set contains "untrusted" AND subject NOT trusted)
    //   OR
    //   (exe path is a PREFIX of a literal set member)
    //
    // The fix (PR #136) adds `eval_dir_setref_with_untrusted_macro` (the exact
    // analogue of `eval_exe_setref_with_untrusted_macro`) and restructures the
    // subject dir= arm to mirror the exe= arm: bare `dir=untrusted` goes to
    // `eval_trust_field`; a SetRef containing "untrusted" goes to the new helper;
    // all other values (prefix literals, execdirs/systemdirs, sets without the
    // macro) fall through to the existing `prefix_string_match` path unchanged.
    //
    // The macro path mirrors the bare `dir=untrusted` Trust::Unknown ->
    // NotEvaluable downgrade when the macro is the deciding factor (no literal
    // prefix matched), mirroring how the exe= SetRef arm works.
    // -----------------------------------------------------------------------

    /// Set `%dirs = {"untrusted", "/tmp/"}`, rule 1 `deny perm=any dir=%dirs :
    /// all`, rule 2 `allow perm=any all : all`. Subject is untrusted
    /// (`subj_trust=No`) and its exe is NOT prefixed by any literal member
    /// (`/home/user/payload`, not under `/tmp/`).
    ///
    /// Expected: decisive Deny at rule 1. The embedded `untrusted` macro must
    /// FIRE because the set contains "untrusted" AND `subj_trust=No`.
    ///
    /// Grounding: f1 §1.4 line 166 (`EXE_DIR`: `untrusted` macro OR'd with
    /// prefix match) + f1 §2.2 line 216 (dir=untrusted is trust-DB-dependent).
    #[test]
    fn dir_setref_with_untrusted_member_fires_for_untrusted_subject() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("dirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("dir", "dirs")],
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
        facts.exe = Some("/home/user/payload".to_string()); // NOT under /tmp/
        facts.subj_trust = Trust::No;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "set %dirs contains the `untrusted` macro and the subject is untrusted: \
             the deny rule must FIRE via the macro (exe not under any literal prefix member)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=No is decisive, not uncertain"
        );
    }

    /// Same `%dirs = {"untrusted", "/tmp/"}`, but the subject IS trusted and
    /// its exe is NOT under a literal prefix member: the macro must NOT fire
    /// (trusted) AND there is no literal prefix match -> the deny rule is
    /// skipped and the ruleset falls through to the rule-2 Allow.
    ///
    /// An impl that fires the macro regardless of trust state would wrongly
    /// Deny here. This test stays GREEN on the current code (prefix match
    /// -> `NoMatch`, fallthrough Allow) but would go RED for an over-broad fix
    /// that always fires the macro.
    #[test]
    fn dir_setref_with_untrusted_member_no_fire_for_trusted_subject() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("dirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("dir", "dirs")],
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
        facts.exe = Some("/home/user/trusted_app".to_string()); // NOT under /tmp/
        facts.subj_trust = Trust::Yes;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "trusted subject + exe not under any literal prefix member: macro does NOT fire \
             and there is no literal match, so the deny rule is skipped and the verdict is \
             the rule-2 Allow"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (allow) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "subj_trust=Yes + literal prefix NoMatch is decisive, not uncertain"
        );
    }

    /// Same `%dirs = {"untrusted", "/tmp/"}`, subject trust Unknown, exe NOT
    /// under a literal prefix member: the embedded `untrusted` macro is the
    /// deciding factor and trust is unknown -> `NotEvaluable` downgrade.
    ///
    /// Grounding: f1 §1.4 line 166 + f1 §2.2 line 216. This mirrors the bare
    /// `dir=untrusted` Unknown behaviour (now also fixed in PR #136) and the
    /// exe= `SetRef` analogue (`exe_setref_with_untrusted_member_unknown_trust_is_uncertain`).
    /// The deny rule (rule 1) downgrades to a possible match; the verdict is
    /// the rule-2 Allow but `uncertain` is set.
    ///
    /// `eval_dir_setref_with_untrusted_macro` routes the deciding macro leg
    /// through `eval_trust_field`, which returns `NotEvaluable` for `Unknown`
    /// with the same "subj trust unknown (no trust DB)" reason string.
    #[test]
    fn dir_setref_with_untrusted_member_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("dirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("dir", "dirs")],
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
        facts.exe = Some("/home/user/payload".to_string()); // NOT under /tmp/
        facts.subj_trust = Trust::Unknown;
        let v = evaluate(&rules, &sets, &facts);
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
            "dir=%dirs (set contains `untrusted`) with Unknown trust and no literal prefix \
             match must downgrade to an uncertain verdict, mirroring bare dir=untrusted"
        );
    }

    /// Set `%dirs = {"untrusted", "/usr/"}`, subject IS trusted, exe IS under
    /// the literal prefix `/usr/` (`/usr/bin/cat`): the literal PREFIX match
    /// fires regardless of trust state.
    ///
    /// This guards that the fix does not break ordinary `dir=` prefix semantics:
    /// a literal prefix member still matches by prefix even when the set also
    /// contains the `untrusted` token. The literal leg must be OR-ed
    /// independently of the macro, exactly as the `exe=` `SetRef` fix works.
    ///
    /// Should remain GREEN on current code (prefix match -> Match, Deny).
    /// Would go RED if a wrong fix only activates when `subj_trust=No`.
    #[test]
    fn dir_setref_literal_prefix_member_matches_regardless_of_trust() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("dirs", &["untrusted", "/usr/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("dir", "dirs")],
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
        facts.exe = Some("/usr/bin/cat".to_string()); // IS under /usr/ -> literal prefix match
        facts.subj_trust = Trust::Yes; // trusted, macro does NOT fire for trusted
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "exe `/usr/bin/cat` is under the prefix `/usr/` in %dirs: the literal-prefix \
             membership match must fire independently of trust (subject is trusted, the \
             `untrusted` macro does NOT fire)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(
            v.source,
            Source::Rule,
            "a decisive literal-prefix-membership match"
        );
        assert!(
            v.uncertain.is_none(),
            "a literal-prefix match is decisive, not uncertain"
        );
    }

    /// Negative guard: set `%safedirs = {"/usr/", "/bin/"}` has NO `untrusted`
    /// member. A rule `deny perm=any dir=%safedirs : all` must NOT become
    /// `NotEvaluable` when `subj_trust=No`: it is ordinary prefix matching.
    ///
    /// This guards against an over-broad fix that marks any `dir=%set` as
    /// potentially-macro-enabled. The result must be an ordinary `NoMatch` (or
    /// `Match`) based solely on the exe prefix, not uncertain.
    ///
    /// Exe is `/home/user/thing` -> NOT under /usr/ or /bin/ -> `NoMatch` ->
    /// the deny rule is skipped, rule 2 allow fires, verdict is Allow.
    ///
    /// Should remain GREEN on current code (no untrusted member, pure prefix
    /// semantics). Would go RED if a wrong fix treats every dir=%set with any
    /// member as potentially untrusted-macro-aware.
    #[test]
    fn dir_setref_without_untrusted_member_does_not_become_not_evaluable() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("safedirs", &["/usr/", "/bin/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_ref("dir", "safedirs")],
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
        facts.exe = Some("/home/user/thing".to_string()); // NOT under /usr/ or /bin/
        facts.subj_trust = Trust::No;
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "set %safedirs has no `untrusted` member: the dir= constraint is a pure prefix \
             match; exe not under any prefix -> NoMatch -> rule 1 deny skipped, rule 2 allow \
             fires"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (allow) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "a pure prefix NoMatch (no untrusted macro involved) is decisive, not uncertain"
        );
    }

    // -----------------------------------------------------------------------
    // OBJECT-SIDE dir=untrusted parity (issue #136 follow-up).
    //
    // Ground truth: upstream rules.c ODIR case honours the `untrusted` macro
    // against OBJECT trust (`!is_obj_trusted(e)`), NOT subject trust.
    // f1 grounding §1.4 line 174 (dir/odir object: same macro as subject dir)
    // + f1 §2.2 line 216 (trust-DB-dependent).
    //
    // In the MODERN fapolicyd grammar, object-side `dir=untrusted` appears as a
    // post-colon attribute in `Rule.object`. The evaluator routes it through
    // `eval_object_field`, whose `dir=` arm (eval_object_field:~L530-536)
    // currently does a plain `prefix_string_match(facts.path, ...)`. For the
    // bare string "untrusted", `prefix_string_match` returns `NotEvaluable` no
    // matter what `obj_trust` is. So:
    //   - `obj_trust=No`      -> currently NotEvaluable (should be Match/Deny)  RED
    //   - `obj_trust=Yes`     -> currently NotEvaluable (should be NoMatch/Allow) RED
    //   - `obj_trust=Unknown` -> currently NotEvaluable (correct outcome, now for
    //                            the right reason after the fix)
    //
    // These tests are RED on the 0677e98 base (subject fix only, no object fix).
    // -----------------------------------------------------------------------

    /// OBJECT `dir=untrusted` must NOT fire for a TRUSTED object (`obj_trust=Yes`).
    ///
    /// Rule: `deny perm=any all : dir=untrusted` (object side).
    /// Facts: `path=Some("/usr/bin/cat")`, `obj_trust=Trust::Yes`.
    ///
    /// Expected: `decision=Allow` (fallthrough), `source=Fallthrough`, `uncertain=None`.
    ///
    /// Current code: `prefix_string_match(path, "untrusted")` returns
    /// `NotEvaluable` unconditionally, so the deny rule downgrades to
    /// `PossibleMatch` regardless of trust. There is no second rule so the
    /// verdict is Allow but `uncertain` IS set. This test asserts
    /// `uncertain.is_none()` (a decisive `NoMatch`) -> RED.
    #[test]
    fn object_dir_untrusted_macro_no_fire_for_trusted_object() {
        use crate::facts::Trust;

        let rules = vec![rule(
            Decision::Deny,
            Some(Perm::Any),
            vec![Attr::All],
            vec![kv("dir", "untrusted")],
        )];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/usr/bin/cat".to_string());
        facts.obj_trust = Trust::Yes;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "object dir=untrusted must NOT fire for a trusted object -> fallthrough Allow"
        );
        assert_eq!(v.source, Source::Fallthrough, "no rule matched");
        assert!(
            v.uncertain.is_none(),
            "obj_trust=Yes makes the object untrusted macro a decisive NoMatch, not uncertain: \
             {:?}",
            v.uncertain
        );
    }

    /// OBJECT `dir=untrusted` FIRES for an UNTRUSTED object (`obj_trust=No`).
    ///
    /// Rule: `deny perm=any all : dir=untrusted` (object side).
    /// Facts: `path=Some("/tmp/payload")`, `obj_trust=Trust::No`.
    ///
    /// Expected: `decision=Deny`, `matched_rule=Some(1)`, `uncertain=None`.
    ///
    /// Current code: `NotEvaluable` is returned from `prefix_string_match`,
    /// but with a single rule + no second rule the verdict is Allow (fallthrough
    /// after `PossibleMatch`). A deny rule with no follow-up rule means the deny
    /// is still possible. Let us mirror the subject tests more faithfully: add a
    /// second `allow all : all` rule so the `PossibleMatch` -> uncertain path is
    /// distinguishable from the decisive-Deny path. With a second rule present:
    ///   - CORRECT (after fix): rule 1 decisively Deny (`obj_trust=No` -> Match).
    ///   - WRONG (pre-fix): rule 1 `PossibleMatch`, rule 2 decisive Allow,
    ///     `decision=Allow`, `uncertain=Some` -> both assertions below fail.
    #[test]
    fn object_dir_untrusted_macro_fires_for_untrusted_object() {
        use crate::facts::Trust;

        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv("dir", "untrusted")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/tmp/payload".to_string());
        facts.obj_trust = Trust::No;
        let v = evaluate(&rules, &empty_sets(), &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "object dir=untrusted must FIRE the deny rule for an untrusted object \
             (trust macro against obj_trust, not a literal prefix compare)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "obj_trust=No is decisive, not uncertain"
        );
    }

    /// OBJECT `dir=untrusted` with `obj_trust=Unknown` is `NotEvaluable`.
    ///
    /// Rules: rule 1 `deny perm=any all : dir=untrusted`,
    ///        rule 2 `allow perm=any all : all`.
    /// Facts: `path=Some("/tmp/payload")`, `obj_trust=Trust::Unknown`.
    ///
    /// Expected: `decision=Allow`, `matched_rule=Some(2)`, `uncertain=Some(...)`.
    ///
    /// Current code returns the same overall verdict shape (uncertain Allow) but
    /// for the wrong reason; after the fix the uncertain reason must reflect
    /// obj-trust-unknown, not a generic `"untrusted is NotEvaluable"` from
    /// `prefix_string_match`. This test just asserts `uncertain.is_some()`,
    /// which is currently true but must remain so with the correct trust path.
    #[test]
    fn object_dir_untrusted_macro_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv("dir", "untrusted")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/tmp/payload".to_string());
        facts.obj_trust = Trust::Unknown;
        let v = evaluate(&rules, &empty_sets(), &facts);
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
            "object dir=untrusted with Unknown obj_trust must downgrade to an uncertain verdict, \
             mirroring the subject-side dir=untrusted Unknown behaviour"
        );
    }

    // -----------------------------------------------------------------------
    // OBJECT-SIDE `dir=%set` containing the `untrusted` macro token.
    //
    // Mirrors the subject-side `dir_setref_with_untrusted_member_*` tests above,
    // but targets `eval_object_field`'s `dir=` arm (object path = facts.path,
    // trust = facts.obj_trust). The set `%objdirs = {"untrusted", "/tmp/"}`.
    //
    // On current 0677e98 code, `eval_object_field`'s dir= arm unconditionally
    // calls `prefix_string_match(facts.path, value, sets)`. For a SetRef
    // containing "untrusted", `prefix_string_match` iterates set members,
    // encounters "untrusted" as a string that is NOT a keyword, tests
    // `/tmp/payload`.starts_with("untrusted") = false, then moves on. So for
    // path="/tmp/payload" (NOT under /tmp/) the result is NoMatch, not the
    // expected macro fire. These tests expose that bug.
    // -----------------------------------------------------------------------

    /// Set `%objdirs = {"untrusted", "/tmp/"}`, rule `deny perm=any all :
    /// dir=%objdirs`. Object `path="/tmp/x"` IS under `"/tmp/"`, `obj_trust=Trust::Yes`.
    ///
    /// Expected: decisive Deny (literal prefix match fires regardless of trust).
    /// This is the literal-leg guard: even though the set contains `untrusted`,
    /// a literal prefix member still matches by prefix independently.
    ///
    /// Should be GREEN on current code (prefix match under `"/tmp/"` -> Match).
    /// Included to anchor that the fix does NOT break ordinary prefix matching.
    #[test]
    fn object_dir_setref_literal_prefix_member_matches_regardless_of_obj_trust() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("objdirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv_ref("dir", "objdirs")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/tmp/x".to_string()); // IS under /tmp/ -> literal prefix match
        facts.obj_trust = Trust::Yes; // trusted; macro must NOT fire for trusted
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "object path /tmp/x is under literal prefix /tmp/ in %objdirs: \
             the deny rule must FIRE via the literal-prefix leg, trust-independently"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive literal-prefix match");
        assert!(
            v.uncertain.is_none(),
            "a literal-prefix match is decisive, not uncertain"
        );
    }

    /// Set `%objdirs = {"untrusted", "/tmp/"}`, object `path="/home/x"` (NOT under
    /// `/tmp/`), `obj_trust=Trust::No`.
    ///
    /// Expected: decisive Deny at rule 1 (the embedded `untrusted` macro FIRES
    /// because the set contains `"untrusted"` AND `obj_trust=No`).
    ///
    /// Current code: `prefix_string_match` treats `"untrusted"` as a plain prefix
    /// literal, tests `"/home/x".starts_with("untrusted")` = false, then `/tmp/`
    /// -> `"/home/x".starts_with("/tmp/")` = false -> `NoMatch` -> rule 1 skipped
    /// -> rule 2 Allow. This test asserts Deny -> RED on 0677e98.
    #[test]
    fn object_dir_setref_with_untrusted_member_fires_for_untrusted_object() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("objdirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv_ref("dir", "objdirs")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/home/x".to_string()); // NOT under /tmp/
        facts.obj_trust = Trust::No; // untrusted object -> macro must fire
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Deny,
            "set %objdirs contains the `untrusted` macro and the object is untrusted: \
             the deny rule must FIRE via the macro (path not under any literal prefix member)"
        );
        assert_eq!(v.matched_rule, Some(1), "the deny rule is rule 1");
        assert_eq!(v.source, Source::Rule, "a decisive rule matched");
        assert!(
            v.uncertain.is_none(),
            "obj_trust=No is decisive, not uncertain"
        );
    }

    /// Set `%objdirs = {"untrusted", "/tmp/"}`, object `path="/home/x"` (NOT under
    /// `/tmp/`), `obj_trust=Trust::Yes`.
    ///
    /// Expected: `decision=Allow`, `matched_rule=Some(2)`, `uncertain=None`.
    /// (Trusted object -> macro does NOT fire; no literal prefix match either.)
    ///
    /// Current code: already returns Allow (via `NoMatch` from `prefix_string_match`)
    /// with `uncertain=None`. This test stays GREEN on current code but would go
    /// RED for an over-broad fix that always fires the macro.
    #[test]
    fn object_dir_setref_with_untrusted_member_no_fire_for_trusted_object() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("objdirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv_ref("dir", "objdirs")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/home/x".to_string()); // NOT under /tmp/
        facts.obj_trust = Trust::Yes; // trusted -> macro does NOT fire
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "trusted object + path not under any literal prefix member: macro does NOT fire \
             and there is no literal match, so the deny rule is skipped, rule 2 allow fires"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (allow) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "obj_trust=Yes + literal-prefix NoMatch is decisive, not uncertain"
        );
    }

    /// Set `%objdirs = {"untrusted", "/tmp/"}`, object `path="/home/x"` (NOT under
    /// `/tmp/`), `obj_trust=Trust::Unknown`.
    ///
    /// Expected: `decision=Allow`, `matched_rule=Some(2)`, `uncertain=Some(...)`.
    /// (The embedded macro is the deciding factor; trust is unknown ->
    /// `NotEvaluable` downgrade, mirroring the bare `dir=untrusted` Unknown case.)
    ///
    /// Current code ALSO returns `uncertain=Some` (because `prefix_string_match`
    /// returns `NoMatch` for the literal `"untrusted"` prefix, then `NoMatch` for
    /// `"/tmp/"` -> overall `NoMatch`, not `NotEvaluable`). Actually wait - let me
    /// think again: `prefix_string_match` for a `SetRef` iterates members. For
    /// member `"untrusted"`: it is not a keyword (execdirs/systemdirs), so the
    /// code does `fact_path.starts_with("untrusted")` = false. For member
    /// `"/tmp/"`: `"/home/x".starts_with("/tmp/")` = false. Returns `NoMatch`.
    /// So the rule is `NoMatch` -> rule 2 Allow. `uncertain=None`. But the test
    /// EXPECTS `uncertain=Some`. -> RED on 0677e98.
    #[test]
    fn object_dir_setref_with_untrusted_member_unknown_trust_is_uncertain() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("objdirs", &["untrusted", "/tmp/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv_ref("dir", "objdirs")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/home/x".to_string()); // NOT under /tmp/
        facts.obj_trust = Trust::Unknown; // unknown -> NotEvaluable downgrade
        let v = evaluate(&rules, &sets, &facts);
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
            "object dir=%objdirs (set contains `untrusted`) with Unknown obj_trust and no \
             literal prefix match must downgrade to an uncertain verdict, mirroring the \
             subject-side SetRef Unknown behaviour"
        );
    }

    /// OBJECT `dir=%set` where the set has NO `untrusted` member must NOT fire
    /// the untrusted macro, even when the object is untrusted (`obj_trust=No`).
    ///
    /// This is the object-side analog of
    /// `dir_setref_without_untrusted_member_does_not_become_not_evaluable` (the
    /// subject-side guard at `eval_subject_field`'s `dir=` arm). It targets the
    /// guard at `eval_object_field`'s `dir=` arm, line 559:
    ///   `None if set_contains_untrusted(value, sets) => { ... }`
    ///
    /// If that guard is mutated to `true`, EVERY object `SetRef` routes to the
    /// macro helper. For `obj_trust=No` the macro fires -> rule 1 Deny. The
    /// correct code takes the `_` arm (pure prefix match), the path is NOT under
    /// any prefix in the set -> `NoMatch` -> rule 1 skipped -> rule 2 Allow.
    ///
    /// Set: `%safedirs = {"/usr/", "/bin/"}` (no `untrusted` member).
    /// Rule 1: `deny perm=any all : dir=%safedirs`.
    /// Rule 2: `allow perm=any all : all`.
    /// Facts: `path=Some("/home/user/thing")` (NOT under `/usr/` or `/bin/`),
    ///        `obj_trust=Trust::No` (key: untrusted object).
    ///
    /// Expected: `decision=Allow`, `matched_rule=Some(2)`, `source=Rule`,
    ///           `uncertain=None` (decisive `NoMatch`, no macro involved).
    ///
    /// Kills the mutant: `replace match guard set_contains_untrusted(value, sets)
    /// with true in eval_object_field` (line 559).
    #[test]
    fn object_dir_setref_without_untrusted_member_does_not_become_not_evaluable() {
        use crate::facts::Trust;

        let sets = SetTable::from_entries(&[set_def("safedirs", &["/usr/", "/bin/"])]);
        let rules = vec![
            rule(
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv_ref("dir", "safedirs")],
            ),
            rule(
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            ),
        ];

        let mut facts = AccessFacts::new(Perm::Open);
        facts.path = Some("/home/user/thing".to_string()); // NOT under /usr/ or /bin/
        facts.obj_trust = Trust::No; // untrusted object: macro would fire if guard wrong
        let v = evaluate(&rules, &sets, &facts);
        assert_eq!(
            v.decision,
            Decision::Allow,
            "set %safedirs has no `untrusted` member: the dir= constraint is a pure prefix \
             match on the object path; path not under any prefix -> NoMatch -> rule 1 deny \
             skipped, rule 2 allow fires"
        );
        assert_eq!(
            v.matched_rule,
            Some(2),
            "rule 2 (allow) is the decisive match"
        );
        assert_eq!(v.source, Source::Rule, "rule 2 is a decisive match");
        assert!(
            v.uncertain.is_none(),
            "a pure prefix NoMatch (no untrusted macro involved) is decisive, not uncertain"
        );
    }
}
