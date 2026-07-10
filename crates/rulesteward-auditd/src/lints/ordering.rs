//! Ordering and reachability lints over the concatenated `rules.d/` stream.
//!
//! Pipeline P2 (#193):
//! * au-W02 - shadowed rule: an earlier rule (in EFFECTIVE load order,
//!   including `-A` prepend head-insertion) subsumes a later rule on the same
//!   filter list: syscall superset, and every earlier field predicate IMPLIED
//!   BY a later predicate on the same field (#219 interval-aware implication via
//!   [`crate::lints::value::implies`], superseding the v1 structural-only D4).
//!   Pairs that are exactly canonical-equal are au-W01 (P1) and MUST be skipped
//!   here (owner decision D2: skip when `canonical_key(a) == canonical_key(b)`).
//! * au-E01 - unreachable rule after the `-e 2` lock: any rule appearing
//!   after the lock line in the concatenated lexical stream never loads
//!   (`auditctl(8)`: `-e 2` makes the config immutable until reboot).
//! * au-W03 - exclude/never suppression conflict: an `exclude`-list (msgtype)
//!   or `never`-action rule suppresses events an `always` rule intends to
//!   record.
//! * au-W04 (stretch, owner decision D6) - `-D` after non-control rules
//!   discards previously loaded rules; the standard layout (`-D` at the top
//!   of the first file) must not fire. NOT implemented in v1 (cuttable per D6;
//!   its barrier tests are `#[cfg(any())]`-gated until enabled).
//!
//! # Effective vs lexical order
//! au-W02 and au-W03 reason about EFFECTIVE kernel order. `-A` sets
//! `AUDIT_FILTER_PREPEND` (`linux/audit.h:185`, set by `auditctl.c:864`,
//! audit 3bfa048), inserting the rule at the HEAD of its filter list. Each
//! prepend goes before the previous one, so within a list the effective order
//! is `reverse(prepends in stream order) ++ (appends in stream order)`. Built
//! globally in [`effective_syscall_rules`]: because every list's prepends
//! still precede its appends and keep their reversed relative order, the
//! within-list relative order needed for same-list comparison is preserved.
//! au-E01 instead uses raw STREAM order: the `-e 2` lock takes effect at load
//! time, sequentially, so any rule auditctl processes after it fails with
//! EPERM regardless of where a `-A` would have placed it in the kernel list.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{
    Action, AuditField, AuditRule, ControlRule, FieldComparison, FieldFilter, FilterList,
    LocatedRule,
};
use crate::lints::field_type::field_type;
use crate::lints::normalize::canonical_key;
use crate::lints::value::{LintOptions, canonical_value, disjoint, implies};

use super::anchored;

/// The comparable components of a syscall rule, borrowed for structural
/// subsumption / overlap analysis. `None` for control and watch rules (which
/// do not participate in syscall-list ordering lints).
struct SyscallParts<'a> {
    list: &'a FilterList,
    action: &'a Action,
    syscalls: &'a [String],
    fields: &'a [FieldFilter],
    field_compares: &'a [FieldComparison],
}

/// Borrow a rule's syscall components, or `None` if it is not a syscall rule.
fn syscall_parts(rule: &AuditRule) -> Option<SyscallParts<'_>> {
    match rule {
        AuditRule::Syscall {
            list,
            action,
            syscalls,
            fields,
            field_compares,
            ..
        } => Some(SyscallParts {
            list,
            action,
            syscalls,
            fields,
            field_compares,
        }),
        AuditRule::Control(_) | AuditRule::Watch { .. } => None,
    }
}

/// The syscall rules in EFFECTIVE kernel order (see the module doc): all
/// prepend (`-A`) rules in reversed stream order, then all append (`-a`) rules
/// in stream order. Control and watch rules are excluded (they do not sit on a
/// syscall filter list).
fn effective_syscall_rules(rules: &[LocatedRule]) -> Vec<&LocatedRule> {
    let mut prepends: Vec<&LocatedRule> = rules
        .iter()
        .filter(|lr| matches!(&lr.rule, AuditRule::Syscall { prepend: true, .. }))
        .collect();
    prepends.reverse();
    let appends = rules
        .iter()
        .filter(|lr| matches!(&lr.rule, AuditRule::Syscall { prepend: false, .. }));
    prepends.into_iter().chain(appends).collect()
}

/// True when `earlier` matches a SUPERSET of `later`'s syscalls. An empty
/// syscall set means "no `-S`", which matches every syscall (a superset of any
/// set); a non-empty `earlier` cannot cover an empty (wildcard) `later`.
fn syscall_superset(earlier: &[String], later: &[String]) -> bool {
    if earlier.is_empty() {
        return true;
    }
    if later.is_empty() {
        return false;
    }
    later.iter().all(|s| earlier.contains(s))
}

/// True when every `earlier` predicate is IMPLIED BY some `later` predicate on
/// the same field (#219): `later`'s matched value-set is a subset of
/// `earlier`'s, so `earlier` is the broader (less constrained) rule. Implication
/// covers exact match, folded-equal values, broader relational thresholds, and a
/// relational range containing a later `=` point (see
/// [`crate::lints::value::implies`]); Ne/bitmask/opaque operands match only
/// exactly. Multiplicity is ignored; real rules carry distinct predicates.
fn fields_subset(earlier: &[FieldFilter], later: &[FieldFilter], opts: LintOptions) -> bool {
    earlier
        .iter()
        .all(|pe| later.iter().any(|pl| implies(pe, pl, opts)))
}

/// As [`fields_subset`] for `-C` inter-field comparisons.
fn compares_subset(earlier: &[FieldComparison], later: &[FieldComparison]) -> bool {
    earlier.iter().all(|c| later.contains(c))
}

/// Subsumption (#219): `earlier` matches a superset of `later`'s traffic - a
/// broader syscall set AND every earlier field predicate implied by a later one
/// (interval-aware, so `auid>=1000` subsumes `auid>=2000`). `-C` inter-field
/// comparisons still match exactly.
fn subsumes(earlier: &SyscallParts, later: &SyscallParts, opts: LintOptions) -> bool {
    syscall_superset(earlier.syscalls, later.syscalls)
        && fields_subset(earlier.fields, later.fields, opts)
        && compares_subset(earlier.field_compares, later.field_compares)
}

/// True when two same-list rules can match overlapping traffic. Syscall sets
/// must intersect (empty = wildcard matches all). Two rules are DISJOINT when a
/// shared field carries provably non-co-matching predicates (#219, via
/// [`crate::lints::value::disjoint`]): contradictory equality (with uid/gid
/// value folding) or non-overlapping numeric intervals. Because all `-F`
/// predicates must match together, a single disjoint field means the rules
/// cannot co-match. Anything not provably disjoint is conservatively treated as
/// overlapping, so au-W03 never drops a real suppression warning.
fn traffic_overlaps(a: &SyscallParts, b: &SyscallParts, opts: LintOptions) -> bool {
    let syscalls_intersect = a.syscalls.is_empty()
        || b.syscalls.is_empty()
        || a.syscalls.iter().any(|s| b.syscalls.contains(s));
    if !syscalls_intersect {
        return false;
    }
    let field_disjoint = a
        .fields
        .iter()
        .any(|fa| b.fields.iter().any(|fb| disjoint(fa, fb, opts)));
    !field_disjoint
}

/// True for an exclude-list rule that suppresses the SYSCALL (1300) record
/// type: `-a always,exclude -F msgtype=1300` (or the symbolic `msgtype=SYSCALL`).
/// Every exit-list syscall rule produces SYSCALL records, so such an exclude
/// silently swallows their output.
///
/// The ACTION is NOT checked: on the exclude filter the action is ignored and
/// defaults to `never` (`man auditctl`: "The action is ignored and uses its
/// default of 'never'"; `man 7 audit.rules` likewise). So `never,exclude`,
/// `always,exclude`, and `exclude,always` all suppress the named msgtype
/// identically -- the auditctl EXAMPLES use them interchangeably.
fn is_syscall_suppressing_exclude(rule: &AuditRule, opts: LintOptions) -> bool {
    let Some(p) = syscall_parts(rule) else {
        return false;
    };
    *p.list == FilterList::Exclude
        && p.fields.iter().any(|f| {
            // The SYSCALL<->1300 knowledge lives in canonical_value (#227): it
            // folds the symbolic name, the number, and base-0 spellings (#229,
            // e.g. 0x514) to "1300". Centralizing it here keeps the one source.
            f.field == AuditField::MsgType
                && canonical_value(field_type(&f.field), &f.value, opts) == "1300"
        })
}

/// au-W02 shadow/subsumption pass.
///
/// For each later rule (in effective order), emit one Warning if an earlier
/// same-list, same-action rule structurally subsumes it (D4) and the pair is
/// not canonical-equal (D2, which is P1's au-W01). The diagnostic anchors at
/// the shadowed (later) rule and cites the shadowing (earlier) rule's
/// `file:line`.
#[must_use]
pub fn w02(rules: &[LocatedRule], opts: LintOptions) -> Vec<Diagnostic> {
    let eff = effective_syscall_rules(rules);
    let mut diags = Vec::new();
    for j in 0..eff.len() {
        let later = eff[j];
        let Some(lp) = syscall_parts(&later.rule) else {
            continue;
        };
        for &earlier in &eff[..j] {
            let Some(ep) = syscall_parts(&earlier.rule) else {
                continue;
            };
            if ep.list != lp.list || ep.action != lp.action {
                continue;
            }
            // D2: a canonical-equal pair is an au-W01 duplicate, not a shadow.
            if canonical_key(&earlier.rule, opts) == canonical_key(&later.rule, opts) {
                continue;
            }
            if subsumes(&ep, &lp, opts) {
                let msg = format!(
                    "shadowed rule: the broader rule at {}:{} on the same filter list \
                     matches this rule's traffic first (kernel first-match), so it never fires",
                    earlier.file.display(),
                    earlier.line
                );
                diags.push(anchored(
                    Severity::Warning,
                    "au-W02",
                    later.span.clone(),
                    msg,
                    later.file.clone(),
                    later.line,
                ));
                break;
            }
        }
    }
    diags
}

/// au-E01 post-lock unreachable-rule pass.
///
/// `-e 2` (and ONLY `-e 2`, not `-e 0`/`-e 1`) makes the audit config
/// immutable; every rule after the first `-e 2` in the lexical stream never
/// loads. Each such rule gets an Error anchored at itself, citing the lock.
#[must_use]
pub fn e01(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let Some(lock_idx) = rules
        .iter()
        .position(|lr| matches!(&lr.rule, AuditRule::Control(ControlRule::Enable(2))))
    else {
        return Vec::new();
    };
    let lock = &rules[lock_idx];
    let msg = format!(
        "unreachable rule: the -e 2 immutable lock at {}:{} freezes the audit \
         configuration, so no later rule loads",
        lock.file.display(),
        lock.line
    );
    rules[lock_idx + 1..]
        .iter()
        .map(|lr| {
            anchored(
                Severity::Error,
                "au-E01",
                lr.span.clone(),
                msg.clone(),
                lr.file.clone(),
                lr.line,
            )
        })
        .collect()
}

/// au-W03 exclude/never suppression-conflict pass.
///
/// Two suppression mechanisms, both anchored at the suppressed `always` rule:
/// * an exclude-list rule dropping SYSCALL records ([`is_syscall_suppressing_exclude`])
///   swallows every exit-list rule's output regardless of position (the
///   exclude filter runs at record-generation time);
/// * a `never`-action rule earlier in EFFECTIVE order on the SAME list
///   suppresses overlapping traffic before the `always` rule is consulted.
#[must_use]
pub fn w03(rules: &[LocatedRule], opts: LintOptions) -> Vec<Diagnostic> {
    let eff = effective_syscall_rules(rules);
    let syscall_exclude = rules
        .iter()
        .find(|lr| is_syscall_suppressing_exclude(&lr.rule, opts));
    let mut diags = Vec::new();
    for j in 0..eff.len() {
        let later = eff[j];
        let Some(lp) = syscall_parts(&later.rule) else {
            continue;
        };
        if *lp.action != Action::Always {
            continue;
        }
        // Case 2: an earlier never rule on the same list drops overlapping traffic.
        for &earlier in &eff[..j] {
            let Some(ep) = syscall_parts(&earlier.rule) else {
                continue;
            };
            if *ep.action == Action::Never && ep.list == lp.list && traffic_overlaps(&ep, &lp, opts)
            {
                let msg = format!(
                    "suppression conflict: the earlier never rule at {}:{} on the same \
                     filter list drops matching traffic first (kernel first-match)",
                    earlier.file.display(),
                    earlier.line
                );
                diags.push(anchored(
                    Severity::Warning,
                    "au-W03",
                    later.span.clone(),
                    msg,
                    later.file.clone(),
                    later.line,
                ));
                break;
            }
        }
        // Case 1: a global exclude-list SYSCALL suppressor swallows this exit rule.
        if *lp.list == FilterList::Exit
            && let Some(ex) = syscall_exclude
        {
            let msg = format!(
                "suppression conflict: the exclude-list msgtype rule at {}:{} drops the \
                 SYSCALL records this always exit-list rule intends to record",
                ex.file.display(),
                ex.line
            );
            diags.push(anchored(
                Severity::Warning,
                "au-W03",
                later.span.clone(),
                msg,
                later.file.clone(),
                later.line,
            ));
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::{
        LintOptions, SyscallParts, is_syscall_suppressing_exclude, syscall_superset,
        traffic_overlaps, w02, w03,
    };
    use crate::ast::{
        Action, AuditField, AuditRule, CompareOp, FieldComparison, FieldFilter, FilterList,
    };
    use crate::parse_rules_str_located;
    use std::path::Path;

    const OFF: LintOptions = LintOptions {
        include_apparmor: false,
    };

    fn field(name: AuditField, op: CompareOp, value: &str) -> FieldFilter {
        FieldFilter {
            field: name,
            op,
            value: value.to_string(),
        }
    }

    // --- syscall_superset: the empty-set-is-wildcard rule ----------------

    #[test]
    fn empty_earlier_syscalls_is_superset_of_anything() {
        // No `-S` matches every syscall: a superset of any concrete set.
        assert!(syscall_superset(&[], &["execve".into()]));
    }

    #[test]
    fn concrete_earlier_is_not_superset_of_empty_wildcard_later() {
        // A finite set cannot cover "all syscalls".
        assert!(!syscall_superset(&["execve".into()], &[]));
    }

    #[test]
    fn syscall_superset_is_set_containment() {
        assert!(syscall_superset(
            &["open".into(), "close".into()],
            &["open".into()]
        ));
        assert!(!syscall_superset(
            &["open".into()],
            &["open".into(), "close".into()]
        ));
        assert!(!syscall_superset(&["read".into()], &["write".into()]));
    }

    // --- traffic_overlaps: structural disjointness ------------------------

    fn parts<'a>(
        list: &'a FilterList,
        action: &'a Action,
        syscalls: &'a [String],
        fields: &'a [FieldFilter],
        cmps: &'a [FieldComparison],
    ) -> SyscallParts<'a> {
        SyscallParts {
            list,
            action,
            syscalls,
            fields,
            field_compares: cmps,
        }
    }

    #[test]
    fn contradictory_equality_makes_rules_disjoint() {
        // uid=0 vs uid=1000 on the same field: the rules never co-match.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let sc = vec!["execve".to_string()];
        let uid0 = vec![field(AuditField::Uid, CompareOp::Eq, "0")];
        let uid1000 = vec![field(AuditField::Uid, CompareOp::Eq, "1000")];
        let a = parts(&exit, &never, &sc, &uid0, &[]);
        let b = parts(&exit, &always, &sc, &uid1000, &[]);
        assert!(!traffic_overlaps(&a, &b, OFF));
    }

    #[test]
    fn disjoint_syscalls_do_not_overlap() {
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let a_sc = vec!["read".to_string()];
        let b_sc = vec!["write".to_string()];
        let a = parts(&exit, &never, &a_sc, &[], &[]);
        let b = parts(&exit, &always, &b_sc, &[], &[]);
        assert!(!traffic_overlaps(&a, &b, OFF));
    }

    #[test]
    fn wildcard_syscalls_overlap_and_same_direction_thresholds_overlap() {
        // Empty (wildcard) syscalls intersect; auid>=1000 and auid>=2000 are
        // same-direction thresholds whose ranges both extend to +inf, so the
        // broader contains the narrower -> they overlap (#219).
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let a_fields = vec![field(AuditField::Auid, CompareOp::Ge, "1000")];
        let b_fields = vec![field(AuditField::Auid, CompareOp::Ge, "2000")];
        let a = parts(&exit, &never, &[], &a_fields, &[]);
        let b = parts(&exit, &always, &[], &b_fields, &[]);
        assert!(traffic_overlaps(&a, &b, OFF));
    }

    #[test]
    fn wildcard_a_overlaps_concrete_b() {
        // An empty (wildcard) `a` matches every syscall, so it overlaps a
        // concrete `b`. Pins that the empty-set short-circuit is an OR, not an
        // AND (a&b both-empty), of the two emptiness checks.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let b_sc = vec!["execve".to_string()];
        let a = parts(&exit, &never, &[], &[], &[]);
        let b = parts(&exit, &always, &b_sc, &[], &[]);
        assert!(
            traffic_overlaps(&a, &b, OFF),
            "wildcard never overlaps concrete always"
        );
    }

    #[test]
    fn eq_outside_relational_range_is_disjoint_219() {
        // #219 (W03 tightened): uid=0 (Eq) is OUTSIDE uid>=1000, so the two
        // rules cannot co-match -- provably disjoint, so they do NOT overlap.
        // (v1 treated Eq-vs-relational as conservatively overlapping.)
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let sc = vec!["execve".to_string()];
        let a_fields = vec![field(AuditField::Uid, CompareOp::Eq, "0")];
        let b_fields = vec![field(AuditField::Uid, CompareOp::Ge, "1000")];
        let a = parts(&exit, &never, &sc, &a_fields, &[]);
        let b = parts(&exit, &always, &sc, &b_fields, &[]);
        assert!(
            !traffic_overlaps(&a, &b, OFF),
            "uid=0 is outside uid>=1000 -> provably disjoint -> no overlap"
        );
    }

    #[test]
    fn eq_inside_relational_range_overlaps_219() {
        // uid=1500 IS inside uid>=1000 -> the rules overlap.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let sc = vec!["execve".to_string()];
        let a_fields = vec![field(AuditField::Uid, CompareOp::Eq, "1500")];
        let b_fields = vec![field(AuditField::Uid, CompareOp::Ge, "1000")];
        let a = parts(&exit, &never, &sc, &a_fields, &[]);
        let b = parts(&exit, &always, &sc, &b_fields, &[]);
        assert!(
            traffic_overlaps(&a, &b, OFF),
            "uid=1500 is inside uid>=1000 -> overlap"
        );
    }

    #[test]
    fn opposite_relational_non_meeting_is_disjoint_219() {
        // auid>=2000 and auid<1000 have no common value -> disjoint.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let sc = vec!["execve".to_string()];
        let a_fields = vec![field(AuditField::Auid, CompareOp::Ge, "2000")];
        let b_fields = vec![field(AuditField::Auid, CompareOp::Lt, "1000")];
        let a = parts(&exit, &never, &sc, &a_fields, &[]);
        let b = parts(&exit, &always, &sc, &b_fields, &[]);
        assert!(
            !traffic_overlaps(&a, &b, OFF),
            "auid>=2000 and auid<1000 are disjoint"
        );
    }

    #[test]
    fn eq_eq_folded_sentinel_still_overlaps_219() {
        // auid=-1 and auid=4294967295 are the SAME value (folded), NOT a
        // contradiction, so the rules overlap. A verbatim string-compare (the
        // v1 Eq/Eq check) would wrongly call them disjoint.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let sc = vec!["execve".to_string()];
        let a_fields = vec![field(AuditField::Auid, CompareOp::Eq, "-1")];
        let b_fields = vec![field(AuditField::Auid, CompareOp::Eq, "4294967295")];
        let a = parts(&exit, &never, &sc, &a_fields, &[]);
        let b = parts(&exit, &always, &sc, &b_fields, &[]);
        assert!(
            traffic_overlaps(&a, &b, OFF),
            "auid=-1 and auid=4294967295 are the same value -> overlap"
        );
    }

    // --- is_syscall_suppressing_exclude -----------------------------------

    fn exclude_msgtype(action: Action, value: &str) -> AuditRule {
        AuditRule::Syscall {
            list: FilterList::Exclude,
            action,
            syscalls: vec![],
            fields: vec![field(AuditField::MsgType, CompareOp::Eq, value)],
            field_compares: vec![],
            prepend: false,
            key: None,
        }
    }

    #[test]
    fn symbolic_syscall_msgtype_is_a_suppressor() {
        assert!(is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Always, "SYSCALL"),
            OFF
        ));
        assert!(is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Always, "1300"),
            OFF
        ));
    }

    #[test]
    fn hex_syscall_msgtype_is_a_suppressor() {
        // #227/#229: msgtype=0x514 is 1300 (SYSCALL); recognized now that the
        // SYSCALL<->1300 knowledge lives in canonical_value.
        assert!(is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Always, "0x514"),
            OFF
        ));
    }

    #[test]
    fn exclude_action_is_ignored_so_never_exclude_also_suppresses() {
        // On the exclude filter the action is ignored (defaults to `never`):
        // `never,exclude`, `always,exclude`, and `possible,exclude` all drop the
        // named msgtype identically (`man auditctl` / `man 7 audit.rules`).
        assert!(is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Never, "1300"),
            OFF
        ));
        assert!(is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Possible, "SYSCALL"),
            OFF
        ));
    }

    #[test]
    fn w03_never_exclude_suppresses_exit_always_rule() {
        // Regression for the action-ignored exclude semantics: a `never,exclude`
        // SYSCALL drop must fire au-W03 against a later exit-list always rule,
        // exactly as `always,exclude` does.
        let input = concat!(
            "-a never,exclude -F msgtype=1300\n",
            "-a always,exit -S execve -k exec_audit\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-nx.rules")).unwrap();
        let diags = w03(&rules, OFF);
        assert_eq!(
            diags.len(),
            1,
            "never,exclude must suppress like always,exclude"
        );
        assert_eq!(diags[0].code, "au-W03");
        assert_eq!(diags[0].line, 2, "anchored at the suppressed always rule");
        assert!(diags[0].message.contains("10-nx.rules:1"));
    }

    #[test]
    fn non_syscall_msgtype_exclude_is_not_a_suppressor() {
        // 1305 = AUDIT_CONFIG_CHANGE, not SYSCALL: does not suppress exit rules.
        assert!(!is_syscall_suppressing_exclude(
            &exclude_msgtype(Action::Always, "1305"),
            OFF
        ));
    }

    // --- w03 Case 2: msgtype-fold disjointness promotion (#475, class 1) ---

    #[test]
    fn w03_msgtype_provably_different_no_longer_flags_475() {
        // #475: before the msgtype-fold promotion, `disjoint()` is always
        // conservative for msgtype Eq/Eq (compare.rs's NOTE), so ANY
        // never/always pair on the same list "overlaps" regardless of the
        // msgtype values and w03's Case 2 fires. After: SYSCALL(1300) and
        // CONFIG_CHANGE(1305) both resolve to numbers (msgtype.rs
        // MSGTYPE_NAMES) and differ -> traffic_overlaps() == false -> w03
        // does NOT fire for this pair. msgtype is legal on exclude|user
        // filter lists only (au-E04, field_filter.rs:134
        // Restriction::ExcludeOrUser); `user` is used here (live-confirmed
        // legal: test_lints_field_filter.rs's msgtype_on_user_must_not_fire,
        // "-a always,user -F msgtype=AVC").
        let input = concat!(
            "-a never,user -F msgtype=SYSCALL -k never_syscall\n",
            "-a always,user -F msgtype=1305 -k always_configchange\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-msgtype-disjoint.rules")).unwrap();
        let diags = w03(&rules, OFF);
        assert!(
            diags.is_empty(),
            "msgtype=SYSCALL (1300) and msgtype=1305 (CONFIG_CHANGE) are \
             provably different record types -> no suppression conflict, \
             got: {diags:?}"
        );
    }

    // --- w02 boundaries beyond the frozen integration fixtures ------------

    #[test]
    fn w02_requires_same_action() {
        // A broad never rule before a narrow always rule is a w03 case, NOT a
        // w02 shadow: subsumption only compares same-action rules.
        let input = concat!(
            "-a never,exit -S execve -k root_suppress\n",
            "-a always,exit -S execve -F 'auid>=1000' -k exec_user\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-act.rules")).unwrap();
        assert!(
            w02(&rules, OFF).is_empty(),
            "w02 must not compare across actions (never vs always)"
        );
    }

    #[test]
    fn w02_field_compare_blocks_subsumption() {
        // The earlier rule carries an extra `-C` the later lacks, so it is the
        // NARROWER rule and does not subsume the later one.
        let input = concat!(
            "-a always,exit -S execve -C uid!=euid -k priv\n",
            "-a always,exit -S execve -k all\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-cmp.rules")).unwrap();
        assert!(
            w02(&rules, OFF).is_empty(),
            "earlier rule with an extra -C is narrower; no shadow"
        );
    }

    #[test]
    fn w02_multiple_prepends_reverse_relative_order() {
        // Two `-A` rules: the FILE-LATER broad prepend lands FIRST in effective
        // order and shadows the FILE-EARLIER narrow prepend. Removing the
        // prepend-reversal would flip this and fire nothing.
        let input = concat!(
            "-A always,exit -S execve -F 'auid>=1000' -k narrow\n",
            "-A always,exit -S execve -k broad\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-prep.rules")).unwrap();
        let diags = w02(&rules, OFF);
        assert_eq!(
            diags.len(),
            1,
            "broad prepend (effective head) shadows narrow"
        );
        // Anchored at the narrow rule (file line 1), citing the broad rule (line 2).
        assert_eq!(diags[0].line, 1);
        assert!(diags[0].message.contains("10-prep.rules:2"));
    }

    #[test]
    fn w03_exclude_only_targets_exit_list_rules() {
        // A SYSCALL-suppressing exclude plus an exit-list always rule fires;
        // a user-list always rule does not produce SYSCALL records, so the
        // exclude does not conflict with it.
        let input = concat!(
            "-a always,exclude -F msgtype=1300\n",
            "-a always,user -k user_evt\n",
        );
        let rules = parse_rules_str_located(input, Path::new("10-x.rules")).unwrap();
        assert!(
            w03(&rules, OFF).is_empty(),
            "exclude-SYSCALL must not flag a non-exit (user-list) always rule"
        );
    }
}
