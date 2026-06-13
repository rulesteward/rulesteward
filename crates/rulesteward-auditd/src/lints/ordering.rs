//! Ordering and reachability lints over the concatenated `rules.d/` stream.
//!
//! Pipeline P2 (#193):
//! * au-W02 - shadowed rule: an earlier rule (in EFFECTIVE load order,
//!   including `-A` prepend head-insertion) structurally subsumes a later rule
//!   on the same filter list. v1 subsumption is STRUCTURAL-only (owner
//!   decision D4): same filter list, syscall superset, field-predicate subset
//!   with exact predicate equality; no interval arithmetic. Pairs that are
//!   exactly canonical-equal are au-W01 (P1) and MUST be skipped here (owner
//!   decision D2: skip when `canonical_key(a) == canonical_key(b)`).
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
    Action, AuditField, AuditRule, CompareOp, ControlRule, FieldComparison, FieldFilter,
    FilterList, LocatedRule,
};
use crate::lints::normalize::canonical_key;

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

/// True when every predicate in `earlier` appears verbatim (field+op+value) in
/// `later` - i.e. `earlier`'s predicate set is a SUBSET of `later`'s, so
/// `earlier` is the broader (less constrained) rule. Multiplicity is ignored;
/// real rules carry distinct predicates.
fn fields_subset(earlier: &[FieldFilter], later: &[FieldFilter]) -> bool {
    earlier.iter().all(|f| later.contains(f))
}

/// As [`fields_subset`] for `-C` inter-field comparisons.
fn compares_subset(earlier: &[FieldComparison], later: &[FieldComparison]) -> bool {
    earlier.iter().all(|c| later.contains(c))
}

/// D4 structural subsumption: `earlier` matches a superset of `later`'s
/// traffic (broader syscall set AND a subset of its field predicates). No
/// interval arithmetic - predicate equality is exact (`auid>=1000` does not
/// subsume `auid>=2000`).
fn subsumes(earlier: &SyscallParts, later: &SyscallParts) -> bool {
    syscall_superset(earlier.syscalls, later.syscalls)
        && fields_subset(earlier.fields, later.fields)
        && compares_subset(earlier.field_compares, later.field_compares)
}

/// True when two same-list rules can match overlapping traffic, structurally.
/// Syscall sets must intersect (empty = wildcard matches all). Two rules are
/// taken as DISJOINT only when a shared field carries contradictory equality
/// (`field = X` vs `field = Y`, `X != Y`); any other shape is conservatively
/// treated as overlapping (no interval arithmetic, per D4's spirit).
fn traffic_overlaps(a: &SyscallParts, b: &SyscallParts) -> bool {
    let syscalls_intersect = a.syscalls.is_empty()
        || b.syscalls.is_empty()
        || a.syscalls.iter().any(|s| b.syscalls.contains(s));
    if !syscalls_intersect {
        return false;
    }
    let contradictory = a.fields.iter().any(|fa| {
        b.fields.iter().any(|fb| {
            fa.field == fb.field
                && fa.op == CompareOp::Eq
                && fb.op == CompareOp::Eq
                && fa.value != fb.value
        })
    });
    !contradictory
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
fn is_syscall_suppressing_exclude(rule: &AuditRule) -> bool {
    let Some(p) = syscall_parts(rule) else {
        return false;
    };
    *p.list == FilterList::Exclude
        && p.fields.iter().any(|f| {
            f.field == AuditField::MsgType
                && (f.value == "1300" || f.value.eq_ignore_ascii_case("SYSCALL"))
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
pub fn w02(rules: &[LocatedRule]) -> Vec<Diagnostic> {
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
            if canonical_key(&earlier.rule) == canonical_key(&later.rule) {
                continue;
            }
            if subsumes(&ep, &lp) {
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
pub fn w03(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let eff = effective_syscall_rules(rules);
    let syscall_exclude = rules
        .iter()
        .find(|lr| is_syscall_suppressing_exclude(&lr.rule));
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
            if *ep.action == Action::Never && ep.list == lp.list && traffic_overlaps(&ep, &lp) {
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
        SyscallParts, is_syscall_suppressing_exclude, syscall_superset, traffic_overlaps, w02, w03,
    };
    use crate::ast::{
        Action, AuditField, AuditRule, CompareOp, FieldComparison, FieldFilter, FilterList,
    };
    use crate::parse_rules_str_located;
    use std::path::Path;

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
        assert!(!traffic_overlaps(&a, &b));
    }

    #[test]
    fn disjoint_syscalls_do_not_overlap() {
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let a_sc = vec!["read".to_string()];
        let b_sc = vec!["write".to_string()];
        let a = parts(&exit, &never, &a_sc, &[], &[]);
        let b = parts(&exit, &always, &b_sc, &[], &[]);
        assert!(!traffic_overlaps(&a, &b));
    }

    #[test]
    fn wildcard_syscalls_overlap_and_inequality_is_not_contradiction() {
        // Empty (wildcard) syscalls intersect; `>=` thresholds are NOT a
        // contradiction (no interval arithmetic), so the rules overlap.
        let (exit, never, always) = (FilterList::Exit, Action::Never, Action::Always);
        let a_fields = vec![field(AuditField::Auid, CompareOp::Ge, "1000")];
        let b_fields = vec![field(AuditField::Auid, CompareOp::Ge, "2000")];
        let a = parts(&exit, &never, &[], &a_fields, &[]);
        let b = parts(&exit, &always, &[], &b_fields, &[]);
        assert!(traffic_overlaps(&a, &b));
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
        assert!(is_syscall_suppressing_exclude(&exclude_msgtype(
            Action::Always,
            "SYSCALL"
        )));
        assert!(is_syscall_suppressing_exclude(&exclude_msgtype(
            Action::Always,
            "1300"
        )));
    }

    #[test]
    fn exclude_action_is_ignored_so_never_exclude_also_suppresses() {
        // On the exclude filter the action is ignored (defaults to `never`):
        // `never,exclude`, `always,exclude`, and `possible,exclude` all drop the
        // named msgtype identically (`man auditctl` / `man 7 audit.rules`).
        assert!(is_syscall_suppressing_exclude(&exclude_msgtype(
            Action::Never,
            "1300"
        )));
        assert!(is_syscall_suppressing_exclude(&exclude_msgtype(
            Action::Possible,
            "SYSCALL"
        )));
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
        let diags = w03(&rules);
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
        assert!(!is_syscall_suppressing_exclude(&exclude_msgtype(
            Action::Always,
            "1305"
        )));
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
            w02(&rules).is_empty(),
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
            w02(&rules).is_empty(),
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
        let diags = w02(&rules);
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
            w03(&rules).is_empty(),
            "exclude-SYSCALL must not flag a non-exit (user-list) always rule"
        );
    }
}
