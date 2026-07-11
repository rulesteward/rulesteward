//! Canonical `-C` field-pair identity for au-W03's contradiction-disjointness
//! promotion (#475 class 2).
//!
//! `auditctl(8) -C left op right` (`FieldComparison` in `ast.rs`) compares two
//! FIELDS, not a field and a value; legal pairs resolve to one of exactly 25
//! `AUDIT_COMPARE_*` wire constants (audit-userspace 3bfa048,
//! `lib/libaudit.c:1135-1409`'s `audit_rule_interfield_comp_data`, mirrored by
//! the uapi table `include/uapi/linux/audit.h:211-243`). This module maps an
//! unordered field pair to its canonical identity for exactly the 16 SAFE
//! (process-vs-process) constants -- rows 10-25 of that table: the
//! uid/gid/auid/euid/suid/fsuid/egid/sgid/fsgid cross-comparisons that do NOT
//! involve `obj_uid`/`obj_gid`.
//!
//! The other 9 constants (`*_TO_OBJ_UID` / `*_TO_OBJ_GID`, uapi rows 1-9) are
//! deliberately EXCLUDED -- not represented in [`canonical_pair`]'s table at
//! all, so a pair containing `obj_uid`/`obj_gid` always maps to `None` and is
//! never proven contradictory. The kernel dispatches those 9 constants via
//! `audit_compare_uid`/`audit_compare_gid` (auditsc.c:332-378), which
//! existentially quantify over `ctx->names_list` (every filesystem object a
//! syscall touched -- `rename(2)`/`link(2)`/`open(2)`-with-parent can attach
//! 2+ names with DIFFERENT owning uids/gids to one event) rather than
//! comparing a single scalar. For a cross-ownership event, `uid=obj_uid` and
//! `uid!=obj_uid` can BOTH independently find a matching name and return
//! true -- they are not logical complements, so treating them as
//! contradictory would be an unsound "provably disjoint" claim that silently
//! drops a real au-W03 warning. See the #475 class 2 grounding doc for the
//! full soundness argument (both the userspace legal-pair table and the
//! kernel-side existential-vs-scalar dispatch split).
//!
//! `auditctl(8)` supports exactly two `-C` operators, `=` and `!=`
//! (`ast.rs`'s [`crate::ast::FieldComparison`] doc comment; independently
//! enforced by both the userspace parser and the kernel's
//! `audit_field_valid`), so for a shared safe pair "the ops differ" already
//! means "the ops are exact complements" -- no further op-kind check is
//! needed.

use crate::ast::{AuditField, FieldComparison};

/// One of the 16 safe (process-vs-process) `AUDIT_COMPARE_*` constants,
/// canonicalized so both operand orderings (`uid=euid` and `euid=uid`) map to
/// the same variant -- matching audit-userspace's own hard-coded symmetric
/// switch (`libaudit.c:1274-1277` vs `1156-1159`: both field1/field2
/// orderings resolve to the identical wire constant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafePair {
    /// `AUDIT_COMPARE_UID_TO_AUID` (uapi row 10): `uid` <-> `auid`.
    UidAuid,
    /// `AUDIT_COMPARE_UID_TO_EUID` (uapi row 11): `uid` <-> `euid`.
    UidEuid,
    /// `AUDIT_COMPARE_UID_TO_FSUID` (uapi row 12): `uid` <-> `fsuid`.
    UidFsuid,
    /// `AUDIT_COMPARE_UID_TO_SUID` (uapi row 13): `uid` <-> `suid`.
    UidSuid,
    /// `AUDIT_COMPARE_AUID_TO_FSUID` (uapi row 14): `auid` <-> `fsuid`.
    AuidFsuid,
    /// `AUDIT_COMPARE_AUID_TO_SUID` (uapi row 15): `auid` <-> `suid`.
    AuidSuid,
    /// `AUDIT_COMPARE_AUID_TO_EUID` (uapi row 16): `auid` <-> `euid`.
    AuidEuid,
    /// `AUDIT_COMPARE_EUID_TO_SUID` (uapi row 17): `euid` <-> `suid`.
    EuidSuid,
    /// `AUDIT_COMPARE_EUID_TO_FSUID` (uapi row 18): `euid` <-> `fsuid`.
    EuidFsuid,
    /// `AUDIT_COMPARE_SUID_TO_FSUID` (uapi row 19): `suid` <-> `fsuid`.
    SuidFsuid,
    /// `AUDIT_COMPARE_GID_TO_EGID` (uapi row 20): `gid` <-> `egid`.
    GidEgid,
    /// `AUDIT_COMPARE_GID_TO_FSGID` (uapi row 21): `gid` <-> `fsgid`.
    GidFsgid,
    /// `AUDIT_COMPARE_GID_TO_SGID` (uapi row 22): `gid` <-> `sgid`.
    GidSgid,
    /// `AUDIT_COMPARE_EGID_TO_FSGID` (uapi row 23): `egid` <-> `fsgid`.
    EgidFsgid,
    /// `AUDIT_COMPARE_EGID_TO_SGID` (uapi row 24): `egid` <-> `sgid`.
    EgidSgid,
    /// `AUDIT_COMPARE_SGID_TO_FSGID` (uapi row 25): `sgid` <-> `fsgid`.
    SgidFsgid,
}

/// Map an unordered `(a, b)` field pair to its safe canonical identity, or
/// `None` if the pair is not one of the 16 safe process-vs-process constants.
///
/// `None` covers three cases uniformly, with no separate exclusion list
/// needed: a process-vs-OBJECT pair (`obj_uid`/`obj_gid` on either side, the
/// 9 excluded constants), a cross-family pair (a UID-family field against a
/// GID-family field -- `libaudit.c`'s switch has no such arm, `default:
/// -EAU_COMPINCOMPAT`), and any other field not part of the 25-constant table
/// at all (e.g. `pid`, `exit`, a self-pair like `uid`/`uid`).
fn canonical_pair(a: &AuditField, b: &AuditField) -> Option<SafePair> {
    use AuditField::{Auid, Egid, Euid, Fsgid, Fsuid, Gid, Sgid, Suid, Uid};
    match (a, b) {
        (Uid, Auid) | (Auid, Uid) => Some(SafePair::UidAuid),
        (Uid, Euid) | (Euid, Uid) => Some(SafePair::UidEuid),
        (Uid, Fsuid) | (Fsuid, Uid) => Some(SafePair::UidFsuid),
        (Uid, Suid) | (Suid, Uid) => Some(SafePair::UidSuid),
        (Auid, Fsuid) | (Fsuid, Auid) => Some(SafePair::AuidFsuid),
        (Auid, Suid) | (Suid, Auid) => Some(SafePair::AuidSuid),
        (Auid, Euid) | (Euid, Auid) => Some(SafePair::AuidEuid),
        (Euid, Suid) | (Suid, Euid) => Some(SafePair::EuidSuid),
        (Euid, Fsuid) | (Fsuid, Euid) => Some(SafePair::EuidFsuid),
        (Suid, Fsuid) | (Fsuid, Suid) => Some(SafePair::SuidFsuid),
        (Gid, Egid) | (Egid, Gid) => Some(SafePair::GidEgid),
        (Gid, Fsgid) | (Fsgid, Gid) => Some(SafePair::GidFsgid),
        (Gid, Sgid) | (Sgid, Gid) => Some(SafePair::GidSgid),
        (Egid, Fsgid) | (Fsgid, Egid) => Some(SafePair::EgidFsgid),
        (Egid, Sgid) | (Sgid, Egid) => Some(SafePair::EgidSgid),
        (Sgid, Fsgid) | (Fsgid, Sgid) => Some(SafePair::SgidFsgid),
        _ => None,
    }
}

/// True iff `a` and `b` (each a rule's `-C` clauses; multiple `-C` on one
/// rule are `AND`ed per `auditctl(8)`) carry opposite ops on a SHARED safe
/// canonical pair -- proving the two rules' overall AND-conjunctions can
/// never both be true for one event.
///
/// Grounded in `audit_filter_rules`'s AND loop (auditsc.c:481-751: `if
/// (!result) return 0;` on the first failing field) and
/// `audit_uid_comparator`/`audit_gid_comparator` (auditfilter.c:1229-1271):
/// for the 16 safe constants, `Audit_equal`/`Audit_not_equal` over a single
/// scalar credential pair are exact logical complements for every event (law
/// of excluded middle on a total boolean predicate). So a contradiction on
/// ANY one shared safe pair is sufficient, regardless of what else either
/// rule's `-C`/`-F` clauses contain -- this is why the check is existential
/// ("does any shared safe pair contradict"), not a requirement that every
/// `-C` entry line up.
///
/// Vacuously `false` when either side is empty (an absent `-C` proves
/// nothing about disjointness -- the rule with fewer conjuncts matches a
/// superset), when the two sides share no pair at all, or when a shared pair
/// is not one of the 16 safe constants (an excluded object-family pair, or
/// any other non-safe/illegal pair -- [`canonical_pair`] returns `None` for
/// both, so this falls out of the design for free).
#[must_use]
pub(crate) fn compare_pairs_contradictory(a: &[FieldComparison], b: &[FieldComparison]) -> bool {
    a.iter().any(|ca| {
        let Some(pa) = canonical_pair(&ca.left, &ca.right) else {
            return false;
        };
        b.iter()
            .any(|cb| canonical_pair(&cb.left, &cb.right) == Some(pa) && ca.op != cb.op)
    })
}

#[cfg(test)]
mod tests {
    use super::compare_pairs_contradictory;
    use crate::ast::{AuditField, CompareOp, FieldComparison};

    fn cmp(left: AuditField, op: CompareOp, right: AuditField) -> FieldComparison {
        FieldComparison { left, op, right }
    }

    #[test]
    fn empty_either_side_is_never_contradictory() {
        let a = [cmp(AuditField::Uid, CompareOp::Eq, AuditField::Euid)];
        assert!(!compare_pairs_contradictory(&a, &[]));
        assert!(!compare_pairs_contradictory(&[], &a));
        assert!(!compare_pairs_contradictory(&[], &[]));
    }

    #[test]
    fn object_family_pair_is_never_contradictory() {
        // uid <-> obj_uid is one of the 9 excluded constants: canonical_pair
        // must return None for it, so it never contradicts even opposite ops.
        let a = [cmp(AuditField::Uid, CompareOp::Eq, AuditField::ObjUid)];
        let b = [cmp(AuditField::Uid, CompareOp::Ne, AuditField::ObjUid)];
        assert!(!compare_pairs_contradictory(&a, &b));
    }

    #[test]
    fn cross_family_pair_is_never_contradictory() {
        // uid <-> egid has no AUDIT_COMPARE_* arm at all (illegal pair,
        // out-of-scope for this promotion): canonical_pair returns None.
        let a = [cmp(AuditField::Uid, CompareOp::Eq, AuditField::Egid)];
        let b = [cmp(AuditField::Uid, CompareOp::Ne, AuditField::Egid)];
        assert!(!compare_pairs_contradictory(&a, &b));
    }

    #[test]
    fn same_safe_pair_opposite_op_is_contradictory() {
        let a = [cmp(AuditField::Uid, CompareOp::Eq, AuditField::Euid)];
        let b = [cmp(AuditField::Euid, CompareOp::Ne, AuditField::Uid)];
        assert!(compare_pairs_contradictory(&a, &b));
    }

    #[test]
    fn same_safe_pair_same_op_is_not_contradictory() {
        let a = [cmp(AuditField::Uid, CompareOp::Eq, AuditField::Euid)];
        let b = [cmp(AuditField::Euid, CompareOp::Eq, AuditField::Uid)];
        assert!(!compare_pairs_contradictory(&a, &b));
    }

    #[test]
    fn multi_clause_shared_contradiction_among_unrelated_pairs() {
        let a = [
            cmp(AuditField::Uid, CompareOp::Eq, AuditField::Euid),
            cmp(AuditField::Gid, CompareOp::Eq, AuditField::Egid),
        ];
        let b = [
            cmp(AuditField::Uid, CompareOp::Ne, AuditField::Euid),
            cmp(AuditField::Sgid, CompareOp::Eq, AuditField::Fsgid),
        ];
        assert!(compare_pairs_contradictory(&a, &b));
    }
}
