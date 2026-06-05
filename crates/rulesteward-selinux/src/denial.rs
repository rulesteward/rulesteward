//! `SELinux` denial model: grouping + record-only floor classifier.
//!
//! Phase-0 shared foundation (issues #96 + #97-denial): the denial grouper +
//! the record-only floor classifier that triage / te-emit / libsepol consume.
//!
//! # Design
//!
//! [`DenialKind`] has two layers:
//! - **Record-only FLOOR** (produced here, always-on offline): `Permissive`,
//!   `MlsSuspected`, `RoleSuspected`, `TeAllowable`.
//! - **Authoritative opt-in** (produced by the later libsepol layer, P5/#105):
//!   `Constraint`, `Bounds`, `ContextInvalid`.
//!
//! [`group_denials`] groups a slice of [`AvcDenial`]s by the triple
//! `(source_type, target_type, tclass)`, unions perm sets, and applies the
//! floor classifier to each group.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::AvcDenial;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Why a denial group cannot (or should not) be fixed with a plain TE `allow`.
///
/// Two layers:
/// - **Authoritative** (`TeAllowable`, `Constraint`, `Bounds`, `ContextInvalid`)
///   are produced ONLY by the opt-in libsepol layer (task P5/#105).
/// - **Record-only FLOOR** (`MlsSuspected`, `RoleSuspected`, `Permissive`)
///   are produced by [`group_denials`] offline, using fields in the AVC record.
///
/// The FLOOR classifier produces only `TeAllowable | MlsSuspected |
/// RoleSuspected | Permissive`. The other three variants are reserved for the
/// authoritative layer and are never emitted by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DenialKind {
    // -- Authoritative (libsepol layer only, P5/#105) -------------------------
    /// A plain `allow` rule would fix this denial (TE policy gap). This is
    /// also the floor classifier's default when no other signal fires.
    TeAllowable,
    /// A `constrain` / `mlsconstrain` statement blocked the access (covers MLS,
    /// MCS, and role-constraint; RBAC `role_allow` fires before and is
    /// subsumed). Plain `allow` won't help.
    Constraint,
    /// A `typebounds` violation: the source type's permissions are not a subset
    /// of its parent's. Needs a policy restructuring, not just an allow.
    Bounds,
    /// The supplied policy does not define one of the contexts in this denial
    /// (cross-host / cross-version analysis where the context is undefined in
    /// the replay policy). Falls back to the floor heuristic for the
    /// suggestion; emits a `policy mismatch` warning.
    ContextInvalid,

    // -- Record-only FLOOR (this module) -------------------------------------
    /// Context MLS/MCS LEVEL differs between source and target context: a
    /// `mlsconstrain` is likely responsible. Suggest investigation before
    /// emitting an allow. (Heuristic - the authoritative layer may
    /// reclassify as `Constraint`.)
    MlsSuspected,
    /// The ROLE components differ AND the target context is NOT using the
    /// universal object role (`object_r`), indicating this may be a role
    /// transition / role-allow problem rather than a missing TE allow.
    /// (Heuristic - the authoritative layer may reclassify as `Constraint`.)
    RoleSuspected,
    /// The denial had `permissive=1`: the access was NOT actually blocked.
    ///
    /// Round-2 reversal of f4 §2.5 invariant 6 (user decision 2026-06-05): the
    /// HUMAN triage render now offers a suggested allow gated behind a
    /// PERMISSIVE-MODE caveat banner; the machine-readable `build_report` JSON
    /// keeps `suggested_rule = null` for this kind (see `triage.rs`).
    Permissive,
}

/// One denial group: all AVC records sharing the same
/// `(source_type, target_type, tclass)` triple, with perms unioned.
///
/// The `perms` set is EXACT: the union of only the perms that were actually
/// denied across all records in this group - no perm-set expansion, no
/// padding (f4 §2.5 invariants 3 and 5).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DenialGroup {
    /// Source domain type (third component of `scontext`).
    pub source_type: String,
    /// Target type (third component of `tcontext`).
    pub target_type: String,
    /// Object class name (e.g. `"file"`, `"dir"`, `"process"`).
    pub tclass: String,
    /// Union of all denied permissions for this triple, sorted and deduplicated.
    pub perms: BTreeSet<String>,
    /// `true` iff any denial in this group had `permissive=Some(true)`.
    pub any_permissive: bool,
    /// Floor classifier result for this group.
    pub kind: DenialKind,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Group a slice of [`AvcDenial`]s by `(source_type, target_type, tclass)`,
/// union their permission sets, and classify each group with the record-only
/// floor classifier.
///
/// Output is sorted deterministically by `(source_type, target_type, tclass)`
/// so callers and JSON snapshots are stable.
///
/// The floor classifier order (applied per group):
/// 1. `any_permissive == true` -> [`DenialKind::Permissive`]
/// 2. MLS/MCS level components differ -> [`DenialKind::MlsSuspected`]
/// 3. Role components differ AND target role is not `object_r` -> [`DenialKind::RoleSuspected`]
/// 4. Otherwise -> [`DenialKind::TeAllowable`]
#[must_use]
pub fn group_denials(denials: &[AvcDenial]) -> Vec<DenialGroup> {
    // Key: (source_type, target_type, tclass)
    // Value: accumulated perms, permissive flag, representative raw contexts.
    type TripleKey = (String, String, String);
    let mut map: BTreeMap<TripleKey, GroupAccumulator> = BTreeMap::new();

    for denial in denials {
        let key = (
            denial.source_type.clone(),
            denial.target_type.clone(),
            denial.tclass.clone(),
        );
        let acc = map.entry(key).or_insert_with(|| GroupAccumulator {
            perms: BTreeSet::new(),
            any_permissive: false,
            scontext_raw: denial.scontext_raw.clone(),
            tcontext_raw: denial.tcontext_raw.clone(),
        });
        for perm in &denial.perms {
            acc.perms.insert(perm.clone());
        }
        if denial.permissive == Some(true) {
            acc.any_permissive = true;
        }
    }

    map.into_iter()
        .map(
            |(
                (source_type, target_type, tclass),
                GroupAccumulator {
                    perms,
                    any_permissive,
                    scontext_raw,
                    tcontext_raw,
                },
            )| {
                let kind = classify_floor(any_permissive, &scontext_raw, &tcontext_raw);
                DenialGroup {
                    source_type,
                    target_type,
                    tclass,
                    perms,
                    any_permissive,
                    kind,
                }
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Accumulator for one `(source_type, target_type, tclass)` group during
/// the grouping pass.
struct GroupAccumulator {
    perms: BTreeSet<String>,
    any_permissive: bool,
    /// Raw context of the first denial seen for this triple (used for
    /// role/level classification; all records in a group share the same
    /// source and target types so a representative context is sufficient).
    scontext_raw: String,
    tcontext_raw: String,
}

/// Extract the ROLE component (2nd colon-delimited field, 0-indexed) from a
/// raw `SELinux` context `user:role:type[:level]`.
///
/// Returns `""` when the context does not contain a role field (e.g. numeric
/// `ssid=NN` fallback forms).
fn extract_role(ctx: &str) -> &str {
    let mut parts = ctx.splitn(4, ':');
    parts.next(); // user
    parts.next().unwrap_or("")
}

/// Extract the LEVEL component (4th colon-delimited field, 0-indexed) from a
/// raw `SELinux` context `user:role:type[:level]`.
///
/// Returns `None` when the context has fewer than 4 colon-delimited components
/// (level is optional in the kernel format).
fn extract_level(ctx: &str) -> Option<&str> {
    let mut parts = ctx.splitn(4, ':');
    parts.next(); // user
    parts.next(); // role
    parts.next(); // type
    let level = parts.next()?;
    if level.is_empty() { None } else { Some(level) }
}

/// Apply the record-only FLOOR classifier in priority order:
///
/// 1. `any_permissive` -> [`DenialKind::Permissive`]
/// 2. levels present and different -> [`DenialKind::MlsSuspected`]
/// 3. roles differ AND target role is not `object_r` -> [`DenialKind::RoleSuspected`]
/// 4. otherwise -> [`DenialKind::TeAllowable`]
fn classify_floor(any_permissive: bool, scontext_raw: &str, tcontext_raw: &str) -> DenialKind {
    // Rule 1: permissive wins unconditionally.
    if any_permissive {
        return DenialKind::Permissive;
    }

    // Rule 2: MLS/MCS level mismatch.
    let slevel = extract_level(scontext_raw);
    let tlevel = extract_level(tcontext_raw);
    // Only flag as MLS when at least one side has a level AND they differ.
    // Both-missing means no level information: treat as equal (no MLS context).
    let levels_differ = match (slevel, tlevel) {
        (Some(s), Some(t)) => s != t,
        (Some(_), None) | (None, Some(_)) => true, // one side has level, other does not
        (None, None) => false,
    };
    if levels_differ {
        return DenialKind::MlsSuspected;
    }

    // Rule 3: role mismatch, but exclude the normal file/object case where the
    // target uses `object_r` (the universal object role). A denial of a plain
    // file/dir/socket etc. has scontext role=`system_r` and tcontext
    // role=`object_r`; the roles differ but this is an ordinary TE gap.
    let srole = extract_role(scontext_raw);
    let trole = extract_role(tcontext_raw);
    if srole != trole && trole != "object_r" {
        return DenialKind::RoleSuspected;
    }

    DenialKind::TeAllowable
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AvcDenial, Verdict};

    // Helper: build a minimal AvcDenial for grouping tests.
    fn make_denial(
        source_type: &str,
        target_type: &str,
        tclass: &str,
        perms: &[&str],
        permissive: Option<bool>,
        scontext_raw: &str,
        tcontext_raw: &str,
    ) -> AvcDenial {
        AvcDenial {
            verdict: Verdict::Denied,
            perms: perms.iter().map(ToString::to_string).collect(),
            source_type: source_type.to_string(),
            target_type: target_type.to_string(),
            tclass: tclass.to_string(),
            permissive,
            scontext_raw: scontext_raw.to_string(),
            tcontext_raw: tcontext_raw.to_string(),
            pid: None,
            comm: None,
            exe: None,
            path: None,
            name: None,
            serial: None,
            timestamp: None,
        }
    }

    // -----------------------------------------------------------------------
    // Anchor 1: Grouping + perm union (f4 §2.2 / §2.5 invariant 5)
    // -----------------------------------------------------------------------

    /// Two denials with the SAME triple (`logrotate_t`, `shadow_t`, `file`) but
    /// different perms must produce ONE group with the union of perms.
    #[test]
    fn test_group_same_triple_unions_perms() {
        let denials = vec![
            make_denial(
                "logrotate_t",
                "shadow_t",
                "file",
                &["read"],
                Some(false),
                "system_u:system_r:logrotate_t:s0",
                "unconfined_u:object_r:shadow_t:s0",
            ),
            make_denial(
                "logrotate_t",
                "shadow_t",
                "file",
                &["getattr"],
                Some(false),
                "system_u:system_r:logrotate_t:s0",
                "unconfined_u:object_r:shadow_t:s0",
            ),
        ];
        let groups = group_denials(&denials);
        assert_eq!(
            groups.len(),
            1,
            "same triple must produce exactly one group"
        );
        let g = &groups[0];
        assert_eq!(g.source_type, "logrotate_t");
        assert_eq!(g.target_type, "shadow_t");
        assert_eq!(g.tclass, "file");
        // Perms are the union, sorted (BTreeSet).
        let expected: BTreeSet<String> = ["getattr", "read"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(g.perms, expected, "perm union must be {{getattr, read}}");
    }

    /// Two denials with DIFFERENT triples must produce TWO groups; perms are
    /// never merged across triples (f4 §2.5 invariant 5).
    #[test]
    fn test_group_different_triples_no_cross_merge() {
        let denials = vec![
            make_denial(
                "logrotate_t",
                "shadow_t",
                "file",
                &["read"],
                Some(false),
                "system_u:system_r:logrotate_t:s0",
                "unconfined_u:object_r:shadow_t:s0",
            ),
            make_denial(
                "logrotate_t",
                "shadow_t",
                "dir",
                &["search"],
                Some(false),
                "system_u:system_r:logrotate_t:s0",
                "unconfined_u:object_r:shadow_t:s0",
            ),
        ];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 2, "different triples must produce two groups");
        // Groups are sorted by triple: (..., dir) < (..., file).
        assert_eq!(groups[0].tclass, "dir");
        assert_eq!(groups[0].perms.len(), 1);
        assert!(groups[0].perms.contains("search"));
        assert_eq!(groups[1].tclass, "file");
        assert_eq!(groups[1].perms.len(), 1);
        assert!(groups[1].perms.contains("read"));
    }

    // -----------------------------------------------------------------------
    // Anchor 2: TeAllowable - the f4 §1.2 capture (the `object_r` exclusion)
    // -----------------------------------------------------------------------

    /// An ordinary enforcing file denial with `scontext` role=`system_r` and
    /// `tcontext` role=`object_r` must produce `TeAllowable`, NOT `RoleSuspected`.
    /// This pins that the `object_r` exclusion works correctly.
    #[test]
    fn test_teallowable_ordinary_file_denial() {
        let denials = vec![make_denial(
            "logrotate_t",
            "shadow_t",
            "file",
            &["read"],
            Some(false),
            "system_u:system_r:logrotate_t:s0",
            "unconfined_u:object_r:shadow_t:s0",
        )];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(
            g.kind,
            DenialKind::TeAllowable,
            "ordinary file denial with `object_r` target must be TeAllowable"
        );
        assert!(!g.any_permissive);
        let expected: BTreeSet<String> = ["read"].iter().map(ToString::to_string).collect();
        assert_eq!(g.perms, expected);
    }

    // -----------------------------------------------------------------------
    // Anchor 3: RoleSuspected - `rocky8-xver-role-dyntransition`
    // -----------------------------------------------------------------------

    /// Process-class denial where both subject and target use non-`object_r`
    /// roles (`staff_r` vs `system_r`). This is a role-transition problem, NOT an
    /// ordinary TE gap.
    #[test]
    fn test_role_suspected_subject_target_roles() {
        let denials = vec![make_denial(
            "newrole_t",
            "newrole_t",
            "process",
            &["dyntransition"],
            Some(false),
            "staff_u:staff_r:newrole_t:s0",
            "staff_u:system_r:newrole_t:s0",
        )];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].kind,
            DenialKind::RoleSuspected,
            "process denial with target role=`system_r` (not `object_r`) must be RoleSuspected"
        );
    }

    // -----------------------------------------------------------------------
    // Anchor 4: MlsSuspected - level components differ
    // -----------------------------------------------------------------------

    /// When source level is `s0` and target level is `s0:c0` they differ ->
    /// `MlsSuspected`.
    #[test]
    fn test_mls_suspected_level_mismatch() {
        let denials = vec![make_denial(
            "t1",
            "t2",
            "file",
            &["read"],
            Some(false),
            "system_u:system_r:t1:s0",
            "system_u:object_r:t2:s0:c0",
        )];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].kind,
            DenialKind::MlsSuspected,
            "differing MLS levels (s0 vs s0:c0) must produce MlsSuspected"
        );
    }

    // -----------------------------------------------------------------------
    // Anchor 5: Permissive - `permissive=Some(true)`
    // -----------------------------------------------------------------------

    /// A denial with `permissive=true` must produce `Permissive` regardless of
    /// role/level (f4 §2.5 invariant 6).
    #[test]
    fn test_permissive_denial() {
        let denials = vec![make_denial(
            "httpd_t",
            "shadow_t",
            "file",
            &["read"],
            Some(true),
            "system_u:system_r:httpd_t:s0",
            "unconfined_u:object_r:shadow_t:s0",
        )];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].kind, DenialKind::Permissive);
        assert!(groups[0].any_permissive);
    }

    // -----------------------------------------------------------------------
    // Anchor 6: Permissive beats role mismatch (priority ordering)
    // -----------------------------------------------------------------------

    /// A permissive denial that ALSO has a role mismatch (both non-`object_r`
    /// roles) must still produce `Permissive` - permissive is checked first.
    #[test]
    fn test_permissive_beats_role_mismatch() {
        let denials = vec![make_denial(
            "newrole_t",
            "newrole_t",
            "process",
            &["dyntransition"],
            Some(true), // permissive=true
            "staff_u:staff_r:newrole_t:s0",
            "staff_u:system_r:newrole_t:s0", // roles differ, target role != object_r
        )];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].kind,
            DenialKind::Permissive,
            "Permissive must take priority over RoleSuspected"
        );
    }

    // -----------------------------------------------------------------------
    // Additional: deterministic output ordering
    // -----------------------------------------------------------------------

    /// Output is sorted by `(source_type, target_type, tclass)` so it is
    /// deterministic regardless of input order.
    #[test]
    fn test_output_is_sorted_by_triple() {
        let denials = vec![
            make_denial(
                "z_t",
                "a_t",
                "file",
                &["write"],
                Some(false),
                "system_u:system_r:z_t:s0",
                "system_u:object_r:a_t:s0",
            ),
            make_denial(
                "a_t",
                "z_t",
                "file",
                &["read"],
                Some(false),
                "system_u:system_r:a_t:s0",
                "system_u:object_r:z_t:s0",
            ),
        ];
        let groups = group_denials(&denials);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].source_type, "a_t",
            "first group must be a_t (sorts before z_t)"
        );
        assert_eq!(groups[1].source_type, "z_t");
    }
}
