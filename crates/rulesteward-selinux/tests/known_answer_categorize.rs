//! Known-answer barrier tests for the libsepol authoritative categorizer (#109).
//!
//! These pin [`rulesteward_selinux::categorize`] against two small, self-contained
//! binary `SELinux` policy fixtures so each authoritative [`DenialKind`] is the
//! OPERATIVE deny reason. Every expected value here was confirmed by replaying the
//! exact `(scontext, tcontext, tclass, perm)` vector through the real libsepol
//! `sepol_compute_av_reason_buffer` (the F4b spike + a throwaway probe linking the
//! same musl `libsepol.a`); the reason bit each case yields is cited inline.
//!
//! # Why these are RED at the barrier
//!
//! The categorizer (`Policy::load` + `categorize`) is a `todo!()` stub at this
//! stage (the FFI is #107, the static link is #106). So every test below PANICS on
//! the `todo!()` - that is the watched-it-fail RED state the barrier requires. They
//! flip to GREEN only when the real libsepol replay lands.
//!
//! # Why feature-gated
//!
//! The whole module is behind `#![cfg(feature = "authoritative-categorizer")]`: the
//! categorizer links libsepol statically (~224 KiB, LGPL-2.1), so the default
//! workspace build must not require it. These tests run only under
//! `--features authoritative-categorizer` (the CI feature job per #106/#109).
//!
//! # Fixtures (built with `secilc`, reproducible)
//!
//! - `tests/fixtures/kat.policy` <- `kat.cil`, built `secilc -M true` (MLS required
//!   for the `mlsconstrain` to be active). Carries the TE gap + the MLS constraint +
//!   the role constraint, all on TE-ALLOWED accesses so the CONSTRAINT (not a TE
//!   gap) is the operative reason.
//! - `tests/fixtures/bounds.policy` <- `bounds.cil`, built `secilc -N -M true`. The
//!   `-N` (disable-neverallow) is REQUIRED: secilc rejects the child-exceeds-parent
//!   over-grant at compile time as a neverallow-class check, so `-N` lets the
//!   over-grant survive into the binary for the RUNTIME `type_attribute_bounds_av`
//!   check to strip (which is what sets the BOUNDS reason bit).
//!
//! Each `AvcDenial` is built through the FROZEN [`parse_avc`] parser from a real
//! kernel-format `type=AVC` line, never hand-constructed - the categorizer consumes
//! the same `scontext_raw` / `tcontext_raw` / `tclass` / `perms` the parser fills.

#![cfg(feature = "authoritative-categorizer")]

use std::path::{Path, PathBuf};

use rulesteward_selinux::{AvcDenial, DenialKind, Policy, categorize, parse_avc};

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Load the TE + CONSTRAINT(MLS) + CONSTRAINT(role) + BADSCON known-answer policy.
fn kat_policy() -> Policy {
    let path = fixture("kat.policy");
    Policy::load(&path).unwrap_or_else(|e| panic!("load kat.policy ({}): {e}", path.display()))
}

/// Load the typebounds BOUNDS known-answer policy.
fn bounds_policy() -> Policy {
    let path = fixture("bounds.policy");
    Policy::load(&path).unwrap_or_else(|e| panic!("load bounds.policy ({}): {e}", path.display()))
}

/// Parse a single-record `type=AVC` line through the frozen parser, asserting
/// exactly one denial comes back.
fn parse_one(line: &str) -> AvcDenial {
    let mut denials = parse_avc(line).unwrap_or_else(|e| panic!("parse_avc failed: {e}"));
    assert_eq!(
        denials.len(),
        1,
        "fixture line must parse to exactly one AVC record"
    );
    denials.pop().unwrap()
}

// ---------------------------------------------------------------------------
// AVC fixture lines (real kernel format; contexts target the kat / bounds policy)
// ---------------------------------------------------------------------------

/// TE gap: `src_t -> tgt_t : file { write }`. The kat policy allows
/// `src_t tgt_t:file { read open getattr }` but deliberately NOT `write`, and no
/// constraint covers `file`, so the only deny reason is a missing TE allow.
/// Grounded: libsepol replay -> `bits=0x1` (`SEPOL_COMPUTEAV_TE`).
const AVC_TE: &str = r#"type=AVC msg=audit(1700000000.001:1001): avc:  denied  { write } for  pid=1001 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=0"#;

/// MLS constraint: `src_t (level s0) -> tgt_t (level s1) : file { read }`. The
/// access IS TE-allowed (`allow src_t tgt_t:file read`), but the kat
/// `(mlsconstrain (file (read)) (dom l1 l2))` requires the source level to dominate
/// the target level; `s0` does NOT dominate `s1`, so the constraint blocks it.
/// Grounded: libsepol replay -> `bits=0x2` (`SEPOL_COMPUTEAV_CONS`).
const AVC_MLS_CONSTRAINT: &str = r#"type=AVC msg=audit(1700000000.002:1002): avc:  denied  { read } for  pid=1002 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s1:c0.c1 tclass=file permissive=0"#;

/// Permissive twin of [`AVC_MLS_CONSTRAINT`]: byte-identical except `permissive=1`.
/// Used for the permissive-flip invariant.
const AVC_MLS_CONSTRAINT_PERMISSIVE: &str = r#"type=AVC msg=audit(1700000000.002:1002): avc:  denied  { read } for  pid=1002 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s1:c0.c1 tclass=file permissive=1"#;

/// Role constraint: `r_a/src_t -> r_b/src_t : process { dyntransition }`. The
/// access IS TE-allowed (`allow src_t src_t:process dyntransition`), but the kat
/// `(constrain (process (dyntransition)) (eq r1 r2))` requires equal roles; `r_a`
/// != `r_b`, so the constraint blocks it. This is the role/RBAC case that maps to
/// `Constraint` (the role-change constrain pre-empts any `role_allow` check; f4b 6.2).
/// Grounded: libsepol replay -> `bits=0x2` (`SEPOL_COMPUTEAV_CONS`).
const AVC_ROLE_CONSTRAINT: &str = r#"type=AVC msg=audit(1700000000.003:1003): avc:  denied  { dyntransition } for  pid=1003 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_b:src_t:s0:c0.c1 tclass=process permissive=0"#;

/// Typebounds violation: `rsbnd_child_t -> tmp_t : file { write }`. The bounds
/// policy bounds `rsbnd_child_t` by `rsbnd_parent_t`; a rule grants the child
/// `write` but the parent lacks it, so the runtime bounds check strips it.
/// Grounded: libsepol replay (against `bounds.policy`) -> `bits=0x8`
/// (`SEPOL_COMPUTEAV_BOUNDS`).
const AVC_BOUNDS: &str = r#"type=AVC msg=audit(1700000000.004:1004): avc:  denied  { write } for  pid=1004 comm="child" scontext=system_u:system_r:rsbnd_child_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0"#;

/// BADSCON: the source context names a type (`zzz_undefined_t`) the kat policy
/// does not define, so `sepol_context_to_sid` fails. Per f4 section 8 this is NOT
/// an error - it maps to `ContextInvalid` (the supplied policy does not define this
/// context; realistic in offline cross-host analysis).
/// Grounded: libsepol replay -> `sepol_context_to_sid` rejects the context (BADSCON).
const AVC_BADSCON: &str = r#"type=AVC msg=audit(1700000000.005:1005): avc:  denied  { read } for  pid=1005 comm="probe" scontext=u1:r_a:zzz_undefined_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=0"#;

// ---------------------------------------------------------------------------
// Known-answer anchors: one per authoritative DenialKind
// ---------------------------------------------------------------------------

#[test]
fn kat_te_gap_is_te_allowable() {
    let policy = kat_policy();
    let denial = parse_one(AVC_TE);
    let kind = categorize(&denial, &policy).expect("TE gap categorizes without error");
    assert_eq!(
        kind,
        DenialKind::TeAllowable,
        "src_t -> tgt_t:file write has no allow and no constraint: must be TeAllowable (reason bit 0x1)"
    );
}

#[test]
fn kat_mls_constraint_is_constraint() {
    let policy = kat_policy();
    let denial = parse_one(AVC_MLS_CONSTRAINT);
    let kind = categorize(&denial, &policy).expect("MLS constraint categorizes without error");
    assert_eq!(
        kind,
        DenialKind::Constraint,
        "src_t(s0) -> tgt_t(s1):file read is TE-allowed but blocked by mlsconstrain (dom l1 l2): must be Constraint (reason bit 0x2)"
    );
}

#[test]
fn kat_role_constraint_is_constraint() {
    let policy = kat_policy();
    let denial = parse_one(AVC_ROLE_CONSTRAINT);
    let kind = categorize(&denial, &policy).expect("role constraint categorizes without error");
    assert_eq!(
        kind,
        DenialKind::Constraint,
        "r_a/src_t -> r_b/src_t:process dyntransition is TE-allowed but blocked by constrain (eq r1 r2): role/RBAC maps to Constraint (reason bit 0x2)"
    );
}

#[test]
fn bounds_typebounds_violation_is_bounds() {
    let policy = bounds_policy();
    let denial = parse_one(AVC_BOUNDS);
    let kind =
        categorize(&denial, &policy).expect("typebounds violation categorizes without error");
    assert_eq!(
        kind,
        DenialKind::Bounds,
        "rsbnd_child_t -> tmp_t:file write exceeds the typebounds parent: must be Bounds (reason bit 0x8)"
    );
}

#[test]
fn kat_undefined_context_is_context_invalid() {
    let policy = kat_policy();
    let denial = parse_one(AVC_BADSCON);
    // BADSCON is NOT an error (f4 section 8): an undefined context maps to
    // ContextInvalid so the caller can fall back to the floor heuristic + warn.
    let kind = categorize(&denial, &policy)
        .expect("an undefined context must be Ok(ContextInvalid), not an Err");
    assert_eq!(
        kind,
        DenialKind::ContextInvalid,
        "a context whose type the supplied policy does not define must be ContextInvalid, not an error"
    );
}

// ---------------------------------------------------------------------------
// Permissive-flip invariant (load-bearing adversarial test)
// ---------------------------------------------------------------------------

/// Categorization is a POLICY REPLAY, not a log read: the `permissive` flag on the
/// record is IGNORED. Flipping `permissive=0 <-> 1` on the SAME record must
/// categorize IDENTICALLY (f4 section 8: flipping the flip gave byte-identical
/// libsepol output). A `permissive=1` enforcing-vs-permissive short-circuit belongs
/// to the floor classifier in `denial.rs`, NEVER to the authoritative replay.
///
/// This is the sharpest adversarial anchor: an implementation that wrongly reads
/// `denial.permissive` (e.g. returning `Permissive` or short-circuiting on it) would
/// pass the five single-category anchors above but FAIL here.
#[test]
fn permissive_flag_is_ignored_by_categorizer() {
    let policy = kat_policy();

    let enforcing = parse_one(AVC_MLS_CONSTRAINT);
    let permissive = parse_one(AVC_MLS_CONSTRAINT_PERMISSIVE);

    // Precondition: the two records differ ONLY in the permissive flag (every
    // field the replay actually uses is identical). This pins that the invariant
    // is really exercising the permissive axis and nothing else.
    assert_eq!(enforcing.permissive, Some(false));
    assert_eq!(permissive.permissive, Some(true));
    assert_eq!(enforcing.scontext_raw, permissive.scontext_raw);
    assert_eq!(enforcing.tcontext_raw, permissive.tcontext_raw);
    assert_eq!(enforcing.tclass, permissive.tclass);
    assert_eq!(enforcing.perms, permissive.perms);

    let kind_enforcing =
        categorize(&enforcing, &policy).expect("enforcing record categorizes without error");
    let kind_permissive =
        categorize(&permissive, &policy).expect("permissive record categorizes without error");

    assert_eq!(
        kind_enforcing, kind_permissive,
        "flipping permissive=0<->1 must NOT change the category: categorization is a policy replay, not a log read"
    );
    assert_eq!(
        kind_enforcing,
        DenialKind::Constraint,
        "both records replay the same MLS-constrained access: Constraint regardless of permissive"
    );
}
