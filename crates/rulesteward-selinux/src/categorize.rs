//! `SELinux` denial categorization - the OPT-IN authoritative layer (P5 / #105).
//!
//! This is the authoritative counterpart to the always-on record-only floor
//! classifier in [`crate::denial`]. Where the floor classifier guesses from the
//! AVC record alone (`MlsSuspected` / `RoleSuspected` / `Permissive` /
//! `TeAllowable`), this layer REPLAYS the denial against a real binary `SELinux`
//! policy via libsepol's `sepol_compute_av_reason_buffer` and returns the
//! authoritative reason: [`DenialKind::TeAllowable`], [`DenialKind::Constraint`],
//! [`DenialKind::Bounds`], or [`DenialKind::ContextInvalid`] (f4 section 8
//! LOCKED Option A; FFI call sequence in f4b section 1).
//!
//! # Why this is feature-gated
//!
//! The replay needs libsepol statically linked under musl (issues #106 build.rs,
//! #107 FFI). That is ~224 KiB of opt-in binary (f4b section 7), so the entire
//! module - and the `rulesteward-selinux-sys` FFI it wraps - lives behind the
//! `authoritative-categorizer` cargo feature. The default workspace build links
//! no libsepol and pays nothing; only a feature-enabled build carries the LGPL
//! obligations (#110).
//!
//! # Categorization contract (f4 section 8 + f4b section 1.3)
//!
//! Map the libsepol reason bitmask to a [`DenialKind`], mirroring `audit2why`'s
//! TE-before-CONS-before-RBAC-before-BOUNDS precedence (`audit2why.c:386-431` (libselinux 3.10)):
//!
//! | libsepol reason bit (`services.h:49-52` (libsepol 3.10)) | [`DenialKind`] |
//! |---|---|
//! | `SEPOL_COMPUTEAV_TE` (0x1)     | [`DenialKind::TeAllowable`] |
//! | `SEPOL_COMPUTEAV_CONS` (0x2)   | [`DenialKind::Constraint`] |
//! | `SEPOL_COMPUTEAV_RBAC` (0x4)   | [`DenialKind::Constraint`] (RBAC is subsumed; the `process` role-change `constrain` fires first - f4b section 6.2) |
//! | `SEPOL_COMPUTEAV_BOUNDS` (0x8) | [`DenialKind::Bounds`] |
//!
//! A BADSCON / BADTCON (the supplied policy does not define a context in the
//! denial - `sepol_context_to_sid` fails, realistic in offline cross-host /
//! cross-version analysis) maps to [`DenialKind::ContextInvalid`] (NOT an error):
//! the caller falls back to the floor heuristic for the suggestion and emits a
//! `policy mismatch: context <ctx> invalid in supplied policy` warning (f4
//! section 8, the el8 `role-dyntransition` BADSCON case).
//!
//! Filled by pipeline P5 (issue #108). The FFI it calls is issue #107; the
//! static-link build is issue #106; known-answer validation is issue #109.

#![cfg(feature = "authoritative-categorizer")]

use std::path::Path;

use rulesteward_selinux_sys::{
    LoadError, Policy as SysPolicy, REASON_BOUNDS, REASON_CONS, REASON_RBAC, REASON_TE,
    ReplayError, ReplayOutcome,
};

use crate::{AvcDenial, DenialKind};

/// Error from the authoritative categorizer.
///
/// Distinct from a BADSCON, which is NOT an error: an undefined context maps to
/// [`DenialKind::ContextInvalid`] (see the module docs). These variants cover
/// the unrecoverable failures - the policy file could not be loaded, or the
/// denial referenced a class/permission the policy does not know (which, unlike
/// an undefined CONTEXT, is a malformed-input condition rather than the expected
/// cross-host mismatch). Return-code mapping is issue #107 (BADTCLASS /
/// BADPERM / BADCOMPUTE; f4b section 9 / `audit2why.c:13-19` (libselinux 3.10)).
#[derive(Debug, thiserror::Error)]
pub enum CategorizeError {
    /// The binary policy file could not be opened or parsed by libsepol
    /// (the `sepol_policydb_read` + `policydb_load_isids` load path the FFI uses
    /// failed). The wrapped string is the libsepol failure detail.
    #[error("failed to load SELinux policy: {0}")]
    PolicyLoad(String),
    /// The denial's `tclass` is not a class defined in the supplied policy
    /// (`sepol_string_to_security_class` failed). Unlike an undefined context,
    /// an unknown class is a malformed denial rather than a cross-host context
    /// mismatch, so it is an error, not [`DenialKind::ContextInvalid`].
    #[error("unknown object class {0:?} in supplied policy")]
    UnknownClass(String),
    /// A permission in the denial's brace list is not valid for its `tclass` in
    /// the supplied policy (`sepol_string_to_av_perm` failed).
    #[error("permission {perm:?} not valid for class {tclass:?} in supplied policy")]
    UnknownPermission {
        /// The offending permission token.
        perm: String,
        /// The class it was checked against.
        tclass: String,
    },
    /// The libsepol replay (`sepol_compute_av_reason_buffer`) returned a hard
    /// error (negative return code). The wrapped value is that code.
    #[error("libsepol reason computation failed (rc={0})")]
    ComputeFailed(i32),
    /// A replay input (a context / class / permission token) contained an
    /// interior NUL byte and could not be passed to libsepol. Mirrors the FFI's
    /// [`ReplayError::InputNul`] (issue #107); additive (D9, P5-local).
    #[error("replay input {what} contains an interior NUL byte")]
    InvalidInput {
        /// Which input carried the NUL (`"scontext"` / `"tcontext"` / `"tclass"`
        /// / `"perm"`).
        what: &'static str,
    },
}

/// A loaded binary `SELinux` policy, ready to categorize denials against.
///
/// Wraps the libsepol policydb that `sepol_set_policydb_from_file` initialises
/// (f4b section 1.2). Loading is the expensive step (read + sidtab init), so a
/// `Policy` is loaded once via [`Policy::load`] and reused across many
/// [`categorize`] calls - exactly the spike's load-once / categorize-many shape.
///
/// The real implementation (#107) owns the libsepol state and frees the
/// reason-buffer allocations libsepol hands back (`reason_buf` must be `free(3)`d
/// per f4b section 4.1); `Policy` is the owner whose `Drop` releases them.
pub struct Policy {
    /// The owned libsepol policydb + sidtab handles, behind the
    /// `rulesteward-selinux-sys` FFI (#107). All `unsafe` lives in that crate;
    /// this wrapper is safe.
    inner: SysPolicy,
}

impl Policy {
    /// Load a binary `SELinux` policy from a file path (the operator-supplied
    /// `--policy <file>`).
    ///
    /// Reads the binary policy into an owned libsepol handle and builds its SID
    /// table (f4b section 1.2). Loading touches no libsepol global state, so two
    /// policies can be loaded and categorized against in one process (the
    /// `rulesteward-selinux-sys` module docs explain the global-swap-per-replay
    /// model this enables).
    ///
    /// # Errors
    ///
    /// Returns [`CategorizeError::PolicyLoad`] when the file cannot be opened or
    /// libsepol rejects it (wrong magic / truncated / unsupported version).
    pub fn load(path: &Path) -> Result<Self, CategorizeError> {
        let inner = SysPolicy::load(path).map_err(|e| match e {
            // Every load failure collapses to PolicyLoad - the operator-facing
            // contract is "the supplied --policy could not be loaded"; the sys
            // error's Display carries the specific cause (open / read / sidtab).
            LoadError::Open { .. }
            | LoadError::Read { .. }
            | LoadError::Sidtab { .. }
            | LoadError::PathNul { .. } => CategorizeError::PolicyLoad(e.to_string()),
        })?;
        Ok(Policy { inner })
    }
}

/// Authoritatively categorize one AVC denial by replaying it against `policy`.
///
/// Replays `(scontext, tcontext, tclass, perms)` through
/// `sepol_compute_av_reason_buffer` and maps the resulting reason bitmask to a
/// [`DenialKind`] per the precedence table in the module docs. A denial whose
/// context is not defined in `policy` (BADSCON / BADTCON) returns
/// `Ok(`[`DenialKind::ContextInvalid`]`)`, NOT an error (f4 section 8).
///
/// Categorization is a POLICY REPLAY, not a log read: the `permissive` flag on
/// the record is IGNORED (a permissive denial categorises identically to an
/// enforcing one - f4 section 8 / f4b section 1, the audit2why behaviour). The
/// floor classifier's `permissive=1 -> Permissive` short-circuit lives in
/// [`crate::denial`], not here.
///
/// # Errors
///
/// Returns [`CategorizeError::UnknownClass`] / [`CategorizeError::UnknownPermission`]
/// when the denial's class or a permission is undefined in `policy` (a malformed
/// denial, distinct from the expected undefined-CONTEXT case), and
/// [`CategorizeError::ComputeFailed`] on a hard libsepol replay error.
pub fn categorize(denial: &AvcDenial, policy: &Policy) -> Result<DenialKind, CategorizeError> {
    Ok(categorize_with_outcome(denial, policy)?.0)
}

/// Authoritatively categorize one AVC denial, returning both the [`DenialKind`]
/// AND the underlying [`ReplayOutcome`].
///
/// This is a NON-BREAKING sibling of [`categorize`] (existing callers/tests are
/// unaffected - [`categorize`] still exists with its original signature). The
/// richer return type exists so the CLI layer can distinguish the two sub-cases
/// that both map to `DenialKind::ContextInvalid`:
///
/// - `ReplayOutcome::Reason(0)` - the supplied policy ALREADY ALLOWS the access
///   (D8 / locked decision #122). The operator message should say "already
///   allows" to diagnose the policy/host mismatch.
/// - `ReplayOutcome::BadContext` - the policy does not define a context in the
///   denial (BADSCON/BADTCON). The operator message should say "does not define".
///
/// Both map to `DenialKind::ContextInvalid` (the enum is FROZEN at 7 variants;
/// no 8th variant is added). The distinction lives at the `ReplayOutcome` layer.
///
/// # Errors
///
/// Same as [`categorize`].
pub fn categorize_with_outcome(
    denial: &AvcDenial,
    policy: &Policy,
) -> Result<(DenialKind, ReplayOutcome), CategorizeError> {
    // `permissive` is intentionally NOT read here: categorization replays the
    // policy, it does not interpret the log (see the fn docs + the frozen
    // permissive-flip invariant). The four replay inputs are the contexts, the
    // class, and the perm set.
    let outcome = policy
        .inner
        .replay(
            &denial.scontext_raw,
            &denial.tcontext_raw,
            &denial.tclass,
            &denial.perms,
        )
        .map_err(|e| match e {
            ReplayError::UnknownClass { tclass } => CategorizeError::UnknownClass(tclass),
            ReplayError::UnknownPermission { perm, tclass } => {
                CategorizeError::UnknownPermission { perm, tclass }
            }
            ReplayError::Compute { rc } => CategorizeError::ComputeFailed(rc),
            ReplayError::InputNul { what } => CategorizeError::InvalidInput { what },
        })?;

    let kind = match outcome {
        // An undefined source/target context (BADSCON / BADTCON) is the expected
        // cross-host case, not an error: fall through to ContextInvalid.
        ReplayOutcome::BadContext => DenialKind::ContextInvalid,
        ReplayOutcome::Reason(bits) => {
            // Precedence mirrors audit2why: TE before CONS/RBAC before BOUNDS
            // (module docs reason-bit table; audit2why.c:386-431 (libselinux 3.10)).
            if bits & REASON_TE != 0 {
                DenialKind::TeAllowable
            } else if bits & (REASON_CONS | REASON_RBAC) != 0 {
                DenialKind::Constraint
            } else if bits & REASON_BOUNDS != 0 {
                DenialKind::Bounds
            } else {
                // D8 (orchestrator-resolved): reason==0 means the SUPPLIED policy
                // already ALLOWS the access the host denied (a policy mismatch).
                // ContextInvalid is the least-wrong of the 7 frozen DenialKinds:
                // it declines to suggest a redundant allow and routes the caller
                // to the floor heuristic, rather than fabricating an 8th variant.
                DenialKind::ContextInvalid
            }
        }
    };
    Ok((kind, outcome))
}
