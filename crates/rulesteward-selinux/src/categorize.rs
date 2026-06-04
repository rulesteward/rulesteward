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
//! TE-before-CONS-before-RBAC-before-BOUNDS precedence (`audit2why.c:386-431`):
//!
//! | libsepol reason bit (`services.h:49-52`) | [`DenialKind`] |
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

use crate::{AvcDenial, DenialKind};

/// Error from the authoritative categorizer.
///
/// Distinct from a BADSCON, which is NOT an error: an undefined context maps to
/// [`DenialKind::ContextInvalid`] (see the module docs). These variants cover
/// the unrecoverable failures - the policy file could not be loaded, or the
/// denial referenced a class/permission the policy does not know (which, unlike
/// an undefined CONTEXT, is a malformed-input condition rather than the expected
/// cross-host mismatch). Return-code mapping is issue #107 (BADTCLASS /
/// BADPERM / BADCOMPUTE; f4b section 9 / `audit2why.c:13-19`).
#[derive(Debug, thiserror::Error)]
pub enum CategorizeError {
    /// The binary policy file could not be opened or parsed by libsepol
    /// (`sepol_set_policydb_from_file` failed). The wrapped string is the
    /// libsepol failure detail.
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
    /// Placeholder so the stub is a constructible type that names its purpose.
    /// The real field set (the libsepol policydb handle owned via the
    /// `rulesteward-selinux-sys` FFI) lands with issue #107.
    _private: (),
}

impl Policy {
    /// Load a binary `SELinux` policy from a file path (the operator-supplied
    /// `--policy <file>`).
    ///
    /// Calls `sepol_set_policydb_from_file` on the opened file, which reads the
    /// binary policy and initialises the internal sidtab in one call
    /// (f4b section 1.2, `services.c:133-153`).
    ///
    /// # Errors
    ///
    /// Returns [`CategorizeError::PolicyLoad`] when the file cannot be opened or
    /// libsepol rejects it (wrong magic / truncated / unsupported version).
    pub fn load(path: &Path) -> Result<Self, CategorizeError> {
        let _ = path;
        todo!("P5 #107/#108: open the policy file + sepol_set_policydb_from_file")
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
    let _ = (denial, policy);
    todo!("P5 #108: replay via sepol_compute_av_reason_buffer + map reason bits")
}
