//! FFI-layer known-answer suite for the libsepol shim (#131).
//!
//! This is the FUNCTIONAL oracle for `Policy::load` / `Policy::replay` at the
//! `-sys` boundary, complementing the other two layers:
//! - `links_from_source.rs` (this crate) is the BUILD/LINK smoke: archive links
//!   and executes. It keeps the `LoadError::Open` / `LoadError::Read` cases.
//! - `rulesteward-selinux/tests/known_answer_categorize.rs` is the MAPPING
//!   oracle: reason bits -> `DenialKind`.
//!
//! This suite exists so `crates/rulesteward-selinux-sys/src/lib.rs` can sit in
//! the cargo-mutants gate (#131): every assertion below is exact (full-bitmask
//! equality or variant + field identity), so a mutated shim observably fails.
//!
//! Ground truth: the committed fixture policies and their `.cil` sources in
//! `rulesteward-selinux/tests/fixtures/` (reused via a workspace-relative path;
//! no binary duplication):
//! - `kat.policy` (kat.cil): file write on `src_t -> tgt_t` is a deliberate TE
//!   gap (bits=0x1); `mlsconstrain (file (read)) (dom l1 l2)` blocks read when
//!   the source level does not dominate the target (bits=0x2);
//!   `constrain (process (dyntransition)) (eq r1 r2)` blocks role-crossing
//!   dyntransition on the TE-allowed `src_t -> src_t` pair (bits=0x2).
//! - `bounds.policy` (bounds.cil): child write over-grant stripped by the
//!   typebounds runtime check (bits=0x8).
//! - `allow.policy` (allow.cil): `(allow src_t tgt_t (file (read open getattr)))`
//!   so read is fully allowed (bits=0x0) and write is a pure TE gap with zero
//!   constraints (the multi-perm accumulation cases).
//!
//! The expected bitmasks match the `bits=0x..` citations in the categorize KAT.

#![cfg(feature = "vendored")]

use std::path::{Path, PathBuf};

use rulesteward_selinux_sys::{
    LoadError, Policy, REASON_BOUNDS, REASON_CONS, REASON_TE, ReplayError, ReplayOutcome,
};

/// Resolve a committed fixture from the `-selinux` crate's test tree.
///
/// Workspace-relative on purpose: the fixtures are git-tracked binaries, and
/// cargo-mutants copies the whole workspace into its scratch tree, so this
/// resolves there too. A wrong path fails the cargo-mutants BASELINE run
/// loudly; it can never silently weaken the gate.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ parent dir exists")
        .join("rulesteward-selinux/tests/fixtures")
        .join(name)
}

fn load(name: &str) -> Policy {
    let path = fixture(name);
    Policy::load(&path).unwrap_or_else(|e| panic!("load {name}: {e}"))
}

fn perms(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

/// Replay and unwrap the `Ok` outcome (the error path has its own tests).
fn replay_ok(policy: &Policy, scon: &str, tcon: &str, class: &str, p: &[&str]) -> ReplayOutcome {
    policy
        .replay(scon, tcon, class, &perms(p))
        .unwrap_or_else(|e| panic!("replay {scon} -> {tcon} {class} {p:?}: {e}"))
}

// kat.cil contexts: user u1, roles r_a/r_b, types src_t/tgt_t, MLS s0/s1 with
// categories c0.c1 (userrange u1 spans l0..l1, so s1 contexts are valid).
const KAT_SCON: &str = "u1:r_a:src_t:s0:c0.c1";
const KAT_TCON_S0: &str = "u1:r_a:tgt_t:s0:c0.c1";
const KAT_TCON_S1: &str = "u1:r_a:tgt_t:s1:c0.c1";
// Target of the role-constraint case: the TE allow for dyntransition is
// src_t -> src_t (kat.cil line 45), so the target TYPE must be src_t and only
// the ROLE differs (r_a -> r_b) for `(eq r1 r2)` to be the operative deny.
const KAT_TCON_ROLE_B: &str = "u1:r_b:src_t:s0:c0.c1";
// A context whose type is not defined in any fixture policy (BADSCON/BADTCON).
const UNDEFINED_CON: &str = "u1:r_a:zzz_undefined_t:s0:c0.c1";

// allow.cil contexts (single sensitivity s0, categories c0.c1).
const ALLOW_SCON: &str = "u1:r_a:src_t:s0:c0.c1";
const ALLOW_TCON: &str = "u1:r_a:tgt_t:s0:c0.c1";

// bounds.cil contexts (plain s0, no categories; object_r is implicitly
// declared by secilc and valid for the target object).
const BOUNDS_SCON: &str = "system_u:system_r:rsbnd_child_t:s0";
const BOUNDS_TCON: &str = "system_u:object_r:tmp_t:s0";

/// All three committed fixtures load: exercises the full success path of
/// `Policy::load` (fopen, policydb create/read, isids), killing rc-check
/// inversions that would turn a good load into an error (or vice versa).
#[test]
fn load_all_fixtures_succeeds() {
    for name in ["kat.policy", "bounds.policy", "allow.policy"] {
        let _policy = load(name);
    }
}

/// A path with an interior NUL byte cannot reach `fopen` and must surface as
/// `LoadError::PathNul` (the `path_to_cstring -> None` arm).
#[test]
fn load_interior_nul_path_is_pathnul() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = Path::new(OsStr::from_bytes(b"fixtures/kat\0.policy"));
    match Policy::load(path) {
        Err(LoadError::PathNul { .. }) => {}
        Ok(_) => panic!("expected LoadError::PathNul for an interior-NUL path, got Ok(loaded)"),
        Err(e) => panic!("expected LoadError::PathNul for an interior-NUL path, got {e:?}"),
    }
}

/// kat.policy: file write on `src_t -> tgt_t` has NO TE allow (kat.cil line
/// 46) -> exactly the TE bit. Also pins the success path through the global
/// swap (`sepol_set_policydb` / `sepol_set_sidtab` rc checks).
#[test]
fn replay_te_gap_is_reason_te() {
    let policy = load("kat.policy");
    let out = replay_ok(&policy, KAT_SCON, KAT_TCON_S0, "file", &["write"]);
    assert_eq!(out, ReplayOutcome::Reason(REASON_TE));
}

/// kat.policy: file read IS TE-allowed but `mlsconstrain (file (read))
/// (dom l1 l2)` blocks it when the source level (s0) does not dominate the
/// target (s1) -> exactly the CONS bit (distinguishes 0x2 from 0x1).
#[test]
fn replay_mls_constraint_is_reason_cons() {
    let policy = load("kat.policy");
    let out = replay_ok(&policy, KAT_SCON, KAT_TCON_S1, "file", &["read"]);
    assert_eq!(out, ReplayOutcome::Reason(REASON_CONS));
}

/// kat.policy: process dyntransition IS TE-allowed (`src_t -> src_t`) but
/// `constrain (process (dyntransition)) (eq r1 r2)` blocks the `r_a` -> `r_b`
/// role crossing -> exactly the CONS bit. Exercises the second object class
/// (`process`) through `sepol_string_to_security_class`.
#[test]
fn replay_role_constraint_is_reason_cons() {
    let policy = load("kat.policy");
    let out = replay_ok(
        &policy,
        KAT_SCON,
        KAT_TCON_ROLE_B,
        "process",
        &["dyntransition"],
    );
    assert_eq!(out, ReplayOutcome::Reason(REASON_CONS));
}

/// bounds.policy: the child's write over-grant is stripped by the typebounds
/// runtime check (parent lacks write on `tmp_t`) -> exactly the BOUNDS bit.
#[test]
fn replay_typebounds_is_reason_bounds() {
    let policy = load("bounds.policy");
    let out = replay_ok(&policy, BOUNDS_SCON, BOUNDS_TCON, "file", &["write"]);
    assert_eq!(out, ReplayOutcome::Reason(REASON_BOUNDS));
}

/// allow.policy: file read is explicitly allowed and no constraint applies ->
/// reason bitmask exactly 0. Kills mutants that inject spurious bits into the
/// passthrough or invert a success-path check.
#[test]
fn replay_allowed_access_is_reason_zero() {
    let policy = load("allow.policy");
    let out = replay_ok(&policy, ALLOW_SCON, ALLOW_TCON, "file", &["read"]);
    assert_eq!(out, ReplayOutcome::Reason(0));
}

/// An undefined SOURCE context is the expected cross-host case: `Ok(BadContext)`,
/// never an `Err`. Exercises the FIRST `sepol_context_to_sid` site (lib.rs:490).
#[test]
fn replay_undefined_scontext_is_badcontext() {
    let policy = load("kat.policy");
    let out = replay_ok(&policy, UNDEFINED_CON, KAT_TCON_S0, "file", &["read"]);
    assert_eq!(out, ReplayOutcome::BadContext);
}

/// An undefined TARGET context with a VALID source: the first
/// `sepol_context_to_sid` call must succeed so only the SECOND site
/// (lib.rs:494) is exercised - a mutant there survives the scontext-only test.
#[test]
fn replay_undefined_tcontext_is_badcontext() {
    let policy = load("kat.policy");
    let out = replay_ok(&policy, KAT_SCON, UNDEFINED_CON, "file", &["read"]);
    assert_eq!(out, ReplayOutcome::BadContext);
}

/// A class not defined in the policy is a hard `ReplayError::UnknownClass`
/// carrying the offending token (variant + field identity, not just `is_err`).
#[test]
fn replay_unknown_class_is_error() {
    let policy = load("kat.policy");
    match policy.replay(
        KAT_SCON,
        KAT_TCON_S0,
        "zzz_no_such_class",
        &perms(&["read"]),
    ) {
        Err(ReplayError::UnknownClass { tclass }) => assert_eq!(tclass, "zzz_no_such_class"),
        Ok(o) => panic!("expected UnknownClass, got Ok({o:?})"),
        Err(e) => panic!("expected UnknownClass, got {e:?}"),
    }
}

/// `dyntransition` is a real permission - but of class `process`, not `file`
/// (kat.cil lines 4-5). Asking for it on `file` must be
/// `ReplayError::UnknownPermission` with BOTH fields plumbed through.
#[test]
fn replay_unknown_permission_is_error() {
    let policy = load("kat.policy");
    match policy.replay(KAT_SCON, KAT_TCON_S0, "file", &perms(&["dyntransition"])) {
        Err(ReplayError::UnknownPermission { perm, tclass }) => {
            assert_eq!(perm, "dyntransition");
            assert_eq!(tclass, "file");
        }
        Ok(o) => panic!("expected UnknownPermission, got Ok({o:?})"),
        Err(e) => panic!("expected UnknownPermission, got {e:?}"),
    }
}

/// Each replay input rejects an interior NUL with `InputNul { what }` naming
/// exactly the offending input (the four `CString::new` early returns).
#[test]
fn replay_interior_nul_inputs_are_inputnul() {
    let policy = load("kat.policy");
    let cases: [(&str, &str, &str, &[&str], &str); 4] = [
        (
            "u1:r_a:src\0_t:s0:c0.c1",
            KAT_TCON_S0,
            "file",
            &["read"],
            "scontext",
        ),
        (
            KAT_SCON,
            "u1:r_a:tgt\0_t:s0:c0.c1",
            "file",
            &["read"],
            "tcontext",
        ),
        (KAT_SCON, KAT_TCON_S0, "fi\0le", &["read"], "tclass"),
        (KAT_SCON, KAT_TCON_S0, "file", &["re\0ad"], "perm"),
    ];
    for (scon, tcon, class, p, expected_what) in cases {
        match policy.replay(scon, tcon, class, &perms(p)) {
            Err(ReplayError::InputNul { what }) => assert_eq!(
                what, expected_what,
                "NUL in {expected_what} must be attributed to {expected_what}"
            ),
            Ok(o) => panic!("expected InputNul({expected_what}), got Ok({o:?})"),
            Err(e) => panic!("expected InputNul({expected_what}), got {e:?}"),
        }
    }
}

/// allow.policy: write is a pure TE gap, read is allowed. Requesting
/// `[write, read]` must OR both bits (denied perm FIRST: a `|=` -> `=`
/// last-write-wins mutant keeps only read's bit and reports `Reason(0)`),
/// while `[read]` alone is `Reason(0)` - together they pin the `|=`
/// accumulation at lib.rs:514.
#[test]
fn replay_multi_perm_accumulates_requested_bits() {
    let policy = load("allow.policy");
    let both = replay_ok(&policy, ALLOW_SCON, ALLOW_TCON, "file", &["write", "read"]);
    assert_eq!(both, ReplayOutcome::Reason(REASON_TE));
    let read_only = replay_ok(&policy, ALLOW_SCON, ALLOW_TCON, "file", &["read"]);
    assert_eq!(read_only, ReplayOutcome::Reason(0));
}

/// allow.policy: a duplicated denied perm must stay denied. A `|=` -> `^=`
/// mutant XORs the second `write` back OUT of the request (requested == 0 ->
/// `Reason(0)`), so idempotence is the observable.
#[test]
fn replay_duplicate_perm_is_idempotent() {
    let policy = load("allow.policy");
    let out = replay_ok(&policy, ALLOW_SCON, ALLOW_TCON, "file", &["write", "write"]);
    assert_eq!(out, ReplayOutcome::Reason(REASON_TE));
}

/// Two live policies alternating replays in one process: each replay must
/// re-point the libsepol global at ITS policy under `GLOBAL_REPLAY_LOCK`.
/// kat answers CONS for the MLS case while allow answers `Reason(0)` for its
/// allowed read, three rounds in a row - a shim that fails to swap (or swaps
/// to the wrong handle) leaks one policy's answer into the other's replay.
#[test]
fn interleaved_policies_replay_independently() {
    let kat = load("kat.policy");
    let allow = load("allow.policy");
    for round in 0..3 {
        let from_kat = replay_ok(&kat, KAT_SCON, KAT_TCON_S1, "file", &["read"]);
        assert_eq!(
            from_kat,
            ReplayOutcome::Reason(REASON_CONS),
            "kat MLS answer drifted on round {round}"
        );
        let from_allow = replay_ok(&allow, ALLOW_SCON, ALLOW_TCON, "file", &["read"]);
        assert_eq!(
            from_allow,
            ReplayOutcome::Reason(0),
            "allow answer drifted on round {round}"
        );
    }
}
