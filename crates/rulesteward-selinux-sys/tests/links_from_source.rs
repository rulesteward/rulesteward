//! Build/link smoke test for the from-source libsepol archive (#120).
//!
//! This is the BUILD-LAYER guard: it proves the `build.rs` from-source `make`
//! build produced an archive that (a) links (every libsepol symbol `Policy::load`
//! references resolves at link time) and (b) actually EXECUTES real libsepol code
//! (`sepol_policydb_read` runs and rejects a non-policy input). It deliberately
//! does NOT assert categorization correctness - the known-answer suite in
//! `rulesteward-selinux/tests/known_answer_categorize.rs` is the functional oracle
//! for that. Splitting the two means a future failure localizes cleanly: a break
//! here is the build/link layer (this PR's concern), a break in the KAT is the
//! categorizer logic.
//!
//! Gated on the `vendored` feature: that feature is what makes `build.rs` build
//! and link libsepol at all (a build WITHOUT `vendored` compiles the `-sys` rlib
//! with a no-op `build.rs` and links no libsepol). Without the feature there is
//! no archive to link against, so the test must not compile.

#![cfg(feature = "vendored")]

use std::fs;
use std::path::PathBuf;

use rulesteward_selinux_sys::{LoadError, Policy};

/// A path that does not exist must surface as `LoadError::Open` - this forces the
/// link of every symbol `Policy::load` references (`sepol_debug`, `fopen`,
/// `sepol_policydb_create`, `sepol_policy_file_*`, `sepol_policydb_read`,
/// `policydb_load_isids`, ...). If the from-source archive were missing any of
/// them, this test target would fail to LINK, not just fail to assert.
#[test]
fn load_missing_file_is_open_error() {
    let missing = PathBuf::from("/nonexistent/rulesteward-libsepol-smoke/does-not-exist.policy");
    match Policy::load(&missing) {
        Err(LoadError::Open { .. }) => {}
        Ok(_) => panic!("expected LoadError::Open for a missing policy file, got Ok(loaded)"),
        Err(e) => panic!("expected LoadError::Open for a missing policy file, got {e:?}"),
    }
}

/// A file that exists but is NOT a binary policy must surface as `LoadError::Read`.
/// This forces real libsepol code to RUN: `sepol_policydb_read` parses the bytes,
/// rejects the bad magic, and returns non-zero. A linked-but-broken archive (wrong
/// ABI, miscompiled) would crash or misbehave here instead of cleanly returning
/// `Read`, so this is the "the archive actually executes" half of the smoke.
#[test]
fn load_garbage_is_read_error() {
    // Unique per-process temp path; no external crates, no Date/rand needed.
    let tmp = std::env::temp_dir().join(format!(
        "rulesteward-libsepol-smoke-{}.bin",
        std::process::id()
    ));
    fs::write(
        &tmp,
        b"this is definitely not a binary SELinux policy\x00\x01\x02",
    )
    .expect("write temp garbage file");

    let result = Policy::load(&tmp);
    let _ = fs::remove_file(&tmp); // best-effort cleanup before asserting

    match result {
        Err(LoadError::Read { .. }) => {}
        Ok(_) => panic!("expected LoadError::Read for a non-policy file, got Ok(loaded)"),
        Err(e) => panic!("expected LoadError::Read for a non-policy file, got {e:?}"),
    }
}
