//! Shared test support for the `SELinux` corpus oracle (#101).
//!
//! Decodes the solid zstd archive of the three stock binary `SELinux` policies
//! (`policy.31` el8 / `policy.33` el9 / `policy.35` el10) IN-PROCESS and memoizes
//! one loaded [`Policy`] per version. No shell-out, no docker: the archive is
//! vendored under `tests/corpus/selinux/_policies/policies.tar.zst` and unpacked
//! once into a process-lifetime [`tempfile::TempDir`].
//!
//! # Load-once / categorize-many
//!
//! `Policy::load` is the expensive step (binary read + sidtab build), so this
//! module unpacks the archive exactly once (a `OnceLock<TempDir>`) and loads each
//! policy version exactly once (a `OnceLock<Policy>` per version). Every corpus
//! scenario that needs the el9 policy shares the same loaded handle.

#![cfg(feature = "authoritative-categorizer")]
// Shared test scaffolding, not product code, so the helpers any one binary does
// not use would trip `dead_code`. (As of 2026-08-03 `mod support;` appears in
// exactly one test target, `selinux_corpus_oracle.rs`; this file is written to be
// included by more, which is why the allow stays.)
#![allow(dead_code)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rulesteward_core::oracle_corpus::resolve_corpus_root;
use rulesteward_selinux::Policy;
use tempfile::TempDir;

/// Path to the vendored solid zstd policy archive.
///
/// Resolved through the SAME `RS_ORACLE_CORPUS_SELINUX` override as the scenario
/// directories, because `_policies/` lives INSIDE the corpus tree and is corpus
/// DATA, not source. Reading it from the compiled-in manifest directory while the
/// scenarios came from an override would make `just diff-selinux-branch` vary two
/// things at once - the product AND the policy fixtures - which is not a
/// differential. Unset (the `just test` path) still resolves to the committed
/// corpus. (This module is included by exactly one test binary,
/// `selinux_corpus_oracle.rs`; the invariant is stated so it survives a second.)
fn archive_path() -> PathBuf {
    let default = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/selinux");
    // The sentinel is spelled out rather than referenced as `crate::SENTINEL`,
    // which IS reachable (this is a `mod support;` module of the same test crate,
    // not an `include!`). It is spelled out because this module is written to be
    // usable by more than one test binary and only `selinux_corpus_oracle.rs`
    // defines that const.
    //
    // NOTHING MECHANICALLY ENFORCES THE MATCH. A mismatched sentinel produces a
    // line matching NEITHER of the driver's guards - not the positive fixed-string
    // match, not the `mode=committed` refusal - so the run passes clean. Change
    // one, change both.
    let (root, _mode) =
        resolve_corpus_root("RS-DIFF-SELINUX", "RS_ORACLE_CORPUS_SELINUX", &default);
    root.join("_policies/policies.tar.zst")
}

/// Unpack the policy archive once into a process-lifetime temp dir.
///
/// Decodes `policies.tar.zst` via a streaming zstd decoder feeding a tar reader
/// (`tar::Archive::new(zstd::stream::read::Decoder::new(File::open(..)?)?)`) and
/// unpacks every entry under a fresh [`TempDir`]. The `TempDir` is leaked into a
/// `OnceLock` so the extracted policy files outlive every test in the binary and
/// are cleaned up only at process exit.
fn policy_dir() -> &'static TempDir {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let archive = archive_path();
        let file = File::open(&archive)
            .unwrap_or_else(|e| panic!("open policy archive {}: {e}", archive.display()));
        let decoder = zstd::stream::read::Decoder::new(file)
            .unwrap_or_else(|e| panic!("zstd decoder for {}: {e}", archive.display()));
        let mut tar = tar::Archive::new(decoder);
        let dir = TempDir::new().expect("create temp dir for policies");
        tar.unpack(dir.path())
            .unwrap_or_else(|e| panic!("unpack policy archive {}: {e}", archive.display()));
        dir
    })
}

/// Resolve the on-disk path of a `policy.NN` file inside the unpacked archive.
///
/// The archive stores the three policies as bare `policy.31` / `policy.33` /
/// `policy.35` files. Some `tar` producers prefix entries with a leading
/// directory, so this searches the top level AND one level down before giving up.
fn policy_file(vers: u32) -> PathBuf {
    let root = policy_dir().path();
    let leaf = format!("policy.{vers}");

    let direct = root.join(&leaf);
    if direct.is_file() {
        return direct;
    }
    // Fall back to a one-level-deep search (tolerates a wrapping dir entry).
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let candidate = entry.path().join(&leaf);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    panic!(
        "policy.{vers} not found under unpacked archive at {} (looked at top level and one dir deep)",
        root.display()
    );
}

/// Return the memoized loaded [`Policy`] for a policy version (31 / 33 / 35).
///
/// Loads the policy exactly once per version (a `OnceLock` per supported version)
/// and hands back a `&'static` reference, so callers do `categorize(d, policy(33))`
/// without re-reading the binary each call.
///
/// # Panics
///
/// Panics on an unsupported version or if `Policy::load` fails (a corrupt or
/// missing vendored policy is a fixture bug, not a runtime condition).
pub fn policy(vers: u32) -> &'static Policy {
    static P31: OnceLock<Policy> = OnceLock::new();
    static P33: OnceLock<Policy> = OnceLock::new();
    static P35: OnceLock<Policy> = OnceLock::new();
    let cell = match vers {
        31 => &P31,
        33 => &P33,
        35 => &P35,
        other => panic!("unsupported policy version {other} (expected 31, 33, or 35)"),
    };
    cell.get_or_init(|| {
        let path = policy_file(vers);
        Policy::load(&path)
            .unwrap_or_else(|e| panic!("load policy.{vers} from {}: {e}", path.display()))
    })
}
