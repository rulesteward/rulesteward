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
// This file is compiled into MULTIPLE integration-test binaries via `mod support;`.
// Any given binary uses only a subset of the helpers, so the unused ones would
// trip `dead_code`. The module is shared test scaffolding, not product code.
#![allow(dead_code)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rulesteward_selinux::Policy;
use tempfile::TempDir;

/// Path to the vendored solid zstd policy archive.
fn archive_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/selinux/_policies/policies.tar.zst")
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
