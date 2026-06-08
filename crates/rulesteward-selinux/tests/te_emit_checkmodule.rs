//! Checkmodule round-trip validation harness for issue #104.
//!
//! Validates that `emit_te` produces `.te` source that `checkmodule -M -m`
//! accepts (exit 0). If the emitted `.te` fails checkmodule, the emission is
//! malformed - fix the emitter, not the test (f4 §3.2).
//!
//! These tests are TEST-ONLY: the product (`emit_te`) never shells out to
//! checkmodule. Shell-out lives only here (f4 §5.4 Q4 + spec Decision #11).
//!
//! # Skip behaviour
//!
//! If `checkmodule` is not in PATH the tests are skipped (not failed). This
//! allows the test suite to pass in environments without the `SELinux` toolchain.
//! In CI (the runner that has checkmodule on PATH) the tests will execute.
//!
//! # Grounding
//!
//! - `checkmodule -M -m` command: f4 §3.2, captured live on el8/el9/el10.
//!   `-M` = enable MLS/MCS (required; running policy has `:s0` in every context).
//!   `-m` = build a loadable MODULE (not a base policy).
//! - The primary artifact: `narrow.te` at `/mnt/side-projects/f4-selinux-grounding/`
//!   compiled cleanly (exit 0) on el9 and el10. Its content is reproduced inline
//!   below as the anchor case.
//! - checkmodule module-language ceiling: 4-19 (el8) / 4-21 (el9) / 4-24 (el10).
//!   The base-module syntax emitted by `emit_te` is low-end (v4); compiled on all
//!   three (f4 §4).

use std::collections::BTreeSet;
use std::io::Write as _;
use std::process::Command;

use rulesteward_selinux::{DenialGroup, DenialKind, emit_te};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `TeAllowable` [`DenialGroup`].
fn group(source_type: &str, target_type: &str, tclass: &str, perms: &[&str]) -> DenialGroup {
    DenialGroup {
        source_type: source_type.to_string(),
        target_type: target_type.to_string(),
        tclass: tclass.to_string(),
        perms: perms
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        any_permissive: false,
        kind: DenialKind::TeAllowable,
    }
}

/// Returns the path to `checkmodule` if it is present and executable, or `None`.
fn find_checkmodule() -> Option<std::path::PathBuf> {
    // Prefer PATH lookup via `which`.
    if let Ok(out) = Command::new("which").arg("checkmodule").output() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !path.is_empty() {
            return Some(std::path::PathBuf::from(path));
        }
    }
    // Fallback: known install location.
    let fallback = std::path::PathBuf::from("/usr/bin/checkmodule");
    fallback.exists().then_some(fallback)
}

/// Run `checkmodule -M -m -o <name.mod> <name.te>` and return (success, stderr).
///
/// Writes `te_source` to a temp file whose BASE NAME matches the module name
/// declared in the `.te` source. This is REQUIRED by checkmodule: it validates
/// that the module name in the source file matches the output base filename
/// (confirmed: checkmodule emits "Module name X is different than the output base
/// filename Y" and exits non-zero when they disagree).
///
/// The module name is extracted from the first `module <name> ...;` line of
/// `te_source`. Falls back to `label` if the line is absent (should not happen
/// in well-formed `emit_te` output).
fn checkmodule_compile(te_source: &str, label: &str) -> (bool, String) {
    // Extract module name from `module NAME 1.0;` first line.
    let module_name = te_source
        .lines()
        .find(|l| l.starts_with("module "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or(label)
        .to_string();

    let dir = std::env::temp_dir().join(format!("te_emit_test_{label}"));
    let _ = std::fs::create_dir_all(&dir);
    let te_path = dir.join(format!("{module_name}.te"));
    let mod_path = dir.join(format!("{module_name}.mod"));

    // Write the .te file.
    {
        let mut f = std::fs::File::create(&te_path).expect("failed to create temp .te file");
        f.write_all(te_source.as_bytes())
            .expect("failed to write temp .te file");
    }

    let output = Command::new("checkmodule")
        .args(["-M", "-m", "-o"])
        .arg(&mod_path)
        .arg(&te_path)
        .output()
        .expect("failed to spawn checkmodule (it was found via find_checkmodule)");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    (output.status.success(), stderr)
}

// ---------------------------------------------------------------------------
// Anchor A: The hand-validated narrow.te (primary grounding artifact, f4 §3.3)
//
// This is the EXACT text from /mnt/side-projects/f4-selinux-grounding/narrow.te
// that compiled + loaded + was removed on el9. If checkmodule rejects it that
// would mean the test environment itself is broken.
// ---------------------------------------------------------------------------

const NARROW_TE_GROUNDING: &str = "module narrow 1.0;\n\nrequire {\n\ttype logrotate_t;\n\ttype shadow_t;\n\tclass file { read getattr };\n\tclass dir read;\n}\n\n# Narrowly scoped: ONLY the exact (source,target,class,perms) denied. No macros, no attributes.\nallow logrotate_t shadow_t:file { read getattr };\nallow logrotate_t shadow_t:dir read;\n";

/// The grounding artifact itself must compile. This test validates the test
/// environment: if it fails the environment lacks a working checkmodule, not
/// an emission bug.
#[test]
fn test_grounding_artifact_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_grounding_artifact_compiles: checkmodule not in PATH");
        return;
    };
    let (ok, stderr) = checkmodule_compile(NARROW_TE_GROUNDING, "grounding_anchor");
    assert!(
        ok,
        "the hand-validated grounding narrow.te must compile with checkmodule -M -m \
         (f4 §3.3 live round-trip proof on el9); if this fails the environment is broken.\n\
         checkmodule stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Anchor B: emit_te output compiles - the el9 example pair (f4 §3.1)
//
// Groups that model the exact denials grounded in f4 §1.2 + §3.1:
//   logrotate_t -> shadow_t:file { read getattr }
//   logrotate_t -> shadow_t:dir read
// ---------------------------------------------------------------------------

/// `emit_te` for the el9-grounded example must produce output that passes
/// `checkmodule -M -m` (exit 0).
///
/// This is the core round-trip test: emission correctness confirmed by the
/// actual compile toolchain (f4 §3.2 + §5.2 "validation harness").
#[test]
fn test_emit_te_el9_example_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_emit_te_el9_example_compiles: checkmodule not in PATH");
        return;
    };
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read", "getattr"]),
        group("logrotate_t", "shadow_t", "dir", &["read"]),
    ];
    let te = emit_te(&groups, Some("narrow"));
    let (ok, stderr) = checkmodule_compile(&te, "el9_example");
    assert!(
        ok,
        "emit_te output for the el9-grounded example must compile with checkmodule -M -m \
         (f4 §3.2 validation harness).\n\
         emitted .te:\n{te}\n\
         checkmodule stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Anchor C: Single-perm group compiles (the `dir read;` form).
// ---------------------------------------------------------------------------

/// Single-perm group: the no-brace form `allow ... dir read;` must also compile.
#[test]
fn test_single_perm_group_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_single_perm_group_compiles: checkmodule not in PATH");
        return;
    };
    let groups = [group("httpd_t", "shadow_t", "dir", &["search"])];
    let te = emit_te(&groups, Some("singleperm"));
    let (ok, stderr) = checkmodule_compile(&te, "single_perm");
    assert!(
        ok,
        "single-perm emit_te output must compile with checkmodule -M -m.\n\
         emitted .te:\n{te}\n\
         checkmodule stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Anchor D: Multi-group, multi-type module compiles.
// ---------------------------------------------------------------------------

/// A module with multiple source+target type pairs must compile.
#[test]
fn test_multi_group_multi_type_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_multi_group_multi_type_compiles: checkmodule not in PATH");
        return;
    };
    let groups = [
        group("httpd_t", "shadow_t", "file", &["read"]),
        group("httpd_t", "httpd_config_t", "file", &["open", "read"]),
        group("crond_t", "shadow_t", "file", &["getattr"]),
    ];
    let te = emit_te(&groups, Some("multi_type_test"));
    let (ok, stderr) = checkmodule_compile(&te, "multi_type");
    assert!(
        ok,
        "multi-group, multi-type emit_te output must compile with checkmodule -M -m.\n\
         emitted .te:\n{te}\n\
         checkmodule stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Anchor E: Default module name (None) produces compilable output.
// ---------------------------------------------------------------------------

/// When `module_name=None` the emitter picks a default; it must still be valid
/// `SELinux` module-language syntax that `checkmodule` accepts.
#[test]
fn test_default_module_name_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_default_module_name_compiles: checkmodule not in PATH");
        return;
    };
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, None);
    let (ok, stderr) = checkmodule_compile(&te, "default_name");
    assert!(
        ok,
        "emit_te with module_name=None must produce compilable output.\n\
         emitted .te:\n{te}\n\
         checkmodule stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Anchor F: All-Permissive module compiles (#165).
//
// `checkmodule` REJECTS an empty `require {}` block ("local.te:4:ERROR 'syntax
// error' at token '}'", reproduced on el8/el9/el10) AND a bare `module NAME 1.0;`.
// The interesting non-degenerate case is an all-Permissive group set: it produces
// NO `allow` rules but DOES populate the require block, so it must still compile.
// (The truly-zero-denial case emits an explanatory comment, validated structurally
// in `te_emit_unit::test_empty_groups_emit_comment_not_fake_module`.)
// ---------------------------------------------------------------------------

#[test]
fn test_all_permissive_module_compiles() {
    let Some(_) = find_checkmodule() else {
        eprintln!("SKIP test_all_permissive_module_compiles: checkmodule not in PATH");
        return;
    };
    // A Permissive group: emit_te skips its `allow` rule but still requires its
    // types/class, so the module has a populated require block and no allow rules.
    let permissive = DenialGroup {
        source_type: "httpd_t".to_string(),
        target_type: "shadow_t".to_string(),
        tclass: "file".to_string(),
        perms: ["read"].iter().map(ToString::to_string).collect(),
        any_permissive: true,
        kind: DenialKind::Permissive,
    };
    let te = emit_te(std::slice::from_ref(&permissive), Some("permmod"));
    assert!(
        !te.contains("allow "),
        "an all-Permissive set must emit no allow rules:\n{te}"
    );
    let (ok, stderr) = checkmodule_compile(&te, "all_permissive");
    assert!(
        ok,
        "an all-Permissive module (require block, no allow rules) must still compile \
         with checkmodule -M -m (#165).\n\
         emitted .te:\n{te}\n\
         checkmodule stderr:\n{stderr}"
    );
}
