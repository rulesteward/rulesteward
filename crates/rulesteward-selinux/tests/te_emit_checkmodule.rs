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
//! If `checkmodule` is not in PATH these tests skip rather than fail, so the
//! suite still passes on a machine without the `SELinux` toolchain.
//!
//! That leniency has a failure mode, and this file lived in it. A skipped test
//! and a passing test are indistinguishable in `cargo test` output, because
//! stdout is swallowed for non-failing tests. So "6 compile-oracle assertions
//! ran" and "6 no-ops ran" looked identical, and until 2026-07-25 the second
//! was what happened on EVERY CI run: `checkpolicy` (which provides
//! `checkmodule`) was installed in no workflow in this repo. The doc here
//! previously asserted "In CI the tests will execute", which had never been
//! true.
//!
//! The fix is an explicit declaration rather than an inference. Set
//! `RS_REQUIRE_CHECKMODULE=1` and a missing `checkmodule` is a hard failure
//! instead of a silent skip; CI sets it. `checkmodule_availability_declared`
//! enforces it in one place, so the skip path stays available locally without
//! being able to hide in CI.
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

/// Environment variable that turns a missing `checkmodule` from a skip into a
/// hard failure. CI sets it; local runs generally do not.
const REQUIRE_ENV: &str = "RS_REQUIRE_CHECKMODULE";

/// Returns the path to `checkmodule` if it is present and executable, or `None`.
///
/// Walks `PATH` directly rather than shelling out to `which`. `which` is NOT
/// installed in the Rocky base images this harness runs in - verified on
/// rockylinux:8, where `command -v which` finds nothing, and ci.yml already
/// notes it was removed outright on RHEL 10. The old lookup therefore failed to
/// spawn in exactly the environment it was meant to serve, and only the
/// hardcoded `/usr/bin/checkmodule` fallback was carrying it.
fn find_checkmodule() -> Option<std::path::PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("checkmodule");
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    // Fallback: known install location, for a caller with an unusual PATH.
    let fallback = std::path::PathBuf::from("/usr/bin/checkmodule");
    is_executable(&fallback).then_some(fallback)
}

/// A regular file with at least one execute bit.
///
/// The mode check is load-bearing, not belt-and-braces. `execvp` SKIPS a
/// non-executable candidate and keeps searching PATH, so an `is_file()`-only
/// lookup could report `/some/dir/checkmodule` as the oracle while the compile
/// silently ran `/usr/bin/checkmodule` instead - an anti-vacuity instrument
/// naming a binary it never executed.
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Does this raw environment value declare the oracle required?
///
/// Pure and total so it can be pinned by a table test without mutating process
/// environment (which is global and would race the other tests here).
///
/// **Fail-closed.** Any non-empty value that is not an explicit off-switch means
/// required. The first cut of this compared `v == "1"`, which is fail-OPEN: a
/// later session writing `RS_REQUIRE_CHECKMODULE: true` in YAML (unquoted, so it
/// arrives as the string `true` - and ci.yml:40 already uses that unquoted
/// scalar style for `RUST_BACKTRACE: 1`) would silently get a fully green suite
/// in which nothing ran. That is the exact failure this file exists to prevent,
/// so the predicate has to lean the other way: ambiguous means required.
fn requirement_declared(raw: Option<&str>) -> bool {
    let Some(value) = raw else { return false };
    let value = value.trim();
    !(value.is_empty()
        || value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off"))
}

/// True when the environment declares that the oracle MUST be present.
fn checkmodule_required() -> bool {
    requirement_declared(std::env::var(REQUIRE_ENV).ok().as_deref())
}

/// Resolve the oracle for a single test, or explain why the test is not running.
///
/// Returns `Some(path)` when `checkmodule` is available. Otherwise: panics if
/// the environment declared the oracle required, and skips (returning `None`)
/// if it did not. Routing all six tests through one helper is what keeps the
/// skip decision from drifting per-test.
fn checkmodule_or_skip(test_name: &str) -> Option<std::path::PathBuf> {
    if let Some(path) = find_checkmodule() {
        return Some(path);
    }
    assert!(
        !checkmodule_required(),
        "{test_name}: checkmodule is REQUIRED here ({REQUIRE_ENV}=1) but was not \
         found on PATH. Install the 'checkpolicy' package, which provides \
         /usr/bin/checkmodule. Refusing to skip: a silent skip is why this \
         harness sat dormant in CI (#572 session)."
    );
    eprintln!("SKIP {test_name}: checkmodule not in PATH");
    None
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

    // Run the path `find_checkmodule` actually resolved, NOT the bare name.
    // `Command::new("checkmodule")` would re-resolve through PATH, which
    // diverges from discovery in two ways: the documented `/usr/bin/checkmodule`
    // fallback is unreachable via PATH (so every test panicked with the ironic
    // "it was found via find_checkmodule" message when PATH lacked it), and a
    // shadowing entry could make the compile run a different binary than the one
    // reported. Resolve once, run that.
    let oracle = find_checkmodule()
        .expect("checkmodule_compile called without an oracle; use checkmodule_or_skip first");
    let output = Command::new(&oracle)
        .args(["-M", "-m", "-o"])
        .arg(&mod_path)
        .arg(&te_path)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn the resolved oracle {}: {e}",
                oracle.display()
            )
        });

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
    let Some(_) = checkmodule_or_skip("test_grounding_artifact_compiles") else {
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
    let Some(_) = checkmodule_or_skip("test_emit_te_el9_example_compiles") else {
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
    let Some(_) = checkmodule_or_skip("test_single_perm_group_compiles") else {
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
    let Some(_) = checkmodule_or_skip("test_multi_group_multi_type_compiles") else {
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
    let Some(_) = checkmodule_or_skip("test_default_module_name_compiles") else {
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
    let Some(_) = checkmodule_or_skip("test_all_permissive_module_compiles") else {
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

// ---------------------------------------------------------------------------
// Anti-vacuity guard
// ---------------------------------------------------------------------------

/// Deliberately malformed policy. A real `checkmodule` rejects this with
/// `syntax error at token 'this'`; verified live on checkpolicy 3.6 (el9),
/// where it exits 1 while a minimal valid module exits 0.
const MALFORMED_TE: &str = "module rs_negative_control 1.0;\n\
                            this is not valid policy syntax at all;\n";

/// The anti-vacuity guard for this file.
///
/// Two failure modes are covered here, both of which previously looked exactly
/// like success:
///
/// 1. **The oracle is absent.** The six tests above skip, and `cargo test`
///    swallows stdout on non-failing tests, so a fully dormant harness is
///    indistinguishable from a passing one. When CI declares the oracle
///    required via `RS_REQUIRE_CHECKMODULE=1`, that now fails here, in one
///    place, with a message naming the package to install.
///
/// 2. **The oracle is present but not discriminating.** Every compile
///    assertion in this file is `assert!(ok)`, where `ok` is just
///    `status.success()`. If `checkmodule` resolved to something that always
///    exits 0 - `/bin/true`, a stub on PATH, a wrapper swallowing errors - all
///    six tests would pass while proving nothing. So this test drives the
///    oracle in BOTH directions and requires it to disagree with itself:
///    accept the hand-validated grounding artifact, reject malformed policy.
///    That is the two-sided positive control CONTRIBUTING's "Differential
///    oracle contract" requires of every harness.
#[test]
fn checkmodule_availability_declared() {
    let Some(path) = checkmodule_or_skip("checkmodule_availability_declared") else {
        eprintln!(
            "checkmodule oracle: ABSENT - the 6 compile-oracle anchors in this file did \
             NOT run. Set {REQUIRE_ENV}=1 to make this a hard failure (CI does)."
        );
        return;
    };

    let (good_ok, good_stderr) = checkmodule_compile(NARROW_TE_GROUNDING, "control_accept");
    assert!(
        good_ok,
        "positive control: the hand-validated grounding narrow.te must COMPILE. \
         It did not, so the oracle at {} is broken and every other assertion in \
         this file is meaningless.\ncheckmodule stderr:\n{good_stderr}",
        path.display()
    );

    let (bad_ok, _bad_stderr) = checkmodule_compile(MALFORMED_TE, "control_reject");
    assert!(
        !bad_ok,
        "negative control: deliberately malformed policy must be REJECTED, but the \
         oracle at {} accepted it. Every compile assertion in this file is \
         assert!(status.success()), so an oracle that never fails makes all six \
         anchors vacuous. Verify that `checkmodule` on PATH is the real \
         checkpolicy binary.",
        path.display()
    );

    eprintln!(
        "checkmodule oracle: AVAILABLE at {} (two-sided control OK: accepts valid, \
         rejects malformed)",
        path.display()
    );
}

/// Pin the requirement predicate's whole decision table.
///
/// The interesting rows are the ones a four-state manual matrix does not reach:
/// an unset variable and `=1` are the two INTERIOR points, and sampling only
/// those is how the fail-open `v == "1"` comparison survived its first review.
/// Every "truthy but not literally 1" spelling must require the oracle, because
/// the cost of being wrong is asymmetric: a spurious hard failure is loud and
/// takes one commit to fix, while a spurious skip is silent and hid this whole
/// harness from CI for months.
#[test]
fn requirement_declaration_is_fail_closed() {
    // Off: absent, or an explicit off-switch.
    for raw in [
        None,
        Some(""),
        Some("  "),
        Some("0"),
        Some("false"),
        Some("FALSE"),
        Some("no"),
        Some("off"),
    ] {
        assert!(
            !requirement_declared(raw),
            "{raw:?} must NOT require the oracle"
        );
    }
    // On: the documented spelling, plus every plausible near-miss.
    for raw in [
        Some("1"),
        Some("1 "),
        Some(" 1"),
        Some("true"),
        Some("True"),
        Some("yes"),
        Some("on"),
        Some("required"),
    ] {
        assert!(
            requirement_declared(raw),
            "{raw:?} must require the oracle (fail-closed: ambiguous means required)"
        );
    }
}

/// Whatever `find_checkmodule` returns must be runnable.
///
/// Its doc says "present and executable", but the first cut only checked
/// `is_file()`. A non-executable file named `checkmodule` earlier on PATH was
/// therefore reported as the oracle while `Command` actually ran a different
/// binary (execvp skips non-executable candidates), so the anti-vacuity
/// instrument named a binary it had never executed.
#[test]
fn resolved_oracle_path_is_executable() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(path) = find_checkmodule() else {
        eprintln!("SKIP resolved_oracle_path_is_executable: checkmodule not present");
        return;
    };
    let mode = std::fs::metadata(&path)
        .expect("resolved oracle path must be stat-able")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "find_checkmodule returned {} but it is not executable (mode {:o}); \
         Command would silently resolve a DIFFERENT binary via PATH",
        path.display(),
        mode
    );
}
