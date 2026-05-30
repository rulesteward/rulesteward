//! Integration gate for the `rules-templates/` sample fapolicyd rule files.
//!
//! These tests are RED until the implementer creates the directory, sample
//! `.rules` files, and `LICENSE`. They verify:
//!
//! 1. `rules-templates/` exists and contains at least 2 non-dotfile `*.rules` files.
//! 2. `rules-templates/LICENSE` exists and its text includes a BSD-3-Clause marker
//!    and the copyright holder `RuleSteward Authors`.
//! 3. `rulesteward fapolicyd lint rules-templates/` exits 0 with zero diagnostics
//!    (no `fapd-` code anywhere in JSON output, i.e. the array is `[]`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

/// Resolve the `rules-templates/` directory relative to this crate's manifest.
/// The cli crate lives at `crates/rulesteward-cli`; the repo root is two levels up.
fn rules_templates_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules-templates")
}

/// Asserts that `rules-templates/` exists and contains at least 2 non-dotfile
/// files with a `.rules` extension.
#[test]
fn rules_templates_dir_exists_with_at_least_two_rules_files() {
    let dir = rules_templates_dir();

    assert!(
        dir.exists(),
        "rules-templates/ directory does not exist at {dir:?} - implementer must create it"
    );
    assert!(
        dir.is_dir(),
        "rules-templates/ path exists but is not a directory: {dir:?}"
    );

    let rules_files: Vec<_> = std::fs::read_dir(&dir)
        .expect("read_dir rules-templates/")
        .filter_map(|entry| {
            let entry = entry.expect("DirEntry");
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Exclude dotfiles; include only *.rules files.
            if name_str.starts_with('.') {
                return None;
            }
            if name_str.ends_with(".rules") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();

    assert!(
        rules_files.len() >= 2,
        "rules-templates/ must contain at least 2 non-dotfile *.rules files, \
         found {}: {rules_files:?}",
        rules_files.len()
    );
}

/// Asserts that `rules-templates/LICENSE` exists and its text includes both a
/// BSD-3-Clause marker and the copyright holder `RuleSteward Authors`.
#[test]
fn rules_templates_license_exists_and_is_bsd3() {
    let license_path = rules_templates_dir().join("LICENSE");

    assert!(
        license_path.exists(),
        "rules-templates/LICENSE does not exist at {license_path:?} - implementer must create it"
    );

    let contents = std::fs::read_to_string(&license_path).expect("read rules-templates/LICENSE");

    assert!(
        contents.contains("BSD-3-Clause")
            || contents.contains("Redistribution and use in source and binary forms"),
        "rules-templates/LICENSE must contain BSD-3-Clause SPDX identifier or canonical \
         BSD-3-Clause redistribution clause text; got:\n{contents}"
    );

    assert!(
        contents.contains("RuleSteward Authors"),
        "rules-templates/LICENSE must attribute 'RuleSteward Authors'; got:\n{contents}"
    );
}

/// Runs `rulesteward fapolicyd lint rules-templates/` and asserts:
/// - exit code 0 (no Fatal/Error/Warning diagnostics).
/// - JSON output contains no `fapd-` codes at all (the array is `[]`).
///
/// This test is RED until the implementer creates fully-clean sample files.
#[test]
fn rules_templates_lint_clean_exit_zero_no_diagnostics() {
    let dir = rules_templates_dir();

    // Pass the directory as a positional arg (directory lint mode, no --file flag).
    // Use --format json so "zero diagnostics" is unambiguous: output must not contain
    // any fapd- code, i.e. the JSON array is [].
    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "lint", "--format", "json"])
        .arg(&dir)
        .assert()
        .code(0)
        // The JSON array must be empty: no diagnostics of any severity.
        .stdout(predicate::str::contains("fapd-").not())
        // Output must be a JSON array (not a tool-error or garbage).
        .stdout(predicate::str::starts_with("["));
}
