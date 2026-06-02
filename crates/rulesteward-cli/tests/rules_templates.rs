//! Integration gate for the `rules-templates/` sample fapolicyd rule files.
//!
//! These tests are RED until the implementer creates the directory, sample
//! `.rules` files, and `LICENSE`. They verify:
//!
//! 1. `rules-templates/` exists and contains at least 2 non-dotfile `*.rules` files.
//! 2. Each `*.rules` file contains at least one fapolicyd decision line (non-comment
//!    line beginning with `allow`/`deny`/`allow_audit`/etc.), so empty template files
//!    cannot pass as "instructive samples".
//! 3. `rules-templates/LICENSE` exists and its text includes a BSD-3-Clause marker,
//!    the copyright holder `RuleSteward Authors`, and the copyright year `2026`.
//! 4. `rulesteward fapolicyd lint rules-templates/` exits 0 with zero diagnostics
//!    (no `fapd-` code anywhere in JSON output, i.e. the array is `[]`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

/// The fapolicyd decision keywords that begin a rule line.
/// Matches the `Decision` enum in `rulesteward-fapolicyd`.
const DECISION_KEYWORDS: &[&str] = &[
    "allow",
    "deny",
    "allow_audit",
    "allow_syslog",
    "allow_log",
    "deny_audit",
    "deny_syslog",
    "deny_log",
];

/// Returns true if `line` is a fapolicyd decision line: non-comment, non-blank,
/// and its first non-whitespace token is one of the eight decision keywords.
fn is_decision_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    // The first whitespace-delimited token must be exactly a decision keyword.
    let first_token = trimmed.split_whitespace().next().unwrap_or("");
    DECISION_KEYWORDS.contains(&first_token)
}

/// Resolve the `rules-templates/` directory relative to this crate's manifest.
/// The cli crate lives at `crates/rulesteward-cli`; the repo root is two levels up.
fn rules_templates_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules-templates")
}

/// Collect all non-dotfile `*.rules` paths from `dir` (non-recursive, top-level only).
fn collect_rules_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("read_dir rules-templates/")
        .filter_map(|entry| {
            let entry = entry.expect("DirEntry");
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                return None;
            }
            if name_str.ends_with(".rules") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect()
}

/// Asserts that `rules-templates/` exists and contains at least 2 non-dotfile
/// files with a `.rules` extension.
///
/// NOTE FOR IMPLEMENTER: every sample file MUST be named with a two-digit
/// `NN-` prefix (e.g. `10-allow-trusted.rules`, `50-deny-untrusted.rules`).
/// Files without the prefix fire `fapd-C01` (Convention), which appears in
/// JSON output and causes the lint-clean assertion below to fail even though
/// C01 does not escalate the exit code. Use exactly two ASCII digits followed
/// by a hyphen at the start of each filename.
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

    let rules_files = collect_rules_files(&dir);

    assert!(
        rules_files.len() >= 2,
        "rules-templates/ must contain at least 2 non-dotfile *.rules files, \
         found {}: {rules_files:?}",
        rules_files.len()
    );
}

/// Asserts that each `*.rules` file in `rules-templates/` contains at least one
/// fapolicyd decision line -- a non-comment, non-blank line whose first token is
/// one of the eight decision keywords (`allow`, `deny`, `allow_audit`, `allow_syslog`,
/// `allow_log`, `deny_audit`, `deny_syslog`, `deny_log`).
///
/// This is a per-file assertion: one real file and one empty file does NOT pass.
/// Empty template files linted by the binary are vacuously clean (exit 0, output
/// `[]`) but are useless as instructive samples, so we reject them explicitly here.
#[test]
fn rules_templates_each_rules_file_has_a_decision_line() {
    let dir = rules_templates_dir();

    assert!(
        dir.exists(),
        "rules-templates/ directory does not exist at {dir:?} - implementer must create it"
    );

    let rules_files = collect_rules_files(&dir);

    assert!(
        !rules_files.is_empty(),
        "rules-templates/ contains no *.rules files; implementer must create sample files"
    );

    for path in &rules_files {
        let contents =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

        let has_decision = contents.lines().any(is_decision_line);

        assert!(
            has_decision,
            "rules-templates file {path:?} contains no fapolicyd decision line.\n\
             Each sample must have at least one non-comment line whose first token is one of:\n\
             allow, deny, allow_audit, allow_syslog, allow_log,\n\
             deny_audit, deny_syslog, deny_log.\n\
             An empty (or comment-only) file lints vacuously clean but is not an \
             instructive template. Add at least one real rule."
        );
    }
}

/// Asserts that `rules-templates/LICENSE` exists and its text includes a
/// BSD-3-Clause marker, the copyright holder `RuleSteward Authors`, and the
/// copyright year `2026`.
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

    assert!(
        contents.contains("2026"),
        "rules-templates/LICENSE must contain the copyright year '2026' \
         (expected: 'Copyright (c) 2026 RuleSteward Authors'); got:\n{contents}"
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
    // Use --format json so "zero diagnostics" is unambiguous: the envelope's
    // `diagnostics` array is empty and no fapd- code appears.
    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "lint", "--format", "json"])
        .arg(&dir)
        .assert()
        .code(0)
        // No diagnostics of any severity.
        .stdout(predicate::str::contains("fapd-").not())
        // Output is the versioned JSON envelope object (not a tool-error or garbage).
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"schemaVersion\": 1"));
}
