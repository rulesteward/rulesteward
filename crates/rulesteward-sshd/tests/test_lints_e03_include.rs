//! sshd-E03: `Include` resolution (filesystem) integration tests.
//!
//! # Grounding (`sshd_config(5)`, OpenSSH 10.2p1)
//! Include: "Multiple pathnames may be specified and each pathname may contain
//! glob(7) wildcards that will be expanded and processed in lexical order. Files
//! without absolute paths are assumed to be in /etc/ssh. An Include directive
//! may appear inside a Match block to perform conditional inclusion."
//!
//! # Linter semantics (operator decisions, this session)
//! * Relative patterns resolve against the DIRECTORY OF THE LINTED FILE (which
//!   equals sshd's /etc/ssh for the real `/etc/ssh/sshd_config`), so the check is
//!   deterministic and testable for a config copy under review.
//! * A missing literal path, or a glob whose literal directory prefix is missing,
//!   is the finding. A glob over an EXISTING directory that currently matches
//!   zero files is NOT flagged (the benign stock `Include
//!   /etc/ssh/sshd_config.d/*.conf` on a system with no drop-ins).
//!
//! These tests build a throwaway directory so the filesystem state is controlled
//! regardless of the host (no dependency on the real /etc/ssh).

use std::path::Path;

use rulesteward_core::Diagnostic;
use rulesteward_sshd::SshdLintContext;
use rulesteward_sshd::lints::structural::e03;
use rulesteward_sshd::parser::parse_config_str_located;

/// Lint `config_body` as if it were the file `<dir>/sshd_config`, so relative
/// includes resolve against `dir`.
fn run_in(dir: &Path, config_body: &str) -> Vec<Diagnostic> {
    let config_path = dir.join("sshd_config");
    let blocks = parse_config_str_located(config_body, &config_path).expect("fixture parses");
    e03(&blocks, &config_path, &SshdLintContext::default())
}

#[test]
fn flags_missing_literal_relative_include() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_in(dir.path(), "Include hardening.conf\n");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].code, "sshd-E03");
    assert_eq!(diags[0].line, 1);
}

#[test]
fn existing_literal_relative_include_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hardening.conf"), "PermitRootLogin no\n").unwrap();
    assert!(run_in(dir.path(), "Include hardening.conf\n").is_empty());
}

#[test]
fn flags_missing_literal_absolute_include() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.conf");
    let body = format!("Include {}\n", missing.display());
    let diags = run_in(dir.path(), &body);
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].code, "sshd-E03");
}

#[test]
fn existing_literal_absolute_include_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let present = dir.path().join("present.conf");
    std::fs::write(&present, "X11Forwarding no\n").unwrap();
    let body = format!("Include {}\n", present.display());
    assert!(run_in(dir.path(), &body).is_empty());
}

#[test]
fn flags_glob_over_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    // `missing.d/` was never created -> the glob's directory prefix is absent.
    let diags = run_in(dir.path(), "Include missing.d/*.conf\n");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].code, "sshd-E03");
}

#[test]
fn glob_over_existing_empty_directory_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("dropin.d")).unwrap();
    // Directory exists but matches nothing: the benign stock-config case.
    assert!(run_in(dir.path(), "Include dropin.d/*.conf\n").is_empty());
}

#[test]
fn glob_with_matches_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("dropin.d")).unwrap();
    std::fs::write(dir.path().join("dropin.d/10-a.conf"), "UsePAM yes\n").unwrap();
    assert!(run_in(dir.path(), "Include dropin.d/*.conf\n").is_empty());
}

#[test]
fn include_inside_match_block_is_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_in(dir.path(), "Match User bob\n    Include missing.conf\n");
    assert_eq!(
        diags.len(),
        1,
        "Includes inside Match blocks are checked too"
    );
    assert_eq!(diags[0].code, "sshd-E03");
    assert_eq!(diags[0].line, 2);
}

#[test]
fn include_of_an_existing_directory_is_flagged() {
    // sshd includes config FILES; an Include that resolves only to a directory
    // loads nothing (verified with `sshd -T`), so it is drift, not a clean include.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("drop")).unwrap();
    let diags = run_in(dir.path(), "Include drop\n");
    assert_eq!(diags.len(), 1, "a directory is not a config file");
    assert_eq!(diags[0].code, "sshd-E03");
}

#[test]
fn glob_with_metacharacter_in_a_parent_component_over_missing_dir_is_flagged() {
    // The metachar is in a directory component, not the trailing filename, and no
    // such directory exists: the glob expands to nothing (a finding, not benign).
    let dir = tempfile::tempdir().unwrap();
    let diags = run_in(dir.path(), "Include subdir?/site.conf\n");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].code, "sshd-E03");
}

#[test]
fn multi_pattern_include_flags_only_the_missing_pattern() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.conf"), "Banner /etc/issue\n").unwrap();
    // One line, two patterns: a.conf exists, b.conf does not.
    let diags = run_in(dir.path(), "Include a.conf b.conf\n");
    assert_eq!(diags.len(), 1, "exactly the one unresolved pattern");
    assert_eq!(diags[0].line, 1);
}
