//! Golden tests over the vendored fixtures.
//!
//! These drive the real binary rather than calling into the library, so the CLI
//! contract in DESIGN.md §9 — stdout, stderr and the exit code — is what gets
//! asserted, not an internal function's return value.
//!
//! `--no-conf` on every run: without it the tool would read the host's
//! /etc/fapolicyd/fapolicyd.conf and the results would differ per machine.
//!
//! `cargo test` writes the changed expectations as `.snap.new`; they are accepted
//! with `cargo insta accept` after reading the diff. A snapshot that gets blessed
//! unread is just a changelog.

mod common;

use std::path::Path;

/// Every action, one report. They are three results out of one pass, so a golden that
/// pinned only one of them would let the others drift unwatched. The single `stderr`
/// section carries every run's stderr and is expected to be empty: §9 puts errors there
/// and nothing else, and a fixture on stdin produces no error.
fn run(fixture: &Path) -> Vec<u8> {
    let input = std::fs::read(fixture).expect("read fixture");

    let mut report = Vec::new();
    let mut errors = Vec::new();
    for action in ["rules", "trust", "why"] {
        let out = common::run(&["fapolicyd", action, "--no-conf"], &input);

        report.extend_from_slice(
            format!("--- {action} exit {} ---\n", out.status.code().unwrap()).as_bytes(),
        );
        report.extend_from_slice(&out.stdout);
        errors.extend_from_slice(&out.stderr);
    }
    report.extend_from_slice(b"--- stderr ---\n");
    report.extend_from_slice(&errors);
    report
}

#[test]
fn fixtures_match_their_goldens() {
    // `glob!` runs every fixture and reports every mismatch in one run; it panics
    // on its own when the pattern matches nothing, so an empty fixture dir cannot
    // pass. Run `xtask/sync-fixtures.sh` if that happens.
    insta::glob!("fixtures/*.log", |fixture| {
        let report = String::from_utf8(run(fixture)).expect(
            "fixture output is UTF-8; use assert_binary_snapshot! if a raw-byte fixture arrives",
        );
        insta::assert_snapshot!(report);
    });
}
