//! Golden tests over the same fixtures with `--format json` (#146, DESIGN.md §9.1).
//!
//! The text goldens are in `golden.rs` and stay there: they are a contract of their own,
//! and a field arriving in a document must never move one of their snapshots.
//!
//! **Its own test binary, and that is the reason.** `insta::glob!` keeps its failure
//! count in one process-wide stack, so a second `glob!` beside the first runs on another
//! test thread, pushes onto the same stack and reports its failures against whichever
//! frame is on top -- a JSON snapshot that needs accepting fails `fixtures_match_their_
//! goldens`, which reads exactly like the text output having moved. Separate binaries are
//! separate processes and separate stacks.
//!
//! `cargo test` writes the changed expectations as `.snap.new`; they are accepted with
//! `cargo insta accept` after reading the diff, like every other snapshot here.

mod common;

/// `check`'s document, from the same conf, candidate and log as `check_matches_its_
/// golden`: `--no-conf` would leave every verdict `unknown` and the entry's `verdict`
/// and `detail` fields would never be exercised on a real capture.
#[test]
fn check_matches_its_json_golden() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let input = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    ))
    .expect("read fixture");

    let out = common::run(
        &[
            "fapolicyd",
            "--conf",
            conf,
            "check",
            candidate,
            "--format",
            "json",
        ],
        &input,
    );
    let report = format!(
        "--- check --format json exit {} ---\n{}--- stderr ---\n{}",
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).expect("UTF-8 document"),
        String::from_utf8(out.stderr).expect("UTF-8 stderr"),
    );
    insta::assert_snapshot!(report);
}

/// The `why` document over every fixture, the corrupted captures included: a document is
/// pinned per capture exactly as the report is, so a field that only one real log reaches
/// is a snapshot diff and not a surprise in someone's pipeline.
#[test]
fn fixtures_match_their_json_goldens() {
    insta::glob!("fixtures/*.log", |fixture| {
        let input = std::fs::read(fixture).expect("read fixture");
        let out = common::run(
            &["fapolicyd", "why", "--no-conf", "--format", "json"],
            &input,
        );
        let report = format!(
            "--- why --format json exit {} ---\n{}--- stderr ---\n{}",
            out.status.code().unwrap(),
            String::from_utf8(out.stdout).expect(
                "a document is UTF-8 by construction; use assert_binary_snapshot! if that changes",
            ),
            String::from_utf8(out.stderr).expect("UTF-8 stderr"),
        );
        insta::assert_snapshot!(report);
    });
}
