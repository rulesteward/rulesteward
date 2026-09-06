//! Golden tests over the vendored fixtures.
//!
//! These drive the real binary rather than calling into the library, so the CLI
//! contract in DESIGN.md §9 — stdout, stderr and the exit code — is what gets
//! asserted, not an internal function's return value.
//!
//! `--no-conf` on every run: without it the tool would read the host's
//! /etc/fapolicyd/fapolicyd.conf and the results would differ per machine.
//!
//! Rewrite the expectations with `UPDATE_GOLDEN=1 cargo test`. Read the diff before
//! you commit it; a golden test that gets blessed unread is just a changelog.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn run(fixture: &Path) -> Vec<u8> {
    let input = std::fs::read(fixture).expect("read fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rulesteward"))
        .args(["fapolicyd", "analyze", "--no-conf"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rulesteward");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");

    let mut report = Vec::new();
    report.extend_from_slice(format!("--- exit {} ---\n", out.status.code().unwrap()).as_bytes());
    report.extend_from_slice(b"--- stdout ---\n");
    report.extend_from_slice(&out.stdout);
    report.extend_from_slice(b"--- stderr ---\n");
    report.extend_from_slice(&out.stderr);
    report
}

#[test]
fn fixtures_match_their_goldens() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();

    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(dir.join("fixtures"))
        .expect("fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "no fixtures; run xtask/sync-fixtures.sh"
    );

    let mut failures = Vec::new();
    for fixture in &fixtures {
        let name = fixture.file_stem().unwrap().to_string_lossy().into_owned();
        let golden = dir.join("golden").join(format!("{name}.txt"));
        let actual = run(fixture);

        if update {
            std::fs::write(&golden, &actual).expect("write golden");
            continue;
        }

        match std::fs::read(&golden) {
            Ok(expected) if expected == actual => {}
            Ok(expected) => failures.push(format!(
                "{name}: output changed\n--- expected ---\n{}\n--- actual ---\n{}",
                String::from_utf8_lossy(&expected),
                String::from_utf8_lossy(&actual)
            )),
            Err(_) => failures.push(format!(
                "{name}: no golden file; run UPDATE_GOLDEN=1 cargo test"
            )),
        }
    }

    assert!(failures.is_empty(), "\n\n{}", failures.join("\n\n"));
}
