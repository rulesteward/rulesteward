//! End-to-end CLI tests for `rulesteward fapolicyd trustdb <verb>`.
//!
//! These drive the whole pipeline: argv -> clap parse -> `run_trustdb` ->
//! trust-DB read (heed) -> verify/diff/stale -> render -> exit code.
//!
//! Fixtures are real LMDB trust DBs built via the feature-gated
//! `write_trustdb_fixture_kv` (enabled by this crate's dev-dependency on
//! `rulesteward-fapolicyd` with `features = ["test-fixtures"]`). Keys are real
//! temp-file paths we create/delete to drive stale / missing / match cases, so
//! the on-disk reality the impl observes is fully controlled by the test.
//!
//! Exit-code contract under test (spec, resolved decisions):
//!   list  -> 0 (3 on DB-open/IO error or missing DB dir)
//!   check/diff/stale -> 0 if all match, 1 if any missing/mismatch/stale/
//!                       only-in-one, 3 on DB-open error or missing DB dir.
//! Never 9, never 5 for trustdb verbs.

use assert_cmd::Command;
use rulesteward_fapolicyd::trustdb::write_trustdb_fixture_kv;
use std::io::Write as _;
use std::path::Path;

/// A real, sha256sum-verified (bytes, size, hex) triple. Computed with coreutils
/// `printf 'hello trustdb\n' | sha256sum`, so the recorded value the impl
/// compares against is grounded in a primary source, not the impl under test.
const KNOWN_BYTES: &[u8] = b"hello trustdb\n";
const KNOWN_SIZE: u64 = 14;
const KNOWN_SHA256: &str = "3ea762cdbe2e0e8bd475edcfbe4ef960df0389bab22131b18ca9d9ccf08ccc27";

/// Build the canonical fapolicyd value bytes for a row.
fn value_bytes(src_int: u32, size: u64, sha256_hex: &str) -> Vec<u8> {
    format!("{src_int} {size} {sha256_hex}").into_bytes()
}

/// Create a real file containing `KNOWN_BYTES` at `path` (a file whose recorded
/// size+hash will MATCH).
fn write_known_file(path: &Path) {
    let mut f = std::fs::File::create(path).expect("create known file");
    f.write_all(KNOWN_BYTES).expect("write known bytes");
    f.flush().expect("flush");
}

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

/// `trustdb list --format json` over a fixture DB exits 0, and stdout parses to
/// a JSON ARRAY of objects each carrying `path` / `source` / `size` / `sha256`,
/// terminated by a trailing newline. Asserts the WIRE FORMAT by parsing stdout
/// into `serde_json::Value`, not by deserializing into a concrete Rust struct.
#[test]
fn trustdb_list_json_emits_array_of_objects_exit_zero() {
    let db_dir = tempfile::tempdir().expect("tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            ("/usr/bin/ls", value_bytes(1, 111, KNOWN_SHA256).as_slice()),
            ("/usr/bin/cat", value_bytes(1, 222, KNOWN_SHA256).as_slice()),
        ],
    );

    let assert = bin()
        .args(["fapolicyd", "trustdb", "list", "--format", "json"])
        .arg(db_dir.path())
        .assert()
        .success();
    let out = assert.get_output();
    assert_eq!(
        out.status.code(),
        Some(0),
        "list over a valid DB must exit 0"
    );

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.ends_with('\n'),
        "machine-readable JSON output must end with a trailing newline"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    let arr = json.as_array().expect("top-level JSON must be an array");
    assert_eq!(
        arr.len(),
        2,
        "two fixture rows must produce two array elements"
    );
    for elem in arr {
        let obj = elem
            .as_object()
            .expect("each element must be a JSON object");
        for key in ["path", "source", "size", "sha256"] {
            assert!(
                obj.contains_key(key),
                "element missing `{key}` field: {obj:?}"
            );
        }
    }
}

/// `trustdb list --source rpm` over a fixture whose rows are src=1 (`RpmDb`)
/// keeps those rows (exit 0, non-empty JSON array). Pins the source filter to
/// the resolved Rpm == `src_int` 1 mapping.
#[test]
fn trustdb_list_source_rpm_filter_keeps_rpm_rows() {
    let db_dir = tempfile::tempdir().expect("tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[("/usr/bin/ls", value_bytes(1, 111, KNOWN_SHA256).as_slice())],
    );

    let assert = bin()
        .args([
            "fapolicyd",
            "trustdb",
            "list",
            "--format",
            "json",
            "--source",
            "rpm",
        ])
        .arg(db_dir.path())
        .assert()
        .success();
    let out = assert.get_output();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let arr = json.as_array().expect("array");
    assert_eq!(
        arr.len(),
        1,
        "the single src=1 row must survive the --source rpm filter"
    );
}

/// `trustdb stale` exits 1 when at least one entry's path no longer exists on
/// disk. The fixture references a path we DELETE before running, so it is stale.
#[test]
fn trustdb_stale_exits_one_when_an_entry_is_stale() {
    let files = tempfile::tempdir().expect("files tempdir");
    let present = files.path().join("present");
    let absent = files.path().join("absent");
    write_known_file(&present);
    // `absent` is never created -> stale.

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            (
                present.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
            ),
            (
                absent.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
            ),
        ],
    );

    bin()
        .args(["fapolicyd", "trustdb", "stale", "--db"])
        .arg(db_dir.path())
        .assert()
        .code(1);
}

/// `trustdb stale` exits 0 when every entry's recorded metadata matches the
/// file on disk (nothing stale).
#[test]
fn trustdb_stale_exits_zero_when_all_match() {
    let files = tempfile::tempdir().expect("files tempdir");
    let f = files.path().join("matchme");
    write_known_file(&f);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            f.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "stale", "--db"])
        .arg(db_dir.path())
        .assert()
        .code(0);
}

/// `trustdb check <PATH>` exits 0 when the path is present in the DB and its
/// recorded size+hash match the file on disk.
#[test]
fn trustdb_check_present_and_matching_exits_zero() {
    let files = tempfile::tempdir().expect("files tempdir");
    let f = files.path().join("checkme");
    write_known_file(&f);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            f.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg(&f)
        .assert()
        .code(0);
}

/// `trustdb check <PATH>` exits 1 when the path is present in the DB but the
/// file on disk has a different size (mismatch).
#[test]
fn trustdb_check_size_mismatch_exits_one() {
    let files = tempfile::tempdir().expect("files tempdir");
    let f = files.path().join("mismatch");
    write_known_file(&f);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    // Recorded size is deliberately wrong (KNOWN_SIZE + 1000).
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            f.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE + 1000, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg(&f)
        .assert()
        .code(1);
}

/// `trustdb check <PATH>` exits 1 when the queried path is absent from the file
/// system (recorded in the DB, but the file is gone -> missing).
#[test]
fn trustdb_check_absent_file_exits_one() {
    let files = tempfile::tempdir().expect("files tempdir");
    let absent = files.path().join("never_created");

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            absent.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg(&absent)
        .assert()
        .code(1);
}

/// `trustdb diff` (no `--against`) compares the DB against on-disk reality and
/// exits 1 when at least one entry diverges (a stale entry whose file is gone).
#[test]
fn trustdb_diff_vs_disk_exits_one_when_entry_diverges() {
    let files = tempfile::tempdir().expect("files tempdir");
    let absent = files.path().join("gone");

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            absent.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_dir.path())
        .assert()
        .code(1);
}

/// `trustdb diff` (no `--against`) exits 0 when every DB entry matches disk.
#[test]
fn trustdb_diff_vs_disk_exits_zero_when_all_match() {
    let files = tempfile::tempdir().expect("files tempdir");
    let f = files.path().join("ok");
    write_known_file(&f);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            f.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_dir.path())
        .assert()
        .code(0);
}

/// `trustdb diff --db <A> --against <B>` exits 1 when the two DBs differ (B has
/// a key A lacks).
#[test]
fn trustdb_diff_against_db_exits_one_when_dbs_differ() {
    let db_a = tempfile::tempdir().expect("db_a tempdir");
    write_trustdb_fixture_kv(
        db_a.path(),
        &[("/usr/bin/ls", value_bytes(1, 111, KNOWN_SHA256).as_slice())],
    );
    let db_b = tempfile::tempdir().expect("db_b tempdir");
    write_trustdb_fixture_kv(
        db_b.path(),
        &[
            ("/usr/bin/ls", value_bytes(1, 111, KNOWN_SHA256).as_slice()),
            ("/usr/bin/cat", value_bytes(1, 222, KNOWN_SHA256).as_slice()),
        ],
    );

    bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_a.path())
        .arg("--against")
        .arg(db_b.path())
        .assert()
        .code(1);
}

/// `trustdb diff --db <A> --against <B>` exits 0 when the two DBs are identical
/// (same single key and value).
#[test]
fn trustdb_diff_against_db_exits_zero_when_dbs_identical() {
    let row = value_bytes(1, 111, KNOWN_SHA256);
    let db_a = tempfile::tempdir().expect("db_a tempdir");
    write_trustdb_fixture_kv(db_a.path(), &[("/usr/bin/ls", row.as_slice())]);
    let db_b = tempfile::tempdir().expect("db_b tempdir");
    write_trustdb_fixture_kv(db_b.path(), &[("/usr/bin/ls", row.as_slice())]);

    bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_a.path())
        .arg("--against")
        .arg(db_b.path())
        .assert()
        .code(0);
}

/// A missing / non-existent DB directory must exit 3 (tool failure), not 0/1/9.
#[test]
fn trustdb_list_missing_db_dir_exits_three() {
    let parent = tempfile::tempdir().expect("tempdir");
    let nonexistent = parent.path().join("no_such_trustdb_dir");
    assert!(!nonexistent.exists(), "precondition: dir must not exist");

    bin()
        .args(["fapolicyd", "trustdb", "list"])
        .arg(&nonexistent)
        .assert()
        .code(3);
}
