//! End-to-end CLI tests for `rulesteward fapolicyd trustdb <verb>`.
// Constant names like KNOWN_SIZE / KNOWN_SHA256 in doc-comments are intentionally
// not backtick-wrapped to reduce noise; the allow covers the whole file.
#![allow(clippy::doc_markdown)]
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
/// the UNIFIED ENVELOPE (CC-2 / #63): a top-level object carrying
/// `schemaVersion: 1`, `kind: "trust-entries"`, and `data` = the array of row
/// objects, terminated by a trailing newline. Asserts the WIRE FORMAT by parsing
/// stdout into `serde_json::Value`, not by deserializing into a concrete struct.
///
/// The key is `"digest"` (not `"sha256"`) because the field holds whatever hash
/// algorithm fapolicyd recorded (MD5/SHA1/SHA256/SHA512 depending on DB version).
#[test]
fn trustdb_list_json_emits_envelope_of_objects_exit_zero() {
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
    assert!(
        json.is_object(),
        "top-level JSON must be the versioned envelope object, not a bare array: {json}"
    );
    assert_eq!(
        json["schemaVersion"],
        serde_json::json!(1),
        "envelope must carry schemaVersion=1: {json}"
    );
    assert_eq!(
        json["kind"],
        serde_json::json!("trust-entries"),
        "envelope must carry kind=trust-entries: {json}"
    );
    let arr = json["data"].as_array().expect("`data` must be an array");
    assert_eq!(
        arr.len(),
        2,
        "two fixture rows must produce two `data` elements"
    );
    for elem in arr {
        let obj = elem
            .as_object()
            .expect("each element must be a JSON object");
        for key in ["path", "source", "size", "digest"] {
            assert!(
                obj.contains_key(key),
                "element missing `{key}` field: {obj:?}"
            );
        }
        assert!(
            !obj.contains_key("sha256"),
            "JSON must NOT contain old 'sha256' key; got: {obj:?}"
        );
    }
}

/// `trustdb list --format csv` over a fixture DB exits 0 and emits a valid,
/// rectangular CSV (#64): a stable header row plus one data row per entry, every
/// row carrying the same column count, terminated by a trailing newline. Asserts
/// the WIRE FORMAT (header + column count) the way the JSON test asserts the
/// envelope shape.
#[test]
fn trustdb_list_csv_emits_rectangular_table_exit_zero() {
    let db_dir = tempfile::tempdir().expect("tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            ("/usr/bin/ls", value_bytes(1, 111, KNOWN_SHA256).as_slice()),
            ("/usr/bin/cat", value_bytes(1, 222, KNOWN_SHA256).as_slice()),
        ],
    );

    let assert = bin()
        .args(["fapolicyd", "trustdb", "list", "--format", "csv"])
        .arg(db_dir.path())
        .assert()
        .success();
    let out = assert.get_output();
    assert_eq!(out.status.code(), Some(0), "list --format csv must exit 0");

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.ends_with('\n'),
        "csv output must end with a trailing newline"
    );
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("source,size,digest,path,weak"),
        "first line must be the stable CSV header"
    );
    let data: Vec<&str> = lines.collect();
    assert_eq!(
        data.len(),
        2,
        "two fixture rows must produce two CSV data rows"
    );
    for row in &data {
        assert_eq!(
            row.split(',').count(),
            5,
            "each data row must have 5 columns: {row}"
        );
    }
}

/// `trustdb list` annotates a weak (MD5 32-hex) digest entry on both the human
/// and JSON surfaces, and leaves a strong (SHA256 64-hex) entry unannotated.
/// Functional smoke for the report side of the fapd-W11 weak-hash surfacing.
#[test]
fn trustdb_list_annotates_weak_digest_entry() {
    // 32-hex = MD5 (weak); KNOWN_SHA256 is 64-hex (strong).
    const MD5_LEN_DIGEST: &str = "0123456789abcdef0123456789abcdef";
    let db_dir = tempfile::tempdir().expect("tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            (
                "/usr/bin/weak",
                value_bytes(1, 111, MD5_LEN_DIGEST).as_slice(),
            ),
            (
                "/usr/bin/strong",
                value_bytes(1, 222, KNOWN_SHA256).as_slice(),
            ),
        ],
    );

    // Human surface: the MD5 line is annotated, the SHA256 line is not.
    let human = bin()
        .args(["fapolicyd", "trustdb", "list"])
        .arg(db_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let human = String::from_utf8(human).expect("utf8 stdout");
    let weak_line = human
        .lines()
        .find(|l| l.contains("/usr/bin/weak"))
        .expect("weak line present");
    let strong_line = human
        .lines()
        .find(|l| l.contains("/usr/bin/strong"))
        .expect("strong line present");
    assert!(
        weak_line.contains("weak: MD5"),
        "the MD5 list line must be annotated 'weak: MD5'; got: {weak_line}"
    );
    assert!(
        !strong_line.contains("weak:"),
        "the SHA256 list line must NOT be annotated; got: {strong_line}"
    );

    // JSON surface: weak row carries "weak":"MD5"; strong row omits the key.
    let json = bin()
        .args(["fapolicyd", "trustdb", "list", "--format", "json"])
        .arg(db_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(json).expect("utf8")).expect("valid json");
    assert_eq!(json["kind"], serde_json::json!("trust-entries"));
    let arr = json["data"].as_array().expect("`data` array");
    let weak = arr
        .iter()
        .find(|o| o["path"] == "/usr/bin/weak")
        .expect("weak obj");
    assert_eq!(
        weak["weak"], "MD5",
        "weak row must serialize \"weak\":\"MD5\""
    );
    let strong = arr
        .iter()
        .find(|o| o["path"] == "/usr/bin/strong")
        .expect("strong obj");
    assert!(
        strong.as_object().expect("obj").get("weak").is_none(),
        "strong row must omit the \"weak\" key; got: {strong}"
    );
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
    assert_eq!(json["kind"], serde_json::json!("trust-entries"));
    let arr = json["data"].as_array().expect("`data` array");
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
///
/// Pins `--integrity sha256` explicitly (#466): `run_check` resolves the
/// effective `IntegrityMode` from `--integrity`, else `--config` (default
/// `/etc/fapolicyd/fapolicyd.conf`), else STRICT if no conf is found (see
/// `resolve_integrity_mode` in `commands/fapolicyd/trustdb.rs`). Without an
/// explicit override, a host that has a real `/etc/fapolicyd/fapolicyd.conf`
/// with `integrity = none` (or `size`, for the hash side) would demote
/// `SizeMismatch` and flip this test's asserted exit 1 to exit 0
/// (`IntegrityMode::enforces`: `SizeMismatch` is enforced under
/// Size/Ima/Sha256, NOT under None). `--integrity` is the highest-priority
/// override and a clap value-enum validated to `{none,size,ima,sha256}`, so
/// `sha256` deterministically forces full enforcement regardless of host state.
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
        .arg("--integrity")
        .arg("sha256")
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

// ---------------------------------------------------------------------------
// IntegrityMode gating tests (issue #292) -- RED until the implementer fills
// IntegrityMode::enforces and wires --config/--integrity into run_check/diff/stale.
//
// GROUNDED CONTRACT (fapolicyd.conf(5)):
//   integrity=none   -> SizeMismatch and HashMismatch are NOT enforced (visible only).
//   integrity=size   -> SizeMismatch IS enforced; HashMismatch is NOT.
//   integrity=sha256 -> Both SizeMismatch and HashMismatch ARE enforced.
//   Missing/ReadError -> ALWAYS enforced regardless of integrity mode.
//   No conf file found -> STRICT (sha256) mode.
//   --integrity <level> overrides --config.
//
// The stub IntegrityMode::enforces always returns true, so:
//   - Tests expecting exit 1 will PASS (stub agrees: it's enforced).
//   - Tests expecting exit 0 (drift not enforced) will FAIL (stub returns
//     enforced=true and raises the exit code when it shouldn't).
//   - The "not enforced" annotation tests will FAIL (stub never annotates).
//   - The JSON enforced=false tests will FAIL (stub always writes enforced=true).
// ---------------------------------------------------------------------------

/// Helper: write a synthetic fapolicyd.conf to a temp file with a given
/// `integrity` value. Returns the NamedTempFile (caller keeps it alive).
fn write_conf(integrity_value: &str) -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::NamedTempFile::new().expect("named tempfile");
    writeln!(f, "# synthetic fapolicyd.conf for testing").expect("write");
    writeln!(f, "integrity = {integrity_value}").expect("write");
    f.flush().expect("flush");
    f
}

/// Build a fixture DB with three kinds of entries controlled by caller-supplied
/// path variables:
///
/// - `path_match`: recorded with correct KNOWN_SIZE / KNOWN_SHA256; caller
///   must have created the file with `write_known_file`.
/// - `path_hash_mismatch`: recorded size = KNOWN_SIZE but WRONG hash (all zeros).
///   Caller must have created the file with `write_known_file`.
/// - `path_size_mismatch`: recorded size = KNOWN_SIZE + 9999 and WRONG hash.
///   Caller must have created the file with `write_known_file`.
/// - `path_missing`: recorded size = KNOWN_SIZE / KNOWN_SHA256 but NO file on disk.
///   Caller must NOT create this file.
fn build_mixed_fixture_db(
    db_dir: &Path,
    path_match: &Path,
    path_hash_mismatch: &Path,
    path_size_mismatch: &Path,
    path_missing: &Path,
) {
    let wrong_hash = "0".repeat(64); // 64 zeros -- definitely not KNOWN_SHA256
    write_trustdb_fixture_kv(
        db_dir,
        &[
            (
                path_match.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
            ),
            (
                path_hash_mismatch.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
            ),
            (
                path_size_mismatch.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
            ),
            (
                path_missing.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
            ),
        ],
    );
}

/// `trustdb diff --config <conf with integrity=none>` exits 0 even when there
/// are hash and size mismatches -- those are visible but NOT enforced under
/// `integrity=none`.
///
/// RED: the stub IntegrityMode::enforces always returns true, so the command
/// will exit 1 when it should exit 0.
///
/// Additionally checks that the human output CONTAINS some indication that
/// drift exists but is not enforced (we check for the path of the hash-mismatch
/// entry, confirming it appears in output). The exact annotation wording is
/// intentionally NOT pinned here (the implementer chooses it); the e2e smoke
/// for the "not enforced" annotation wording lives below.
#[test]
fn integrity_none_hash_and_size_mismatch_exit_zero() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_match = files.path().join("match");
    let path_hash = files.path().join("hash_mismatch");
    let path_size = files.path().join("size_mismatch");
    let path_missing = files.path().join("missing_never_created");

    write_known_file(&path_match);
    write_known_file(&path_hash);
    write_known_file(&path_size);
    // path_missing is intentionally not created.

    let db_dir = tempfile::tempdir().expect("db tempdir");
    build_mixed_fixture_db(
        db_dir.path(),
        &path_match,
        &path_hash,
        &path_size,
        &path_missing,
    );

    let conf = write_conf("none");

    // Under integrity=none: hash-mismatch and size-mismatch are NOT enforced
    // (exit 0). Missing IS always enforced (exit 1). To test the none->exit-0
    // case we use `trustdb check` on ONLY the hash and size mismatch paths.
    let out = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_hash)
        .arg(&path_size)
        .output()
        .expect("run check");
    assert_eq!(
        out.status.code(),
        Some(0),
        "integrity=none must not enforce hash/size mismatch (exit 0); got: {:?} stdout={:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );

    // VISIBILITY: demoted (non-enforced) drift must STILL appear in stdout -- a
    // non-enforced verdict is reported with an annotation, not silently dropped.
    // This directly kills a silent-drop impl that would suppress the rows it
    // chooses not to enforce. (The JSON len==2 test also constrains this, but we
    // close the loop here too so the body matches the docstring.)
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.contains(path_hash.to_str().unwrap()),
        "hash-mismatch drift must remain VISIBLE in stdout even when not enforced; got:\n{stdout}"
    );
    assert!(
        stdout.contains(path_size.to_str().unwrap()),
        "size-mismatch drift must remain VISIBLE in stdout even when not enforced; got:\n{stdout}"
    );
}

/// Under `integrity=none`, a Missing entry IS enforced (exit 1) even though
/// hash and size mismatches are not.
///
/// GREEN: the stub always returns enforced=true, so Missing -> exit 1 matches.
/// This test should PASS even with the stub. Included to confirm that Missing
/// is always enforced and the none-exits-0 tests above don't silently mask it.
#[test]
fn integrity_none_missing_is_still_exit_one() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_missing = files.path().join("missing_never_created");
    // Do not create path_missing.

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_missing.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    let conf = write_conf("none");

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_missing)
        .assert()
        .code(1);
}

/// INVARIANT GUARD (not a RED test): `NotInDb` is ALWAYS enforced and is NEVER
/// subject to integrity demotion. `NotInDb` is a `CheckVerdict`-only state (the
/// queried path is recorded NOWHERE in the trust DB) -- it has no `DiskVerdict`
/// variant, so the `IntegrityMode::enforces` table structurally cannot reach it,
/// and the only place this rule can be wrong is in the CLI wiring.
///
/// This test is GREEN against the always-true stub (the stub over-enforces, which
/// is the CORRECT answer for `NotInDb`) and MUST STAY GREEN against the real impl.
/// Its value is as a regression guard: it kills a wrong impl that lumps `NotInDb`
/// into the demotable class and (incorrectly) demotes it under `integrity=none`,
/// which would flip the exit code to 0 and/or set `enforced: false`.
///
/// Asserts: exit 1 even under `integrity=none`, and the JSON `not_in_db` row
/// carries `enforced: true`.
#[test]
fn integrity_none_not_in_db_is_always_enforced_invariant_guard() {
    let files = tempfile::tempdir().expect("files tempdir");
    // A path that exists on disk but is NOT recorded in the trust DB at all.
    let path_present_but_unrecorded = files.path().join("on_disk_not_in_db");
    write_known_file(&path_present_but_unrecorded);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    // The DB contains ONE unrelated key; the queried path is absent -> NotInDb.
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            "/some/other/recorded/path",
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    let conf = write_conf("none");

    // Exit 1: NotInDb is always enforced, even under integrity=none.
    let out = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_present_but_unrecorded)
        .output()
        .expect("run check");
    assert_eq!(
        out.status.code(),
        Some(1),
        "NotInDb must ALWAYS be enforced (exit 1) even under integrity=none; got: {:?} stdout={:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );

    // JSON: the not_in_db row carries enforced=true.
    let out_json = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--format")
        .arg("json")
        .arg(&path_present_but_unrecorded)
        .output()
        .expect("run check json");
    let stdout = String::from_utf8(out_json.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.ends_with('\n'),
        "json output must end with a trailing newline"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = json["data"].as_array().expect("`data` array");
    assert_eq!(arr.len(), 1, "exactly one queried path -> one row");
    let row = arr[0].as_object().expect("row object");
    assert_eq!(
        row["verdict"],
        serde_json::json!("not_in_db"),
        "the queried unrecorded path must surface as the not_in_db verdict; got: {row:?}"
    );
    assert_eq!(
        row["enforced"],
        serde_json::json!(true),
        "a not_in_db row must always carry enforced=true (NotInDb is never demoted); got: {row:?}"
    );
}

/// `trustdb diff --config <conf with integrity=sha256>` exits 1 when there is
/// any hash or size mismatch.
///
/// GREEN-ish with stub: stub returns enforced=true -> exit 1 matches. But this
/// also confirms sha256 mode works after the impl (should still be 1).
#[test]
fn integrity_sha256_hash_mismatch_exit_one() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_mismatch");
    write_known_file(&path_hash);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_hash.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
        )],
    );

    let conf = write_conf("sha256");

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_hash)
        .assert()
        .code(1);
}

/// `integrity=size` enforces size mismatch (exit 1) but NOT hash mismatch
/// (exit 0 for hash-only drift).
///
/// RED for the hash-mismatch sub-case: stub returns enforced=true -> exit 1,
/// but the intended behavior after impl is exit 0.
#[test]
fn integrity_size_enforces_size_mismatch_but_not_hash_mismatch() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_only_drift");
    let path_size = files.path().join("size_drift");
    write_known_file(&path_hash);
    write_known_file(&path_size);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            // Hash mismatch only (recorded size = KNOWN_SIZE, correct).
            (
                path_hash.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
            ),
            // Size mismatch (recorded size wrong).
            (
                path_size.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
            ),
        ],
    );

    let conf = write_conf("size");

    // Hash-only drift under integrity=size: NOT enforced -> exit 0.
    // RED: stub exits 1 instead.
    let out_hash = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_hash)
        .output()
        .expect("check hash");
    assert_eq!(
        out_hash.status.code(),
        Some(0),
        "integrity=size must NOT enforce hash mismatch (exit 0); got: {:?}",
        out_hash.status
    );

    // Size drift under integrity=size: enforced -> exit 1.
    // GREEN with stub (both exit 1).
    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_size)
        .assert()
        .code(1);
}

/// `--integrity ima` enforces size mismatch (exit 1) but NOT trust-DB hash
/// mismatch (exit 0). Closes the last enforcement-matrix corner at the CLI
/// surface and proves `IntegrityMode::from_conf_value` surfaces the `ima` mode
/// through the `--integrity` flag path.
///
/// Per the grounded contract (fapolicyd.conf(5)): under `ima`, the daemon checks
/// the IMA xattr hash, NOT the trust-DB digest, so a trust-DB `HashMismatch` is
/// NOT enforced; `SizeMismatch` (a prerequisite check) IS enforced.
///
/// RED for the hash-mismatch sub-case: the stub returns enforced=true -> exit 1,
/// but the intended behavior after impl is exit 0.
#[test]
fn integrity_ima_enforces_size_mismatch_but_not_hash_mismatch() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("ima_hash_only_drift");
    let path_size = files.path().join("ima_size_drift");
    write_known_file(&path_hash);
    write_known_file(&path_size);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            // Hash mismatch only (recorded size = KNOWN_SIZE, correct).
            (
                path_hash.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
            ),
            // Size mismatch (recorded size wrong).
            (
                path_size.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
            ),
        ],
    );

    // Use the --integrity ima FLAG (no conf) so this also proves the flag path
    // surfaces the `ima` mode via from_conf_value.
    // Hash-only drift under integrity=ima: NOT enforced -> exit 0.
    // RED: stub exits 1 instead.
    let out_hash = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--integrity")
        .arg("ima")
        .arg(&path_hash)
        .output()
        .expect("check hash");
    assert_eq!(
        out_hash.status.code(),
        Some(0),
        "integrity=ima must NOT enforce trust-DB hash mismatch (exit 0); got: {:?}",
        out_hash.status
    );

    // Size drift under integrity=ima: enforced -> exit 1.
    // GREEN with stub (both exit 1).
    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--integrity")
        .arg("ima")
        .arg(&path_size)
        .assert()
        .code(1);
}

/// `--integrity sha256` flag overrides a `--config` whose conf says
/// `integrity=none` -> exit 1 for hash mismatch (sha256 enforced).
///
/// GREEN-ish with stub: stub returns enforced=true -> exit 1 matches.
/// Becomes a true gating test after the impl: if --integrity doesn't override
/// --config's none, the hash-mismatch path would exit 0 (wrong).
#[test]
fn integrity_flag_overrides_config_none_to_sha256() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_only_drift");
    write_known_file(&path_hash);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_hash.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
        )],
    );

    // conf says none, but --integrity sha256 overrides it -> exit 1.
    let conf = write_conf("none");
    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--integrity")
        .arg("sha256")
        .arg(&path_hash)
        .assert()
        .code(1);
}

/// When `--config` points at a non-existent file (no conf found), STRICT mode
/// (sha256) is assumed -> any mismatch exits 1.
///
/// GREEN-ish with stub: stub always enforces -> exits 1 matches.
/// True gate after impl: if the no-conf path doesn't go STRICT, hash-only
/// drift would (incorrectly) exit 0.
#[test]
fn no_conf_file_means_strict_mode_exits_one_for_hash_mismatch() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_only_drift");
    write_known_file(&path_hash);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_hash.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
        )],
    );

    // Point --config at a path that does not exist.
    let nonexistent_conf = files.path().join("no_such_fapolicyd.conf");
    assert!(
        !nonexistent_conf.exists(),
        "precondition: conf must not exist"
    );

    bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(&nonexistent_conf)
        .arg(&path_hash)
        .assert()
        .code(1);
}

/// Under `integrity=none`, the JSON output of `trustdb check --format json`
/// must carry an `enforced: false` field on hash-mismatch and size-mismatch
/// rows, and must end with a trailing newline.
///
/// RED: the stub always writes `enforced: true`, so the `enforced: false`
/// assertions will fail.
#[test]
fn integrity_none_json_has_enforced_false_on_drift_rows_and_trailing_newline() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_drift_json");
    let path_size = files.path().join("size_drift_json");
    write_known_file(&path_hash);
    write_known_file(&path_size);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[
            (
                path_hash.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
            ),
            (
                path_size.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
            ),
        ],
    );

    let conf = write_conf("none");

    let out = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--format")
        .arg("json")
        .arg(&path_hash)
        .arg(&path_size)
        .output()
        .expect("run check json");

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.ends_with('\n'),
        "json output must end with a trailing newline; got: {stdout:?}"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(
        json["kind"],
        serde_json::json!("trust-entries"),
        "must be the trust-entries envelope"
    );
    let arr = json["data"].as_array().expect("`data` array");
    assert_eq!(arr.len(), 2, "two drift rows in the fixture");

    for row in arr {
        let obj = row.as_object().expect("row is object");
        assert!(
            obj.contains_key("enforced"),
            "each check row must carry an `enforced` field in JSON; got: {obj:?}"
        );
        assert_eq!(
            row["enforced"],
            serde_json::json!(false),
            "under integrity=none, hash/size drift rows must have enforced=false; got: {obj:?}"
        );
    }
}

/// Under `integrity=sha256`, JSON rows for hash and size mismatch carry
/// `enforced: true`.
///
/// GREEN-ish with stub: stub sets enforced=true. Included so the test suite
/// covers the sha256 enforced=true JSON surface (and keeps the matrix complete).
#[test]
fn integrity_sha256_json_has_enforced_true_on_drift_rows() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_drift_sha256");
    write_known_file(&path_hash);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_hash.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
        )],
    );

    let conf = write_conf("sha256");

    let out = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--format")
        .arg("json")
        .arg(&path_hash)
        .output()
        .expect("run check json sha256");

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(stdout.ends_with('\n'), "must end with trailing newline");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = json["data"].as_array().expect("`data` array");
    assert_eq!(arr.len(), 1, "one drift row");
    assert_eq!(
        arr[0]["enforced"],
        serde_json::json!(true),
        "sha256 hash-mismatch row must have enforced=true"
    );
}

/// Under `integrity=none`, the human output for a hash-mismatch row contains
/// a substring indicating the verdict is visible but not enforced (i.e. some
/// form of "not enforced" annotation), AND also contains the integrity value
/// "none". We do NOT pin the exact wording to keep it robust.
///
/// RED: the stub does not annotate rows at all; the annotation won't appear.
#[test]
fn integrity_none_human_output_contains_not_enforced_annotation() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_hash = files.path().join("hash_annotate");
    write_known_file(&path_hash);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_hash.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
        )],
    );

    let conf = write_conf("none");

    let out = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg(&path_hash)
        .output()
        .expect("run check");

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    // The annotation must contain "not enforced" (case-insensitive acceptable
    // since we only check lowercase here). This is the stable semantic anchor;
    // the implementer may word it as "not enforced under integrity=none" or
    // similar.
    assert!(
        stdout.to_lowercase().contains("not enforced"),
        "human output under integrity=none must annotate drift as 'not enforced'; got:\n{stdout}"
    );
    // The integrity level must appear in the annotation.
    assert!(
        stdout.contains("none"),
        "the annotation must name the integrity mode 'none'; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Integrity gating for the OTHER two vs-disk verbs: `diff` (vs-disk) + `stale`.
//
// The check-verb tests above already exercise the demotion boundary, but a wrong
// impl that drops the `&& enforced` exit-gate in run_diff / run_stale specifically
// would survive on those alone (the pre-existing diff/stale tests run with NO
// --config -> STRICT mode, where the gate is a no-op). These tests pin the
// demotion boundary for `diff` and `stale` too.
//
// They are GREEN against the CORRECT impl (they lock behavior, killing the
// wrong-impl shortcut), and RED against the current always-true stub (the stub
// over-enforces, so the integrity=none exit-0 expectation fails).
// ---------------------------------------------------------------------------

/// Build a fixture DB with exactly two on-disk drift entries (one HashMismatch,
/// one SizeMismatch) and NO Missing entry, so the only divergences are the two
/// integrity-DEMOTABLE verdicts. Both files are created on disk by this helper,
/// so `diff`/`stale` see a real size/hash drift (not a Missing).
///
/// Returns `(path_hash, path_size)`. The `files` tempdir must outlive the DB use.
fn build_two_drift_fixture(
    db_dir: &Path,
    files_dir: &Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let path_hash = files_dir.join("diffstale_hash_drift");
    let path_size = files_dir.join("diffstale_size_drift");
    write_known_file(&path_hash);
    write_known_file(&path_size);
    let wrong_hash = "0".repeat(64);
    write_trustdb_fixture_kv(
        db_dir,
        &[
            // Hash mismatch only (recorded size = KNOWN_SIZE, correct).
            (
                path_hash.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE, &wrong_hash).as_slice(),
            ),
            // Size mismatch (recorded size wrong).
            (
                path_size.to_str().unwrap(),
                value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
            ),
        ],
    );
    (path_hash, path_size)
}

/// A1: `trustdb diff` (vs-disk, NO --against) under `integrity=none` exits 0 even
/// with a HashMismatch AND a SizeMismatch entry: both are demoted (visible, not
/// enforced). The JSON rows carry `enforced:false`; the human output still SHOWS
/// both drift rows with the "not enforced" annotation; the row count equals the
/// drift count (demoted rows are NOT dropped).
///
/// RED against the always-true stub (it exits 1). GREEN against the correct impl.
/// Pins the demotion exit-gate for `run_diff` specifically.
#[test]
fn integrity_none_diff_vs_disk_demotes_hash_and_size_exit_zero() {
    let files = tempfile::tempdir().expect("files tempdir");
    let db_dir = tempfile::tempdir().expect("db tempdir");
    let (path_hash, path_size) = build_two_drift_fixture(db_dir.path(), files.path());

    let conf = write_conf("none");

    // Human surface: exit 0, both drift rows visible, "not enforced" annotation.
    let out = bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .output()
        .expect("run diff");
    assert_eq!(
        out.status.code(),
        Some(0),
        "integrity=none must not enforce hash/size drift in `diff` (exit 0); got: {:?} stdout={:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    assert!(
        stdout.contains(path_hash.to_str().unwrap()),
        "hash-mismatch drift must stay VISIBLE in `diff` output even when not enforced; got:\n{stdout}"
    );
    assert!(
        stdout.contains(path_size.to_str().unwrap()),
        "size-mismatch drift must stay VISIBLE in `diff` output even when not enforced; got:\n{stdout}"
    );
    assert!(
        stdout.to_lowercase().contains("not enforced"),
        "`diff` human output under integrity=none must annotate drift as 'not enforced'; got:\n{stdout}"
    );

    // JSON surface: exit 0, two rows, each enforced=false, count == drift count.
    let out_json = bin()
        .args(["fapolicyd", "trustdb", "diff", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run diff json");
    assert_eq!(
        out_json.status.code(),
        Some(0),
        "integrity=none `diff --format json` must exit 0; got: {:?}",
        out_json.status
    );
    let stdout = String::from_utf8(out_json.stdout.clone()).expect("utf8");
    assert!(
        stdout.ends_with('\n'),
        "json must end with a trailing newline"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = json["data"].as_array().expect("`data` array");
    assert_eq!(
        arr.len(),
        2,
        "demoted rows must NOT be dropped: the two drift entries must both appear; got: {arr:?}"
    );
    for row in arr {
        assert_eq!(
            row["enforced"],
            serde_json::json!(false),
            "under integrity=none, each `diff` drift row must carry enforced=false; got: {row:?}"
        );
    }
}

/// A2: `trustdb stale --db <same fixture> --config <integrity=none>` exits 0; the
/// stale rows are visible with `enforced:false` in JSON.
///
/// RED against the always-true stub. GREEN against the correct impl. Pins the
/// demotion exit-gate for `run_stale` specifically.
#[test]
fn integrity_none_stale_demotes_hash_and_size_exit_zero() {
    let files = tempfile::tempdir().expect("files tempdir");
    let db_dir = tempfile::tempdir().expect("db tempdir");
    let (path_hash, path_size) = build_two_drift_fixture(db_dir.path(), files.path());

    let conf = write_conf("none");

    // Human surface: exit 0, both stale rows visible.
    let out = bin()
        .args(["fapolicyd", "trustdb", "stale", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .output()
        .expect("run stale");
    assert_eq!(
        out.status.code(),
        Some(0),
        "integrity=none must not enforce hash/size drift in `stale` (exit 0); got: {:?} stdout={:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    assert!(
        stdout.contains(path_hash.to_str().unwrap()),
        "hash-mismatch stale row must stay VISIBLE even when not enforced; got:\n{stdout}"
    );
    assert!(
        stdout.contains(path_size.to_str().unwrap()),
        "size-mismatch stale row must stay VISIBLE even when not enforced; got:\n{stdout}"
    );

    // JSON surface: exit 0, two rows, each enforced=false.
    let out_json = bin()
        .args(["fapolicyd", "trustdb", "stale", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run stale json");
    assert_eq!(
        out_json.status.code(),
        Some(0),
        "integrity=none `stale --format json` must exit 0; got: {:?}",
        out_json.status
    );
    let stdout = String::from_utf8(out_json.stdout.clone()).expect("utf8");
    assert!(
        stdout.ends_with('\n'),
        "json must end with a trailing newline"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = json["data"].as_array().expect("`data` array");
    assert_eq!(
        arr.len(),
        2,
        "both demoted stale rows must appear (not dropped); got: {arr:?}"
    );
    for row in arr {
        assert_eq!(
            row["enforced"],
            serde_json::json!(false),
            "under integrity=none, each `stale` row must carry enforced=false; got: {row:?}"
        );
    }
}

/// A3: `trustdb stale --db <fixture with a SizeMismatch> --config <integrity=size>`
/// exits 1: SizeMismatch IS enforced under `integrity=size`.
///
/// GREEN against BOTH the stub (over-enforces -> exit 1) and the correct impl
/// (size enforces SizeMismatch -> exit 1). Locks that `stale` honors the
/// ENFORCED side of the boundary under `size`, not just the demoted side.
#[test]
fn integrity_size_stale_size_mismatch_exits_one() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path_size = files.path().join("stale_size_enforced");
    write_known_file(&path_size);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path_size.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE + 9999, KNOWN_SHA256).as_slice(),
        )],
    );

    let conf = write_conf("size");

    bin()
        .args(["fapolicyd", "trustdb", "stale", "--db"])
        .arg(db_dir.path())
        .arg("--config")
        .arg(conf.path())
        .assert()
        .code(1);
}

/// B: An UNRECOGNIZED `--integrity` value on the explicit CLI flag must be
/// REJECTED with a non-zero (clap parse-error) exit, NOT silently mapped to
/// `none` and exited 0. The accepted set is exactly {none, size, ima, sha256}.
///
/// RED against the current impl: `--integrity` is a free-form `Option<String>`
/// that `from_conf_value` maps (unknown -> none), so the command parses and exits
/// 0. The implementer converts `--integrity` to a value-enum that accepts ONLY
/// the four keywords, after which an invalid value is a clap parse error.
///
/// SCOPE NOTE: this rejection applies ONLY to the explicit `--integrity` FLAG.
/// An unknown value inside a `--config` FILE keeps the daemon-faithful
/// unknown->none behavior (fapolicyd.conf(5) parity) and is deliberately NOT
/// tested as a rejection here.
#[test]
fn unknown_integrity_flag_value_is_rejected_not_silently_none() {
    let files = tempfile::tempdir().expect("files tempdir");
    let path = files.path().join("anything");
    write_known_file(&path);

    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            path.to_str().unwrap(),
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    // `strict` is NOT one of {none,size,ima,sha256}; must be a parse error.
    let out_strict = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--integrity")
        .arg("strict")
        .arg(&path)
        .output()
        .expect("run check bogus integrity");
    assert_ne!(
        out_strict.status.code(),
        Some(0),
        "`--integrity strict` (not a valid keyword) must be REJECTED with a non-zero \
         exit, not silently mapped to none; got exit {:?} stdout={:?} stderr={:?}",
        out_strict.status.code(),
        String::from_utf8_lossy(&out_strict.stdout),
        String::from_utf8_lossy(&out_strict.stderr),
    );

    // `sha-256` (hyphenated) is also not a valid keyword -> rejected.
    let out_hyphen = bin()
        .args(["fapolicyd", "trustdb", "check", "--db"])
        .arg(db_dir.path())
        .arg("--integrity")
        .arg("sha-256")
        .arg(&path)
        .output()
        .expect("run check bogus integrity 2");
    assert_ne!(
        out_hyphen.status.code(),
        Some(0),
        "`--integrity sha-256` (not a valid keyword) must be REJECTED with a non-zero \
         exit; got exit {:?} stderr={:?}",
        out_hyphen.status.code(),
        String::from_utf8_lossy(&out_hyphen.stderr),
    );
}
