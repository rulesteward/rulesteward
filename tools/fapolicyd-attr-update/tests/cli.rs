//! End-to-end CLI tests: exercise the built binary fully offline (via `check` /
//! `derive` with `--fixtures DIR`) and assert the exit-code contract - 0 in
//! sync, 1 on drift, 2 on error - mirroring
//! `tools/{stig,sshd-stig}-update/tests/cli.rs`.
//!
//! `--fixtures DIR` expects `DIR/<version>/{subject,object}-attr.c` per pinned
//! version (see `../attr-refs.toml` and `src/main.rs`'s module doc for why this
//! tool uses a directory override rather than the single-file `--file` other
//! tools/*-update crates use: it needs two files per version, not one file per
//! product).
//!
//! PROVENANCE CONTRACT (ATL round-1 adversary miss #1): the offline
//! `--fixtures` path must verify each file's bytes against the config's sha256
//! pins, exactly like the network path - the PR gate runs `check --fixtures`
//! on the committed fixtures, so an unverified offline read is a fail-OPEN
//! (silently corrupted/stale fixtures would pass the gate). Consequently every
//! test that feeds SYNTHETIC bytes writes its own pin-matching `refs.toml`
//! (hashes computed test-locally, independent of the impl's own hex encoder)
//! and passes it via `--config`; tests exercising the REAL committed bytes use
//! the default committed `attr-refs.toml`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

const SUBJECT_1_3_2: &str = include_str!("fixtures/1.3.2/subject-attr.c");
const OBJECT_1_3_2: &str = include_str!("fixtures/1.3.2/object-attr.c");
const SUBJECT_1_4_5: &str = include_str!("fixtures/1.4.5/subject-attr.c");
const OBJECT_1_4_5: &str = include_str!("fixtures/1.4.5/object-attr.c");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fapolicyd-attr-update")
}

/// Test-local sha256 hex - computed DIRECTLY via the sha2 crate, deliberately
/// NOT routed through the crate's own `source::verify_sha256`/`to_hex` helpers,
/// so a broken impl-side hex encoder cannot make a test's pins self-consistently
/// wrong (both sides agreeing on garbage).
fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Write a `tests/fixtures/`-shaped root (`<root>/<version>/{subject,object}-attr.c`
/// for both pinned versions) to a fresh temp directory, using the REAL committed
/// fixture content for every file except the `(version, filename)` pairs present
/// in `overrides`. Also writes `<root>/refs.toml`: an `attr-refs.toml`-shaped
/// config whose sha256 pins are computed (test-locally) from the bytes actually
/// written, so a test feeding synthetic fixture content can pass
/// `--config <root>/refs.toml` and keep the provenance gate green while
/// exercising a downstream behavior (drift / parse failure). Returns the root.
fn write_fixtures_root(tag: &str, overrides: &HashMap<(&str, &str), String>) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("fapd-attr-update-cli-{}-{tag}", std::process::id()));
    let real: [(&str, &str, &str); 4] = [
        ("1.3.2", "subject-attr.c", SUBJECT_1_3_2),
        ("1.3.2", "object-attr.c", OBJECT_1_3_2),
        ("1.4.5", "subject-attr.c", SUBJECT_1_4_5),
        ("1.4.5", "object-attr.c", OBJECT_1_4_5),
    ];
    let mut hashes: HashMap<(&str, &str), String> = HashMap::new();
    for (version, file, content) in real {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).expect("create fixture version dir");
        let body = overrides
            .get(&(version, file))
            .map(String::as_str)
            .unwrap_or(content);
        std::fs::write(dir.join(file), body).expect("write fixture file");
        hashes.insert((version, file), sha256_hex(body));
    }

    // Mirror the committed attr-refs.toml's shape (real tags + commits; only the
    // hashes track the possibly-overridden bytes written above).
    let refs = format!(
        "[versions.\"1.3.2\"]\n\
         tag = \"v1.3.2\"\n\
         commit = \"7870b72f60394c8f1f8e22db9f738bbf1855978c\"\n\
         subject_sha256 = \"{}\"\n\
         object_sha256 = \"{}\"\n\
         \n\
         [versions.\"1.4.5\"]\n\
         tag = \"v1.4.5\"\n\
         commit = \"69b55c21271aa40ae24bce7e1c869a635ea08776\"\n\
         subject_sha256 = \"{}\"\n\
         object_sha256 = \"{}\"\n",
        hashes[&("1.3.2", "subject-attr.c")],
        hashes[&("1.3.2", "object-attr.c")],
        hashes[&("1.4.5", "subject-attr.c")],
        hashes[&("1.4.5", "object-attr.c")],
    );
    std::fs::write(root.join("refs.toml"), refs).expect("write refs.toml");
    root
}

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// GREEN baseline: the real, unmutated committed fixtures for both pinned
/// versions must check clean end-to-end through the full CLI (arg parsing +
/// the DEFAULT committed `attr-refs.toml` + file read + provenance pins +
/// parse + drift compare) - a superset of what the library-level `registry`
/// tests cover (those call the derivation functions directly and skip
/// `main.rs`'s own glue entirely).
#[test]
fn check_real_fixtures_report_no_drift() {
    let root = write_fixtures_root("insync", &HashMap::new());
    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(0),
        "in-sync fixtures must exit 0; stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("OK (0 drift"), "stdout={stdout}");
}

/// Drift RED-case (the frozen contract test): rename ONE table row (the
/// `object-attr.c` `OBJ_TRUST` row, `"trust"` -> `"trustx"`) in the 1.4.5
/// fixture only, leaving 1.3.2 and 1.4.5's `subject-attr.c` untouched. This
/// simultaneously produces:
/// * a NAME drift ("trustx" is derived but not in the shipped registry), and
/// * a SIDE drift ("trust" is demoted from Both to Subject-only, since its
///   object-table row is gone).
///
/// `check` must report DRIFT, exit 1 (a non-zero outcome), and the reported
/// message must name the offending attribute. The test's own pin-matching
/// `--config` keeps the provenance gate green so the DRIFT path (not the
/// hash-mismatch path) is what's exercised.
#[test]
fn check_mutated_object_table_row_reports_drift_and_exits_1() {
    let mut overrides = HashMap::new();
    let mutated_object = OBJECT_1_4_5.replace("\"trust\"", "\"trustx\"");
    assert_ne!(
        mutated_object, OBJECT_1_4_5,
        "sanity: the mutation must actually change the fixture content"
    );
    overrides.insert(("1.4.5", "object-attr.c"), mutated_object);
    let root = write_fixtures_root("mutated-trust", &overrides);
    let config = root.join("refs.toml");

    let (code, stdout, stderr) = run(&[
        "check",
        "--fixtures",
        &root.to_string_lossy(),
        "--config",
        &config.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "a renamed table row must exit 1; stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("trust"),
        "the drift report must name the offending attribute (trust/trustx): stdout={stdout}"
    );
}

/// SIDE-ONLY drift still exits 1 (ATL round-1 mutation survivor: main.rs
/// `name_drift.is_empty() && side_drift.is_empty()` mutated `&&` -> `||`
/// survived because every prior drift case tripped BOTH halves). Dropping the
/// `SUBJ_TRUST` row from 1.4.5's `table2` changes NO names (`trust` remains
/// via 1.4.5's object table and both 1.3.2 tables, so the cross-version name
/// union is untouched) but demotes derived-1.4.5 `trust` from Both to
/// Object-only vs the shipped Both - a side-level-only disagreement. Under the
/// `||` mutant (either-empty == OK) this reports OK/exit 0; the real `&&`
/// contract must report DRIFT/exit 1 and the message must name `trust`.
#[test]
fn check_side_only_drift_exits_1() {
    let mut overrides = HashMap::new();
    let mutated_subject = SUBJECT_1_4_5.replace("{\tSUBJ_TRUST, \"trust\"\t},\n", "");
    assert_ne!(
        mutated_subject, SUBJECT_1_4_5,
        "sanity: the SUBJ_TRUST table2 row must actually be removed"
    );
    overrides.insert(("1.4.5", "subject-attr.c"), mutated_subject);
    let root = write_fixtures_root("side-only", &overrides);
    let config = root.join("refs.toml");

    let (code, stdout, stderr) = run(&[
        "check",
        "--fixtures",
        &root.to_string_lossy(),
        "--config",
        &config.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "a side-only disagreement must still exit 1; stdout={stdout} stderr={stderr}"
    );
    // Pin that this is the side-only shape: ZERO name drift, non-zero side.
    assert!(
        stdout.contains("DRIFT (0 name,"),
        "the drift must be side-level ONLY (0 name changes): stdout={stdout}"
    );
    assert!(
        stdout.contains("trust"),
        "the side drift must name the offending attribute: stdout={stdout}"
    );
}

/// Malformed/truncated fixture fails CLOSED: the 1.4.5 `subject-attr.c` is cut
/// off mid-`table2` declaration (no closing `};`). `check` must exit 2 (a parse
/// error), NOT exit 0 (which would mean the parser silently treated the
/// truncated file as an empty-but-valid registry) and NOT exit 1 (an empty
/// registry would also register as massive but well-formed "drift", which is
/// the WRONG failure mode for a corrupted source file - this must be a hard
/// error, distinguishable from a legitimate upstream registry change). The
/// test's pin-matching `--config` keeps the provenance gate green, so the
/// failure exercised here is specifically the PARSE fail-closed path (the
/// stderr must name the unparseable table), not the hash gate.
#[test]
fn check_truncated_fixture_fails_closed_exits_2() {
    let mut overrides = HashMap::new();
    let cut = SUBJECT_1_4_5
        .find("static const nv_t table2")
        .expect("table2 present in fixture");
    let truncated = format!(
        "{}static const nv_t table2[] = {{\n{{\tALL_SUBJ,   \"all\"\t}},\n",
        &SUBJECT_1_4_5[..cut]
    );
    overrides.insert(("1.4.5", "subject-attr.c"), truncated);
    let root = write_fixtures_root("truncated", &overrides);
    let config = root.join("refs.toml");

    let (code, _stdout, stderr) = run(&[
        "check",
        "--fixtures",
        &root.to_string_lossy(),
        "--config",
        &config.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(2),
        "a truncated subject-attr.c must fail closed (exit 2), not report success or drift; stderr={stderr}"
    );
    assert!(
        stderr.contains("table2"),
        "the error must come from the table2 parse (not the hash gate): stderr={stderr}"
    );
}

/// PROVENANCE fail-closed (ATL round-1 adversary miss #1, CLI half): fixture
/// bytes that PARSE identically to the committed ones (the tamper is a benign
/// trailing comment, outside every table, containing no quotes - the derived
/// registry is byte-for-byte the same 18 names) but do NOT match the default
/// `attr-refs.toml` sha256 pins must fail CLOSED with exit 2 and a message
/// naming the hash mismatch. Without offline verification this is a fail-OPEN:
/// `check --fixtures` (the PR gate's invocation) would report "OK (0 drift)"
/// on corrupted/stale fixture bytes, silently divorcing the gate from the
/// pinned upstream provenance.
#[test]
fn check_tampered_fixture_bytes_fail_closed_exits_2() {
    let mut overrides = HashMap::new();
    let tampered = format!("{OBJECT_1_4_5}\n// locally tampered: not the pinned upstream bytes\n");
    overrides.insert(("1.4.5", "object-attr.c"), tampered);
    let root = write_fixtures_root("tampered", &overrides);
    // Deliberately NO --config: the DEFAULT committed attr-refs.toml pins the
    // real upstream bytes, which the tampered file no longer matches.

    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "fixture bytes that mismatch the committed sha256 pins must fail closed \
         (exit 2), even though they parse to the identical registry; \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("sha256"),
        "the error must name the hash mismatch: stderr={stderr}"
    );
}

/// A `--fixtures` root missing a pinned version's directory entirely (e.g. the
/// 1.4.5 subdirectory absent) must also fail closed (exit 2), not silently skip
/// that version and report a partial "OK".
#[test]
fn check_missing_version_directory_fails_closed_exits_2() {
    let root = std::env::temp_dir().join(format!(
        "fapd-attr-update-cli-{}-missing-version",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("1.3.2")).expect("create dir");
    std::fs::write(root.join("1.3.2").join("subject-attr.c"), SUBJECT_1_3_2).expect("write");
    std::fs::write(root.join("1.3.2").join("object-attr.c"), OBJECT_1_3_2).expect("write");
    // 1.4.5/ deliberately absent.

    let (code, _stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "a missing pinned-version fixture directory must fail closed (exit 2); stderr={stderr}"
    );
}

/// `derive` must print the ACTUAL rendered registry, filtered to the selected
/// `--version` only (ATL round-1 mutation survivors: `render_row` gutted to
/// `""`/`"xyzzy"`, `derive_version` -> `Ok(vec![])`, `cmd_derive` ->
/// `Ok(Default::default())`, the `--version` filter's `&&`/`!=` operators, and
/// `flag` -> `None` all survived because the prior suite never asserted derive
/// OUTPUT content). Pins: the per-version header with the exact name count,
/// three exact rendered rows (one per Side variant), exactly 18 row lines, and
/// the ABSENCE of the non-selected version (kills the filter mutants: an
/// inverted/ignored filter prints 1.3.2's section too).
#[test]
fn derive_prints_rendered_rows_for_selected_version_only() {
    let root = write_fixtures_root("derive-content", &HashMap::new());
    let (code, stdout, stderr) = run(&[
        "derive",
        "--fixtures",
        &root.to_string_lossy(),
        "--version",
        "1.4.5",
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={stderr}");

    assert!(
        stdout.contains("# fapolicyd 1.4.5 (18 names)"),
        "the version header must carry the real name count: stdout={stdout}"
    );
    // One exact rendered row per Side variant (render_row's real format).
    for row in [
        "(\"filehash\", Object),",
        "(\"pattern\", Subject),",
        "(\"trust\", Both),",
    ] {
        assert!(
            stdout.contains(row),
            "derive output must contain the rendered row {row:?}: stdout={stdout}"
        );
    }
    let row_lines = stdout.lines().filter(|l| l.contains("(\"")).count();
    assert_eq!(
        row_lines, 18,
        "exactly the 18 derived 1.4.5 rows must be rendered: stdout={stdout}"
    );
    assert!(
        !stdout.contains("1.3.2"),
        "--version 1.4.5 must not print the 1.3.2 section: stdout={stdout}"
    );
}

/// `derive --version <unpinned>` is a user error: exit 2 with a message naming
/// the unknown version (kills the `printed_any` / `!` operator mutants guarding
/// the unknown-version error path).
#[test]
fn derive_unknown_version_exits_2() {
    let root = write_fixtures_root("derive-unknown", &HashMap::new());
    let (code, _stdout, stderr) = run(&[
        "derive",
        "--fixtures",
        &root.to_string_lossy(),
        "--version",
        "9.9.9",
    ]);
    assert_eq!(code, Some(2), "an unpinned --version must exit 2");
    assert!(
        stderr.contains("9.9.9"),
        "the error must name the unknown version: stderr={stderr}"
    );
}
