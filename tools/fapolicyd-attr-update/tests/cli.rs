//! End-to-end CLI tests: exercise the built binary fully offline (via `check
//! --fixtures DIR`) and assert the exit-code contract - 0 in sync, 1 on drift, 2
//! on error - mirroring `tools/{stig,sshd-stig}-update/tests/cli.rs`.
//!
//! `--fixtures DIR` expects `DIR/<version>/{subject,object}-attr.c` per pinned
//! version (see `../attr-refs.toml` and `src/main.rs`'s module doc for why this
//! tool uses a directory override rather than the single-file `--file` other
//! tools/*-update crates use: it needs two files per version, not one file per
//! product).

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

/// Write a `tests/fixtures/`-shaped root (`<root>/<version>/{subject,object}-attr.c`
/// for both pinned versions) to a fresh temp directory, using the REAL committed
/// fixture content for every file except the `(version, filename)` pairs present
/// in `overrides`. Returns the root directory path.
fn write_fixtures_root(tag: &str, overrides: &HashMap<(&str, &str), String>) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("fapd-attr-update-cli-{}-{tag}", std::process::id()));
    let real: [(&str, &str, &str); 4] = [
        ("1.3.2", "subject-attr.c", SUBJECT_1_3_2),
        ("1.3.2", "object-attr.c", OBJECT_1_3_2),
        ("1.4.5", "subject-attr.c", SUBJECT_1_4_5),
        ("1.4.5", "object-attr.c", OBJECT_1_4_5),
    ];
    for (version, file, content) in real {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).expect("create fixture version dir");
        let body = overrides
            .get(&(version, file))
            .map(String::as_str)
            .unwrap_or(content);
        std::fs::write(dir.join(file), body).expect("write fixture file");
    }
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
/// `attr-refs.toml` load + file read + parse + drift compare) - a superset of
/// what the library-level `registry` tests cover (those call the derivation
/// functions directly and skip `main.rs`'s own glue entirely).
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
/// message must name the offending attribute.
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

    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
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

/// Malformed/truncated fixture fails CLOSED: the 1.4.5 `subject-attr.c` is cut
/// off mid-`table2` declaration (no closing `};`). `check` must exit 2 (a parse
/// error), NOT exit 0 (which would mean the parser silently treated the
/// truncated file as an empty-but-valid registry) and NOT exit 1 (an empty
/// registry would also register as massive but well-formed "drift", which is
/// the WRONG failure mode for a corrupted source file - this must be a hard
/// error, distinguishable from a legitimate upstream registry change).
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

    let (code, _stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "a truncated subject-attr.c must fail closed (exit 2), not report success or drift; stderr={stderr}"
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
