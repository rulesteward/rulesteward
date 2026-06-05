//! Black-box e2e oracle tests for `rulesteward fapolicyd report` (issues #81/#82/#83/#84).
//!
//! ## Role (TDD barrier - TEST AUTHOR, IMPL-BLIND)
//!
//! These tests are authored BLIND to the implementation. They pin the CORRECT
//! output of `report` via 72 vendored golden scenarios. They FAIL RED because
//! `commands/report.rs::run()` is a `todo!()` stub (exit 101). When the
//! `feat-report` implementer fills the stub, all tests must turn GREEN.
//!
//! ## trustJoin shape - RESOLVED (f2 section 3.2, orchestrator 2026-06-04)
//!
//! All path-join scenarios use Shape A: `[{ "grantIndex": N, "rows": [...] }]`.
//! The two former Shape-B goldens have been normalized. The enumerate-cap shape
//! (grantSource/count/enumerated/entries) is a distinct opt-in form kept as-is.
//!
//! ## Corpus provenance
//!
//! Vendored from NFS at 2026-06-04T from:
//!   /mnt/side-projects/fapolicyd-report-corpus/20260603T034301Z-wave1-consolidated
//! Oracle method: f2 section 3.2 spec-derived golden registers + real trustdb digests.
//! See tests/corpus/report/PROVENANCE.md for full provenance record.
//!
//! ## Count note
//!
//! Issue #84 cites "63 scenarios" but the actual corpus has 73 (the
//! report-wave1-patch phase added 9 more after the issue was filed; the
//! adversarial-review fix added `trustdb-enumerate-cap-noflag`). All 73 are
//! wired here. The floor guard asserts >= 73.

use assert_cmd::Command;
use rulesteward_fapolicyd::trustdb::write_trustdb_fixture_kv;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("report")
}

fn scenario_rules_d(category: &str, id: &str) -> PathBuf {
    corpus_dir().join(category).join(id).join("rules.d")
}

fn scenario_golden(category: &str, id: &str) -> serde_json::Value {
    let path = corpus_dir()
        .join(category)
        .join(id)
        .join("golden-register.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read golden {category}/{id}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse golden {category}/{id}: {e}"))
}

fn scenario_snapshot(category: &str, id: &str) -> serde_json::Value {
    let path = corpus_dir().join(category).join(id).join("snapshot.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read snapshot {category}/{id}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse snapshot {category}/{id}: {e}"))
}

/// Run `rulesteward fapolicyd report <rules_d> --format json [extra...]` and
/// return the parsed JSON output. Panics if the binary cannot be found.
fn run_report_json(rules_d: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let output = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(rules_d)
        .args(["--format", "json"])
        .args(extra)
        .output()
        .expect("run rulesteward");
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = serde_json::from_str(stdout.as_ref()).unwrap_or_else(|e| {
        panic!("report output is not valid JSON (exit {exit_code}): {e}\nstdout: {stdout}")
    });
    (exit_code, parsed)
}

/// Assert the JSON output exactly matches the golden register (parsed value
/// comparison for stable key-order independence).
fn assert_matches_golden(actual: &serde_json::Value, golden: &serde_json::Value, label: &str) {
    assert_eq!(
        actual, golden,
        "{label}: JSON output must exactly match the golden register\nactual:  {actual:#}\ngolden:  {golden:#}"
    );
}

/// Assert the envelope top-level fields match spec constraints:
/// - `schemaVersion` == 1
/// - `kind` is the expected value
fn assert_envelope(v: &serde_json::Value, expected_kind: &str, label: &str) {
    assert_eq!(v["schemaVersion"], 1, "{label}: schemaVersion must be 1");
    assert_eq!(
        v["kind"].as_str().unwrap_or(""),
        expected_kind,
        "{label}: kind must be \"{expected_kind}\""
    );
}

// ---------------------------------------------------------------------------
// Trust-DB fixture builder
//
// Builds a real LMDB trust DB from a list of (path, source_int, size, digest)
// rows (all captured from manifest.json oracle blocks), using the test-fixtures
// feature of rulesteward-fapolicyd. Returns the tempdir that keeps the DB
// alive.
// ---------------------------------------------------------------------------

/// Build a tempdir LMDB trust DB from explicit rows.
///
/// Each row is `(path, source_int, size_bytes, sha256_hex)`. The LMDB value
/// format is `"<src_int> <size> <sha256_hex>"` (fapolicyd on-disk format,
/// per `trustdb.rs::parse_trust_value`).
///
/// `source_int`: 0=Unknown, 1=RpmDb, 2=FileDb, 3=Deb (`trustdb.rs::from_int`).
fn build_trustdb_from_rows(rows: &[(&str, u32, u64, &str)]) -> TempDir {
    let tmp = tempfile::tempdir().expect("tempdir for fixture trustdb");
    let kv: Vec<(&str, Vec<u8>)> = rows
        .iter()
        .map(|(path, src_int, size, digest)| {
            let value = format!("{src_int} {size} {digest}").into_bytes();
            (*path, value)
        })
        .collect();
    let kv_refs: Vec<(&str, &[u8])> = kv.iter().map(|(k, v)| (*k, v.as_slice())).collect();
    write_trustdb_fixture_kv(tmp.path(), &kv_refs);
    tmp
}

// ---------------------------------------------------------------------------
// Floor guard: all 72 scenarios enumerated
// ---------------------------------------------------------------------------

/// Enumerate all expected scenario IDs across all categories.
fn all_scenario_ids() -> Vec<(&'static str, &'static str)> {
    vec![
        // cardinality (5)
        ("cardinality", "card-empty-no-grants"),
        ("cardinality", "card-empty-only-setdef"),
        ("cardinality", "card-multi-many-mixed"),
        ("cardinality", "card-multi-three-distinct"),
        ("cardinality", "card-single-allow-all"),
        // decision (5)
        ("decision", "dec-all-four-one-file"),
        ("decision", "dec-allow"),
        ("decision", "dec-allow-audit"),
        ("decision", "dec-allow-log"),
        ("decision", "dec-allow-syslog"),
        // perm (4)
        ("perm", "perm-any"),
        ("perm", "perm-default-open"),
        ("perm", "perm-execute"),
        ("perm", "perm-explicit-open"),
        // scope (14)
        ("scope", "combo-exe-and-filehash"),
        ("scope", "combo-legacy-syntax-grant"),
        ("scope", "combo-multi-everything"),
        ("scope", "combo-trust-and-ftype"),
        ("scope", "combo-uid-gid-no-path"),
        ("scope", "scope-all"),
        ("scope", "scope-dir-object"),
        ("scope", "scope-ftype-object"),
        ("scope", "scope-hash-filehash"),
        ("scope", "scope-path-exe"),
        ("scope", "scope-path-object"),
        ("scope", "scope-pattern-subject"),
        ("scope", "scope-trust-object"),
        ("scope", "scope-trust-subject"),
        // hash-origin-alg (8)
        ("hash-origin-alg", "hash-filehash-md5-32"),
        ("hash-origin-alg", "hash-filehash-sha1-40"),
        ("hash-origin-alg", "hash-filehash-sha256-64"),
        ("hash-origin-alg", "hash-filehash-sha512-128"),
        ("hash-origin-alg", "hash-none-trustscope"),
        ("hash-origin-alg", "hash-none-typescope"),
        ("hash-origin-alg", "hash-sha256hash-attr-64"),
        ("hash-origin-alg", "hash-two-grants-diff-alg"),
        // set-expansion (5)
        ("set-expansion", "set-defined-but-unused"),
        ("set-expansion", "set-expansion-ftype-members"),
        ("set-expansion", "set-expansion-single-member"),
        ("set-expansion", "set-expansion-two-refs-one-rule"),
        ("set-expansion", "set-no-expansion"),
        // path-extraction (6)
        ("path-extraction", "paths-both-sides"),
        ("path-extraction", "paths-multi-same-side"),
        ("path-extraction", "paths-none"),
        ("path-extraction", "paths-object-dir"),
        ("path-extraction", "paths-object-path"),
        ("path-extraction", "paths-subject-exe"),
        // against-trustdb (9) - handled separately in against_trustdb module
        ("against-trustdb", "trustdb-enumerate-cap"),
        ("against-trustdb", "trustdb-enumerate-cap-noflag"),
        ("against-trustdb", "trustdb-enumerate-trust1"),
        ("against-trustdb", "trustdb-no-flag-trust1"),
        ("against-trustdb", "trustdb-path-join-miss"),
        ("against-trustdb", "trustdb-path-join-rpm"),
        ("against-trustdb", "trustdb-source-filedb"),
        ("against-trustdb", "trustdb-source-rpmdb"),
        ("against-trustdb", "trustdb-source-unknown"),
        // diff-drift (12) - handled separately in diff_drift module
        ("diff-drift", "diff-added-grant"),
        ("diff-drift", "diff-changed-hash-repin"),
        ("diff-drift", "diff-changed-origin"),
        ("diff-drift", "diff-changed-trustdb-digest"),
        ("diff-drift", "diff-line-churn-no-drift"),
        ("diff-drift", "diff-multi-drift"),
        ("diff-drift", "diff-no-drift"),
        ("diff-drift", "diff-object-change-dir"),
        ("diff-drift", "diff-object-change-ftype"),
        ("diff-drift", "diff-object-change-path"),
        ("diff-drift", "diff-removed-grant"),
        ("diff-drift", "diff-reorder-no-drift"),
        // load-order (4)
        ("load-order", "load-index-within-file"),
        ("load-order", "load-order-dup-predicate"),
        ("load-order", "load-order-numeric-prefix"),
        ("load-order", "load-order-two-files"),
        // noise-filter (5)
        ("noise-filter", "loadindex-deny-before-allow"),
        ("noise-filter", "noise-comments-blanks"),
        ("noise-filter", "noise-deny-excluded"),
        ("noise-filter", "noise-deny-family-all-four"),
        ("noise-filter", "noise-setdef-not-a-grant"),
    ]
}

/// Floor guard: all 77 vendored scenarios must be reachable on disk.
#[test]
fn corpus_floor_guard_77_scenarios_present() {
    let all = all_scenario_ids();
    let count = all.len();
    assert!(
        count >= 77,
        "Corpus floor guard: expected >= 77 scenarios, got {count}. \
         Issue #84 cited 63; wave1-patch added 9 more (72); adversarial-review fix added \
         trustdb-enumerate-cap-noflag (73); adversarial-impl-review added 3 drift-key \
         collision killers + 1 loadindex-deny-before-allow (77)."
    );
    for (category, id) in &all {
        let rules_d = scenario_rules_d(category, id);
        assert!(
            rules_d.exists(),
            "Missing vendored scenario rules.d: {}/{id}/rules.d (expected at {})",
            category,
            rules_d.display()
        );
        let golden = corpus_dir()
            .join(category)
            .join(id)
            .join("golden-register.json");
        assert!(
            golden.exists(),
            "Missing vendored golden: {category}/{id}/golden-register.json",
        );
    }
}

// ---------------------------------------------------------------------------
// Plain (no trustdb, no diff) oracle tests - one per scenario
// ---------------------------------------------------------------------------
//
// For each scenario that does NOT require --against-trustdb or --diff-against,
// run `report <rules.d> --format json` and assert output == golden.
//
// All of these are RED because run() is todo!() -> exit 101.

macro_rules! plain_oracle_test {
    ($test_name:ident, $category:expr, $id:expr) => {
        #[test]
        fn $test_name() {
            let rules_d = scenario_rules_d($category, $id);
            let golden = scenario_golden($category, $id);
            let (exit_code, actual) = run_report_json(&rules_d, &[]);
            assert_eq!(
                exit_code, 0,
                "{}/{}: expected exit 0, got {exit_code}",
                $category, $id
            );
            assert_envelope(
                &actual,
                "exception-register",
                &format!("{}/{}", $category, $id),
            );
            assert_matches_golden(&actual, &golden, &format!("{}/{}", $category, $id));
        }
    };
}

// cardinality
plain_oracle_test!(
    oracle_card_empty_no_grants,
    "cardinality",
    "card-empty-no-grants"
);
plain_oracle_test!(
    oracle_card_empty_only_setdef,
    "cardinality",
    "card-empty-only-setdef"
);
plain_oracle_test!(
    oracle_card_multi_many_mixed,
    "cardinality",
    "card-multi-many-mixed"
);
plain_oracle_test!(
    oracle_card_multi_three_distinct,
    "cardinality",
    "card-multi-three-distinct"
);
plain_oracle_test!(
    oracle_card_single_allow_all,
    "cardinality",
    "card-single-allow-all"
);

// decision
plain_oracle_test!(
    oracle_dec_all_four_one_file,
    "decision",
    "dec-all-four-one-file"
);
plain_oracle_test!(oracle_dec_allow, "decision", "dec-allow");
plain_oracle_test!(oracle_dec_allow_audit, "decision", "dec-allow-audit");
plain_oracle_test!(oracle_dec_allow_log, "decision", "dec-allow-log");
plain_oracle_test!(oracle_dec_allow_syslog, "decision", "dec-allow-syslog");

// perm
plain_oracle_test!(oracle_perm_any, "perm", "perm-any");
plain_oracle_test!(oracle_perm_default_open, "perm", "perm-default-open");
plain_oracle_test!(oracle_perm_execute, "perm", "perm-execute");
plain_oracle_test!(oracle_perm_explicit_open, "perm", "perm-explicit-open");

// scope
plain_oracle_test!(
    oracle_combo_exe_and_filehash,
    "scope",
    "combo-exe-and-filehash"
);
plain_oracle_test!(
    oracle_combo_legacy_syntax_grant,
    "scope",
    "combo-legacy-syntax-grant"
);
plain_oracle_test!(
    oracle_combo_multi_everything,
    "scope",
    "combo-multi-everything"
);
plain_oracle_test!(
    oracle_combo_trust_and_ftype,
    "scope",
    "combo-trust-and-ftype"
);
plain_oracle_test!(
    oracle_combo_uid_gid_no_path,
    "scope",
    "combo-uid-gid-no-path"
);
plain_oracle_test!(oracle_scope_all, "scope", "scope-all");
plain_oracle_test!(oracle_scope_dir_object, "scope", "scope-dir-object");
plain_oracle_test!(oracle_scope_ftype_object, "scope", "scope-ftype-object");
plain_oracle_test!(oracle_scope_hash_filehash, "scope", "scope-hash-filehash");
plain_oracle_test!(oracle_scope_path_exe, "scope", "scope-path-exe");
plain_oracle_test!(oracle_scope_path_object, "scope", "scope-path-object");
plain_oracle_test!(
    oracle_scope_pattern_subject,
    "scope",
    "scope-pattern-subject"
);
plain_oracle_test!(oracle_scope_trust_object, "scope", "scope-trust-object");
plain_oracle_test!(oracle_scope_trust_subject, "scope", "scope-trust-subject");

// hash-origin-alg (loadIndex is 1-based per f2 sections 2.4 / 3.2 and the
// wave-1-patch correction; all six previously 0-based goldens were fixed to start at 1)
plain_oracle_test!(
    oracle_hash_filehash_md5_32,
    "hash-origin-alg",
    "hash-filehash-md5-32"
);
plain_oracle_test!(
    oracle_hash_filehash_sha1_40,
    "hash-origin-alg",
    "hash-filehash-sha1-40"
);
plain_oracle_test!(
    oracle_hash_filehash_sha256_64,
    "hash-origin-alg",
    "hash-filehash-sha256-64"
);
plain_oracle_test!(
    oracle_hash_filehash_sha512_128,
    "hash-origin-alg",
    "hash-filehash-sha512-128"
);
plain_oracle_test!(
    oracle_hash_none_trustscope,
    "hash-origin-alg",
    "hash-none-trustscope"
);
plain_oracle_test!(
    oracle_hash_none_typescope,
    "hash-origin-alg",
    "hash-none-typescope"
);
plain_oracle_test!(
    oracle_hash_sha256hash_attr_64,
    "hash-origin-alg",
    "hash-sha256hash-attr-64"
);
plain_oracle_test!(
    oracle_hash_two_grants_diff_alg,
    "hash-origin-alg",
    "hash-two-grants-diff-alg"
);

// set-expansion
plain_oracle_test!(
    oracle_set_defined_but_unused,
    "set-expansion",
    "set-defined-but-unused"
);
plain_oracle_test!(
    oracle_set_expansion_ftype_members,
    "set-expansion",
    "set-expansion-ftype-members"
);
plain_oracle_test!(
    oracle_set_expansion_single_member,
    "set-expansion",
    "set-expansion-single-member"
);
plain_oracle_test!(
    oracle_set_expansion_two_refs_one_rule,
    "set-expansion",
    "set-expansion-two-refs-one-rule"
);
plain_oracle_test!(oracle_set_no_expansion, "set-expansion", "set-no-expansion");

// path-extraction
plain_oracle_test!(
    oracle_paths_both_sides,
    "path-extraction",
    "paths-both-sides"
);
plain_oracle_test!(
    oracle_paths_multi_same_side,
    "path-extraction",
    "paths-multi-same-side"
);
plain_oracle_test!(oracle_paths_none, "path-extraction", "paths-none");
plain_oracle_test!(
    oracle_paths_object_dir,
    "path-extraction",
    "paths-object-dir"
);
plain_oracle_test!(
    oracle_paths_object_path,
    "path-extraction",
    "paths-object-path"
);
plain_oracle_test!(
    oracle_paths_subject_exe,
    "path-extraction",
    "paths-subject-exe"
);

// load-order
plain_oracle_test!(
    oracle_load_index_within_file,
    "load-order",
    "load-index-within-file"
);
plain_oracle_test!(
    oracle_load_order_dup_predicate,
    "load-order",
    "load-order-dup-predicate"
);
plain_oracle_test!(
    oracle_load_order_numeric_prefix,
    "load-order",
    "load-order-numeric-prefix"
);
plain_oracle_test!(
    oracle_load_order_two_files,
    "load-order",
    "load-order-two-files"
);

// noise-filter
plain_oracle_test!(
    oracle_loadindex_deny_before_allow,
    "noise-filter",
    "loadindex-deny-before-allow"
);
plain_oracle_test!(
    oracle_noise_comments_blanks,
    "noise-filter",
    "noise-comments-blanks"
);
plain_oracle_test!(
    oracle_noise_deny_excluded,
    "noise-filter",
    "noise-deny-excluded"
);
plain_oracle_test!(
    oracle_noise_deny_family_all_four,
    "noise-filter",
    "noise-deny-family-all-four"
);
plain_oracle_test!(
    oracle_noise_setdef_not_a_grant,
    "noise-filter",
    "noise-setdef-not-a-grant"
);

// against-trustdb: trustdb-no-flag-trust1 is the one against-trustdb scenario
// that does NOT use --against-trustdb (it tests the trust=1 case WITHOUT the
// flag; the golden has no trustJoin block). It runs as a plain test.
plain_oracle_test!(
    oracle_trustdb_no_flag_trust1,
    "against-trustdb",
    "trustdb-no-flag-trust1"
);

// ---------------------------------------------------------------------------
// against-trustdb oracle tests
//
// trustJoin shape - RESOLVED (f2 section 3.2, orchestrator decision 2026-06-04)
//
// All path-join scenarios use Shape A (per-grant array):
//   "trustJoin": [{ "grantIndex": 0, "rows": [{path, source, size, digest}] }]
//
// The former Shape B goldens (diff-changed-trustdb-digest and trustdb-source-unknown)
// have been normalized to Shape A in the trustJoin-fix commit.
//
// trustdb-enumerate-cap uses a distinct shape (object with grantSource/count/
// enumerated/entries) for the --enumerate-trust opt-in cap form (f2 section 2.4).
// This is intentionally different from the per-grant path-join Shape A and is
// kept as-is.
//
// The three trustJoin forms and which scenarios use them:
//   Shape A (path-join): all against-trustdb path-join scenarios + diff-drift
//     scenarios that use --against-trustdb (trustdb-path-join-rpm, trustdb-source-*,
//     trustdb-path-join-miss, diff-changed-trustdb-digest)
//   Enumerate-cap shape: trustdb-enumerate-cap (--enumerate-trust opt-in)
//   No trustJoin: scenarios without --against-trustdb (trustdb-no-flag-trust1, all
//     cardinality/decision/perm/scope/hash-origin-alg/set-expansion/path-extraction/
//     load-order/noise-filter and most diff-drift scenarios)
// ---------------------------------------------------------------------------

/// Trustdb fixture rows for scenarios that join `/usr/bin/rpm` (`RpmDb`, `src_int=1`).
/// Digest from the real fapolicyd trust DB (grounding in manifest.json oracle blocks).
fn rpm_trustdb_rows() -> Vec<(&'static str, u32, u64, &'static str)> {
    vec![(
        "/usr/bin/rpm",
        1, // RpmDb
        24200,
        "4153ba40ce4cbbe142248737a1438016d504ec50d00a186d9a0958e482de0826",
    )]
}

/// trustdb-path-join-rpm: a concrete exe= path grant joins to its trust-DB row;
/// hashOrigin becomes "trustdb", SHA256. trustJoin has grantIndex=0 with one row.
#[test]
fn oracle_trustdb_path_join_rpm() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-path-join-rpm");
    let golden = scenario_golden("against-trustdb", "trustdb-path-join-rpm");
    let tmp = build_trustdb_from_rows(&rpm_trustdb_rows());
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "trustdb-path-join-rpm: expected exit 0, got {exit_code}"
    );
    assert_envelope(&actual, "exception-register", "trustdb-path-join-rpm");
    assert_matches_golden(&actual, &golden, "trustdb-path-join-rpm");
    // Additionally assert Shape A trustJoin structure explicitly (impl guard):
    let join = &actual["trustJoin"];
    assert!(join.is_array(), "trustJoin must be a JSON array");
    let first = &join[0];
    assert!(
        first["grantIndex"].is_number(),
        "trustJoin[0].grantIndex must exist (Shape A)"
    );
    assert!(
        first["rows"].is_array(),
        "trustJoin[0].rows must be an array (Shape A)"
    );
}

/// trustdb-source-rpmdb: source int 1 maps to `TrustSource::RpmDb` in the `trustJoin` row.
#[test]
fn oracle_trustdb_source_rpmdb() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-source-rpmdb");
    let golden = scenario_golden("against-trustdb", "trustdb-source-rpmdb");
    let tmp = build_trustdb_from_rows(&rpm_trustdb_rows());
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "trustdb-source-rpmdb: expected exit 0");
    assert_matches_golden(&actual, &golden, "trustdb-source-rpmdb");
    let rows = &actual["trustJoin"][0]["rows"];
    assert_eq!(
        rows[0]["source"], "RpmDb",
        "source int 1 must render as RpmDb"
    );
}

/// trustdb-source-filedb: source int 2 maps to `TrustSource::FileDb`.
#[test]
fn oracle_trustdb_source_filedb() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-source-filedb");
    let golden = scenario_golden("against-trustdb", "trustdb-source-filedb");
    let filedb_rows = vec![(
        "/usr/local/bin/mytool",
        2, // FileDb
        22,
        "541af05cc76beb84d47421e052366c026740bb87cff284865238374c336e5545",
    )];
    let tmp = build_trustdb_from_rows(&filedb_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "trustdb-source-filedb: expected exit 0");
    assert_matches_golden(&actual, &golden, "trustdb-source-filedb");
    let rows = &actual["trustJoin"][0]["rows"];
    assert_eq!(
        rows[0]["source"], "FileDb",
        "source int 2 must render as FileDb"
    );
}

/// trustdb-source-unknown: source int 0 maps to `TrustSource::Unknown`.
/// The corpus golden for this scenario now uses Shape A (normalized by the
/// trustJoin-fix commit). The inline expected below matches the golden file.
#[test]
fn oracle_trustdb_source_unknown() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-source-unknown");
    // Build the expected Shape A golden for assertion
    // (inline so the test is self-contained and the structure is explicit):
    let expected = serde_json::json!({
        "schemaVersion": 1,
        "kind": "exception-register",
        "grants": [{
            "decision": "allow",
            "perm": "open",
            "subject": "exe=/opt/vendor/bin/agent",
            "object": "all",
            "subjectPaths": ["/opt/vendor/bin/agent"],
            "objectPaths": [],
            "hash": "c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08",
            "hashOrigin": "trustdb",
            "hashAlgorithm": "SHA256",
            "scope": "path",
            "setExpansions": {},
            "source": { "file": "96-srcunknown.rules", "line": 1 },
            "loadIndex": 1
        }],
        "trustJoin": [{
            "grantIndex": 0,
            "rows": [{
                "path": "/opt/vendor/bin/agent",
                "source": "Unknown",
                "size": 51,
                "digest": "c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08"
            }]
        }]
    });
    let unknown_rows = vec![(
        "/opt/vendor/bin/agent",
        0, // Unknown
        51u64,
        "c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08",
    )];
    let tmp = build_trustdb_from_rows(&unknown_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "trustdb-source-unknown: expected exit 0");
    assert_envelope(&actual, "exception-register", "trustdb-source-unknown");
    assert_matches_golden(
        &actual,
        &expected,
        "trustdb-source-unknown (Shape A authoritative)",
    );
    let rows = &actual["trustJoin"][0]["rows"];
    assert_eq!(
        rows[0]["source"], "Unknown",
        "source int 0 must render as Unknown"
    );
}

/// trustdb-path-join-miss: a path grant with no matching trust-DB row; hashOrigin
/// stays "none"; trustJoin has grantIndex=0 with an empty rows array.
#[test]
fn oracle_trustdb_path_join_miss() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-path-join-miss");
    let golden = scenario_golden("against-trustdb", "trustdb-path-join-miss");
    // The trust DB contains /usr/bin/ls (NOT the exe= in the rule, which is
    // /usr/local/bin/notindb) - so the join MISSES.
    let miss_rows = vec![(
        "/usr/bin/ls",
        1, // RpmDb
        49,
        "309b3c9a3246361ec0338641aed3c14e7f91e23e7cf10de000c75135ba99fddd",
    )];
    let tmp = build_trustdb_from_rows(&miss_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "trustdb-path-join-miss: expected exit 0");
    assert_matches_golden(&actual, &golden, "trustdb-path-join-miss");
    // The miss yields an empty rows array (not absent trustJoin):
    let rows = &actual["trustJoin"][0]["rows"];
    assert!(
        rows.is_array() && rows.as_array().unwrap().is_empty(),
        "trustdb-path-join-miss: trustJoin[0].rows must be an empty array on a miss"
    );
}

/// trustdb-enumerate-trust1: a trust=1 grant WITH --against-trustdb and
/// --enumerate-trust; the trustJoin block must carry the full entry list.
/// This scenario has 3 trust DB rows (ls/cat/opt-local-tool).
#[test]
fn oracle_trustdb_enumerate_trust1() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-enumerate-trust1");
    let golden = scenario_golden("against-trustdb", "trustdb-enumerate-trust1");
    // Three rows from manifest.json oracle block
    let enum_rows = vec![
        (
            "/usr/bin/ls",
            1, // RpmDb
            49,
            "309b3c9a3246361ec0338641aed3c14e7f91e23e7cf10de000c75135ba99fddd",
        ),
        (
            "/usr/bin/cat",
            2, // FileDb
            50,
            "c6138c9502337f42763d627e4b665dd4fd66f26a987891d0a7e8313783f689ad",
        ),
        (
            "/opt/local/tool",
            0, // Unknown
            23,
            "03d2c1c283a28a22e87c242b19ae8b5040d8335cc4eb3781529955d281ff0cfe",
        ),
    ];
    let tmp = build_trustdb_from_rows(&enum_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &[
            "--against-trustdb",
            tmp.path().to_str().expect("utf8"),
            "--enumerate-trust",
        ],
    );
    assert_eq!(exit_code, 0, "trustdb-enumerate-trust1: expected exit 0");
    assert_matches_golden(&actual, &golden, "trustdb-enumerate-trust1");
}

/// trustdb-enumerate-cap (WITHOUT --enumerate-trust): the enumeration gate must
/// suppress the full 25-entry list and emit the count-only cap form.
///
/// # The property under test (f2 section 2.4 / Q4, issue #82)
///
/// A single `trust=1` grant covers ~72k trusted files in production. Without
/// `--enumerate-trust` the implementation MUST emit a suppressed cap block:
///   `{ "grantSource": ..., "count": 25, "enumerated": false }`
/// with NO `entries` list. An implementation that always enumerates all entries
/// (ignores the gate) passes the old weak assertion but FAILS this test.
///
/// The `trustdb-enumerate-cap-noflag` golden pins the exact no-flag wire shape.
/// The WITH-flag twin (`oracle_trustdb_enumerate_cap_with_flag`) pins the full form.
/// Together they force the implementer to honour BOTH sides of the gate.
///
/// The 25 fixture rows are the same `build_cap_trustdb_rows()` used by the WITH-flag test.
#[test]
fn oracle_trustdb_enumerate_cap_without_flag() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-enumerate-cap");
    let golden_noflag = scenario_golden("against-trustdb", "trustdb-enumerate-cap-noflag");
    let cap_rows = build_cap_trustdb_rows();
    let tmp = build_trustdb_from_rows(&cap_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--against-trustdb", tmp.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "trustdb-enumerate-cap (no flag): expected exit 0"
    );
    assert_envelope(
        &actual,
        "exception-register",
        "trustdb-enumerate-cap (no flag)",
    );

    // Pin the exact no-flag wire shape against the vendored golden.
    // This fails a never-cap impl (one that always emits the 25-entry list):
    // such an impl would produce `enumerated: true` + a 25-element `entries`
    // array, which does not equal the golden's `enumerated: false` + no `entries`.
    assert_matches_golden(&actual, &golden_noflag, "trustdb-enumerate-cap (no flag)");

    // Belt-and-suspenders: assert the suppression invariants directly so a
    // structural mismatch in the golden itself does not hide the property.
    let join = actual["trustJoin"]
        .as_object()
        .expect("trustdb-enumerate-cap (no flag): trustJoin must be a JSON object in the cap form");
    assert_eq!(
        join.get("enumerated").and_then(serde_json::Value::as_bool),
        Some(false),
        "trustdb-enumerate-cap (no flag): trustJoin.enumerated must be false (entries suppressed)"
    );
    assert_eq!(
        join.get("count").and_then(serde_json::Value::as_u64),
        Some(25),
        "trustdb-enumerate-cap (no flag): trustJoin.count must be 25"
    );
    // No `entries` key, or an empty/absent entries array - the 25-row list must
    // not be present. A wrong impl emitting `entries: [25 items]` fails here.
    let entries_len = join
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(
        entries_len, 0,
        "trustdb-enumerate-cap (no flag): trustJoin must NOT carry the 25-entry list without \
         --enumerate-trust (got {entries_len} entries; expected 0 or absent)"
    );
}

#[test]
fn oracle_trustdb_enumerate_cap_with_flag() {
    let rules_d = scenario_rules_d("against-trustdb", "trustdb-enumerate-cap");
    let golden = scenario_golden("against-trustdb", "trustdb-enumerate-cap");
    let cap_rows = build_cap_trustdb_rows();
    let tmp = build_trustdb_from_rows(&cap_rows);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &[
            "--against-trustdb",
            tmp.path().to_str().expect("utf8"),
            "--enumerate-trust",
        ],
    );
    assert_eq!(
        exit_code, 0,
        "trustdb-enumerate-cap (with flag): expected exit 0"
    );
    assert_matches_golden(
        &actual,
        &golden,
        "trustdb-enumerate-cap (--enumerate-trust)",
    );
}

/// Build the 25 `FileDb` trust-DB rows captured in trustdb-enumerate-cap/manifest.json.
// 25 data rows in tuple form; there is no meaningful way to reduce line count further.
#[allow(clippy::too_many_lines)]
fn build_cap_trustdb_rows() -> Vec<(&'static str, u32, u64, &'static str)> {
    vec![
        (
            "/usr/bin/[",
            2,
            48,
            "afd97bbd643bfe1473794af167cd5c6f44fe449681033e3584b40b836f624b4b",
        ),
        (
            "/usr/bin/addr2line",
            2,
            28408,
            "cba8e8f3f6cbbae449c426c354b62eb2641daacff4524534c91866f54e827971",
        ),
        (
            "/usr/bin/alias",
            2,
            33,
            "c277897660adddce26a75871188bdae7ffa73f571a6fb779090a4c92df33988d",
        ),
        (
            "/usr/bin/ar",
            2,
            57328,
            "a11f48a428eb1255cc70d98fa44a6379b77d8daa4362da0e4beedddbc788ad5f",
        ),
        (
            "/usr/bin/arch",
            2,
            51,
            "209bae4071910ef54b4a3bd302059bf7e00870d8bacffcd7c5489425f37ed16f",
        ),
        (
            "/usr/bin/arping",
            2,
            27896,
            "1bd55e017ba8746aa0ff5561382ec72f1e0dbc8eada677a6c63ab7821e9f32c9",
        ),
        (
            "/usr/bin/as",
            2,
            727_368,
            "515db58c63606abb91c08960022c1e541ef473f8a9e0d81f6ebcf1eb5868a0d2",
        ),
        (
            "/usr/bin/attr",
            2,
            16096,
            "dea7d94771744cd115d74864cf4c439f40f033ad3d813102076747ee9c4e3366",
        ),
        (
            "/usr/bin/audit2allow",
            2,
            15064,
            "c540b9edef596cb74442d82634bf340193cd0445efad6853944ef595062b5e55",
        ),
        (
            "/usr/bin/aulast",
            2,
            19664,
            "8152e96195cfb6e186cec4dc4fa64e6861a6b5492f5ef3d417ebe8fe68808b5e",
        ),
        (
            "/usr/bin/aulastlog",
            2,
            15488,
            "a0bae31df53fe3a574748ca15b08aff722feab9e32b4db4200accc0df589c611",
        ),
        (
            "/usr/bin/ausyscall",
            2,
            15480,
            "78dbed9adeb3c599963b4d83a9d159aad090cd2fe5c220a5bd7f8fe8f6c2eb34",
        ),
        (
            "/usr/bin/auvirt",
            2,
            36152,
            "6d2f500a2c6efb3801fd0288c889a1e8678302ead32b9ec267dd9655731fc4fe",
        ),
        (
            "/usr/bin/b2sum",
            2,
            52,
            "9116333c88eee22e55e30db1ad088483f52a3024b624356416873bc14fad9359",
        ),
        (
            "/usr/bin/base32",
            2,
            53,
            "ff10172686b6db691ae57530dff6cd14b980cbba7ed81a8dcf81bd42dd7bb23b",
        ),
        (
            "/usr/bin/base64",
            2,
            53,
            "fed1b291454a61812e605fd06b04f915ef7e5436cfc1ee17f96523f56c2fbebf",
        ),
        (
            "/usr/bin/basename",
            2,
            55,
            "9a1e6804fef8ca36d39b008210b187dc4a82c456919574e61e17ab40c033589c",
        ),
        (
            "/usr/bin/basenc",
            2,
            53,
            "cd8a131e0af4133b97da4adcca84ae61cc24c898d8d0e2b6aabac6d2d7a34094",
        ),
        (
            "/usr/bin/bash",
            2,
            1_389_024,
            "ec6d007d48ef11bc47ad3f372b4b20ff2f0d4e63867e7e4cc0f1b17b19fa88b2",
        ),
        (
            "/usr/bin/bashbug-64",
            2,
            7079,
            "5588678b4cf9d513e85c908fad23ed079135656be7b79559570b23f4c3433022",
        ),
        (
            "/usr/bin/bg",
            2,
            30,
            "5a864f2047a83aa767ac1a3fca577e5f3a8eb4d129b4b1974fb2009960a9a0be",
        ),
        (
            "/usr/bin/busctl",
            2,
            102_560,
            "d13279e945ea5f87d1e8142bc8c72f5dc3480df4553797e69f5cac1a9c259e4d",
        ),
        (
            "/usr/bin/c++filt",
            2,
            27832,
            "5e4cc686f443c908863a7316cd3c99d901d3daf59ea16a9372e918baedb54343",
        ),
        (
            "/usr/bin/ca-legacy",
            2,
            1648,
            "48f9c9bd7473d45f2f2e30d5c723cf58d7175be9e3f19573a67049cbac35330a",
        ),
        (
            "/usr/bin/cal",
            2,
            53064,
            "0b83b31f33a5fde9116308d50574b6b7e256812897ab53dd938eb0cfe1d04a2c",
        ),
    ]
}

// ---------------------------------------------------------------------------
// diff-drift oracle tests
// ---------------------------------------------------------------------------

/// Helper: write a `serde_json::Value` to a tempfile, return the `NamedTempFile`.
fn write_json_tmp(v: &serde_json::Value) -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::NamedTempFile::new().expect("tempfile for snapshot");
    serde_json::to_writer_pretty(&mut f, v).expect("write snapshot JSON");
    f.flush().expect("flush snapshot");
    f
}

/// diff-added-grant: one new grant in current vs snapshot; drift has one "added" row.
/// Exit 0 (--fail-on-drift absent; drift is informational by default per f2 section 5).
#[test]
fn oracle_diff_added_grant() {
    let rules_d = scenario_rules_d("diff-drift", "diff-added-grant");
    let golden = scenario_golden("diff-drift", "diff-added-grant");
    let snapshot = scenario_snapshot("diff-drift", "diff-added-grant");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "diff-added-grant: default exit must be 0 (drift is informational)"
    );
    assert_envelope(&actual, "exception-register-drift", "diff-added-grant");
    assert_matches_golden(&actual, &golden, "diff-added-grant");
    // Specifically assert the drift array has one "added" row
    let drift = actual["drift"].as_array().expect("drift must be an array");
    assert_eq!(
        drift.len(),
        1,
        "diff-added-grant: must have exactly 1 drift row"
    );
    assert_eq!(
        drift[0]["kind"], "added",
        "diff-added-grant: drift row must be 'added'"
    );
}

/// diff-added-grant with --fail-on-drift: must exit 1 because drift exists.
#[test]
fn oracle_diff_added_grant_fail_on_drift_exits_one() {
    let rules_d = scenario_rules_d("diff-drift", "diff-added-grant");
    let snapshot = scenario_snapshot("diff-drift", "diff-added-grant");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, _actual) = run_report_json(
        &rules_d,
        &[
            "--diff-against",
            snap_file.path().to_str().expect("utf8"),
            "--fail-on-drift",
        ],
    );
    assert_eq!(
        exit_code, 1,
        "diff-added-grant --fail-on-drift: must exit 1 when drift is present (f2 section 5)"
    );
}

/// diff-removed-grant: one grant present in snapshot, absent now; one "removed" row.
#[test]
fn oracle_diff_removed_grant() {
    let rules_d = scenario_rules_d("diff-drift", "diff-removed-grant");
    let golden = scenario_golden("diff-drift", "diff-removed-grant");
    let snapshot = scenario_snapshot("diff-drift", "diff-removed-grant");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "diff-removed-grant: default exit must be 0");
    assert_envelope(&actual, "exception-register-drift", "diff-removed-grant");
    assert_matches_golden(&actual, &golden, "diff-removed-grant");
    let drift = actual["drift"].as_array().expect("drift must be an array");
    assert_eq!(
        drift.len(),
        1,
        "diff-removed-grant: must have exactly 1 drift row"
    );
    assert_eq!(drift[0]["kind"], "removed", "drift row must be 'removed'");
    assert!(
        drift[0]["from"].is_object(),
        "removed row must carry 'from'"
    );
    assert!(drift[0]["to"].is_null(), "removed row must have null 'to'");
}

/// diff-changed-hash-repin: same canonical key, different filehash; one "changed" row.
#[test]
fn oracle_diff_changed_hash_repin() {
    let rules_d = scenario_rules_d("diff-drift", "diff-changed-hash-repin");
    let golden = scenario_golden("diff-drift", "diff-changed-hash-repin");
    let snapshot = scenario_snapshot("diff-drift", "diff-changed-hash-repin");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "diff-changed-hash-repin: default exit 0");
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-changed-hash-repin",
    );
    assert_matches_golden(&actual, &golden, "diff-changed-hash-repin");
    let drift = actual["drift"].as_array().expect("drift array");
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0]["kind"], "changed", "must be 'changed'");
    // Both from and to must be present for a changed row
    assert!(
        drift[0]["from"].is_object(),
        "changed row must carry 'from'"
    );
    assert!(drift[0]["to"].is_object(), "changed row must carry 'to'");
}

/// diff-no-drift: current == snapshot; drift array is empty; exit 0 without flag.
#[test]
fn oracle_diff_no_drift() {
    let rules_d = scenario_rules_d("diff-drift", "diff-no-drift");
    let golden = scenario_golden("diff-drift", "diff-no-drift");
    // The snapshot IS the current golden register (same grants); use the
    // golden register itself as the snapshot to produce zero drift.
    let snap_file = write_json_tmp(&golden);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    // When drift is empty, the output is a drift envelope with drift: []
    assert_eq!(exit_code, 0, "diff-no-drift: exit 0 when drift is empty");
    assert_envelope(&actual, "exception-register-drift", "diff-no-drift");
    let drift = actual["drift"].as_array().expect("drift array");
    assert!(drift.is_empty(), "diff-no-drift: drift must be empty");
}

/// diff-no-drift with --fail-on-drift: must STILL exit 0 (no drift present).
#[test]
fn oracle_diff_no_drift_fail_on_drift_exits_zero() {
    let rules_d = scenario_rules_d("diff-drift", "diff-no-drift");
    let golden = scenario_golden("diff-drift", "diff-no-drift");
    let snap_file = write_json_tmp(&golden);
    let (exit_code, _actual) = run_report_json(
        &rules_d,
        &[
            "--diff-against",
            snap_file.path().to_str().expect("utf8"),
            "--fail-on-drift",
        ],
    );
    assert_eq!(
        exit_code, 0,
        "diff-no-drift --fail-on-drift: must exit 0 when no drift is present"
    );
}

/// diff-line-churn-no-drift: snapshot and current differ ONLY in line numbers;
/// canonical predicate keys match; drift empty (proves diff key is predicate-based).
#[test]
fn oracle_diff_line_churn_no_drift() {
    let rules_d = scenario_rules_d("diff-drift", "diff-line-churn-no-drift");
    // Snapshot: same two grants but at lines 1 and 2 (no leading comments).
    // Current: same grants at lines 3 and 4 (two leading comments shift them).
    // The canonical key ignores file:line, so drift = [].
    let snapshot = serde_json::json!({
        "schemaVersion": 1,
        "kind": "exception-register",
        "grants": [
            {
                "decision": "allow",
                "perm": "open",
                "subject": "all",
                "object": "all",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": null,
                "hashOrigin": "none",
                "hashAlgorithm": null,
                "scope": "all",
                "setExpansions": {},
                "source": { "file": "A7-churn.rules", "line": 1 },
                "loadIndex": 1
            },
            {
                "decision": "allow",
                "perm": "execute",
                "subject": "all",
                "object": "trust=1",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": null,
                "hashOrigin": "none",
                "hashAlgorithm": null,
                "scope": "trust",
                "setExpansions": {},
                "source": { "file": "A7-churn.rules", "line": 2 },
                "loadIndex": 2
            }
        ]
    });
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "diff-line-churn-no-drift: exit 0");
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-line-churn-no-drift",
    );
    let drift = actual["drift"].as_array().expect("drift array");
    assert!(
        drift.is_empty(),
        "diff-line-churn-no-drift: line-number-only changes must NOT produce drift rows"
    );
}

/// diff-reorder-no-drift: same grants in different load order; set-equality on
/// canonical keys produces empty drift.
#[test]
fn oracle_diff_reorder_no_drift() {
    let rules_d = scenario_rules_d("diff-drift", "diff-reorder-no-drift");
    // Snapshot: all-all FIRST, then execute/trust=1.
    // Current (rules.d/A8-reorder.rules): execute/trust=1 FIRST, then all-all.
    // Drift comparison is order-independent -> empty.
    let snapshot = serde_json::json!({
        "schemaVersion": 1,
        "kind": "exception-register",
        "grants": [
            {
                "decision": "allow",
                "perm": "open",
                "subject": "all",
                "object": "all",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": null,
                "hashOrigin": "none",
                "hashAlgorithm": null,
                "scope": "all",
                "setExpansions": {},
                "source": { "file": "A8-reorder.rules", "line": 1 },
                "loadIndex": 1
            },
            {
                "decision": "allow",
                "perm": "execute",
                "subject": "all",
                "object": "trust=1",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": null,
                "hashOrigin": "none",
                "hashAlgorithm": null,
                "scope": "trust",
                "setExpansions": {},
                "source": { "file": "A8-reorder.rules", "line": 2 },
                "loadIndex": 2
            }
        ]
    });
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "diff-reorder-no-drift: exit 0");
    assert_envelope(&actual, "exception-register-drift", "diff-reorder-no-drift");
    let drift = actual["drift"].as_array().expect("drift array");
    assert!(
        drift.is_empty(),
        "diff-reorder-no-drift: reordering grants must NOT produce drift rows"
    );
}

/// diff-multi-drift: simultaneous added (all-all), removed (execute/trust=1), and
/// changed (hash re-pin for filehash grant). Three drift rows total.
#[test]
fn oracle_diff_multi_drift() {
    let rules_d = scenario_rules_d("diff-drift", "diff-multi-drift");
    // NOTE: golden is the CURRENT register (2 grants); the diff output is
    // an exception-register-drift envelope. We assert the drift structure below.
    // Construct the snapshot per the README:
    // - allow perm=open all : filehash=ffff...ffff (same key as current grant 2, diff digest) -> changed
    // - allow perm=execute all : trust=1 (absent from current) -> removed
    // - current allow perm=open all : all is absent from snapshot -> added
    let snapshot = serde_json::json!({
        "schemaVersion": 1,
        "kind": "exception-register",
        "grants": [
            {
                "decision": "allow",
                "perm": "open",
                "subject": "all",
                "object": "filehash=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "hashOrigin": "rule-filehash",
                "hashAlgorithm": "SHA256",
                "scope": "hash",
                "setExpansions": {},
                "source": { "file": "A6-multi.rules", "line": 2 },
                "loadIndex": 2
            },
            {
                "decision": "allow",
                "perm": "execute",
                "subject": "all",
                "object": "trust=1",
                "subjectPaths": [],
                "objectPaths": [],
                "hash": null,
                "hashOrigin": "none",
                "hashAlgorithm": null,
                "scope": "trust",
                "setExpansions": {},
                "source": { "file": "A6-multi.rules", "line": 3 },
                "loadIndex": 3
            }
        ]
    });
    // NOTE: the golden for diff-multi-drift is the CURRENT register (two grants),
    // not the drift output. The diff-against mode wraps output in an
    // exception-register-drift envelope. We assert the drift envelope structure.
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(exit_code, 0, "diff-multi-drift: default exit 0");
    assert_envelope(&actual, "exception-register-drift", "diff-multi-drift");
    let drift = actual["drift"].as_array().expect("drift array");
    assert_eq!(
        drift.len(),
        3,
        "diff-multi-drift: must have 3 drift rows (added+removed+changed)"
    );
    // One of each kind:
    let kinds: Vec<&str> = drift
        .iter()
        .map(|r| r["kind"].as_str().unwrap_or(""))
        .collect();
    assert!(kinds.contains(&"added"), "must have an added row");
    assert!(kinds.contains(&"removed"), "must have a removed row");
    assert!(kinds.contains(&"changed"), "must have a changed row");
    // --fail-on-drift exits 1
    let (fail_code, _) = run_report_json(
        &rules_d,
        &[
            "--diff-against",
            snap_file.path().to_str().expect("utf8"),
            "--fail-on-drift",
        ],
    );
    assert_eq!(
        fail_code, 1,
        "diff-multi-drift --fail-on-drift: must exit 1"
    );
}

/// diff-changed-origin: hashOrigin changed from "none" to "trustdb" (same canonical
/// predicate key). This uses both --against-trustdb and --diff-against.
#[test]
fn oracle_diff_changed_origin() {
    let rules_d = scenario_rules_d("diff-drift", "diff-changed-origin");
    let snapshot = scenario_snapshot("diff-drift", "diff-changed-origin");
    // The snapshot has hashOrigin "none"; with --against-trustdb the join enriches
    // the current grant to hashOrigin "trustdb". Same canonical key -> "changed".
    let rpm_rows = rpm_trustdb_rows();
    let tmp = build_trustdb_from_rows(&rpm_rows);
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &[
            "--against-trustdb",
            tmp.path().to_str().expect("utf8"),
            "--diff-against",
            snap_file.path().to_str().expect("utf8"),
        ],
    );
    assert_eq!(exit_code, 0, "diff-changed-origin: default exit 0");
    assert_envelope(&actual, "exception-register-drift", "diff-changed-origin");
    let drift = actual["drift"].as_array().expect("drift array");
    assert_eq!(drift.len(), 1, "diff-changed-origin: must have 1 drift row");
    assert_eq!(drift[0]["kind"], "changed", "must be 'changed'");
    assert_eq!(
        drift[0]["from"]["hashOrigin"], "none",
        "from.hashOrigin must be 'none'"
    );
    assert_eq!(
        drift[0]["to"]["hashOrigin"], "trustdb",
        "to.hashOrigin must be 'trustdb'"
    );
}

/// diff-changed-trustdb-digest: the trust-DB digest for a path grant changed between
/// snapshots (integrity drift). Uses --against-trustdb and --diff-against.
/// The corpus golden now uses Shape A trustJoin (normalized by the trustJoin-fix commit).
#[test]
fn oracle_diff_changed_trustdb_digest() {
    let rules_d = scenario_rules_d("diff-drift", "diff-changed-trustdb-digest");
    // The snapshot has the CURRENT digest (4153ba...); the fixture DB contains the
    // SAME digest -> no digest change in the DB itself. But the golden shows a
    // "changed" drift row. Per the manifest: the scenario tests that the trust-DB
    // digest matching the rule's path triggers a "changed" (integrity-drift) row
    // vs. the snapshot value.
    // To produce the drift: snapshot must have a DIFFERENT digest than the DB row.
    // The snapshot in the golden has the SAME digest as the real RPM DB, so there
    // would be no change. Per the scenario description ("the resolved trust-DB digest
    // for an enumerable grant differs from the snapshot"), the snapshot must have a
    // STALE digest that doesn't match the DB.
    // We construct the snapshot with a stale digest to force the "changed" row.
    let stale_snapshot = serde_json::json!({
        "schemaVersion": 1,
        "kind": "exception-register",
        "grants": [{
            "decision": "allow",
            "perm": "open",
            "subject": "exe=/usr/bin/rpm",
            "object": "all",
            "subjectPaths": ["/usr/bin/rpm"],
            "objectPaths": [],
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "hashOrigin": "trustdb",
            "hashAlgorithm": "SHA256",
            "scope": "path",
            "setExpansions": {},
            "source": { "file": "A4-trustdigest.rules", "line": 1 },
            "loadIndex": 1
        }]
    });
    let rpm_rows = rpm_trustdb_rows(); // has the REAL digest 4153ba...
    let tmp = build_trustdb_from_rows(&rpm_rows);
    let snap_file = write_json_tmp(&stale_snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &[
            "--against-trustdb",
            tmp.path().to_str().expect("utf8"),
            "--diff-against",
            snap_file.path().to_str().expect("utf8"),
        ],
    );
    assert_eq!(exit_code, 0, "diff-changed-trustdb-digest: default exit 0");
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-changed-trustdb-digest",
    );
    let drift = actual["drift"].as_array().expect("drift array");
    assert_eq!(drift.len(), 1, "must have 1 drift row");
    assert_eq!(drift[0]["kind"], "changed", "must be 'changed'");
    // The from digest must be the stale value; to must be the real DB value
    assert_eq!(
        drift[0]["from"]["hash"],
        "0000000000000000000000000000000000000000000000000000000000000000",
        "from.hash must be the stale snapshot digest"
    );
    assert_eq!(
        drift[0]["to"]["hash"], "4153ba40ce4cbbe142248737a1438016d504ec50d00a186d9a0958e482de0826",
        "to.hash must be the DB-resolved digest"
    );
}

// ---------------------------------------------------------------------------
// Drift-key collision killing tests (adversarial-impl-review, 2026-06-05)
//
// The impl's compute_drift keys on `decision|perm|subject|scope`, which collides
// when two grants share the same scope but have DIFFERENT object values (e.g.
// dir=/a/ vs dir=/b/ both have scope=dir -> the old key treats them as the SAME
// grant -> reports zero drift instead of removed+added). These three scenarios
// each supply a snapshot with one object value and a current rules.d with a
// different object of the same scope, asserting exactly 2 drift rows (removed +
// added). They are RED against the current impl (which collapses them to zero drift).
// The diff-changed-hash-repin test (above) ensures hash repins STAY "changed"
// after the implementer's fix.
// ---------------------------------------------------------------------------

/// diff-object-change-dir: snapshot has `allow open all : dir=/a/`; current has
/// `allow open all : dir=/b/`. Same scope (dir), same subject (all), same
/// decision/perm. Different object -> must be REMOVED + ADDED (NOT zero drift).
///
/// RED against the current impl (which keys on decision|perm|subject|scope and
/// collides /a/ and /b/ into a single key -> reports no drift).
#[test]
fn oracle_diff_object_change_dir() {
    let rules_d = scenario_rules_d("diff-drift", "diff-object-change-dir");
    let golden = scenario_golden("diff-drift", "diff-object-change-dir");
    let snapshot = scenario_snapshot("diff-drift", "diff-object-change-dir");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "diff-object-change-dir: default exit must be 0 (drift is informational)"
    );
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-object-change-dir",
    );
    assert_matches_golden(&actual, &golden, "diff-object-change-dir");
    // The key property: EXACTLY 2 drift rows (added for dir=/b/, removed for dir=/a/).
    // A drift-key-colliding impl reports 0 rows here -> RED.
    let drift = actual["drift"].as_array().expect("drift must be an array");
    assert_eq!(
        drift.len(),
        2,
        "diff-object-change-dir: must have exactly 2 drift rows (removed dir=/a/ + added dir=/b/), \
         not 0 (which indicates drift-key collision: decision|perm|subject|scope collapses both)"
    );
    let kinds: std::collections::HashSet<&str> =
        drift.iter().filter_map(|r| r["kind"].as_str()).collect();
    assert!(
        kinds.contains("added"),
        "diff-object-change-dir: must have an 'added' row for dir=/b/"
    );
    assert!(
        kinds.contains("removed"),
        "diff-object-change-dir: must have a 'removed' row for dir=/a/"
    );
    // Verify the object values appear in the drift rows (not just the count):
    let added = drift.iter().find(|r| r["kind"] == "added").unwrap();
    assert_eq!(
        added["grant"]["object"], "dir=/b/",
        "added row must reference dir=/b/"
    );
    let removed = drift.iter().find(|r| r["kind"] == "removed").unwrap();
    assert_eq!(
        removed["grant"]["object"], "dir=/a/",
        "removed row must reference dir=/a/"
    );
}

/// diff-object-change-ftype: snapshot has `allow open all : ftype=application/x-executable`;
/// current has `allow open all : ftype=text/x-shellscript`. Same ftype scope, different
/// MIME type -> must be REMOVED + ADDED.
///
/// RED against the current impl (ftype-scope collision produces zero drift).
#[test]
fn oracle_diff_object_change_ftype() {
    let rules_d = scenario_rules_d("diff-drift", "diff-object-change-ftype");
    let golden = scenario_golden("diff-drift", "diff-object-change-ftype");
    let snapshot = scenario_snapshot("diff-drift", "diff-object-change-ftype");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "diff-object-change-ftype: default exit must be 0"
    );
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-object-change-ftype",
    );
    assert_matches_golden(&actual, &golden, "diff-object-change-ftype");
    let drift = actual["drift"].as_array().expect("drift must be an array");
    assert_eq!(
        drift.len(),
        2,
        "diff-object-change-ftype: must have exactly 2 drift rows (removed + added), \
         not 0 (drift-key ftype-scope collision)"
    );
    let kinds: std::collections::HashSet<&str> =
        drift.iter().filter_map(|r| r["kind"].as_str()).collect();
    assert!(kinds.contains("added"), "must have 'added' row");
    assert!(kinds.contains("removed"), "must have 'removed' row");
    let added = drift.iter().find(|r| r["kind"] == "added").unwrap();
    assert_eq!(
        added["grant"]["object"], "ftype=text/x-shellscript",
        "added row must reference ftype=text/x-shellscript"
    );
    let removed = drift.iter().find(|r| r["kind"] == "removed").unwrap();
    assert_eq!(
        removed["grant"]["object"], "ftype=application/x-executable",
        "removed row must reference ftype=application/x-executable"
    );
}

/// diff-object-change-path: snapshot has `allow open all : path=/x`;
/// current has `allow open all : path=/y`. Same path scope, different path ->
/// must be REMOVED + ADDED.
///
/// RED against the current impl (path-scope collision produces zero drift).
#[test]
fn oracle_diff_object_change_path() {
    let rules_d = scenario_rules_d("diff-drift", "diff-object-change-path");
    let golden = scenario_golden("diff-drift", "diff-object-change-path");
    let snapshot = scenario_snapshot("diff-drift", "diff-object-change-path");
    let snap_file = write_json_tmp(&snapshot);
    let (exit_code, actual) = run_report_json(
        &rules_d,
        &["--diff-against", snap_file.path().to_str().expect("utf8")],
    );
    assert_eq!(
        exit_code, 0,
        "diff-object-change-path: default exit must be 0"
    );
    assert_envelope(
        &actual,
        "exception-register-drift",
        "diff-object-change-path",
    );
    assert_matches_golden(&actual, &golden, "diff-object-change-path");
    let drift = actual["drift"].as_array().expect("drift must be an array");
    assert_eq!(
        drift.len(),
        2,
        "diff-object-change-path: must have exactly 2 drift rows (removed path=/x + added path=/y), \
         not 0 (drift-key path-scope collision)"
    );
    let kinds: std::collections::HashSet<&str> =
        drift.iter().filter_map(|r| r["kind"].as_str()).collect();
    assert!(kinds.contains("added"), "must have 'added' row");
    assert!(kinds.contains("removed"), "must have 'removed' row");
    let added = drift.iter().find(|r| r["kind"] == "added").unwrap();
    assert_eq!(
        added["grant"]["object"], "path=/y",
        "added row must reference path=/y"
    );
    let removed = drift.iter().find(|r| r["kind"] == "removed").unwrap();
    assert_eq!(
        removed["grant"]["object"], "path=/x",
        "removed row must reference path=/x"
    );
}

// ---------------------------------------------------------------------------
// C02 parity test: canonical_grant_key agrees with the linter's C02 AST-equality
// notion (issue #82, spec-reviewer requirement).
//
// This is a WHITE-BOX unit test calling the frozen register::canonical_grant_key
// function directly (via rulesteward-fapolicyd's public API). It guards against
// the register's canonicalization and the linter's C02 duplicate-detection
// silently drifting apart.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod c02_parity {
    use rulesteward_core::span;
    use rulesteward_fapolicyd::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
    use rulesteward_fapolicyd::facts::SetTable;
    use rulesteward_fapolicyd::register::canonical_grant_key;

    fn kv(key: &str, value: AttrValue) -> Attr {
        Attr::Kv {
            key: key.to_owned(),
            value,
            span: span(0, 0),
        }
    }

    fn rule(decision: Decision, perm: Option<Perm>, subject: Vec<Attr>, object: Vec<Attr>) -> Rule {
        Rule {
            decision,
            perm,
            subject,
            object,
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: span(0, 0),
        }
    }

    fn empty_sets() -> SetTable {
        SetTable::from_entries(&[])
    }

    /// C02 duplicate pair: two allow rules with the SAME predicate in DIFFERENT
    /// attribute order. A C02-detecting linter considers these duplicates; the
    /// register's `canonical_grant_key` must return EQUAL keys for both.
    ///
    /// Rule A: `allow perm=open exe=/usr/bin/bash uid=0 : all`
    /// Rule B: `allow perm=open uid=0 exe=/usr/bin/bash : all` (attrs reordered)
    /// Same canonical predicate -> SAME key.
    #[test]
    fn c02_parity_attribute_order_different_same_key() {
        let sets = empty_sets();
        let rule_a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![
                kv("exe", AttrValue::Str("/usr/bin/bash".into())),
                kv("uid", AttrValue::Int(0)),
            ],
            vec![Attr::All],
        );
        let rule_b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![
                kv("uid", AttrValue::Int(0)),
                kv("exe", AttrValue::Str("/usr/bin/bash".into())),
            ],
            vec![Attr::All],
        );
        assert_eq!(
            canonical_grant_key(&rule_a, &sets),
            canonical_grant_key(&rule_b, &sets),
            "C02 parity: reordered-attribute pair must produce EQUAL canonical keys"
        );
    }

    /// C02 duplicate pair: a `%set` reference vs its explicit expanded members.
    /// A C02-detecting linter considers these duplicates; `canonical_grant_key`
    /// must return EQUAL keys.
    ///
    /// Rule A: `allow perm=open uid=%admins : all` where `%admins` = {0, 1000}
    /// Rule B: `allow perm=open uid=0,1000 : all` (literal with sorted members)
    ///
    /// The canonical value of a `SetRef` expands and sorts members, so `uid=%admins`
    /// (= {0, 1000}) and `uid=0,1000` (treated as a literal "0,1000") must
    /// produce the same canonical string. This tests the intersection of
    /// C02's set-expansion and register's set-expansion.
    #[test]
    fn c02_parity_set_ref_vs_explicit_members_same_key() {
        let sets = SetTable::from_entries(&[Entry::SetDefinition {
            name: "admins".to_owned(),
            values: vec!["1000".to_owned(), "0".to_owned()], // unsorted, proves expansion sorts
            line: 1,
            span: span(0, 0),
        }]);
        let via_ref = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::SetRef("admins".into()))],
            vec![Attr::All],
        );
        // Literal whose canonical form is "0,1000" (sorted members joined with comma)
        let via_literal = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::Str("0,1000".into()))],
            vec![Attr::All],
        );
        assert_eq!(
            canonical_grant_key(&via_ref, &sets),
            canonical_grant_key(&via_literal, &sets),
            "C02 parity: %set reference must canonicalize to same key as explicit sorted members"
        );
    }

    /// Non-duplicate pair: different decisions must produce DIFFERENT keys.
    /// A C02-detecting linter would NOT flag these as duplicates.
    #[test]
    fn c02_parity_different_decision_different_key() {
        let sets = empty_sets();
        let allow_rule = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        let deny_rule = rule(
            Decision::Deny,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&allow_rule, &sets),
            canonical_grant_key(&deny_rule, &sets),
            "C02 parity: different decision must produce DIFFERENT canonical keys"
        );
    }

    /// Non-duplicate pair: different perm must produce DIFFERENT keys.
    #[test]
    fn c02_parity_different_perm_different_key() {
        let sets = empty_sets();
        let open_rule = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        let exec_rule = rule(
            Decision::Allow,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&open_rule, &sets),
            canonical_grant_key(&exec_rule, &sets),
            "C02 parity: different perm must produce DIFFERENT canonical keys"
        );
    }

    /// Non-duplicate pair: different subject path must produce DIFFERENT keys.
    #[test]
    fn c02_parity_different_subject_different_key() {
        let sets = empty_sets();
        let rule_a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("exe", AttrValue::Str("/usr/bin/bash".into()))],
            vec![Attr::All],
        );
        let rule_b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("exe", AttrValue::Str("/usr/bin/sh".into()))],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&rule_a, &sets),
            canonical_grant_key(&rule_b, &sets),
            "C02 parity: different subject must produce DIFFERENT canonical keys"
        );
    }

    /// Non-duplicate pair: different object path must produce DIFFERENT keys.
    #[test]
    fn c02_parity_different_object_different_key() {
        let sets = empty_sets();
        let rule_a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/usr/bin/a".into()))],
        );
        let rule_b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/usr/bin/b".into()))],
        );
        assert_ne!(
            canonical_grant_key(&rule_a, &sets),
            canonical_grant_key(&rule_b, &sets),
            "C02 parity: different object path must produce DIFFERENT canonical keys"
        );
    }

    /// Absent perm defaults to open: `allow : all` keys equal
    /// `allow perm=open : all` (C02 treats these as identical).
    #[test]
    fn c02_parity_absent_perm_equals_explicit_open() {
        let sets = empty_sets();
        let no_perm = rule(Decision::Allow, None, vec![Attr::All], vec![Attr::All]);
        let explicit_open = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_eq!(
            canonical_grant_key(&no_perm, &sets),
            canonical_grant_key(&explicit_open, &sets),
            "C02 parity: absent perm must default to open for canonical key purposes"
        );
    }

    /// Drift-key collision guard: two rules with the SAME decision/perm/subject
    /// but DIFFERENT object values MUST produce DIFFERENT canonical keys.
    ///
    /// This pins the requirement that `compute_drift` keys on the FULL canonical
    /// predicate (including the object). A drift key of `decision|perm|subject|scope`
    /// (without the object value) would make `allow open all : dir=/a/` and
    /// `allow open all : dir=/b/` collide -> `compute_drift` reports zero drift
    /// instead of removed+added. `canonical_grant_key` already encodes the object
    /// (it was always correct); this test asserts that the drift function uses
    /// the SAME notion (i.e. the implementer must key `compute_drift` on the full
    /// canonical predicate, not a truncated scope-only key).
    #[test]
    fn c02_parity_drift_key_includes_object_value_no_collision() {
        let sets = empty_sets();

        // dir=/a/ vs dir=/b/ - same scope=dir, different object value
        let dir_a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("dir", AttrValue::Str("/a/".into()))],
        );
        let dir_b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("dir", AttrValue::Str("/b/".into()))],
        );
        assert_ne!(
            canonical_grant_key(&dir_a, &sets),
            canonical_grant_key(&dir_b, &sets),
            "canonical_grant_key: dir=/a/ and dir=/b/ must produce DIFFERENT keys \
             (object value is part of the key; drift must key on this, not just scope)"
        );

        // ftype=A vs ftype=B - same scope=ftype, different MIME
        let ftype_exec = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv(
                "ftype",
                AttrValue::Str("application/x-executable".into()),
            )],
        );
        let ftype_sh = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("ftype", AttrValue::Str("text/x-shellscript".into()))],
        );
        assert_ne!(
            canonical_grant_key(&ftype_exec, &sets),
            canonical_grant_key(&ftype_sh, &sets),
            "canonical_grant_key: ftype=application/x-executable and ftype=text/x-shellscript \
             must produce DIFFERENT keys"
        );

        // path=/x vs path=/y - same scope=path, different object path
        let path_x = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/x".into()))],
        );
        let path_y = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/y".into()))],
        );
        assert_ne!(
            canonical_grant_key(&path_x, &sets),
            canonical_grant_key(&path_y, &sets),
            "canonical_grant_key: path=/x and path=/y must produce DIFFERENT keys"
        );
    }
}
