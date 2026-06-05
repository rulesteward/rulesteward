//! #127 RED tests for `rulesteward fapolicyd simulate`:
//!
//! 1. `--trustdb <dir>` performs a READ-ONLY trust lookup, resolving subject /
//!    object trust FROM THE DB when the workload omits the `trust` field.
//! 2. On-demand object hashing: a `filehash=`/`sha256hash=` rule is evaluated by
//!    hashing the object file on disk when the workload omits `sha256` but the
//!    object `path` exists.
//!
//! ## TDD state: RED
//!
//! The current `simulate::run()` accepts `--trustdb` but does NOT read it
//! (it emits a stderr note and uses `Trust::Unknown`), and never hashes the
//! object on disk. Both tests below FAIL against the current impl and PASS only
//! once #127 wires the DB lookup + on-demand hashing.
//!
//! ## Grounding
//!
//! - Trust-DB fixtures are real LMDB DBs built via the feature-gated
//!   `write_trustdb_fixture_kv` (the CLI crate enables `rulesteward-fapolicyd`
//!   with `features = ["test-fixtures"]`), value format `"<src> <size> <sha256>"`
//!   (the fapolicyd on-disk shape; see `trustdb.rs::write_trustdb_fixture_kv`).
//! - `KNOWN_*` is a coreutils-`sha256sum`-verified (bytes, size, hex) triple for
//!   `b"hello trustdb\n"` (primary source, not derived from the impl under test);
//!   the same constant the trustdb tests use.
//! - The `exe=trusted`/`exe=untrusted` trust-macro semantics (#126) are what let
//!   a DB-resolved subject trust change the verdict, grounded on the re-vendored
//!   `adversarial/exe-untrusted-macro-*` oracle scenarios (real fapolicyd 1.4.5).

use assert_cmd::Command;
use rulesteward_fapolicyd::trustdb::write_trustdb_fixture_kv;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// coreutils-verified triple for `b"hello trustdb\n"`:
/// `printf 'hello trustdb\n' | sha256sum`. Grounded in a primary source.
const KNOWN_BYTES: &[u8] = b"hello trustdb\n";
const KNOWN_SIZE: u64 = 14;
const KNOWN_SHA256: &str = "3ea762cdbe2e0e8bd475edcfbe4ef960df0389bab22131b18ca9d9ccf08ccc27";

/// Build the canonical fapolicyd trust-DB value bytes: `"<src> <size> <sha256>"`.
fn value_bytes(src_int: u32, size: u64, sha256_hex: &str) -> Vec<u8> {
    format!("{src_int} {size} {sha256_hex}").into_bytes()
}

/// Create a real file containing `KNOWN_BYTES` at `path`.
fn write_known_file(path: &Path) {
    let mut f = std::fs::File::create(path).expect("create known file");
    f.write_all(KNOWN_BYTES).expect("write known bytes");
    f.flush().expect("flush");
}

/// Write a `rules.d` dir containing a single `.rules` file. Returns the guard
/// (kept alive) and the dir path.
fn write_rules_dir(rules_content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("10-test.rules"), rules_content).expect("write rules");
    let p = dir.path().to_path_buf();
    (dir, p)
}

/// Write a workload JSON file. Returns the guard (kept alive) and its path.
fn write_workload(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("workload tempfile");
    write!(f, "{json}").expect("write workload");
    f.flush().expect("flush");
    f
}

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

fn parse_json(label: &str, bytes: &[u8]) -> serde_json::Value {
    let s = String::from_utf8_lossy(bytes);
    serde_json::from_str(&s)
        .unwrap_or_else(|e| panic!("{label}: output is not valid JSON: {e}\nstdout: {s}"))
}

// ---------------------------------------------------------------------------
// #127 part 1: --trustdb read-only resolution of subject trust
// ---------------------------------------------------------------------------

/// `simulate --trustdb <db>` resolves SUBJECT trust from the DB when the workload
/// omits `trust`.
///
/// Setup:
///   - Trust DB contains the subject exe path `/usr/bin/trusted-tool`.
///   - Ruleset: `deny_audit perm=any exe=trusted : all` then `allow perm=any all : all`.
///   - Workload: `{exe: /usr/bin/trusted-tool, path: /etc/hostname, perm: open}`
///     -- NO `trust` field.
///
/// Expected with #127: the DB lookup resolves `subj_trust = Yes`, so the
/// `exe=trusted` macro (#126) FIRES rule 1 -> `decision=deny, matchedRule=1`,
/// `verdict=Decisive`.
///
/// Why a wrong impl fails: an impl that ignores `--trustdb` leaves
/// `subj_trust = Unknown`; the `exe=trusted` macro is then `NotEvaluable` ->
/// rule 1 is a Possible (not decisive) -> fallthrough to rule 2 `allow`. So the
/// wrong impl predicts `decision=allow, matchedRule=2, verdict=Possible` and the
/// `decision == "deny"` assertion fails.
#[test]
fn trustdb_resolves_subject_trust_when_workload_omits_trust() {
    let db_dir = tempfile::tempdir().expect("db tempdir");
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            "/usr/bin/trusted-tool",
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    let (_rules_guard, rules_dir) =
        write_rules_dir("deny_audit perm=any exe=trusted : all\nallow perm=any all : all\n");
    // NOTE: workload deliberately omits `trust` / `subjTrust` / `objTrust`.
    let workload =
        write_workload(r#"{"exe":"/usr/bin/trusted-tool","path":"/etc/hostname","perm":"open"}"#);

    let out = bin()
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--trustdb",
            db_dir.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("trustdb_resolves_subject_trust", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "deny",
        "--trustdb must resolve subj_trust=Yes from the DB so exe=trusted fires (rule 1 deny)"
    );
    assert_eq!(
        result["matchedRule"], 1,
        "the deny rule (exe=trusted) is rule 1"
    );
    assert_eq!(
        result["verdict"], "Decisive",
        "DB-resolved trust makes the macro decisive, not Possible"
    );
    assert_eq!(result["source"], "rule");
}

/// `simulate --trustdb <db>` resolves an ABSENT-from-DB subject as untrusted.
///
/// Setup mirrors the above but the workload's exe (`/tmp/payload`) is NOT a key
/// in the DB. With #127 the lookup resolves `subj_trust = No`, so the
/// `exe=untrusted` macro fires rule 1 deny.
///
/// Why a wrong impl fails: ignoring `--trustdb` leaves `Unknown` ->
/// `exe=untrusted` is `NotEvaluable` -> rule 1 Possible -> fallthrough allow.
/// A correct impl that consults the DB and finds the path ABSENT must map that
/// to `No` (present-in-DB => trusted; absent => untrusted), firing the deny.
#[test]
fn trustdb_absent_subject_resolves_untrusted() {
    let db_dir = tempfile::tempdir().expect("db tempdir");
    // DB has some OTHER trusted path, but NOT the workload's exe.
    write_trustdb_fixture_kv(
        db_dir.path(),
        &[(
            "/usr/bin/some-trusted-binary",
            value_bytes(1, KNOWN_SIZE, KNOWN_SHA256).as_slice(),
        )],
    );

    let (_rules_guard, rules_dir) =
        write_rules_dir("deny_audit perm=any exe=untrusted : all\nallow perm=any all : all\n");
    let workload = write_workload(r#"{"exe":"/tmp/payload","path":"/etc/hostname","perm":"open"}"#);

    let out = bin()
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--trustdb",
            db_dir.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("trustdb_absent_subject_resolves_untrusted", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "deny",
        "an exe absent from the trust DB resolves untrusted -> exe=untrusted fires (deny)"
    );
    assert_eq!(result["matchedRule"], 1, "the deny rule is rule 1");
    assert_eq!(
        result["verdict"], "Decisive",
        "DB-resolved (absent=>untrusted) trust is decisive, not Possible"
    );
}

// ---------------------------------------------------------------------------
// #127 part 2: on-demand object hashing for filehash= / sha256hash=
// ---------------------------------------------------------------------------

/// `simulate` HASHES the object file on disk on demand when the workload supplies
/// the object `path` but OMITS `sha256`, so a `sha256hash=` rule is evaluated.
///
/// Setup:
///   - A real file on disk at the workload's `path`, containing `KNOWN_BYTES`
///     (sha256 = `KNOWN_SHA256`).
///   - Ruleset: `deny_audit perm=any all : sha256hash=<KNOWN_SHA256>` then
///     `allow perm=any all : all`.
///   - Workload: `{exe, path: <the file>, perm: open}` -- NO `sha256` field.
///
/// Expected with #127: simulate hashes the file, gets `KNOWN_SHA256`, the
/// `sha256hash=` rule MATCHES -> `decision=deny, matchedRule=1, verdict=Decisive`.
///
/// Why a wrong impl fails: the current impl evaluates `sha256hash=` only against
/// a workload-supplied `sha256`. With `sha256` absent, `facts.sha256 = None`, so
/// the object field WIDENS (absent fact => match) and rule 1 deny fires by
/// accident -- BUT the `verdict` is the tell: without a real hash there is no
/// uncertainty here either, so to distinguish a CORRECT on-demand hash from the
/// absent-fact-widening shortcut we use a SECOND scenario (below) where the file
/// hash does NOT match the rule; the widening impl wrongly denies while the
/// correct hashing impl correctly allows.
#[test]
fn filehash_on_demand_hash_matches_rule() {
    let file_dir = tempfile::tempdir().expect("file tempdir");
    let obj_path = file_dir.path().join("trusted-object");
    write_known_file(&obj_path);

    let rules =
        format!("deny_audit perm=any all : sha256hash={KNOWN_SHA256}\nallow perm=any all : all\n");
    let (_rules_guard, rules_dir) = write_rules_dir(&rules);
    // workload omits `sha256`; supplies the on-disk `path`.
    let workload = write_workload(&format!(
        r#"{{"exe":"/usr/bin/cat","path":"{}","perm":"open"}}"#,
        obj_path.display()
    ));

    let out = bin()
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("filehash_on_demand_hash_matches_rule", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "deny",
        "on-demand hash of the object file matches sha256hash= -> deny rule 1 fires"
    );
    assert_eq!(
        result["matchedRule"], 1,
        "the sha256hash= deny rule is rule 1"
    );
    assert_eq!(
        result["verdict"], "Decisive",
        "a real on-demand hash is a decisive match, not Possible"
    );
}

/// On-demand hashing distinguishes from the absent-fact WIDENING shortcut: when
/// the object file's real hash does NOT match the `sha256hash=` rule, the rule
/// must NOT match (fallthrough to allow).
///
/// Why this is the load-bearing #127 test: the CURRENT impl, with `sha256`
/// absent, sets `facts.sha256 = None`, so the `sha256hash=` object field WIDENS
/// (absent fact => Match) and rule 1 deny fires WRONGLY. A correct on-demand
/// hashing impl computes the file's real hash (`KNOWN_SHA256`), compares it to
/// the rule's DIFFERENT hash, gets `NoMatch`, and falls through to rule 2 allow.
///
/// Expected with #127: `decision=allow, matchedRule=2, verdict=Decisive`.
/// The wrong (widening) impl predicts `decision=deny, matchedRule=1` -> FAILS.
#[test]
fn filehash_on_demand_hash_mismatch_does_not_match() {
    let file_dir = tempfile::tempdir().expect("file tempdir");
    let obj_path = file_dir.path().join("real-object");
    write_known_file(&obj_path); // real hash == KNOWN_SHA256

    // The rule's hash is a DIFFERENT valid sha256 (all-zero-bytes empty-string
    // sha256), so the on-demand hash of the file must NOT match it.
    let other_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_ne!(
        other_sha256, KNOWN_SHA256,
        "rule hash must differ from file hash"
    );

    let rules =
        format!("deny_audit perm=any all : sha256hash={other_sha256}\nallow perm=any all : all\n");
    let (_rules_guard, rules_dir) = write_rules_dir(&rules);
    let workload = write_workload(&format!(
        r#"{{"exe":"/usr/bin/cat","path":"{}","perm":"open"}}"#,
        obj_path.display()
    ));

    let out = bin()
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("filehash_on_demand_hash_mismatch", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "allow",
        "on-demand hash differs from the rule's sha256hash= -> rule 1 does NOT match -> allow"
    );
    assert_eq!(
        result["matchedRule"], 2,
        "the decisive rule is rule 2 (allow fallthrough rule)"
    );
}
