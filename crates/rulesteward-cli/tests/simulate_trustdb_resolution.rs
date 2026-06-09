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
///   - Trust DB CONTAINS the subject exe path `/usr/bin/trusted-tool` (present => trusted).
///   - Ruleset: `deny_audit perm=any exe=untrusted : all` then `allow perm=any all : all`.
///   - Workload: `{exe: /usr/bin/trusted-tool, path: /etc/hostname, perm: open}`
///     -- NO `trust` field.
///
/// Expected with #127: the DB lookup resolves `subj_trust = Yes` (trusted), so the
/// `exe=untrusted` macro does NOT fire rule 1 (trusted subject != untrusted) -> falls
/// through to rule 2 -> `decision=allow, matchedRule=2, verdict=Decisive`.
///
/// Why a wrong impl fails: an impl that ignores `--trustdb` leaves
/// `subj_trust = Unknown`; the `exe=untrusted` macro is then `NotEvaluable` ->
/// rule 1 is a Possible -> fallthrough to rule 2 `allow` BUT `verdict=Possible`
/// (unevaluable rule above the match). The correct impl gives `verdict=Decisive`
/// because there is no unevaluable rule above the match (rule 1 was fully evaluated
/// and got `NoMatch`). Asserting `verdict=Decisive` distinguishes the two impls.
///
/// Pair with `trustdb_absent_subject_resolves_untrusted` which pins the absent=>No
/// direction: together they prove present=>trusted / absent=>untrusted.
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

    // Rule 1: deny untrusted subjects.  Rule 2: allow everything else.
    // A PRESENT (trusted) subject must NOT match exe=untrusted -> falls through to allow.
    let (_rules_guard, rules_dir) =
        write_rules_dir("deny_audit perm=any exe=untrusted : all\nallow perm=any all : all\n");
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
        result["decision"], "allow",
        "--trustdb must resolve subj_trust=Yes (trusted) so exe=untrusted does NOT fire; \
         the subject falls through to rule 2 allow"
    );
    assert_eq!(
        result["matchedRule"], 2,
        "the allow fallthrough rule is rule 2 (exe=untrusted did not match the trusted subject)"
    );
    assert_eq!(
        result["verdict"], "Decisive",
        "DB-resolved trust makes rule 1 a full NoMatch (not NotEvaluable), so rule 2 \
         is Decisive rather than Possible"
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

/// ABSENT object path widens the `sha256hash=` field (regression pin for the two
/// mutation survivors in `evaluate.rs:379` and `trustdb.rs:164`).
///
/// When the workload names an object `path` that does NOT exist on disk and OMITS
/// `sha256`, `sha256_file` returns `Ok(None)` (`NotFound` branch, `trustdb.rs:164`).
/// `evaluate_query` propagates that as `sha256 = None, sha256_unhashable = false`.
/// `evaluate.rs:382` then hits `None => Match` (the standard absent-fact-widening
/// path, rules.c:1572-1575 (fapolicyd 1.4.5)), so the `sha256hash=` object constraint WIDENS and rule
/// 1 (`allow`) fires.
///
/// The two mutation survivors both flip this to deny:
/// - `evaluate.rs:379` mutant (`facts.sha256_unhashable` -> `true`): the unhashable
///   guard fires even though `sha256_unhashable = false`, routing to `NoMatch`.
/// - `trustdb.rs:164` mutant (`NotFound` guard -> `false`): `NotFound` propagates as
///   `Err` => `sha256_unhashable = true`, same `NoMatch` outcome.
///
/// Either way the verdict flips to deny at rule 2, killing this test.
///
/// Grounding: absent-path widening is the standard absent-fact skip documented in
/// f1 grounding §1.4 ~line 173 (rules.c:1572-1575 (fapolicyd 1.4.5)). It is DISTINCT from the
/// present-but-unhashable `FILE_HASH` error-as-denial (rules.c:1606-1611 (fapolicyd 1.4.5)) pinned by
/// `filehash_present_but_unhashable_is_denied_not_widened` below.
///
/// This test PASSES against the current (correct) impl (regression pin); it does NOT
/// have a RED phase because the absent-path widening shipped as part of #127 and has
/// been correct since then - this test only closes the mutation gap.
#[test]
fn filehash_absent_object_path_widens_not_denied() {
    // Use a path that is guaranteed to not exist. Include a UUID-like suffix so
    // even a parallel test run cannot accidentally create it.
    let obj_path = std::path::PathBuf::from(format!(
        "/tmp/does-not-exist-rulesteward-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0xdead_beef, |d| d.subsec_nanos())
    ));
    // Confirm the path truly does not exist (smoke-guard; not a test assertion).
    assert!(
        !obj_path.exists(),
        "test setup error: {obj_path:?} exists; choose a different path"
    );

    // Same ruleset shape as the unhashable test: sha256hash= allow rule first, then
    // a deny_audit catch-all.  The all-zeros sha256 is a valid 64-hex string that
    // can never collide with `KNOWN_SHA256` or an empty-file hash.
    let all_zeros = "0000000000000000000000000000000000000000000000000000000000000000";
    let rules =
        format!("allow perm=open all : sha256hash={all_zeros}\ndeny_audit perm=any all : all\n");
    let (_rules_guard, rules_dir) = write_rules_dir(&rules);

    // Workload names the absent path and OMITS `sha256`.
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

    let json = parse_json("filehash_absent_object_path_widens_not_denied", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "allow",
        "absent object path: sha256_file returns Ok(None) (NotFound), sha256_unhashable \
         stays false, the sha256hash= field WIDENS (None => Match, rules.c:1572-1575 (fapolicyd 1.4.5)), \
         so rule 1 allow fires. Both mutant survivors flip this to deny."
    );
    assert_eq!(
        result["matchedRule"], 1,
        "rule 1 (allow sha256hash=) matches via absent-fact widening; rule 2 is never reached"
    );
    assert_eq!(
        result["verdict"], "Decisive",
        "no uncertainty above the match (sha256_unhashable=false means no NotEvaluable \
         guard fired); the widened match is Decisive"
    );
    assert_eq!(result["source"], "rule", "a rule fired, not a fallthrough");
}

/// `FILE_HASH` error-as-denial: the object file is PRESENT but UNHASHABLE (unreadable),
/// so a `sha256hash=` rule must NOT match -> the verdict falls through to the next
/// (deny) rule. This is DISTINCT from the absent-fact skip (object entirely absent).
///
/// Grounding (real fapolicyd): the `FILE_HASH` case returns 0 (= the constraint does
/// NOT match, deny/fall-through) when the object is present but its hash backend
/// yields nothing - `src/library/rules.c:1606-1611` (fapolicyd 1.4.5):
/// `if (!obj->o) { /* Treat errors as denial for file hash lookups */ if (type == FILE_HASH) return 0; break; }`.
/// This error-as-denial path is DISTINCT from the
/// object-NULL skip-widening at `rules.c:1572-1575` (fapolicyd 1.4.5). See f1 grounding §1.4 line ~173
/// and the canonical NFS oracle
/// `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/adversarial/filehash-missing-object-present-deny/`
/// (the canonical workload OMITS `sha256`, exercising the on-demand path; the repo
/// corpus fixture diverged by SUPPLYING one - restored to OMIT it in this pass).
///
/// Setup:
///   - A real file on disk made UNREADABLE via `chmod 000`, so `sha256_file`
///     returns `Err(PermissionDenied)` (present-but-unhashable), NOT `Ok(None)`
///     (absent). Mirrors `trustdb.rs::verify_entry_open_permission_denied_is_read_error`.
///   - Ruleset: `allow perm=open all : sha256hash=<all-zeros>` then
///     `deny_audit perm=any all : all` (matches the canonical oracle's `rules.d`).
///   - Workload: `{exe, path: <the unreadable file>, perm: open}` -- NO `sha256`.
///
/// Expected with the #127 fix: hashing the present file FAILS (EACCES); the
/// `sha256hash=` constraint must be treated as error-as-denial = `NoMatch`, so rule
/// 1 `allow` does NOT fire and the verdict is rule 2 `deny_audit` ->
/// `decision=deny, matchedRule=2`.
///
/// Why the CURRENT (buggy) impl fails this: `evaluate_query` collapses the hash
/// error into `None` (`sha256_file(...).ok().flatten()` at simulate.rs:427-432);
/// `evaluate()` then WIDENS the absent `sha256hash=` field to `Match`
/// (evaluate.rs:374-376), firing rule 1 `allow` -> the buggy impl predicts
/// `decision=allow, matchedRule=1` -> this `decision == "deny"` assertion FAILS.
/// The fix must distinguish present-but-unhashable (error -> `NoMatch` -> deny) from
/// object-absent (skip -> widen).
///
/// Skipped under root: `chmod 000` has no effect (DAC bypassed), so the file is
/// readable, hashing succeeds, and the path is never exercised (the all-zeros rule
/// would still `NoMatch` -> deny rule 2, but for the wrong reason - not the error
/// path). Probe by opening the file; if it succeeds we are root and skip.
#[test]
fn filehash_present_but_unhashable_is_denied_not_widened() {
    let file_dir = tempfile::tempdir().expect("file tempdir");
    let obj_path = file_dir.path().join("present-but-unhashable");
    write_known_file(&obj_path); // a real, present file

    // Remove all permissions so File::open returns PermissionDenied (EACCES).
    let status = std::process::Command::new("chmod")
        .args(["000", obj_path.to_str().expect("utf8 path")])
        .status()
        .expect("chmod");
    assert!(status.success(), "chmod 000 failed");

    // Skip under root: DAC checks are bypassed, so chmod 000 has no effect and the
    // present-but-unhashable error path cannot be observed. Restore + return.
    if std::fs::File::open(&obj_path).is_ok() {
        let _ = std::process::Command::new("chmod")
            .args(["644", obj_path.to_str().expect("utf8 path")])
            .status();
        return;
    }

    // Rule 1 allow gated on a sha256hash= (all-zeros, like the canonical oracle);
    // rule 2 deny_audit catch-all. Matches the canonical NFS `rules.d`.
    let all_zeros = "0000000000000000000000000000000000000000000000000000000000000000";
    let rules =
        format!("allow perm=open all : sha256hash={all_zeros}\ndeny_audit perm=any all : all\n");
    let (_rules_guard, rules_dir) = write_rules_dir(&rules);
    // Workload supplies the on-disk `path` (present-but-unreadable) and OMITS sha256.
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

    // Restore permissions so the tempdir can be cleaned up.
    let _ = std::process::Command::new("chmod")
        .args(["644", obj_path.to_str().expect("utf8 path")])
        .status();

    let json = parse_json("filehash_present_but_unhashable", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["decision"], "deny",
        "present-but-unhashable object: the sha256hash= rule must NOT match \
         (FILE_HASH error-as-denial, rules.c:1606-1611 (fapolicyd 1.4.5)), so rule 1 allow does not \
         fire and the verdict is rule 2 deny_audit. The buggy widening impl wrongly \
         allows at rule 1."
    );
    assert_eq!(
        result["matchedRule"], 2,
        "the decisive rule is rule 2 (deny_audit catch-all); rule 1 allow did not fire \
         because the present file's hash could not be computed"
    );
    assert_eq!(
        result["source"], "rule",
        "rule 2 is a decisive rule match, not a fallthrough"
    );
}
