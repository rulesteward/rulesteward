//! Empirical NO_LOCK reader-vs-writer contention harness for the fapolicyd
//! trust DB (#291), now also the regression gate for the fix (#317).
// This module doc references shell commands (--test, sha256sum) and bare
// identifiers (NO_LOCK, DIGEST_A) intentionally; backticking each one hurts
// readability of the command snippets. Matches the convention in the other
// trustdb integration tests (e2e_trustdb.rs, explain_*.rs).
#![allow(clippy::doc_markdown)]
//!
//! BACKGROUND. The original `open_trustdb_readonly` opened the LMDB env with
//! `READ_ONLY | NO_LOCK`. A `NO_LOCK` reader takes no reader-table slot, so the
//! single LMDB writer (the fapolicyd daemon, or `fapolicyd-cli --file update`)
//! can free and reuse the pages the reader is iterating mid-read -- a torn read.
//! This harness reproduced that EMPIRICALLY (5/8 runs returned a silently
//! corrupt `Ok`), which is now tracked + fixed as #317.
//!
//! WHAT THIS HARNESS GATES: the LAYER-1 PREVENTION path. `open_trustdb_readonly`
//! now opens `READ_ONLY` WITH the lock table on a writable dir, taking a real
//! reader slot, so the torn read CANNOT happen. The single test below drives a
//! live subprocess writer against the production `open_trustdb_readonly` default
//! path and asserts NO torn read (and no silently corrupt `Ok`).
//!
//! The LAYER-2 DETECTION floor (`parse_trust_value` / key validation converting
//! a torn record into a clean `TrustDbError`) is covered DETERMINISTICALLY and
//! WITHOUT a live writer by the inline unit tests in `trustdb.rs`
//! (`nolock_*_is_clean_torn_read`). A live-writer NO_LOCK contention test is
//! deliberately ABSENT (see the note at the bottom of this file): such a reader
//! can SIGABRT inside LMDB's C cursor code, which is un-gateable.
//!
//! THE CHARACTERIZATION INVARIANT (a STABLE gate, NOT "a torn read can never
//! happen"): every read returns EITHER entries whose `(path, digest)` the writer
//! ACTUALLY wrote (we track the exact set of values the writer puts) OR a clean
//! `TrustDbError` -- and NEVER a panic, and NEVER a value the writer never wrote
//! surfacing as a "valid" `Ok` entry.
//!
//! DETERMINISTIC RED. LMDB is single-writer and heed's `Env` is `!Send`, so the
//! writer is a SEPARATE OS PROCESS (this test binary RE-EXEC'd in a writer mode
//! gated by `RS_TRUSTDB_CONTENTION_WRITER_DIR`) that opens its OWN read-write
//! `Env` on the same directory. The writer alternates each key between TWO
//! KNOWN, SAME-LENGTH (64-hex) digests, so even a one-page splice that stays
//! shape-valid (64 lowercase-hex chars) yields a digest matching NEITHER written
//! value -- which the `(path, digest) in written_set` check reliably catches at
//! the VALUE level. Pre-fix this harness fails (a torn `Ok` whose digest is not
//! in the written set, or a panic); post-fix it passes clean on both paths.
//!
//! The harness is `#[ignore]`d AND gated behind `required-features =
//! ["test-fixtures"]` (this crate's Cargo.toml `[[test]]` entry), so the default
//! `cargo test` / coverage run never compiles or executes it. It runs only via
//! its dedicated `just trustdb-contention` recipe / isolated CI job:
//!   cargo test -p rulesteward-fapolicyd --features test-fixtures \
//!       --test trustdb_contention -- --ignored --test-threads=1

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use rulesteward_fapolicyd::trustdb::{
    TrustDb, TrustEntry, TrustSource, open_trustdb_readonly, write_trustdb_fixture_kv,
};

/// Env var that routes a re-exec'd process into writer mode (value = DB dir).
const WRITER_DIR_ENV: &str = "RS_TRUSTDB_CONTENTION_WRITER_DIR";

/// Env var overriding the writer's maximum wall-time (in whole seconds). The
/// writer exits when this duration elapses, regardless of the sentinel file.
/// Default (30 s) is generous: the healthy contention window is a few seconds,
/// so the cap only fires for an orphaned writer whose parent died abnormally.
const WRITER_MAX_SECS_ENV: &str = "RS_TRUSTDB_CONTENTION_WRITER_MAX_SECS";

/// Default maximum wall-time for the writer subprocess (30 seconds).
const WRITER_MAX_SECS_DEFAULT: u64 = 30;

/// Number of read iterations the parent performs per run. Bounded so the test is
/// deterministic and never flaky-by-timeout.
const READ_ITERATIONS: usize = 4000;

/// The four accepted lowercase-hex digest lengths (MD5/SHA1/SHA256/SHA512).
const ACCEPTED_DIGEST_LENS: [usize; 4] = [32, 40, 64, 128];

/// Number of distinct keys the writer churns. Small enough that put+delete
/// batches commit fast (maximizing free/reuse cycles), large enough that an
/// iteration touches many pages.
const CHURN_KEYS: usize = 64;

/// TWO distinct, real, same-length (64-hex) SHA-256 digests. The writer
/// alternates a key between value A (`DIGEST_A`) and value B (`DIGEST_B`). A
/// torn splice between them (or with the seed) yields a 64-hex string matching
/// NEITHER, caught by the written-set assertion at the value level. Both are
/// genuine sha256sums:
///   printf 'hello trustdb\n'   | sha256sum -> DIGEST_A
///   printf 'goodbye trustdb\n' | sha256sum -> DIGEST_B
const DIGEST_A: &str = "3ea762cdbe2e0e8bd475edcfbe4ef960df0389bab22131b18ca9d9ccf08ccc27";
const DIGEST_B: &str = "84c9417b87d1c4b64102c52ba7c93f89ace4ef537fa9076ddc02c5379d7131af";

/// A trust-DB key for index `i`.
fn key_for(i: usize) -> String {
    format!("/usr/bin/contend-{i:04}")
}

/// Build the canonical fapolicyd value bytes `"<src_int> <size> <digest_hex>"`.
fn value_bytes(src_int: u32, size: u64, digest: &str) -> Vec<u8> {
    format!("{src_int} {size} {digest}").into_bytes()
}

/// The set of legitimate `(key -> {digest})` the writer + seed ever associate.
/// The reader checks every `Ok` entry's `(path, digest)` against it: an entry
/// the writer never wrote (a torn read) fails the check.
struct WrittenSet {
    by_key: HashMap<String, HashSet<String>>,
}

impl WrittenSet {
    fn build() -> Self {
        let mut by_key: HashMap<String, HashSet<String>> = HashMap::new();
        for i in 0..CHURN_KEYS {
            // The writer alternates A/B and the seed uses A/B, so the only
            // legitimate digests for any key are exactly {A, B}.
            let digs = HashSet::from([DIGEST_A.to_owned(), DIGEST_B.to_owned()]);
            by_key.insert(key_for(i), digs);
        }
        Self { by_key }
    }

    /// True iff `entry`'s (path, digest) is one the writer/seed actually wrote.
    fn contains(&self, entry: &TrustEntry) -> bool {
        self.by_key
            .get(&entry.path)
            .is_some_and(|digs| digs.contains(&entry.digest))
    }
}

/// Open a read-write heed `Env` on `dir` and churn the trust DB: each round,
/// put a fresh batch (every key set to value A or value B by round parity),
/// commit, delete the batch, commit. Each commit frees the prior batch's pages
/// and the next put reuses them -- the free/reuse a live fapolicyd writer
/// produces and the torn-read surface #291 targets. Loops until the parent
/// removes the sentinel file OR the wall-time cap elapses (whichever comes
/// first). The wall-time cap prevents an orphaned writer from looping forever
/// when the parent dies abnormally and the sentinel is never removed (#320).
///
/// Runs in the RE-EXEC'd child (its own `Env`). Opens RW WITHOUT `NO_LOCK`
/// (taking the writer lock + creating `lock.mdb`), matching the real daemon.
fn run_writer_mode(dir: &Path, sentinel: &Path) {
    let max_secs = std::env::var(WRITER_MAX_SECS_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(WRITER_MAX_SECS_DEFAULT);
    let deadline = Instant::now() + Duration::from_secs(max_secs);

    // SAFETY: opens a tempdir LMDB env RW to churn a test fixture. The only
    // other accessor is the parent process. The mmap aliasing contract heed
    // flags `unsafe` is exactly the scenario under test. unsafe_code is `deny`
    // (not forbid) workspace-wide for this audited heed boundary.
    #[allow(unsafe_code)]
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(2)
            .map_size(64 * 1024 * 1024)
            .open(dir)
            .expect("writer: open RW env")
    };

    let mut wtxn = env.write_txn().expect("writer: write_txn");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .database_options()
        .types::<heed::types::Bytes, heed::types::Bytes>()
        .flags(heed::DatabaseFlags::DUP_SORT)
        .name("trust.db")
        .create(&mut wtxn)
        .expect("writer: create trust.db");
    wtxn.commit().expect("writer: initial commit");

    let mut round: u64 = 0;
    while sentinel.exists() && Instant::now() < deadline {
        round = round.wrapping_add(1);
        // Alternate every key between value A and value B by round parity. Both
        // values are legitimate (their digests are in the written set); the
        // alternation is what makes a torn SPLICE between them detectable.
        let (digest, src) = if round.is_multiple_of(2) {
            (DIGEST_A, 1u32)
        } else {
            (DIGEST_B, 2u32)
        };

        let mut wtxn = env.write_txn().expect("writer: put txn");
        for i in 0..CHURN_KEYS {
            let key = key_for(i);
            let v = value_bytes(src, round.wrapping_mul(1000) + i as u64, digest);
            db.put(&mut wtxn, key.as_bytes(), &v).expect("writer: put");
        }
        wtxn.commit().expect("writer: put commit");

        let mut wtxn = env.write_txn().expect("writer: delete txn");
        for i in 0..CHURN_KEYS {
            let key = key_for(i);
            db.delete(&mut wtxn, key.as_bytes())
                .expect("writer: delete");
        }
        wtxn.commit().expect("writer: delete commit");
    }
    // env dropped here -> writer lock released, file flushed.
}

/// Assert the characterization invariant on one read result. A read is allowed
/// to be EITHER a `Vec<TrustEntry>` whose every entry has a sane shape AND a
/// `(path, digest)` the writer ACTUALLY wrote, OR a clean `TrustDbError`. It must
/// NEVER panic and NEVER surface an entry the writer never wrote as valid.
fn assert_read_invariant(
    result: &Result<Vec<TrustEntry>, rulesteward_fapolicyd::trustdb::TrustDbError>,
    written: &WrittenSet,
    what: &str,
) {
    match result {
        Ok(entries) => {
            for e in entries {
                // Shape floor.
                let source_ok = matches!(
                    e.source,
                    TrustSource::FileDb
                        | TrustSource::RpmDb
                        | TrustSource::Deb
                        | TrustSource::Unknown
                );
                assert!(source_ok, "{what}: invalid TrustSource: {e:?}");
                assert!(
                    ACCEPTED_DIGEST_LENS.contains(&e.digest.len()),
                    "{what}: digest length {} not in {ACCEPTED_DIGEST_LENS:?}: {e:?}",
                    e.digest.len(),
                );
                assert!(
                    e.digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "{what}: digest is not lowercase hex: {e:?}",
                );
                // VALUE floor: the (path, digest) must be one the writer/seed
                // actually wrote. A torn read producing a shape-valid digest the
                // writer never wrote is caught HERE.
                assert!(
                    written.contains(e),
                    "{what}: TORN READ -- entry (path,digest) was never written by the writer: {e:?}",
                );
            }
        }
        Err(_clean_error) => {
            // A typed TrustDbError (TornRead / MalformedValue / Open / Missing)
            // is the OTHER acceptable outcome. Reaching this arm means the
            // reader degraded gracefully instead of panicking or returning a
            // silently corrupt Ok.
        }
    }
}

/// Run one read iteration against an already-open `TrustDb`: hammer
/// `iter_entries`, a keyed `get_entry`, and `contains_path`, asserting the
/// invariant on each. Returns whether `iter_entries` was `Ok`.
fn one_read(db: &TrustDb, written: &WrittenSet, iter: usize) -> bool {
    let iter_result = db.iter_entries();
    let ok = iter_result.is_ok();
    assert_read_invariant(&iter_result, written, &format!("iter_entries iter#{iter}"));

    let key = key_for(iter % CHURN_KEYS);
    match db.get_entry(&key) {
        Ok(Some(rows)) => {
            assert_read_invariant(&Ok(rows), written, &format!("get_entry iter#{iter}"));
        }
        Ok(None) => { /* key may be mid-delete; absence is fine */ }
        Err(_clean) => { /* typed error is fine, not a panic */ }
    }
    // contains_path must never panic regardless of contention.
    let _ = db.contains_path(&key);
    ok
}

/// Seed the DUPSORT trust DB via the test-fixtures helper so the initial shape
/// matches the production reader's expectations. The seed uses BOTH legitimate
/// digests (A and B) per key, so the written set is exactly {A, B}.
fn seed_db(db_dir: &Path) {
    let seed_a = value_bytes(1, 111, DIGEST_A);
    let seed_b = value_bytes(2, 222, DIGEST_B);
    let mut seed_rows: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..CHURN_KEYS {
        seed_rows.push((key_for(i), seed_a.clone()));
        seed_rows.push((key_for(i), seed_b.clone()));
    }
    let seed_refs: Vec<(&str, &[u8])> = seed_rows
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    write_trustdb_fixture_kv(db_dir, &seed_refs);
}

/// Spawn the writer subprocess (this binary re-exec'd in writer mode) against
/// `db_dir`, arming the sentinel first. Returns the child handle; the caller
/// must remove the sentinel and `wait()` to reap it.
///
/// If `max_wall_secs` is `Some(n)`, sets `WRITER_MAX_SECS_ENV` on the child to
/// `n`; otherwise inherits the current environment (which may or may not have
/// the var set, falling back to the 30s default).
fn spawn_writer(db_dir: &Path, test_name: &str, max_wall_secs: Option<u64>) -> std::process::Child {
    let sentinel = db_dir.join("writer.run");
    std::fs::write(&sentinel, b"run").expect("arm sentinel");

    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--ignored")
        .arg("--exact")
        .arg(test_name)
        .arg("--test-threads=1")
        .env(WRITER_DIR_ENV, db_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(secs) = max_wall_secs {
        cmd.env(WRITER_MAX_SECS_ENV, secs.to_string());
    }
    let child = cmd.spawn().expect("spawn writer subprocess");

    // Bounded warmup so the reader window overlaps live writes (the writer
    // creates lock.mdb when it takes the write lock). Not a correctness
    // timeout: the reader loop is iteration-bounded regardless.
    let warmup_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < warmup_deadline {
        if db_dir.join("lock.mdb").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}

/// If THIS process was re-exec'd as the writer, do the writer work and return
/// `true` (the caller must then return immediately). Otherwise `false`.
fn maybe_run_as_writer() -> bool {
    if let Ok(dir) = std::env::var(WRITER_DIR_ENV) {
        let dir = std::path::PathBuf::from(dir);
        let sentinel = dir.join("writer.run");
        run_writer_mode(&dir, &sentinel);
        true
    } else {
        false
    }
}

/// Reap the writer and assert it exited cleanly (a writer-side panic under
/// contention is itself a finding).
fn reap_writer(db_dir: &Path, mut writer: std::process::Child) {
    let _ = std::fs::remove_file(db_dir.join("writer.run"));
    let status = writer.wait().expect("wait for writer subprocess");
    assert!(
        status.success(),
        "writer subprocess exited non-zero ({status:?}); a writer-side panic under contention is itself a finding"
    );
}

/// LAYER 1 (PREVENTION). The DEFAULT production reader `open_trustdb_readonly`
/// takes the lock-table path on a writable tempdir, so the torn read CANNOT
/// happen. Under a live concurrent writer, every read must be a clean entry
/// (whose (path,digest) the writer wrote) or a clean error -- never a torn read
/// or a silently corrupt `Ok`.
#[test]
#[ignore = "NO_LOCK contention harness (#291/#317): isolated CI job only; run via `just trustdb-contention`"]
fn trustdb_prevention_path_has_no_torn_reads() {
    if maybe_run_as_writer() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_dir = tmp.path();
    seed_db(db_dir);
    let written = WrittenSet::build();
    let writer = spawn_writer(db_dir, "trustdb_prevention_path_has_no_torn_reads", None);

    let mut reads_ok = 0usize;
    let mut reads_err = 0usize;
    for iter in 0..READ_ITERATIONS {
        // open_trustdb_readonly is the exact #291 path; on a writable dir it
        // takes the Layer-1 locked branch. A bounded open error under heavy
        // writer churn is acceptable (a typed error, not a panic).
        match open_trustdb_readonly(db_dir) {
            Ok(db) => {
                if one_read(&db, &written, iter) {
                    reads_ok += 1;
                } else {
                    reads_err += 1;
                }
            }
            Err(_clean_open_error) => reads_err += 1,
        }
    }

    reap_writer(db_dir, writer);

    assert_eq!(
        reads_ok + reads_err,
        READ_ITERATIONS,
        "every read iteration must be accounted for (ok={reads_ok}, err={reads_err})"
    );
    assert!(
        reads_ok > 0,
        "expected at least one successful read (ok={reads_ok}, err={reads_err}); harness may not be exercising the reader"
    );
    eprintln!(
        "trustdb PREVENTION harness: {READ_ITERATIONS} iterations \
         ({reads_ok} ok, {reads_err} clean-error) against a live writer; \
         no torn read, no panic, no silently-corrupt Ok."
    );
}

/// WALL-TIME BOUND (#320). If the parent dies without removing the sentinel, the
/// writer must exit on its own within the `WRITER_MAX_SECS_ENV` cap. This test
/// arms the sentinel, spawns the writer with a 2-second cap, does NOT remove the
/// sentinel, and asserts the child exits on its own within 10 seconds.
///
/// On unpatched code (no wall-time bound) the writer loops forever, and this
/// test would hang until the 10-second poll budget is exhausted, then fail.
#[test]
#[ignore = "wall-time-bound orphan test (#320): isolated CI job only; run via `just trustdb-contention`"]
fn trustdb_writer_exits_on_wall_time_bound_without_sentinel_removal() {
    if maybe_run_as_writer() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_dir = tmp.path();
    seed_db(db_dir);

    // Spawn the writer with a short 2-second cap. Do NOT remove the sentinel:
    // the writer must exit via the wall-time bound, not via sentinel removal.
    let mut writer = spawn_writer(
        db_dir,
        "trustdb_writer_exits_on_wall_time_bound_without_sentinel_removal",
        Some(2),
    );

    // Poll for up to 10 seconds. The writer should exit within ~2 seconds (cap)
    // plus build/startup overhead. 10 seconds is a 5x safety margin.
    let poll_deadline = Instant::now() + Duration::from_secs(10);
    let exited = loop {
        if writer.try_wait().expect("try_wait").is_some() {
            break true;
        }
        if Instant::now() >= poll_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // Sentinel is still present; remove it and reap the child either way to
    // avoid leaving a zombie or a leaked subprocess behind.
    let _ = std::fs::remove_file(db_dir.join("writer.run"));
    if !exited {
        let _ = writer.kill();
    }
    let _ = writer.wait();

    assert!(
        exited,
        "writer did not exit within 10 s despite a 2-second wall-time cap (#320 regression)"
    );
}

/// WALL-TIME BOUND via the PRODUCTION (`None`) spawn path (#320). The prevention
/// harness spawns the writer with `None` (no explicit cap), so the child must be
/// bounded by the DEFAULT path -- `run_writer_mode`'s
/// `unwrap_or(WRITER_MAX_SECS_DEFAULT)`. The existing wall-time test uses the
/// explicit `Some(2)` branch (spawn_writer sets the env directly), so it never
/// exercises the `None`/default path that actually defends the real harness.
///
/// This test drives the EXACT production spawn (`None`) but injects a small cap
/// through the INHERITED environment (which the `None` path falls back to), so a
/// regression that left the `None` path unbounded reintroduces the #320 leak and
/// fails here -- proven in seconds, not the 30 s default.
#[test]
#[ignore = "wall-time-bound orphan test (#320): isolated CI job only; run via `just trustdb-contention`"]
fn trustdb_writer_none_spawn_path_is_bounded_by_inherited_cap() {
    if maybe_run_as_writer() {
        return;
    }

    // The default cap must itself be a SMALL bound (the production None path
    // falls back to it via unwrap_or); guard against an accidental huge value.
    assert!(
        (1..=60).contains(&WRITER_MAX_SECS_DEFAULT),
        "WRITER_MAX_SECS_DEFAULT must be a small bound, got {WRITER_MAX_SECS_DEFAULT}"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_dir = tmp.path();
    seed_db(db_dir);

    // spawn_writer(.., None) does NOT set the cap env on the child, so the child
    // relies on the inherited env / default. Inject a small cap via the inherited
    // environment so the None path self-terminates in seconds. SAFETY: the
    // contention tests run with --test-threads=1, so this single-threaded env
    // mutation has no concurrent reader; the child inherits the value at spawn and
    // we clear it immediately afterward.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var(WRITER_MAX_SECS_ENV, "2");
    }
    let mut writer = spawn_writer(
        db_dir,
        "trustdb_writer_none_spawn_path_is_bounded_by_inherited_cap",
        None,
    );
    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var(WRITER_MAX_SECS_ENV);
    }

    // Poll up to 10 s; do NOT remove the sentinel -- exit must come from the cap.
    let poll_deadline = Instant::now() + Duration::from_secs(10);
    let exited = loop {
        if writer.try_wait().expect("try_wait").is_some() {
            break true;
        }
        if Instant::now() >= poll_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let _ = std::fs::remove_file(db_dir.join("writer.run"));
    if !exited {
        let _ = writer.kill();
    }
    let _ = writer.wait();

    assert!(
        exited,
        "writer spawned via the production None path did not self-terminate within 10s \
         despite an inherited 2-second cap; the None/default path must be bounded (#320)"
    );
}

// NOTE: a live-writer NO_LOCK contention test was deliberately NOT added here.
// Empirically (this harness, #291/#317) a `NO_LOCK` reader racing a live writer
// does not merely return a corrupt value - it can corrupt LMDB's own B-tree
// cursor traversal and ABORT THE PROCESS via an internal C assertion
// (`IS_BRANCH(...) failed in mdb_cursor_sibling`, SIGABRT). A C-level abort is
// un-gateable (no Rust check can catch it) and a test that tolerates the harness
// process aborting proves nothing. The Layer-2 DETECTION floor is instead
// covered DETERMINISTICALLY and without a live writer by the inline unit tests
// in `trustdb.rs` (`nolock_*_is_clean_torn_read`), which feed a static
// torn-shaped DB to `open_trustdb_readonly_nolock` and assert a clean
// `TrustDbError`. Only the Layer-1 PREVENTION path above is safe under a live
// writer, which is exactly why NO_LOCK is fallback-only.
