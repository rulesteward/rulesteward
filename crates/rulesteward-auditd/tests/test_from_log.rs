//! RED barrier tests for the `--from-log` reader module (#91).
//!
//! # Grounding
//! - Read-only line scan of `audit.log`; aggregate by `key=` field: f3 section 5.3c.
//! - `key=` appears in SYSCALL records as `key="value"` or `key=(null)`.
//! - Count distinct audit event serials per key (one SYSCALL per serial = one event).
//! - Oracle: `rocky8-live-from-log-execve/oracle/from-log-counts.json`:
//!   `wc_s4_execve_short -> 106` unique serials.
//! - Fixture: `tests/fixtures/logs/from_log_execve_keyed.log` (106 key-tagged lines).
//! - Fixture: `tests/fixtures/logs/synthetic_minimal.log` (8 lines, known counts).

use std::path::Path;

use rulesteward_auditd::from_log::count_events_by_key;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

// --------------------------------------------------------------------------
// Synthetic minimal log (deterministic, known counts)
// --------------------------------------------------------------------------

/// Synthetic log: 3 events with `key="test_execve"`, 2 with `key="test_watch"`,
/// 1 with `key=(null)`. Total distinct events: 6 (but 3 are non-SYSCALL lines).
///
/// The reader must count by UNIQUE SERIAL from SYSCALL records:
/// - `test_execve`: serials 1001, 1002, 1003 -> 3 events.
/// - `test_watch`: serials 1004, 1005 -> 2 events.
/// - None (`key=(null)`): serial 1006 -> 1 event.
///
/// Grounded: f3 section 5.3c -- count events by `key=` to measure per-key rates.
#[test]
fn synthetic_log_counts_correct() {
    let path = fixture_path("logs/synthetic_minimal.log");
    let rates = count_events_by_key(&path).expect("synthetic log must be readable");

    assert_eq!(
        rates
            .counts
            .get(&Some("test_execve".to_string()))
            .copied()
            .unwrap_or(0),
        3,
        "test_execve must have 3 events (serials 1001/1002/1003)"
    );
    assert_eq!(
        rates
            .counts
            .get(&Some("test_watch".to_string()))
            .copied()
            .unwrap_or(0),
        2,
        "test_watch must have 2 events (serials 1004/1005)"
    );
    // key=(null) maps to None in our map.
    let no_key = rates.counts.get(&None).copied().unwrap_or(0);
    assert_eq!(
        no_key, 1,
        "key=(null) events must be counted under None; got {no_key}"
    );
}

/// Synthetic log: total `lines_scanned` is non-zero for a non-empty log.
/// (`lines_scanned` is for diagnostics, not the event count.)
#[test]
fn synthetic_log_lines_scanned_nonzero() {
    let path = fixture_path("logs/synthetic_minimal.log");
    let rates = count_events_by_key(&path).expect("synthetic log must be readable");
    assert!(
        rates.lines_scanned > 0,
        "lines_scanned must be > 0 for a non-empty log"
    );
}

// --------------------------------------------------------------------------
// Corpus oracle: from-log-execve (real VM-captured log slice)
// --------------------------------------------------------------------------

/// Oracle: `from_log_execve_keyed.log` contains exactly 106 events with
/// `key="wc_s4_execve_short"`.
///
/// This is the primary per-key event count from the Wave-1b corpus
/// (rocky8-live-from-log-execve/oracle/from-log-counts.json).
/// The file was captured on Rocky 8 from 100x `/bin/true` invocations
/// (the for-loop also spawns seq etc., giving 106 total, not 100).
///
/// ADVERSARIAL property: a wrong impl that counts ALL lines (not unique serials)
/// would report the same number here because each keyed line has a distinct serial.
/// But on a log with duplicate serials (from PATH/CWD records sharing a serial),
/// it would overcount. The synthetic test above covers that trap.
#[test]
fn corpus_from_log_execve_counts_106() {
    let path = fixture_path("logs/from_log_execve_keyed.log");
    let rates = count_events_by_key(&path).expect("execve keyed log must be readable");

    let count = rates
        .counts
        .get(&Some("wc_s4_execve_short".to_string()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        count, 106,
        "must count exactly 106 events for key wc_s4_execve_short \
         (corpus oracle rocky8-live-from-log-execve/oracle/from-log-counts.json)"
    );
}

// --------------------------------------------------------------------------
// Error handling
// --------------------------------------------------------------------------

/// A non-existent file must return `Err(LogReadError)`.
/// (Not a panic, not Ok with zero counts.)
#[test]
fn nonexistent_file_returns_err() {
    let path = Path::new("/tmp/this_file_absolutely_does_not_exist_rulesteward_test.log");
    let result = count_events_by_key(path);
    assert!(
        result.is_err(),
        "reading a non-existent file must return Err, not Ok"
    );
}

// --------------------------------------------------------------------------
// Empty and no-key-event logs
// --------------------------------------------------------------------------

/// A log with no SYSCALL records (empty) returns an empty count map.
#[test]
fn empty_log_returns_empty_counts() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().expect("tmp file");
    writeln!(tmpfile, "# no audit records here").unwrap();
    let path = tmpfile.path().to_path_buf();
    let rates = count_events_by_key(&path).expect("empty-ish log must parse");
    // Might have one line_scanned but no SYSCALL entries.
    assert!(
        rates.counts.is_empty() || rates.counts.values().all(|&v| v == 0),
        "no SYSCALL records should yield empty or all-zero counts"
    );
}
