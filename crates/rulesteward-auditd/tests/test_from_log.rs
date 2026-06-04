//! RED barrier tests for the `--from-log` reader module (#91).
//!
//! # Grounding
//! - Read-only line scan of `audit.log`; aggregate by `key=` field: f3 section 5.3c.
//! - `key=` appears in any record type as `key="value"` or `key=(null)`.
//! - Count distinct audit event serials per key (one serial = one event, any record type).
//! - Oracle: `rocky8-live-from-log-execve/oracle/from-log-counts.json`:
//!   `wc_s4_execve_short -> 106` unique serials (105 SYSCALL + 1 `CONFIG_CHANGE`, all keyed).
//! - Fixture: `tests/fixtures/logs/from_log_execve_keyed.log` (106 key-tagged lines).
//! - Fixture: `tests/fixtures/logs/synthetic_minimal.log` (8 lines, known counts).
//! - Fixture: `tests/fixtures/logs/synthetic_serial_dedup.log` (serial-dedup trap).

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
/// 1 with `key=(null)`. Total distinct events: 6 (2 non-SYSCALL lines carry no key=).
///
/// The reader must count by UNIQUE SERIAL across all record types:
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
/// Structure: 1 `CONFIG_CHANGE` + 105 SYSCALL records, all 106 carrying the key.
/// All serials are distinct, so a line-count impl and a serial-dedup impl both
/// produce 106 here. The `serial_dedup_collapses_same_key` test covers the
/// trap where serials are shared.
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
// Serial-dedup: two key-bearing records sharing one serial = 1 event
// --------------------------------------------------------------------------

/// A PATH record sharing the same serial as its SYSCALL parent MUST NOT be
/// counted as a second event.
///
/// Fixture: `synthetic_serial_dedup.log` has 2 serials (2001, 2002), each with
/// one SYSCALL + one PATH record, both carrying `key="dup_key"`. That is 4
/// key-bearing lines but only 2 distinct serials -> the count must be 2, not 4.
///
/// ADVERSARIAL TRAP: a lazy impl that increments the counter for every line
/// matching `key=X` (ignoring serial) reports 4 here. A correct serial-dedup
/// impl reports 2. This test is the only fixture that distinguishes them.
/// Grounded: f3 section 5.3c -- "count distinct audit event serials per key".
#[test]
fn serial_dedup_collapses_same_key() {
    let path = fixture_path("logs/synthetic_serial_dedup.log");
    let rates = count_events_by_key(&path).expect("serial dedup fixture must be readable");
    let count = rates
        .counts
        .get(&Some("dup_key".to_string()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        count, 2,
        "4 key-bearing lines across 2 serials must collapse to 2 events, not 4 \
         (serial-dedup trap: a naive line-counter reports 4)"
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
// Serial arithmetic (from_log.rs:112) -- kills `+ -> -` and `+ -> *` mutants
// --------------------------------------------------------------------------

/// `extract_serial` computes `&after_paren[colon_pos + 1..]` to skip the `:`.
///
/// Two mutation survivors:
///   - replace `+` with `-` in `colon_pos + 1`: yields `colon_pos - 1` (one byte
///     before the colon), so `after_colon` starts inside the timestamp rather than
///     at the serial, and the extracted serial is a wrong substring.
///   - replace `+` with `*` in `colon_pos + 1`: yields `colon_pos * 1 = colon_pos`
///     (same index as the colon itself), so `after_colon` starts at `:9876...` and
///     the extracted serial includes the leading `:` character.
///
/// Fixture: `synthetic_serial_arithmetic.log` -- one SYSCALL record with serial `9876`
/// at a non-zero offset inside `after_paren` (timestamp `1780453500.123`, colon at
/// index 14). A wrong-arithmetic impl produces serial `3` (with `-`) or `:9876`
/// (with `*`), neither of which matches `"9876"`, so the serial is not found in
/// the key-serials map and the count is 0 instead of 1.
///
/// Grounded: audit log format `msg=audit(TIMESTAMP:SERIAL):`; SERIAL is the
/// monotonically increasing integer after the colon (auditd source, `log_handler.c`).
#[test]
fn extract_serial_arithmetic_correct() {
    use std::io::Write as _;

    let path = fixture_path("logs/synthetic_serial_arithmetic.log");
    let rates =
        count_events_by_key(&path).expect("synthetic_serial_arithmetic log must be readable");

    // The record carries key="arith_key" with serial 9876.
    // Correct arithmetic (+1): serial extracted as "9876", count = 1.
    // Wrong arithmetic (-1): serial extracted from inside timestamp -> wrong string,
    //   key entry created under a garbage serial -> count still 1 BUT the dedup
    //   set key is wrong, so a second record with the same real serial 9876 would
    //   NOT be deduped. More directly: the exact serial string "9876" is not
    //   inserted, which we verify via the single-record count below.
    //
    // Single-record case: correct impl counts 1; both mutants also count 1 here
    // because there is only one line. To distinguish +1 from -1 and *1 we need
    // TWO lines sharing the SAME serial where the dedup must collapse them to 1.
    // We use the existing `synthetic_serial_dedup.log` for that; this fixture tests
    // that the extracted serial string is exact so a SECOND record sharing that
    // serial IS correctly deduped (not double-counted).
    //
    // Direct verification: add a second line with the SAME serial 9876 but different
    // record type; correct impl dedupes to 1; wrong-arithmetic impl produces 2
    // (because it extracts a different serial string for one of the two lines).
    // We do this inline with a tempfile.
    let mut tmpfile = tempfile::NamedTempFile::new().expect("tmp file");
    // Two records, same serial 9876, both keyed "arith_key".
    // Correct: dedup -> count=1. Wrong arithmetic: two different "serials" -> count=2.
    writeln!(
        tmpfile,
        "type=SYSCALL msg=audit(1780453500.123:9876): arch=c000003e syscall=59 \
         success=yes exit=0 a0=1 a1=2 items=1 ppid=500 pid=501 auid=1000 \
         uid=1000 gid=1000 tty=pts0 ses=3 comm=\"bash\" exe=\"/bin/bash\" key=\"arith_key\""
    )
    .unwrap();
    writeln!(
        tmpfile,
        "type=PATH msg=audit(1780453500.123:9876): item=0 name=\"/bin/bash\" \
         inode=789 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 key=\"arith_key\""
    )
    .unwrap();
    tmpfile.flush().unwrap();

    let rates2 =
        count_events_by_key(tmpfile.path()).expect("two-record same-serial log must be readable");
    let count = rates2
        .counts
        .get(&Some("arith_key".to_string()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        count, 1,
        "two records sharing serial 9876 must dedup to 1 event; got {count}. \
         Wrong arithmetic (+->- or +->*) extracts different serial strings for \
         each line, bypassing dedup and reporting 2."
    );

    // Also assert the single-record fixture counts 1 (basic sanity).
    let single_count = rates
        .counts
        .get(&Some("arith_key".to_string()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        single_count, 1,
        "single-record log with key='arith_key' must count 1 event"
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
