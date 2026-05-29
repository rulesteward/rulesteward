//! Layer-1 insta snapshot tests for the `rulesteward-sink` crate.
//!
//! Two snapshots are taken using FIXED, deterministic `Event` values so that
//! the snapshot files are stable across runs:
//!
//! 1. `single_event_json` - pins the exact `serde_json::to_string` output of one
//!    event: field names, field order, quoting.
//! 2. `two_event_ndjson_file` - writes two events through `NdjsonFileSink` to a
//!    tempfile, reads the file back, and snapshots the exact bytes: one JSON object
//!    per line + a trailing newline.
//!
//! Snapshots land in `tests/snapshots/` with `set_prepend_module_to_snapshot(false)`
//! so the file name is exactly the snapshot name.

use std::path::PathBuf;

use rulesteward_sink::{Event, EventSink, NdjsonFileSink};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Fixed event used across both snapshot tests - deterministic, no randomness.
fn fixed_event() -> Event {
    Event::new(
        42,
        "deny",
        "application/x-executable",
        "/usr/bin/ssh",
        "/tmp/scan",
        "2026-05-28T00:00:00Z",
    )
}

/// Second fixed event for the two-event stream test.
fn fixed_event_2() -> Event {
    Event::new(
        7,
        "allow",
        "text/plain",
        "/bin/sh",
        "/etc/passwd",
        "2026-05-28T01:00:00Z",
    )
}

/// Snapshot 1: the exact JSON serialization of a single `Event`.
/// Pins field names + order. A `#[serde(rename)]` on any field, or a change
/// in `serde_json`'s field ordering, will diff this snapshot.
#[test]
fn single_event_json() {
    let ev = fixed_event();
    let rendered = serde_json::to_string(&ev).expect("serde_json::to_string must succeed");

    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        insta::assert_snapshot!("single_event_json", rendered);
    });
}

/// Snapshot 2: exact file contents of a two-event NDJSON stream written via
/// `NdjsonFileSink`. Pins one-object-per-line + trailing newline contract.
#[test]
fn two_event_ndjson_file() {
    let tmp = tempfile::tempdir().expect("tempdir creation must succeed");
    let path = tmp.path().join("events.jsonl");

    let sink = NdjsonFileSink::create(&path).expect("NdjsonFileSink::create must succeed");
    sink.emit(&fixed_event())
        .expect("emit event 1 must succeed");
    sink.emit(&fixed_event_2())
        .expect("emit event 2 must succeed");
    sink.flush().expect("flush must succeed");
    drop(sink);

    let rendered = std::fs::read_to_string(&path).expect("read events file must succeed");

    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        insta::assert_snapshot!("two_event_ndjson_file", rendered);
    });
}
