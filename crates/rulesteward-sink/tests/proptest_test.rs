//! Layer-2 proptest property tests for the `rulesteward-sink` crate.
//!
//! Three properties are tested with 256 cases each:
//!
//! 1. **Round-trip**: `serde_json::from_str(serde_json::to_string(ev)) == ev`
//!    for arbitrary `Event` values.
//!
//! 2. **One-line-per-event**: for a `Vec<Event>` of length N (0..=20), writing
//!    all events through a single `NdjsonFileSink` and reading back produces
//!    exactly N newline-terminated lines, each deserializing to the corresponding
//!    input event in order.
//!
//! 3. **No interior newline**: `serde_json::to_string(ev)` never contains `\n`,
//!    even when field values contain newlines or other unusual characters. This is
//!    the structural guarantee that NDJSON integrity holds for arbitrary inputs.

use proptest::prelude::*;
use rulesteward_sink::{Event, EventSink, NdjsonFileSink};

/// Strategy that generates an arbitrary `Event` with arbitrary string fields.
/// Strings may contain quotes, newlines, unicode, control characters - the
/// no-interior-newline property specifically needs such inputs to be exercised.
fn arb_event() -> impl Strategy<Value = Event> {
    (
        any::<u32>(),
        any::<String>(),
        any::<String>(),
        any::<String>(),
        any::<String>(),
        any::<String>(),
    )
        .prop_map(|(rule_id, decision, ftype, exe, path, timestamp)| {
            Event::new(rule_id, decision, ftype, exe, path, timestamp)
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..Default::default()
    })]

    /// Property 1: round-trip through JSON preserves all fields exactly.
    ///
    /// serde_json serializes then deserializes every arbitrary `Event` back to
    /// the same value. Catches any field that is silently dropped, renamed, or
    /// type-coerced during the serde round-trip.
    #[test]
    fn round_trip_json(ev in arb_event()) {
        let json = serde_json::to_string(&ev).expect("serde_json::to_string must succeed");
        let back: Event = serde_json::from_str(&json).expect("serde_json::from_str must succeed");
        prop_assert_eq!(ev, back);
    }

    /// Property 2: N events written to a single `NdjsonFileSink` produce exactly
    /// N newline-terminated lines, each deserializing to the corresponding input
    /// event in the original order.
    ///
    /// Edge case N=0: file is empty (zero lines). Any interior-newline bug in a
    /// field value would split one JSON line into multiple lines, breaking the N
    /// count and causing a deserialization failure on the shorter fragment.
    #[test]
    fn one_line_per_event(events in prop::collection::vec(arb_event(), 0..=20)) {
        let tmp = tempfile::tempdir().expect("tempdir must succeed");
        let path = tmp.path().join("events.jsonl");

        let sink = NdjsonFileSink::create(&path).expect("NdjsonFileSink::create must succeed");
        for ev in &events {
            sink.emit(ev).expect("emit must succeed");
        }
        sink.flush().expect("flush must succeed");
        drop(sink);

        let text = std::fs::read_to_string(&path).expect("read must succeed");

        if events.is_empty() {
            prop_assert_eq!(&text, "", "empty event list must produce empty file");
        } else {
            // Each line is terminated by a newline, so splitting on lines()
            // (which strips the terminator) gives exactly N elements.
            let lines: Vec<&str> = text.lines().collect();
            prop_assert_eq!(
                lines.len(),
                events.len(),
                "number of lines must equal number of events"
            );
            // The file must end with a newline (NDJSON convention).
            prop_assert!(
                text.ends_with('\n'),
                "NDJSON file must end with a newline"
            );
            // Each line must deserialize back to the corresponding input event.
            for (i, (line, expected)) in lines.iter().zip(events.iter()).enumerate() {
                let got: Event = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("line {i} is not valid JSON: {e}\nline={line:?}"));
                prop_assert_eq!(&got, expected, "line {} must round-trip to the original event", i);
            }
        }
    }

    /// Property 3: `serde_json::to_string` of an arbitrary `Event` never
    /// contains an interior newline character (`\n`).
    ///
    /// serde_json's compact serializer escapes newlines in string values as
    /// `\n` (the two-character escape), so even an event whose `decision` field
    /// is literally `"foo\nbar"` serializes to a single line. This property
    /// is the structural proof that NDJSON integrity is maintained for all
    /// possible inputs - no field value can split a line.
    #[test]
    fn no_interior_newline(ev in arb_event()) {
        let json = serde_json::to_string(&ev).expect("serde_json::to_string must succeed");
        prop_assert!(
            !json.contains('\n'),
            "compact JSON must not contain interior newlines, got: {json:?}"
        );
    }
}
