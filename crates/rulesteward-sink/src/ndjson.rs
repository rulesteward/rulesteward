//! NDJSON sinks: one JSON object per line via `serde_jsonlines`. A generic
//! `NdjsonSink<W>` holds the writer behind a `Mutex` (so `emit(&self)` satisfies
//! `Send + Sync`); the file/stdout sinks are thin newtypes over it.
use crate::{Event, EventSink, SinkError};
use serde_jsonlines::JsonLinesWriter;
use std::io::Write;
use std::sync::Mutex;

pub(crate) struct NdjsonSink<W: Write + Send> {
    inner: Mutex<JsonLinesWriter<W>>,
}

impl<W: Write + Send> NdjsonSink<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self {
            inner: Mutex::new(JsonLinesWriter::new(writer)),
        }
    }
    #[cfg(test)]
    pub(crate) fn into_inner(self) -> W {
        self.inner
            .into_inner()
            .expect("mutex not poisoned")
            .into_inner()
    }
}

impl<W: Write + Send> EventSink for NdjsonSink<W> {
    fn emit(&self, event: &Event) -> Result<(), SinkError> {
        let mut w = self.inner.lock().expect("sink mutex poisoned");
        w.write(event)?;
        Ok(())
    }
    fn flush(&self) -> Result<(), SinkError> {
        let mut w = self.inner.lock().expect("sink mutex poisoned");
        w.flush()?;
        Ok(())
    }
}

use std::fs::File;
use std::io::{BufWriter, Stdout};
use std::path::Path;

/// Writes NDJSON events to a file. Wraps the writer in `BufWriter` - its own
/// `Drop` flushes best-effort, so no explicit `Drop` is needed (call `flush()` to
/// observe errors). v0.1 default for `--emit-events file:/path` (CLI wiring is v0.2).
pub struct NdjsonFileSink(NdjsonSink<BufWriter<File>>);

impl NdjsonFileSink {
    /// Create (truncating) the events file.
    pub fn create(path: &Path) -> Result<Self, SinkError> {
        let file = File::create(path)?;
        Ok(Self(NdjsonSink::new(BufWriter::new(file))))
    }
}

impl EventSink for NdjsonFileSink {
    fn emit(&self, event: &Event) -> Result<(), SinkError> {
        self.0.emit(event)
    }
    fn flush(&self) -> Result<(), SinkError> {
        self.0.flush()
    }
}

/// Writes NDJSON events to stdout (one object per line). v0.1 default for
/// `--format json --emit-events -` (CLI wiring is v0.2).
pub struct NdjsonStdoutSink(NdjsonSink<Stdout>);

impl NdjsonStdoutSink {
    #[must_use]
    pub fn new() -> Self {
        Self(NdjsonSink::new(std::io::stdout()))
    }
}

impl Default for NdjsonStdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for NdjsonStdoutSink {
    fn emit(&self, event: &Event) -> Result<(), SinkError> {
        self.0.emit(event)
    }
    fn flush(&self) -> Result<(), SinkError> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::NdjsonSink;
    use crate::{Event, EventSink};

    fn sample(n: u32) -> Event {
        Event::new(n, "deny", "ftype", "/bin/x", "/p", "2026-05-28T00:00:00Z")
    }

    #[test]
    fn emits_one_json_object_per_line_with_trailing_newline() {
        let sink = NdjsonSink::new(Vec::<u8>::new());
        sink.emit(&sample(1)).unwrap();
        sink.emit(&sample(2)).unwrap();
        sink.flush().unwrap();
        let bytes = sink.into_inner();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(text.ends_with('\n'));
        let first: Event = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first, sample(1));
    }

    #[test]
    fn dyn_trait_object_is_object_safe_and_emits_without_panic() {
        // Structural assertion: `EventSink` is object-safe and `NdjsonSink<Vec<u8>>`
        // satisfies the trait object's `Send + Sync` auto-trait bounds. (The bytes
        // are not observable here because the writer is moved into the `Box`; the
        // exact-bytes behavior is covered by the `Vec<u8>` tests above.)
        let sink: Box<dyn EventSink> = Box::new(NdjsonSink::new(Vec::<u8>::new()));
        sink.emit(&sample(7)).unwrap();
        sink.flush().unwrap();
    }

    #[test]
    fn file_sink_writes_readable_ndjson_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("events.jsonl");
        {
            let sink = super::NdjsonFileSink::create(&p).unwrap();
            sink.emit(&sample(1)).unwrap();
            sink.emit(&sample(2)).unwrap();
            sink.flush().unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        // Assert the first line round-trips to the SAME event emitted first, so a
        // future refactor that reordered or dropped events would be caught.
        let first: Event = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first, sample(1));
    }

    #[test]
    fn file_sink_create_on_unwritable_path_errors_not_panics() {
        let r =
            super::NdjsonFileSink::create(std::path::Path::new("/nonexistent-dir/rs-trap/e.jsonl"));
        assert!(matches!(r, Err(crate::SinkError::Io(_))));
    }

    #[test]
    fn stdout_sink_constructs_and_emits() {
        let sink = super::NdjsonStdoutSink::new();
        sink.emit(&sample(1)).unwrap();
        sink.flush().unwrap();
    }

    /// Kill the `NdjsonSink<W>::flush` survivor: use a `BufWriter<Vec<u8>>`
    /// so flush is required to move buffered bytes to the inner vec before
    /// `into_inner()` extracts them. We verify the flush method returns Ok.
    /// The actual byte-level correctness is also verified via `file_flush_visible_before_drop`.
    #[test]
    fn generic_flush_returns_ok_on_buffered_writer() {
        use std::io::BufWriter;
        let sink = NdjsonSink::new(BufWriter::new(Vec::<u8>::new()));
        sink.emit(&sample(3)).unwrap();
        // flush() must succeed (not return Err or be a no-op that silently loses data)
        sink.flush().unwrap();
        // into_inner() consumes self and returns the BufWriter, then inner Vec
        let buf: BufWriter<Vec<u8>> = sink.into_inner();
        // After flush(), BufWriter's internal buffer should be empty;
        // all bytes were pushed to the inner Vec.
        // The BufWriter buffer capacity is default (8192); after flush the Vec holds the data.
        // We call into_inner() which calls flush() on BufWriter and returns Vec.
        let bytes = buf.into_inner().expect("bufwriter flush ok");
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with('\n'));
    }

    /// Kill the `NdjsonFileSink::flush` survivor: read the file while the
    /// sink is still alive (before Drop). The data must be on disk after
    /// an explicit `flush()`, even though `BufWriter::drop` hasn't fired yet.
    #[test]
    fn file_flush_visible_before_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("flush-before-drop.jsonl");
        let sink = super::NdjsonFileSink::create(&p).unwrap();
        sink.emit(&sample(5)).unwrap();
        sink.flush().unwrap();
        // Sink is still alive here (not dropped). The file must be readable.
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with('\n'));
        // Keep sink alive so Drop hasn't fired yet.
        drop(sink);
    }
}
