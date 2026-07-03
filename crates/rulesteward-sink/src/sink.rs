//! The `EventSink` trait (spec §12.3, Decision 10). `&self` + explicit `flush`
//! under `Send + Sync` - implementations use interior mutability. Call `flush()`
//! to observe I/O errors; dropping a buffered sink flushes best-effort.
use crate::{Event, SinkError};

pub trait EventSink: Send + Sync {
    /// Serialize and write one event.
    fn emit(&self, event: &Event) -> Result<(), SinkError>;
    /// Flush buffered output, surfacing any I/O error.
    fn flush(&self) -> Result<(), SinkError>;
}
