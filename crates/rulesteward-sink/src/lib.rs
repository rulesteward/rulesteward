mod error;
mod event;
mod ndjson;
mod sink;

pub use error::SinkError;
pub use event::Event;
pub use ndjson::{NdjsonFileSink, NdjsonStdoutSink};
pub use sink::EventSink;
