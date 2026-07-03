//! Event sinks for `RuleSteward`. Defines the stable [`Event`] wire schema and the
//! [`EventSink`] trait (spec §12.3, Decision 10), with NDJSON stdout/file sinks.
//!
//! v0.1 ships the abstraction and the NDJSON default only: [`NdjsonStdoutSink`]
//! and [`NdjsonFileSink`]. Concrete production sinks (Syslog/CEF/OCSF/Splunk-HEC)
//! and the `collect` subcommand / `--emit-events` CLI wiring are v0.2.
//!
//! Sinks take `&self` and use interior mutability (a `Mutex` around a buffered
//! writer), so a single sink is shareable as `Send + Sync` and usable behind a
//! `Box<dyn EventSink>`. Call [`EventSink::flush`] to observe I/O errors; dropping
//! a buffered sink flushes best-effort.

mod error;
mod event;
mod ndjson;
mod sink;

pub use error::SinkError;
pub use event::Event;
pub use ndjson::{NdjsonFileSink, NdjsonStdoutSink};
pub use sink::EventSink;
