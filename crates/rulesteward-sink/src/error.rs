//! Errors from event sinks. `#[non_exhaustive]` so v0.2 network-backed sinks
//! (Syslog/CEF/HEC) can add variants without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SinkError {
    /// Writing the serialized event failed. `serde-jsonlines` folds serialization
    /// errors into `io::Error`, so this single variant covers both today.
    #[error("writing event: {0}")]
    Io(#[from] std::io::Error),
}
