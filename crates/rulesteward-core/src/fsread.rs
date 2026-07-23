//! Shared config-file reading with special-file protection (#560).
//!
//! Phase-0 stub for the 9i fan-out: the module file exists so parallel lanes
//! never edit `lib.rs` concurrently. Lane 2 (#560/#561) owns the body: a
//! regular-file-only reader that rejects FIFOs / device nodes / other
//! non-regular files with a clear error instead of hanging on an unbounded
//! `fs::read_to_string`. Consumed via full path (`rulesteward_core::fsread`);
//! `lib.rs` re-exports are consolidated at integration, not per-lane.
