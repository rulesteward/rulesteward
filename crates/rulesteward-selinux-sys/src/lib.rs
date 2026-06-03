//! libsepol FFI shim for `RuleSteward`.
//!
//! This crate is a placeholder skeleton. The real FFI declarations, the
//! `build.rs` that probes for `libsepol`, and the `links = "sepol"` manifest
//! key are all deferred to Phase-0 Task P5 (issues #106 and #107). Nothing
//! in this stub file uses `unsafe` or `extern "C"` call sites, so the crate
//! compiles cleanly under the workspace-wide `unsafe_code = "deny"` lint.
