//! `SELinux` module - AVC parsing, denial model, triage, TE emit, and categorization.
//!
//!
//! Module skeletons are wired here; real implementations land in their respective
//! Phase-0 tasks and pipelines (see per-module doc comments for issue references).

mod avc;
mod categorize;
mod denial;
mod te_emit;
mod triage;

#[doc(hidden)]
pub fn placeholder() {}
