//! auditd module - rule parser, cost calculator, band classifier, and log converter.
//!
//! Module skeletons are wired here; real implementations land in pipeline P2
//! (see per-module doc comments for issue references).

mod ast;
mod bands;
mod cost;
mod from_log;
mod parser;

#[doc(hidden)]
pub fn placeholder() {}
