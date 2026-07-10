//! `fapolicyd-attr-update` - derive + drift-check the fapd-E01 attribute registry
//! (`crates/rulesteward-fapolicyd/src/attrs.rs`'s `SUBJECT_ONLY` / `OBJECT_ONLY` /
//! `BOTH_SIDES` consts) against upstream fapolicyd's `src/library/{subject,
//! object}-attr.c`.
//!
//! Library half (the testable core): [`parse`] extracts attribute names + side
//! classification out of a raw C source string; [`registry`] compares a derived
//! registry against the shipped consts (the two-part name/side drift contract -
//! see `registry`'s module doc); [`config`] reads the pinned versions +
//! sha256 pins from `attr-refs.toml`. The `main` binary wires these into the
//! `derive` / `check` subcommands. Network fetch is isolated behind [`source`] so
//! the core is tested offline with the committed `tests/fixtures/`.

pub mod config;
pub mod parse;
pub mod registry;
pub mod source;
