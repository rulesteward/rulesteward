//! Shared inline-comment stripping, parameterized per backend (#562).
//!
//! Phase-0 stub for the 9i fan-out: the module file exists so parallel lanes
//! never edit `lib.rs` concurrently. Lane 3 (#562) owns the body: one
//! parameterized stripper replacing the three line-level implementations
//! (fapolicyd `parser/inline.rs`, auditd `parser.rs`, sudoers `parser.rs`),
//! with each backend's quote rules expressed as explicit parameters. sshd's
//! token-level `algo_list_value` stripping stays separate by decision
//! (2026-07-23). Consumed via full path (`rulesteward_core::comment`);
//! `lib.rs` re-exports are consolidated at integration, not per-lane.
