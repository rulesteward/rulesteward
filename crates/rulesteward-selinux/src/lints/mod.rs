//! Semantic lint passes over a parsed `/etc/selinux/config` (issue #520).
//!
//! Passes:
//! * `se-W01` - `SELINUX=` not enforcing at boot (rhel9/rhel10 only).
//! * `se-W02` - `SELINUXTYPE=` not targeted (rhel8 only).
//!
//! The `se-` code catalog is frozen in [`catalog`]. Both passes live in
//! [`boot`] and consume [`crate::config::SelinuxConfig`] (the already-parsed
//! directives), never raw file text directly.

pub mod boot;
pub mod catalog;

pub use boot::{check_enforcing, check_policy_type};
