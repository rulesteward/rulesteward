//! `selinux-stig-update` - derive and drift-check the `rulesteward-selinux`
//! se-W01/se-W02 STIG control-family table (`stig.rs`) from the official DISA
//! XCCDF, per RHEL product.
//!
//! Library half (the testable core): [`xccdf`] parses an XCCDF benchmark into
//! the normalized, family-classified control table; [`derive`] holds the
//! owned comparison shape, the shipped-projection side
//! ([`derive::code_table`]), and the drift diff; [`config`] reads the pinned
//! DISA zip refs. The `main` binary wires these into the `derive` / `check`
//! subcommands. The network fetch is isolated behind the [`source`] seam so
//! the core is tested offline with fixtures.
//!
//! Mirrors `tools/auditd-stig-update`'s module layout (Cargo.toml,
//! `stig-refs.toml`, `tests/cli.rs` exit-code contract) with ONE structural
//! deviation: unlike au-W06 (one row per required RULES.D LINE, several lines
//! per requirement), the selinux STIG table is a small, fixed 5-FAMILY
//! classification (`ControlFamily::{Enforcing,PolicyType,Policycoreutils,
//! PolicycoreutilsPython,FaillockDirContext}`), so [`xccdf`] classifies each
//! `<Group>` into (at most) one family by its `check-content` shape rather
//! than extracting auditctl-syntax lines.

pub mod config;
pub mod derive;
pub mod source;
pub mod xccdf;
