//! `cis-update` - derive and drift-check the per-backend CIS control tables from
//! ComplianceAsCode/content source (`products/<p>/controls/cis_<p>.yml`), per RHEL
//! product.
//!
//! Library half (the testable core): [`controls`] parses the CIS controls file
//! (after `stig_update::jinja` per-product resolution); [`family`] groups the
//! parsed controls into per-backend families (sshd / sudoers / sysctld / auditd);
//! [`values`] delegates sysctl VALUE derivation to `stig_update::derive`;
//! [`registry`] maps each (family, product) to its shipped table (all `Pending`
//! until the Wave-3 lanes land); [`report`] renders derive output, drift diffs,
//! and the exact SKIPPED/anchor wording; [`config`] reads the pinned refs. The
//! `main` binary wires these into the `derive` / `check` subcommands. Network
//! fetch stays behind `stig_update::source` plus the thin [`source`] shim here,
//! so the core is tested offline with fixtures.

pub mod config;
pub mod controls;
pub mod family;
pub mod registry;
pub mod report;
pub mod source;
pub mod values;
