//! `cis-update` - derive and drift-check the per-backend CIS control tables from
//! ComplianceAsCode/content source (`products/<p>/controls/cis_<p>.yml`), per RHEL
//! product.
//!
//! Library half (the testable core): [`controls`] parses the CIS controls file
//! (after `stig_update::jinja` per-product resolution); [`family`] groups the
//! parsed controls into per-backend families (sshd / sudoers / sysctld / auditd);
//! [`values`] delegates sysctl VALUE derivation to `stig_update::derive`;
//! [`overrides`] corrects verbatim upstream artifacts in the pinned controls
//! files (applied on both check and derive via `controls::parse_corrected`);
//! [`stig_refs`] joins auditd CIS rules to DISA STIG ids via the product STIG
//! controls file at the same pin (`derive --stig-refs`); [`registry`] maps each
//! (family, product) to its shipped table (all four Wave-3 families armed;
//! `Pending` is reserved for backends without a CIS lane yet);
//! [`report`] renders derive output, drift diffs, and the exact
//! SKIPPED/anchor wording; [`config`] reads the pinned refs. The `main` binary
//! wires these into the `derive` / `check` subcommands. Network fetch stays
//! behind `stig_update::source` plus the thin [`source`] shim here, so the core
//! is tested offline with fixtures.

pub mod config;
pub mod controls;
pub mod family;
pub mod overrides;
pub mod registry;
pub mod report;
pub mod source;
pub mod stig_refs;
pub mod values;
