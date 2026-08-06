//! `stig-update` - derive and drift-check the sysctld STIG baseline tables.
//!
//! The sysctld-STIG derivation is sourced from the official DISA XCCDF (mirroring
//! `tools/sshd-stig-update` / `tools/auditd-stig-update`, which also source
//! DISA): [`xccdf`] is the derivation core (parses a DISA XCCDF benchmark
//! directly into the baseline table) and [`config`] reads the DISA zip/base_url
//! pins. [`jinja`] (per-product Jinja conditional resolution), [`cac`] (CaC YAML
//! parsing), and most of [`derive`] (`DerivedKey`, `normalize_set`,
//! `derive_table`) exist for `tools/cis-update`, which path-deps this
//! crate and uses them for its OWN, CaC-sourced CIS-value derivation
//! (a different standard/data source; see `tools/cis-update/Cargo.toml`'s header
//! and `xccdf.rs`'s module doc for the full survival-constraint rationale).
//! [`derive::code_table`] is a pure projection of the shipped
//! `rulesteward_sysctld` baseline into this crate's comparison shape, used by
//! `xccdf.rs`'s golden tests. The `main` binary wires [`xccdf`]/[`config`] into
//! the `derive` / `check` subcommands. Network fetch is isolated behind a thin
//! seam ([`source`]) so the derivation core is tested offline with fixtures.

pub mod cac;
pub mod config;
pub mod derive;
pub mod jinja;
pub mod source;
pub mod xccdf;
