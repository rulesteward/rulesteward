//! `stig-update` - derive and drift-check the sysctld STIG baseline tables from
//! ComplianceAsCode/content source (controls + rule.yml), per RHEL product.
//!
//! Library half (the testable core): [`jinja`] resolves the per-product Jinja
//! conditionals in a rule.yml; [`cac`] parses the resolved YAML; [`derive`] turns a
//! `(product, ref)` into the normalized baseline table; [`config`] reads the pinned
//! refs + exclusions. The `main` binary wires these into the `derive` / `check`
//! subcommands. Network fetch is isolated behind a thin seam so the core is tested
//! offline with fixtures.

pub mod cac;
pub mod config;
pub mod derive;
pub mod jinja;
pub mod source;
