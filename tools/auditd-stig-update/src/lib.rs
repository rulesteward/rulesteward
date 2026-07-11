//! `auditd-stig-update` - derive and drift-check the `rulesteward-auditd`
//! au-W06 STIG baseline tables from the official DISA XCCDF, per RHEL product.
//!
//! Library half (the testable core): [`xccdf`] parses an XCCDF benchmark into the
//! normalized required-rule table; [`derive`] holds the owned comparison shape, the
//! shipped-projection side ([`derive::code_table`]), and the drift diff; [`config`]
//! reads the pinned DISA zip refs. The `main` binary wires these into the `derive`
//! / `check` subcommands. The network fetch is isolated behind the [`source`] seam
//! so the core is tested offline with fixtures.
//!
//! Mirrors `tools/sshd-stig-update`'s module layout (Cargo.toml, `.cargo/mutants.toml`,
//! `stig-refs.toml`, `tests/cli.rs` exit-code contract) with ONE deliberate deviation:
//! the canonical required-rule VALUE is extracted from `check-content`, not `fixtext`
//! (see [`xccdf`]'s module doc for the grounded reason).

pub mod config;
pub mod derive;
pub mod source;
pub mod xccdf;
