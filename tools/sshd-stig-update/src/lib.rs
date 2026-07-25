//! `sshd-stig-update` - derive and drift-check the `rulesteward-sshd` W01/W02 STIG
//! baseline tables from the official DISA XCCDF, per RHEL product.
//!
//! Library half (the testable core): [`xccdf`] parses an XCCDF benchmark into the
//! normalized control table; [`derive`] holds the owned comparison shape, the
//! shipped-projection side ([`derive::code_table`]), and the drift diff; [`config`]
//! reads the pinned DISA zip refs. The `main` binary wires these into the `derive`
//! / `check` subcommands. The network fetch is isolated behind the [`source`] seam
//! so the core is tested offline with fixtures. [`pin`] is the upstream-pin
//! staleness detector (#550): a next-candidate-filename probe, not a "latest"
//! query - see that module's doc for why, and for the offline-testable seam.

pub mod config;
pub mod derive;
pub mod pin;
pub mod source;
pub mod xccdf;
