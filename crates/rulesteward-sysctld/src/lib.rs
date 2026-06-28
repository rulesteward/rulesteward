//! `sysctl.d` / `sysctl.conf` backend: parses kernel-parameter assignment files
//! (`/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`,
//! `/usr/lib/sysctl.d/*.conf`) and runs security-baseline lint passes over them.
//!
//! # Scope (implemented)
//! Three codes (the [`parser`] tokenizes the file and runs F01/W01; the STIG
//! baseline W02 lives in [`lints::baseline`]):
//! * `sysctld-F01` - the file does not parse (a malformed line).
//! * `sysctld-W01` - a last-wins conflict (the same key is assigned different
//!   effective values across the drop-in precedence order).
//! * `sysctld-W02` - the version-aware STIG kernel-hardening baseline check
//!   (issue #335): a STIG-required key unset or set to an insecure value. Runs
//!   only when a `--target rhel8|rhel9|rhel10` baseline is selected.
//!
//! The catalog ([`catalog`]) lists the FULL `sysctld-` taxonomy in sorted order;
//! freezing it up front means the lint passes emit only already-catalogued codes
//! and never edit that shared file.
//!
//! Cross-directory system precedence (the full `/etc` vs `/run` vs `/usr/lib`
//! override ordering across the standard sysctl.d search path) remains a deferred
//! follow-up (issue #150); W01/W02 reason within a single supplied set of files.

pub mod catalog;
pub mod lints;
pub mod parser;

pub use lints::baseline::TargetVersion;
