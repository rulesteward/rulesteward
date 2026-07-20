//! `sysctl.d` / `sysctl.conf` backend: parses kernel-parameter assignment files
//! (`/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`,
//! `/usr/lib/sysctl.d/*.conf`) and runs security-baseline lint passes over them.
//!
//! # Scope (implemented)
//! Four codes (the [`parser`] tokenizes the file and runs F01/W01; the STIG
//! baseline W02 lives in [`lints::baseline`]; the CIS baseline W04 lives in
//! [`lints::cis`]):
//! * `sysctld-F01` - the file does not parse (a malformed line).
//! * `sysctld-W01` - a last-wins conflict (the same key is assigned different
//!   effective values across the drop-in precedence order).
//! * `sysctld-W02` - the version-aware STIG kernel-hardening baseline check
//!   (issue #335): a STIG-required key unset or set to an insecure value. Runs
//!   only when a `--target rhel8|rhel9|rhel10` baseline is selected.
//! * `sysctld-W04` - the version-aware CIS-Benchmark kernel-hardening baseline
//!   check (issue #527): a CIS-required key unset or set to a value outside the
//!   benchmark-accepted set. Runs only when a `--target` baseline is selected;
//!   additive to (coexists with) `sysctld-W02`.
//!
//! The catalog ([`catalog`]) lists the FULL `sysctld-` taxonomy in sorted order;
//! freezing it up front means the lint passes emit only already-catalogued codes
//! and never edit that shared file.
//!
//! Cross-directory system precedence (the full `/etc` vs `/run` vs `/usr/lib`
//! override ordering across the standard sysctl.d search path, issue #420) lives in
//! [`system`]: [`system::lint_system`] enumerates the search path (same-basename
//! directory masking + global lexicographic merge), reruns F01/W01/W02 over the
//! merged set, and adds the cross-directory `sysctld-W03` pass (lower-precedence
//! override, procps/systemd applier divergence, masked-drop-in key drop). It fires
//! only in `--system` mode; `lint_str`/`lint_dir` (below) are UNCHANGED and never
//! emit `sysctld-W03`; W01/W02 there still reason within a single supplied file or
//! directory only.

pub mod catalog;
pub mod lints;
pub mod parser;
pub mod system;

pub use lints::baseline::{StigEntry, TargetVersion, stig_baseline};
pub use lints::cis::{CisControl, cis_baseline};
