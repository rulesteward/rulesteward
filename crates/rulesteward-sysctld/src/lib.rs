//! `sysctl.d` / `sysctl.conf` backend: parses kernel-parameter assignment files
//! (`/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`,
//! `/usr/lib/sysctl.d/*.conf`) and runs security-baseline lint passes over them.
//!
//! # Scope (implemented)
//! Five codes (the [`parser`] tokenizes the file and runs F01/W01; the STIG
//! baseline W02 lives in [`lints::baseline`]; the CIS baseline W04 lives in
//! [`lints::cis`]; the cross-directory W03 pass lives in [`system`]):
//! * `sysctld-F01` - the file does not parse (a malformed line).
//! * `sysctld-W01` - a last-wins conflict (the same key is assigned different
//!   effective values across the drop-in precedence order).
//! * `sysctld-W02` - the version-aware STIG kernel-hardening baseline check
//!   (issue #335): a STIG-required key unset or set to an insecure value. Runs
//!   only when a `--target rhel8|rhel9|rhel10` baseline is selected.
//! * `sysctld-W03` - the cross-directory precedence surprise (issue #420):
//!   lower-precedence-directory override, masked drop-in key drop, and
//!   procps/systemd applier divergence. Fires only in `--system` mode.
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
//! directory masking + global lexicographic merge), reruns F01/W01/W02/W04 over the
//! merged set, and adds the cross-directory `sysctld-W03` pass (lower-precedence
//! override, procps/systemd applier divergence, masked-drop-in key drop). It fires
//! only in `--system` mode; `lint_str`/`lint_dir` (below) are UNCHANGED and never
//! emit `sysctld-W03`; W01/W02/W04 there still reason within a single supplied file
//! or directory only.

pub mod catalog;
pub mod lints;
// Differential-oracle adapter. Not a product feature: it
// is the product side of `tests/sysctld_corpus_oracle.rs`, which checks this
// crate's tree-materializer, inventory recomputation and transcript classifier
// against what the real `systemd-sysctl` daemon did. It lives in `src/` so
// that logic is covered by clippy, the coverage floor and the mutation gate.
pub mod oracle;
pub mod parser;
pub mod system;

pub use lints::baseline::{StigEntry, TargetVersion, stig_baseline};
pub use lints::cis::{CisControl, cis_baseline};
