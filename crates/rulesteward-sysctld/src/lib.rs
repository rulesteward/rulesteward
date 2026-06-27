//! `sysctl.d` / `sysctl.conf` backend: parses kernel-parameter assignment files
//! (`/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`,
//! `/usr/lib/sysctl.d/*.conf`) and runs security-baseline lint passes over them.
//!
//! # v1 scope (implemented)
//! v1 ships two codes, both implemented (the [`parser`] tokenizes the file and
//! runs the passes; see [`lints`]):
//! * `sysctld-F01` - the file does not parse (a malformed line).
//! * `sysctld-W01` - a last-wins conflict (the same key is assigned different
//!   effective values across the drop-in precedence order).
//!
//! The catalog ([`catalog`]) lists the FULL planned `sysctld-` taxonomy in
//! sorted order; freezing it up front means the lint passes emit only
//! already-catalogued codes and never edit that shared file.
//!
//! `sysctld-W02` (the STIG hardening baseline) and cross-directory system
//! precedence (the full `/etc` vs `/run` vs `/usr/lib` override ordering across
//! the standard sysctl.d search path) are deferred follow-ups (issues #150 /
//! #335); v1's W01 reasons within a single supplied set of files only.

pub mod catalog;
pub mod lints;
pub mod parser;
