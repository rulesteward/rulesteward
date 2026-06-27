//! `sysctl.d` / `sysctl.conf` backend: parses kernel-parameter assignment files
//! (`/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`,
//! `/usr/lib/sysctl.d/*.conf`) and runs security-baseline lint passes over them.
//!
//! # Frozen in Phase 0
//! The catalog ([`catalog`]) lists the FULL planned `sysctld-` taxonomy now, even
//! though the pass bodies are still empty stubs. Freezing the whole list here in
//! Phase 0 means the later lint pipelines start emitting a code that is ALREADY
//! catalogued: they never edit this shared file, which keeps the milestone fan-out
//! conflict-free.
//!
//! # v1 scope
//! v1 ships two codes:
//! * `sysctld-F01` - the file does not parse.
//! * `sysctld-W01` - a last-wins conflict (the same key is assigned different
//!   effective values across the drop-in precedence order).
//!
//! `sysctld-W02` (the STIG hardening baseline) and cross-directory system
//! precedence (the full `/etc` vs `/run` vs `/usr/lib` override ordering across
//! the standard sysctl.d search path) are deferred follow-ups tracked under issue
//! #150; v1's W01 reasons within a single supplied set of files only.

pub mod catalog;
pub mod lints;
pub mod parser;
