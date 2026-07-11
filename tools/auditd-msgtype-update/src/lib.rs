//! `auditd-msgtype-update` - derive + drift-check the auditd msgtype
//! name<->number tables (`crates/rulesteward-auditd/src/lints/value/msgtype.rs`'s
//! `MSGTYPE_NAMES` / `APPARMOR_MSGTYPE_NAMES` consts) against upstream
//! audit-userspace's `lib/msg_typetab.h` + `lib/audit-records.h` and the Linux
//! kernel's `include/uapi/linux/audit.h`.
//!
//! Library half (the testable core): [`parse`] extracts the
//! `_S(AUDIT_<NAME>, "<NAME>")` rows (base vs `#ifdef WITH_APPARMOR`) out of
//! `msg_typetab.h` and the `#define AUDIT_<NAME> <number>` constants out of
//! the two number sources, then resolves names to numbers (audit-records.h
//! first, kernel header for names it lacks, hard error on a cross-source
//! conflict); [`registry`] compares a derived table pair against the shipped
//! consts (projected via the `rulesteward-auditd` path-dep); [`config`] reads
//! the pinned refs + sha256 pins from `msgtype-refs.toml`. The `main` binary
//! wires these into the `derive` / `check` subcommands. Network fetch is
//! isolated behind [`source`] so the core is tested offline with the committed
//! `tests/fixtures/`.

pub mod config;
pub mod parse;
pub mod registry;
pub mod source;
