//! auditd log-to-rule converter.
//!
//! Filled by pipeline P2 (issue #91).
//!
//! # Grounding
//! - Read-only line scan of `audit.log`; aggregate by `key=` field (f3 section 5.3c).
//! - `key=` appears as `key="value"` in SYSCALL and watch SYSCALL records.
//! - `key=(null)` means no key tag; those events are counted under `None`.
//! - Used by `--from-log` to REPLACE assumed rate bands with measured rates.
//! - Shared substrate for future Option-2 noise-reduction (f3 section 7).

use std::collections::HashMap;
use std::path::Path;

/// Error from the `--from-log` reader.
#[derive(Debug, Clone, PartialEq)]
pub struct LogReadError {
    pub message: String,
}

/// Measured per-key event counts from a real `audit.log` slice.
///
/// The map key is the audit `key=` value (the `-k` tag from the rule);
/// `None` maps to events with `key=(null)` (rules with no `-k` tag).
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredRates {
    /// Events counted per key. No-key events are under `None`.
    pub counts: HashMap<Option<String>, u64>,
    /// Total lines scanned (for diagnostics).
    pub lines_scanned: u64,
}

/// Scan an `audit.log` file and aggregate audit events by `key=` value.
///
/// Any record type that carries `key="value"` contributes to the count for that
/// key (`SYSCALL`, `CONFIG_CHANGE`, `WATCH`, etc.). Records with no `key=` field or
/// with `key=(null)` are counted under `None`. Multiple records sharing the
/// same audit serial number are collapsed into one event (serial-dedup).
///
/// Returns `Err` when the file cannot be opened or read.
///
/// # Errors
/// I/O errors are wrapped in `LogReadError`.
pub fn count_events_by_key(_path: &Path) -> Result<MeasuredRates, LogReadError> {
    todo!("P2 #91 fills from-log reader")
}
