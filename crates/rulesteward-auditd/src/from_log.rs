//! auditd log-to-rule converter.
//!
//! Issue #91 -- pipeline P2.
//!
//! # Grounding
//! - Read-only line scan of `audit.log`; aggregate by `key=` field (f3 section 5.3c).
//! - `key=` appears as `key="value"` in any record type (SYSCALL, `CONFIG_CHANGE`, PATH, etc.).
//! - `key=(null)` means no key tag; those events are counted under `None`.
//! - Multiple records sharing the same audit serial number are collapsed into one
//!   event (serial-dedup): a SYSCALL + its PATH/CWD companions on one serial = 1 event.
//! - Used by `--from-log` to REPLACE assumed rate bands with measured rates.

use std::collections::{HashMap, HashSet};
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
    /// Total on-disk bytes per key (#307).
    ///
    /// For each counted serial, the sum of every sharing record's on-disk byte
    /// length (record text + `\n` terminator) is attributed to that event's key.
    /// Companion records (PATH/CWD/EOE) that share an event's serial but carry no
    /// `key=` field contribute their bytes to that event's key. Same key set as
    /// `counts`. Used by `--from-log` MEASURED mode to size events by their actual
    /// bytes instead of the flat ~1200 B assumption.
    pub bytes: HashMap<Option<String>, u64>,
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
pub fn count_events_by_key(path: &Path) -> Result<MeasuredRates, LogReadError> {
    let content = std::fs::read_to_string(path).map_err(|e| LogReadError {
        message: format!("cannot read {}: {e}", path.display()),
    })?;

    // First pass: group records by audit serial. For each serial we accumulate
    // (a) its total on-disk bytes -- every record sharing the serial, companions
    // included -- and (b) the set of `key=` values seen on its key-bearing records.
    // A serial with NO key-bearing record is not an event (no rule matched it), so
    // its bytes are dropped when we fold per key below.
    //
    // Counts remain the prior model (distinct serials per key); the per-serial byte
    // sum is the #307 addition. Because the byte total is keyed off the serial (not
    // the key-bearing line), the key-less PATH/CWD/EOE companions of a SYSCALL are
    // sized into the event -- a naive per-`key=`-line byte sum would undercount.
    let mut serial_bytes: HashMap<String, u64> = HashMap::new();
    let mut serial_keys: HashMap<String, HashSet<Option<String>>> = HashMap::new();
    let mut lines_scanned: u64 = 0;

    for raw_line in content.lines() {
        lines_scanned += 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract the serial from msg=audit(TS:SERIAL).
        let Some(serial) = extract_serial(line) else {
            continue;
        };

        // On-disk byte length: the record text plus its '\n' terminator (#307).
        // Audit logs are '\n'-terminated on Linux; a final line without a trailing
        // newline over-counts by one byte, negligible for a cost estimate.
        *serial_bytes.entry(serial.clone()).or_default() += raw_line.len() as u64 + 1;

        // key="value" -> Some(Some(..)); key=(null) -> Some(None); no key= -> None.
        if let Some(key_value) = extract_key(line) {
            serial_keys.entry(serial).or_default().insert(key_value);
        }
    }

    // Fold per key: each distinct serial bearing a key contributes 1 event and its
    // full record-group byte sum to that key.
    let mut counts: HashMap<Option<String>, u64> = HashMap::new();
    let mut bytes: HashMap<Option<String>, u64> = HashMap::new();
    for (serial, keys) in &serial_keys {
        let serial_total = serial_bytes.get(serial).copied().unwrap_or(0);
        for key in keys {
            *counts.entry(key.clone()).or_default() += 1;
            *bytes.entry(key.clone()).or_default() += serial_total;
        }
    }

    Ok(MeasuredRates {
        counts,
        bytes,
        lines_scanned,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract the audit serial number from a record line.
///
/// Audit records contain `msg=audit(TIMESTAMP:SERIAL):` where SERIAL is a
/// monotonically increasing integer. Format: `msg=audit(1234567890.123:4567):`.
fn extract_serial(line: &str) -> Option<String> {
    // Find `msg=audit(` then extract the part between `:` and `)`.
    let start = line.find("msg=audit(")?;
    let after_paren = &line[start + "msg=audit(".len()..];
    let colon_pos = after_paren.find(':')?;
    let after_colon = &after_paren[colon_pos + 1..];
    let end = after_colon.find(')')?;
    let serial = &after_colon[..end];
    Some(serial.to_string())
}

/// Extract the `key=` value from a record line.
///
/// Returns:
/// - `Some(Some("value"))` for `key="value"`
/// - `Some(None)` for `key=(null)`
/// - `None` if the line has no `key=` field at all
///
/// The outer/inner `Option` distinction is intentional: outer `None` = "no key= field present"
/// (line does not contribute to any key's event count); inner `None` = `key=(null)` (rule had
/// no `-k` tag; counted under the `None` bucket in `MeasuredRates::counts`).
#[allow(clippy::option_option)]
fn extract_key(line: &str) -> Option<Option<String>> {
    // Find `key=` in the line.
    // The key can appear as: key="value" or key=(null)
    // It may appear anywhere in the line (not just at end).
    let key_pos = line.find(" key=")?;
    let after_key = &line[key_pos + " key=".len()..];

    if after_key.starts_with("(null)") {
        Some(None)
    } else if let Some(after_quote) = after_key.strip_prefix('"') {
        // key="value" - extract up to the closing quote.
        let end = after_quote.find('"').unwrap_or(after_quote.len());
        Some(Some(after_quote[..end].to_string()))
    } else {
        // Unquoted value (unusual but handle gracefully).
        let end = after_key
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after_key.len());
        let val = &after_key[..end];
        if val.is_empty() {
            None
        } else {
            Some(Some(val.to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for private helpers
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::extract_serial;

    // Kills mutant: replace + with - (returns "3:8675309" instead of "8675309")
    // Kills mutant: replace + with * (returns ":8675309" instead of "8675309")
    #[test]
    fn extract_serial_basic() {
        let line = "type=SYSCALL msg=audit(1738000000.123:8675309): arch=c000003e syscall=59";
        assert_eq!(extract_serial(line), Some("8675309".to_string()));
    }

    // Different timestamp length + short serial - rules out degenerate coincidences.
    #[test]
    fn extract_serial_short_serial() {
        let line = "type=CWD msg=audit(1700000001.001:1): cwd=\"/tmp\"";
        assert_eq!(extract_serial(line), Some("1".to_string()));
    }

    // Large serial with longer timestamp - rules out off-by-one coincidences.
    #[test]
    fn extract_serial_large_serial() {
        let line = "type=PATH msg=audit(1738999999.999:999999): item=0 name=\"/usr/bin/ls\"";
        assert_eq!(extract_serial(line), Some("999999".to_string()));
    }

    // Line without msg=audit(...) returns None.
    #[test]
    fn extract_serial_missing_returns_none() {
        let line = "type=EOE";
        assert_eq!(extract_serial(line), None);
    }
}
