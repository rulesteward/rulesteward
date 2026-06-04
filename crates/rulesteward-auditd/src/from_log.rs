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

    // serial -> key for events we have already seen for that serial.
    // We record the key at first encounter; subsequent records on the same serial
    // don't add a new event count but do contribute their key (if the first record
    // had no key but a companion does - we record the key when we first see a
    // key-bearing record for this serial).
    //
    // Implementation: track seen (serial, key) pairs.
    // A serial gets one count per unique key. Because the fixture confirms
    // "any record type that carries key=X contributes", but the serial-dedup
    // collapses them: we track Set<serial> per key.
    let mut key_serials: HashMap<Option<String>, HashSet<String>> = HashMap::new();
    let mut lines_scanned: u64 = 0;

    for line in content.lines() {
        lines_scanned += 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract the serial from msg=audit(TS:SERIAL).
        let Some(serial) = extract_serial(line) else {
            continue;
        };

        // Extract key= value.
        let key = extract_key(line);

        // Only count lines that carry a key (either named or null).
        // Lines with no key= field at all are skipped (they contribute nothing
        // to the per-key event rate; if they carry no key we can't attribute them).
        // key=(null) -> key=None -> counted under None bucket.
        if let Some(key_value) = key {
            key_serials.entry(key_value).or_default().insert(serial);
        }
    }

    // Convert serial-sets to counts.
    let counts = key_serials
        .into_iter()
        .map(|(k, serials)| (k, serials.len() as u64))
        .collect();

    Ok(MeasuredRates {
        counts,
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
