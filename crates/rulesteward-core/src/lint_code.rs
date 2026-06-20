//! Shared lint-code catalog primitives for the per-backend lint catalogs.
//!
//! Every backend that owns a family of lint codes (auditd `au-`, sshd `sshd-`,
//! fapolicyd `fapd-`) carries a machine-readable catalog: one entry per code
//! with its stable id, severity tier, and a short operator-facing description.
//! The 3-field [`BaseLintCode`] is the shared shape; the auditd and sshd
//! catalogs alias it directly. The fapolicyd catalog keeps its own 4-field
//! struct (it is a genuine superset: it adds a SARIF run-`condition` field), so
//! it does not use this type.
//!
//! [`assert_catalog_invariants`] is the shared catalog-integrity check the
//! per-backend tests call so the sorted-by-code / no-duplicate /
//! letter-matches-severity / descriptions-non-empty rules live in exactly one
//! place. It is a PLAIN `pub fn` (not `#[cfg(test)]`-gated) so a downstream
//! consumer could call it too and so it is itself inside the mutation gate.

use crate::Severity;

/// One catalogued lint code: its stable id, severity tier, and a short
/// operator-facing description. The shared shape across the auditd and sshd
/// catalogs (the fapolicyd catalog is a superset and keeps its own struct).
#[derive(Debug, Clone, Copy)]
pub struct BaseLintCode {
    /// The stable lint id, e.g. `"au-W01"` / `"sshd-E02"`.
    pub code: &'static str,
    /// Severity tier; its letter (F/E/W/S/C/X) matches the code's letter.
    pub severity: Severity,
    /// One-line operator-facing description of what the check looks for.
    pub description: &'static str,
}

/// Assert the four catalog-integrity invariants every backend catalog must hold:
///
/// 1. **Sorted by `code` ascending** - `codes.windows(2).all(|w| w[0].code < w[1].code)`
///    (strict, so duplicates also fail this rung).
/// 2. **No duplicate codes** - a stricter, message-bearing second pass.
/// 3. **Severity letter matches the code** - the letter after the backend
///    prefix (the first char of the second `-`-delimited segment) must equal
///    `severity.letter()`. This reproduces the per-backend
///    `catalog_letters_match_severities` rule, which was byte-identical across
///    all three backends modulo the prefix being stripped.
/// 4. **Descriptions are non-empty** when trimmed.
///
/// # Panics
/// Panics with a descriptive message if any invariant is violated. Intended to
/// be called from a backend's `#[cfg(test)] mod tests`.
pub fn assert_catalog_invariants(codes: &[BaseLintCode]) {
    // 1. sorted strictly ascending by code.
    assert!(
        codes.windows(2).all(|w| w[0].code < w[1].code),
        "catalog must be authored in strictly-ascending sorted-by-code order"
    );

    // 2. no duplicate codes (a stronger, message-bearing check than the strict
    //    sort above; kept explicit so a future relaxation of the sort rule can
    //    never silently admit a duplicate).
    for w in codes.windows(2) {
        assert_ne!(w[0].code, w[1].code, "duplicate catalog code {}", w[0].code);
    }

    for entry in codes {
        // 3. severity letter matches the code's letter. The code is
        //    `<prefix>-<L><nn>`; the tier letter is the first char of the
        //    segment AFTER the (single) `-` separating prefix from key.
        let letter = entry
            .code
            .split('-')
            .nth(1)
            .and_then(|seg| seg.chars().next())
            .unwrap_or_else(|| panic!("malformed catalog code {:?}", entry.code));
        assert_eq!(
            letter,
            entry.severity.letter(),
            "{}: code letter must match severity tier",
            entry.code
        );

        // 4. descriptions non-empty (trimmed).
        assert!(
            !entry.description.trim().is_empty(),
            "{}: description must not be empty",
            entry.code
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small, well-formed catalog that satisfies every invariant.
    const GOOD: &[BaseLintCode] = &[
        BaseLintCode {
            code: "xx-E01",
            severity: Severity::Error,
            description: "an error",
        },
        BaseLintCode {
            code: "xx-W01",
            severity: Severity::Warning,
            description: "a warning",
        },
    ];

    #[test]
    fn good_catalog_passes() {
        assert_catalog_invariants(GOOD);
    }

    #[test]
    #[should_panic(expected = "sorted-by-code")]
    fn mis_sorted_catalog_panics() {
        let bad = &[
            BaseLintCode {
                code: "xx-W01",
                severity: Severity::Warning,
                description: "a warning",
            },
            BaseLintCode {
                code: "xx-E01",
                severity: Severity::Error,
                description: "an error",
            },
        ];
        assert_catalog_invariants(bad);
    }

    #[test]
    #[should_panic(expected = "sorted-by-code")]
    fn duplicate_code_panics() {
        // Two identical codes: the strict-ascending sort rung (rung 1) catches
        // this first (`w[0].code < w[1].code` is false for equal codes), so the
        // observed panic is the sorted-by-code assertion.
        let bad = &[
            BaseLintCode {
                code: "xx-E01",
                severity: Severity::Error,
                description: "an error",
            },
            BaseLintCode {
                code: "xx-E01",
                severity: Severity::Error,
                description: "another error",
            },
        ];
        assert_catalog_invariants(bad);
    }

    #[test]
    #[should_panic(expected = "description must not be empty")]
    fn empty_description_panics() {
        let bad = &[BaseLintCode {
            code: "xx-E01",
            severity: Severity::Error,
            description: "   ",
        }];
        assert_catalog_invariants(bad);
    }

    #[test]
    #[should_panic(expected = "code letter must match severity tier")]
    fn wrong_letter_panics() {
        // Code says E (Error) but the severity is Warning.
        let bad = &[BaseLintCode {
            code: "xx-E01",
            severity: Severity::Warning,
            description: "mismatched",
        }];
        assert_catalog_invariants(bad);
    }
}
