//! Machine-readable catalog of the auditd (`au-`) lint codes: each code's id,
//! severity tier, and a short operator-facing description.
//!
//! Mirrors the fapolicyd catalog (the crate that OWNS the codes carries the
//! catalog, inside the mutation `examine_globs`), minus the `Condition`
//! machinery: every auditd pass runs unconditionally, and there is no SARIF
//! for auditd (locked CC-4: SARIF is `fapolicyd lint` only).

use rulesteward_core::Severity;

/// One catalogued `au-` lint code: its stable id, severity tier, and a short
/// operator-facing description.
#[derive(Debug, Clone, Copy)]
pub struct LintCode {
    /// The stable lint id, e.g. `"au-W01"`.
    pub code: &'static str,
    /// Severity tier; its letter (F/E/W) matches the code's letter.
    pub severity: Severity,
    /// One-line operator-facing description of what the check looks for.
    pub description: &'static str,
}

/// The catalog of every `au-` lint code, authored in sorted-by-code order for
/// deterministic, byte-stable output. Pinned against the authoritative emitted
/// set by `catalog_covers_exactly_the_authoritative_code_set`.
pub const AU_CODES: &[LintCode] = &[
    LintCode {
        code: "au-E01",
        severity: Severity::Error,
        description: "unreachable rule: it appears after the -e 2 lock line and will never load",
    },
    LintCode {
        code: "au-E02",
        severity: Severity::Error,
        description: "comparison operator is not valid for this field's type; auditctl rejects the rule at load time",
    },
    LintCode {
        code: "au-E03",
        severity: Severity::Error,
        description: "load-aborting duplicate: a structurally identical earlier rule makes auditctl -R abort, so every later rule silently fails to load",
    },
    LintCode {
        code: "au-F01",
        severity: Severity::Fatal,
        description: "rules file does not parse",
    },
    LintCode {
        code: "au-W01",
        severity: Severity::Warning,
        description: "duplicate rule: normalized-equal to an earlier rule in the rules.d/ load order",
    },
    LintCode {
        code: "au-W02",
        severity: Severity::Warning,
        description: "shadowed rule: an earlier, broader rule on the same filter list subsumes it, so it never fires",
    },
    LintCode {
        code: "au-W03",
        severity: Severity::Warning,
        description: "suppression conflict: an exclude/never rule suppresses events an always rule intends to record",
    },
    LintCode {
        code: "au-W04",
        severity: Severity::Warning,
        description: "-D after rules have been loaded discards them; delete-all belongs at the top of the first file",
    },
];

#[cfg(test)]
mod tests {
    use super::AU_CODES;

    /// The authoritative emitted set (session 6a allocation, owner-ratified).
    /// au-W04 is the P2 stretch lint (owner decision D6); if it is cut at
    /// integration, remove it HERE and from the catalog in the same commit.
    const ALL_CODES: &[&str] = &[
        "au-E01", "au-E02", "au-E03", "au-F01", "au-W01", "au-W02", "au-W03", "au-W04",
    ];

    #[test]
    fn catalog_covers_exactly_the_authoritative_code_set() {
        let catalog: Vec<&str> = AU_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, ALL_CODES,
            "catalog must list exactly the authoritative au- codes, sorted"
        );
    }

    #[test]
    fn catalog_is_sorted_by_code() {
        let codes: Vec<&str> = AU_CODES.iter().map(|c| c.code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted, "AU_CODES must be authored in sorted order");
    }

    #[test]
    fn catalog_letters_match_severities() {
        for entry in AU_CODES {
            let letter = entry
                .code
                .strip_prefix("au-")
                .and_then(|s| s.chars().next())
                .unwrap_or_else(|| panic!("malformed code {:?}", entry.code));
            assert_eq!(
                letter,
                entry.severity.letter(),
                "{}: code letter must match severity tier",
                entry.code
            );
        }
    }

    #[test]
    fn catalog_descriptions_are_nonempty() {
        for entry in AU_CODES {
            assert!(
                !entry.description.trim().is_empty(),
                "{}: description must not be empty",
                entry.code
            );
        }
    }
}
