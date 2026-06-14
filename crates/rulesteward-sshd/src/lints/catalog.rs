//! Machine-readable catalog of the `sshd_config` (`sshd-`) lint codes: each code's
//! id, severity tier, and a short operator-facing description.
//!
//! Mirrors the auditd catalog (the crate that OWNS the codes carries the catalog,
//! inside the mutation `examine_globs`): no `Condition` machinery, since there is
//! no SARIF for sshd (locked CC-4: SARIF is `fapolicyd lint` only).
//!
//! # Frozen in Phase 0
//! The catalog lists the FULL planned sshd taxonomy now, even though only
//! `sshd-F01` (parse failure) is emitted today. Freezing the whole list here in
//! Phase 0 means the later parallel lint pipelines start emitting a code that is
//! ALREADY catalogued - they never edit this shared file, which keeps the
//! milestone fan-out conflict-free. The remaining codes land per the wave plan
//! tracked under epic #149.
//!
//! # Numbering note
//! `sshd-F01` is the parse-failure Fatal, matching every other backend
//! (`fapd-F01`, `au-F01`). The research sketch (E2 "Module 1") used `sshd-F01`
//! for the drop-in-fragmentation lint; that lint is `sshd-F02` here so the
//! parse-failure code aligns across backends.

use rulesteward_core::Severity;

/// One catalogued `sshd-` lint code: its stable id, severity tier, and a short
/// operator-facing description.
#[derive(Debug, Clone, Copy)]
pub struct LintCode {
    /// The stable lint id, e.g. `"sshd-W01"`.
    pub code: &'static str,
    /// Severity tier; its letter (F/E/W) matches the code's letter.
    pub severity: Severity,
    /// One-line operator-facing description of what the check looks for.
    pub description: &'static str,
}

/// The catalog of every `sshd-` lint code, authored in sorted-by-code order for
/// deterministic, byte-stable output. Pinned against the frozen taxonomy by
/// `catalog_is_the_frozen_taxonomy`.
///
/// Severities follow the SELint-style letter scheme (`F`/`E`/`W`). The emitting pass (and
/// its tracking issue under epic #149) for each not-yet-implemented code is named
/// in the per-family `lints/` modules.
pub const SSHD_CODES: &[LintCode] = &[
    LintCode {
        code: "sshd-E01",
        severity: Severity::Error,
        description: "unknown directive: not a recognized sshd_config keyword for the target OpenSSH version",
    },
    LintCode {
        code: "sshd-E02",
        severity: Severity::Error,
        description: "duplicate global directive: a later line silently overrides an earlier one (sshd takes the first value for most keywords)",
    },
    LintCode {
        code: "sshd-E03",
        severity: Severity::Error,
        description: "Include directive references a path or glob that resolves to nothing",
    },
    LintCode {
        code: "sshd-E04",
        severity: Severity::Error,
        description: "directive is not permitted inside a Match block and is silently ignored at runtime",
    },
    LintCode {
        code: "sshd-F01",
        severity: Severity::Fatal,
        description: "sshd_config file does not parse",
    },
    LintCode {
        code: "sshd-F02",
        severity: Severity::Fatal,
        description: "drop-in sshd_config.d/*.conf fragment overrides a required global directive",
    },
    LintCode {
        code: "sshd-W01",
        severity: Severity::Warning,
        description: "STIG-required directive is missing from the configuration",
    },
    LintCode {
        code: "sshd-W02",
        severity: Severity::Warning,
        description: "directive value is weaker than the STIG baseline for the target",
    },
    LintCode {
        code: "sshd-W03",
        severity: Severity::Warning,
        description: "weak algorithm in Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms (CBC, MD5/SHA1, group1, ssh-rsa)",
    },
    LintCode {
        code: "sshd-W04",
        severity: Severity::Warning,
        description: "directive is deprecated or removed in the target OpenSSH version",
    },
    LintCode {
        code: "sshd-W05",
        severity: Severity::Warning,
        description: "Match block overrides a required global directive in a more permissive direction",
    },
    LintCode {
        code: "sshd-W06",
        severity: Severity::Warning,
        description: "algorithm-list prefix operator (+/-/^) may reintroduce a weak default algorithm",
    },
];

#[cfg(test)]
mod tests {
    use super::SSHD_CODES;

    /// The frozen sshd taxonomy (Phase 0, epic #149). Every code the backend will
    /// ever emit across the wave plan is listed here in sorted order; the parallel
    /// lint pipelines start emitting an already-catalogued code rather than editing
    /// this shared file. Update this list ONLY when the taxonomy itself changes.
    const FROZEN_CODES: &[&str] = &[
        "sshd-E01", "sshd-E02", "sshd-E03", "sshd-E04", "sshd-F01", "sshd-F02", "sshd-W01",
        "sshd-W02", "sshd-W03", "sshd-W04", "sshd-W05", "sshd-W06",
    ];

    #[test]
    fn catalog_is_the_frozen_taxonomy() {
        let catalog: Vec<&str> = SSHD_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, FROZEN_CODES,
            "SSHD_CODES must list exactly the frozen sshd- taxonomy, sorted"
        );
    }

    #[test]
    fn catalog_is_sorted_by_code() {
        let codes: Vec<&str> = SSHD_CODES.iter().map(|c| c.code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted, "SSHD_CODES must be authored in sorted order");
    }

    #[test]
    fn catalog_letters_match_severities() {
        for entry in SSHD_CODES {
            let letter = entry
                .code
                .strip_prefix("sshd-")
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
        for entry in SSHD_CODES {
            assert!(
                !entry.description.trim().is_empty(),
                "{}: description must not be empty",
                entry.code
            );
        }
    }

    #[test]
    fn parse_failure_code_is_catalogued() {
        // Phase 0 emits exactly one code, sshd-F01 (parse failure). It MUST be in
        // the catalog (the emitted-subset-of-catalogued direction the milestone
        // relies on). The fan-out adds emitters for the rest, each already here.
        assert!(
            SSHD_CODES.iter().any(|c| c.code == "sshd-F01"),
            "the one Phase-0-emitted code must be catalogued"
        );
    }
}
