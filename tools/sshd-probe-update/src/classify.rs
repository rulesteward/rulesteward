//! The `Command`-free classifier: turn a keyword's probe stderr into the three
//! lint-family verdicts. A direct, faithful translation of the validated
//! `validate_probe.py` classifier - the substring rules and, critically, the
//! `e04_class` ORDERING (unknown first) must match it exactly, or the drift
//! comparison diverges from the ground-truth reference.

/// The daemon's marker for an unrecognized keyword (sshd-E01's province).
const BAD_CONFIG_OPTION: &str = "Bad configuration option";
/// The daemon's marker for a deprecated keyword (sshd-W04).
const DEPRECATED_OPTION: &str = "Deprecated option";
/// The daemon's marker for a keyword that names a `Match` CONDITION (e.g. the
/// `Match` keyword itself), not a body directive.
const BAD_MATCH_CONDITION: &str = "Bad Match condition";
/// The daemon's marker for a global-only keyword used inside a `Match` block
/// (sshd-E04: silently ignored at runtime).
const NOT_ALLOWED_IN_MATCH: &str = "not allowed within a Match block";

/// E01: a keyword is KNOWN iff `sshd -t -o KW=yes` did NOT report it as a
/// `Bad configuration option`. (An invalid VALUE for a real keyword still counts
/// as known - the daemon recognized the keyword, it just rejected `yes`.)
#[must_use]
pub fn e01_known(opt_stderr: &str) -> bool {
    !opt_stderr.contains(BAD_CONFIG_OPTION)
}

/// W04: a keyword is probe-derivably DEPRECATED iff `sshd -t -o KW=yes` reported
/// it as a `Deprecated option`.
#[must_use]
pub fn w04_probe_deprecated(opt_stderr: &str) -> bool {
    opt_stderr.contains(DEPRECATED_OPTION)
}

/// The E04 classification of a keyword from its `Match`-block probe stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E04Class {
    /// The daemon rejected the keyword outright (`Bad configuration option`).
    /// sshd-E01's province - E04 never fires here (avoids a double-report).
    Unknown,
    /// The keyword names a `Match` CONDITION, not a body directive
    /// (`Bad Match condition`); skip it - it is not an E04 candidate.
    MatchCondition,
    /// A global-only keyword used inside a `Match` block
    /// (`not allowed within a Match block`) - sshd-E04 fires.
    GlobalOnly,
    /// The keyword is permitted inside a `Match` block (no diagnostic marker).
    Permitted,
}

/// Classify a keyword's `Match`-block probe stderr. ORDER MATTERS and mirrors
/// `validate_probe.py`: test unknown FIRST (a keyword the daemon does not know is
/// E01's alone), THEN the Match-condition marker, THEN the global-only marker;
/// anything else is `Permitted`. An empty stderr (no marker) classifies as
/// `Permitted`.
#[must_use]
pub fn e04_class(match_stderr: &str) -> E04Class {
    if match_stderr.contains(BAD_CONFIG_OPTION) {
        E04Class::Unknown
    } else if match_stderr.contains(BAD_MATCH_CONDITION) {
        E04Class::MatchCondition
    } else if match_stderr.contains(NOT_ALLOWED_IN_MATCH) {
        E04Class::GlobalOnly
    } else {
        E04Class::Permitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e01_known_is_true_unless_bad_config() {
        assert!(e01_known(""));
        assert!(e01_known(
            "command-line line 0: unsupported option \"yes\"."
        ));
        assert!(!e01_known(
            "command-line line 0: Bad configuration option: zzzz_bogus"
        ));
    }

    #[test]
    fn w04_probe_deprecated_needs_the_marker() {
        assert!(w04_probe_deprecated(
            "command-line line 0: Deprecated option RSAAuthentication"
        ));
        assert!(!w04_probe_deprecated(""));
        assert!(!w04_probe_deprecated("Bad configuration option: x"));
    }

    #[test]
    fn e04_unknown_takes_priority_over_everything() {
        // A stderr that (pathologically) contains BOTH the unknown marker and the
        // not-allowed marker must classify Unknown - unknown-first ordering.
        let s = "Bad configuration option: x; also not allowed within a Match block";
        assert_eq!(e04_class(s), E04Class::Unknown);
    }

    #[test]
    fn e04_match_condition_is_skipped() {
        assert_eq!(
            e04_class("/tmp/x line 2: Bad Match condition"),
            E04Class::MatchCondition
        );
    }

    #[test]
    fn e04_global_only_fires() {
        assert_eq!(
            e04_class("/tmp/x line 2: Directive 'foo' is not allowed within a Match block"),
            E04Class::GlobalOnly
        );
    }

    #[test]
    fn e04_permitted_when_no_marker() {
        assert_eq!(e04_class(""), E04Class::Permitted);
        assert_eq!(
            e04_class("command-line line 0: unsupported option value"),
            E04Class::Permitted
        );
    }
}
