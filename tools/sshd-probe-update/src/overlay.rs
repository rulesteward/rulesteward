//! The W04 hand-curated overlay: the honesty layer over the probe.
//!
//! Four keywords are in the shipped sshd-W04 deprecated set BY POLICY yet the
//! daemon does NOT emit `Deprecated option` for them (it parses them cleanly, or
//! rejects only the value), so a probe can never derive them. They are modelled
//! as [`W04Provenance::HandCuratedOverlay`]; every other W04 entry is
//! [`W04Provenance::ProbeDerived`]. The drift comparison ([`crate::derive`]) must
//! therefore (a) subtract the overlays from the probe-derivable expected set so
//! they are never reported as "missing from probe", and (b) advisory-verify that
//! each overlay still parses clean - a flip to `Deprecated option` is an advisory
//! note (the entry became probe-derivable), NOT gate-failing drift.
//!
//! `skeyauthentication` is NOT an overlay: it is version-split and
//! probe-derivable (deprecated on rhel8, accepted on rhel9/10), already handled
//! by `deprecated_keywords(target)` returning it only for rhel8.

use crate::classify::w04_probe_deprecated;

/// The four W04 entries that parse CLEAN and so cannot be probe-derived.
pub const CLEAN_PARSE_OVERLAY: &[&str] = &[
    "protocol",
    "challengeresponseauthentication",
    "pubkeyacceptedkeytypes",
    "hostbasedacceptedkeytypes",
];

/// The provenance of a shipped W04 entry: derivable from a live probe, or a
/// hand-curated policy entry the probe cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W04Provenance {
    /// The daemon emits `Deprecated option`, so a probe derives it directly.
    ProbeDerived,
    /// In the W04 set by policy, but parses clean - hand-curated, not probe-derivable.
    HandCuratedOverlay,
}

/// Whether `kw` is one of the four clean-parse overlays.
#[must_use]
pub fn is_overlay(kw: &str) -> bool {
    CLEAN_PARSE_OVERLAY.contains(&kw)
}

/// The provenance of a W04 keyword.
#[must_use]
pub fn provenance(kw: &str) -> W04Provenance {
    if is_overlay(kw) {
        W04Provenance::HandCuratedOverlay
    } else {
        W04Provenance::ProbeDerived
    }
}

/// The result of advisory-verifying one overlay against its `opt` probe stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayVerdict {
    /// The overlay still parses clean (expected) - no `Deprecated option`.
    StillClean,
    /// The overlay now emits `Deprecated option` - it became probe-derivable.
    /// Advisory: the maintainer could reclassify it as `ProbeDerived`.
    NowDeprecated,
    /// The overlay was not present in the transcript - could not verify.
    NotProbed,
}

/// Advisory-verify a single overlay `kw` given its `opt`-probe stderr, if any.
/// `opt_stderr = None` means the keyword had no `opt` reply in the transcript.
#[must_use]
pub fn verify_overlay(opt_stderr: Option<&str>) -> OverlayVerdict {
    match opt_stderr {
        None => OverlayVerdict::NotProbed,
        Some(s) if w04_probe_deprecated(s) => OverlayVerdict::NowDeprecated,
        Some(_) => OverlayVerdict::StillClean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_overlays_are_recognized() {
        for kw in CLEAN_PARSE_OVERLAY {
            assert!(is_overlay(kw), "{kw} should be an overlay");
            assert_eq!(provenance(kw), W04Provenance::HandCuratedOverlay);
        }
        assert_eq!(CLEAN_PARSE_OVERLAY.len(), 4);
    }

    #[test]
    fn skeyauthentication_is_not_an_overlay() {
        // Version-split + probe-derivable, handled by deprecated_keywords(), not here.
        assert!(!is_overlay("skeyauthentication"));
        assert_eq!(
            provenance("skeyauthentication"),
            W04Provenance::ProbeDerived
        );
    }

    #[test]
    fn a_normal_deprecated_keyword_is_probe_derived() {
        assert_eq!(provenance("rsaauthentication"), W04Provenance::ProbeDerived);
    }

    #[test]
    fn verify_overlay_classifies_the_three_cases() {
        assert_eq!(verify_overlay(Some("")), OverlayVerdict::StillClean);
        assert_eq!(
            verify_overlay(Some("command-line line 0: Bad key types 'yes'.")),
            OverlayVerdict::StillClean
        );
        assert_eq!(
            verify_overlay(Some("Deprecated option Protocol")),
            OverlayVerdict::NowDeprecated
        );
        assert_eq!(verify_overlay(None), OverlayVerdict::NotProbed);
    }
}
