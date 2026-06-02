//! RHEL target-version model for version-aware fapolicyd linting.
//!
//! `--target rhel8|rhel9|rhel10` selects a fapolicyd dialect so version-divergent
//! checks (fapd-W07 hash-keyword advice, `device=` subject-side validity,
//! `pattern=` value set, hash-value length) can be correct per deployment.
//!
//! The RHEL release name is the user-facing concept; the mapping to a concrete
//! fapolicyd version (and the real behavioral threshold of 1.4.2, which falls
//! BETWEEN rhel8's 1.3.2 and rhel9's 1.4.3) is an internal detail. The variants
//! are declared oldest-first so the derived `Ord` matches release age: a check
//! that lands at fapolicyd 1.4.2+ is expressed as `target >= TargetVersion::Rhel9`.
//!
//! ASSUMPTION - one pin per RHEL MAJOR, "latest minor": each variant maps to the
//! fapolicyd shipped by the LATEST minor of that release. A major spans several
//! fapolicyd builds across its minors (e.g. RHEL 9.0-9.7 shipped 1.1.x WITHOUT
//! `filehash`; 9.8 rebased to 1.4.3), so a host on an older minor than the pin may
//! be linted against behavior its daemon does not yet have. `--target rhelN`
//! therefore means "newest fapolicyd in the rhelN line", not "every rhelN host".
//! Finer-grained pinning is deferred until a real older-minor deployment needs it.
//!
//! This enum is intentionally clap-free; the CLI mirrors it with a `ValueEnum`
//! arg type and converts (the same layering as `TrustSourceFilter` -> `TrustSource`).

use std::fmt;

/// A RHEL-family target release selected via `--target`, declared oldest-first so
/// the derived `Ord` follows release age (and the fapolicyd-1.4.2 threshold is
/// `>= Rhel9`). Maps internally to a concrete fapolicyd version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetVersion {
    /// RHEL 8 family: fapolicyd 1.3.2.
    Rhel8,
    /// RHEL 9 family: fapolicyd 1.4.3.
    Rhel9,
    /// RHEL 10 family: fapolicyd 1.4.5.
    Rhel10,
}

impl TargetVersion {
    /// The concrete fapolicyd version shipped by this RHEL release, as verified
    /// empirically on the img8/img9/img10 containers (see the A3 wave-2 matrix).
    #[must_use]
    pub fn fapolicyd_version(self) -> &'static str {
        match self {
            TargetVersion::Rhel8 => "1.3.2",
            TargetVersion::Rhel9 => "1.4.3",
            TargetVersion::Rhel10 => "1.4.5",
        }
    }
}

impl fmt::Display for TargetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TargetVersion::Rhel8 => "rhel8",
            TargetVersion::Rhel9 => "rhel9",
            TargetVersion::Rhel10 => "rhel10",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::TargetVersion;

    #[test]
    fn fapolicyd_version_maps_each_rhel_release() {
        // Grounded in the A3 wave-2 matrix + I-fapolicyd-release lane:
        // img8=1.3.2, img9=1.4.3, img10=1.4.5 (img10 is 1.4.5, NOT 1.3.3).
        assert_eq!(TargetVersion::Rhel8.fapolicyd_version(), "1.3.2");
        assert_eq!(TargetVersion::Rhel9.fapolicyd_version(), "1.4.3");
        assert_eq!(TargetVersion::Rhel10.fapolicyd_version(), "1.4.5");
    }

    #[test]
    fn ordering_follows_release_age() {
        // The 1.4.2 behavioral threshold sits between rhel8 and rhel9, so all
        // grounded divergences are an "rhel8 vs rhel9+" split: `>= Rhel9`.
        assert!(TargetVersion::Rhel8 < TargetVersion::Rhel9);
        assert!(TargetVersion::Rhel9 < TargetVersion::Rhel10);
        assert!(TargetVersion::Rhel8 < TargetVersion::Rhel10);
    }

    #[test]
    fn display_is_the_rhel_name() {
        assert_eq!(TargetVersion::Rhel8.to_string(), "rhel8");
        assert_eq!(TargetVersion::Rhel9.to_string(), "rhel9");
        assert_eq!(TargetVersion::Rhel10.to_string(), "rhel10");
    }
}
