//! RHEL target-version model for version-aware selinux STIG linting (#520).
//!
//! `--target rhel8|rhel9|rhel10` selects which STIG boot-configuration checks
//! (se-W01/se-W02) and control-family rows ([`crate::stig`]) apply. The variant
//! order is oldest-first (mirroring `rulesteward_fapolicyd::TargetVersion`) so
//! the derived `Ord` follows release age, even though today's se-W01/se-W02
//! gating is a flat per-target match rather than a `>=` threshold.
//!
//! This enum is intentionally clap-free; the CLI mirrors it with a
//! `TargetVersionArg` `ValueEnum` and converts via a `From` impl in
//! `rulesteward-cli/src/cli/mod.rs` (the same layering as
//! `TrustSourceFilter` -> `TrustSource`, and the 5th copy of the
//! `TargetVersionArg` -> per-backend `TargetVersion` pattern: fapolicyd, sshd,
//! sysctld, auditd, and now selinux).

/// A RHEL-family target release selected via `--target`, declared oldest-first
/// so the derived `Ord` follows release age.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetVersion {
    /// RHEL 8 family.
    Rhel8,
    /// RHEL 9 family.
    Rhel9,
    /// RHEL 10 family.
    Rhel10,
}

#[cfg(test)]
mod tests {
    use super::TargetVersion;

    #[test]
    fn ordering_follows_release_age() {
        assert!(TargetVersion::Rhel8 < TargetVersion::Rhel9);
        assert!(TargetVersion::Rhel9 < TargetVersion::Rhel10);
        assert!(TargetVersion::Rhel8 < TargetVersion::Rhel10);
    }

    #[test]
    fn variants_are_distinct_and_copy() {
        // Copy + Eq: constructing and comparing does not consume the value.
        let a = TargetVersion::Rhel9;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(TargetVersion::Rhel8, TargetVersion::Rhel9);
        assert_ne!(TargetVersion::Rhel9, TargetVersion::Rhel10);
        assert_ne!(TargetVersion::Rhel8, TargetVersion::Rhel10);
    }
}
