//! auditd cost band classifier.
//!
//! Filled by pipeline P2 (issue #89).
//!
//! # Grounding
//! - Volume tiers (HIGH/MEDIUM/LOW/NEGATIVE): f3 section 3.5.
//! - Rate-band defaults (low/typical/high): f3 section 6.
//!   - Unrestricted execve: 5k / 50k / 500k events/day.
//!   - Broad dir watch (`-w /dir/ -p wa`): 1k / 20k / 200k events/day.
//!   - Narrowed syscall (`-F auid>=1000` etc.): ~0.3x the unrestricted form.
//!   - Control / `never` / `exclude` list: 0.
//! - Never/exclude direction is SUPPRESSIVE (f3 section 3.5).

use crate::ast::AuditRule;

/// Volume tier for a single rule.
///
/// `Negative` means the rule SUPPRESSES events (never-action or exclude-list).
/// The cost model must NOT add volume for a Negative rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VolumeTier {
    /// High-volume: unrestricted execve, broad dir watches, perm=r/w on wide trees.
    High,
    /// Medium-volume: narrowed syscall rules (e.g. `-F auid>=1000`), file watches.
    Medium,
    /// Low-volume: rarely-called syscalls (adjtimex, settimeofday, mount), single-file
    /// watches on stable paths.
    Low,
    /// Zero additive volume; suppresses events (never action or exclude list).
    Negative,
}

/// Whether a rule adds to or reduces event volume.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Additive,
    Suppressive,
}

/// Events/day estimate as a low/typical/high band.
///
/// All three fields are 0 for `Negative` / suppressive rules.
/// Fields are `f64` because per-rule aggregation may involve fractional scaling
/// (e.g. 0.3x the unrestricted form per f3 section 6).
#[derive(Debug, Clone, PartialEq)]
pub struct RateBand {
    pub low: f64,
    pub typical: f64,
    pub high: f64,
}

impl RateBand {
    /// The zero band: used for control/never/exclude rules.
    pub const ZERO: RateBand = RateBand {
        low: 0.0,
        typical: 0.0,
        high: 0.0,
    };
}

/// Classify a single rule's volume tier and direction.
///
/// This is a pure function over the AST (no I/O, no state).
/// Never / exclude-list rules return `Negative` + `Suppressive`.
/// Control rules return `Negative` + `Suppressive`.
#[must_use]
pub fn classify_rule(_rule: &AuditRule) -> (VolumeTier, Direction) {
    todo!("P2 #89 fills band classifier")
}

/// Return the default events/day rate band for a rule.
///
/// Bands are labeled assumptions (f3 section 6); they are only used when
/// no `--from-log` measurement is available.
/// Negative/suppressive rules always return `RateBand::ZERO`.
#[must_use]
pub fn default_rate_band(_rule: &AuditRule) -> RateBand {
    todo!("P2 #89 fills band classifier")
}
