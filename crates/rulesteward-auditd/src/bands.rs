//! auditd cost band classifier.
//!
//! Issue #89 -- pipeline P2.
//!
//! # Grounding
//! - Volume tiers (HIGH/MEDIUM/LOW/NEGATIVE): f3 section 3.5.
//! - Rate-band defaults (low/typical/high): f3 section 6.
//!   - Unrestricted execve: 5k / 50k / 500k events/day.
//!   - Broad dir watch (`-w /dir/ -p wa`): 1k / 20k / 200k events/day.
//!   - Narrowed syscall (`-F auid>=1000` etc.): ~0.3x the unrestricted form.
//!   - Control / `never` / `exclude` list: 0.
//! - Never/exclude direction is SUPPRESSIVE (f3 section 3.5).

use crate::ast::{Action, AuditRule, FilterList};

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

// ---------------------------------------------------------------------------
// Syscalls that are HIGH-volume when unrestricted (f3 section 3.5)
// ---------------------------------------------------------------------------

/// Syscalls classified as HIGH-volume when unrestricted.
///
/// These fire on common, high-frequency operations (every process start, broad
/// file access). Grounded in f3 section 3.5 + [VM] openat burst demonstration.
const HIGH_SYSCALLS: &[&str] = &[
    "execve", "execveat", "openat", "openat2", "open", "read", "write", "close", "mmap", "mprotect",
];

/// Syscalls classified as LOW-volume: rarely called (f3 section 3.5).
const LOW_SYSCALLS: &[&str] = &[
    "adjtimex",
    "settimeofday",
    "clock_settime",
    "mount",
    "umount2",
    "reboot",
    "swapon",
    "swapoff",
    "syslog",
    "kexec_load",
    "init_module",
    "delete_module",
    "acct",
    "nfsservctl",
    "setdomainname",
    "sethostname",
    "pivot_root",
    "ioperm",
    "iopl",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classify a single rule's volume tier and direction.
///
/// This is a pure function over the AST (no I/O, no state).
/// Never / exclude-list rules return `Negative` + `Suppressive`.
/// Control rules return `Negative` + `Suppressive`.
#[must_use]
pub fn classify_rule(rule: &AuditRule) -> (VolumeTier, Direction) {
    match rule {
        // Control rules configure the subsystem; zero runtime events.
        AuditRule::Control(_) => (VolumeTier::Negative, Direction::Suppressive),

        // Watch rules: directory = HIGH (recursive); single-file = MEDIUM.
        AuditRule::Watch { is_dir, .. } => {
            let tier = if *is_dir {
                VolumeTier::High
            } else {
                VolumeTier::Medium
            };
            (tier, Direction::Additive)
        }

        AuditRule::Syscall {
            action,
            list,
            syscalls,
            fields,
            ..
        } => {
            // Exclude-list rules suppress record types regardless of action.
            // Never-action rules suppress matching events.
            if *list == FilterList::Exclude || *action == Action::Never {
                return (VolumeTier::Negative, Direction::Suppressive);
            }

            // Additive rule: classify by syscall name and narrowing.
            let is_narrowed = !fields.is_empty();

            // Determine base tier from syscall name(s).
            let base_tier = if syscalls.is_empty() {
                // Pure field-filter rule (no -S): treat as Low (rare, narrow).
                VolumeTier::Low
            } else if syscalls.iter().any(|s| HIGH_SYSCALLS.contains(&s.as_str())) {
                VolumeTier::High
            } else if syscalls.iter().all(|s| LOW_SYSCALLS.contains(&s.as_str())) {
                VolumeTier::Low
            } else {
                // Unknown/unlisted syscalls: conservatively Medium.
                VolumeTier::Medium
            };

            // Narrowing with -F demotes one tier (HIGH -> MEDIUM; MEDIUM -> LOW; LOW stays LOW).
            let tier = if is_narrowed {
                match base_tier {
                    VolumeTier::High => VolumeTier::Medium,
                    VolumeTier::Medium | VolumeTier::Low => VolumeTier::Low,
                    VolumeTier::Negative => VolumeTier::Negative,
                }
            } else {
                base_tier
            };

            (tier, Direction::Additive)
        }
    }
}

/// Return the default events/day rate band for a rule.
///
/// Bands are labeled assumptions (f3 section 6); they are only used when
/// no `--from-log` measurement is available.
/// Negative/suppressive rules always return `RateBand::ZERO`.
#[must_use]
pub fn default_rate_band(rule: &AuditRule) -> RateBand {
    let (tier, direction) = classify_rule(rule);

    if direction == Direction::Suppressive {
        return RateBand::ZERO;
    }

    match tier {
        VolumeTier::Negative => RateBand::ZERO,

        // Unrestricted HIGH: f3 section 6 - 5k / 50k / 500k events/day.
        VolumeTier::High => RateBand {
            low: 5_000.0,
            typical: 50_000.0,
            high: 500_000.0,
        },

        // Narrowed rule (~0.3x the unrestricted form): f3 section 6.
        // 5k*0.3=1.5k / 50k*0.3=15k / 500k*0.3=150k
        VolumeTier::Medium => RateBand {
            low: 1_500.0,
            typical: 15_000.0,
            high: 150_000.0,
        },

        // Low-volume: rarely-called syscalls. f3 section 3.5.
        // Very small band: 1 / 10 / 100 events/day.
        VolumeTier::Low => RateBand {
            low: 1.0,
            typical: 10.0,
            high: 100.0,
        },
    }
}
