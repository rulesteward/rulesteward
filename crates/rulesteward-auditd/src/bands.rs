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

use crate::ast::{Action, AuditField, AuditRule, CompareOp, FilterList};

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
    "finit_module",
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
// Tier demotion helpers
// ---------------------------------------------------------------------------

/// Demote one volume tier (HIGH -> MEDIUM -> LOW), saturating at LOW.
///
/// `Negative` is unreachable here (suppressive rules return before any demotion)
/// but is mapped to itself so the match stays total.
fn demote(tier: VolumeTier) -> VolumeTier {
    match tier {
        VolumeTier::High => VolumeTier::Medium,
        VolumeTier::Medium | VolumeTier::Low => VolumeTier::Low,
        VolumeTier::Negative => VolumeTier::Negative,
    }
}

/// Whether an `arch=` field VALUE selects a 32-bit ABI.
///
/// `b32` is auditctl's canonical 32-bit ABI selector (libaudit.c:1419 (audit 3bfa048); `b64` is
/// the 64-bit form). A rule pinned to `b32` fires far less often than its b64
/// sibling on a modern `x86_64` host, so it earns an extra tier demotion (#161,
/// oracle rocky9-arch-paired). Machine-name forms (`i386` etc.) are accepted by
/// auditctl but are normalized and do not appear in generated rules.d files; they
/// are out of scope until grounding shows them in real rules.
fn is_32bit_arch(value: &str) -> bool {
    value == "b32"
}

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
            field_compares,
            ..
        } => {
            // Exclude-list rules suppress record types regardless of action.
            // Never-action rules suppress matching events.
            if *list == FilterList::Exclude || *action == Action::Never {
                return (VolumeTier::Negative, Direction::Suppressive);
            }

            // Filesystem-list rules (`-a always,filesystem`) audit by filesystem
            // TYPE: a broad class of operations. The tier is MEDIUM regardless of
            // the `fstype` value or any `-F` narrowing - it is content-INDEPENDENT
            // (unlike the path-based no-`-S` rules, whose volume depends on which
            // binary/file is watched; those are content-aware and tracked as the
            // non-deterministic #140 Finding 1). Grounded in corpus
            // rocky9-filesystem-list (#140 Finding 2).
            if *list == FilterList::Filesystem {
                return (VolumeTier::Medium, Direction::Additive);
            }

            // Additive rule: classify by syscall name and narrowing. A `-C`
            // inter-field comparison narrows the syscall exactly like a `-F`
            // filter (oracle rocky9-field-compare, #161), so either one counts.
            let is_narrowed = !fields.is_empty() || !field_compares.is_empty();

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
            let mut tier = if is_narrowed {
                demote(base_tier)
            } else {
                base_tier
            };

            // A rule PINNED to the 32-bit ABI (`-F arch=b32`) fires far less
            // often than its b64 sibling on a modern x86_64 host, so it demotes
            // ONE more tier (#161, oracle rocky9-arch-paired). The pin is an
            // EQUALITY on `b32`: `arch=b64` selects the dominant ABI and
            // `arch!=b32` selects the dominant ABI by exclusion - neither is
            // extra-demoted, so the operator matters, not just the value.
            if fields.iter().any(|f| {
                f.field == AuditField::Arch && f.op == CompareOp::Eq && is_32bit_arch(&f.value)
            }) {
                tier = demote(tier);
            }

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AuditField, CompareOp, FieldFilter};

    /// Build an additive `exit`-list syscall rule with the given syscalls and
    /// `-F` field filters (no key, no prepend).
    fn syscall_rule(syscalls: &[&str], fields: Vec<FieldFilter>) -> AuditRule {
        AuditRule::Syscall {
            list: FilterList::Exit,
            action: Action::Always,
            syscalls: syscalls.iter().map(ToString::to_string).collect(),
            fields,
            field_compares: vec![],
            prepend: false,
            key: None,
        }
    }

    fn ff(field: AuditField, op: CompareOp, value: &str) -> FieldFilter {
        FieldFilter {
            field,
            op,
            value: value.to_string(),
        }
    }

    // -- finit_module (#140 Finding 2, rocky9-key-collision) -----------------

    /// `-S init_module -S finit_module` must classify LOW: both are rare
    /// module-load syscalls (`finit_module` loads a module from an fd, the
    /// modern variant of `init_module`). Before the fix `finit_module` was
    /// absent from `LOW_SYSCALLS`, so the all-low check failed and the rule
    /// classified MEDIUM.
    #[test]
    fn module_load_syscalls_are_low_volume() {
        let rule = syscall_rule(&["init_module", "finit_module"], vec![]);
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Low, Direction::Additive),
            "init_module + finit_module are both rare module-load syscalls -> LOW"
        );
    }

    /// `finit_module` alone is also LOW (guards against only adding it to a
    /// multi-syscall path).
    #[test]
    fn finit_module_alone_is_low_volume() {
        let rule = syscall_rule(&["finit_module"], vec![]);
        assert_eq!(classify_rule(&rule).0, VolumeTier::Low);
    }

    // -- filesystem-list (#140 Finding 2, rocky9-filesystem-list) -------------

    /// A `filesystem`-list rule audits by filesystem TYPE (a broad class of
    /// operations) and is MEDIUM regardless of the `fstype` value or any `-F`
    /// narrowing. Before the fix it had no `-S`, so it classified LOW.
    #[test]
    fn filesystem_list_rule_is_medium_volume() {
        let rule = AuditRule::Syscall {
            list: FilterList::Filesystem,
            action: Action::Always,
            syscalls: vec![],
            fields: vec![
                ff(AuditField::Fstype, CompareOp::Eq, "ext4"),
                ff(AuditField::Auid, CompareOp::Ge, "1000"),
            ],
            field_compares: vec![],
            prepend: false,
            key: None,
        };
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Medium, Direction::Additive),
            "filesystem-list rule -> MEDIUM (broad, content-independent)"
        );
    }

    /// The filesystem-list MEDIUM tier is independent of the `fstype` VALUE
    /// (content-independence: this is a deterministic fix, unlike the path-based
    /// Finding-1 cases).
    #[test]
    fn filesystem_list_tier_independent_of_fstype_value() {
        for fstype in ["ext4", "xfs", "btrfs"] {
            let rule = AuditRule::Syscall {
                list: FilterList::Filesystem,
                action: Action::Always,
                syscalls: vec![],
                fields: vec![ff(AuditField::Fstype, CompareOp::Eq, fstype)],
                field_compares: vec![],
                prepend: false,
                key: None,
            };
            assert_eq!(
                classify_rule(&rule).0,
                VolumeTier::Medium,
                "filesystem-list tier must not depend on fstype={fstype}"
            );
        }
    }

    /// A `filesystem`-list rule with `never`/`exclude` semantics is still
    /// suppressive: the filesystem MEDIUM branch must NOT override the
    /// suppressive check. (`-a never,filesystem`.)
    #[test]
    fn filesystem_list_never_action_is_suppressive() {
        let rule = AuditRule::Syscall {
            list: FilterList::Filesystem,
            action: Action::Never,
            syscalls: vec![],
            fields: vec![ff(AuditField::Fstype, CompareOp::Eq, "ext4")],
            field_compares: vec![],
            prepend: false,
            key: None,
        };
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Negative, Direction::Suppressive),
            "never-action filesystem rule must stay suppressive"
        );
    }

    /// A non-filesystem `exit`-list rule with `-F` fields but no `-S` stays LOW:
    /// the filesystem fix must NOT broaden to all no-syscall field-filter rules
    /// (the path-based MEDIUM cases are content-aware Finding-1, deliberately
    /// left unfixed).
    #[test]
    fn exit_list_field_filter_only_stays_low() {
        let rule = syscall_rule(&[], vec![ff(AuditField::Auid, CompareOp::Ge, "1000")]);
        assert_eq!(
            classify_rule(&rule).0,
            VolumeTier::Low,
            "no-S exit field-filter rule stays LOW (not broadened by the filesystem fix)"
        );
    }

    // -- arch-aware demotion (#161, rocky9-arch-paired) -----------------------

    /// `-F arch=b32 -S execve -F auid>=1000` classifies LOW: a 32-bit-ABI execve
    /// fires far less often than the b64 form on a modern `x86_64` host. execve is
    /// HIGH, the `-F` narrowing demotes to MEDIUM, and the `arch=b32` selector
    /// demotes ONE more tier to LOW (oracle rocky9-arch-paired). Before #161 the
    /// classifier ignored the arch field and returned MEDIUM.
    #[test]
    fn arch_b32_execve_narrowed_demotes_to_low() {
        let rule = syscall_rule(
            &["execve"],
            vec![
                ff(AuditField::Arch, CompareOp::Eq, "b32"),
                ff(AuditField::Auid, CompareOp::Ge, "1000"),
            ],
        );
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Low, Direction::Additive),
            "arch=b32 narrowed execve -> LOW (rare 32-bit ABI on a modern host)"
        );
    }

    /// The b64 sibling of the paired rule stays MEDIUM: arch=b64 selects the
    /// DOMINANT ABI and must NOT trigger the extra demotion. Guards against the
    /// b32 fix accidentally demoting every arch-narrowed rule.
    #[test]
    fn arch_b64_execve_narrowed_stays_medium() {
        let rule = syscall_rule(
            &["execve"],
            vec![
                ff(AuditField::Arch, CompareOp::Eq, "b64"),
                ff(AuditField::Auid, CompareOp::Ge, "1000"),
            ],
        );
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Medium, Direction::Additive),
            "arch=b64 narrowed execve -> MEDIUM (the dominant ABI is not extra-demoted)"
        );
    }

    /// `arch=b32` as the ONLY field still demotes twice: execve HIGH -> MEDIUM
    /// (the arch field counts as narrowing) -> LOW (the b32 selector). Pins the
    /// documented edge case so the intent is explicit, not incidental.
    #[test]
    fn arch_b32_alone_execve_demotes_to_low() {
        let rule = syscall_rule(
            &["execve"],
            vec![ff(AuditField::Arch, CompareOp::Eq, "b32")],
        );
        assert_eq!(
            classify_rule(&rule).0,
            VolumeTier::Low,
            "arch=b32 alone on execve -> LOW (narrowed then b32-demoted)"
        );
    }

    /// The b32 demotion saturates at LOW: applied to an already-LOW syscall
    /// (`mount`) it does not underflow past `Low`.
    #[test]
    fn arch_b32_on_low_syscall_saturates_low() {
        let rule = syscall_rule(&["mount"], vec![ff(AuditField::Arch, CompareOp::Eq, "b32")]);
        assert_eq!(
            classify_rule(&rule).0,
            VolumeTier::Low,
            "arch=b32 on a LOW syscall stays LOW (demotion saturates)"
        );
    }

    /// `-F arch!=b32` selects the NON-32-bit (dominant) ABI, exactly like
    /// `arch=b64`, so it must NOT trigger the extra demotion: execve HIGH ->
    /// MEDIUM (narrowed) and stops there. The b32 demotion keys on PINNING to
    /// 32-bit (`arch == b32`), so it must inspect the operator, not just the
    /// value string `"b32"`. (Adversarial review #161: an operator-blind check
    /// would wrongly demote this to LOW.)
    #[test]
    fn arch_ne_b32_execve_stays_medium() {
        let rule = syscall_rule(
            &["execve"],
            vec![
                ff(AuditField::Arch, CompareOp::Ne, "b32"),
                ff(AuditField::Auid, CompareOp::Ge, "1000"),
            ],
        );
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Medium, Direction::Additive),
            "arch!=b32 selects the dominant ABI -> MEDIUM (only arch=b32 extra-demotes)"
        );
    }

    // -- -C field-comparison narrowing (#161, rocky9-field-compare) -----------

    /// A `-C` inter-field comparison narrows the syscall exactly like a `-F`
    /// filter even when there are NO `-F` fields: `-S execve -C uid!=euid` is
    /// HIGH demoted once to MEDIUM (oracle rocky9-field-compare, rule A). Before
    /// #161 a `-C`-only rule had empty `fields`, so `is_narrowed` was false and it
    /// classified HIGH.
    #[test]
    fn field_comparison_narrows_execve_to_medium() {
        use crate::ast::FieldComparison;
        let rule = AuditRule::Syscall {
            list: FilterList::Exit,
            action: Action::Always,
            syscalls: vec!["execve".to_string()],
            fields: vec![],
            field_compares: vec![FieldComparison {
                left: AuditField::Uid,
                op: CompareOp::Ne,
                right: AuditField::Euid,
            }],
            prepend: false,
            key: None,
        };
        assert_eq!(
            classify_rule(&rule),
            (VolumeTier::Medium, Direction::Additive),
            "execve narrowed by a -C comparison -> MEDIUM (a -C narrows like a -F)"
        );
    }
}
