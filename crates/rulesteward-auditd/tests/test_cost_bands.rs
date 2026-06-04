//! RED barrier tests for the cost model + band classifier (#88, #89).
//!
//! # Grounding
//! - Byte constant 1200 B/event ENRICHED LOCKED 2026-06-03 (issue #88 body).
//! - RAW factor 0.75x (f3 section 3.4).
//! - Decimal GB = bytes / 1e9 (f3 section 4.1). NOT GiB (factor 1.073... difference ~7%).
//! - cost/month = gb/day * 30.4 * price/GB (f3 section 4.1).
//! - Unrestricted execve rate band: low 5k / typical 50k / high 500k (f3 section 6).
//! - Broad dir watch rate band: low 1k / typical 20k / high 200k (f3 section 6).
//! - Narrowed rule (~0.3x): low 1.5k / typical 15k / high 150k (f3 section 6).
//! - Control / never / exclude: 0 events/day (f3 section 6).
//! - Oracle values from corpus `rocky9-execve-unrestricted/oracle/cost-band.json`.
//! - Adversarial trap: never-action and exclude-list rules must be SUPPRESSIVE (0 volume).

use rulesteward_auditd::{
    Action, AuditRule, ControlRule, Direction, FilterList, LogFormat, PermBits, RateBand,
    VolumeTier,
    bands::{classify_rule, default_rate_band},
    cost::{bytes_per_event, compute_cost_band, sum_rate_bands},
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn syscall_always_exit(syscalls: Vec<&str>, key: Option<&str>) -> AuditRule {
    AuditRule::Syscall {
        list: FilterList::Exit,
        action: Action::Always,
        syscalls: syscalls.into_iter().map(str::to_string).collect(),
        fields: vec![],
        prepend: false,
        key: key.map(str::to_string),
    }
}

fn syscall_never_exit(syscalls: Vec<&str>) -> AuditRule {
    AuditRule::Syscall {
        list: FilterList::Exit,
        action: Action::Never,
        syscalls: syscalls.into_iter().map(str::to_string).collect(),
        fields: vec![],
        prepend: false,
        key: None,
    }
}

fn syscall_exclude(msgtype: &str) -> AuditRule {
    use rulesteward_auditd::{AuditField, CompareOp, FieldFilter};
    AuditRule::Syscall {
        list: FilterList::Exclude,
        action: Action::Always,
        syscalls: vec![],
        fields: vec![FieldFilter {
            field: AuditField::MsgType,
            op: CompareOp::Eq,
            value: msgtype.to_string(),
        }],
        prepend: false,
        key: None,
    }
}

fn watch_wa(path: &str, is_dir: bool, key: Option<&str>) -> AuditRule {
    AuditRule::Watch {
        path: path.to_string(),
        perms: PermBits {
            write: true,
            attr: true,
            ..Default::default()
        },
        key: key.map(str::to_string),
        is_dir,
    }
}

fn control_delete_all() -> AuditRule {
    AuditRule::Control(ControlRule::DeleteAll)
}

// --------------------------------------------------------------------------
// bytes_per_event: LOCKED constants (issue #88)
// --------------------------------------------------------------------------

/// ENRICHED format -> 1200 B/event (locked constant, f3 section 3.3, Wave-1b).
///
/// A wrong impl (e.g. returning 1024 for "round KB", or 1024*1024 for MB)
/// would fail this test. The constant is LOAD-BEARING for all cost math.
#[test]
fn bytes_per_event_enriched_is_1200() {
    assert_eq!(
        bytes_per_event(LogFormat::Enriched),
        1200,
        "ENRICHED constant must be 1200 B/event (locked 2026-06-03)"
    );
}

/// RAW format -> 900 B/event (1200 * 0.75 = 900, f3 section 3.4).
///
/// A wrong impl returning the same value for both formats silently overstates
/// RAW-log costs by 33%.
#[test]
fn bytes_per_event_raw_is_900() {
    assert_eq!(
        bytes_per_event(LogFormat::Raw),
        900,
        "RAW constant must be 900 B/event (1200 * 0.75 per f3 section 3.4)"
    );
}

/// ENRICHED and RAW must be distinct (catches a wrong impl that returns the same value).
#[test]
fn bytes_per_event_enriched_ne_raw() {
    assert_ne!(
        bytes_per_event(LogFormat::Enriched),
        bytes_per_event(LogFormat::Raw),
        "ENRICHED and RAW byte constants must differ"
    );
}

// --------------------------------------------------------------------------
// Decimal GB math: NOT GiB (issue #88)
// --------------------------------------------------------------------------

/// 1 billion bytes = 1.0 GB (decimal, 10^9). NOT 1 GiB (2^30 = 1,073,741,824).
/// A GiB mistake produces a ~7% undercount on cost estimates.
/// Grounded: f3 section 4.1, "decimal GB, matching SIEM per GB billing".
#[test]
fn compute_cost_band_uses_decimal_gb_not_gib() {
    // 1,000,000,000 events * 1 B/event = 1 GB/day exactly if decimal GB is used.
    // Construct a band where typical events/day * bytes/event = exactly 1e9 bytes.
    // bytes_per_event(Enriched) = 1200.
    // 1e9 / 1200 = 833_333.333... events/day = ~833k. Use a round number instead:
    // 1_000_000 events * 1200 B = 1.2e9 bytes = 1.2 GB exactly.
    let band = RateBand {
        low: 0.0,
        typical: 1_000_000.0,
        high: 0.0,
    };
    let cost = compute_cost_band(&band, LogFormat::Enriched, 5.00);
    // gb_per_day typical = 1e6 * 1200 / 1e9 = 1.2 (decimal GB).
    // If GiB was used: 1e6 * 1200 / 1_073_741_824 ≈ 1.1176 (WRONG).
    let expected_gb = 1.2_f64;
    let actual_gb = cost.gb_per_day.typical;
    let diff = (actual_gb - expected_gb).abs();
    assert!(
        diff < 0.001,
        "gb_per_day.typical must be {expected_gb} (decimal 10^9); got {actual_gb} (diff={diff}). \
         GiB would give ~1.1176 -- if you see that, the implementation is using GiB."
    );
}

// --------------------------------------------------------------------------
// cost/month math: gb_per_day * 30.4 * price (issue #88)
// --------------------------------------------------------------------------

/// Corpus oracle: unrestricted execve at typical 50k events/day, $5/GB ENRICHED.
///
/// Grounded: `rocky9-execve-unrestricted/oracle/cost-band.json`.
/// ```
/// gb/day = 50000 * 1200 / 1e9 = 0.06
/// $/month = 0.06 * 30.4 * 5.00 = $9.12
/// ```
/// A wrong impl using 30 days/month gives $9.00 (fails); using 31 gives $9.30 (fails).
#[test]
fn compute_cost_band_typical_execve_oracle_match() {
    let band = RateBand {
        low: 5_000.0,
        typical: 50_000.0,
        high: 500_000.0,
    };
    let cost = compute_cost_band(&band, LogFormat::Enriched, 5.00);

    // Typical GB/day: 50000 * 1200 / 1e9 = 0.06
    let expected_gb_typical = 0.06_f64;
    let diff_gb = (cost.gb_per_day.typical - expected_gb_typical).abs();
    assert!(
        diff_gb < 1e-6,
        "gb_per_day.typical must be {expected_gb_typical}; got {}",
        cost.gb_per_day.typical
    );

    // Typical $/month: 0.06 * 30.4 * 5.00 = $9.12
    let expected_cost_typical = 9.12_f64;
    let diff_cost = (cost.cost_per_month_usd.typical - expected_cost_typical).abs();
    assert!(
        diff_cost < 0.01,
        "cost_per_month_usd.typical must be ~${expected_cost_typical} (oracle); \
         got ${} -- check the 30.4 days/month multiplier",
        cost.cost_per_month_usd.typical
    );
}

/// Low band oracle: 5k events/day -> $0.91/month.
/// Grounded: `rocky9-execve-unrestricted/oracle/cost-band.json`.
/// ```
/// gb/day = 5000 * 1200 / 1e9 = 0.006
/// $/month = 0.006 * 30.4 * 5.00 = $0.912
/// ```
#[test]
fn compute_cost_band_low_band_oracle_match() {
    let band = RateBand {
        low: 5_000.0,
        typical: 50_000.0,
        high: 500_000.0,
    };
    let cost = compute_cost_band(&band, LogFormat::Enriched, 5.00);
    let expected_low = 0.912_f64;
    let diff = (cost.cost_per_month_usd.low - expected_low).abs();
    assert!(
        diff < 0.01,
        "cost_per_month_usd.low must be ~${expected_low}; got ${}",
        cost.cost_per_month_usd.low
    );
}

/// High band oracle: 500k events/day -> $91.20/month.
/// Grounded: `rocky9-execve-unrestricted/oracle/cost-band.json`.
#[test]
fn compute_cost_band_high_band_oracle_match() {
    let band = RateBand {
        low: 5_000.0,
        typical: 50_000.0,
        high: 500_000.0,
    };
    let cost = compute_cost_band(&band, LogFormat::Enriched, 5.00);
    let expected_high = 91.20_f64;
    let diff = (cost.cost_per_month_usd.high - expected_high).abs();
    assert!(
        diff < 0.10,
        "cost_per_month_usd.high must be ~${expected_high}; got ${}",
        cost.cost_per_month_usd.high
    );
}

/// `sum_rate_bands`: two ZERO bands sum to ZERO.
/// Guards against a wrong impl that initializes the accumulator non-zero.
#[test]
#[allow(clippy::float_cmp)]
fn sum_rate_bands_all_zero() {
    let result = sum_rate_bands(&[RateBand::ZERO, RateBand::ZERO]);
    // These values are exactly representable (0.0); strict == is correct.
    assert_eq!(result.typical, 0.0);
    assert_eq!(result.low, 0.0);
    assert_eq!(result.high, 0.0);
}

/// `sum_rate_bands`: single non-zero band passes through unchanged.
#[test]
#[allow(clippy::float_cmp)]
fn sum_rate_bands_single_passthrough() {
    let band = RateBand {
        low: 1_000.0,
        typical: 10_000.0,
        high: 100_000.0,
    };
    // Exact integer-valued floats; strict == is correct.
    let result = sum_rate_bands(std::slice::from_ref(&band));
    assert_eq!(result.low, 1_000.0);
    assert_eq!(result.typical, 10_000.0);
    assert_eq!(result.high, 100_000.0);
}

/// `sum_rate_bands`: two distinct bands sum component-wise.
#[test]
#[allow(clippy::float_cmp)]
fn sum_rate_bands_two_additive() {
    let b1 = RateBand {
        low: 1_000.0,
        typical: 10_000.0,
        high: 100_000.0,
    };
    let b2 = RateBand {
        low: 5_000.0,
        typical: 50_000.0,
        high: 500_000.0,
    };
    // Exact integer-valued floats; strict == is correct.
    let result = sum_rate_bands(&[b1, b2]);
    assert_eq!(result.low, 6_000.0);
    assert_eq!(result.typical, 60_000.0);
    assert_eq!(result.high, 600_000.0);
}

// --------------------------------------------------------------------------
// Volume-tier classifier (issue #89)
// --------------------------------------------------------------------------

/// Unrestricted execve -> HIGH + Additive.
/// Grounded: f3 section 3.5, section 6.
#[test]
fn classify_unrestricted_execve_is_high_additive() {
    let rule = syscall_always_exit(vec!["execve"], Some("execve"));
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::High,
        "unrestricted execve must be HIGH tier"
    );
    assert_eq!(
        direction,
        Direction::Additive,
        "always-action rule must be Additive"
    );
}

/// `never`-action rule -> NEGATIVE + Suppressive.
///
/// ADVERSARIAL TRAP: a naive classifier that ignores the action field and
/// classifies by syscall name only would mark this HIGH -- and the cost model
/// would OVERCOUNT. This test catches that bug.
/// Grounded: f3 section 3.5 -- "never action rules SUPPRESS events".
#[test]
fn classify_never_action_is_negative_suppressive() {
    let rule = syscall_never_exit(vec!["execve"]);
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::Negative,
        "never-action rule must be NEGATIVE tier (suppressive, not additive)"
    );
    assert_eq!(
        direction,
        Direction::Suppressive,
        "never-action rule must be Suppressive"
    );
}

/// `exclude`-list rule -> NEGATIVE + Suppressive, even with `action=Always`.
///
/// ADVERSARIAL TRAP: `always,exclude` looks like "always" in the action field,
/// but the EXCLUDE LIST suppresses record types from the event stream, not adds
/// them. A naive impl that only checks action=Always returns Additive here -- a
/// costly overcounting bug.
/// Grounded: f3 section 2.3, 3.5; corpus `rocky9-exclude-msgtype`.
#[test]
fn classify_exclude_list_always_is_negative_suppressive() {
    let rule = syscall_exclude("PROCTITLE");
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::Negative,
        "exclude-list rule (even with action=Always) must be NEGATIVE tier"
    );
    assert_eq!(
        direction,
        Direction::Suppressive,
        "exclude-list rule must be Suppressive"
    );
}

/// Control rule -> NEGATIVE + Suppressive (zero runtime volume).
/// Grounded: f3 section 2.1 -- control rules configure the subsystem, emit no events.
#[test]
fn classify_control_rule_is_negative_suppressive() {
    let rule = control_delete_all();
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::Negative,
        "control rule must be NEGATIVE (zero runtime volume)"
    );
    assert_eq!(direction, Direction::Suppressive);
}

/// Rare syscall (adjtimex) -> LOW + Additive.
///
/// ADVERSARIAL TRAP: a naive classifier that treats all syscall rules as HIGH
/// would misclassify this. The test pins the LOW tier for rare syscalls.
/// Grounded: f3 section 3.5 -- "rules on rarely-called syscalls: LOW".
#[test]
fn classify_rare_syscall_is_low() {
    let rule = syscall_always_exit(vec!["adjtimex"], Some("time_change"));
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::Low,
        "adjtimex must be LOW tier (rarely called syscall, f3 section 3.5)"
    );
    assert_eq!(direction, Direction::Additive);
}

/// Directory watch (`is_dir=true`) -> HIGH + Additive.
///
/// Grounded: f3 section 2.2, 3.5 -- "a directory watch is recursive to the
/// bottom of the subtree ... a large volume multiplier."
#[test]
fn classify_directory_watch_is_high() {
    let rule = watch_wa("/etc/", true, Some("etc_changes"));
    let (tier, direction) = classify_rule(&rule);
    assert_eq!(
        tier,
        VolumeTier::High,
        "directory watch (is_dir=true) must be HIGH tier (recursive, high volume)"
    );
    assert_eq!(direction, Direction::Additive);
}

/// Single-file watch -> MEDIUM or LOW + Additive (not HIGH).
///
/// ADVERSARIAL TRAP: a naive classifier that marks all watches HIGH would
/// mislead operators about identity-watch costs. A single stable file like
/// `/etc/passwd` is low-to-medium (few writes/day on a hardened host).
/// Grounded: f3 section 3.5.
#[test]
fn classify_single_file_watch_is_not_high() {
    let rule = watch_wa("/etc/passwd", false, Some("identity"));
    let (tier, _direction) = classify_rule(&rule);
    assert_ne!(
        tier,
        VolumeTier::High,
        "single-file watch must NOT be HIGH tier; should be MEDIUM or LOW"
    );
}

// --------------------------------------------------------------------------
// Rate-band defaults (issue #89)
// --------------------------------------------------------------------------

/// Unrestricted execve default band: low 5k / typical 50k / high 500k.
/// Grounded: f3 section 6.
#[test]
#[allow(clippy::float_cmp)]
fn default_rate_band_execve_unrestricted() {
    let rule = syscall_always_exit(vec!["execve"], None);
    let band = default_rate_band(&rule);
    // Exact integer-valued constants from f3 section 6; strict == is correct.
    assert_eq!(
        band.low, 5_000.0,
        "unrestricted execve low must be 5k events/day (f3 section 6)"
    );
    assert_eq!(
        band.typical, 50_000.0,
        "unrestricted execve typical must be 50k events/day (f3 section 6)"
    );
    assert_eq!(
        band.high, 500_000.0,
        "unrestricted execve high must be 500k events/day (f3 section 6)"
    );
}

/// Never-action rule default band: ALL zeros (suppressive, contributes no additive volume).
///
/// ADVERSARIAL TRAP: a wrong impl might return the unrestricted execve band for
/// a never-execve rule. That would overcount cost by 3+ orders of magnitude.
#[test]
#[allow(clippy::float_cmp)]
fn default_rate_band_never_action_is_zero() {
    let rule = syscall_never_exit(vec!["execve"]);
    let band = default_rate_band(&rule);
    // Exact 0.0; strict == is correct.
    assert_eq!(band.low, 0.0, "never-action rule must have low=0.0");
    assert_eq!(band.typical, 0.0, "never-action rule must have typical=0.0");
    assert_eq!(band.high, 0.0, "never-action rule must have high=0.0");
}

/// Exclude-list rule default band: ALL zeros (suppressive).
///
/// Same adversarial trap as never: `always,exclude` looks like `always` but SUPPRESSES.
#[test]
#[allow(clippy::float_cmp)]
fn default_rate_band_exclude_list_is_zero() {
    let rule = syscall_exclude("PROCTITLE");
    let band = default_rate_band(&rule);
    assert_eq!(band.typical, 0.0, "exclude-list rule must have typical=0.0");
}

/// Control rule default band: ALL zeros.
/// Grounded: f3 section 6.
#[test]
#[allow(clippy::float_cmp)]
fn default_rate_band_control_rule_is_zero() {
    let rule = control_delete_all();
    let band = default_rate_band(&rule);
    assert_eq!(band.typical, 0.0, "control rule must have typical=0.0");
}

/// Narrowed execve (auid filter) default band: ~0.3x the unrestricted form.
/// low ~1.5k / typical ~15k / high ~150k (f3 section 6).
///
/// ADVERSARIAL TRAP: returning the full 50k typical for a narrowed rule
/// overstates cost ~3x and ignores the filter.
#[test]
fn default_rate_band_narrowed_execve_is_0_3x() {
    use rulesteward_auditd::{AuditField, CompareOp, FieldFilter};
    let rule = AuditRule::Syscall {
        list: FilterList::Exit,
        action: Action::Always,
        syscalls: vec!["execve".to_string()],
        fields: vec![
            FieldFilter {
                field: AuditField::Auid,
                op: CompareOp::Ge,
                value: "1000".to_string(),
            },
            FieldFilter {
                field: AuditField::Auid,
                op: CompareOp::Ne,
                value: "unset".to_string(),
            },
        ],
        prepend: false,
        key: Some("execve".to_string()),
    };
    let band = default_rate_band(&rule);
    // Should be ~0.3x the unrestricted band. Typical: 50k * 0.3 = 15k.
    // Allow 20% tolerance; oracle says 15k.
    let expected_typical = 15_000.0_f64;
    let diff = (band.typical - expected_typical).abs();
    assert!(
        diff < 3_000.0,
        "narrowed execve typical must be ~{expected_typical} (0.3x unrestricted); \
         got {} (oracle: rocky9-execve-auid/oracle/cost-band.json)",
        band.typical
    );
    assert!(
        band.typical < 50_000.0,
        "narrowed execve band must be < unrestricted (50k); got {}",
        band.typical
    );
}
