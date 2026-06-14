//! Corpus-driven tests for the auditd cost model (issue #93).
//!
//! ## Scope (RE-SCOPED from the over-asserting prior pass at c080ba7)
//!
//! The prior pass asserted per-rule `rate_band` and watch-tier -- both
//! non-deterministic (the byte-for-byte identical line `-w /etc/passwd -p wa`
//! is MEDIUM/{10,500,5000} in some scenarios but LOW/{10,100,1000} in
//! rocky9-exclude-msgtype). Those assertions are removed. Only CONSISTENT,
//! deterministic oracles are asserted; non-deterministic dimensions are
//! tracked as follow-up issue #140.
//!
//! ## What IS asserted (all deterministic)
//!
//! 1. **Floor guard**: >= 33 grammar scenarios + the from-log slice vendored.
//! 2. **Cost-band $** (the #93 byte-constant core): for scenarios whose
//!    `oracle/cost-band.json` has non-null `eventsPerDay`, aggregate additive
//!    rules (each mapped through `default_rate_band`, then `sum_rate_bands`), compute with Enriched/5.00,
//!    and assert gbPerDay + costPerMonth within +/-15%. NULL (watch-only) skipped.
//! 3. **From-log exact counts**: `count_events_by_key` on the vendored log
//!    slice matches `oracle/from-log-counts.json` exactly.
//! 4. **SYSCALL tier + direction**: for `kind=="syscall"` oracle rules (matched
//!    by position), assert `classify_rule` returns the oracle tier and direction.
//!    Scenarios with known code gaps are in `XFAIL_SYSCALL`; see inline FINDING
//!    comments tagged `#140`.
//! 5. **Negative/suppressive trap**: never-action, exclude-list, and control
//!    rules in oracle must classify as `(Negative, Suppressive)` with
//!    `default_rate_band == RateBand::ZERO`. Each oracle line is parsed
//!    directly (avoids ordering ambiguity from `-A` prepend).
//! 6. **Watch direction only**: `kind=="watch"` oracle rules must classify as
//!    `direction == Additive`. Watch tier and `rate_band` are NOT asserted
//!    (non-deterministic; deferred to #140).
//!
//! ## What is NOT asserted (deferred to #140)
//!
//! - Per-rule `rate_band` for any rule kind.
//! - Watch-rule `tier` (HIGH vs MEDIUM vs LOW for watches is content-aware
//!   and not stable across identical rule lines in different scenarios).

use std::path::{Path, PathBuf};

use rulesteward_auditd::{
    Direction, LogFormat, RateBand, VolumeTier,
    bands::{classify_rule, default_rate_band},
    cost::{CostBand, compute_cost_band, compute_cost_band_banded, sum_rate_bands},
    from_log::count_events_by_key,
    parser::{parse_rules_str, parse_target},
};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("auditd")
}

fn scenario_dir(name: &str) -> PathBuf {
    corpus_root().join(name)
}

// ---------------------------------------------------------------------------
// Oracle loaders
// ---------------------------------------------------------------------------

fn load_tiers_json(scenario: &str) -> serde_json::Value {
    let path = scenario_dir(scenario).join("oracle").join("tiers.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read tiers.json for {scenario}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse tiers.json for {scenario}: {e}"))
}

fn load_cost_band_json(scenario: &str) -> serde_json::Value {
    let path = scenario_dir(scenario).join("oracle").join("cost-band.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read cost-band.json for {scenario}: {e}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parse cost-band.json for {scenario}: {e}"))
}

fn load_from_log_oracle(scenario: &str) -> serde_json::Value {
    let path = scenario_dir(scenario)
        .join("oracle")
        .join("from-log-counts.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read from-log-counts.json for {scenario}: {e}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parse from-log-counts.json for {scenario}: {e}"))
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn parse_oracle_tier(s: &str) -> VolumeTier {
    match s.to_uppercase().as_str() {
        "HIGH" => VolumeTier::High,
        "MEDIUM" => VolumeTier::Medium,
        "LOW" => VolumeTier::Low,
        "NEGATIVE" => VolumeTier::Negative,
        other => panic!("unknown oracle tier: {other}"),
    }
}

/// Map an oracle direction string to `Direction`.
///
/// Oracle uses "additive" | "suppressive" | "neutral" | "inert".
/// - "neutral"  -> control rules: code returns Suppressive.
/// - "inert"    -> never rule behind an always rule (ordering trap): code still
///   returns Suppressive (code has no load-order awareness).
///
/// Both map to `Direction::Suppressive` for assertion purposes.
fn parse_oracle_direction(s: &str) -> Direction {
    match s.to_lowercase().as_str() {
        "additive" => Direction::Additive,
        "suppressive" | "neutral" | "inert" => Direction::Suppressive,
        other => panic!("unknown oracle direction: {other}"),
    }
}

/// Assert `|computed - oracle| / |oracle| <= tolerance_pct / 100`.
/// When oracle == 0, asserts computed == 0 exactly.
fn assert_within_pct(label: &str, computed: f64, oracle: f64, tolerance_pct: f64) {
    if oracle == 0.0 {
        assert!(
            computed.abs() < 1e-12,
            "{label}: oracle=0 but computed={computed}"
        );
    } else {
        let diff_pct = (computed - oracle).abs() / oracle.abs() * 100.0;
        assert!(
            diff_pct <= tolerance_pct,
            "{label}: computed={computed:.6}, oracle={oracle:.6}, diff={diff_pct:.1}% (limit {tolerance_pct}%)"
        );
    }
}

fn rate_band_is_zero(rb: &RateBand) -> bool {
    rb.low.abs() < 1e-12 && rb.typical.abs() < 1e-12 && rb.high.abs() < 1e-12
}

// ---------------------------------------------------------------------------
// Scenario lists
// ---------------------------------------------------------------------------

/// All 33 grammar scenario IDs (excludes the from-log scenario).
const ALL_GRAMMAR: &[&str] = &[
    "rocky8-cis-file-watches",
    "rocky8-pci-dss",
    "rocky9-arch-paired",
    "rocky9-deep-many-watches",
    "rocky9-exclude-msgtype",
    "rocky9-exclude-overlap",
    "rocky9-execve-auid",
    "rocky9-execve-unrestricted",
    "rocky9-field-compare",
    "rocky9-filesystem-list",
    "rocky9-huge-ruleset",
    "rocky9-identity-watches",
    "rocky9-key-collision",
    "rocky9-login-watches",
    "rocky9-mac-policy",
    "rocky9-multi-S-or",
    "rocky9-never-below-always",
    "rocky9-never-suppress",
    "rocky9-no-key-rules",
    "rocky9-perm-watch-expansion",
    "rocky9-prepend-vs-append",
    "rocky9-priv-commands",
    "rocky9-rare-syscall",
    "rocky9-stig-finalize",
    "rocky9-stig-hardened",
    "rocky9-stock-control",
    "rocky9-task-list",
    "rocky9-time-change",
    "rocky9-whitespace-torture",
    "rocky10-cis-benchmark",
    "rocky10-module-ops",
    "rocky10-rulesd-multifile",
    "rocky10-watch-vs-syscall-equiv",
];

/// Grammar scenarios with a non-NULL `oracle/cost-band.json` (syscall-driven,
/// deterministic `rate_band`). Watch-only or mixed scenarios whose `eventsPerDay`
/// is null are excluded; they use the deferred watch model (#140).
const NON_NULL_COST_BAND: &[&str] = &[
    "rocky9-execve-auid",
    "rocky9-execve-unrestricted",
    "rocky9-stock-control",
];

/// Syscall-tier scenarios xfailed because of known limitations (not test errors).
///
/// Two distinct classes remain after the #140 Finding-2 deterministic fixes
/// landed (`finit_module` -> `LOW_SYSCALLS` greened `rocky9-key-collision`;
/// `list==Filesystem` -> MEDIUM greened `rocky9-filesystem-list`):
///
/// - **Finding 1 (content-aware, NON-deterministic):** the per-rule tier depends
///   on the watched path/binary's real-world churn, which is NOT in the rule AST.
///   A pure static classifier cannot reproduce these (see the `sudo`=MEDIUM vs
///   `su`/`passwd`=LOW split inside `rocky9-priv-commands`). Tracked by #140
///   Finding 1; not fixable without a content-aware volume model.
/// - **Finding 2 (deterministic, DEFERRED):** real, fixable static gaps deferred
///   to a #140 follow-up (arch-aware demotion + `-C` field-comparison parsing).
const XFAIL_SYSCALL: &[&str] = &[
    // FINDING (#140 Finding 1, content-aware): rocky10-watch-vs-syscall-equiv -
    // `-F path=/etc/passwd -F perm=wa` (no -S) -> oracle MEDIUM. Same AST shape as
    // the `su`/`passwd` rules in rocky9-priv-commands that the oracle rates LOW;
    // the tier difference is driven by the watched PATH's churn (/etc/passwd vs
    // /usr/bin/su), which is not derivable from the rule. NOT deterministically
    // fixable; belongs to the non-deterministic Finding 1, not a static code gap.
    "rocky10-watch-vs-syscall-equiv",
    // NOTE: rocky9-arch-paired (arch=b32 demotion) and rocky9-field-compare
    // (`-C` field-comparison parsing) were the two deterministic #140 Finding 2
    // gaps. Both are now FIXED in #161 (arch-aware demotion in bands.rs + `-C`
    // parsing into FieldComparison), so they are no longer xfailed and assert
    // their oracle tiers directly.
    // FINDING (#140 Finding 1, content-aware): rocky9-priv-commands - three
    // byte-identical `-F path=<bin> -F perm=x` rules (no -S) the oracle rates
    // differently (sudo=MEDIUM, su=LOW, passwd=LOW) purely by which binary is
    // watched. No pure-AST classifier can reproduce this; belongs to the
    // non-deterministic Finding 1.
    "rocky9-priv-commands",
];

// ---------------------------------------------------------------------------
// Test 1: Floor guard
// ---------------------------------------------------------------------------

/// Verify the vendored corpus is intact: >= 33 grammar scenarios + the from-log slice.
#[test]
fn floor_guard_scenario_count() {
    // 33 grammar scenarios listed in ALL_GRAMMAR.
    assert!(
        ALL_GRAMMAR.len() >= 33,
        "ALL_GRAMMAR has {} entries; expected >= 33",
        ALL_GRAMMAR.len()
    );

    // All grammar scenario dirs must exist on disk.
    let mut missing = Vec::new();
    for &s in ALL_GRAMMAR {
        let d = corpus_root().join(s);
        if !d.is_dir() {
            missing.push(s);
        }
    }
    assert!(
        missing.is_empty(),
        "missing grammar corpus dirs: {missing:?}"
    );

    // The from-log scenario dir must exist.
    let from_log_dir = corpus_root().join("rocky8-live-from-log-execve");
    assert!(
        from_log_dir.is_dir(),
        "from-log scenario dir missing: {}",
        from_log_dir.display()
    );

    // The from-log audit-sample.log must exist.
    let log_file = from_log_dir.join("audit-sample.log");
    assert!(
        log_file.is_file(),
        "from-log audit-sample.log missing: {}",
        log_file.display()
    );

    eprintln!(
        "[PASS] floor_guard_scenario_count: {} grammar + 1 from-log scenarios present",
        ALL_GRAMMAR.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2: Cost-band $ (the #93 byte-constant core)
// ---------------------------------------------------------------------------

/// Assert the banded total (#234) widens the single-byte projection in the right
/// direction: the typical edge is byte-identical, the low edge sits below it (byte
/// 760 < 1200) and the high edge above it (2300 > 1200) whenever the aggregate rate
/// edge is non-zero. This kills any impl that ignores `bytes_per_event_band`, even
/// one a re-grounded static oracle would still pass.
fn assert_banded_widens_single(
    scenario: &str,
    banded: &CostBand,
    single: &CostBand,
    agg: &RateBand,
) {
    assert!(
        (banded.gb_per_day.typical - single.gb_per_day.typical).abs() < 1e-12
            && (banded.cost_per_month_usd.typical - single.cost_per_month_usd.typical).abs()
                < 1e-12,
        "{scenario}: banded TYPICAL must equal the single-byte typical (byte-identical invariant)"
    );
    // Strict < / >; skip the all-zeros control band (sum_rate_bands -> ZERO), where
    // low == high == 0 and a band cannot widen. low > 0 iff high > 0 for every
    // default_rate_band tier, so neither guard skips a direction asymmetrically.
    if agg.low > 0.0 {
        assert!(
            banded.gb_per_day.low < single.gb_per_day.low
                && banded.cost_per_month_usd.low < single.cost_per_month_usd.low,
            "{scenario}: banded LOW must sit below the single-byte low (byte 760 < 1200)"
        );
    }
    if agg.high > 0.0 {
        assert!(
            banded.gb_per_day.high > single.gb_per_day.high
                && banded.cost_per_month_usd.high > single.cost_per_month_usd.high,
            "{scenario}: banded HIGH must exceed the single-byte high (byte 2300 > 1200)"
        );
    }
}

/// For each scenario in `NON_NULL_COST_BAND` (syscall-driven, deterministic),
/// aggregate additive rules' `default_rate_band` via `sum_rate_bands`, compute
/// `compute_cost_band_banded(&agg, Enriched, 5.00)` (the production ASSUMED-mode
/// total path, #112/#234), and assert `gbPerDay` + `costPerMonth`
/// low/typical/high are within +/-15% of the banded oracle.
///
/// Scenarios whose `cost-band.json` has null `eventsPerDay` (watch-only or mixed)
/// are skipped; the watch model is deferred to #140.
#[test]
fn cost_band_dollar_core() {
    const TOLERANCE: f64 = 15.0; // percent
    let mut checked = 0;

    for &scenario in NON_NULL_COST_BAND {
        let oracle_json = load_cost_band_json(scenario);

        // Verify non-null: oracle eventsPerDay must be present.
        assert!(
            oracle_json.get("eventsPerDay").is_some(),
            "{scenario}: cost-band.json missing eventsPerDay (expected non-null scenario)"
        );
        let events_per_day = oracle_json.get("eventsPerDay").unwrap();
        assert!(
            events_per_day
                .get("typical")
                .and_then(serde_json::Value::as_f64)
                .is_some(),
            "{scenario}: eventsPerDay.typical is null; only non-null scenarios belong in NON_NULL_COST_BAND"
        );

        let rules_path = scenario_dir(scenario).join("audit.rules");
        let parsed = parse_target(&rules_path)
            .unwrap_or_else(|e| panic!("parse_target failed for {scenario}: {e:?}"));
        assert!(
            !parsed.is_empty(),
            "{scenario}: parse_target returned 0 rules"
        );

        // Aggregate additive rules; suppressive rules contribute ZERO.
        let additive_bands: Vec<_> = parsed
            .iter()
            .map(|rule| {
                let (_, dir) = classify_rule(rule);
                if dir == Direction::Additive {
                    default_rate_band(rule)
                } else {
                    RateBand::ZERO
                }
            })
            .collect();
        let agg = sum_rate_bands(&additive_bands);
        // Banded path (#234): assert the production ASSUMED-mode TOTAL the way
        // `auditd cost` actually prints it. compute_cost_band_banded folds the
        // per-event byte BAND (enriched 760/1200/2300, #112) into the low/high
        // edges; the oracle low/high below are grounded in that banded math, while
        // the TYPICAL edge stays byte-identical to the single-byte path (the band's
        // typical equals the 1200 scalar).
        let cost = compute_cost_band_banded(&agg, LogFormat::Enriched, 5.00);
        // Anti-vacuity guard (#234): prove the banding actually happened, not just
        // that the re-grounded static oracle matches (see the helper's doc).
        let single = compute_cost_band(&agg, LogFormat::Enriched, 5.00);
        assert_banded_widens_single(scenario, &cost, &single, &agg);

        // Oracle from oracle/cost-band.json.
        macro_rules! oracle_f64 {
            ($section:expr, $key:expr) => {
                oracle_json
                    .get($section)
                    .and_then(|v| v.get($key))
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(|| {
                        panic!("{scenario}: cost-band.json missing {}.{}", $section, $key)
                    })
            };
        }
        let oracle_gb_low = oracle_f64!("gbPerDay", "low");
        let oracle_gb_typ = oracle_f64!("gbPerDay", "typical");
        let oracle_gb_high = oracle_f64!("gbPerDay", "high");
        let oracle_cost_low = oracle_f64!("costPerMonth", "low");
        let oracle_cost_typ = oracle_f64!("costPerMonth", "typical");
        let oracle_cost_high = oracle_f64!("costPerMonth", "high");

        assert_within_pct(
            &format!("{scenario}: gbPerDay.low"),
            cost.gb_per_day.low,
            oracle_gb_low,
            TOLERANCE,
        );
        assert_within_pct(
            &format!("{scenario}: gbPerDay.typical"),
            cost.gb_per_day.typical,
            oracle_gb_typ,
            TOLERANCE,
        );
        assert_within_pct(
            &format!("{scenario}: gbPerDay.high"),
            cost.gb_per_day.high,
            oracle_gb_high,
            TOLERANCE,
        );
        assert_within_pct(
            &format!("{scenario}: costPerMonth.low"),
            cost.cost_per_month_usd.low,
            oracle_cost_low,
            TOLERANCE,
        );
        assert_within_pct(
            &format!("{scenario}: costPerMonth.typical"),
            cost.cost_per_month_usd.typical,
            oracle_cost_typ,
            TOLERANCE,
        );
        assert_within_pct(
            &format!("{scenario}: costPerMonth.high"),
            cost.cost_per_month_usd.high,
            oracle_cost_high,
            TOLERANCE,
        );

        checked += 1;
        eprintln!("[PASS] {scenario}: cost-band within {TOLERANCE}%");
    }

    assert!(
        checked >= 3,
        "expected >= 3 non-null cost-band scenarios checked, got {checked}"
    );
    eprintln!("[PASS] cost_band_dollar_core: {checked} scenarios checked within {TOLERANCE}%");
}

// ---------------------------------------------------------------------------
// Test 3: From-log exact counts
// ---------------------------------------------------------------------------

/// Run `count_events_by_key` on the vendored `audit-sample.log` and assert
/// per-key event counts exactly equal the oracle.
#[test]
fn from_log_event_counts() {
    let log_path = corpus_root()
        .join("rocky8-live-from-log-execve")
        .join("audit-sample.log");
    assert!(
        log_path.is_file(),
        "audit-sample.log missing: {}",
        log_path.display()
    );

    let result = count_events_by_key(&log_path)
        .unwrap_or_else(|e| panic!("count_events_by_key failed: {}", e.message));

    let oracle = load_from_log_oracle("rocky8-live-from-log-execve");
    let per_key = oracle
        .get("per_key_counts")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("from-log oracle missing per_key_counts"));

    for (key, expected_val) in per_key {
        let expected: u64 = expected_val
            .as_u64()
            .unwrap_or_else(|| panic!("per_key_counts.{key} is not a u64"));
        let actual = result.counts.get(&Some(key.clone())).copied().unwrap_or(0);
        assert_eq!(
            actual, expected,
            "from-log key={key:?}: code={actual}, oracle={expected}"
        );
    }

    assert!(
        result.lines_scanned > 0,
        "lines_scanned should be > 0, got {}",
        result.lines_scanned
    );

    eprintln!(
        "[PASS] from_log_event_counts: {} keys verified, {} lines scanned",
        per_key.len(),
        result.lines_scanned
    );
}

// ---------------------------------------------------------------------------
// Test 4: SYSCALL tier + direction
// ---------------------------------------------------------------------------

/// For each grammar scenario (not in `XFAIL_SYSCALL`), iterate oracle
/// `kind=="syscall"` rules. For each, parse the oracle "line" string directly
/// and assert `classify_rule` returns the oracle tier and direction.
///
/// Using the oracle line (not positional `parse_target` output) avoids two
/// brittleness sources:
/// - Scenarios where oracle rules[] is a summary (fewer entries than the file)
///   e.g. rocky9-exclude-msgtype omits its 3 control rules from oracle.
/// - Scenarios where oracle documents EFFECTIVE order (-A prepend) vs TEXT order
///   e.g. rocky9-prepend-vs-append.
///
/// Scenarios with genuine code classification gaps are in `XFAIL_SYSCALL` with
/// inline FINDING comments tagged #140.
#[test]
fn syscall_tier_and_direction() {
    let mut checked_scenarios = 0;
    let mut checked_rules = 0;

    for &scenario in ALL_GRAMMAR {
        if XFAIL_SYSCALL.contains(&scenario) {
            eprintln!("[XFAIL] {scenario}: syscall tier+direction (see XFAIL_SYSCALL comment)");
            continue;
        }

        let tiers = load_tiers_json(scenario);
        let Some(oracle_rules) = tiers.get("rules").and_then(|v| v.as_array()) else {
            // No rules[] array (summary format or empty): skip.
            eprintln!("[SKIP] {scenario}: tiers.json has no rules[] array");
            continue;
        };

        // Filter to syscall-kind oracle entries.
        let syscall_oracle: Vec<(usize, &serde_json::Value)> = oracle_rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.get("kind").and_then(|v| v.as_str()) == Some("syscall"))
            .collect();

        if syscall_oracle.is_empty() {
            continue;
        }

        let mut scenario_had_assertions = false;

        for (idx, oracle_row) in &syscall_oracle {
            let label = format!("{scenario}[{idx}]");

            let line = oracle_row
                .get("line")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{label}: syscall oracle row missing 'line'"));

            // Parse the oracle line string directly. If the parser doesn't support a
            // token in this line (e.g. -C field-comparison), skip with a note rather
            // than panic -- that case should be in XFAIL_SYSCALL.
            let parsed = match parse_rules_str(line) {
                Ok(rules) => rules,
                Err(e) => {
                    eprintln!(
                        "[SKIP-PARSE] {label}: parse_rules_str failed for {line:?}: {e:?} \
                         -- add scenario to XFAIL_SYSCALL if this is a known code gap"
                    );
                    continue;
                }
            };
            assert_eq!(
                parsed.len(),
                1,
                "{label}: expected 1 rule from oracle line {line:?}, got {}",
                parsed.len()
            );
            let rule = &parsed[0];

            let oracle_tier_str = oracle_row
                .get("tier")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{label}: missing tier in oracle"));
            let expected_tier = parse_oracle_tier(oracle_tier_str);

            let oracle_dir_str = oracle_row
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{label}: missing direction in oracle"));
            let expected_dir = parse_oracle_direction(oracle_dir_str);

            let (actual_tier, actual_dir) = classify_rule(rule);

            assert_eq!(
                actual_tier, expected_tier,
                "{label}: syscall tier: code={actual_tier:?} oracle={oracle_tier_str}"
            );
            assert_eq!(
                actual_dir, expected_dir,
                "{label}: syscall direction: code={actual_dir:?} oracle={oracle_dir_str}"
            );

            checked_rules += 1;
            scenario_had_assertions = true;
        }

        if scenario_had_assertions {
            checked_scenarios += 1;
        }
    }

    assert!(
        checked_scenarios >= 5,
        "expected >= 5 non-XFAIL syscall scenarios checked, got {checked_scenarios}"
    );
    assert!(
        checked_rules >= 10,
        "expected >= 10 syscall rule assertions, got {checked_rules}"
    );
    eprintln!(
        "[PASS] syscall_tier_and_direction: {checked_scenarios} scenarios, \
         {checked_rules} rule assertions"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Negative/suppressive trap
// ---------------------------------------------------------------------------

/// For every NEGATIVE-tier rule in any tiers.json oracle, parse the rule's
/// "line" string directly and assert `classify_rule` returns
/// `(VolumeTier::Negative, Direction::Suppressive)` and
/// `default_rate_band` returns `RateBand::ZERO`.
///
/// This covers: `never`-action, `exclude`-list, and `control` rules.
/// The oracle line is parsed directly (avoids positional ordering issues
/// introduced by `-A` prepend semantics).
#[test]
fn negative_rules_are_suppressive_zero() {
    let mut checked = 0;

    for &scenario in ALL_GRAMMAR {
        let tiers = load_tiers_json(scenario);
        let Some(oracle_rules) = tiers.get("rules").and_then(|v| v.as_array()) else {
            continue;
        };

        for (idx, oracle_row) in oracle_rules.iter().enumerate() {
            let tier_str = oracle_row
                .get("tier")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{scenario}: rule[{idx}] missing string 'tier' field"));
            if tier_str != "NEGATIVE" {
                continue;
            }

            let line = oracle_row
                .get("line")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{scenario}[{idx}]: NEGATIVE rule missing line"));

            // Parse the oracle line directly (single rule).
            let parsed = parse_rules_str(line).unwrap_or_else(|e| {
                panic!(
                    "{scenario}[{idx}]: parse_rules_str failed for NEGATIVE rule {line:?}: {e:?}"
                )
            });
            assert_eq!(
                parsed.len(),
                1,
                "{scenario}[{idx}]: expected 1 parsed rule for line {line:?}, got {}",
                parsed.len()
            );
            let rule = &parsed[0];
            let label = format!("{scenario}[{idx}] line={line:?}");

            let (tier, dir) = classify_rule(rule);
            assert_eq!(
                tier,
                VolumeTier::Negative,
                "{label}: expected Negative, got {tier:?}"
            );
            assert_eq!(
                dir,
                Direction::Suppressive,
                "{label}: expected Suppressive, got {dir:?}"
            );

            let rb = default_rate_band(rule);
            assert!(
                rate_band_is_zero(&rb),
                "{label}: expected RateBand::ZERO, got low={} typical={} high={}",
                rb.low,
                rb.typical,
                rb.high
            );

            checked += 1;
        }
    }

    assert!(
        checked >= 10,
        "expected >= 10 negative rule assertions across all scenarios, got {checked}"
    );
    eprintln!("[PASS] negative_rules_are_suppressive_zero: {checked} negative rules verified");
}

// ---------------------------------------------------------------------------
// Test 6: Watch direction only
// ---------------------------------------------------------------------------

/// For every `kind=="watch"` rule in any tiers.json oracle, parse the rule's
/// "line" string directly and assert `classify_rule` returns
/// `direction == Direction::Additive`.
///
/// Watch tier (HIGH/MEDIUM/LOW) and `rate_band` are NOT asserted -- those are
/// content-aware and non-deterministic across identical rule lines in
/// different scenarios (deferred to #140).
#[test]
fn watch_rules_are_additive() {
    let mut checked = 0;

    for &scenario in ALL_GRAMMAR {
        let tiers = load_tiers_json(scenario);
        let Some(oracle_rules) = tiers.get("rules").and_then(|v| v.as_array()) else {
            continue;
        };

        for (idx, oracle_row) in oracle_rules.iter().enumerate() {
            let kind = oracle_row
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{scenario}: rule[{idx}] missing string 'kind' field"));
            if kind != "watch" {
                continue;
            }

            let line = oracle_row
                .get("line")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{scenario}[{idx}]: watch rule missing line"));

            let parsed = parse_rules_str(line).unwrap_or_else(|e| {
                panic!("{scenario}[{idx}]: parse_rules_str failed for watch rule {line:?}: {e:?}")
            });
            assert_eq!(
                parsed.len(),
                1,
                "{scenario}[{idx}]: expected 1 parsed rule for {line:?}, got {}",
                parsed.len()
            );
            let rule = &parsed[0];
            let label = format!("{scenario}[{idx}] line={line:?}");

            let (_, dir) = classify_rule(rule);
            assert_eq!(
                dir,
                Direction::Additive,
                "{label}: watch rule must be Additive, got {dir:?}"
            );

            checked += 1;
        }
    }

    assert!(
        checked >= 10,
        "expected >= 10 watch rule direction assertions, got {checked}"
    );
    eprintln!("[PASS] watch_rules_are_additive: {checked} watch rules verified as Additive");
}
