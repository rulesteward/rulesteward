//! Body of `rulesteward auditd <subcommand>`.
//!
//! Issue #90 -- pipeline P2.

use std::fmt::Write as _;

use serde::Serialize;

use crate::cli::{AuditdCommand, CostArgs, HumanJsonFormat};
use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;
use rulesteward_auditd::{
    AuditRule, Direction,
    bands::{RateBand, classify_rule, default_rate_band},
    cost::{CostBand, LogFormat, compute_cost_band, sum_rate_bands},
    from_log::count_events_by_key,
    parser::parse_target,
};

/// Schema version for the `auditd-cost` payload kind.
/// Bumps only on a breaking change (field removal, rename, retype).
const AUDITD_COST_SCHEMA_VERSION: u32 = 1;

pub fn run(cmd: AuditdCommand) -> anyhow::Result<i32> {
    match cmd {
        AuditdCommand::Cost(args) => Ok(cost(&args)),
    }
}

fn cost(args: &CostArgs) -> i32 {
    // Parse the rules file or directory.
    let rules = match parse_target(&args.rules) {
        Ok(r) => r,
        Err(errs) => {
            for e in &errs {
                eprintln!("auditd cost: parse error (line {}): {}", e.line, e.message);
            }
            return EXIT_RULE_PARSE_ERROR;
        }
    };

    // --recommend: not yet implemented (Option-2 noise-reduction seam).
    if args.recommend {
        eprintln!(
            "[NOT YET IMPLEMENTED] --recommend: noise-reduction recommendations are deferred (see issue #85 Option 2)"
        );
    }

    let price_per_gb = args.price_per_gb;
    let log_format = LogFormat::Enriched; // default; --log-format flag deferred

    // Determine rate bands: measured (--from-log) or assumed (default bands).
    let (rate_source, rule_bands) = if let Some(log_path) = &args.from_log {
        // --from-log: measure real per-key rates from an audit log.
        let measured = match count_events_by_key(log_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "auditd cost: cannot read --from-log {}: {}",
                    log_path.display(),
                    e.message
                );
                return EXIT_TOOL_FAILURE;
            }
        };
        let bands = build_rule_entries_from_log(&rules, &measured.counts, log_format, price_per_gb);
        (RateSource::Measured, bands)
    } else {
        // No --from-log: use the default assumed rate bands (f3 section 6).
        let bands = build_rule_entries_assumed(&rules, log_format, price_per_gb);
        (RateSource::Assumed, bands)
    };

    // Sum all additive bands.
    let additive_bands: Vec<RateBand> = rule_bands
        .iter()
        .filter(|e| e.direction == Direction::Additive)
        .map(|e| e.rate_band.clone())
        .collect();
    let total_rate = sum_rate_bands(&additive_bands);
    let total_cost = compute_cost_band(&total_rate, log_format, price_per_gb);

    // Render output.
    let output = match args.format {
        HumanJsonFormat::Human => render_human(&rule_bands, &total_cost, price_per_gb, rate_source),
        HumanJsonFormat::Json => render_json(
            &rule_bands,
            &total_cost,
            price_per_gb,
            log_format,
            rate_source,
        ),
    };

    print!("{output}");
    EXIT_CLEAN
}

// ---------------------------------------------------------------------------
// Rate source
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum RateSource {
    Assumed,
    Measured,
}

// ---------------------------------------------------------------------------
// Per-rule entry (shared between human and JSON renderers)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RuleEntry {
    rule_text: String,
    key: Option<String>,
    tier: String,
    direction: Direction,
    rate_band: RateBand,
    cost: CostBand,
}

/// Build rule entries using assumed default rate bands (no --from-log).
fn build_rule_entries_assumed(rules: &[AuditRule], fmt: LogFormat, price: f64) -> Vec<RuleEntry> {
    rules
        .iter()
        .map(|rule| {
            let (tier, direction) = classify_rule(rule);
            let band = if direction == Direction::Suppressive {
                RateBand::ZERO
            } else {
                default_rate_band(rule)
            };
            let cost = compute_cost_band(&band, fmt, price);
            RuleEntry {
                rule_text: fmt_rule(rule),
                key: rule_key(rule),
                tier: format!("{tier:?}").to_lowercase(),
                direction,
                rate_band: band,
                cost,
            }
        })
        .collect()
}

/// Build rule entries using measured per-key event counts from --from-log.
fn build_rule_entries_from_log(
    rules: &[AuditRule],
    counts: &std::collections::HashMap<Option<String>, u64>,
    fmt: LogFormat,
    price: f64,
) -> Vec<RuleEntry> {
    rules
        .iter()
        .map(|rule| {
            let (tier, direction) = classify_rule(rule);
            let key = rule_key(rule);

            let band = if direction == Direction::Suppressive {
                RateBand::ZERO
            } else {
                // Look up measured count by rule key.
                // counts are u64; event counts that fit in u64 are well within f64 precision
                // for the rates we deal with (millions per day at most).
                #[allow(clippy::cast_precision_loss)]
                let measured_events = counts.get(&key).copied().unwrap_or(0) as f64;
                // Use measured rate as a point estimate (low=typical=high).
                RateBand {
                    low: measured_events,
                    typical: measured_events,
                    high: measured_events,
                }
            };
            let cost = compute_cost_band(&band, fmt, price);
            RuleEntry {
                rule_text: fmt_rule(rule),
                key: key.clone(),
                tier: format!("{tier:?}").to_lowercase(),
                direction,
                rate_band: band,
                cost,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

fn render_human(entries: &[RuleEntry], total: &CostBand, price: f64, source: RateSource) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "auditd cost estimate  (price ${price:.2}/GB ingested, ENRICHED format, ~1200 B/event)"
    )
    .unwrap();
    writeln!(
        out,
        "{:<50} {:<16} {:<8} {:<22} {:<12}",
        "RULE", "KEY", "TIER", "EVENTS/DAY (est)", "GB/DAY"
    )
    .unwrap();
    out.push_str(&"-".repeat(110));
    out.push('\n');

    for entry in entries {
        let key_str = entry.key.as_deref().unwrap_or("(none)");
        let events_str = if entry.direction == Direction::Additive {
            if (entry.rate_band.low - entry.rate_band.high).abs() < 1.0 {
                // Point estimate (from-log mode)
                format!("{:.0}", entry.rate_band.typical)
            } else {
                format!(
                    "{:.0} [{:.0}-{:.0}]",
                    entry.rate_band.typical, entry.rate_band.low, entry.rate_band.high
                )
            }
        } else {
            "0 (suppressive)".to_string()
        };

        // Truncate long rule text for display
        let rule_display = if entry.rule_text.len() > 49 {
            format!("{}...", &entry.rule_text[..46])
        } else {
            entry.rule_text.clone()
        };

        writeln!(
            out,
            "{:<50} {:<16} {:<8} {:<22} {:.6}",
            rule_display, key_str, entry.tier, events_str, entry.cost.gb_per_day.typical,
        )
        .unwrap();
    }

    out.push_str(&"-".repeat(110));
    out.push('\n');

    let band_suffix = match source {
        RateSource::Assumed => format!(
            " (band {:.4} - {:.4} GB/day)",
            total.gb_per_day.low, total.gb_per_day.high
        ),
        RateSource::Measured => String::new(),
    };

    writeln!(
        out,
        "Estimated volume:  ~{:.4} GB/day typical{}",
        total.gb_per_day.typical, band_suffix
    )
    .unwrap();

    let cost_band_suffix = match source {
        RateSource::Assumed => format!(
            " (band ${:.2} - ${:.2}/month)",
            total.cost_per_month_usd.low, total.cost_per_month_usd.high
        ),
        RateSource::Measured => String::new(),
    };

    writeln!(
        out,
        "Estimated cost:    ~${:.2}/month typical{}",
        total.cost_per_month_usd.typical, cost_band_suffix
    )
    .unwrap();

    let confidence_msg = match source {
        RateSource::Assumed => {
            "rates are ASSUMPTIONS (no --from-log). Supply --from-log /var/log/audit/audit.log\n            to replace assumed rates with this host's measured per-key event rates."
        }
        RateSource::Measured => "rates are MEASURED from --from-log",
    };
    writeln!(out, "CONFIDENCE: {confidence_msg}").unwrap();

    out
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CostPayload<'a> {
    assumptions: Assumptions,
    rules: Vec<RuleJson>,
    totals: Totals,
    confidence: &'a str,
}

#[derive(Serialize)]
struct Assumptions {
    #[serde(rename = "pricePerGb")]
    price_per_gb: f64,
    currency: &'static str,
    #[serde(rename = "bytesPerEvent")]
    bytes_per_event: u64,
    #[serde(rename = "logFormat")]
    log_format: &'static str,
    #[serde(rename = "rateSource")]
    rate_source: &'static str,
}

#[derive(Serialize)]
struct RuleJson {
    rule: String,
    key: Option<String>,
    tier: String,
    #[serde(rename = "eventsPerDay")]
    events_per_day: BandJson,
    #[serde(rename = "gbPerDay")]
    gb_per_day: f64,
    direction: String,
}

#[derive(Serialize)]
struct BandJson {
    low: f64,
    typical: f64,
    high: f64,
}

#[derive(Serialize)]
struct Totals {
    #[serde(rename = "gbPerDayTypical")]
    gb_per_day_typical: f64,
    #[serde(rename = "gbPerDayLow")]
    gb_per_day_low: f64,
    #[serde(rename = "gbPerDayHigh")]
    gb_per_day_high: f64,
    #[serde(rename = "costPerMonthTypical")]
    cost_per_month_typical: f64,
    #[serde(rename = "costPerMonthLow")]
    cost_per_month_low: f64,
    #[serde(rename = "costPerMonthHigh")]
    cost_per_month_high: f64,
}

fn render_json(
    entries: &[RuleEntry],
    total: &CostBand,
    price: f64,
    fmt: LogFormat,
    source: RateSource,
) -> String {
    use rulesteward_auditd::cost::bytes_per_event;

    let confidence = match source {
        RateSource::Assumed => "rates assumed; supply --from-log to measure",
        RateSource::Measured => "rates measured from --from-log",
    };
    let rate_source_str = match source {
        RateSource::Assumed => "assumed",
        RateSource::Measured => "measured",
    };
    let log_format_str = match fmt {
        LogFormat::Enriched => "enriched",
        LogFormat::Raw => "raw",
    };

    let payload = CostPayload {
        assumptions: Assumptions {
            price_per_gb: price,
            currency: "USD",
            bytes_per_event: bytes_per_event(fmt),
            log_format: log_format_str,
            rate_source: rate_source_str,
        },
        rules: entries
            .iter()
            .map(|e| RuleJson {
                rule: e.rule_text.clone(),
                key: e.key.clone(),
                tier: e.tier.clone(),
                events_per_day: BandJson {
                    low: e.rate_band.low,
                    typical: e.rate_band.typical,
                    high: e.rate_band.high,
                },
                gb_per_day: e.cost.gb_per_day.typical,
                direction: fmt_direction(e.direction),
            })
            .collect(),
        totals: Totals {
            gb_per_day_typical: total.gb_per_day.typical,
            gb_per_day_low: total.gb_per_day.low,
            gb_per_day_high: total.gb_per_day.high,
            cost_per_month_typical: total.cost_per_month_usd.typical,
            cost_per_month_low: total.cost_per_month_usd.low,
            cost_per_month_high: total.cost_per_month_usd.high,
        },
        confidence,
    };

    render_envelope("auditd-cost", AUDITD_COST_SCHEMA_VERSION, &payload)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Format a rule as a compact text string for display.
fn fmt_rule(rule: &AuditRule) -> String {
    match rule {
        AuditRule::Control(c) => format!("{c:?}"),
        AuditRule::Watch {
            path, perms, key, ..
        } => {
            let mut s = format!("-w {path}");
            let mut p = String::new();
            if perms.read {
                p.push('r');
            }
            if perms.write {
                p.push('w');
            }
            if perms.exec {
                p.push('x');
            }
            if perms.attr {
                p.push('a');
            }
            if !p.is_empty() {
                write!(s, " -p {p}").unwrap();
            }
            if let Some(k) = key {
                write!(s, " -k {k}").unwrap();
            }
            s
        }
        AuditRule::Syscall {
            list,
            action,
            syscalls,
            fields,
            prepend,
            key,
        } => {
            let flag = if *prepend { "-A" } else { "-a" };
            let list_str = fmt_filter_list(list);
            let action_str = fmt_action(action);
            let mut s = format!("{flag} {list_str},{action_str}");
            for sc in syscalls {
                write!(s, " -S {sc}").unwrap();
            }
            for f in fields {
                write!(s, " -F {}{}{}", fmt_field(&f.field), fmt_op(&f.op), f.value).unwrap();
            }
            if let Some(k) = key {
                write!(s, " -k {k}").unwrap();
            }
            s
        }
    }
}

fn rule_key(rule: &AuditRule) -> Option<String> {
    match rule {
        AuditRule::Control(_) => None,
        AuditRule::Watch { key, .. } | AuditRule::Syscall { key, .. } => key.clone(),
    }
}

fn fmt_direction(d: Direction) -> String {
    match d {
        Direction::Additive => "additive".to_string(),
        Direction::Suppressive => "suppressive".to_string(),
    }
}

fn fmt_filter_list(list: &rulesteward_auditd::FilterList) -> &'static str {
    use rulesteward_auditd::FilterList;
    match list {
        FilterList::Task => "task",
        FilterList::Exit => "exit",
        FilterList::User => "user",
        FilterList::Exclude => "exclude",
        FilterList::Filesystem => "filesystem",
    }
}

fn fmt_action(action: &rulesteward_auditd::Action) -> &'static str {
    use rulesteward_auditd::Action;
    match action {
        Action::Never => "never",
        Action::Possible => "possible",
        Action::Always => "always",
    }
}

fn fmt_field(field: &rulesteward_auditd::AuditField) -> &'static str {
    use rulesteward_auditd::AuditField;
    match field {
        AuditField::Arch => "arch",
        AuditField::Auid => "auid",
        AuditField::DevMajor => "devmajor",
        AuditField::DevMinor => "devminor",
        AuditField::Dir => "dir",
        AuditField::Egid => "egid",
        AuditField::Euid => "euid",
        AuditField::Exe => "exe",
        AuditField::Exit => "exit",
        AuditField::FieldCompare => "field_compare",
        AuditField::Filetype => "filetype",
        AuditField::Fsgid => "fsgid",
        AuditField::Fstype => "fstype",
        AuditField::Fsuid => "fsuid",
        AuditField::Gid => "gid",
        AuditField::Inode => "inode",
        AuditField::Key => "key",
        AuditField::MsgType => "msgtype",
        AuditField::ObjGid => "obj_gid",
        AuditField::ObjLevHigh => "obj_lev_high",
        AuditField::ObjLevLow => "obj_lev_low",
        AuditField::ObjRole => "obj_role",
        AuditField::ObjType => "obj_type",
        AuditField::ObjUid => "obj_uid",
        AuditField::ObjUser => "obj_user",
        AuditField::Path => "path",
        AuditField::Perm => "perm",
        AuditField::Pers => "pers",
        AuditField::Pid => "pid",
        AuditField::Ppid => "ppid",
        AuditField::SaddrFam => "saddr_fam",
        AuditField::SessionId => "sessionid",
        AuditField::Sgid => "sgid",
        AuditField::SubjClr => "subj_clr",
        AuditField::SubjRole => "subj_role",
        AuditField::SubjSen => "subj_sen",
        AuditField::SubjType => "subj_type",
        AuditField::SubjUser => "subj_user",
        AuditField::Success => "success",
        AuditField::Suid => "suid",
        AuditField::Uid => "uid",
    }
}

fn fmt_op(op: &rulesteward_auditd::CompareOp) -> &'static str {
    use rulesteward_auditd::CompareOp;
    match op {
        CompareOp::Eq => "=",
        CompareOp::Ne => "!=",
        CompareOp::Lt => "<",
        CompareOp::Gt => ">",
        CompareOp::Le => "<=",
        CompareOp::Ge => ">=",
        CompareOp::BitAnd => "&",
        CompareOp::BitAndEq => "&=",
    }
}
