//! Body of `rulesteward auditd <subcommand>`.
//!
//! Issue #90 -- pipeline P2.

use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::cli::{AuditdCommand, AuditdLintArgs, CostArgs, HumanJsonCsvFormat, HumanJsonFormat};
use crate::exit_code::{self, EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};
use crate::output::csv::to_csv;
use crate::output::json::render_envelope;
use rulesteward_auditd::{
    AuditRule, Direction, LocatedRule,
    bands::{RateBand, VolumeTier, classify_rule, default_rate_band},
    cost::{CostBand, LogFormat, compute_cost_band, compute_cost_band_banded, sum_rate_bands},
    from_log::count_events_by_key,
    lints,
    parser::{parse_rules_str_located, parse_target, rules_files_in_load_order},
};

/// Schema version for the `auditd-cost` payload kind.
/// Bumps only on a breaking change (field removal, rename, retype).
const AUDITD_COST_SCHEMA_VERSION: u32 = 1;

/// Schema version for the `auditd-lint` payload kind (#193, session 6a).
/// Bumps only on a breaking change (field removal, rename, retype).
const AUDITD_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target, mirroring where augenrules(8) reads rules from.
const DEFAULT_AUDIT_RULES_D: &str = "/etc/audit/rules.d/";

pub fn run(cmd: AuditdCommand) -> anyhow::Result<i32> {
    match cmd {
        AuditdCommand::Cost(args) => Ok(cost(&args)),
        AuditdCommand::Lint(args) => Ok(lint(&args)),
    }
}

// ---------------------------------------------------------------------------
// auditd lint (#193, session 6a): the Phase-0 command shell. The semantic
// passes live in rulesteward_auditd::lints (the crate owns the au- codes and
// the mutation gate); this shell does target resolution, source-map staging,
// rendering, and exit-code mapping only.
// ---------------------------------------------------------------------------

/// JSON payload for the `auditd-lint` envelope kind (CC-1).
#[derive(Serialize)]
struct AuditdLintPayload<'a> {
    diagnostics: &'a [rulesteward_core::Diagnostic],
}

fn lint(args: &AuditdLintArgs) -> i32 {
    let target = args
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_AUDIT_RULES_D));

    let files = match resolve_lint_target(&target) {
        Ok(files) => files,
        Err(msg) => {
            eprintln!("auditd lint: {msg}");
            return EXIT_TOOL_FAILURE;
        }
    };

    // Stage each file's raw text (keyed by display path, the diagnostics'
    // source_id convention) and parse with provenance, in load order.
    let mut sources = std::collections::BTreeMap::new();
    let mut rules: Vec<LocatedRule> = Vec::new();
    let mut diags: Vec<rulesteward_core::Diagnostic> = Vec::new();
    for file in &files {
        let source = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("auditd lint: cannot read {}: {e}", file.display());
                return EXIT_TOOL_FAILURE;
            }
        };
        match parse_rules_str_located(&source, file) {
            Ok(located) => rules.extend(located),
            Err(errs) => diags.extend(errs.iter().map(lints::parse_error_to_diagnostic)),
        }
        sources.insert(file.display().to_string(), source);
    }

    // The semantic passes run only on a FULLY-parsed stream: with a file
    // missing from the stream, cross-file duplicate/ordering/shadowing claims
    // would be unsound. Parse failures exit 5 on their own (au-F01 -> D3).
    if diags.is_empty() {
        diags.extend(lints::lint(&rules));
    }

    let output = match args.format {
        HumanJsonFormat::Human => crate::output::human::render(&diags, &sources),
        HumanJsonFormat::Json => render_envelope(
            "auditd-lint",
            AUDITD_LINT_SCHEMA_VERSION,
            &AuditdLintPayload {
                diagnostics: &diags,
            },
        ),
    };
    if !output.is_empty() {
        print!("{output}");
    }

    exit_code::compute(&diags, false)
}

/// Resolve the lint target to a load-ordered file list: a single file is
/// linted alone; a directory yields its `*.rules` files in augenrules order.
fn resolve_lint_target(target: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    if target.is_file() {
        Ok(vec![target.to_path_buf()])
    } else if target.is_dir() {
        rules_files_in_load_order(target).map_err(|e| e.message)
    } else {
        Err(format!("path does not exist: {}", target.display()))
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
            // EXIT_RULE_PARSE_ERROR (5): auditd cost parses a RULES file, so an
            // unparseable file matches `lint`'s fapd-F01 -> 5 mapping (spec §9.4).
            // `explain` parses a denial RECORD (not a rule) and returns EXIT_ERRORS
            // (2) instead; the divergence is intentional (#114).
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
    // The ASSUMED-rate total folds the per-event byte-size band (#112) into its
    // low/high edges; the MEASURED --from-log total keeps a single typical byte so
    // an exact measured count is not re-widened by a byte-size assumption.
    let total_cost = match rate_source {
        RateSource::Assumed => compute_cost_band_banded(&total_rate, log_format, price_per_gb),
        RateSource::Measured => compute_cost_band(&total_rate, log_format, price_per_gb),
    };

    // Render output.
    let output = match args.format {
        HumanJsonCsvFormat::Human => {
            render_human(&rule_bands, &total_cost, price_per_gb, rate_source)
        }
        HumanJsonCsvFormat::Json => render_json(
            &rule_bands,
            &total_cost,
            price_per_gb,
            log_format,
            rate_source,
        ),
        // CSV is the flat per-rule table ONLY; totals stay in JSON/human (#64).
        HumanJsonCsvFormat::Csv => render_csv_cost(&rule_bands),
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
                tier: tier_str(tier).to_string(),
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
                tier: tier_str(tier).to_string(),
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
// CSV renderer (#64 / CC-3): flat per-rule table ONLY
// ---------------------------------------------------------------------------

/// Render the per-rule cost table as RFC-4180 CSV.
///
/// One row per rule; the nested event band is flattened to
/// `eventsPerDayLow/Typical/High` columns, and `gbPerDay` is the per-rule
/// typical volume. Per the locked CSV policy, the aggregate totals, the rate
/// band, the rate source, and the confidence note are deliberately EXCLUDED:
/// CSV is a single rectangular table, so a consumer who needs the grand total
/// sums the `gbPerDay` column. Numeric columns are emitted at full f64 precision
/// (matching the JSON surface), not the human renderer's rounded display.
#[must_use]
fn render_csv_cost(entries: &[RuleEntry]) -> String {
    let headers = &[
        "rule",
        "key",
        "tier",
        "direction",
        "eventsPerDayLow",
        "eventsPerDayTypical",
        "eventsPerDayHigh",
        "gbPerDay",
    ];
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                e.rule_text.clone(),
                e.key.clone().unwrap_or_default(),
                e.tier.clone(),
                fmt_direction(e.direction),
                e.rate_band.low.to_string(),
                e.rate_band.typical.to_string(),
                e.rate_band.high.to_string(),
                e.cost.gb_per_day.typical.to_string(),
            ]
        })
        .collect();
    to_csv(headers, &rows)
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
            field_compares,
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
            // `-C` inter-field comparisons (both operands are field names).
            for c in field_compares {
                write!(
                    s,
                    " -C {}{}{}",
                    fmt_field(&c.left),
                    fmt_op(&c.op),
                    fmt_field(&c.right)
                )
                .unwrap();
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

/// The stable wire string for a volume tier.
///
/// Explicit (not `format!("{tier:?}")`) so a `VolumeTier` rename is a compile
/// error here rather than a silent JSON-contract change (#115).
fn tier_str(tier: VolumeTier) -> &'static str {
    match tier {
        VolumeTier::High => "high",
        VolumeTier::Medium => "medium",
        VolumeTier::Low => "low",
        VolumeTier::Negative => "negative",
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
        AuditField::A0 => "a0",
        AuditField::A1 => "a1",
        AuditField::A2 => "a2",
        AuditField::A3 => "a3",
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

#[cfg(test)]
mod tests {
    use super::tier_str;
    use rulesteward_auditd::bands::VolumeTier;

    #[test]
    fn tier_str_maps_each_variant_to_its_lowercase_name() {
        // Pins the JSON/human wire string for every VolumeTier variant. A variant
        // rename or a wrong arm silently changes the output contract; this guards
        // it (the prior `format!("{tier:?}").to_lowercase()` had no such test, #115).
        assert_eq!(tier_str(VolumeTier::High), "high");
        assert_eq!(tier_str(VolumeTier::Medium), "medium");
        assert_eq!(tier_str(VolumeTier::Low), "low");
        assert_eq!(tier_str(VolumeTier::Negative), "negative");
    }

    #[test]
    fn fmt_field_renders_syscall_argument_fields_a0_to_a3() {
        // #164: the a0..a3 syscall-argument fields must render their fieldtab.h
        // names (guards a copy-paste typo like A2 => "a1" in the fmt_field arms,
        // and confirms they reach the renderer at all).
        use super::fmt_field;
        use rulesteward_auditd::AuditField;
        assert_eq!(fmt_field(&AuditField::A0), "a0");
        assert_eq!(fmt_field(&AuditField::A1), "a1");
        assert_eq!(fmt_field(&AuditField::A2), "a2");
        assert_eq!(fmt_field(&AuditField::A3), "a3");
        // Anchor: an existing field still renders (guards an accidental reorder).
        assert_eq!(fmt_field(&AuditField::Arch), "arch");
    }

    #[test]
    fn fmt_rule_round_trips_dash_c_field_comparison() {
        // #161: a -C inter-field comparison must render back as `-C left op right`.
        // Dropping it would silently lose the privilege-transition clause from the
        // echoed rule text (the content bug the functional-smoke rule targets). A
        // `-C` is NOT a `-F`, so it renders with its own flag and two field names.
        use super::fmt_rule;
        use rulesteward_auditd::ast::{Action, AuditRule, FieldComparison, FilterList};
        use rulesteward_auditd::{AuditField, CompareOp};
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
            key: Some("priv".to_string()),
        };
        let rendered = fmt_rule(&rule);
        assert!(
            rendered.contains("-C uid!=euid"),
            "fmt_rule must render the -C comparison verbatim; got {rendered:?}"
        );
    }

    // -- #64: `auditd cost --format csv` (per-rule table ONLY) ----------------

    use super::{RuleEntry, render_csv_cost};
    use rulesteward_auditd::Direction;
    use rulesteward_auditd::bands::RateBand;
    use rulesteward_auditd::cost::{LogFormat, compute_cost_band};

    /// Build a `RuleEntry` for the CSV tests, deriving the cost band the same way
    /// the production builders do (so `gbPerDay` is the real computed value).
    fn entry(
        rule: &str,
        key: Option<&str>,
        tier: &str,
        dir: Direction,
        band: RateBand,
    ) -> RuleEntry {
        let cost = compute_cost_band(&band, LogFormat::Enriched, 5.0);
        RuleEntry {
            rule_text: rule.to_owned(),
            key: key.map(str::to_owned),
            tier: tier.to_owned(),
            direction: dir,
            rate_band: band,
            cost,
        }
    }

    /// CSV has a stable header and one flat row per rule: the nested event band
    /// is flattened to low/typical/high columns; `gbPerDay` is the per-rule cost.
    /// An absent key is an empty cell; a suppressive rule shows a zero band.
    #[test]
    fn csv_cost_per_rule_columns_and_values() {
        let entries = vec![
            entry(
                "-w /etc/passwd -p wa",
                Some("identity"),
                "high",
                Direction::Additive,
                RateBand {
                    low: 10.0,
                    typical: 20.0,
                    high: 30.0,
                },
            ),
            entry(
                "never-rule",
                None,
                "negative",
                Direction::Suppressive,
                RateBand::ZERO,
            ),
        ];
        let csv = render_csv_cost(&entries);
        let mut lines = csv.lines();
        assert_eq!(
            lines.next(),
            Some(
                "rule,key,tier,direction,eventsPerDayLow,eventsPerDayTypical,eventsPerDayHigh,gbPerDay"
            ),
            "stable flat header"
        );
        let rows: Vec<&str> = lines.collect();
        assert_eq!(rows.len(), 2, "one row per rule, no totals/summary row");

        let f: Vec<&str> = rows[0].split(',').collect();
        assert_eq!(f.len(), 8, "8 columns per row");
        assert_eq!(f[0], "-w /etc/passwd -p wa");
        assert_eq!(f[1], "identity");
        assert_eq!(f[2], "high");
        assert_eq!(f[3], "additive");
        assert!((f[4].parse::<f64>().unwrap() - 10.0).abs() < 1e-9);
        assert!((f[5].parse::<f64>().unwrap() - 20.0).abs() < 1e-9);
        assert!((f[6].parse::<f64>().unwrap() - 30.0).abs() < 1e-9);
        assert!(
            (f[7].parse::<f64>().unwrap() - entries[0].cost.gb_per_day.typical).abs() < 1e-12,
            "gbPerDay column must be the per-rule typical cost"
        );

        let s: Vec<&str> = rows[1].split(',').collect();
        assert_eq!(s[0], "never-rule");
        assert_eq!(s[1], "", "absent key is an empty cell");
        assert_eq!(s[3], "suppressive");
        assert!(
            s[5].parse::<f64>().unwrap().abs() < 1e-9,
            "suppressive band is zero"
        );
    }

    /// The CSV is the flat per-rule table ONLY: no totals, no band/confidence
    /// summary lines leak into it (locked decision: totals stay in JSON/human).
    #[test]
    fn csv_cost_excludes_totals_and_summary() {
        let entries = vec![entry(
            "r",
            None,
            "low",
            Direction::Additive,
            RateBand {
                low: 1.0,
                typical: 1.0,
                high: 1.0,
            },
        )];
        let csv = render_csv_cost(&entries);
        for forbidden in ["Estimated", "CONFIDENCE", "cost estimate", "(band"] {
            assert!(
                !csv.contains(forbidden),
                "CSV must be per-rule rows only; found `{forbidden}`:\n{csv}"
            );
        }
        assert_eq!(csv.lines().count(), 2, "header + exactly one rule row");
    }

    /// Rule text containing a comma is RFC-4180 quoted (delegated to `to_csv`).
    #[test]
    fn csv_cost_quotes_rule_text_with_comma() {
        let entries = vec![entry(
            "-a always,exit -S execve",
            Some("k"),
            "high",
            Direction::Additive,
            RateBand {
                low: 1.0,
                typical: 1.0,
                high: 1.0,
            },
        )];
        let csv = render_csv_cost(&entries);
        assert!(
            csv.contains("\"-a always,exit -S execve\""),
            "comma in rule text must be quoted:\n{csv}"
        );
    }
}

// ---------------------------------------------------------------------------
// auditd lint shell tests (#193, session 6a Phase 0). These exercise ONLY the
// shell's pure parts (target resolution, parse-error mapping, exit codes);
// the semantic-pass dispatcher is stubbed until the pipelines land and is
// covered by the (currently #[ignore]d) e2e contract tests at integration.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod lint_shell_tests {
    use super::{lint, resolve_lint_target};
    use crate::cli::{AuditdLintArgs, HumanJsonFormat};
    use crate::exit_code::{EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};

    fn args(path: &std::path::Path, format: HumanJsonFormat) -> AuditdLintArgs {
        AuditdLintArgs {
            path: Some(path.to_path_buf()),
            format,
        }
    }

    #[test]
    fn resolve_file_mode_returns_single_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("audit.rules");
        std::fs::write(&f, "-D\n").expect("write");
        let files = resolve_lint_target(&f).expect("file target resolves");
        assert_eq!(files, vec![f]);
    }

    #[test]
    fn resolve_dir_returns_load_ordered_rules_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("50-b.rules"), "-D\n").expect("write");
        std::fs::write(dir.path().join("10-a.rules"), "-D\n").expect("write");
        std::fs::write(dir.path().join("notes.txt"), "x").expect("write");
        let files = resolve_lint_target(dir.path()).expect("dir target resolves");
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["10-a.rules", "50-b.rules"]);
    }

    #[test]
    fn resolve_missing_path_errors() {
        let err = resolve_lint_target(std::path::Path::new("/nonexistent/6a/x"))
            .expect_err("missing path must error");
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn lint_missing_target_exits_tool_failure() {
        let a = args(
            std::path::Path::new("/nonexistent/6a/x"),
            HumanJsonFormat::Human,
        );
        assert_eq!(lint(&a), EXIT_TOOL_FAILURE);
    }

    #[test]
    fn lint_parse_error_exits_five_and_skips_semantic_passes() {
        // An unparseable line maps to au-F01 -> exit 5 (D3). Crucially this
        // must NOT invoke the semantic dispatcher (its passes are todo!()
        // stubs until the pipelines land; a partial stream would also make
        // cross-file claims unsound) - if it did, this test would panic.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("10-bad.rules"), "-Z bogus\n").expect("write");
        let a = args(dir.path(), HumanJsonFormat::Json);
        assert_eq!(lint(&a), EXIT_RULE_PARSE_ERROR);
    }
}
