//! auditd rule cost calculator.
//!
//! Filled by pipeline P2 (issue #88).
//!
//! # Grounding
//! - Single ~1200 B/event constant (ENRICHED) LOCKED 2026-06-03 (issue #88 body,
//!   Wave-1b VM measurement; supersedes per-record-sum model).
//! - RAW factor ~0.75x (f3 section 3.4).
//! - Decimal GB (`10^9`) matches SIEM billing (f3 section 4.1).
//! - `gb_per_month` = `gb_per_day` * 30.4 (f3 section 4.1 math).

use crate::bands::RateBand;

/// `log_format = ENRICHED` (default, VM-measured) or `RAW` (f3 section 3.4).
///
/// ENRICHED appends resolved-name fields (~27% overhead on SYSCALL records).
/// RAW reduces per-event bytes by ~25% (factor 0.75).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum LogFormat {
    #[default]
    Enriched,
    Raw,
}

/// Bytes per complete audit event for the given log format.
///
/// LOCKED constant: 1200 B/event ENRICHED (f3 section 3.3, Wave-1b).
/// RAW = 1200 * 0.75 = 900 B/event (f3 section 3.4 factor).
///
/// These are the ONLY operative constants; the per-record figures (SYSCALL ~500,
/// PATH ~260, etc.) are retained as evidence in issue #88, not used by the model.
#[must_use]
pub fn bytes_per_event(_fmt: LogFormat) -> u64 {
    todo!("P2 #88 fills cost model")
}

/// Cost estimate for a single rule or for the full ruleset total.
///
/// All monetary values are in USD. GB is decimal (`10^9` bytes per f3 section 4.1).
#[derive(Debug, Clone, PartialEq)]
pub struct CostBand {
    /// Assumed events/day: low / typical / high.
    pub events_per_day: RateBand,
    /// Estimated GB/day: low / typical / high.
    pub gb_per_day: RateBand,
    /// Estimated cost in USD/month: low / typical / high.
    pub cost_per_month_usd: RateBand,
}

/// Compute a `CostBand` from an events/day band, log format, and price/GB.
///
/// Uses the formula from f3 section 4.1:
/// ```text
/// gb_per_day = events_per_day * bytes_per_event / 1e9
/// cost_per_month = gb_per_day * 30.4 * price_per_gb
/// ```
///
/// Arguments:
/// - `rate_band` - events/day low/typical/high.
/// - `fmt` - ENRICHED or RAW log format.
/// - `price_per_gb_usd` - price per decimal GB; default is 5.00 per f3 section 4.2.
#[must_use]
pub fn compute_cost_band(
    _rate_band: &RateBand,
    _fmt: LogFormat,
    _price_per_gb_usd: f64,
) -> CostBand {
    todo!("P2 #88 fills cost model")
}

/// Sum a slice of `RateBand`s into one aggregate band.
///
/// Only additive rules' bands should be summed; suppressive (Negative) rules
/// contribute `RateBand::ZERO` and must not inflate the total.
#[must_use]
pub fn sum_rate_bands(_bands: &[RateBand]) -> RateBand {
    todo!("P2 #88 fills cost model")
}
