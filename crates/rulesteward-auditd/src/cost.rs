//! auditd rule cost calculator.
//!
//! Issue #88 -- pipeline P2.
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
pub fn bytes_per_event(fmt: LogFormat) -> u64 {
    match fmt {
        LogFormat::Enriched => 1_200,
        LogFormat::Raw => 900, // 1200 * 0.75
    }
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

// Decimal GB: bytes / 1e9 (NOT GiB / 2^30).
const BYTES_PER_GB: f64 = 1_000_000_000.0;
const DAYS_PER_MONTH: f64 = 30.4;

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
pub fn compute_cost_band(rate_band: &RateBand, fmt: LogFormat, price_per_gb_usd: f64) -> CostBand {
    // bytes_per_event returns 1200 or 900 -- both well within f64 precision range.
    #[allow(clippy::cast_precision_loss)]
    let bpe = bytes_per_event(fmt) as f64;

    let gb_low = rate_band.low * bpe / BYTES_PER_GB;
    let gb_typical = rate_band.typical * bpe / BYTES_PER_GB;
    let gb_high = rate_band.high * bpe / BYTES_PER_GB;

    let cost_low = gb_low * DAYS_PER_MONTH * price_per_gb_usd;
    let cost_typical = gb_typical * DAYS_PER_MONTH * price_per_gb_usd;
    let cost_high = gb_high * DAYS_PER_MONTH * price_per_gb_usd;

    CostBand {
        events_per_day: rate_band.clone(),
        gb_per_day: RateBand {
            low: gb_low,
            typical: gb_typical,
            high: gb_high,
        },
        cost_per_month_usd: RateBand {
            low: cost_low,
            typical: cost_typical,
            high: cost_high,
        },
    }
}

/// Sum a slice of `RateBand`s into one aggregate band.
///
/// Only additive rules' bands should be summed; suppressive (Negative) rules
/// contribute `RateBand::ZERO` and must not inflate the total.
#[must_use]
pub fn sum_rate_bands(bands: &[RateBand]) -> RateBand {
    bands.iter().fold(RateBand::ZERO, |acc, b| RateBand {
        low: acc.low + b.low,
        typical: acc.typical + b.typical,
        high: acc.high + b.high,
    })
}
