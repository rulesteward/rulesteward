//! auditd module - rule parser, cost calculator, band classifier, and log converter.

pub mod ast;
pub mod bands;
pub mod cost;
pub mod from_log;
pub mod lints;
// Differential-oracle adapter. Not a product feature: it is the
// product side of `tests/auditd_corpus_oracle.rs`, which checks this crate's
// parser against what the real `auditctl -R` said. It lives in `src/` so the
// one function that decides "did the daemon accept this line?" is covered by
// clippy, the coverage floor and the mutation gate.
pub mod oracle;
pub mod parser;

// Re-export the primary public surface for convenience.
pub use ast::{
    Action, AuditField, AuditRule, CompareOp, ControlRule, FieldComparison, FieldFilter,
    FilterList, LocatedRule, PermBits,
};
pub use bands::{Direction, RateBand, VolumeTier};
pub use cost::{CostBand, LogFormat};
pub use from_log::{LogReadError, MeasuredRates};
pub use lints::TargetVersion;
pub use parser::{
    LocatedParseError, ParseError, parse_rules_file, parse_rules_file_located, parse_rules_str,
    parse_rules_str_located, parse_target, parse_target_located, rules_files_in_load_order,
};
