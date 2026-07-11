//! auditd module - rule parser, cost calculator, band classifier, and log converter.
//!
//! Module skeletons are wired here; real implementations land in pipeline P2
//! (see per-module doc comments for issue references).

pub mod ast;
pub mod bands;
pub mod cost;
pub mod from_log;
pub mod lints;
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
