//! Shared types for the `RuleSteward` toolkit.
//!
//! Diagnostics and severity live here so every module (`fapolicyd`,
//! `selinux`, `auditd`, …) emits the same wire shape.

pub mod audit;
pub mod diagnostic;
pub mod lint_code;
pub mod span;

pub use audit::extract_audit_field;
pub use diagnostic::{Diagnostic, Severity, anchored, anchored_at, parse_error_diagnostic};
pub use lint_code::BaseLintCode;
pub use span::span_util::fill_columns;
pub use span::{Span, span, span_util};
