//! Shared types for the `RuleSteward` toolkit.
//!
//! Diagnostics and severity live here so every module (`fapolicyd`,
//! `selinux`, `auditd`, …) emits the same wire shape.

pub mod diagnostic;
pub mod span;

pub use diagnostic::{Diagnostic, Severity};
pub use span::{Span, span, span_util};
