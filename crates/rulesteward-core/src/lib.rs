//! Shared types for the `RuleSteward` toolkit.
//!
//! Diagnostics, severity, and AST primitives live here so every module
//! (`fapolicyd`, `selinux`, `auditd`, …) emits the same wire shape.
//!
//! Session 1 ships an intentionally empty surface; types land in session 2
//! alongside the first parser. See `.private-docs/handoff-session-2.md`.

#[doc(hidden)]
pub fn placeholder() {}
