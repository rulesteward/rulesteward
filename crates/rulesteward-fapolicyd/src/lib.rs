//! fapolicyd module: rule parser, trust-DB reader, audit-log reader.
//!
//! Session 1 ships a stub. The real parser (chumsky 0.13 + ariadne 0.6
//! diagnostics) and the `lint` lint passes land in session 2 — see
//! `.private-docs/handoff-session-2.md`.

#[doc(hidden)]
pub fn placeholder() {}
