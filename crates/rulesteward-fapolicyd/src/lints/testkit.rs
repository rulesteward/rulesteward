//! Shared `#[cfg(test)]` AST builders for the fapolicyd lint test modules.
//!
//! Each lint's `mod tests` previously defined byte-identical private copies of
//! these builders. This is the single source. Compiled only under `#[cfg(test)]`
//! and `pub(crate)`, so sibling unit-test modules reach it without leaking into
//! the public API. Bodies are filled in Task 1 (CLEAN-1).
#![cfg(test)]
// Transitional: the imports below are unused until Task 1 (CLEAN-1) fills the
// builder bodies. Kept here (not removed) so the Phase-0 stub matches the plan
// and every lane worktree branches off a warning-clean foundation. Task 1
// removes this `allow` once the builders consume every import.
#![allow(unused_imports)]

use std::path::PathBuf;

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
