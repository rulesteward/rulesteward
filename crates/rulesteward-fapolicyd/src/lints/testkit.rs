//! Shared `#[cfg(test)]` AST builders for the fapolicyd lint test modules.
//!
//! Each lint's `mod tests` previously defined byte-identical private copies of
//! these builders. This is the single source. Compiled only under `#[cfg(test)]`
//! and `pub(crate)`, so sibling unit-test modules reach it without leaking into
//! the public API.
#![cfg(test)]

use std::path::PathBuf;

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};

/// Canonical rules-file path used by the lint tests.
pub(crate) fn p() -> PathBuf {
    PathBuf::from("/tmp/test.rules")
}

/// `key=value` string attribute.
pub(crate) fn kv(key: &str, value: &str) -> Attr {
    Attr::Kv {
        key: key.to_string(),
        value: AttrValue::Str(value.to_string()),
        span: 0..0,
    }
}

/// `key=<int>` integer attribute.
pub(crate) fn kv_int(key: &str, value: i64) -> Attr {
    Attr::Kv {
        key: key.to_string(),
        value: AttrValue::Int(value),
        span: 0..0,
    }
}

/// `key=%set` macro-reference attribute.
pub(crate) fn kv_ref(key: &str, set: &str) -> Attr {
    Attr::Kv {
        key: key.to_string(),
        value: AttrValue::SetRef(set.to_string()),
        span: 0..0,
    }
}

/// A Modern-flavor rule entry. Named `modern_rule` to disambiguate from
/// `walker.rs`'s `legacy_rule`. The 4-arg `cross_db` variant folds in here by
/// passing `perm = None`.
pub(crate) fn modern_rule(
    line: usize,
    decision: Decision,
    perm: Option<Perm>,
    subj: Vec<Attr>,
    obj: Vec<Attr>,
) -> Entry {
    Entry::Rule(Rule {
        decision,
        perm,
        subject: subj,
        object: obj,
        syntax: SyntaxFlavor::Modern,
        line,
        span: rulesteward_core::span(0, 0),
    })
}

/// A Legacy-flavor rule entry (pre-1.4 / no-colon `perm` grammar). Mirror of
/// `modern_rule` with `syntax = SyntaxFlavor::Legacy`, so a test can assert a
/// value lint emits identical diagnostics regardless of flavor (the value lints
/// key off attributes, not `Rule.syntax`). `walker.rs` keeps a private copy for
/// its fapd-F03 flavor-mix tests; this is the shared one for sibling modules.
pub(crate) fn legacy_rule(
    line: usize,
    decision: Decision,
    perm: Option<Perm>,
    subj: Vec<Attr>,
    obj: Vec<Attr>,
) -> Entry {
    Entry::Rule(Rule {
        decision,
        perm,
        subject: subj,
        object: obj,
        syntax: SyntaxFlavor::Legacy,
        line,
        span: rulesteward_core::span(0, 0),
    })
}

/// A set-definition entry. Canonical superset of the four pre-existing
/// `setdef`/`set_def` shapes.
pub(crate) fn set_def(line: usize, name: &str, values: &[&str]) -> Entry {
    Entry::SetDefinition {
        name: name.to_string(),
        values: values.iter().map(|s| (*s).to_string()).collect(),
        line,
        span: rulesteward_core::span(0, 0),
    }
}
