//! fapd-X01 - trust-DB entries not referenced by any rule (one capped summary).
//! STUB: the body is filled by the X01 fan-out pipeline (Task 5). Invoked from the
//! CLI (not from `lint_with_context`). The SIGNATURE is the frozen contract.
use std::path::PathBuf;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::trustdb::TrustDb;

#[allow(unused_variables)] // STUB params; the X01 fan-out body uses them.
#[must_use]
pub fn lint_orphans(files: &[(PathBuf, Vec<Entry>)], db: &TrustDb) -> Vec<Diagnostic> {
    Vec::new()
}
