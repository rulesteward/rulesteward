//! fapd-W06 - a `path=`/`exe=` literal value in neither the trust DB nor on disk.
//! STUB: the body is filled by the W06 fan-out pipeline (Task 4). The SIGNATURE
//! is the frozen contract that `lint_with_context` and the W06 tests depend on;
//! until the body lands, it emits no diagnostics so the no-context invariant holds.
use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::trustdb::TrustDb;

#[allow(unused_variables)] // STUB params; the W06 fan-out body uses them.
pub(crate) fn w06(entries: &[Entry], file: &Path, db: &TrustDb) -> Vec<Diagnostic> {
    Vec::new()
}
