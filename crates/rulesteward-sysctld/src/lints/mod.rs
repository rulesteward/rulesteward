//! Semantic lint passes over a parsed `sysctl.d`/`sysctl.conf` file - PHASE-0 STUB.
//!
//! v1 ships two passes (issue #150):
//! * `sysctld-F01` - parse failure (emitted by the parser, not a pass here).
//! * `sysctld-W01` - last-wins conflict (the same key assigned different effective
//!   values across the drop-in precedence order).
//!
//! The `sysctld-` code catalog is frozen in Phase 0 ([`crate::catalog`]). The
//! dispatcher below is the conflict-free Phase-0 scaffold and returns no findings
//! yet; the F01/W01 impl fills the pass bodies in the test-author barrier + impl
//! pipeline.

use std::path::Path;

use rulesteward_core::Diagnostic;

/// Run every `sysctld-` semantic lint pass over a parsed file's assignments and
/// return the merged diagnostic list, in catalog order for byte-stable output.
///
/// PHASE-0 STUB: always returns an empty `Vec`. The W01 (last-wins conflict) pass
/// is filled in by the lint-impl pipeline (issue #150). The signature mirrors the
/// sshd `lints::lint` dispatcher shape so the impl pipeline only fills this body.
#[must_use]
pub fn lint(file: &Path) -> Vec<Diagnostic> {
    // Phase-0 stub: no passes run yet. The W01 impl replaces this with the real
    // per-pass dispatch over the parsed assignment model.
    let _ = file;
    Vec::new()
}
