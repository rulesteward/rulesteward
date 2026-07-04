//! `sysctl lint --system`: cross-directory precedence scan (issue #420).
//!
//! Real systems apply `sysctl.d` drop-ins across a search path of four-plus
//! directories plus `/etc/sysctl.conf`; the effective value of a key can be
//! silently decided by a file the operator would not expect to win. This module
//! is meant to enumerate that search path (optionally rooted at a `--root`
//! prefix for hermetic testing), apply the grounded same-basename directory
//! masking + global lexicographic merge, and run the existing `sysctld-F01`/
//! `sysctld-W01`/`sysctld-W02` passes over the merged, precedence-ordered
//! assignment list plus the new cross-directory `sysctld-W03` pass (three
//! sub-cases: lower-precedence-directory override, procps/systemd applier
//! divergence, and a masked drop-in that silently drops a key). See
//! `rulesteward-docs/2026-07-04-sysctld-cross-directory-precedence-420-design.md`
//! for the full grounded model.
//!
//! # Phase 0 (this file, today)
//! [`lint_system`] is a STUB: it always returns an empty result. It exists only
//! so the `--system`/`--root` CLI surface and the crate's public API compile;
//! the real enumeration/mask/merge/W03 logic lands with the impl pipeline. The
//! existing [`crate::parser::lint_str`] / [`crate::parser::lint_dir`] entry
//! points are untouched and never emit `sysctld-W03`.

use std::collections::BTreeMap;
use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::lints::baseline::TargetVersion;

/// Scan the standard `sysctl.d` search-path directories (`/etc/sysctl.d`,
/// `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`) plus
/// `/etc/sysctl.conf`, optionally rooted at `root` (the `--root PREFIX`
/// hermetic-testing / chroot-linting surface), and run the full `sysctld-`
/// pass set over the precedence-merged result: `sysctld-F01`/`sysctld-W01`,
/// the version-aware `sysctld-W02` when `target` is `Some`, and the
/// cross-directory `sysctld-W03`.
///
/// Returns the diagnostics plus every read file's staged source (keyed by
/// display path, the `source_id` convention `anchored` sets), so the human
/// renderer can show an ariadne snippet (issue #337 convention), matching
/// [`crate::parser::lint_dir_with_target`]'s return shape.
///
/// STUB (issue #420 Phase 0): always returns `(vec![], BTreeMap::new())`. No
/// enumeration, masking, merge, or `sysctld-W03` detection happens yet.
#[must_use]
pub fn lint_system(
    _root: Option<&Path>,
    _target: Option<TargetVersion>,
) -> (Vec<Diagnostic>, BTreeMap<String, String>) {
    (Vec::new(), BTreeMap::new())
}
