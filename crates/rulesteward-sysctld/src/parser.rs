//! `sysctl.d`/`sysctl.conf` parser - PHASE-0 STUB.
//!
//! `sysctl.conf(5)` syntax is `token = value` lines: whole-line `#`/`;` comments,
//! `key = value` assignments (a leading `-` on the key suppresses load errors),
//! and blank lines. The real tokenizer + assignment model land with the F01/W01
//! implementation in the test-author barrier + impl pipeline (issue #150); this
//! file is the conflict-free Phase-0 scaffold and parses nothing yet.

use std::path::Path;

use rulesteward_core::Diagnostic;

/// Parse `source` (the contents of a `sysctl.d`/`sysctl.conf` file at `path`) and
/// run the `sysctld-` lint passes over it, returning the merged diagnostics.
///
/// PHASE-0 STUB: always returns an empty `Vec`. The real parse + F01/W01 passes
/// are filled in by the lint-impl pipeline (issue #150); this is the frozen
/// public entry point the CLI command handler calls, kept minimal and obviously
/// stub so the Phase-0 wiring compiles and runs end to end.
#[must_use]
pub fn lint_str(source: &str, path: &Path) -> Vec<Diagnostic> {
    // Phase-0 stub: discard the inputs and emit no findings. The F01/W01 impl
    // replaces this body with a real tokenizer + the lints dispatcher.
    let _ = (source, path);
    Vec::new()
}
