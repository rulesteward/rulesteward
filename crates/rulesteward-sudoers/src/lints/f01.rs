//! sudo-F01 (#433 split from `lints/mod.rs`): a Fatal for every
//! `Malformed` logical line.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

/// sudo-F01: emit a Fatal for every [`Malformed`](LineKind::Malformed) logical
/// line across all files.
///
/// Unlike auditd/sshd (whose parsers can fail and gate anchoring on
/// `line == 0`, a genuine file-level I/O failure), the sudoers parser is TOTAL
/// (see `parser::parse`) and every [`LogicalLine`] -- even a synthesized
/// `@include`-resolution marker (`resolve::malformed_marker`) -- carries a real,
/// nonzero `line` number. The signal that distinguishes an ANCHORABLE malformed
/// line from one that is not is therefore the line's byte `span`: a genuine
/// malformed line inside real source text carries a non-empty span into that
/// file's own `source`, so it anchors (`source_id` set to the file's display
/// path, ariadne can render a caret snippet). A missing/cyclic `@include`
/// target has no real backing source (the resolver's marker has an empty
/// `source` and `Span::default()`), so it stays UNANCHORED (no `source_id`,
/// span preserved as `0..0`) -- while still carrying the real directive line
/// number, since sudoers always knows which `@include` failed (issue #382).
/// `column` is 1 for every real line, anchored or not.
#[must_use]
pub fn f01(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for line in &file.lines {
            if let LineKind::Malformed(message) = &line.kind {
                if line.span.is_empty() {
                    // Synthetic marker (missing/cyclic @include): no real backing
                    // source, so it stays unanchored, preserving the real
                    // directive line number.
                    diags.push(Diagnostic::new(
                        Severity::Fatal,
                        "sudo-F01",
                        0..0,
                        message.clone(),
                        file.path.clone(),
                        line.line,
                        1,
                    ));
                } else {
                    // A genuine malformed line in real source text: anchor so
                    // ariadne can render a caret snippet.
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F01",
                        line.span.clone(),
                        message.clone(),
                        file.path.clone(),
                        line.line,
                    ));
                }
            }
        }
    }
    diags
}
