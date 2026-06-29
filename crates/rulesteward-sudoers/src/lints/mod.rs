//! Semantic lint passes over parsed `sudoers(5)` files.
//!
//! Code split (one file per semantic family; the parallel pipelines each fill ONE
//! file's bodies, mirroring the sshd / auditd crates' Phase-0 freeze):
//! * `aliases` - sudo-E01 (undefined-alias reference), sudo-W03 (dead alias)
//!   (#331).
//! * `tags` - sudo-W01 (NOPASSWD on ALL; #330), sudo-W02 (`Cmnd_Alias`
//!   transitively expands to ALL under NOPASSWD; #332).
//! * `stig` - sudo-W04 (Defaults setting weaker than the sudo STIG baseline)
//!   (#333).
//! * `catalog` - the machine-readable `sudo-` code catalog (frozen Phase 0).
//!
//! The dispatcher [`lint`] runs every pass for real (so `rulesteward sudoers lint`
//! works end to end and a clean file exits 0). In Phase 0 only `sudo-F01` emits
//! (one Fatal per [`Malformed`](crate::ast::LineKind::Malformed) logical line); the
//! e01/w01..w04 passes are `Vec::new()` stubs filled by the later pipelines. Pass
//! modules are `pub` so each pipeline's tests can call their own entrypoint
//! directly.

pub mod aliases;
pub mod catalog;
pub mod stig;
pub mod tags;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{LineKind, SudoersFile};

/// Inputs the lint passes share beyond the parsed files.
///
/// Phase 0 carries no fields - the sudo STIG findings (#333) are version-agnostic,
/// so there is intentionally NO `--target` rail (unlike the sshd / sysctld
/// backends). The struct exists so the later passes can grow shared context
/// without changing the [`lint`] signature. `#[non_exhaustive]` is deliberately
/// NOT used: the struct is constructed by both the CLI and the in-crate tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct SudoersLintContext {}

/// Build a byte-anchored `Diagnostic` with the sudoers emission convention: column
/// 1 (line-start) and the source-id set to the file path's display string.
///
/// Re-exported from the shared `rulesteward-core` helper (issue #289); the lint
/// passes emit through `crate::lints::anchored`.
pub use rulesteward_core::anchored;

/// Run every semantic lint pass over the parsed `files` and return the merged
/// diagnostic list, in catalog order for byte-stable output.
///
/// Takes a SLICE so the include/dir resolution seam (#334) only populates the
/// slice and never changes this signature. In Phase 0 only [`f01`] emits; the
/// other passes are stubs.
#[must_use]
pub fn lint(files: &[SudoersFile], ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = aliases::e01(files, ctx);
    diags.extend(f01(files, ctx));
    diags.extend(tags::w01(files, ctx));
    diags.extend(tags::w02(files, ctx));
    diags.extend(aliases::w03(files, ctx));
    diags.extend(stig::w04(files, ctx));
    diags
}

/// sudo-F01: emit a Fatal for every [`Malformed`](LineKind::Malformed) logical
/// line across all files.
///
/// The diagnostic is UNANCHORED (empty span, no source-id, plain rendering),
/// mirroring sshd's `parse_error_to_diagnostic` convention: a malformed line never
/// became a structured node, so there is no byte range to caret. The 1-based line
/// number is carried so the operator can find it; `column` is 1 for a real line.
#[must_use]
pub fn f01(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for line in &file.lines {
            if let LineKind::Malformed(message) = &line.kind {
                diags.push(Diagnostic::new(
                    Severity::Fatal,
                    "sudo-F01",
                    0..0,
                    message.clone(),
                    file.path.clone(),
                    line.line,
                    1,
                ));
            }
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::{SudoersLintContext, f01, lint};
    use crate::parser::parse;
    use std::path::Path;

    fn parse_one(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    #[test]
    fn f01_emits_one_fatal_per_malformed_line() {
        let files = parse_one("frobnicate\nroot ALL=(ALL) ALL\nalso garbage\n");
        let diags = f01(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 2, "two malformed lines -> two sudo-F01");
        for d in &diags {
            assert_eq!(d.code, "sudo-F01");
            assert_eq!(d.severity, rulesteward_core::Severity::Fatal);
            assert!(d.source_id.is_none(), "F01 is unanchored: plain rendering");
            assert_eq!(d.span, 0..0);
        }
        // The first malformed line is line 1; the second is line 3.
        assert_eq!(diags[0].line, 1);
        assert_eq!(diags[1].line, 3);
    }

    #[test]
    fn f01_carries_the_malformed_message() {
        let files = parse_one("frobnicate\n");
        let diags = f01(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 1);
        assert!(
            !diags[0].message.trim().is_empty(),
            "the F01 message describes why the line is malformed"
        );
    }

    #[test]
    fn clean_file_produces_no_diagnostics_in_phase_0() {
        // A fully valid sudoers file emits nothing today: F01 finds no malformed
        // lines and the e01/w01..w04 passes are stubs.
        let files = parse_one(
            "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n",
        );
        let diags = lint(&files, &SudoersLintContext::default());
        assert!(
            diags.is_empty(),
            "a clean file produces no diagnostics in Phase 0; got {diags:?}"
        );
    }

    #[test]
    fn lint_dispatcher_emits_f01_for_a_malformed_file() {
        let files = parse_one("this is not valid sudoers\n");
        let diags = lint(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sudo-F01");
    }

    #[test]
    fn lint_spans_multiple_files() {
        // The slice signature lets #334 feed several SudoersFiles; F01 reports
        // across all of them.
        let mut files = parse_one("root ALL=(ALL) ALL\n");
        files.extend(parse_one("garbage here\n"));
        let diags = lint(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 1, "the malformed second file yields one F01");
        assert_eq!(diags[0].code, "sudo-F01");
    }
}
