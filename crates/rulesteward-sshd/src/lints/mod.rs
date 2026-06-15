//! Semantic lint passes over a parsed `sshd_config` file.
//!
//! Code split (one file per semantic family; the parallel pipelines each fill
//! ONE file's bodies, mirroring the auditd crate's Phase-0 freeze):
//! * `structural` - sshd-E01 unknown directive, sshd-E02 duplicate global,
//!   sshd-E03 Include resolution, sshd-E04 Match-illegal directive, sshd-W05
//!   permissive Match override (Wave A, plus the registry-gated E01).
//! * `stig` - sshd-W01 required-directive-missing, sshd-W02 weaker-than-baseline
//!   (Wave B; gated on the STIG-baseline grounding task).
//! * `crypto` - sshd-W03 weak algorithm, sshd-W06 prefix-op reintroduction
//!   (Wave B/C; gated on the per-version default-algorithm lists).
//! * `deprecation` - sshd-W04 deprecated/removed directive (Wave B).
//! * `catalog` - the machine-readable `sshd-` code catalog (frozen Phase 0).
//!
//! Every pass is a `Vec::new()`-returning stub in Phase 0: the dispatcher runs
//! for real (so `rulesteward sshd lint` works end to end and a clean file exits
//! 0), but the only code actually emitted today is `sshd-F01` from the parser,
//! mapped by [`parse_error_to_diagnostic`]. Pass modules are `pub` so each
//! pipeline's tests can call their own entrypoint directly.

pub mod catalog;
pub mod crypto;
pub mod deprecation;
pub mod registry;
pub mod stig;
pub mod structural;

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity, Span};

use crate::ast::Block;
use crate::parser::LocatedParseError;

/// Target OS / OpenSSH baseline for the version-aware lints (sshd-W01..W04).
///
/// Selected by the CLI's shared `--target rhel8|rhel9|rhel10` value-enum (the
/// same umbrella the fapolicyd backend uses for version-aware checks). Each RHEL
/// release pins an OpenSSH version and a DISA STIG required-directive baseline;
/// the mapping tables are the Wave-B grounding work and are not in Phase 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// Inputs the lint passes share beyond the parsed blocks.
///
/// `target` is `None` when the operator did not pass `--target`; the
/// version-aware passes (Wave B) decide how to behave in that case. `single_file`
/// distinguishes linting one file from linting a directory of drop-ins (relevant
/// to the future cross-file sshd-F02).
#[derive(Debug, Clone, Copy)]
pub struct SshdLintContext {
    /// The `--target` baseline, or `None` when unspecified.
    pub target: Option<TargetVersion>,
    /// True when the lint target is a single file (not a drop-in directory).
    pub single_file: bool,
}

impl Default for SshdLintContext {
    fn default() -> Self {
        Self {
            target: None,
            single_file: true,
        }
    }
}

/// Build a byte-anchored `Diagnostic` with the sshd emission convention: column
/// 1 (line-start) and the source-id set to the file path's display string.
///
/// sshd directive spans cover the whole raw line (see
/// [`crate::parser::parse_config_str_located`]), so the line-start anchor is
/// exact and no span-derived column backfill is needed. `pub` because the lint
/// passes emit through it; pinned by `anchored_equals_handwritten_diagnostic` so
/// a refactor that changes its output shape fails fast.
#[must_use]
pub fn anchored(
    sev: Severity,
    code: &'static str,
    span: Span,
    msg: impl Into<String>,
    file: impl Into<std::path::PathBuf>,
    line: usize,
) -> Diagnostic {
    let file = file.into();
    let source_id = file.display().to_string();
    Diagnostic::new(sev, code, span, msg, file, line, 1).with_source_id(source_id)
}

/// Map a located parse error to an `sshd-F01` Fatal diagnostic.
///
/// Lives here (not in the CLI) because this crate OWNS the `sshd-` codes and is
/// inside the mutation `examine_globs`. Parse errors carry file + line but no
/// byte span (the failing line never became a directive), so the diagnostic is
/// unanchored: empty span, no source-id, plain rendering. `line == 0` marks a
/// file-level error (unreadable file) and keeps column 0; a line-level error gets
/// column 1.
#[must_use]
pub fn parse_error_to_diagnostic(err: &LocatedParseError) -> Diagnostic {
    let column = usize::from(err.line != 0);
    Diagnostic::new(
        Severity::Fatal,
        "sshd-F01",
        0..0,
        err.message.clone(),
        err.file.clone(),
        err.line,
        column,
    )
}

/// Run every single-file semantic lint pass over the parsed blocks and return the
/// merged diagnostic list, in catalog order for byte-stable output.
///
/// Phase 0: every pass is a stub returning no diagnostics, so a successfully
/// parsed file yields an empty list (exit 0). The passes are filled by the
/// parallel pipelines under epic #149. The cross-file sshd-F02 (drop-in override)
/// is a future separate entrypoint, not part of this single-file dispatcher.
#[must_use]
pub fn lint(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = structural::e01(blocks, file, ctx);
    diags.extend(structural::e02(blocks, file, ctx));
    diags.extend(structural::e03(blocks, file, ctx));
    diags.extend(structural::e04(blocks, file, ctx));
    diags.extend(stig::w01(blocks, file, ctx));
    diags.extend(stig::w02(blocks, file, ctx));
    diags.extend(crypto::w03(blocks, file, ctx));
    diags.extend(deprecation::w04(blocks, file, ctx));
    diags.extend(structural::w05(blocks, file, ctx));
    diags.extend(crypto::w06(blocks, file, ctx));
    diags
}

#[cfg(test)]
mod tests {
    use super::{SshdLintContext, anchored, lint, parse_error_to_diagnostic};
    use crate::parser::LocatedParseError;
    use rulesteward_core::{Diagnostic, Severity};

    #[test]
    fn anchored_equals_handwritten_diagnostic() {
        let file = std::path::Path::new("/etc/ssh/sshd_config");
        let span = 3..9;
        let got = anchored(
            Severity::Warning,
            "sshd-W01",
            span.clone(),
            "missing",
            file,
            7,
        );
        let want = Diagnostic::new(Severity::Warning, "sshd-W01", span, "missing", file, 7, 1)
            .with_source_id(file.display().to_string());
        assert_eq!(got, want);
    }

    #[test]
    fn parse_error_maps_to_sshd_f01_fatal() {
        let err = LocatedParseError {
            file: "/etc/ssh/sshd_config".into(),
            line: 7,
            message: "unterminated quoted string".to_string(),
        };
        let d = parse_error_to_diagnostic(&err);
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "sshd-F01");
        assert_eq!(d.message, "unterminated quoted string");
        assert_eq!(d.file, err.file);
        assert_eq!(d.line, 7);
        assert_eq!(d.column, 1, "line-level parse errors anchor at column 1");
        assert_eq!(d.span, 0..0, "parse errors carry no byte span");
        assert!(d.source_id.is_none(), "unanchored: plain rendering");
    }

    #[test]
    fn file_level_parse_error_keeps_line_and_column_zero() {
        let err = LocatedParseError {
            file: "/nonexistent".into(),
            line: 0,
            message: "cannot read file".to_string(),
        };
        let d = parse_error_to_diagnostic(&err);
        assert_eq!((d.line, d.column), (0, 0), "file-level errors stay 0/0");
        assert_eq!(d.code, "sshd-F01");
    }

    #[test]
    fn dispatcher_on_parsed_blocks_is_empty_in_phase_0() {
        // Every pass is a Phase-0 stub, so a parsed file yields no diagnostics
        // (exit 0). This pins the no-op contract: if a pass starts emitting before
        // its tests are wired, this fails and forces the wiring.
        let blocks = crate::parser::parse_config_str_located(
            "PermitRootLogin no\nMaxAuthTries 4\n",
            std::path::Path::new("/etc/ssh/sshd_config"),
        )
        .expect("valid config parses");
        let diags = lint(
            &blocks,
            std::path::Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        );
        assert!(
            diags.is_empty(),
            "Phase-0 passes emit nothing; got {diags:?}"
        );
    }
}
