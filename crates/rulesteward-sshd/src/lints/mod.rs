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
//! The dispatcher runs every pass for real (so `rulesteward sshd lint` works end
//! to end and a clean file exits 0). 8 of the 10 single-file passes emit today
//! (sshd-E01..E04, sshd-W01..W04), alongside `sshd-F01` from the parser (mapped by
//! [`parse_error_to_diagnostic`]); only sshd-W05 and sshd-W06 remain `Vec::new()`
//! stubs (Wave C, gated on the W01 required-set and the per-version
//! default-algorithm lists). Pass modules are `pub` so each pipeline's tests can
//! call their own entrypoint directly.

pub mod catalog;
pub mod crypto;
pub mod deprecation;
pub mod drop_in;
pub mod registry;
pub mod stig;
pub mod structural;

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, MatchBlock};
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

/// Whether a `Match` block is the unconditional `Match all`: exactly one criterion
/// whose keyword is case-insensitively `all` AND which carries no value.
///
/// `Match all` is always active (verified rocky9 `sshd -T`), so its body is GLOBAL
/// context, not a per-connection override: the structural passes (sshd-E04 illegal-
/// in-Match, sshd-W05 permissive override) skip it, and the STIG passes (sshd-W01 /
/// sshd-W02) fold its body into the effective-global set via
/// `stig::effective_global_directives`. Shared by `structural`, `stig`, and
/// `drop_in` so all three classify `Match all` identically.
///
/// The `values.is_empty()` guard is load-bearing: real sshd does NOT accept `all`
/// with an argument. `Match all=` / `Match all=foo` is an "Unsupported Match
/// attribute" that `sshd -t` rejects (rc 255; OpenSSH `servconf.c` `match_cfg_line`,
/// where `all` is absent from the `=`-split allowlist and the `all` handler rejects
/// any argument). The tolerant parser splits criteria on `=` first, so `all=`
/// arrives as a single criterion `{keyword:"all", values:[""]}`; the non-empty value
/// marks it as NOT the genuine valueless `all`, so it stays conditional and the
/// structural passes still apply to it (issue #336).
pub(crate) fn is_unconditional_match_all(block: &MatchBlock) -> bool {
    block.criteria.len() == 1
        && block.criteria[0].keyword.eq_ignore_ascii_case("all")
        && block.criteria[0].values.is_empty()
}

/// Build a byte-anchored `Diagnostic` with the sshd emission convention: column
/// 1 (line-start) and the source-id set to the file path's display string.
///
/// sshd directive spans cover the whole raw line (see
/// [`crate::parser::parse_config_str_located`]), so the line-start anchor is
/// exact and no span-derived column backfill is needed. Re-exported from the
/// shared `rulesteward-core` helper (issue #289); the lint passes emit through it
/// via `crate::lints::anchored`. Pinned by `anchored_equals_handwritten_diagnostic`
/// so a refactor that changes its output shape fails fast.
pub use rulesteward_core::anchored;

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
/// All 10 single-file passes emit today (sshd-E01..E04, sshd-W01..W06). The
/// cross-file sshd-F02 (drop-in override) is a separate entrypoint
/// (`drop_in::lint_drop_in`) used for directory targets, not part of this
/// single-file dispatcher. (epic #149)
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
    use super::{SshdLintContext, TargetVersion, anchored, lint, parse_error_to_diagnostic};
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
    fn dispatcher_emits_no_structural_or_error_codes_for_minimal_config() {
        // A minimal but syntactically valid config should never trigger structural
        // (sshd-E0x) or parser (sshd-F01) diagnostics.  W-level diagnostics
        // (sshd-W01, sshd-W02, ...) are intentionally excluded from this
        // assertion: once the STIG passes are implemented they WILL fire for a
        // minimal config that lacks required directives, and that is correct
        // behaviour.  This test pins the structural/error-code contract only,
        // which must remain stable across all implementation waves.
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
        let structural_or_error: Vec<_> = diags
            .iter()
            .filter(|d| d.code.starts_with("sshd-E") || d.code.starts_with("sshd-F"))
            .collect();
        assert!(
            structural_or_error.is_empty(),
            "a syntactically valid config must not produce structural (sshd-E0x) or \
             fatal (sshd-F01) diagnostics; got {structural_or_error:?}"
        );
    }

    #[test]
    fn match_all_weak_value_reports_w02_not_w05_or_e04() {
        // issue #336 full-dispatcher integration: a weak STIG value inside an
        // unconditional `Match all` is a GLOBAL weakness. It must surface as
        // sshd-W02, never sshd-W05 (`Match all` is not a conditional override) and
        // never sshd-E04 (PermitRootLogin is Match-legal regardless).
        let blocks = crate::parser::parse_config_str_located(
            "Match all\n    PermitRootLogin yes\n",
            std::path::Path::new("/etc/ssh/sshd_config"),
        )
        .expect("valid config parses");
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let diags = lint(&blocks, std::path::Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "weak value under `Match all` must report the global W02; got {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-W05"),
            "`Match all` is not a conditional override; W05 must not fire; got {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-E04"),
            "PermitRootLogin is Match-legal; E04 must not fire; got {diags:?}"
        );
    }
}
