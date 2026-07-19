//! Semantic lint passes over a parsed `sshd_config` file.
//!
//! Code split (one file per semantic family; the parallel pipelines each fill
//! ONE file's bodies, mirroring the auditd crate's Phase-0 freeze):
//! * `structural` - sshd-E01 unknown directive, sshd-E02 duplicate global,
//!   sshd-E03 Include resolution, sshd-E04 Match-illegal directive, sshd-W05
//!   permissive Match override (Wave A, plus the registry-gated E01).
//! * `stig` - sshd-W01 required-directive-missing, sshd-W02 weaker-than-baseline
//!   (Wave B; gated on the STIG-baseline grounding task).
//! * `cis` - the per-product CIS Benchmark table + `Framework::Cis` `ControlRef`
//!   attachment onto the sshd-W01/W02 findings that overlap a CIS control (v0.8
//!   Wave 3, issue #525).
//! * `crypto` - sshd-W03 weak algorithm, sshd-W06 prefix-op reintroduction
//!   (Wave B/C; gated on the per-version default-algorithm lists).
//! * `deprecation` - sshd-W04 deprecated/removed directive (Wave B).
//! * `catalog` - the machine-readable `sshd-` code catalog (frozen Phase 0).
//!
//! The dispatcher runs every pass for real (so `rulesteward sshd lint` works end
//! to end and a clean file exits 0). All 11 single-file passes emit today
//! (sshd-E01..E04, sshd-W01..W07), alongside `sshd-F01` from the parser (mapped by
//! [`parse_error_to_diagnostic`]); the cross-file sshd-F02 has its own entrypoint
//! (`drop_in::lint_drop_in`). Pass modules are `pub` so each pipeline's tests can
//! call their own entrypoint directly.

pub mod catalog;
pub mod cis;
pub mod crypto;
pub mod deprecation;
pub mod drop_in;
pub mod registry;
pub mod stig;
pub mod structural;

use std::path::Path;

use rulesteward_core::Diagnostic;

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
/// inside the mutation `examine_globs`. Line-level parse errors (line != 0) are
/// anchored via `anchored(...)`: the `span` field carries the byte range of the
/// failing raw line (populated by the running-offset loop in the parser), and the
/// source-id is set so ariadne can render a snippet. File-level errors (line == 0,
/// e.g. unreadable file) stay unanchored (span 0..0, no source-id) because no
/// source byte range exists.
#[must_use]
pub fn parse_error_to_diagnostic(err: &LocatedParseError) -> Diagnostic {
    rulesteward_core::parse_error_diagnostic(
        "sshd-F01",
        err.file.clone(),
        err.line,
        err.span.clone(),
        err.message.clone(),
    )
}

/// Run every single-file semantic lint pass over the parsed blocks and return the
/// merged diagnostic list, in catalog order for byte-stable output.
///
/// All 11 single-file passes emit today (sshd-E01..E04, sshd-W01..W07). The
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
    diags.extend(structural::w07(blocks, file, ctx));
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
        // Line 2 of "MaxAuthTries 4\nBanner \"abc\n": "Banner \"abc" starts at
        // byte 15 and is 11 bytes long. The span must be 15..26.
        let err = LocatedParseError {
            file: "/etc/ssh/sshd_config".into(),
            line: 2,
            message: "unterminated quoted string".to_string(),
            span: 15..26,
        };
        let d = parse_error_to_diagnostic(&err);
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "sshd-F01");
        assert_eq!(d.message, "unterminated quoted string");
        assert_eq!(d.file, err.file);
        assert_eq!(d.line, 2);
        assert_eq!(d.column, 1, "line-level parse errors anchor at column 1");
        assert_eq!(
            d.span,
            15..26,
            "parse errors carry the real byte range of the failing line"
        );
        assert!(d.source_id.is_some(), "anchored: ariadne source-id is set");
        assert_eq!(
            d.source_id.as_deref(),
            Some("/etc/ssh/sshd_config"),
            "source-id is the file path display string"
        );
    }

    #[test]
    fn parse_error_span_matches_failing_line_byte_range() {
        // "MaxAuthTries 4\nBanner \"abc\n": "MaxAuthTries 4" = 14 bytes + newline,
        // so "Banner \"abc" starts at byte 15 and is 11 bytes long -> span = 15..26.
        let input = "MaxAuthTries 4\nBanner \"abc\n";
        let file = std::path::Path::new("/etc/ssh/sshd_config");
        let errs = crate::parser::parse_config_str_located(input, file)
            .expect_err("unterminated quote must fail");
        assert_eq!(errs.len(), 1, "exactly one error");
        assert_eq!(
            errs[0].span,
            15..26,
            "span must cover the raw 'Banner \"abc' line: starts at byte 15, length 11"
        );
        assert_eq!(
            &input[errs[0].span.clone()],
            "Banner \"abc",
            "span must slice to the failing raw line"
        );
    }

    #[test]
    fn parse_error_span_is_byte_offsets_not_char_offsets() {
        // The failing line `Banner "naïve abc` opens a double quote that is never
        // closed (unterminated-quote error) and carries a 2-byte UTF-8 char inside
        // the quoted region, so its BYTE length != CHAR count. This distinguishes
        // the correct `raw_line.len()` (bytes) span computation from a plausible
        // `raw_line.chars().count()` (chars) regression. With "MaxAuthTries 4\n"
        // = 15 bytes, the failing line starts at byte 15; the byte-correct span
        // end is 15 + 18.
        let input = "MaxAuthTries 4\nBanner \"na\u{ef}ve abc\n";
        let failing_line = "Banner \"na\u{ef}ve abc";
        let file = std::path::Path::new("/etc/ssh/sshd_config");
        let errs = crate::parser::parse_config_str_located(input, file)
            .expect_err("unterminated quote must fail on the multibyte line");
        assert_eq!(errs.len(), 1, "exactly one error");
        assert_eq!(
            errs[0].span,
            15..33,
            "span must be BYTE offsets: failing line starts at byte 15, byte length 18"
        );
        assert_eq!(
            &input[errs[0].span.clone()],
            failing_line,
            "span must slice to the exact failing line text"
        );
        let span_len = errs[0].span.end - errs[0].span.start;
        assert_eq!(
            span_len,
            failing_line.len(),
            "span length must equal the failing line's BYTE length"
        );
        assert!(
            span_len > failing_line.chars().count(),
            "byte length ({span_len}) must exceed char count ({}); a chars()-based span \
             would be off by one here",
            failing_line.chars().count()
        );
    }

    #[test]
    fn file_level_parse_error_keeps_line_and_column_zero() {
        // File-level errors (line == 0, e.g. unreadable file) stay unanchored:
        // no meaningful byte range exists, so span stays 0..0 and source_id is None.
        let err = LocatedParseError {
            file: "/nonexistent".into(),
            line: 0,
            message: "cannot read file".to_string(),
            span: 0..0,
        };
        let d = parse_error_to_diagnostic(&err);
        assert_eq!((d.line, d.column), (0, 0), "file-level errors stay 0/0");
        assert_eq!(d.code, "sshd-F01");
        assert_eq!(d.span, 0..0, "file-level errors carry no byte span");
        assert!(d.source_id.is_none(), "file-level errors are unanchored");
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
