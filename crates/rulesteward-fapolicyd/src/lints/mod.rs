//! Post-parse lint passes.
//!
//! Code split:
//! * `walker` - AST-driven passes (fapd-F03, fapd-E01, fapd-W02).
//! * `validation` - AST-driven attribute-value validation (fapd-E02).
//! * `macros` - AST-driven macro-system passes (fapd-E03, fapd-E04, fapd-E05, fapd-S02).
//! * `deprecation` - AST-driven deprecated-attribute-name passes (fapd-W07).
//! * `reachability` - AST-driven rule-shadowing pass (fapd-W01).
//! * `subsume` - shared rule-subsumption engine reused by fapd-W01 and fapd-W04.
//! * `source_scan` - raw-source re-scan for fapd-W03.
//! * `layout` - filesystem-driven fapd-F02 check.
//! * `cross_file` - cross-`rules.d/` passes (fapd-W04 ordering, fapd-C01 filename convention).
//! * `dir_slash` - AST-driven per-attribute trailing-slash lint (fapd-W08).
//! * `version_target` - version-divergent checks gated on `--target` (fapd-E06).
//! * `type_compat` - set/attribute value-type compatibility (fapd-E07).
//! * `trust_path` - trust-DB-aware per-file pass (fapd-W06).
//! * `cross_db` - trust-DB cross-pass (fapd-X01), CLI-invoked.
//! * `trust_hash` - trust-DB weak-digest surfacing (fapd-W11), CLI-invoked.

pub mod catalog;
pub(crate) mod cross_db;
mod cross_file;
mod deprecation;
mod dir_slash;
mod identity;
mod layout;
mod macros;
mod reachability;
mod source_scan;
mod subsume;
#[cfg(test)]
pub(crate) mod testkit;
pub(crate) mod trust_hash;
mod trust_path;
mod type_compat;
mod validation;
mod version_target;
mod walker;

pub use layout::check_layout;

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity, Span, fill_columns};

use crate::ast::Entry;
use crate::parser;
use crate::trustdb::TrustDb;
use crate::version::TargetVersion;

/// Build a byte-anchored `Diagnostic` with the fapolicyd emission convention:
/// column defaults to 1 and the source-id is the file path's display string.
///
/// Thin wrapper over [`anchored_at`] with `column = 1`. Used by the bulk of the
/// anchored lint sites whose caret sits at the start of the line.
pub(crate) fn anchored(
    sev: Severity,
    code: &'static str,
    span: Span,
    msg: impl Into<String>,
    file: impl Into<std::path::PathBuf>,
    line: usize,
) -> Diagnostic {
    anchored_at(sev, code, span, msg, file, line, 1)
}

/// Build a byte-anchored `Diagnostic` at an explicit 1-based `column`, with the
/// source-id set to the file path's display string. Used by the sites that point
/// the caret at a sub-rule token rather than the rule's first column: fapd-E01
/// (the offending attribute), fapd-W03 (the inline `#`), and fapd-F01 (the parse
/// offset within the line body).
pub(crate) fn anchored_at(
    sev: Severity,
    code: &'static str,
    span: Span,
    msg: impl Into<String>,
    file: impl Into<std::path::PathBuf>,
    line: usize,
    column: usize,
) -> Diagnostic {
    let file = file.into();
    let source_id = file.display().to_string();
    Diagnostic::new(sev, code, span, msg, file, line, column).with_source_id(source_id)
}

/// Build a file-level `Diagnostic` NOT anchored to a source byte range: empty
/// span `0..0`, line and column `0`, and NO source-id. Used by findings about a
/// file's existence or name rather than its contents - fapd-F02 (layout
/// coexistence), fapd-C01 (filename convention), and fapd-X01 (trust-DB orphans)
/// - which the renderer shows as a bare message with no source snippet.
pub(crate) fn file_level(
    sev: Severity,
    code: &'static str,
    msg: impl Into<String>,
    file: impl Into<std::path::PathBuf>,
) -> Diagnostic {
    Diagnostic::new(sev, code, 0..0, msg, file, 0, 0)
}

/// Optional external resources + mode flags for the context-gated lint passes.
/// `Default` is "no trust DB, no earlier-file macros, directory mode, no version
/// target, no identity check", which reproduces the plain per-file `lint()`
/// behavior exactly.
#[derive(Default)]
pub struct LintContext<'a> {
    /// Trust DB for fapd-W06 (`path=`/`exe=` literal not in the trust DB).
    pub trustdb: Option<&'a TrustDb>,
    /// Macro names defined in EARLIER-loading `rules.d/` files (the post-fagenrules
    /// concatenated stream up to but excluding the current file). A `%setname`
    /// reference whose name is in this set is in scope for fapd-E03 (cross-file
    /// define-before-use). `None` reproduces per-file resolution and is used by
    /// `lint()` and by single-file `--file` mode, which have no earlier-file context.
    pub earlier_macros: Option<&'a std::collections::HashSet<String>>,
    /// True for single-file `--file` lint: a `%setname` reference not defined
    /// anywhere in the lone file becomes fapd-W09 (it may be defined in an unseen
    /// sibling) rather than fapd-E03. A within-file forward reference stays E03.
    pub single_file: bool,
    /// Selected RHEL target for version-aware checks (`--target`). `None` is the
    /// implicit 1.4.x dialect and suppresses every version-divergent diagnostic,
    /// so a default context preserves today's version-agnostic behavior.
    pub target: Option<TargetVersion>,
    /// True when `--check-identities` is set: enable the opt-in fapd-W05 `uid=` /
    /// `gid=` getent check. Off by default (read-only-by-default; the check spawns
    /// a `getent` subprocess that may query SSSD/LDAP/AD).
    pub check_identities: bool,
}

/// Run every per-file lint pass with a default (empty) context and return the
/// merged diagnostic list. Thin wrapper over
/// [`lint_with_context`]`(.., &LintContext::default())` so the context-free
/// callers (snapshot driver, proptests, downstream consumers) are unaffected.
///
/// `source` is the raw rules-file text, needed for fapd-W03 (inline trailing
/// `# comment`) re-scan. `file` is the path used in every emitted
/// `Diagnostic::file`.
#[must_use]
pub fn lint(entries: &[Entry], source: &str, file: &Path) -> Vec<Diagnostic> {
    lint_with_context(entries, source, file, &LintContext::default())
}

/// Run cross-file lint passes over all rules.d files in fagenrules load order.
/// Directory-mode only (a single `--file` has no cross-file relationships).
#[must_use]
pub fn lint_cross_file(files: &[(std::path::PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let mut diags = cross_file::w04(files);
    diags.extend(cross_file::c01(files));
    diags.extend(cross_file::c02(files));
    diags.extend(cross_file::w10(files));
    diags
}

/// The single implementation of the per-file pass list, honoring the
/// `LintContext`. The context-free [`lint`] delegates here with a default
/// context, so a default context returns exactly what `lint()` returns.
///
/// Pass ordering is load-bearing and MUST be preserved: the AST/source passes
/// run first, then `fill_columns` backfills their columns from byte spans, and
/// `trust_path::w06` runs LAST so its column stays as emitted (matching the
/// pre-context behavior where W06 was appended after `lint()` had already
/// filled columns). Do not move `fill_columns` after the W06 append.
#[must_use]
pub fn lint_with_context(
    entries: &[Entry],
    source: &str,
    file: &Path,
    ctx: &LintContext,
) -> Vec<Diagnostic> {
    let mut diags = walker::walk(entries, file);
    diags.extend(validation::walk(entries, file));
    diags.extend(macros::walk(
        entries,
        file,
        ctx.earlier_macros,
        ctx.single_file,
    ));
    diags.extend(reachability::walk(entries, file));
    diags.extend(deprecation::walk(entries, file, ctx.target));
    diags.extend(dir_slash::walk(entries, file));
    diags.extend(source_scan::w03_scan(source, file));
    // Version-aware checks: no-op when ctx.target is None (implicit 1.4.x), so a
    // default context is byte-identical to the pre-version-target behavior.
    diags.extend(version_target::walk(entries, file, ctx.target));
    // fapd-E07 set/attribute type-compatibility. Unlike version_target, this is
    // NOT fully gated on `ctx.target`: universal mismatches (wrong on every
    // version) fire under `None`, version-divergent ones only under a target.
    diags.extend(type_compat::walk(entries, file, ctx.target));
    // fapd-W05 uid=/gid= getent check: opt-in via --check-identities. Runs among
    // the AST passes (before fill_columns) so its column backfills from the span.
    if ctx.check_identities {
        diags.extend(identity::walk(entries, file));
    }
    // Backfill column from each diagnostic's byte span. Lint passes and the
    // parser historically hardcoded column = 1; this makes the column field
    // agree with the byte span the human renderer uses for its caret, so
    // JSON / plain / snapshot columns are consistent with the ariadne display.
    fill_columns(&mut diags, source);
    if let Some(db) = ctx.trustdb {
        diags.extend(trust_path::w06(entries, file, db));
    }
    diags
}

/// Read + parse + lint a file with a `LintContext`. Mirrors `lint_file`; the
/// no-context `lint_file` now delegates here with a default context.
#[must_use = "lint results contain parse and lint diagnostics that should be checked"]
pub fn lint_file_with_context(
    path: &Path,
    ctx: &LintContext,
) -> Result<(Vec<Entry>, Vec<Diagnostic>), std::io::Error> {
    let source = std::fs::read_to_string(path)?;
    let (entries, parse_diags) = match parser::parse_rules_file(&source, path) {
        Ok(entries) => (entries, Vec::new()),
        Err(diags) => (Vec::new(), diags),
    };
    let mut diags = parse_diags;
    diags.extend(lint_with_context(&entries, &source, path, ctx));
    Ok((entries, diags))
}

/// Read a rules file, parse it, and run every per-file lint pass against it.
///
/// Returns `(entries, diagnostics)` on read success. `entries` is empty when
/// parsing failed; `diagnostics` always contains everything the parser and
/// lint walker found. The `io::Error` is propagated unchanged so the CLI
/// can map it to exit code 3 (tool failure).
#[must_use = "lint results contain parse and lint diagnostics that should be checked"]
pub fn lint_file(path: &Path) -> Result<(Vec<Entry>, Vec<Diagnostic>), std::io::Error> {
    lint_file_with_context(path, &LintContext::default())
}

/// Names of every `%name=` set definition in `entries`, in source order
/// (duplicates preserved; callers dedup via a `HashSet`). Rules, comments, and
/// blanks contribute nothing.
///
/// Used to seed the cross-file "earlier macros" set for fapd-E03 in directory
/// mode: a macro defined in an earlier-loading `rules.d/` file is in scope for
/// later files (the post-fagenrules concatenated stream). Names-only by design,
/// distinct from `subsume::build_macro_map` (which expands `name -> values` for
/// rule subsumption); fapd-E03 needs only the set of defined names. `pub` so the
/// CLI two-phase loop can accumulate it across files in load order.
#[must_use]
pub fn collect_macro_names(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            Entry::SetDefinition { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;

    #[test]
    fn lint_aggregator_calls_all_walks_and_merges_diagnostics() {
        // Pins the invariant: `lint()` invokes ALL seven walks (walker,
        // validation, macros, reachability, deprecation, dir_slash, source_scan) and
        // merges their diagnostics into the returned Vec. A mutant that drops
        // one walk from the aggregator body silently loses the corresponding
        // code from the output; this test fails fast in that case.
        //
        // The source is constructed so each walk fires on its own code:
        //   walker::e01         -> `bogusattr=` (unknown attribute name)
        //   validation::e02     -> `sha256hash=abc` (3 chars, not 64 hex)
        //   macros::e03         -> `exe=%undefinedmacro` (unknown macro ref)
        //   macros::s02         -> `%latemacro=` defined AFTER the first rule
        //   deprecation::w07    -> `sha256hash=` (deprecated attribute name)
        //   source_scan::w03    -> trailing `# bad` (inline comment past tokens)
        //   reachability::w01   -> line 3 duplicates line 2's terminal rule,
        //                          so line 3 is unreachable (shadowed).
        //   dir_slash::w08      -> `dir=/no/slash` on the object (no trailing slash)
        //
        // The parser strips the inline `# bad` BEFORE chumsky sees the line,
        // so the rule itself parses cleanly; fapd-W03 is then re-detected from
        // the raw `source` string by the source_scan walk.
        //
        // Line 3 is an exact copy of line 2: `allow` is terminal and the
        // predicates are identical, so line 2 shadows line 3 -> fapd-W01 on
        // line 3. The duplicate also re-fires fapd-E03 (still an undefined
        // macro), but `codes` is a set so that does not perturb the other
        // assertions.
        //
        // Line 4 defines `%latemacro` AFTER the first rule, firing fapd-S02
        // (definition not at file top). The name is distinct from
        // `%undefinedmacro` (so it does not satisfy the line 2/3 reference,
        // leaving fapd-E03 intact) and unreferenced (so it adds no E03/E04),
        // and its single string value is homogeneous (so no fapd-E05). Being
        // a SetDefinition rather than a Rule, it cannot perturb fapd-W01.
        let source = "allow uid=0 bogusattr=x : sha256hash=abc dir=/no/slash # bad\nallow uid=0 : exe=%undefinedmacro\nallow uid=0 : exe=%undefinedmacro\n%latemacro=/usr/bin/foo\n";
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(source.as_bytes()).expect("write");
        let path = f.path().to_path_buf();
        let entries = parser::parse_rules_file(source, &path).expect("source must parse");
        let diags = lint(&entries, source, &path);
        let codes: HashSet<&str> = diags.iter().map(|d| d.code.as_ref()).collect();
        assert!(
            codes.contains("fapd-E01"),
            "expected walker::e01 to fire (bogusattr= on subject side), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-E02"),
            "expected validation::e02 to fire (sha256hash=abc -> 3 chars not 64), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-E03"),
            "expected macros::e03 to fire (%undefinedmacro reference), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W07"),
            "expected deprecation::w07 to fire (sha256hash= deprecated), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W03"),
            "expected source_scan::w03 to fire (inline `# bad` comment), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W01"),
            "expected reachability::w01 to fire (line 3 duplicates line 2's terminal rule), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-S02"),
            "expected macros::s02 to fire (macro after first rule), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W08"),
            "expected dir_slash::w08 to fire (dir=/no/slash on the object has no trailing slash), got codes={codes:?} diags={diags:?}",
        );
    }

    #[test]
    fn lint_file_returns_entries_and_no_diagnostics_for_clean_input() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "allow uid=0 : all").expect("write");
        let (entries, diags) = lint_file(f.path()).expect("read");
        assert_eq!(entries.len(), 1);
        assert!(
            diags.is_empty(),
            "clean rule should produce no diagnostics, got {diags:?}"
        );
    }

    #[test]
    fn lint_file_returns_f01_on_parse_failure() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "!!!garbage").expect("write");
        let (entries, diags) = lint_file(f.path()).expect("read");
        assert!(
            entries.is_empty(),
            "expected no entries on parse failure, got {entries:?}"
        );
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-F01"),
            "garbage line must produce fapd-F01, got {diags:?}"
        );
        let f01 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-F01")
            .expect("fapd-F01 should be present");
        assert_eq!(
            f01.file,
            f.path(),
            "fapd-F01 diagnostic file should match input path, got {:?}",
            f01.file
        );
        // The parser anchors fapd-F01 to `path` (source_id = path.display()),
        // so the ariadne renderer can find the source text in the CLI's source
        // map without any post-pass rewrite. Without source_id, fapd-F01 would
        // silently fall back to plain rendering even though its span is a real
        // byte range.
        assert_eq!(
            f01.source_id.as_deref(),
            Some(f.path().display().to_string().as_str()),
            "fapd-F01 source_id must match the file path string used by the CLI source map",
        );
    }

    #[test]
    fn lint_file_propagates_io_error_for_missing_path() {
        let result = lint_file(std::path::Path::new("/nonexistent/path/to/nothing"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn collect_macro_names_returns_setdefinition_names_in_source_order() {
        // Every `%name=` set definition, in source order, duplicates PRESERVED
        // (the caller dedups via a HashSet). Rules, comments, and blanks
        // contribute nothing. The two `%a` definitions both appear so a caller
        // building the cross-file "earlier macros" set sees every definition.
        let src = "%a=1\nallow uid=0 : all\n%b=2,3\n# c\n%a=9\n";
        let p = std::path::Path::new("t.rules");
        let entries = parser::parse_rules_file(src, p)
            .unwrap_or_else(|diags| panic!("fixture must parse: {diags:?}"));
        assert_eq!(
            collect_macro_names(&entries),
            vec!["a".to_string(), "b".to_string(), "a".to_string()],
        );
    }

    // --- B.2: LintContext.earlier_macros behavior ---

    #[test]
    fn earlier_macros_context_suppresses_e03_vs_default() {
        // Parse `allow uid=0 : exe=%langs\n` (a reference to `%langs` with no
        // local definition) and assert:
        //
        //   1. With a default (empty) context, lint_with_context returns a Vec
        //      that CONTAINS at least one fapd-E03 (undefined macro reference).
        //
        //   2. With a context whose `earlier_macros` set contains "langs",
        //      lint_with_context returns a Vec that does NOT contain any fapd-E03
        //      (the macro is satisfied by the earlier-file context).
        //
        // RED against the frozen foundation: `e03` ignores `ctx.earlier_macros`,
        // so BOTH contexts produce fapd-E03, and assertion 2 fails.
        let src = "allow uid=0 : exe=%langs\n";
        let path = std::path::Path::new("rules.d/70-x.rules");
        let entries = parser::parse_rules_file(src, path)
            .unwrap_or_else(|diags| panic!("fixture must parse cleanly: {diags:?}"));

        // 1. Default context must contain fapd-E03.
        let default_diags = lint_with_context(&entries, src, path, &LintContext::default());
        assert!(
            default_diags.iter().any(|d| d.code.as_ref() == "fapd-E03"),
            "default context: expected at least one fapd-E03 for undefined %%langs, \
             got: {default_diags:?}",
        );

        // 2. Context with earlier_macros = {"langs"} must NOT contain fapd-E03.
        let mut earlier = HashSet::new();
        earlier.insert("langs".to_string());
        let ctx_with_earlier = LintContext {
            earlier_macros: Some(&earlier),
            ..Default::default()
        };
        let earlier_diags = lint_with_context(&entries, src, path, &ctx_with_earlier);
        assert!(
            !earlier_diags.iter().any(|d| d.code.as_ref() == "fapd-E03"),
            "context with earlier_macros={{\"langs\"}}: fapd-E03 must be suppressed \
             (macro defined in earlier-loading file), got: {earlier_diags:?}",
        );
    }

    // --- column backfill tests (A5: derive column from span) ---

    #[test]
    fn diagnostic_column_is_derived_from_span() {
        // Two-line file. Line 1 is a clean rule; line 2 references an undefined
        // macro. The E03 diagnostic's span.start is the byte offset of line 2's
        // rule start within the whole file (non-zero). Before the column backfill,
        // d.column was hardcoded to 1. After the backfill, it must equal
        // line_col(d.span, src).1.
        //
        // Line 1: "allow uid=0 : all\n"     = 18 bytes (line 1, col 1..17)
        // Line 2: "allow uid=0 : exe=%undef\n"  starts at byte offset 18 -> col 1
        //         BUT its span.start = 18, so line_col(18, src) = (2, 1).
        //
        // To get a non-1 column on a rule, we need a finding that anchors to a
        // mid-rule span, OR we use fapd-W03 (already anchors to the `#` position).
        // Here we use the `all_lint_diagnostics_have_column_matching_line_col`
        // test for the universal check, and this test specifically verifies the
        // key invariant: column == line_col(span, source).1 for at least one
        // non-trivially-placed diagnostic (E03 on line 2).
        let src = "allow uid=0 : all\nallow uid=0 : exe=%undef\n";
        let p = std::path::Path::new("t.rules");
        let entries = parser::parse_rules_file(src, p)
            .unwrap_or_else(|diags| panic!("fixture must parse, got parse errors: {diags:?}"));
        let diags = lint(&entries, src, p);
        let e03 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E03")
            .unwrap_or_else(|| {
                let summary: Vec<_> = diags
                    .iter()
                    .map(|d| {
                        format!(
                            "[{}] col={} span={}..{}",
                            d.code, d.column, d.span.start, d.span.end
                        )
                    })
                    .collect();
                panic!("fapd-E03 expected for undefined macro %undef, diags={summary:?}")
            });
        // The E03 span should start at byte 18 (start of line 2).
        assert!(
            e03.span.start > 0,
            "E03 span.start must be non-zero (rule is on line 2): got span={}..{}",
            e03.span.start,
            e03.span.end
        );
        let (expected_line, expected_col) = rulesteward_core::span_util::line_col(&e03.span, src);
        assert_eq!(
            e03.line, expected_line,
            "line must match line_col: got {} expected {}",
            e03.line, expected_line
        );
        assert_eq!(
            e03.column, expected_col,
            "column must be span-derived (not hardcoded 1): got {} expected {} (span={}..{})",
            e03.column, expected_col, e03.span.start, e03.span.end
        );
    }

    #[test]
    fn all_lint_diagnostics_have_column_matching_line_col() {
        // Smoke test: every diagnostic returned by lint() must have d.column ==
        // line_col(d.span, source).1, confirming the backfill is universal.
        // Uses the same multi-code fixture as lint_aggregator_calls_all_walks.
        let src = "allow uid=0 bogusattr=x : sha256hash=abc dir=/no/slash # bad\nallow uid=0 : exe=%undefinedmacro\nallow uid=0 : exe=%undefinedmacro\n%latemacro=/usr/bin/foo\n";
        let p = std::path::Path::new("t.rules");
        let entries = parser::parse_rules_file(src, p).expect("should parse");
        let diags = lint(&entries, src, p);
        for d in &diags {
            // Skip unanchored diagnostics (0..0 span) - these are file-layout
            // fatals with no source byte range.
            if d.span.start == 0 && d.span.end == 0 {
                continue;
            }
            let (expected_line, expected_col) = rulesteward_core::span_util::line_col(&d.span, src);
            assert_eq!(
                d.column, expected_col,
                "[{}] line={} span={}..{}: column {} != line_col column {}",
                d.code, d.line, d.span.start, d.span.end, d.column, expected_col
            );
            let _ = expected_line; // line correctness is pre-existing
        }
    }

    // --- CLEAN-2: anchored() equality anchor ---
    //
    // This test is GREEN immediately (anchored() exists in Phase 0). It acts
    // as a behavior-preservation anchor: if any refactor changes anchored()'s
    // output shape (column, source_id, etc.) relative to the hand-written
    // Diagnostic::new(...).with_source_id(...) form, this test fails fast.

    #[test]
    fn anchored_equals_handwritten_diagnostic() {
        use std::path::Path;
        let file = Path::new("/tmp/x.rules");
        let span = 3..9;
        let got = super::anchored(Severity::Error, "fapd-E02", span.clone(), "boom", file, 7);
        let want = Diagnostic::new(Severity::Error, "fapd-E02", span, "boom", file, 7, 1)
            .with_source_id(file.display().to_string());
        assert_eq!(got, want);
    }

    // --- Task 4: anchored_at() / file_level() equality anchors ---
    //
    // Parity guards for the two new helpers introduced by the raw-Diagnostic::new
    // migration. They must reproduce the hand-written forms EXACTLY so the
    // migrated sites (walker E01, source_scan W03, parser F01; layout F02,
    // cross_db X01, cross_file C01) are byte-for-byte behavior-preserving.

    #[test]
    fn anchored_at_equals_handwritten_diagnostic() {
        use std::path::Path;
        let file = Path::new("/tmp/x.rules");
        let span = 3..9;
        let got = super::anchored_at(
            Severity::Error,
            "fapd-E01",
            span.clone(),
            "boom",
            file,
            7,
            4,
        );
        let want = Diagnostic::new(Severity::Error, "fapd-E01", span, "boom", file, 7, 4)
            .with_source_id(file.display().to_string());
        assert_eq!(got, want);
    }

    #[test]
    fn anchored_is_anchored_at_column_one() {
        use std::path::Path;
        let file = Path::new("/tmp/x.rules");
        let span = 0..2;
        assert_eq!(
            super::anchored(Severity::Warning, "fapd-W03", span.clone(), "m", file, 5),
            super::anchored_at(Severity::Warning, "fapd-W03", span, "m", file, 5, 1),
        );
    }

    #[test]
    fn file_level_equals_handwritten_diagnostic() {
        use std::path::Path;
        let file = Path::new("/tmp/x.rules");
        let got = super::file_level(Severity::Fatal, "fapd-F02", "boom", file);
        let want = Diagnostic::new(Severity::Fatal, "fapd-F02", 0..0, "boom", file, 0, 0);
        assert_eq!(got, want);
        assert!(
            got.source_id.is_none(),
            "file_level must NOT set a source_id (renders as a bare message)",
        );
    }

    #[test]
    fn parse_f01_column_matches_line_col() {
        // F01 parse errors should also have column == line_col(span, source).1
        // after the parse backfill. Uses a multi-line source where the failure
        // is on line 2 at a non-trivial column offset.
        let src = "allow uid=0 : all\n!!!garbage\n";
        let p = std::path::Path::new("t.rules");
        let diags = parser::parse_rules_file(src, p).expect_err("line 2 must fail");
        for d in &diags {
            if d.span.start == 0 && d.span.end == 0 {
                continue;
            }
            let (_, expected_col) = rulesteward_core::span_util::line_col(&d.span, src);
            assert_eq!(
                d.column, expected_col,
                "[{}] line={} span={}..{}: column {} != line_col column {}",
                d.code, d.line, d.span.start, d.span.end, d.column, expected_col
            );
        }
    }

    // --- Phase 0 (version-target): LintContext gains `target` + `check_identities` ---

    #[test]
    fn context_default_has_no_target_and_no_identity_check() {
        // The Phase-0 freeze adds two fields that BOTH default to "off" so a
        // default context reproduces today's behavior exactly:
        //   * `target: Option<TargetVersion>` = None (no --target, implicit 1.4.x)
        //   * `check_identities: bool` = false (fapd-W05 getent check is opt-in)
        // RED until the fields exist (compile-coupled).
        let ctx = LintContext::default();
        assert!(
            ctx.target.is_none(),
            "default LintContext.target must be None (no version target selected)"
        );
        assert!(
            !ctx.check_identities,
            "default LintContext.check_identities must be false (W05 is opt-in)"
        );
    }

    // --- Task 3: lint_with_context / LintContext contract ---

    #[test]
    fn empty_context_matches_plain_lint() {
        // Pins the KEY invariant: lint_with_context with a default (empty)
        // context must produce BYTE-IDENTICAL output to the existing lint().
        //
        // Non-vacuity: the source references an undefined macro (%undefinedmacro)
        // so lint() returns a NON-EMPTY Vec (at minimum fapd-E03). The comparison
        // is therefore meaningful: both paths must agree on real diagnostics, not
        // just both-empty.
        //
        // This test will NOT compile until the impl lands LintContext +
        // lint_with_context (Task 3). That compile failure is the expected RED.
        // The symbols are re-exported from the crate root (lib.rs pub use), so we
        // import them from `super::` (same module) where they will be added.
        let src = "allow uid=0 : exe=%undefinedmacro\n";
        let path = std::path::Path::new("rules.d/10-x.rules");
        let entries = parser::parse_rules_file(src, path).unwrap_or_default();

        // Confirm non-vacuity: plain lint must return at least one diagnostic.
        let plain = lint(&entries, src, path);
        assert!(
            !plain.is_empty(),
            "fixture must fire at least one lint (expected fapd-E03 for %undefinedmacro), \
             got empty vec - the non-vacuity guarantee is broken"
        );

        // THE INVARIANT: lint_with_context with a default context == plain lint.
        // lint_with_context and LintContext do not exist yet; this line causes
        // the compile error that marks this test RED.
        assert_eq!(
            lint_with_context(&entries, src, path, &LintContext::default()),
            plain,
            "lint_with_context with a default (empty) context must equal plain lint()"
        );
    }
}
