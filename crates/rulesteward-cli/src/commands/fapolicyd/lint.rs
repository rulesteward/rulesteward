//! `rulesteward fapolicyd lint`: policy validation pipeline.
//!
//! Reads + parses the target `.rules` file(s) in fagenrules load order, runs the
//! per-file and cross-file lints (threading earlier-file macro context and an
//! optional trust DB), and renders diagnostics in the requested format. Also
//! owns target resolution (`--file` vs directory vs default `rules.d/`) and the
//! `--sarif-include-pass` coverage attestation (#137).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Framework};
use rulesteward_fapolicyd::{
    Entry, LintContext, catalog, check_layout, collect_macro_names, lint_cross_file, lint_orphans,
    lint_weak_digests, lint_with_context, open_trustdb_readonly, parse_rules_file,
};
use thiserror::Error;

use crate::cli::{LintArgs, OutputFormat, TargetVersionArg};
use crate::commands::target_probe::{HostTargetProbe, LiveTargetProbe, resolve_target};
use crate::exit_code::{EXIT_LMDB_ERROR, EXIT_TOOL_FAILURE};
use crate::output::{self, RenderError};

const DEFAULT_RULES_D: &str = "/etc/fapolicyd/rules.d/";

/// Typed errors from [`resolve_targets`].
///
/// Previously `resolve_targets` returned `anyhow::Result<...>`. Switching to a
/// typed error lets callers pattern-match on the exact failure mode rather than
/// parsing error strings.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// The supplied path (or the default) is not a directory.
    #[error("{path}: not a directory")]
    NotADirectory { path: PathBuf },
    /// The directory could not be read (IO error).
    #[error("reading directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub(super) fn run_lint(args: &LintArgs, profile: Option<Framework>) -> anyhow::Result<i32> {
    run_lint_with_probe(args, &LiveTargetProbe, profile)
}

/// `run_lint` with the host probe injected, so the `--target auto` resolution path
/// is unit-testable without reading the test host's `/etc/os-release`. `run_lint`
/// supplies the real [`LiveTargetProbe`]; tests supply a fake.
fn run_lint_with_probe(
    args: &LintArgs,
    probe: &dyn HostTargetProbe,
    profile: Option<Framework>,
) -> anyhow::Result<i32> {
    // Resolve --target in the command layer (epic #251): explicit value as-is,
    // `auto` from the host probe, omitted -> version-agnostic. A failed `auto`
    // degrades to version-agnostic with a warning, never an error (read-only tool).
    let resolved = resolve_target(args.target, probe);
    if let Some(warning) = &resolved.warning {
        eprintln!("fapolicyd lint: {warning}");
    }
    run_lint_resolved(args, resolved.target, profile)
}

/// The lint pipeline with `--target` already resolved to a concrete baseline (or
/// `None` for the version-agnostic dialect). Split from [`run_lint_with_probe`] at
/// the resolution boundary so the resolved target feeds BOTH the per-file lint
/// context and the SARIF per-check coverage attestation (they never disagree),
/// keeping each function within the line budget.
fn run_lint_resolved(
    args: &LintArgs,
    target: Option<TargetVersionArg>,
    profile: Option<Framework>,
) -> anyhow::Result<i32> {
    let trustdb = match &args.against_trustdb {
        Some(p) => {
            if !p.is_dir() {
                eprintln!("error: opening trust DB {}: not a directory", p.display());
                return Ok(EXIT_TOOL_FAILURE);
            }
            match open_trustdb_readonly(p) {
                Ok(db) => Some(db),
                Err(e) => {
                    eprintln!("error: opening trust DB {}: {e}", p.display());
                    return Ok(EXIT_LMDB_ERROR);
                }
            }
        }
        None => None,
    };

    let (target_files, layout_diag) = resolve_targets(args).map_err(anyhow::Error::from)?;

    let mut all_diags: Vec<Diagnostic> = layout_diag.into_iter().collect();
    let mut tool_err = false;
    // Build source map: source_id (file path string) -> raw file content for ariadne.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    // Parsed entries per file, preserved for the cross-file (W04/C01) and
    // orphan (X01) passes that run after all per-file lints complete.
    let mut parsed: Vec<(PathBuf, Vec<Entry>)> = Vec::new();

    // `single_file=true` when the operator passes `--file <FILE>`: one file,
    // no earlier-file context; a missing macro becomes fapd-W09 instead of E03.
    let single_file = args.file.is_some();

    // Phase 1 - read + parse every target file in fagenrules load order into a
    // staging vec (path, source, entries). Parse errors (fapd-F01) are emitted
    // immediately; IO errors are surfaced but do not stop the other files.
    let mut staged: Vec<(PathBuf, String, Vec<Entry>)> = Vec::new();
    for path in &target_files {
        match std::fs::read_to_string(path) {
            Ok(source) => {
                let (entries, parse_diags) = match parse_rules_file(&source, path) {
                    Ok(e) => (e, Vec::new()),
                    Err(d) => (Vec::new(), d),
                };
                all_diags.extend(parse_diags);
                staged.push((path.clone(), source, entries));
            }
            Err(io) => {
                // Per-file IO failure must not halt the loop. Attach the path
                // as anyhow context so the operator sees
                // `error: linting <path>\n  Caused by: <io>`.
                let err = anyhow::Error::new(io).context(format!("linting {}", path.display()));
                eprintln!("error: {err:#}");
                tool_err = true;
            }
        }
    }

    // Phase 2 - lint each file in load order, threading a running set of macro
    // names from earlier-loading files (for cross-file fapd-E03 resolution).
    // `earlier.extend(...)` MUST come AFTER lint_with_context: own-file
    // SetDefinitions are NOT in scope for own-file forward references.
    let mut earlier: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (path, source, entries) in &staged {
        let ctx = LintContext {
            trustdb: trustdb.as_ref(),
            earlier_macros: if single_file { None } else { Some(&earlier) },
            single_file,
            target: target.map(Into::into),
            check_identities: args.check_identities,
        };
        all_diags.extend(lint_with_context(entries, source, path, &ctx));
        // Populate the ariadne source cache from the already-read source text.
        sources.insert(path.display().to_string(), source.clone());
        if !single_file {
            earlier.extend(collect_macro_names(entries));
        }
    }

    // Consume staged into the per-path structures needed by the cross-file
    // and orphan passes.
    for (path, _source, entries) in staged {
        parsed.push((path, entries));
    }

    // Cross-file passes (fapd-W04 ordering, fapd-C01 filename convention) apply
    // only in directory mode; a single `--file` has no cross-file relationships.
    // `target_files` is already in fagenrules load order (resolve_targets).
    if !single_file {
        // Route cross-file diagnostics (fapd-W04/C01) through the same column
        // backfill as the per-file lint() path, for uniformity. This is a no-op
        // today: every rule span starts at its line's first byte (the grammar
        // includes leading whitespace in the span), so W04 columns are already 1,
        // and C01's 0..0 span is skipped by fill_columns. It future-proofs any
        // later cross-file diagnostic that anchors mid-line.
        let mut cross = lint_cross_file(&parsed);
        for d in &mut cross {
            if let Some(src) = sources.get(&d.file.display().to_string()) {
                rulesteward_core::fill_columns(std::slice::from_mut(d), src);
            }
        }
        all_diags.extend(cross);
    }

    if args.report_orphans {
        match trustdb.as_ref() {
            Some(db) => all_diags.extend(lint_orphans(&parsed, db)),
            None => eprintln!("warning: --report-orphans has no effect without --against-trustdb"),
        }
    }

    // Weak trust-DB digests (fapd-W11): surfaced whenever a trust DB is attached
    // (no opt-in flag - a weak digest is a genuine Warning, capped to one summary).
    if let Some(db) = trustdb.as_ref() {
        all_diags.extend(lint_weak_digests(db));
    }

    // Apply the global `--profile` filter (issue #506) BEFORE building the SARIF
    // pass/coverage attestation, so the attestation and the rendered results
    // reflect the SAME (filtered) set. fapolicyd findings carry no controls, so any
    // `--profile` empties the set -> `no_op` -> exit 9 (correct: nothing in this
    // policy maps to the requested framework).
    let no_op = crate::profile::apply_profile(&mut all_diags, profile);

    let pass_info = sarif_pass_info(
        args,
        target,
        trustdb.is_some(),
        single_file,
        &parsed,
        tool_err,
        &all_diags,
    );

    let rendered = match output::render(args.format, &all_diags, &sources, pass_info.as_ref()) {
        Ok(s) => s,
        Err(RenderError::Serialization(msg)) => {
            eprintln!("error: rendering {:?} output: {msg}", args.format);
            return Ok(EXIT_TOOL_FAILURE);
        }
    };
    if !rendered.is_empty() {
        print!("{rendered}");
    }

    Ok(crate::profile::resolve_exit_code(
        no_op, &all_diags, tool_err,
    ))
}

/// Build the SARIF per-check coverage payload (#137) for a `--sarif-include-pass`
/// SARIF run, or `None` for any other run (which keeps SARIF output byte-identical
/// to the pre-#137 form). [`catalog::evaluated`] is the single source of truth for
/// which checks actually ran given the run's gates (`--target`,
/// `--check-identities`, `--against-trustdb` + `--report-orphans`, single-file vs
/// directory); the clean subset (evaluated minus the codes that fired) is emitted
/// as `kind:"pass"`.
fn sarif_pass_info(
    args: &LintArgs,
    target: Option<TargetVersionArg>,
    trustdb_present: bool,
    single_file: bool,
    parsed: &[(PathBuf, Vec<Entry>)],
    tool_err: bool,
    all_diags: &[Diagnostic],
) -> Option<output::sarif::PassInfo> {
    if !(args.sarif_include_pass && matches!(args.format, OutputFormat::Sarif)) {
        return None;
    }
    // Coverage attestation is only emitted for a fully-analyzed, non-empty
    // policy. A parse failure (fapd-F01) or an unreadable file (`tool_err`) means
    // the policy was not fully read, and zero Rule/SetDefinition entries means
    // there was no content to validate. In those cases claiming the always-on
    // checks "passed" would overstate coverage, so suppress the attestation
    // entirely (no `rules[]`, no pass results) - #137 owner decision.
    let has_rule_content = parsed
        .iter()
        .flat_map(|(_, entries)| entries)
        .any(|e| matches!(e, Entry::Rule(_) | Entry::SetDefinition { .. }));
    let parse_failed = tool_err || all_diags.iter().any(|d| d.code.as_ref() == "fapd-F01");
    if !has_rule_content || parse_failed {
        return None;
    }
    let inputs = catalog::EvalInputs {
        trustdb: trustdb_present,
        check_identities: args.check_identities,
        report_orphans: args.report_orphans,
        target: target.map(Into::into),
        single_file,
    };
    let rules = catalog::evaluated(inputs);
    let fired: std::collections::HashSet<&str> =
        all_diags.iter().map(|d| d.code.as_ref()).collect();
    let passes = rules
        .iter()
        .copied()
        .filter(|c| !fired.contains(c.code))
        .collect();
    Some(output::sarif::PassInfo { rules, passes })
}

// Returns `(files_to_lint, optional_layout_diagnostic)`.
//
// * `--file <FILE>` -> lint exactly that file. No layout check.
// * No `--file`, positional `[PATH]` directory -> enumerate `*.rules` in it; also run fapd-F02 against the parent of that dir.
// * Default: `/etc/fapolicyd/rules.d/`.
fn resolve_targets(args: &LintArgs) -> Result<(Vec<PathBuf>, Option<Diagnostic>), ResolveError> {
    if let Some(file) = &args.file {
        return Ok((vec![file.clone()], None));
    }
    let dir = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_D));
    if !dir.is_dir() {
        return Err(ResolveError::NotADirectory { path: dir });
    }
    let rules_root = dir.parent().map_or_else(|| dir.clone(), Path::to_path_buf);
    let layout_diag = check_layout(&rules_root);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|source| ResolveError::ReadDir {
            path: dir.clone(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        // Skip hidden dotfiles: fagenrules enumerates via `ls -1v | grep '\.rules$'`
        // (no -a), so a `.NN-x.rules` is never compiled - linting it would emit a
        // phantom fapd-C01.
        .filter(|p| {
            p.is_file()
                && p.extension().and_then(|s| s.to_str()) == Some("rules")
                && !p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    files.sort_by(|a, b| rulesteward_fapolicyd::fagenrules_cmp(a, b));
    Ok((files, layout_diag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{OutputFormat, TargetSelector, TargetVersionArg};
    use crate::exit_code::EXIT_CLEAN;
    use std::path::PathBuf;

    /// A host probe returning a canned result, so the `--target auto` wiring is
    /// exercised without depending on the test host's /etc/os-release.
    struct FakeProbe(Result<Option<TargetVersionArg>, String>);
    impl HostTargetProbe for FakeProbe {
        fn detect(&self) -> Result<Option<TargetVersionArg>, String> {
            self.0.clone()
        }
    }

    /// A single rules file whose lint result is VERSION-DIVERGENT: the `device=`
    /// object field is rejected (fapd-E06) under any `--target rhelN` but accepted
    /// in the version-agnostic dialect. A clean-under-every-target fixture would
    /// make the parity assertions below vacuous (0 == 0); this one fails any wrong
    /// impl that does not thread the resolved target into the lint pass.
    fn version_divergent_rules_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("10-test.rules");
        std::fs::write(&f, "allow perm=open device=/dev/sda1 : path=/etc/hosts\n").expect("write");
        (dir, f)
    }

    #[test]
    fn target_auto_resolving_to_rhel9_matches_explicit_rhel9() {
        // `--target auto` whose probe detects rhel9 must behave identically to an
        // explicit `--target rhel9`. On the version-divergent fixture both fire
        // fapd-E06 (a non-clean exit); a broken impl that dropped the resolved
        // target would lint "auto" clean, failing the assert_ne below.
        let (_dir, f) = version_divergent_rules_file();
        let mut auto = lint_args(None, Some(f.clone()));
        auto.target = Some(TargetSelector::Auto);
        let mut explicit = lint_args(None, Some(f));
        explicit.target = Some(TargetSelector::Rhel9);
        let auto_rc =
            run_lint_with_probe(&auto, &FakeProbe(Ok(Some(TargetVersionArg::Rhel9))), None)
                .expect("auto run");
        let explicit_rc =
            run_lint_with_probe(&explicit, &FakeProbe(Ok(None)), None).expect("explicit run");
        assert_ne!(
            auto_rc, EXIT_CLEAN,
            "the version-divergent fixture must not lint clean under rhel9 (else the test is vacuous)"
        );
        assert_eq!(
            auto_rc, explicit_rc,
            "--target auto (detect rhel9) must match explicit --target rhel9"
        );
    }

    #[test]
    fn target_auto_unmappable_matches_version_agnostic() {
        // A probe that yields None (non-EL host) degrades to the version-agnostic
        // dialect: the version-divergent fixture lints clean (exit 0), same as
        // omitting --target - and distinct from an explicit-rhel9 control (non-clean),
        // so "resolves to nothing" is proven, not merely "always clean".
        let (_dir, f) = version_divergent_rules_file();
        let mut auto = lint_args(None, Some(f.clone()));
        auto.target = Some(TargetSelector::Auto);
        let agnostic = lint_args(None, Some(f.clone())); // target: None
        let mut control = lint_args(None, Some(f));
        control.target = Some(TargetSelector::Rhel9);
        let auto_rc = run_lint_with_probe(&auto, &FakeProbe(Ok(None)), None).expect("auto run");
        let agnostic_rc =
            run_lint_with_probe(&agnostic, &FakeProbe(Ok(None)), None).expect("agnostic run");
        let control_rc =
            run_lint_with_probe(&control, &FakeProbe(Ok(None)), None).expect("control run");
        assert_eq!(
            auto_rc, EXIT_CLEAN,
            "auto resolving to None must lint the fixture version-agnostic (clean)"
        );
        assert_eq!(
            auto_rc, agnostic_rc,
            "--target auto that resolves to nothing must match omitting --target"
        );
        assert_ne!(
            control_rc, agnostic_rc,
            "control: explicit rhel9 must differ from agnostic (the fixture is version-divergent)"
        );
    }

    fn lint_args(path: Option<PathBuf>, file: Option<PathBuf>) -> LintArgs {
        LintArgs {
            path,
            file,
            format: OutputFormat::Human,
            against_trustdb: None,
            report_orphans: false,
            target: None,
            check_identities: false,
            sarif_include_pass: false,
        }
    }

    #[test]
    fn resolve_targets_file_mode_returns_single_file_no_layout_diag() {
        let args = lint_args(None, Some(PathBuf::from("/some/path/foo.rules")));
        let (files, layout_diag) = resolve_targets(&args).expect("ok");
        assert_eq!(files, vec![PathBuf::from("/some/path/foo.rules")]);
        assert!(
            layout_diag.is_none(),
            "--file mode must NOT run layout check"
        );
    }

    #[test]
    fn resolve_targets_directory_enumerates_rules_files_in_fagenrules_order() {
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        // Order where lexicographic != fagenrules natural sort (lexicographic
        // would give 100, 10, 9; fagenrules `ls -v` gives 9, 10, 100).
        for name in ["10-aaa.rules", "9-zzz.rules", "100-mmm.rules"] {
            std::fs::write(rules_d.join(name), "").expect("write");
        }
        let args = lint_args(Some(rules_d), None);
        let (files, _layout) = resolve_targets(&args).expect("ok");
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["9-zzz.rules", "10-aaa.rules", "100-mmm.rules"]);
    }

    #[test]
    fn resolve_targets_directory_filters_non_rules_extensions() {
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        for name in ["40-x.rules", "40-x.rules.bak", "README.txt", "40-x"] {
            std::fs::write(rules_d.join(name), "").expect("write");
        }
        let args = lint_args(Some(rules_d), None);
        let (files, _layout) = resolve_targets(&args).expect("ok");
        assert_eq!(files.len(), 1, "expected only 40-x.rules, got {files:?}");
        assert_eq!(
            files[0].file_name().unwrap().to_string_lossy(),
            "40-x.rules"
        );
    }

    #[test]
    fn resolve_targets_nonexistent_path_returns_err_with_not_a_directory() {
        let args = lint_args(Some(PathBuf::from("/nonexistent/path/12345")), None);
        let result = resolve_targets(&args);
        let err = result.expect_err("expected Err for non-existent path");
        let msg = format!("{err}");
        assert!(
            msg.contains("not a directory"),
            "expected 'not a directory' in error message, got {msg}"
        );
    }

    /// Typed error: a non-directory path must yield `ResolveError::NotADirectory`.
    /// RED: will fail until `resolve_targets` returns `Result<_, ResolveError>`.
    #[test]
    fn resolve_targets_not_a_directory_yields_typed_error_variant() {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let path = f.path().to_path_buf();
        let args = lint_args(Some(path.clone()), None);
        let err = resolve_targets(&args).expect_err("file-as-dir must fail");
        // Must be the NotADirectory variant - pattern match is the typed check.
        assert!(
            matches!(err, ResolveError::NotADirectory { path: ref p } if p == &path),
            "expected ResolveError::NotADirectory with path={path:?}, got {err:?}"
        );
    }

    #[test]
    fn resolve_targets_file_as_dir_error_chain_includes_path() {
        // Locks the fact that the typed error carries the offending path.
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let path = f.path().to_path_buf();
        let args = lint_args(Some(path.clone()), None);
        let err = resolve_targets(&args).expect_err("file-as-dir must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains(path.display().to_string().as_str()),
            "error must mention the offending path, got {msg}",
        );
    }

    #[test]
    fn resolve_targets_directory_skips_hidden_dotfiles() {
        // A normal NN-x.rules plus a hidden .NN-hidden.rules: only the former is
        // linted. fagenrules excludes dotfiles (enumerates via `ls -1v | grep
        // '\.rules$'`, no `-a`); linting a dotfile would emit a phantom fapd-C01.
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        std::fs::write(rules_d.join("10-real.rules"), "allow perm=open all : all\n")
            .expect("write");
        std::fs::write(
            rules_d.join(".50-hidden.rules"),
            "allow perm=open all : all\n",
        )
        .expect("write");
        let args = lint_args(Some(rules_d), None);
        let (files, _layout) = resolve_targets(&args).expect("ok");
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["10-real.rules"],
            "hidden dotfile must be skipped, got {names:?}"
        );
    }

    #[test]
    fn resolve_targets_directory_runs_check_layout_against_parent() {
        // Mirror the fapd-F02 trap corpus: parent has BOTH rules.d/ and fapolicyd.rules.
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        std::fs::write(rules_d.join("40-x.rules"), "").expect("write");
        std::fs::write(parent.path().join("fapolicyd.rules"), "").expect("write");

        let args = lint_args(Some(rules_d), None);
        let (_files, layout_diag) = resolve_targets(&args).expect("ok");
        let diag = layout_diag
            .expect("fapd-F02 must fire when both rules.d/ and fapolicyd.rules exist at parent");
        assert_eq!(diag.code.as_ref(), "fapd-F02");
    }
}
