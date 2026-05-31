//! Body of `rulesteward fapolicyd <subcommand>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use rulesteward_core::Diagnostic;
use rulesteward_fapolicyd::{
    Entry, LintContext, check_layout, collect_macro_names, lint_cross_file, lint_orphans,
    lint_with_context, open_trustdb_readonly, parse_rules_file,
};

use crate::cli::{FapolicydCommand, LintArgs};
use crate::exit_code::{self, EXIT_NO_OP, EXIT_TOOL_FAILURE};
use crate::output::{self, RenderError};

const DEFAULT_RULES_D: &str = "/etc/fapolicyd/rules.d/";

pub fn run(cmd: FapolicydCommand) -> anyhow::Result<i32> {
    match cmd {
        FapolicydCommand::Lint(args) => run_lint(&args),
        FapolicydCommand::Simulate
        | FapolicydCommand::Explain
        | FapolicydCommand::Report
        | FapolicydCommand::ContainerCheck
        | FapolicydCommand::Trustdb
        | FapolicydCommand::Migrate
        | FapolicydCommand::Doctor => {
            eprintln!("rulesteward fapolicyd <subcommand>: not yet implemented in v0.1.0-dev");
            Ok(EXIT_NO_OP)
        }
    }
}

fn run_lint(args: &LintArgs) -> anyhow::Result<i32> {
    let trustdb = match &args.against_trustdb {
        Some(p) => match open_trustdb_readonly(p) {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("error: opening trust DB {}: {e}", p.display());
                return Ok(EXIT_TOOL_FAILURE);
            }
        },
        None => None,
    };

    let (target_files, layout_diag) = resolve_targets(args)?;

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

    let rendered = match output::render(args.format, &all_diags, &sources) {
        Ok(s) => s,
        Err(RenderError::Serialization(msg)) => {
            eprintln!("error: rendering {:?} output: {msg}", args.format);
            return Ok(EXIT_TOOL_FAILURE);
        }
    };
    if !rendered.is_empty() {
        print!("{rendered}");
    }

    Ok(exit_code::compute(&all_diags, tool_err))
}

// Returns `(files_to_lint, optional_layout_diagnostic)`.
//
// * `--file <FILE>` → lint exactly that file. No layout check.
// * No `--file`, positional `[PATH]` directory → enumerate `*.rules` in it; also run fapd-F02 against the parent of that dir.
// * Default: `/etc/fapolicyd/rules.d/`.
fn resolve_targets(args: &LintArgs) -> anyhow::Result<(Vec<PathBuf>, Option<Diagnostic>)> {
    if let Some(file) = &args.file {
        return Ok((vec![file.clone()], None));
    }
    let dir = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_D));
    if !dir.is_dir() {
        bail!("{}: not a directory", dir.display());
    }
    let rules_root = dir.parent().map_or_else(|| dir.clone(), Path::to_path_buf);
    let layout_diag = check_layout(&rules_root);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
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
    use crate::cli::OutputFormat;
    use std::path::PathBuf;

    fn lint_args(path: Option<PathBuf>, file: Option<PathBuf>) -> LintArgs {
        LintArgs {
            path,
            file,
            format: OutputFormat::Human,
            against_trustdb: None,
            report_orphans: false,
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
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a directory"),
            "expected 'not a directory' in error chain, got {msg}"
        );
    }

    #[test]
    fn resolve_targets_file_as_dir_error_chain_includes_path() {
        // Phase B: locks the anyhow::Error return type AND the fact that
        // the bail!() carries the offending path through to the chain.
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let path = f.path().to_path_buf();
        let args = lint_args(Some(path.clone()), None);
        let err: anyhow::Error = resolve_targets(&args).expect_err("file-as-dir must fail");
        let chain = format!("{err:#}");
        assert!(
            chain.contains(path.display().to_string().as_str()),
            "error chain must mention the offending path, got {chain}",
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
