//! Body of `rulesteward fapolicyd <subcommand>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rulesteward_core::Diagnostic;
use rulesteward_fapolicyd::{check_layout, lint_file};

use crate::cli::{FapolicydCommand, LintArgs};
use crate::exit_code::{self, EXIT_NO_OP, EXIT_TOOL_FAILURE};
use crate::output::{self, RenderError};

const DEFAULT_RULES_D: &str = "/etc/fapolicyd/rules.d/";

#[must_use]
pub fn run(cmd: FapolicydCommand) -> i32 {
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
            EXIT_NO_OP
        }
    }
}

#[must_use]
fn run_lint(args: &LintArgs) -> i32 {
    if args.against_trustdb.is_some() {
        eprintln!("--against-trustdb is not yet implemented in v0.1.0-dev");
        return EXIT_NO_OP;
    }

    let (target_files, layout_diag) = match resolve_targets(args) {
        Ok(out) => out,
        Err(msg) => {
            eprintln!("{msg}");
            return EXIT_TOOL_FAILURE;
        }
    };

    let mut all_diags: Vec<Diagnostic> = layout_diag.into_iter().collect();
    let mut tool_err = false;
    // Build source map: source_id (file path string) -> raw file content.
    // Re-reading each file here is intentional: lint_file already read it
    // once for parsing; we read again to populate the ariadne source cache.
    // For v0.1 single-file workloads the double-read cost is negligible.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();

    for path in &target_files {
        match lint_file(path) {
            Ok((_entries, diags)) => {
                all_diags.extend(diags);
                // Load source text for ariadne snippets. Failures are soft:
                // the human renderer falls back to plain format if the entry
                // is absent from `sources`.
                if let Ok(text) = std::fs::read_to_string(path) {
                    sources.insert(path.display().to_string(), text);
                }
            }
            Err(io) => {
                eprintln!("{}: {}", path.display(), io);
                tool_err = true;
            }
        }
    }

    let rendered = match output::render(args.format, &all_diags, &sources) {
        Ok(s) => s,
        Err(RenderError::SarifNotImplemented) => {
            println!("{{\"error\":\"sarif format not yet implemented in v0.1.0-dev\"}}");
            return EXIT_TOOL_FAILURE;
        }
    };
    if !rendered.is_empty() {
        print!("{rendered}");
    }

    exit_code::compute(&all_diags, tool_err)
}

// Returns `(files_to_lint, optional_layout_diagnostic)`.
//
// * `--file <FILE>` → lint exactly that file. No layout check.
// * No `--file`, positional `[PATH]` directory → enumerate `*.rules` in it; also run F02 against the parent of that dir.
// * Default: `/etc/fapolicyd/rules.d/`.
fn resolve_targets(args: &LintArgs) -> Result<(Vec<PathBuf>, Option<Diagnostic>), String> {
    if let Some(file) = &args.file {
        return Ok((vec![file.clone()], None));
    }
    let dir = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_D));
    if !dir.is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    let rules_root = dir.parent().map_or_else(|| dir.clone(), Path::to_path_buf);
    let layout_diag = check_layout(&rules_root);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    files.sort();
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
    fn resolve_targets_directory_enumerates_rules_files_alphabetically() {
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        // Write in NON-alphabetical order to verify sorting.
        for name in ["80-zzz.rules", "10-aaa.rules", "40-mmm.rules"] {
            std::fs::write(rules_d.join(name), "").expect("write");
        }
        let args = lint_args(Some(rules_d), None);
        let (files, _layout) = resolve_targets(&args).expect("ok");
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["10-aaa.rules", "40-mmm.rules", "80-zzz.rules"]);
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
        assert!(
            err.contains("not a directory"),
            "expected 'not a directory' in error, got {err}"
        );
    }

    #[test]
    fn resolve_targets_directory_runs_check_layout_against_parent() {
        // Mirror the F02 trap corpus: parent has BOTH rules.d/ and fapolicyd.rules.
        let parent = tempfile::tempdir().expect("tempdir");
        let rules_d = parent.path().join("rules.d");
        std::fs::create_dir(&rules_d).expect("mkdir");
        std::fs::write(rules_d.join("40-x.rules"), "").expect("write");
        std::fs::write(parent.path().join("fapolicyd.rules"), "").expect("write");

        let args = lint_args(Some(rules_d), None);
        let (_files, layout_diag) = resolve_targets(&args).expect("ok");
        let diag = layout_diag
            .expect("F02 must fire when both rules.d/ and fapolicyd.rules exist at parent");
        assert_eq!(diag.code.as_ref(), "F02");
    }
}
