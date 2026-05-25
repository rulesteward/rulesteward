//! Body of `rulesteward fapolicyd <subcommand>`.

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

    for path in &target_files {
        match lint_file(path) {
            Ok((_entries, diags)) => all_diags.extend(diags),
            Err(io) => {
                eprintln!("{}: {}", path.display(), io);
                tool_err = true;
            }
        }
    }

    let rendered = match output::render(args.format, &all_diags) {
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

/// Returns `(files_to_lint, optional_layout_diagnostic)`.
///
/// * `--file <FILE>` → lint exactly that file. No layout check.
/// * No `--file`, positional `[PATH]` directory → enumerate `*.rules` in it; also run F02 against the parent of that dir.
/// * Default: `/etc/fapolicyd/rules.d/`.
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
    let rules_root = dir
        .parent()
        .map_or_else(|| dir.clone(), Path::to_path_buf);
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
