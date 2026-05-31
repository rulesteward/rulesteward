//! Body of `rulesteward fapolicyd <subcommand>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use rulesteward_core::Diagnostic;
use rulesteward_fapolicyd::{
    Entry, LintContext, TrustDb, TrustEntry, TrustSource, check_layout, collect_macro_names,
    lint_cross_file, lint_orphans, lint_with_context, open_trustdb_readonly, parse_rules_file,
    verify_entry,
};

use crate::cli::{
    FapolicydCommand, LintArgs, TrustSourceFilter, TrustdbCheckArgs, TrustdbCommand,
    TrustdbDiffArgs, TrustdbFormat, TrustdbListArgs, TrustdbStaleArgs,
};
use crate::exit_code::{
    self, EXIT_CLEAN, EXIT_LMDB_ERROR, EXIT_NO_OP, EXIT_TOOL_FAILURE, EXIT_WARNINGS,
};
use crate::output::trustdb as trustdb_out;
use crate::output::trustdb::{CheckRow, CheckVerdict, DbDiffKind, DbDiffRow, ListRow};
use crate::output::{self, RenderError};

const DEFAULT_RULES_D: &str = "/etc/fapolicyd/rules.d/";
const DEFAULT_TRUSTDB_DIR: &str = "/var/lib/fapolicyd/";

pub fn run(cmd: FapolicydCommand) -> anyhow::Result<i32> {
    match cmd {
        FapolicydCommand::Lint(args) => run_lint(&args),
        FapolicydCommand::Trustdb(cmd) => run_trustdb(cmd),
        FapolicydCommand::Simulate
        | FapolicydCommand::Explain
        | FapolicydCommand::Report
        | FapolicydCommand::ContainerCheck
        | FapolicydCommand::Migrate
        | FapolicydCommand::Doctor => {
            eprintln!("rulesteward fapolicyd <subcommand>: not yet implemented in v0.1.0-dev");
            Ok(EXIT_NO_OP)
        }
    }
}

fn run_trustdb(cmd: TrustdbCommand) -> anyhow::Result<i32> {
    match cmd {
        TrustdbCommand::List(args) => run_list(&args),
        TrustdbCommand::Check(args) => run_check(&args),
        TrustdbCommand::Diff(args) => run_diff(&args),
        TrustdbCommand::Stale(args) => run_stale(&args),
    }
}

/// Resolve the trust-DB directory (positional/`--db` arg, else the default) and
/// open it read-only. On a missing/not-a-dir path or an open error, print
/// `error: ...` to stderr and return `Err`-as-an-exit-code via the `Result`
/// caller mapping (here surfaced as `Ok(Err(EXIT_TOOL_FAILURE))`-style).
fn open_db(db: Option<&Path>) -> Result<TrustDb, i32> {
    let dir = db.map_or_else(|| PathBuf::from(DEFAULT_TRUSTDB_DIR), Path::to_path_buf);
    if !dir.is_dir() {
        eprintln!("error: trust DB {}: not a directory", dir.display());
        return Err(EXIT_TOOL_FAILURE);
    }
    match open_trustdb_readonly(&dir) {
        Ok(db) => Ok(db),
        Err(e) => {
            eprintln!("error: opening trust DB {}: {e}", dir.display());
            Err(EXIT_TOOL_FAILURE)
        }
    }
}

fn json(format: TrustdbFormat) -> bool {
    matches!(format, TrustdbFormat::Json)
}

/// A stable total order over `TrustSource` (which is not `Ord`) for sorting the
/// per-path value multisets in a DB-vs-DB diff.
fn source_rank(source: TrustSource) -> u8 {
    match source {
        TrustSource::Unknown => 0,
        TrustSource::RpmDb => 1,
        TrustSource::FileDb => 2,
        TrustSource::Deb => 3,
    }
}

fn source_matches(filter: TrustSourceFilter, source: TrustSource) -> bool {
    matches!(
        (filter, source),
        (TrustSourceFilter::Rpm, TrustSource::RpmDb)
            | (TrustSourceFilter::File, TrustSource::FileDb)
            | (TrustSourceFilter::Deb, TrustSource::Deb)
            | (TrustSourceFilter::Unknown, TrustSource::Unknown)
    )
}

fn run_list(args: &TrustdbListArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };
    let entries = db.iter_entries()?;
    let rows: Vec<ListRow> = entries
        .iter()
        .filter(|e| args.source.is_none_or(|f| source_matches(f, e.source)))
        .map(ListRow::from)
        .collect();
    print!("{}", trustdb_out::render_list(&rows, json(args.format)));
    Ok(EXIT_CLEAN)
}

fn run_check(args: &TrustdbCheckArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };
    let mut rows: Vec<CheckRow> = Vec::new();
    for path in &args.paths {
        let key = path.to_string_lossy();
        match db.get_entry(&key)? {
            None => rows.push(CheckRow {
                path: key.into_owned(),
                verdict: CheckVerdict::NotInDb,
            }),
            Some(entries) => {
                for entry in &entries {
                    rows.push(CheckRow {
                        path: entry.path.clone(),
                        verdict: CheckVerdict::from(&verify_entry(entry)),
                    });
                }
            }
        }
    }
    let diverged = rows.iter().any(|r| r.verdict.is_divergence());
    print!("{}", trustdb_out::render_checks(&rows, json(args.format)));
    Ok(if diverged { EXIT_WARNINGS } else { EXIT_CLEAN })
}

fn run_diff(args: &TrustdbDiffArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };
    if let Some(against) = &args.against {
        let other = match open_db(Some(against.as_path())) {
            Ok(db) => db,
            Err(code) => return Ok(code),
        };
        return run_diff_db(&db, &other, json(args.format));
    }
    // DB-vs-on-disk: verify every entry.
    let entries = db.iter_entries()?;
    let rows: Vec<CheckRow> = entries
        .iter()
        .map(|e| CheckRow {
            path: e.path.clone(),
            verdict: CheckVerdict::from(&verify_entry(e)),
        })
        .collect();
    let diverged = rows.iter().any(|r| r.verdict.is_divergence());
    print!("{}", trustdb_out::render_checks(&rows, json(args.format)));
    Ok(if diverged { EXIT_WARNINGS } else { EXIT_CLEAN })
}

/// DB-vs-DB diff: compare the two `(path, value)` row sets. A row that appears
/// in only one DB, or under a shared key with a differing value-multiset, is a
/// divergence. Rather than treat a value change on a shared path as a pair of
/// only-in-A / only-in-B rows, we group both DBs by path and compare the sorted
/// multiset of value-tuples per path, classifying each path as only-in-db,
/// only-in-against, or value-differs.
/// Group trust-DB entries by path into a sorted multiset of value-tuples per
/// path, so a value difference on a shared path is detected without spurious
/// only-in-X rows. `TrustSource` is not `Ord` (frozen foundation type), so the
/// per-path sort uses `source_rank` for a stable total order.
fn group_by_path(entries: &[TrustEntry]) -> BTreeMap<String, Vec<(TrustSource, u64, String)>> {
    let mut m: BTreeMap<String, Vec<(TrustSource, u64, String)>> = BTreeMap::new();
    for e in entries {
        m.entry(e.path.clone())
            .or_default()
            .push((e.source, e.size, e.sha256.clone()));
    }
    for v in m.values_mut() {
        v.sort_by(|x, y| (source_rank(x.0), x.1, &x.2).cmp(&(source_rank(y.0), y.1, &y.2)));
    }
    m
}

fn run_diff_db(db: &TrustDb, other: &TrustDb, json: bool) -> anyhow::Result<i32> {
    let a = db.iter_entries()?;
    let b = other.iter_entries()?;

    let ga = group_by_path(&a);
    let gb = group_by_path(&b);

    let mut rows: Vec<DbDiffRow> = Vec::new();
    let mut paths: Vec<&String> = ga.keys().chain(gb.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        match (ga.get(path), gb.get(path)) {
            (Some(_), None) => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::OnlyInDb,
            }),
            (None, Some(_)) => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::OnlyInAgainst,
            }),
            (Some(va), Some(vb)) if va != vb => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::ValueDiffers,
            }),
            _ => {}
        }
    }

    let diverged = !rows.is_empty();
    print!("{}", trustdb_out::render_db_diff(&rows, json));
    Ok(if diverged { EXIT_WARNINGS } else { EXIT_CLEAN })
}

fn run_stale(args: &TrustdbStaleArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };
    let entries = db.iter_entries()?;
    let rows: Vec<CheckRow> = entries
        .iter()
        .map(|e| CheckRow {
            path: e.path.clone(),
            verdict: CheckVerdict::from(&verify_entry(e)),
        })
        // stale = filtered to non-Match rows only.
        .filter(|r| r.verdict.is_divergence())
        .collect();
    let any_stale = !rows.is_empty();
    print!("{}", trustdb_out::render_checks(&rows, json(args.format)));
    Ok(if any_stale { EXIT_WARNINGS } else { EXIT_CLEAN })
}

fn run_lint(args: &LintArgs) -> anyhow::Result<i32> {
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
