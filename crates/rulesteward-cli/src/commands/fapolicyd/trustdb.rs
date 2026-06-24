//! `rulesteward fapolicyd trustdb <list|check|diff|stale>`: trust-DB register
//! inspection and drift detection.
//!
//! Opens the fapolicyd trust DB read-only and reports its contents (`list`),
//! verifies entries against on-disk files (`check`), diffs the DB against disk
//! or another DB (`diff`), or surfaces only the divergent entries (`stale`).

use std::path::{Path, PathBuf};

use rulesteward_fapolicyd::{
    IntegrityMode, TrustDb, TrustSource, open_trustdb_readonly, verify_entry,
};

use crate::cli::{
    TrustSourceFilter, TrustdbCheckArgs, TrustdbCommand, TrustdbDiffArgs, TrustdbFormat,
    TrustdbListArgs, TrustdbListFormat, TrustdbStaleArgs,
};
use crate::commands::conf::conf_value;
use crate::commands::trustdb_compute;
use crate::exit_code::{EXIT_CLEAN, EXIT_TOOL_FAILURE, EXIT_WARNINGS};
use crate::output::trustdb as trustdb_out;
use crate::output::trustdb::{CheckRow, CheckVerdict, ListRow};

const DEFAULT_TRUSTDB_DIR: &str = "/var/lib/fapolicyd/";
const DEFAULT_CONF_PATH: &str = "/etc/fapolicyd/fapolicyd.conf";

pub(super) fn run_trustdb(cmd: TrustdbCommand) -> anyhow::Result<i32> {
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

fn source_matches(filter: TrustSourceFilter, source: TrustSource) -> bool {
    matches!(
        (filter, source),
        (TrustSourceFilter::Rpm, TrustSource::RpmDb)
            | (TrustSourceFilter::File, TrustSource::FileDb)
            | (TrustSourceFilter::Deb, TrustSource::Deb)
            | (TrustSourceFilter::Unknown, TrustSource::Unknown)
    )
}

/// Resolve the effective `IntegrityMode` with precedence:
///
/// 1. `--integrity <level>` flag (highest priority)
/// 2. `integrity` key from `--config <path>` (or default `/etc/fapolicyd/fapolicyd.conf`)
///    - Key present in a found conf: use its value (may parse to `None` for "none")
///    - Key absent in a found conf: daemon default `IntegrityMode::None`
/// 3. No conf file found at the path: STRICT (`IntegrityMode::Sha256`)
///
/// Returns `(mode, source_description)` so callers can emit an informational header.
fn resolve_integrity_mode(
    integrity_flag: Option<&str>,
    config_path: Option<&Path>,
) -> (IntegrityMode, String) {
    // --integrity flag wins unconditionally.
    if let Some(level) = integrity_flag {
        let mode = IntegrityMode::from_conf_value(Some(level));
        return (mode, format!("--integrity flag ({level})"));
    }

    // Determine which conf path to read.
    let conf_path = config_path.map_or_else(|| PathBuf::from(DEFAULT_CONF_PATH), Path::to_path_buf);

    if let Ok(text) = std::fs::read_to_string(&conf_path) {
        // Conf found: read the integrity key (absent key -> daemon default None).
        let raw = conf_value(&text, "integrity");
        let mode = IntegrityMode::from_conf_value(raw);
        let src = format!(
            "{} (integrity={})",
            conf_path.display(),
            raw.unwrap_or("absent")
        );
        (mode, src)
    } else {
        // Conf NOT found: STRICT (treat as sha256).
        let src = format!("no conf found at {} - strict (sha256)", conf_path.display());
        (IntegrityMode::Sha256, src)
    }
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
    let rendered = match args.format {
        TrustdbListFormat::Human => trustdb_out::render_list(&rows, false),
        TrustdbListFormat::Json => trustdb_out::render_list(&rows, true),
        TrustdbListFormat::Csv => trustdb_out::render_csv_list(&rows),
    };
    print!("{rendered}");
    Ok(EXIT_CLEAN)
}

fn run_check(args: &TrustdbCheckArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };

    let (mode, mode_src) =
        resolve_integrity_mode(args.integrity.as_deref(), args.config.as_deref());

    let mut rows: Vec<CheckRow> = Vec::new();
    for path in &args.paths {
        let key = path.to_string_lossy();
        match db.get_entry(&key)? {
            None => rows.push(CheckRow {
                path: key.into_owned(),
                verdict: CheckVerdict::NotInDb,
                enforced: true,
            }),
            Some(entries) => {
                for entry in &entries {
                    let disk_verdict = verify_entry(entry);
                    let enforced = mode.enforces(&disk_verdict);
                    rows.push(CheckRow {
                        path: entry.path.clone(),
                        verdict: CheckVerdict::from(&disk_verdict),
                        enforced,
                    });
                }
            }
        }
    }
    let any_enforced_divergence = rows.iter().any(|r| r.verdict.is_divergence() && r.enforced);
    let is_json = json(args.format);
    print!(
        "{}",
        trustdb_out::render_checks(&rows, is_json, Some((mode, &mode_src)))
    );
    Ok(if any_enforced_divergence {
        EXIT_WARNINGS
    } else {
        EXIT_CLEAN
    })
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
        // DB-vs-DB mode: integrity gating does not apply.
        return run_diff_db(&db, &other, json(args.format));
    }

    let (mode, mode_src) =
        resolve_integrity_mode(args.integrity.as_deref(), args.config.as_deref());

    // DB-vs-on-disk: verify every entry.
    let entries = db.iter_entries()?;
    let rows: Vec<CheckRow> = entries
        .iter()
        .map(|e| {
            let disk_verdict = verify_entry(e);
            let enforced = mode.enforces(&disk_verdict);
            CheckRow {
                path: e.path.clone(),
                verdict: CheckVerdict::from(&disk_verdict),
                enforced,
            }
        })
        .collect();
    let any_enforced_divergence = rows.iter().any(|r| r.verdict.is_divergence() && r.enforced);
    let is_json = json(args.format);
    print!(
        "{}",
        trustdb_out::render_checks(&rows, is_json, Some((mode, &mode_src)))
    );
    Ok(if any_enforced_divergence {
        EXIT_WARNINGS
    } else {
        EXIT_CLEAN
    })
}

/// DB-vs-DB diff: read both DBs, classify the diff via the pure
/// [`compute_db_diff`](trustdb_compute::compute_db_diff), and render. A non-empty
/// diff is a divergence (`EXIT_WARNINGS`).
fn run_diff_db(db: &TrustDb, other: &TrustDb, json: bool) -> anyhow::Result<i32> {
    let a = db.iter_entries()?;
    let b = other.iter_entries()?;

    let rows = trustdb_compute::compute_db_diff(&a, &b);

    let diverged = !rows.is_empty();
    print!("{}", trustdb_out::render_db_diff(&rows, json));
    Ok(if diverged { EXIT_WARNINGS } else { EXIT_CLEAN })
}

fn run_stale(args: &TrustdbStaleArgs) -> anyhow::Result<i32> {
    let db = match open_db(args.db.as_deref()) {
        Ok(db) => db,
        Err(code) => return Ok(code),
    };

    let (mode, mode_src) =
        resolve_integrity_mode(args.integrity.as_deref(), args.config.as_deref());

    let entries = db.iter_entries()?;
    let all_rows: Vec<CheckRow> = entries
        .iter()
        .map(|e| {
            let disk_verdict = verify_entry(e);
            let enforced = mode.enforces(&disk_verdict);
            CheckRow {
                path: e.path.clone(),
                verdict: CheckVerdict::from(&disk_verdict),
                enforced,
            }
        })
        .collect();
    // stale = the divergent (non-Match) rows; the filter is the pure
    // `trustdb_compute::stale_rows` so it is unit-tested + mutation-covered.
    let rows = trustdb_compute::stale_rows(all_rows);
    let any_enforced_divergence = rows.iter().any(|r| r.verdict.is_divergence() && r.enforced);
    let is_json = json(args.format);
    print!(
        "{}",
        trustdb_out::render_checks(&rows, is_json, Some((mode, &mode_src)))
    );
    Ok(if any_enforced_divergence {
        EXIT_WARNINGS
    } else {
        EXIT_CLEAN
    })
}
