//! `rulesteward fapolicyd report` body.
//!
//! Builds the exception register (every effective allow grant) from a
//! `rules.d/` directory or single file. Optionally cross-checks grants against
//! a fapolicyd trust DB (`--against-trustdb`) and/or computes drift against a
//! prior snapshot (`--diff-against`). Renders in human / json / csv format.

use std::path::PathBuf;

use anyhow::Context as _;
use rulesteward_fapolicyd::register::{build_register, compute_drift};
use rulesteward_fapolicyd::{
    Entry, HashOrigin, RegisterRow, Scope, fagenrules_cmp, open_trustdb_readonly, parse_rules_file,
};
use serde::Deserialize;

use crate::cli::{HumanJsonCsvFormat, ReportArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_LMDB_ERROR};
use crate::output::register::{
    TrustJoinCap, TrustJoinCapSource, TrustJoinEntry, TrustJoinRow, render_csv_register,
    render_human_register, render_json_drift, render_json_register, render_json_register_with_cap,
    render_json_register_with_join,
};

const DEFAULT_RULES_D: &str = "/etc/fapolicyd/rules.d/";

/// When the trust DB has more entries than this threshold for a trust=1 grant,
/// the `trustJoin` output uses the cap form (JSON object with grantSource/count/
/// enumerated) instead of Shape A (JSON array with per-grant rows).
///
/// Grounded from corpus:  3 entries -> Shape A;  25 entries -> cap form.
/// Threshold of 10 distinguishes these two test points.
const TRUST_CAP_THRESHOLD: usize = 10;

/// Snapshot envelope shape - parse only the `grants` array from a prior report.
#[derive(Deserialize)]
struct RegisterSnapshot {
    grants: Vec<RegisterRow>,
}

/// Run the report subcommand.
///
/// `args` is passed by value to match the `explain::run` / `simulate::run`
/// convention at the dispatch call site; individual fields are referenced
/// where not moved.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn run(args: crate::cli::ReportArgs) -> anyhow::Result<i32> {
    // 1. Resolve the target files in fagenrules load order.
    let target_files = resolve_targets(&args)?;

    // 2. Parse each file; abort on any parse error (treat as fatal).
    let mut files_with_entries: Vec<(String, Vec<Entry>)> = Vec::new();
    for path in &target_files {
        let source =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let entries = match parse_rules_file(&source, path) {
            Ok(e) => e,
            Err(diags) => {
                // Emit parse diagnostics to stderr and exit with the parse error code.
                for d in &diags {
                    eprintln!(
                        "error: {}:{}: [{}] {}",
                        d.file.display(),
                        d.line,
                        d.code,
                        d.message
                    );
                }
                return Ok(crate::exit_code::EXIT_RULE_PARSE_ERROR);
            }
        };
        let filename = path.file_name().map_or_else(
            || path.display().to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        files_with_entries.push((filename, entries));
    }

    // 3. Build the register.
    let file_refs: Vec<(&str, &[Entry])> = files_with_entries
        .iter()
        .map(|(name, entries)| (name.as_str(), entries.as_slice()))
        .collect();
    let mut grants = build_register(&file_refs);

    // 4. --against-trustdb: open the trust DB, enrich grants, build trustJoin.
    let trust_join_output = if let Some(ref db_path) = args.against_trustdb {
        if !db_path.is_dir() {
            eprintln!("error: trust DB {}: not a directory", db_path.display());
            return Ok(EXIT_LMDB_ERROR);
        }
        let db = match open_trustdb_readonly(db_path) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("error: opening trust DB {}: {e}", db_path.display());
                return Ok(EXIT_LMDB_ERROR);
            }
        };

        // Detect whether any grant is a trust=1-scoped grant on the object side.
        let trust1_grant_idx = grants
            .iter()
            .position(|r| matches!(r.scope, Scope::Trust) && r.object.contains("trust=1"));

        if let Some(tidx) = trust1_grant_idx {
            // trust=1 grant: enumerate all trust DB entries.
            let all_entries = db.iter_entries().context("iterating trust DB")?;
            let count = all_entries.len();
            let trust_grant = &grants[tidx];

            // Determine whether to use cap form or Shape A.
            // Cap form: when the DB is large (> TRUST_CAP_THRESHOLD) OR when
            // --enumerate-trust is absent (cap form always suppresses without flag).
            // Shape A: small DB with --enumerate-trust.
            let use_cap = count > TRUST_CAP_THRESHOLD || !args.enumerate_trust;

            if use_cap {
                let cap = if args.enumerate_trust {
                    // Cap form with all entries listed.
                    let entries = all_entries
                        .iter()
                        .map(TrustJoinRow::from_entry)
                        .collect::<Vec<_>>();
                    TrustJoinCap {
                        grant_source: TrustJoinCapSource {
                            file: trust_grant.source.file.clone(),
                            line: trust_grant.source.line,
                        },
                        count,
                        enumerated: true,
                        entries: Some(entries),
                    }
                } else {
                    // Cap form: suppressed (no entries list).
                    TrustJoinCap {
                        grant_source: TrustJoinCapSource {
                            file: trust_grant.source.file.clone(),
                            line: trust_grant.source.line,
                        },
                        count,
                        enumerated: false,
                        entries: None,
                    }
                };
                Some(TrustJoinOutputKind::Cap(cap))
            } else {
                // Shape A: small DB with --enumerate-trust, list all entries.
                // Row order: lexicographic by path (LMDB already iterates in key
                // order, so no additional sort is needed).
                let rows: Vec<TrustJoinRow> =
                    all_entries.iter().map(TrustJoinRow::from_entry).collect();
                let join_entry = TrustJoinEntry {
                    grant_index: tidx,
                    rows,
                };
                Some(TrustJoinOutputKind::Array(vec![join_entry]))
            }
        } else {
            // Shape A: per-grant path join for non-trust=1 grants.
            let mut join_entries = Vec::new();
            for (grant_index, grant) in grants.iter_mut().enumerate() {
                let paths = collect_grant_paths(grant);
                let mut rows = Vec::new();
                for path_str in &paths {
                    match db.get_entry(path_str) {
                        Ok(Some(db_entries)) => {
                            // Enrich the grant with trust-DB hash (first entry).
                            if let Some(first) = db_entries.first() {
                                grant.hash = Some(first.digest.clone());
                                grant.hash_origin = HashOrigin::Trustdb;
                                grant.hash_algorithm = hash_algorithm_from_len(&first.digest);
                            }
                            for e in &db_entries {
                                rows.push(TrustJoinRow::from_entry(e));
                            }
                        }
                        Ok(None) => {
                            // Miss: empty rows array for this grant.
                        }
                        Err(e) => {
                            eprintln!("error: trust DB lookup {path_str}: {e}");
                            return Ok(EXIT_LMDB_ERROR);
                        }
                    }
                }
                join_entries.push(TrustJoinEntry { grant_index, rows });
            }
            Some(TrustJoinOutputKind::Array(join_entries))
        }
    } else {
        None
    };

    // 5. --diff-against: compute drift.
    if let Some(ref snapshot_path) = args.diff_against {
        let snap_text = std::fs::read_to_string(snapshot_path)
            .with_context(|| format!("reading snapshot {}", snapshot_path.display()))?;
        let snapshot: RegisterSnapshot = serde_json::from_str(&snap_text)
            .with_context(|| format!("parsing snapshot {}", snapshot_path.display()))?;

        let drift = compute_drift(&grants, &snapshot.grants);
        let has_drift = !drift.is_empty();

        let rendered = render_json_drift(&drift);
        print!("{rendered}");

        if args.fail_on_drift && has_drift {
            return Ok(1); // EXIT_DRIFT_DETECTED (spec §9.4)
        }
        return Ok(EXIT_CLEAN);
    }

    // 6. Render the register (no diff mode).
    let rendered = match args.format {
        HumanJsonCsvFormat::Json => match trust_join_output {
            None => render_json_register(&grants),
            Some(TrustJoinOutputKind::Array(join)) => render_json_register_with_join(&grants, join),
            Some(TrustJoinOutputKind::Cap(cap)) => render_json_register_with_cap(&grants, cap),
        },
        HumanJsonCsvFormat::Csv => render_csv_register(&grants),
        HumanJsonCsvFormat::Human => render_human_register(&grants),
    };
    print!("{rendered}");
    Ok(EXIT_CLEAN)
}

/// Wrapper to distinguish the two trustJoin output shapes.
enum TrustJoinOutputKind {
    Array(Vec<TrustJoinEntry>),
    Cap(TrustJoinCap),
}

/// Collect all path literals from a grant's subject paths and object paths
/// for trust-DB lookup (exe= and path= keys only; dir= is a prefix, not exact key).
fn collect_grant_paths(grant: &RegisterRow) -> Vec<String> {
    let mut paths = Vec::new();
    paths.extend(grant.subject_paths.clone());
    paths.extend(grant.object_paths.clone());
    paths
}

/// Determine the `HashAlgorithm` from a hex digest's length.
fn hash_algorithm_from_len(hex: &str) -> Option<rulesteward_fapolicyd::HashAlgorithm> {
    use rulesteward_fapolicyd::HashAlgorithm;
    match hex.len() {
        32 => Some(HashAlgorithm::Md5),
        40 => Some(HashAlgorithm::Sha1),
        64 => Some(HashAlgorithm::Sha256),
        128 => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

/// Resolve the target rule files in fagenrules load order.
fn resolve_targets(args: &ReportArgs) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(file) = &args.file {
        return Ok(vec![file.clone()]);
    }
    let dir = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_D));
    if !dir.is_dir() {
        anyhow::bail!("{}: not a directory", dir.display());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension().and_then(|s| s.to_str()) == Some("rules")
                && !p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    files.sort_by(|a, b| fagenrules_cmp(a, b));
    Ok(files)
}
