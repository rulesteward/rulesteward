//! `rulesteward fapolicyd simulate` body.
//!
//! Replays a workload of access attempts against a rule set and reports
//! which rule decides each access (or fallthrough), with a 3-state verdict:
//!
//! - `Decisive` - no unevaluable rule sat above the matched rule.
//! - `Possible` - an unevaluable rule (`pattern=`, unknown `ftype=`, missing
//!   trust DB) appeared before the matched/fallthrough rule.
//! - `NoMatch` - fallthrough with no unevaluable rule encountered.
//!
//! ## Known limitations (#69)
//!
//! - `pattern=` rules cannot be evaluated statically; they produce a
//!   `Possible` verdict with a confidence note.
//! - `ftype=` (non-`any`) requires a real MIME lookup (libmagic); absent
//!   `ftype` in the workload is `NotEvaluable` -> `Possible`.
//! - Trust-DB presence is not the same as runtime integrity: the daemon
//!   re-checks sha256/size on every access; a file modified on disk after
//!   the trust DB was built will be marked untrusted at runtime.
//! - `exe=untrusted` / `exe=trusted` trust macros are NOT evaluated
//!   (treated as literal exe paths); tracked in issue #126.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::PathBuf;

use anyhow::Context as _;
use rulesteward_fapolicyd::{AccessFacts, Decision, Entry, Perm, Rule, SetTable, Source, Trust};
use serde::Serialize;

use crate::cli::{HumanJsonFormat, SimulateArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;

/// Schema version for the `simulate` kind (issue #66).
const SIMULATE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// The 3-state verdict (§2.3 of the simulate grounding doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum Verdict3 {
    /// All evaluated fields matched; no unevaluable rule sat above the match.
    Decisive,
    /// An unevaluable rule (`pattern=`, unknown `ftype=`, missing trust DB)
    /// appeared before the decisive/fallthrough rule.
    Possible,
    /// Fallthrough with no unevaluable rules encountered.
    NoMatch,
}

/// One result entry in the `results` array.
#[derive(Debug, Serialize)]
struct ResultEntry {
    verdict: Verdict3,
    decision: &'static str,
    #[serde(rename = "matchedRule")]
    matched_rule: Option<usize>,
    source: &'static str,
    #[serde(rename = "confidenceNote")]
    confidence_note: String,
}

/// Summary counts over all results.
#[derive(Debug, Default, Serialize)]
struct Summary {
    total: usize,
    decisive: usize,
    possible: usize,
    #[serde(rename = "noMatch")]
    no_match: usize,
}

/// The `simulate` JSON payload (flattened into the envelope).
#[derive(Debug, Serialize)]
struct SimulatePayload {
    results: Vec<ResultEntry>,
    summary: Summary,
}

// ---------------------------------------------------------------------------
// Workload parsing
// ---------------------------------------------------------------------------

/// A single parsed access query from the workload.
struct Query {
    perm: Perm,
    exe: Option<String>,
    path: Option<String>,
    comm: Option<String>,
    device: Option<String>,
    uids: Vec<u32>,
    gids: Vec<u32>,
    ftype: Option<String>,
    sha256: Option<String>,
    /// Trust applies to both subject and object (the workload.json has a single
    /// `trust` field; the evaluate engine checks trust on both sides against the
    /// same value so that a workload expressing "this exe is trusted" and "this
    /// object is trusted" can be expressed with one field).
    trust: Trust,
}

/// Parse a single JSON object `{exe, path, perm, ...}` into a `Query`.
fn parse_json_object(obj: &serde_json::Map<String, serde_json::Value>) -> anyhow::Result<Query> {
    let perm_str = obj.get("perm").and_then(|v| v.as_str()).unwrap_or("open");
    let perm = match perm_str {
        "open" => Perm::Open,
        "execute" => Perm::Execute,
        "any" => Perm::Any,
        other => anyhow::bail!("unknown perm value in workload: {other:?}"),
    };

    // Use `resolved_exe` when present (multicall binaries on RHEL 8/9/10 resolve
    // to a different path than the symlink), falling back to `exe`.
    let exe = obj
        .get("resolved_exe")
        .or_else(|| obj.get("exe"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let path = obj.get("path").and_then(|v| v.as_str()).map(str::to_owned);
    let comm = obj.get("comm").and_then(|v| v.as_str()).map(str::to_owned);
    let device = obj
        .get("device")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let ftype = obj.get("ftype").and_then(|v| v.as_str()).map(str::to_owned);
    let sha256 = obj
        .get("sha256")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // uid / gid: accept a single integer, an array of integers, or null (= absent).
    let uids = parse_int_field(obj, "uid")?;
    let gids = parse_int_field(obj, "gid")?;

    // trust: bool, null, or absent. null and absent both map to Trust::Unknown.
    let trust = match obj.get("trust") {
        None | Some(serde_json::Value::Null) => Trust::Unknown,
        Some(serde_json::Value::Bool(true)) => Trust::Yes,
        Some(serde_json::Value::Bool(false)) => Trust::No,
        Some(other) => anyhow::bail!("unexpected trust value in workload: {other}"),
    };

    Ok(Query {
        perm,
        exe,
        path,
        comm,
        device,
        uids,
        gids,
        ftype,
        sha256,
        trust,
    })
}

/// Parse a uid or gid field: single integer, array, null, or absent.
/// `null` and absent both produce an empty Vec (absent fact - widens the match).
fn parse_int_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<Vec<u32>> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{key} must be a non-negative integer"))?;
            Ok(vec![
                u32::try_from(v).context(format!("{key} value {v} overflows u32"))?,
            ])
        }
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| {
                        anyhow::anyhow!("{key} array element must be a non-negative integer")
                    })
                    .and_then(|n| {
                        u32::try_from(n).context(format!("{key} value {n} overflows u32"))
                    })
            })
            .collect(),
        Some(other) => anyhow::bail!("unexpected {key} value: {other}"),
    }
}

/// Parse a terse line `perm exe -> path` into a `Query`.
///
/// Grammar: `<perm> <exe> -> <path>`
/// Examples:
///   `execute /usr/bin/curl -> /tmp/payload`
///   `open /usr/bin/cat -> /etc/hostname`
fn parse_terse_line(line: &str) -> anyhow::Result<Query> {
    let line = line.trim();
    // Split on " -> "
    let (left, path_part) = line
        .split_once(" -> ")
        .ok_or_else(|| anyhow::anyhow!("terse line missing ' -> ': {line:?}"))?;

    let mut parts = left.splitn(2, ' ');
    let perm_str = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("terse line missing perm: {line:?}"))?;
    let exe_str = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("terse line missing exe: {line:?}"))?;

    let perm = match perm_str {
        "open" => Perm::Open,
        "execute" => Perm::Execute,
        "any" => Perm::Any,
        other => anyhow::bail!("unknown perm in terse line: {other:?}"),
    };

    Ok(Query {
        perm,
        exe: Some(exe_str.trim().to_owned()),
        path: Some(path_part.trim().to_owned()),
        comm: None,
        device: None,
        uids: Vec::new(),
        gids: Vec::new(),
        ftype: None,
        sha256: None,
        trust: Trust::Unknown,
    })
}

/// Parse the workload string into a `Vec<Query>`.
///
/// Detects JSON (`{` or `[` prefix) vs terse line format.
fn parse_workload(raw: &str) -> anyhow::Result<Vec<Query>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // JSON path
        let value: serde_json::Value =
            serde_json::from_str(trimmed).context("parsing workload JSON")?;
        match value {
            serde_json::Value::Object(obj) => Ok(vec![parse_json_object(&obj)?]),
            serde_json::Value::Array(arr) => arr
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    item.as_object()
                        .ok_or_else(|| {
                            anyhow::anyhow!("workload array element {i} is not an object")
                        })
                        .and_then(parse_json_object)
                })
                .collect(),
            other => anyhow::bail!("workload JSON must be an object or array, got: {other}"),
        }
    } else {
        // Terse line format
        raw.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(parse_terse_line)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Ruleset loading (mirroring the pattern in commands/explain.rs)
// ---------------------------------------------------------------------------

/// Load and parse all `*.rules` files from `rules_dir` in fagenrules order.
///
/// Returns `(entries, parse_error)` where `parse_error` is true when any file
/// had a parse failure (caller should return `EXIT_RULE_PARSE_ERROR`).
fn load_ruleset(rules_dir: &std::path::Path) -> anyhow::Result<(Vec<Entry>, bool)> {
    if !rules_dir.is_dir() {
        anyhow::bail!("{}: not a directory", rules_dir.display());
    }

    let mut rule_files: Vec<PathBuf> = std::fs::read_dir(rules_dir)
        .with_context(|| format!("reading rules directory {}", rules_dir.display()))?
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
    rule_files.sort_by(|a, b| rulesteward_fapolicyd::fagenrules_cmp(a, b));

    let mut all_entries: Vec<Entry> = Vec::new();
    let mut parse_error = false;

    for path in &rule_files {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("reading rule file {}", path.display()))?;
        match rulesteward_fapolicyd::parse_rules_file(&source, path) {
            Ok(entries) => all_entries.extend(entries),
            Err(_diags) => {
                eprintln!("error: parsing rule file {}", path.display());
                parse_error = true;
            }
        }
    }

    Ok((all_entries, parse_error))
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Map a `Decision` to the canonical `"allow"` / `"deny"` string.
fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog => {
            "allow"
        }
        Decision::Deny | Decision::DenyAudit | Decision::DenySyslog | Decision::DenyLog => "deny",
    }
}

/// Evaluate one `Query` against the ruleset and produce a `ResultEntry`.
fn evaluate_query(query: &Query, rules: &[Rule], sets: &SetTable) -> ResultEntry {
    // Single workload `trust` field maps to both sides of the trust check.
    // This means a workload expressing "exe is trusted, object is trusted"
    // covers both subject-side `trust=1` and object-side `trust=1` rules.
    let facts = AccessFacts {
        perm: query.perm,
        exe: query.exe.clone(),
        comm: query.comm.clone(),
        path: query.path.clone(),
        device: query.device.clone(),
        uids: query.uids.clone(),
        gids: query.gids.clone(),
        auid: None,
        sessionid: None,
        pid: None,
        ppid: None,
        subj_trust: query.trust,
        obj_trust: query.trust,
        ftype: query.ftype.clone(),
        sha256: query.sha256.clone(),
    };

    let verdict = rulesteward_fapolicyd::evaluate(rules, sets, &facts);

    // 3-state: Possible when uncertain is Some; NoMatch when fallthrough + no
    // uncertainty; Decisive otherwise.
    let v3 = if verdict.uncertain.is_some() {
        Verdict3::Possible
    } else if verdict.source == Source::Fallthrough {
        Verdict3::NoMatch
    } else {
        Verdict3::Decisive
    };

    let source_str = match verdict.source {
        Source::Rule => "rule",
        Source::Fallthrough => "fallthrough",
    };

    let confidence_note = if let Some(ref reason) = verdict.uncertain {
        format!("uncertain: {reason}")
    } else if verdict.source == Source::Fallthrough {
        "no rule matched; implicit allow (fallthrough)".to_owned()
    } else {
        format!(
            "decisive: rule {} {}",
            verdict.matched_rule.unwrap_or(0),
            decision_str(verdict.decision)
        )
    };

    ResultEntry {
        verdict: v3,
        decision: decision_str(verdict.decision),
        matched_rule: verdict.matched_rule,
        source: source_str,
        confidence_note,
    }
}

// ---------------------------------------------------------------------------
// Human rendering
// ---------------------------------------------------------------------------

/// Render results in human-readable form.
fn render_human(results: &[ResultEntry], queries: &[Query]) -> String {
    let mut out = String::new();
    for (i, (res, q)) in results.iter().zip(queries.iter()).enumerate() {
        let verdict_label = match res.verdict {
            Verdict3::Decisive => "DECISIVE",
            Verdict3::Possible => "POSSIBLE",
            Verdict3::NoMatch => "NO MATCH",
        };
        let exe_label = q.exe.as_deref().unwrap_or("<unknown>");
        let path_label = q.path.as_deref().unwrap_or("<unknown>");
        let perm_str = match q.perm {
            Perm::Open => "open",
            Perm::Execute => "execute",
            Perm::Any => "any",
        };
        let _ = writeln!(
            out,
            "query {n}: {perm} {exe} -> {path}",
            n = i + 1,
            perm = perm_str,
            exe = exe_label,
            path = path_label,
        );
        if res.source == "rule" {
            let _ = writeln!(
                out,
                "  verdict: {verdict_label} {decision} (rule {rule})",
                decision = res.decision,
                rule = res.matched_rule.unwrap_or(0),
            );
        } else {
            let _ = writeln!(
                out,
                "  verdict: {verdict_label} allow (fallthrough - no rule matched)"
            );
        }
        let _ = writeln!(out, "  note: {}", res.confidence_note);
    }

    // Summary line
    let total = results.len();
    let decisive = results
        .iter()
        .filter(|r| r.verdict == Verdict3::Decisive)
        .count();
    let possible = results
        .iter()
        .filter(|r| r.verdict == Verdict3::Possible)
        .count();
    let no_match = results
        .iter()
        .filter(|r| r.verdict == Verdict3::NoMatch)
        .count();
    out.push('\n');
    let _ = writeln!(
        out,
        "summary: {total} queries, {decisive} decisive, {possible} possible, {no_match} no-match"
    );
    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the simulate subcommand.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: SimulateArgs) -> anyhow::Result<i32> {
    // --- Load ruleset ---
    let (entries, parse_error) = match load_ruleset(&args.rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: loading ruleset: {e:#}");
            return Ok(EXIT_TOOL_FAILURE);
        }
    };
    if parse_error {
        return Ok(EXIT_RULE_PARSE_ERROR);
    }

    // Extract only Rule items (SetDefinitions are used by SetTable; blanks/comments skip).
    let rules: Vec<Rule> = entries
        .iter()
        .filter_map(|e| {
            if let Entry::Rule(r) = e {
                Some(r.clone())
            } else {
                None
            }
        })
        .collect();
    let sets = SetTable::from_entries(&entries);

    // --- Read workload ---
    let workload_raw = if args.workload == std::path::Path::new("-") {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading workload from stdin")?;
        buf
    } else {
        std::fs::read_to_string(&args.workload)
            .with_context(|| format!("reading workload file {}", args.workload.display()))?
    };

    // --- Parse workload ---
    let queries = match parse_workload(&workload_raw) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("error: parsing workload: {e:#}");
            return Ok(EXIT_TOOL_FAILURE);
        }
    };

    // --- Evaluate ---
    let results: Vec<ResultEntry> = queries
        .iter()
        .map(|q| evaluate_query(q, &rules, &sets))
        .collect();

    // --- Summary ---
    let mut summary = Summary {
        total: results.len(),
        ..Summary::default()
    };
    for res in &results {
        match res.verdict {
            Verdict3::Decisive => summary.decisive += 1,
            Verdict3::Possible => summary.possible += 1,
            Verdict3::NoMatch => summary.no_match += 1,
        }
    }

    // --- Render ---
    match args.format {
        HumanJsonFormat::Human => {
            print!("{}", render_human(&results, &queries));
        }
        HumanJsonFormat::Json => {
            let payload = SimulatePayload { results, summary };
            print!(
                "{}",
                render_envelope("simulate", SIMULATE_SCHEMA_VERSION, &payload)
            );
        }
    }

    Ok(EXIT_CLEAN)
}
