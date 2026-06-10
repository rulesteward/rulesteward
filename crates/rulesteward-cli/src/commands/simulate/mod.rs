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
//! - The `exe=untrusted` / `exe=trusted` trust macros (#126) are evaluated
//!   against subject trust, but they are real only on fapolicyd >= 1.4.x;
//!   on 1.3.2 fapolicyd treats them as inert literal paths. simulate has no
//!   target-version parameter, so it always applies the >= 1.4.x semantics.

mod evaluate;
mod render;
mod workload;

use std::io::Read as _;

use anyhow::Context as _;
use rulesteward_fapolicyd::trustdb::{self, TrustDb};
use rulesteward_fapolicyd::{Entry, Rule, SetTable};
use serde::Serialize;

use crate::cli::{HumanJsonFormat, SimulateArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;

use evaluate::{EvalContext, evaluate_query, load_ruleset, ruleset_uses_filehash};
use render::render_human;
use workload::parse_workload;

/// Schema version for the `simulate` kind (issue #66).
const SIMULATE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// The 3-state verdict (section 2.3 of the simulate grounding doc).
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

    // Open the trust DB read-only (#127). Workload-supplied trust still takes
    // priority per-query; the DB only fills in trust the workload left Unknown.
    // A failure to open is non-fatal: warn and fall back to workload-only trust.
    let trustdb: Option<TrustDb> = match &args.trustdb {
        Some(db_path) => match trustdb::open_trustdb_readonly(db_path) {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!(
                    "warning: could not open --trustdb {}: {e}; trust taken from workload only",
                    db_path.display()
                );
                None
            }
        },
        None => None,
    };

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
    let ctx = EvalContext {
        trustdb: trustdb.as_ref(),
        ruleset_uses_filehash: ruleset_uses_filehash(&rules),
    };
    let results: Vec<ResultEntry> = queries
        .iter()
        .map(|q| evaluate_query(q, &rules, &sets, &ctx))
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
