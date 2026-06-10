//! Ruleset loading and per-query evaluation.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use rulesteward_fapolicyd::trustdb::{self, TrustDb};
use rulesteward_fapolicyd::{AccessFacts, Attr, Decision, Entry, Rule, SetTable, Source, Trust};

use super::workload::Query;
use super::{ResultEntry, Verdict3};

/// Load and parse all `*.rules` files from `rules_dir` in fagenrules order.
///
/// Returns `(entries, parse_error)` where `parse_error` is true when any file
/// had a parse failure (caller should return `EXIT_RULE_PARSE_ERROR`).
pub(super) fn load_ruleset(rules_dir: &std::path::Path) -> anyhow::Result<(Vec<Entry>, bool)> {
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

/// Map a `Decision` to the canonical `"allow"` / `"deny"` string.
fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog => {
            "allow"
        }
        Decision::Deny | Decision::DenyAudit | Decision::DenySyslog | Decision::DenyLog => "deny",
    }
}

/// Resolution context threaded into per-query evaluation (#127).
///
/// Holds the optional read-only trust DB handle (for `--trustdb` trust
/// resolution) and a flag for whether the ruleset references a
/// `filehash=`/`sha256hash=` object attribute (so we only hash the object file
/// on demand when a rule actually needs it).
pub(super) struct EvalContext<'a> {
    /// Open read-only trust DB, when `--trustdb` was supplied and opened OK.
    pub(super) trustdb: Option<&'a TrustDb>,
    /// True iff at least one rule's object side carries `filehash=`/`sha256hash=`.
    pub(super) ruleset_uses_filehash: bool,
}

/// True iff any rule's object side carries a `filehash=`/`sha256hash=` attribute.
pub(super) fn ruleset_uses_filehash(rules: &[Rule]) -> bool {
    rules.iter().any(|r| {
        r.object.iter().any(|a| {
            matches!(
                a,
                Attr::Kv { key, .. } if key == "filehash" || key == "sha256hash"
            )
        })
    })
}

/// Resolve a side's trust from the trust DB when the workload left it `Unknown`.
///
/// Workload-supplied trust always wins (`current != Unknown` is returned as-is).
/// Otherwise, with an open DB and a known path: PRESENT in the DB => `Trust::Yes`,
/// ABSENT => `Trust::No`. With no DB or no path, the original value is unchanged.
fn resolve_trust(current: Trust, path: Option<&str>, db: Option<&TrustDb>) -> Trust {
    if current != Trust::Unknown {
        return current; // workload-supplied trust takes priority over the DB
    }
    match (db, path) {
        (Some(db), Some(p)) => {
            if db.contains_path(p) {
                Trust::Yes
            } else {
                Trust::No
            }
        }
        _ => current,
    }
}

/// Evaluate one `Query` against the ruleset and produce a `ResultEntry`.
pub(super) fn evaluate_query(
    query: &Query,
    rules: &[Rule],
    sets: &SetTable,
    ctx: &EvalContext,
) -> ResultEntry {
    // Subject and object trust are tracked independently. The workload JSON
    // supports `subjTrust` / `objTrust` per-side overrides as well as the
    // symmetric `trust` shorthand (parsed in `parse_json_object`). When the
    // workload left a side `Unknown`, `--trustdb` resolves it (#127): the
    // subject side keys on the exe path, the object side on the object path.
    let subj_trust = resolve_trust(query.subj_trust, query.exe.as_deref(), ctx.trustdb);
    let obj_trust = resolve_trust(query.obj_trust, query.path.as_deref(), ctx.trustdb);

    // On-demand object hashing (#127): when a `filehash=`/`sha256hash=` rule
    // needs the object's hash and the workload omitted `sha256`, hash the object
    // `path` now. Three outcomes, distinguished so the filehash field evaluates
    // correctly (rules.c:1606-1611 (fapolicyd 1.4.5) treats a hash-lookup error as a denial):
    //   - `Ok(Some(h))`  : hashed OK -> use the digest.
    //   - `Ok(None)`     : object ABSENT (NotFound) -> leave `sha256 = None`;
    //                      the absent-fact-widening / NotEvaluable behavior applies.
    //   - `Err(_)`       : object PRESENT but UNHASHABLE (e.g. EACCES) -> leave
    //                      `sha256 = None` AND set `sha256_unhashable = true`, so
    //                      the `filehash=` constraint is `NoMatch` (deny), not widen.
    let (sha256, sha256_unhashable) = match (&query.sha256, &query.path) {
        (None, Some(p)) if ctx.ruleset_uses_filehash => match trustdb::sha256_file(Path::new(p)) {
            Ok(opt) => (opt, false),
            Err(e) => {
                eprintln!(
                    "simulate: could not hash object {p}: {e}; treating as unhashable \
                         (deny per FILE_HASH error-as-denial)"
                );
                (None, true)
            }
        },
        _ => (query.sha256.clone(), false),
    };

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
        subj_trust,
        obj_trust,
        ftype: query.ftype.clone(),
        sha256,
        sha256_unhashable,
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
