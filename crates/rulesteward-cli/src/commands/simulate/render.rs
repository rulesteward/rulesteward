//! Human-readable rendering of simulate results.

use std::fmt::Write as _;

use rulesteward_fapolicyd::Perm;

use super::workload::Query;
use super::{ResultEntry, Verdict3};

/// Render results in human-readable form.
pub(super) fn render_human(results: &[ResultEntry], queries: &[Query]) -> String {
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
