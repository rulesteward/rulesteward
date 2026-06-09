//! JSON and human renderers for the doctor report.

use std::fmt::Write as _;

use serde::Serialize;

use super::model::{CheckResult, CheckStatus};
use crate::output::json::render_envelope;

/// Schema version for the `doctor-report` kind.
/// Bumps only on a breaking change (field removal, rename, retype).
const DOCTOR_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// JSON payload
// ---------------------------------------------------------------------------

/// Summary counts for the JSON payload.
#[derive(Serialize)]
struct DoctorSummary {
    total: usize,
    ok: usize,
    warn: usize,
    fail: usize,
    skip: usize,
    unknown: usize,
}

/// Tally check statuses once. Shared by both renderers so the JSON `summary`
/// and the human `Summary:` line cannot drift (e.g. when a `CheckStatus`
/// variant is added, only this function changes).
fn status_counts(results: &[CheckResult]) -> DoctorSummary {
    let mut s = DoctorSummary {
        total: results.len(),
        ok: 0,
        warn: 0,
        fail: 0,
        skip: 0,
        unknown: 0,
    };
    for r in results {
        match r.status {
            CheckStatus::Ok => s.ok += 1,
            CheckStatus::Warn => s.warn += 1,
            CheckStatus::Fail => s.fail += 1,
            CheckStatus::Skip => s.skip += 1,
            CheckStatus::Unknown => s.unknown += 1,
        }
    }
    s
}

/// The `doctor-report` JSON payload (flattened into the envelope).
#[derive(Serialize)]
struct DoctorPayload<'a> {
    summary: DoctorSummary,
    checks: &'a [CheckResult],
}

pub(super) fn render_json(results: &[CheckResult]) -> String {
    let payload = DoctorPayload {
        summary: status_counts(results),
        checks: results,
    };
    render_envelope("doctor-report", DOCTOR_SCHEMA_VERSION, &payload)
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

pub(super) fn render_human(results: &[CheckResult]) -> String {
    // `writeln!` into a `String` (via `fmt::Write`) is infallible -- the buffer
    // never returns Err -- so the `let _ =` discards the impossible error.
    let mut out = String::new();
    let _ = writeln!(out, "fapolicyd doctor report");
    let _ = writeln!(out, "{}", "-".repeat(60));
    for r in results {
        let status_label = match r.status {
            CheckStatus::Ok => " OK  ",
            CheckStatus::Warn => "WARN ",
            CheckStatus::Fail => "FAIL ",
            CheckStatus::Skip => "SKIP ",
            CheckStatus::Unknown => " ?? ",
        };
        let _ = writeln!(out, "[{status_label}] {}: {}", r.name, r.detail);
        if let Some(ref rem) = r.remediation {
            let _ = writeln!(out, "       -> {rem}");
        }
    }
    let _ = writeln!(out, "{}", "-".repeat(60));

    // Shared tally so the human summary cannot drift from the JSON summary.
    let c = status_counts(results);
    let _ = writeln!(
        out,
        "Summary: {} ok, {} warn, {} fail, {} skip, {} unknown",
        c.ok, c.warn, c.fail, c.skip, c.unknown
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: CheckStatus) -> CheckResult {
        CheckResult {
            name: "test",
            status,
            detail: String::new(),
            remediation: None,
        }
    }

    // -------------------------------------------------------------------------
    // JSON output contract
    // -------------------------------------------------------------------------

    #[test]
    fn render_json_output_has_correct_envelope() {
        let results = vec![
            CheckResult {
                name: "service-status",
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckResult {
                name: "kernel-version",
                status: CheckStatus::Fail,
                detail: "old kernel".to_string(),
                remediation: Some("upgrade".to_string()),
            },
        ];
        let out = render_json(&results);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["kind"], "doctor-report");
        assert_eq!(v["schemaVersion"], 1);
        assert!(v["summary"].is_object(), "summary must be an object");
        assert!(v["checks"].is_array(), "checks must be an array");
        assert_eq!(v["checks"].as_array().unwrap().len(), 2);
        assert!(out.ends_with('\n'), "output must end with newline");
    }

    #[test]
    fn render_json_check_status_serializes_as_lowercase() {
        // Serde rename_all = "lowercase" means "ok"/"warn"/"fail"/"skip"/"unknown".
        let results = vec![
            result(CheckStatus::Ok),
            result(CheckStatus::Warn),
            result(CheckStatus::Fail),
            result(CheckStatus::Skip),
            result(CheckStatus::Unknown),
        ];
        let out = render_json(&results);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let statuses: Vec<&str> = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, ["ok", "warn", "fail", "skip", "unknown"]);
    }
    // -------------------------------------------------------------------------
    // JOB 1A: status_counts tally -- kills the `replace += with *=` survivors
    //
    // A `*= 1` mutant would leave every counter at 0, so asserting exact
    // non-zero counts for each bucket kills all five mutants at once.
    // The JSON summary path is also asserted to pin that render_json uses the
    // same tally (the two renderers share status_counts, so they cannot drift).
    // -------------------------------------------------------------------------

    #[test]
    fn status_counts_exact_tally_kills_star_eq_mutants() {
        // 2 Ok, 1 Warn, 3 Fail, 1 Skip, 1 Unknown -- total 8.
        let results: Vec<CheckResult> = vec![
            result(CheckStatus::Ok),
            result(CheckStatus::Ok),
            result(CheckStatus::Warn),
            result(CheckStatus::Fail),
            result(CheckStatus::Fail),
            result(CheckStatus::Fail),
            result(CheckStatus::Skip),
            result(CheckStatus::Unknown),
        ];
        let s = status_counts(&results);
        assert_eq!(s.total, 8);
        assert_eq!(s.ok, 2, "ok count");
        assert_eq!(s.warn, 1, "warn count");
        assert_eq!(s.fail, 3, "fail count");
        assert_eq!(s.skip, 1, "skip count");
        assert_eq!(s.unknown, 1, "unknown count");
    }

    #[test]
    fn render_json_summary_reflects_exact_tally() {
        // The JSON envelope must carry the exact per-bucket counts.
        // Pins that render_json calls status_counts and that the JSON field
        // names match the DoctorSummary struct fields.
        let results: Vec<CheckResult> = vec![
            result(CheckStatus::Ok),
            result(CheckStatus::Ok),
            result(CheckStatus::Warn),
            result(CheckStatus::Fail),
            result(CheckStatus::Fail),
            result(CheckStatus::Fail),
            result(CheckStatus::Skip),
            result(CheckStatus::Unknown),
        ];
        let out = render_json(&results);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["summary"]["total"], 8);
        assert_eq!(v["summary"]["ok"], 2);
        assert_eq!(v["summary"]["warn"], 1);
        assert_eq!(v["summary"]["fail"], 3);
        assert_eq!(v["summary"]["skip"], 1);
        assert_eq!(v["summary"]["unknown"], 1);
    }
}
