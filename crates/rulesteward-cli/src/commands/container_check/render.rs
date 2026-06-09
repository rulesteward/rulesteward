//! JSON and human renderers for the container-check report.

use std::fmt::Write as _;

use serde::Serialize;

use super::checks::{DeepEvidence, Report};
use super::model::{Finding, RuntimeStatus, Severity};
use crate::output::json::render_envelope;

/// Schema version for the `container-check` kind. Bumps only on a breaking
/// change to the payload (field removal, rename, retype).
const CONTAINER_CHECK_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Shared severity tally (anti-drift between the two renderers)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SeverityCounts {
    high: usize,
    warn: usize,
    info: usize,
}

/// Tally finding severities once. Shared by both renderers so the JSON
/// `summary` and the human `Summary:` line cannot drift.
fn severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts {
        high: 0,
        warn: 0,
        info: 0,
    };
    for f in findings {
        match f.severity {
            Severity::High => c.high += 1,
            Severity::Warn => c.warn += 1,
            Severity::Info => c.info += 1,
        }
    }
    c
}

// ---------------------------------------------------------------------------
// JSON payload
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainerCheckPayload<'a> {
    rhcos: bool,
    fapolicyd_running: bool,
    summary: SeverityCounts,
    runtimes: &'a [RuntimeStatus],
    findings: &'a [Finding],
    #[serde(skip_serializing_if = "Option::is_none")]
    deep: Option<&'a DeepEvidence>,
}

impl Serialize for DeepEvidence {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("deep", 2)?;
        st.serialize_field("trust", &self.trust)?;
        st.serialize_field("denials", &self.denials)?;
        st.end()
    }
}

pub fn render_json(report: &Report) -> String {
    let payload = ContainerCheckPayload {
        rhcos: report.rhcos.is_rhcos,
        fapolicyd_running: report.fapolicyd_running,
        summary: severity_counts(&report.findings),
        runtimes: &report.runtimes,
        findings: &report.findings,
        deep: report.deep.as_ref(),
    };
    render_envelope("container-check", CONTAINER_CHECK_SCHEMA_VERSION, &payload)
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

pub fn render_human(report: &Report) -> String {
    // `writeln!` into a String is infallible; the `let _ =` discards the
    // impossible fmt::Error.
    let mut out = String::new();
    let _ = writeln!(out, "fapolicyd container-check");
    let _ = writeln!(out, "{}", "-".repeat(60));

    if report.rhcos.is_rhcos {
        let _ = writeln!(
            out,
            "[RHCOS] {} (fapolicyd is not the supported app-control path here)",
            report.rhcos.detail
        );
    }

    let _ = writeln!(out, "Detected runtimes:");
    for r in &report.runtimes {
        let state = if r.active {
            "active"
        } else if r.present {
            "present (inactive)"
        } else {
            "not detected"
        };
        let tag = if r.informational { " [info]" } else { "" };
        let _ = writeln!(out, "  - {}: {}{}", r.name, state, tag);
    }

    let _ = writeln!(out, "{}", "-".repeat(60));
    if report.findings.is_empty() {
        let _ = writeln!(out, "No risk findings.");
    } else {
        for f in &report.findings {
            let label = match f.severity {
                Severity::High => "HIGH",
                Severity::Warn => "WARN",
                Severity::Info => "INFO",
            };
            let _ = writeln!(out, "[{label}] {}: {}", f.code, f.detail);
        }
    }

    if let Some(ev) = &report.deep {
        let _ = writeln!(out, "{}", "-".repeat(60));
        let _ = writeln!(out, "Deep evidence (--deep):");
        let _ = writeln!(
            out,
            "  trust-DB: crun={}, runc={}, conmon={}",
            fmt_trust(ev.trust.crun_trusted),
            fmt_trust(ev.trust.runc_trusted),
            fmt_trust(ev.trust.conmon_trusted),
        );
        let _ = writeln!(
            out,
            "  recent FANOTIFY denials: {} total, {} from runtime binaries",
            ev.denials.total, ev.denials.runtime_denials
        );
    }

    let _ = writeln!(out, "{}", "-".repeat(60));
    let c = severity_counts(&report.findings);
    let _ = writeln!(
        out,
        "Summary: {} high, {} warn, {} info",
        c.high, c.warn, c.info
    );
    out
}

/// Render an `Option<bool>` trust flag: trusted / untrusted / n/a.
fn fmt_trust(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "trusted",
        Some(false) => "UNTRUSTED",
        None => "n/a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::container_check::model::RhcosStatus;

    fn report_with(findings: Vec<Finding>) -> Report {
        Report {
            runtimes: vec![],
            findings,
            rhcos: RhcosStatus {
                is_rhcos: false,
                detail: String::new(),
            },
            fapolicyd_running: true,
            deep: None,
        }
    }

    #[test]
    fn json_has_correct_envelope_and_kind() {
        let out = render_json(&report_with(vec![Finding {
            code: "namespace-limitation",
            severity: Severity::Warn,
            detail: "x".into(),
        }]));
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["kind"], "container-check");
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["summary"]["warn"], 1);
        assert_eq!(v["findings"][0]["severity"], "warn");
        // Trailing newline for shell pipelines.
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn json_omits_deep_when_absent() {
        let out = render_json(&report_with(vec![]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v.get("deep").is_none(),
            "deep must be absent without --deep"
        );
    }

    #[test]
    fn human_reports_no_findings_cleanly() {
        let out = render_human(&report_with(vec![]));
        assert!(out.contains("No risk findings."));
        assert!(!out.contains('<'), "no placeholder leakage");
    }

    #[test]
    fn json_summary_tallies_every_severity() {
        // Pins each severity_counts branch (high/warn/info) independently.
        let f = |code, sev| Finding {
            code,
            severity: sev,
            detail: String::new(),
        };
        let out = render_json(&report_with(vec![
            f("a", Severity::High),
            f("b", Severity::Warn),
            f("c", Severity::Info),
            f("d", Severity::Info),
        ]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["summary"]["high"], 1);
        assert_eq!(v["summary"]["warn"], 1);
        assert_eq!(v["summary"]["info"], 2);
    }

    #[test]
    fn human_deep_section_renders_each_trust_state() {
        use crate::commands::container_check::model::{DeepDenials, DeepTrust};
        let mut report = report_with(vec![]);
        report.deep = Some(DeepEvidence {
            trust: DeepTrust {
                crun_trusted: Some(true),
                runc_trusted: Some(false),
                conmon_trusted: None,
            },
            denials: DeepDenials {
                total: 3,
                runtime_denials: 2,
            },
        });
        let out = render_human(&report);
        // Pins fmt_trust's three arms and the denial-count line.
        assert!(out.contains("crun=trusted"), "{out}");
        assert!(out.contains("runc=UNTRUSTED"), "{out}");
        assert!(out.contains("conmon=n/a"), "{out}");
        assert!(out.contains("3 total, 2 from runtime binaries"), "{out}");
    }
}
