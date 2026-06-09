//! Pure classification logic for container-check.
//!
//! Every function here is pure over [`ContainerProbe`] data: no OS access, so
//! the whole module is unit-tested with `FakeProbe`. The live shell-outs live in
//! [`super::probe`].

use std::path::Path;

use super::model::{
    ContainerProbe, DeepDenials, DeepTrust, Finding, RhcosStatus, RuntimeStatus, Severity,
};

/// The factual namespace-limitation notice attached to WARN/HIGH findings.
///
/// This is the spec's wedge text (section 6.1, lines 423-425) WITHOUT the
/// trailing `See <paid-product-url>/...` placeholder sentence (a literal
/// placeholder is never emitted). The `stb.id.au` citation is a real source.
pub const NAMESPACE_NOTICE: &str = "fapolicyd does not fully support container namespaces (Red Hat Bug RHEL-114562). For application control in Kubernetes/OpenShift, Red Hat recommends Red Hat Advanced Cluster Security rather than fapolicyd (https://www.stb.id.au/blog/app-control-for-everyone).";

/// `--deep` evidence gathered from the running daemon.
#[derive(Debug, Clone)]
pub struct DeepEvidence {
    pub trust: DeepTrust,
    pub denials: DeepDenials,
}

/// The full container-check result.
#[derive(Debug, Clone)]
pub struct Report {
    /// The seven detectable runtimes (RHCOS is tracked separately).
    pub runtimes: Vec<RuntimeStatus>,
    /// Risk findings, in evaluation order.
    pub findings: Vec<Finding>,
    /// RHCOS / `OpenShift` node detection (forces exit 3).
    pub rhcos: RhcosStatus,
    /// Whether fapolicyd was running (drives the inactive-downgrade rule).
    pub fapolicyd_running: bool,
    /// `--deep` evidence, present only when `--deep` was passed.
    pub deep: Option<DeepEvidence>,
}

/// Gather the seven detectable runtimes (RHCOS handled separately).
pub fn detect_runtimes(probe: &dyn ContainerProbe) -> Vec<RuntimeStatus> {
    vec![
        probe.podman_rootful(),
        probe.podman_rootless(),
        probe.docker(),
        probe.containerd(),
        probe.crio(),
        probe.kubelet(),
        probe.cni_configured(),
    ]
}

/// True if any non-informational runtime is active. CNI is informational and
/// never counts toward the "active runtime" risk trigger.
pub fn any_runtime_active(runtimes: &[RuntimeStatus]) -> bool {
    runtimes.iter().any(|r| r.active && !r.informational)
}

/// Classify the host: detect runtimes, evaluate the risk verdicts, and (under
/// `--deep`) attach evidence. Pure over the probe.
pub fn classify(probe: &dyn ContainerProbe, rules_dir: &Path, deep: bool) -> Report {
    let runtimes = detect_runtimes(probe);
    let rhcos = probe.rhcos_status();
    let state = probe.fapolicyd_state();
    let conf = probe.effective_conf(rules_dir);
    let bins = probe.runtime_binaries();
    let coverage = probe.crun_rule_coverage(rules_dir);

    let active = any_runtime_active(&runtimes);
    let tmpfs_watched = conf.watch_fs.iter().any(|fs| fs == "tmpfs");
    let mut findings: Vec<Finding> = Vec::new();

    // HIGH: tmpfs in effective watch_fs AND a container runtime active (RHEL-114562).
    if active && tmpfs_watched {
        findings.push(Finding {
            code: "tmpfs-watch-fs",
            severity: Severity::High,
            detail: format!(
                "tmpfs is in the effective watch_fs list and a container runtime is active; \
                 container layer execs on tmpfs can hit the broken-pipe class of failures. {NAMESPACE_NOTICE}"
            ),
        });
    }

    // HIGH: allow_filesystem_mark=1 AND a container runtime active.
    if active && conf.allow_filesystem_mark {
        findings.push(Finding {
            code: "allow-filesystem-mark",
            severity: Severity::High,
            detail: format!(
                "allow_filesystem_mark=1 with a container runtime active; overlay mediation can \
                 block container layer execs. {NAMESPACE_NOTICE}"
            ),
        });
    }

    // WARN baseline: a runtime is active on an enforcing fapolicyd host but no
    // HIGH trigger fired. The general namespace limitation still applies.
    if active && !tmpfs_watched && !conf.allow_filesystem_mark {
        findings.push(Finding {
            code: "namespace-limitation",
            severity: Severity::Warn,
            detail: format!(
                "a container runtime is active on a host running fapolicyd. {NAMESPACE_NOTICE}"
            ),
        });
    }

    // INFO: runc/crun present but no allow rule covers it (independent advisory).
    if (bins.crun || bins.runc) && !coverage.covered {
        findings.push(Finding {
            code: "crun-no-allow-rule",
            severity: Severity::Info,
            detail: format!(
                "a container runtime binary (crun/runc) is present but no allow rule covers it: {}",
                coverage.detail
            ),
        });
    }

    let deep_ev = if deep {
        Some(DeepEvidence {
            trust: probe.deep_trust(),
            denials: probe.deep_denials(),
        })
    } else {
        None
    };

    // Inactive-downgrade: if fapolicyd is not running it is not enforcing, so
    // every High/Warn finding drops to Info (spec: "fapolicyd inactive/disabled
    // -> drop to INFO regardless"). We trigger on `!running` (not currently
    // enforcing); a running-but-not-enabled daemon is still enforcing now.
    if !state.running {
        for f in &mut findings {
            if f.severity != Severity::Info {
                f.severity = Severity::Info;
                f.detail = format!("{} (downgraded: fapolicyd is not running)", f.detail);
            }
        }
    }

    Report {
        runtimes,
        findings,
        rhcos,
        fapolicyd_running: state.running,
        deep: deep_ev,
    }
}

/// The worst finding severity, if any (ignores RHCOS, which is separate).
#[must_use]
pub fn worst_severity(report: &Report) -> Option<Severity> {
    report
        .findings
        .iter()
        .map(|f| f.severity)
        .max_by_key(|s| match s {
            Severity::Info => 0,
            Severity::Warn => 1,
            Severity::High => 2,
        })
}

/// Map a [`Report`] to the process exit code.
///
/// Precedence (spec section 6.1, line 421): RHCOS wins (exit 3) even if a HIGH
/// finding is also present; otherwise HIGH -> 2, WARN -> 1, else 0. INFO is
/// non-escalating.
#[must_use]
pub fn exit_code(report: &Report) -> i32 {
    if report.rhcos.is_rhcos {
        return 3;
    }
    match worst_severity(report) {
        Some(Severity::High) => 2,
        Some(Severity::Warn) => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::container_check::model::{
        CrunRuleCoverage, EffectiveConf, FapolicydState, RuntimeBinaries,
    };

    // -----------------------------------------------------------------------
    // FakeProbe -- configurable, defaults to "nothing detected, fapolicyd
    // running+enabled, no tmpfs in watch_fs, no mark, no runtime binaries,
    // crun rule covered". Tests mutate only what they care about.
    // -----------------------------------------------------------------------
    struct FakeProbe {
        runtimes: Vec<RuntimeStatus>,
        rhcos: RhcosStatus,
        state: FapolicydState,
        conf: EffectiveConf,
        bins: RuntimeBinaries,
        coverage: CrunRuleCoverage,
        deep_trust: DeepTrust,
        deep_denials: DeepDenials,
    }

    fn rt(name: &'static str, present: bool, active: bool, informational: bool) -> RuntimeStatus {
        RuntimeStatus {
            name,
            present,
            active,
            informational,
            detail: String::new(),
        }
    }

    impl FakeProbe {
        fn new() -> Self {
            FakeProbe {
                runtimes: vec![
                    rt("podman-rootful", false, false, false),
                    rt("podman-rootless", false, false, false),
                    rt("docker", false, false, false),
                    rt("containerd", false, false, false),
                    rt("crio", false, false, false),
                    rt("kubelet", false, false, false),
                    rt("cni", false, false, true),
                ],
                rhcos: RhcosStatus {
                    is_rhcos: false,
                    detail: "not rhcos".into(),
                },
                state: FapolicydState {
                    running: true,
                    enabled: true,
                },
                conf: EffectiveConf {
                    watch_fs: vec!["ext4".into(), "xfs".into()],
                    allow_filesystem_mark: false,
                    readable: true,
                },
                bins: RuntimeBinaries {
                    crun: false,
                    runc: false,
                    conmon: false,
                },
                coverage: CrunRuleCoverage {
                    covered: true,
                    detail: "covered".into(),
                },
                deep_trust: DeepTrust {
                    crun_trusted: None,
                    runc_trusted: None,
                    conmon_trusted: None,
                },
                deep_denials: DeepDenials {
                    total: 0,
                    runtime_denials: 0,
                },
            }
        }

        /// Mark a runtime row active by name (also sets present).
        fn activate(mut self, name: &str) -> Self {
            for r in &mut self.runtimes {
                if r.name == name {
                    r.present = true;
                    r.active = true;
                }
            }
            self
        }
    }

    impl ContainerProbe for FakeProbe {
        fn podman_rootful(&self) -> RuntimeStatus {
            self.runtimes[0].clone()
        }
        fn podman_rootless(&self) -> RuntimeStatus {
            self.runtimes[1].clone()
        }
        fn docker(&self) -> RuntimeStatus {
            self.runtimes[2].clone()
        }
        fn containerd(&self) -> RuntimeStatus {
            self.runtimes[3].clone()
        }
        fn crio(&self) -> RuntimeStatus {
            self.runtimes[4].clone()
        }
        fn kubelet(&self) -> RuntimeStatus {
            self.runtimes[5].clone()
        }
        fn cni_configured(&self) -> RuntimeStatus {
            self.runtimes[6].clone()
        }
        fn rhcos_status(&self) -> RhcosStatus {
            self.rhcos.clone()
        }
        fn fapolicyd_state(&self) -> FapolicydState {
            self.state.clone()
        }
        fn effective_conf(&self, _rules_dir: &Path) -> EffectiveConf {
            self.conf.clone()
        }
        fn runtime_binaries(&self) -> RuntimeBinaries {
            self.bins.clone()
        }
        fn crun_rule_coverage(&self, _rules_dir: &Path) -> CrunRuleCoverage {
            self.coverage.clone()
        }
        fn deep_trust(&self) -> DeepTrust {
            self.deep_trust.clone()
        }
        fn deep_denials(&self) -> DeepDenials {
            self.deep_denials.clone()
        }
    }

    fn classify_fake(p: &FakeProbe, deep: bool) -> Report {
        classify(p, Path::new("/etc/fapolicyd/rules.d"), deep)
    }

    // ---- Detection ----

    #[test]
    fn detect_lists_all_seven_runtimes() {
        let p = FakeProbe::new();
        let runtimes = detect_runtimes(&p);
        assert_eq!(runtimes.len(), 7);
        assert!(runtimes.iter().any(|r| r.name == "podman-rootful"));
        assert!(runtimes.iter().any(|r| r.name == "cni"));
    }

    #[test]
    fn cni_active_does_not_count_as_runtime_active() {
        // CNI is informational: even "active", it must not trigger the WARN baseline.
        let mut p = FakeProbe::new();
        for r in &mut p.runtimes {
            if r.name == "cni" {
                r.active = true;
                r.present = true;
            }
        }
        let report = classify_fake(&p, false);
        assert!(
            report.findings.is_empty(),
            "CNI active alone must not produce a finding"
        );
        assert_eq!(exit_code(&report), 0);
    }

    // ---- Risk verdicts ----

    #[test]
    fn tmpfs_in_watch_fs_with_active_runtime_is_high() {
        let mut p = FakeProbe::new().activate("podman-rootful");
        p.conf.watch_fs = vec!["ext4".into(), "tmpfs".into()];
        let report = classify_fake(&p, false);
        let f = report
            .findings
            .iter()
            .find(|f| f.code == "tmpfs-watch-fs")
            .expect("tmpfs HIGH finding present");
        assert_eq!(f.severity, Severity::High);
        assert!(f.detail.contains("RHEL-114562"));
        // The dropped placeholder must NOT appear.
        assert!(!f.detail.contains("paid-product-url"));
        assert!(!f.detail.contains('<'));
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn allow_filesystem_mark_with_active_runtime_is_high() {
        let mut p = FakeProbe::new().activate("docker");
        p.conf.allow_filesystem_mark = true;
        let report = classify_fake(&p, false);
        let f = report
            .findings
            .iter()
            .find(|f| f.code == "allow-filesystem-mark")
            .expect("mark HIGH finding present");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn high_triggers_without_active_runtime_produce_no_finding() {
        // Negative control: tmpfs + mark set but NO runtime active -> no risk.
        let mut p = FakeProbe::new();
        p.conf.watch_fs = vec!["tmpfs".into()];
        p.conf.allow_filesystem_mark = true;
        let report = classify_fake(&p, false);
        assert!(report.findings.is_empty());
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn active_runtime_no_high_trigger_is_warn_baseline() {
        let p = FakeProbe::new().activate("podman-rootful");
        let report = classify_fake(&p, false);
        let f = report
            .findings
            .iter()
            .find(|f| f.code == "namespace-limitation")
            .expect("baseline WARN present");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("RHEL-114562"));
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn crun_present_without_allow_rule_is_info() {
        let mut p = FakeProbe::new();
        p.bins.crun = true;
        p.coverage = CrunRuleCoverage {
            covered: false,
            detail: "no allow rule found".into(),
        };
        let report = classify_fake(&p, false);
        let f = report
            .findings
            .iter()
            .find(|f| f.code == "crun-no-allow-rule")
            .expect("crun INFO present");
        assert_eq!(f.severity, Severity::Info);
        // INFO alone is non-escalating.
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn crun_present_with_allow_rule_produces_no_info() {
        let mut p = FakeProbe::new();
        p.bins.crun = true; // coverage.covered defaults to true
        let report = classify_fake(&p, false);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == "crun-no-allow-rule")
        );
    }

    #[test]
    fn fapolicyd_inactive_downgrades_high_to_info() {
        let mut p = FakeProbe::new().activate("podman-rootful");
        p.conf.watch_fs = vec!["tmpfs".into()];
        p.state.running = false;
        let report = classify_fake(&p, false);
        // The tmpfs finding still exists but is downgraded to Info.
        let f = report
            .findings
            .iter()
            .find(|f| f.code == "tmpfs-watch-fs")
            .expect("finding still present");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.detail.contains("not running"));
        assert_eq!(exit_code(&report), 0);
    }

    // ---- Exit-code precedence ----

    #[test]
    fn rhcos_forces_exit_3_even_with_high_finding() {
        let mut p = FakeProbe::new().activate("crio");
        p.conf.watch_fs = vec!["tmpfs".into()]; // would be HIGH/exit 2
        p.rhcos = RhcosStatus {
            is_rhcos: true,
            detail: "rhcos detected".into(),
        };
        let report = classify_fake(&p, false);
        // The HIGH finding is still listed in the body...
        assert!(report.findings.iter().any(|f| f.severity == Severity::High));
        // ...but RHCOS wins the exit code.
        assert_eq!(exit_code(&report), 3);
    }

    #[test]
    fn exit_code_ladder_no_findings_is_zero() {
        let report = classify_fake(&FakeProbe::new(), false);
        assert_eq!(exit_code(&report), 0);
    }

    // ---- --deep evidence (evidence-only: no severity change) ----

    #[test]
    fn deep_absent_by_default() {
        let report = classify_fake(&FakeProbe::new().activate("podman-rootful"), false);
        assert!(report.deep.is_none());
    }

    #[test]
    fn deep_gathers_evidence_without_changing_severity() {
        let mut p = FakeProbe::new().activate("podman-rootful");
        // Untrusted crun + denials present under --deep.
        p.deep_trust = DeepTrust {
            crun_trusted: Some(false),
            runc_trusted: None,
            conmon_trusted: None,
        };
        p.deep_denials = DeepDenials {
            total: 12,
            runtime_denials: 5,
        };
        let cheap = classify_fake(&p, false);
        let deep = classify_fake(&p, true);
        // Evidence is attached...
        let ev = deep.deep.as_ref().expect("deep evidence present");
        assert_eq!(ev.denials.runtime_denials, 5);
        assert_eq!(ev.trust.crun_trusted, Some(false));
        // ...but the verdict (exit code) is identical to the cheap path.
        assert_eq!(exit_code(&deep), exit_code(&cheap));
    }

    // ---- exit-code unit (synthetic WARN, independent of a real verdict path) ----

    #[test]
    fn exit_code_warn_only_is_one() {
        let report = Report {
            runtimes: vec![],
            findings: vec![Finding {
                code: "x",
                severity: Severity::Warn,
                detail: String::new(),
            }],
            rhcos: RhcosStatus {
                is_rhcos: false,
                detail: String::new(),
            },
            fapolicyd_running: true,
            deep: None,
        };
        assert_eq!(exit_code(&report), 1);
    }
}
