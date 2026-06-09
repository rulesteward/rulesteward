//! container-check result model and the `ContainerProbe` dependency-injection seam.
//!
//! Plain data only: the severity/finding/report types, the probe-input structs,
//! and the `ContainerProbe` trait. The live OS implementation lives in the
//! `probe` submodule; the pure classification logic in `checks`.

use std::path::Path;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Result model (spec section 6.1, lines 414-421)
// ---------------------------------------------------------------------------

/// Severity of a single container-check finding.
///
/// `High > Warn > Info` for exit-code escalation. RHCOS detection is handled
/// separately from severity: it forces exit 3 regardless of any findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    High,
}

/// A single container-check finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Short machine-readable code (e.g. `tmpfs-watch-fs`, `allow-filesystem-mark`).
    pub code: &'static str,
    /// Info/Warn/High verdict.
    pub severity: Severity,
    /// Human-readable detail (carries the namespace-limitation notice / evidence).
    pub detail: String,
}

/// One container runtime's detected presence.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    /// Stable runtime name (e.g. `podman-rootful`, `docker`, `cni`).
    pub name: &'static str,
    /// True if the cheap detection probe matched (binary/package/socket present).
    pub present: bool,
    /// True if the runtime is confirmed active (service running / live storage).
    pub active: bool,
    /// True if this row is informational only and never contributes to the
    /// "any runtime active" risk trigger (CNI).
    pub informational: bool,
    /// Human-readable detail describing what was observed.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Probe input types -- plain data returned by ContainerProbe methods
// ---------------------------------------------------------------------------

/// fapolicyd service state relevant to the inactive-downgrade rule.
#[derive(Debug, Clone)]
pub struct FapolicydState {
    /// `systemctl is-active fapolicyd` succeeded.
    pub running: bool,
    /// `systemctl is-enabled fapolicyd` succeeded.
    pub enabled: bool,
}

/// The `watch_fs` list and `allow_filesystem_mark` flag from fapolicyd.conf.
#[derive(Debug, Clone)]
pub struct EffectiveConf {
    /// Filesystem types in the effective `watch_fs=` list (e.g. `tmpfs`, `xfs`).
    pub watch_fs: Vec<String>,
    /// True if `allow_filesystem_mark = 1`.
    pub allow_filesystem_mark: bool,
    /// False if fapolicyd.conf could not be read (probe degraded gracefully).
    pub readable: bool,
}

/// Presence of the container-runtime helper binaries under /usr/bin.
#[derive(Debug, Clone)]
pub struct RuntimeBinaries {
    pub crun: bool,
    pub runc: bool,
    pub conmon: bool,
}

/// Whether a rules.d allow rule covers `exe=/usr/bin/crun` (or runc).
#[derive(Debug, Clone)]
pub struct CrunRuleCoverage {
    /// True if some `allow ... exe=/usr/bin/crun` (or runc) rule was found.
    pub covered: bool,
    /// Human-readable detail (which rule, or that none was found).
    pub detail: String,
}

/// RHCOS / `OpenShift` node detection.
#[derive(Debug, Clone)]
pub struct RhcosStatus {
    /// True if the host is Red Hat `CoreOS` / an `OpenShift` node.
    pub is_rhcos: bool,
    /// Human-readable detail describing how it was (not) detected.
    pub detail: String,
}

// --- --deep evidence (only gathered when --deep is set) ---

/// Trust-DB coverage of the runtime binaries (from `fapolicyd-cli --dump-db`).
///
/// `None` for a binary means "not present on the host, so trust is N/A".
// The shared `_trusted` suffix is intentional: each field is the trust state of
// a specific runtime binary and serializes to a distinct JSON key (crunTrusted,
// runcTrusted, conmonTrusted), which reads better than a nested map.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize)]
pub struct DeepTrust {
    pub crun_trusted: Option<bool>,
    pub runc_trusted: Option<bool>,
    pub conmon_trusted: Option<bool>,
}

/// Recent FANOTIFY denial evidence (from `ausearch -m FANOTIFY`).
#[derive(Debug, Clone, Serialize)]
pub struct DeepDenials {
    /// Total FANOTIFY DENY records seen in the window.
    pub total: u64,
    /// Of those, how many name a container-runtime binary as the subject.
    pub runtime_denials: u64,
}

// ---------------------------------------------------------------------------
// ContainerProbe trait -- dependency-injection seam
// ---------------------------------------------------------------------------

/// Trait for all environment I/O used by container-check.
///
/// Each method returns plain data. The classifier in [`super::checks`] contains
/// ONLY logic over that data, making it fully unit-testable with a `FakeProbe`
/// and no real OS access. The real [`LiveContainerProbe`](super::probe::LiveContainerProbe)
/// shells out and is excluded from the mutation gate by name.
///
/// Detection methods do not return `Result`: a failed/absent probe is reported
/// as `present=false`/`active=false`, which is the correct classification input
/// (a host without `systemctl` simply has no detectable services). Readability
/// of fapolicyd.conf is surfaced via [`EffectiveConf::readable`] instead.
pub trait ContainerProbe {
    fn podman_rootful(&self) -> RuntimeStatus;
    fn podman_rootless(&self) -> RuntimeStatus;
    fn docker(&self) -> RuntimeStatus;
    fn containerd(&self) -> RuntimeStatus;
    fn crio(&self) -> RuntimeStatus;
    fn kubelet(&self) -> RuntimeStatus;
    fn cni_configured(&self) -> RuntimeStatus;
    fn rhcos_status(&self) -> RhcosStatus;

    /// fapolicyd service state (for the inactive-downgrade rule).
    fn fapolicyd_state(&self) -> FapolicydState;
    /// `watch_fs` + `allow_filesystem_mark` from fapolicyd.conf.
    fn effective_conf(&self, rules_dir: &Path) -> EffectiveConf;
    /// Presence of /usr/bin/{crun,runc,conmon}.
    fn runtime_binaries(&self) -> RuntimeBinaries;
    /// Whether an allow rule covers exe=/usr/bin/crun (or runc).
    fn crun_rule_coverage(&self, rules_dir: &Path) -> CrunRuleCoverage;

    /// --deep: trust-DB coverage of the runtime binaries.
    fn deep_trust(&self) -> DeepTrust;
    /// --deep: recent FANOTIFY denial counts.
    fn deep_denials(&self) -> DeepDenials;
}
