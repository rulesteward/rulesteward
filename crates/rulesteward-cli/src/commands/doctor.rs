//! `rulesteward fapolicyd doctor` -- composite deployment health check.
//!
//! # Architecture
//!
//! All environment I/O (systemctl, uname, auditctl, fapolicyd-cli, rpm,
//! statvfs, config-file reads) is routed through the [`SystemProbe`] trait.
//! The 13 check functions contain ONLY classification logic over plain data, so
//! they are fully unit-testable with [`FakeProbe`] without touching the real OS.
//! The real [`LiveProbe`] shells out and is NOT unit-tested directly -- it is
//! exercised by the live VM smoke test and the graceful-degradation e2e test.
//!
//! Dependency injection via a trait object (`&dyn SystemProbe`) keeps `run_checks`
//! decoupled from the OS: swap in `FakeProbe` in tests, `LiveProbe` in production.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Stdio;

use serde::Serialize;

use crate::cli::{DoctorArgs, HumanJsonFormat};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_WARNINGS};
use crate::output::json::render_envelope;

/// Schema version for the `doctor-report` kind.
/// Bumps only on a breaking change (field removal, rename, retype).
const DOCTOR_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Check result model (spec §6.1 + locked design decision #2)
// ---------------------------------------------------------------------------

/// The status of a single doctor check.
///
/// `Fail > Warn > Ok` for exit-code escalation.
/// `Skip` and `Unknown` are informational only and never escalate the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
    Unknown,
}

/// The result of a single doctor check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Short machine-readable name for this check.
    pub name: &'static str,
    /// Pass/warn/fail/skip/unknown verdict.
    pub status: CheckStatus,
    /// Human-readable detail describing what was observed.
    pub detail: String,
    /// Remediation hint shown for Warn / Fail; None for Ok / Skip / Unknown.
    pub remediation: Option<String>,
}

// ---------------------------------------------------------------------------
// Probe input types -- plain data structs returned by SystemProbe methods
// ---------------------------------------------------------------------------

/// Fapolicyd service state from systemctl.
#[derive(Debug, Clone)]
pub struct ServiceState {
    pub running: bool,
    pub enabled: bool,
    /// If Some, the mode string (e.g. "enforcing" or "permissive").
    pub mode: Option<String>,
}

/// Outcome of running a command (fapolicyd-cli --check-*).
#[derive(Debug, Clone)]
pub struct CommandOutcome {
    pub success: bool,
    pub message: String,
}

/// Lint result counts from `rulesteward fapolicyd lint`.
#[derive(Debug, Clone)]
pub struct LintCounts {
    pub errors: u32,
    pub warnings: u32,
}

/// Free-space information for a path.
#[derive(Debug, Clone)]
pub struct FsSpace {
    /// Bytes available to unprivileged users.
    pub bytes_free: u64,
}

/// Denial statistics for the recent-denial-rate check.
#[derive(Debug, Clone)]
pub struct DenialStats {
    pub count_24h: u64,
    pub count_7d: u64,
    /// Top denied subject+object pairs (subject path, object path, count).
    pub top_denied: Vec<(String, String, u64)>,
}

/// Contents of fapolicyd.conf relevant to misconfiguration checks.
#[derive(Debug, Clone)]
pub struct FapolicydConf {
    /// True if `permissive=1` is set.
    pub permissive_set: bool,
    /// True if any rule file contains `sha256hash=`.
    pub deprecated_sha256hash: bool,
    /// True if both `/etc/fapolicyd/fapolicyd.rules` AND `rules.d/` exist.
    pub both_layouts_present: bool,
}

// ---------------------------------------------------------------------------
// SystemProbe trait -- dependency-injection seam (design decision #1)
// ---------------------------------------------------------------------------

/// Trait for all environment I/O used by the doctor checks.
///
/// Each method returns plain data (structs / Result). The 13 check functions
/// contain ONLY classification logic over that data, making them testable with
/// [`FakeProbe`] without any real OS access. The real [`LiveProbe`] shells out.
pub trait SystemProbe {
    /// Query the fapolicyd systemd service status.
    fn service_state(&self) -> Result<ServiceState, String>;

    /// Return the kernel release string (from `uname -r`).
    fn kernel_release(&self) -> Result<String, String>;

    /// Return the count of loaded audit syscall rules.
    fn audit_rule_count(&self) -> Result<u32, String>;

    /// Run `fapolicyd-cli --check-config`.
    fn check_config(&self) -> Result<CommandOutcome, String>;

    /// Run `rulesteward fapolicyd lint` on the given rules dir.
    fn lint_rules(&self, rules_dir: &Path) -> Result<LintCounts, String>;

    /// Run `fapolicyd-cli --check-trustdb`.
    fn check_trustdb(&self) -> Result<CommandOutcome, String>;

    /// Run `fapolicyd-cli --check-watch_fs`.
    fn check_watch_fs(&self) -> Result<CommandOutcome, String>;

    /// Run `fapolicyd-cli --check-ignore_mounts` (v1.4+); return None if not
    /// supported by the installed version.
    fn check_ignore_mounts(&self) -> Result<Option<CommandOutcome>, String>;

    /// Check whether the `rpm-plugin-fapolicyd` RPM package is installed.
    fn rpm_plugin_installed(&self) -> Result<bool, String>;

    /// Return free bytes in /var/lib/fapolicyd/.
    fn fapolicyd_db_space(&self) -> Result<FsSpace, String>;

    /// Return denial statistics from the audit log.
    fn denial_stats(&self) -> Result<DenialStats, String>;

    /// Parse /etc/fapolicyd/fapolicyd.conf and the rules dir for misconfiguration flags.
    fn fapolicyd_conf(&self, rules_dir: &Path) -> Result<FapolicydConf, String>;
}

// ---------------------------------------------------------------------------
// LiveProbe -- real OS access (not unit-tested; covered by e2e / VM smoke)
// ---------------------------------------------------------------------------

/// Real probe that shells out to the OS.
///
/// On hosts without fapolicyd installed, each method returns an Err string that
/// the check functions map to `CheckStatus::Unknown`, so the binary gracefully
/// degrades on a bare development host.
pub struct LiveProbe;

impl SystemProbe for LiveProbe {
    fn service_state(&self) -> Result<ServiceState, String> {
        // `systemctl is-active` returns 0 for active, non-zero otherwise.
        let active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "fapolicyd"])
            .status()
            .is_ok_and(|s| s.success());

        let enabled = std::process::Command::new("systemctl")
            .args(["is-enabled", "--quiet", "fapolicyd"])
            .status()
            .is_ok_and(|s| s.success());

        // Read mode from /etc/fapolicyd/fapolicyd.conf (permissive=1 => permissive).
        let mode = read_fapolicyd_mode();

        Ok(ServiceState {
            running: active,
            enabled,
            mode,
        })
    }

    fn kernel_release(&self) -> Result<String, String> {
        let out = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map_err(|e| format!("uname -r failed: {e}"))?;
        if !out.status.success() {
            return Err("uname -r returned non-zero".to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn audit_rule_count(&self) -> Result<u32, String> {
        // Try `auditctl -l`; count lines that look like rules.
        let out = std::process::Command::new("auditctl")
            .arg("-l")
            .output()
            .map_err(|e| format!("auditctl -l failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "auditctl -l exited non-zero: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        // Count non-empty non-header lines (rule lines start with "-a" or "-w").
        let count = text
            .lines()
            .filter(|l| l.starts_with("-a") || l.starts_with("-w") || l.starts_with("-A"))
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    fn check_config(&self) -> Result<CommandOutcome, String> {
        let out = std::process::Command::new("fapolicyd-cli")
            .arg("--check-config")
            .output()
            .map_err(|e| format!("fapolicyd-cli not found: {e}"))?;
        Ok(CommandOutcome {
            success: out.status.success(),
            message: String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_string()
                .chars()
                .take(200)
                .collect(),
        })
    }

    fn lint_rules(&self, rules_dir: &Path) -> Result<LintCounts, String> {
        // Run the current binary in lint mode (argv[0] is this process).
        let exe = std::env::current_exe().map_err(|e| format!("cannot find current exe: {e}"))?;
        let out = std::process::Command::new(&exe)
            .args([
                "fapolicyd",
                "lint",
                "--format",
                "json",
                rules_dir.to_str().unwrap_or("/etc/fapolicyd/rules.d"),
            ])
            .output()
            .map_err(|e| format!("lint subprocess failed: {e}"))?;
        // Parse the JSON envelope to count errors and warnings.
        let text = String::from_utf8_lossy(&out.stdout);
        parse_lint_counts(&text)
    }

    fn check_trustdb(&self) -> Result<CommandOutcome, String> {
        let out = std::process::Command::new("fapolicyd-cli")
            .arg("--check-trustdb")
            .output()
            .map_err(|e| format!("fapolicyd-cli not found: {e}"))?;
        Ok(CommandOutcome {
            success: out.status.success(),
            message: String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_string()
                .chars()
                .take(200)
                .collect(),
        })
    }

    fn check_watch_fs(&self) -> Result<CommandOutcome, String> {
        let out = std::process::Command::new("fapolicyd-cli")
            .arg("--check-watch_fs")
            .output()
            .map_err(|e| format!("fapolicyd-cli not found: {e}"))?;
        Ok(CommandOutcome {
            success: out.status.success(),
            message: String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_string()
                .chars()
                .take(200)
                .collect(),
        })
    }

    fn check_ignore_mounts(&self) -> Result<Option<CommandOutcome>, String> {
        let out = std::process::Command::new("fapolicyd-cli")
            .arg("--check-ignore_mounts")
            .output()
            .map_err(|e| format!("fapolicyd-cli not found: {e}"))?;
        // If the flag is unrecognized (pre-1.4), fapolicyd-cli exits non-zero
        // with "invalid option" in stderr -- treat as Skip.
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("invalid option")
            || stderr.contains("unrecognized")
            || stderr.contains("unknown option")
        {
            return Ok(None); // Skip: pre-v1.4 fapolicyd
        }
        Ok(Some(CommandOutcome {
            success: out.status.success(),
            message: String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_string()
                .chars()
                .take(200)
                .collect(),
        }))
    }

    fn rpm_plugin_installed(&self) -> Result<bool, String> {
        // `rpm -q` prints the package NVR to stdout on a match; null it so the
        // probe never pollutes the command's own stdout (which carries the JSON
        // envelope). We only care about the exit status here.
        let status = std::process::Command::new("rpm")
            .args(["-q", "rpm-plugin-fapolicyd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("rpm not found: {e}"))?;
        Ok(status.success())
    }

    fn fapolicyd_db_space(&self) -> Result<FsSpace, String> {
        // Use statvfs via the `nix` crate path -- but we avoid extra deps.
        // Instead, parse `df -B1 /var/lib/fapolicyd/` output.
        let out = std::process::Command::new("df")
            .args(["-B1", "--output=avail", "/var/lib/fapolicyd/"])
            .output()
            .map_err(|e| format!("df failed: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Output is header + value line, e.g.: "    Avail\n123456789\n"
        let bytes_free = text
            .lines()
            .find_map(|l| l.trim().parse::<u64>().ok())
            .ok_or_else(|| format!("could not parse df output: {text:?}"))?;
        Ok(FsSpace { bytes_free })
    }

    fn denial_stats(&self) -> Result<DenialStats, String> {
        // Run ausearch for each window separately so the counts are distinct.
        // ausearch exits 1 (no results) or fails if the binary is absent;
        // empty stdout with non-zero exit is treated as 0 denials, not an error.
        let run_ausearch = |start_arg: &str| -> Result<String, String> {
            let out = std::process::Command::new("ausearch")
                .args(["-m", "FANOTIFY", "--raw", "--start", start_arg])
                .output()
                .map_err(|e| format!("ausearch not found: {e}"))?;
            if !out.status.success() && out.stdout.is_empty() {
                return Ok(String::new()); // no results -- treat as empty
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };

        let raw_24h = run_ausearch("today")?;
        let raw_7d = run_ausearch("week-ago")?;

        let (count_24h, _) = parse_fanotify_denials(&raw_24h);
        let (count_7d, mut top_denied) = parse_fanotify_denials(&raw_7d);
        top_denied.truncate(10);

        Ok(DenialStats {
            count_24h,
            count_7d,
            top_denied,
        })
    }

    fn fapolicyd_conf(&self, rules_dir: &Path) -> Result<FapolicydConf, String> {
        let conf_path = Path::new("/etc/fapolicyd/fapolicyd.conf");
        let conf_text = std::fs::read_to_string(conf_path)
            .map_err(|e| format!("cannot read {}: {e}", conf_path.display()))?;
        let permissive_set = conf_text
            .lines()
            .any(|l| l.trim() == "permissive=1" || l.trim().starts_with("permissive = 1"));

        // Check for sha256hash= in any rules file.
        let deprecated_sha256hash = check_sha256hash_in_dir(rules_dir);

        // Check for both legacy fapolicyd.rules and rules.d/ at the parent.
        let legacy = rules_dir
            .parent()
            .map(|p| p.join("fapolicyd.rules"))
            .is_some_and(|p| p.exists());
        let modern = rules_dir.exists();
        let both_layouts_present = legacy && modern;

        Ok(FapolicydConf {
            permissive_set,
            deprecated_sha256hash,
            both_layouts_present,
        })
    }
}

// ---------------------------------------------------------------------------
// LiveProbe helpers
// ---------------------------------------------------------------------------

/// Read mode from /etc/fapolicyd/fapolicyd.conf.
/// Returns Some("enforcing") or Some("permissive") or None.
fn read_fapolicyd_mode() -> Option<String> {
    read_fapolicyd_mode_from(Path::new("/etc/fapolicyd/fapolicyd.conf"))
}

/// Inner implementation of `read_fapolicyd_mode` that accepts an explicit path
/// so that unit tests can supply a temp file without touching the real system.
///
/// Returns `Some("permissive")` if `permissive=1` (or `permissive = 1`) is set,
/// `Some("enforcing")` if the file is readable but the key is absent or set to
/// anything other than `1`, and `None` if the file cannot be read.
fn read_fapolicyd_mode_from(conf_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(conf_path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("permissive") {
            let val = trimmed.split('=').nth(1)?.trim();
            if val == "1" {
                return Some("permissive".to_string());
            }
        }
    }
    Some("enforcing".to_string())
}

/// Scan all `.rules` files in `rules_dir` for deprecated `sha256hash=`.
///
/// Returns `true` if any `.rules` file in `rules_dir` contains the literal
/// string `sha256hash=`; `false` if the dir cannot be read or no file matches.
fn check_sha256hash_in_dir(rules_dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(rules_dir) else {
        return false;
    };
    for entry in rd.filter_map(Result::ok) {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("rules") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p)
            && text.contains("sha256hash=")
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// FANOTIFY denial parser (pure -- testable without a real audit log)
// ---------------------------------------------------------------------------

/// Parse raw `ausearch -m FANOTIFY --raw` output and extract the total denial
/// count plus the top denied subject→object pairs sorted descending by count.
///
/// Each `type=FANOTIFY` record group that contains both a FANOTIFY line with
/// `resp=2` (`FAN_DENY`) and a SYSCALL `exe=` field contributes one hit to the
/// `(subject_exe, object_path)` tally.  When a group has `resp=2` but no
/// `exe=`, the subject is reported as `"(unknown)"`.  Groups with `resp=1`
/// (`FAN_ALLOW`) are ignored.
///
/// The function is era-agnostic: it uses the SYSCALL `exe=` field (present in
/// both era1 and era2 ausearch blocks) for the subject and the PATH `name=`
/// field for the object.  Groups that contain only a bare FANOTIFY line (no
/// SYSCALL companion) are still counted when `resp=2`.
///
/// Returns `(total_denials, top_pairs)` where `top_pairs` is sorted by count
/// descending (capped at the first 10 by the caller).
#[must_use]
pub fn parse_fanotify_denials(raw: &str) -> (u64, Vec<(String, String, u64)>) {
    use std::collections::HashMap;

    let mut total: u64 = 0;
    let mut tally: HashMap<(String, String), u64> = HashMap::new();

    // ausearch separates events with "----" lines; split on those.
    // A bare FANOTIFY-only input with no separator is treated as one block.
    let blocks: Vec<&str> = raw
        .split("\n----\n")
        .flat_map(|chunk| chunk.split("----\n"))
        .collect();

    for block in blocks {
        let mut fanotify_resp: Option<u32> = None;
        let mut exe: Option<&str> = None;
        let mut obj_path: Option<&str> = None;

        for line in block.lines() {
            let t = line.trim();
            if t.is_empty() || t == "----" {
                continue;
            }
            if t.contains("type=FANOTIFY") {
                // Extract resp= field (unquoted decimal).
                if let Some(resp_val) = extract_kv(t, "resp") {
                    fanotify_resp = resp_val.parse::<u32>().ok();
                }
            } else if t.contains("type=SYSCALL") {
                exe = extract_kv(t, "exe");
            } else if t.contains("type=PATH") {
                obj_path = extract_kv(t, "name");
            }
        }

        // Only count DENY records (resp == 2).
        if fanotify_resp == Some(2) {
            total += 1;
            let subj = exe.unwrap_or("(unknown)").to_string();
            let obj = obj_path.unwrap_or("(unknown)").to_string();
            *tally.entry((subj, obj)).or_insert(0) += 1;
        }
    }

    let mut pairs: Vec<(String, String, u64)> =
        tally.into_iter().map(|((s, o), c)| (s, o, c)).collect();
    // Sort descending by count; stable tie-break by (subj, obj) for determinism.
    pairs.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    (total, pairs)
}

/// Minimal key=value extractor for audit record lines (handles quoted and
/// unquoted values; word-boundary match so `pid=` doesn't match inside
/// `ppid=`).  Mirrors the logic in `rulesteward_fapolicyd::fanotify`.
fn extract_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let (abs_pos, _) = line.match_indices(needle.as_str()).find(|&(pos, _)| {
        pos == 0
            || line
                .as_bytes()
                .get(pos - 1)
                .is_some_and(u8::is_ascii_whitespace)
    })?;
    let after = &line[abs_pos + needle.len()..];
    if let Some(inner) = after.strip_prefix('"') {
        let end = inner.find('"')?;
        return Some(&inner[..end]);
    }
    let end = after.find(char::is_whitespace).unwrap_or(after.len());
    Some(&after[..end])
}

/// Parse the JSON lint output and count severity=Error / severity=Warning diagnostics.
fn parse_lint_counts(json_text: &str) -> Result<LintCounts, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_text).map_err(|e| format!("lint JSON parse error: {e}"))?;
    let diags = v
        .get("diagnostics")
        .and_then(|d| d.as_array())
        .ok_or("lint JSON missing 'diagnostics' array")?;
    let mut errors = 0u32;
    let mut warnings = 0u32;
    for d in diags {
        match d.get("severity").and_then(|s| s.as_str()) {
            Some("Error" | "Fatal") => errors += 1,
            Some("Warning") => warnings += 1,
            _ => {}
        }
    }
    Ok(LintCounts { errors, warnings })
}

// ---------------------------------------------------------------------------
// The 13 check functions (pure classification over probe data)
// ---------------------------------------------------------------------------

/// Check 1: fapolicyd service status.
///
/// Fail if not running; Warn if permissive; Ok if running + enforcing.
fn check_service(probe: &dyn SystemProbe) -> CheckResult {
    match probe.service_state() {
        Err(e) => CheckResult {
            name: "service-status",
            status: CheckStatus::Unknown,
            detail: format!("could not query service state: {e}"),
            remediation: None,
        },
        Ok(state) => {
            if !state.running {
                return CheckResult {
                    name: "service-status",
                    status: CheckStatus::Fail,
                    detail: "fapolicyd is not running".to_string(),
                    remediation: Some("systemctl start fapolicyd".to_string()),
                };
            }
            let mode = state.mode.as_deref().unwrap_or("enforcing");
            if mode == "permissive" {
                CheckResult {
                    name: "service-status",
                    status: CheckStatus::Warn,
                    detail: "fapolicyd is running in permissive mode (permissive=1)".to_string(),
                    remediation: Some(
                        "Set permissive=0 in /etc/fapolicyd/fapolicyd.conf and restart the service"
                            .to_string(),
                    ),
                }
            } else {
                // Surface the ACTUAL mode string rather than hard-coding
                // "enforcing": `read_fapolicyd_mode` defaults an absent
                // permissive= key to "enforcing", but if a future probe ever
                // returns some other value we report it verbatim instead of
                // mislabeling it as enforcing.
                CheckResult {
                    name: "service-status",
                    status: CheckStatus::Ok,
                    detail: format!(
                        "fapolicyd is running, enabled={}, mode={mode}",
                        state.enabled
                    ),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 2: kernel version (fanotify >= 4.20; full FANOTIFY field set >= 6.3).
///
/// Fail < 4.20; Warn >= 4.20 but < 6.3; Ok >= 6.3.
fn check_kernel(probe: &dyn SystemProbe) -> CheckResult {
    match probe.kernel_release() {
        Err(e) => CheckResult {
            name: "kernel-version",
            status: CheckStatus::Unknown,
            detail: format!("could not query kernel release: {e}"),
            remediation: None,
        },
        Ok(release) => {
            match parse_kernel_version(&release) {
                None => CheckResult {
                    name: "kernel-version",
                    status: CheckStatus::Unknown,
                    detail: format!("could not parse kernel version from: {release:?}"),
                    remediation: None,
                },
                Some((major, minor)) => {
                    // Compare as (major, minor) tuples.
                    if (major, minor) < (4, 20) {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Fail,
                            detail: format!(
                                "kernel {release} is below 4.20 (fanotify requires >= 4.20)"
                            ),
                            remediation: Some("Upgrade to kernel >= 4.20".to_string()),
                        }
                    } else if (major, minor) < (6, 3) {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Warn,
                            detail: format!(
                                "kernel {release} supports fanotify but lacks the full \
                                 FANOTIFY field set (requires >= 6.3)"
                            ),
                            remediation: Some(
                                "Upgrade to kernel >= 6.3 for the full FANOTIFY field set"
                                    .to_string(),
                            ),
                        }
                    } else {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Ok,
                            detail: format!(
                                "kernel {release} supports fanotify and the full FANOTIFY field set"
                            ),
                            remediation: None,
                        }
                    }
                }
            }
        }
    }
}

/// Parse "major.minor[.patch...]" from a kernel release string.
///
/// Returns `Some((major, minor))` on success, `None` if unparseable.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    // Kernel release strings look like "6.3.0-0.rc1.20230326git.el9" -- split on
    // the first non-numeric/non-dot char, then take major.minor.
    let version_part = release
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()?;
    let mut parts = version_part.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Check 3: at least one audit syscall rule loaded (#78).
///
/// Fail if count == 0; Ok otherwise.
fn check_audit_rules(probe: &dyn SystemProbe) -> CheckResult {
    match probe.audit_rule_count() {
        Err(e) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Unknown,
            detail: format!("could not query auditctl rules: {e}"),
            remediation: None,
        },
        Ok(0) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Fail,
            detail: "no audit syscall rules loaded; fapolicyd FANOTIFY events may be invisible"
                .to_string(),
            remediation: Some(
                "auditctl -a always,exit -F arch=b64 -S all -k fapolicyd".to_string(),
            ),
        },
        Ok(count) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Ok,
            detail: format!("{count} audit rule(s) loaded"),
            remediation: None,
        },
    }
}

/// Check 4: `fapolicyd-cli --check-config`.
fn check_config_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_config() {
        Err(e) => CheckResult {
            name: "config-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-config: {e}"),
            remediation: None,
        },
        Ok(outcome) => {
            if outcome.success {
                CheckResult {
                    name: "config-check",
                    status: CheckStatus::Ok,
                    detail: if outcome.message.is_empty() {
                        "fapolicyd-cli --check-config passed".to_string()
                    } else {
                        outcome.message.clone()
                    },
                    remediation: None,
                }
            } else {
                CheckResult {
                    name: "config-check",
                    status: CheckStatus::Fail,
                    detail: format!("fapolicyd-cli --check-config failed: {}", outcome.message),
                    remediation: Some(
                        "Review /etc/fapolicyd/fapolicyd.conf for syntax errors".to_string(),
                    ),
                }
            }
        }
    }
}

/// Check 5: `rulesteward fapolicyd lint /etc/fapolicyd/rules.d/`.
fn check_lint(probe: &dyn SystemProbe, rules_dir: &Path) -> CheckResult {
    match probe.lint_rules(rules_dir) {
        Err(e) => CheckResult {
            name: "rules-lint",
            status: CheckStatus::Unknown,
            detail: format!("lint probe failed: {e}"),
            remediation: None,
        },
        Ok(counts) => {
            if counts.errors > 0 {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Fail,
                    detail: format!(
                        "lint found {} error(s) and {} warning(s) in {}",
                        counts.errors,
                        counts.warnings,
                        rules_dir.display()
                    ),
                    remediation: Some(format!(
                        "Run `rulesteward fapolicyd lint {}` to see full details",
                        rules_dir.display()
                    )),
                }
            } else if counts.warnings > 0 {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Warn,
                    detail: format!(
                        "lint found {} warning(s) in {}",
                        counts.warnings,
                        rules_dir.display()
                    ),
                    remediation: Some(format!(
                        "Run `rulesteward fapolicyd lint {}` for details",
                        rules_dir.display()
                    )),
                }
            } else {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Ok,
                    detail: format!("no lint issues in {}", rules_dir.display()),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 6: `fapolicyd-cli --check-trustdb`.
fn check_trustdb_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_trustdb() {
        Err(e) => CheckResult {
            name: "trustdb-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-trustdb: {e}"),
            remediation: None,
        },
        Ok(outcome) => cmd_outcome_to_result("trustdb-check", &outcome, "trust DB is consistent"),
    }
}

/// Check 7: `fapolicyd-cli --check-watch_fs`.
fn check_watch_fs_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_watch_fs() {
        Err(e) => CheckResult {
            name: "watch-fs-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-watch_fs: {e}"),
            remediation: None,
        },
        Ok(outcome) => cmd_outcome_to_result(
            "watch-fs-check",
            &outcome,
            "watch_fs configuration is consistent",
        ),
    }
}

/// Check 8: `fapolicyd-cli --check-ignore_mounts` (v1.4+ only).
///
/// Skip with note if the installed fapolicyd predates 1.4.
fn check_ignore_mounts_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_ignore_mounts() {
        Err(e) => CheckResult {
            name: "ignore-mounts-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-ignore_mounts: {e}"),
            remediation: None,
        },
        Ok(None) => CheckResult {
            name: "ignore-mounts-check",
            status: CheckStatus::Skip,
            detail:
                "--check-ignore_mounts not supported by this fapolicyd version (requires >= 1.4)"
                    .to_string(),
            remediation: None,
        },
        Ok(Some(outcome)) => cmd_outcome_to_result(
            "ignore-mounts-check",
            &outcome,
            "ignore_mounts configuration is consistent",
        ),
    }
}

/// Check 9: container-check (stub -- Skip with note per design decision #4).
fn check_container(_probe: &dyn SystemProbe) -> CheckResult {
    // Design decision #4: container-check subcommand is not yet implemented.
    // This check emits Skip so it appears in the report without implying
    // the deployment is unhealthy.
    CheckResult {
        name: "container-check",
        status: CheckStatus::Skip,
        detail: "container-check not yet implemented (tracked separately)".to_string(),
        remediation: None,
    }
}

/// Check 10: `rpm-plugin-fapolicyd` installed.
///
/// Ok if present; Warn if absent (live RPM trust-DB update path missing).
fn check_rpm_plugin(probe: &dyn SystemProbe) -> CheckResult {
    match probe.rpm_plugin_installed() {
        Err(e) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Unknown,
            detail: format!("could not query rpm-plugin-fapolicyd: {e}"),
            remediation: None,
        },
        Ok(true) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Ok,
            detail: "rpm-plugin-fapolicyd is installed".to_string(),
            remediation: None,
        },
        Ok(false) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Warn,
            detail:
                "rpm-plugin-fapolicyd is not installed; RPM trust-DB updates will not be automatic"
                    .to_string(),
            remediation: Some("dnf install rpm-plugin-fapolicyd".to_string()),
        },
    }
}

// Thresholds for the free-space check (decision #11 + spec §6.1 check 11).
// LMDB pre-allocates ~100 MiB; warn below 128 MiB, fail below 100 MiB.
const WARN_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
const FAIL_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Check 11: free space in /var/lib/fapolicyd/ (LMDB pre-allocates ~100 MiB).
fn check_disk_space(probe: &dyn SystemProbe) -> CheckResult {
    match probe.fapolicyd_db_space() {
        Err(e) => CheckResult {
            name: "disk-space",
            status: CheckStatus::Unknown,
            detail: format!("could not query /var/lib/fapolicyd/ free space: {e}"),
            remediation: None,
        },
        Ok(space) => {
            let mib = space.bytes_free / (1024 * 1024);
            if space.bytes_free < FAIL_BYTES {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Fail,
                    detail: format!(
                        "/var/lib/fapolicyd/ has only {mib} MiB free (< 100 MiB threshold)"
                    ),
                    remediation: Some(
                        "Free space on the /var/lib/fapolicyd partition; LMDB needs >= 100 MiB"
                            .to_string(),
                    ),
                }
            } else if space.bytes_free < WARN_BYTES {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Warn,
                    detail: format!(
                        "/var/lib/fapolicyd/ has {mib} MiB free (< 128 MiB warning threshold)"
                    ),
                    remediation: Some(
                        "Consider freeing space; LMDB pre-allocates ~100 MiB".to_string(),
                    ),
                }
            } else {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Ok,
                    detail: format!("/var/lib/fapolicyd/ has {mib} MiB free"),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 12: recent denial rate (24h / 7d) + top-10 denied subj/obj.
///
/// Informational: Ok (we surface counts in detail; Warn only on a very high spike).
fn check_denial_rate(probe: &dyn SystemProbe) -> CheckResult {
    match probe.denial_stats() {
        Err(e) => CheckResult {
            name: "denial-rate",
            status: CheckStatus::Unknown,
            detail: format!("could not query denial statistics: {e}"),
            remediation: None,
        },
        Ok(stats) => {
            let mut detail = format!(
                "denials: {} in past 24h, {} in past 7d",
                stats.count_24h, stats.count_7d
            );
            if !stats.top_denied.is_empty() {
                detail.push_str("; top denied: ");
                for (subj, obj, count) in stats.top_denied.iter().take(10) {
                    let _ = write!(detail, "[{subj} -> {obj} x{count}]");
                }
            }
            CheckResult {
                name: "denial-rate",
                status: CheckStatus::Ok,
                detail,
                remediation: None,
            }
        }
    }
}

/// Check 13: misconfiguration warnings.
///
/// Each condition that is true -> Warn with specific detail. All false -> Ok.
fn check_misconfig(probe: &dyn SystemProbe, rules_dir: &Path) -> CheckResult {
    match probe.fapolicyd_conf(rules_dir) {
        Err(e) => CheckResult {
            name: "misconfiguration",
            status: CheckStatus::Unknown,
            detail: format!("could not read fapolicyd configuration: {e}"),
            remediation: None,
        },
        Ok(conf) => {
            let mut issues: Vec<String> = Vec::new();
            if conf.permissive_set {
                issues.push("`permissive=1` is set in fapolicyd.conf".to_string());
            }
            if conf.deprecated_sha256hash {
                issues.push(
                    "deprecated `sha256hash=` attribute found in rules (use `filehash=` instead)"
                        .to_string(),
                );
            }
            if conf.both_layouts_present {
                issues.push(
                    "both legacy fapolicyd.rules AND rules.d/ are present (fapd-F02)".to_string(),
                );
            }
            if issues.is_empty() {
                CheckResult {
                    name: "misconfiguration",
                    status: CheckStatus::Ok,
                    detail: "no misconfiguration detected".to_string(),
                    remediation: None,
                }
            } else {
                CheckResult {
                    name: "misconfiguration",
                    status: CheckStatus::Warn,
                    detail: issues.join("; "),
                    remediation: Some(
                        "Review the listed configuration items and correct them".to_string(),
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Convert a `CommandOutcome` to a `CheckResult` for simple pass/fail checks.
fn cmd_outcome_to_result(
    name: &'static str,
    outcome: &CommandOutcome,
    ok_detail: &'static str,
) -> CheckResult {
    if outcome.success {
        CheckResult {
            name,
            status: CheckStatus::Ok,
            detail: ok_detail.to_string(),
            remediation: None,
        }
    } else {
        CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!("failed: {}", outcome.message),
            remediation: Some(format!("Investigate the {name} failure")),
        }
    }
}

// ---------------------------------------------------------------------------
// run_checks -- drives all 13 checks via &dyn SystemProbe
// ---------------------------------------------------------------------------

/// Run all 13 doctor checks, returning a Vec of results in declaration order.
pub fn run_checks(probe: &dyn SystemProbe, rules_dir: &Path) -> Vec<CheckResult> {
    vec![
        check_service(probe),
        check_kernel(probe),
        check_audit_rules(probe),
        check_config_cmd(probe),
        check_lint(probe, rules_dir),
        check_trustdb_cmd(probe),
        check_watch_fs_cmd(probe),
        check_ignore_mounts_cmd(probe),
        check_container(probe),
        check_rpm_plugin(probe),
        check_disk_space(probe),
        check_denial_rate(probe),
        check_misconfig(probe, rules_dir),
    ]
}

// ---------------------------------------------------------------------------
// Exit code computation (worst-status-wins, design decision #3)
// ---------------------------------------------------------------------------

/// Compute the overall exit code from a list of check results.
///
/// Any `Fail` -> `EXIT_ERRORS` (2); else any `Warn` -> `EXIT_WARNINGS` (1);
/// else `EXIT_CLEAN` (0). `Skip` and `Unknown` never escalate.
#[must_use]
pub fn worst_exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| r.status == CheckStatus::Fail) {
        return EXIT_ERRORS;
    }
    if results.iter().any(|r| r.status == CheckStatus::Warn) {
        return EXIT_WARNINGS;
    }
    EXIT_CLEAN
}

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

fn render_json(results: &[CheckResult]) -> String {
    let payload = DoctorPayload {
        summary: status_counts(results),
        checks: results,
    };
    render_envelope("doctor-report", DOCTOR_SCHEMA_VERSION, &payload)
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

fn render_human(results: &[CheckResult]) -> String {
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const DEFAULT_RULES_DIR: &str = "/etc/fapolicyd/rules.d/";

/// Run the `fapolicyd doctor` subcommand.
pub fn run(args: &DoctorArgs) -> anyhow::Result<i32> {
    let rules_dir = args
        .rules_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_RULES_DIR));

    let probe = LiveProbe;
    let results = run_checks(&probe, rules_dir);

    let output = match args.format {
        HumanJsonFormat::Human => render_human(&results),
        HumanJsonFormat::Json => render_json(&results),
    };

    print!("{output}");

    Ok(worst_exit_code(&results))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -------------------------------------------------------------------------
    // FakeProbe -- the test double for SystemProbe
    //
    // Fields default to Err("not configured") so individual tests need only
    // override the probe methods relevant to the check under test.
    // -------------------------------------------------------------------------

    /// Configurable fake probe for unit tests.
    ///
    /// Each field holds the value that the corresponding probe method returns.
    /// `None` means "return Err('not configured')" -- any check that hits an
    /// un-configured field becomes `CheckStatus::Unknown`.
    #[derive(Default)]
    struct FakeProbe {
        service: Option<ServiceState>,
        kernel: Option<String>,
        audit_count: Option<u32>,
        config: Option<CommandOutcome>,
        lint: Option<LintCounts>,
        trustdb: Option<CommandOutcome>,
        watch_fs: Option<CommandOutcome>,
        // Three-state on purpose: outer None = "not configured" (probe Errs);
        // Some(None) = pre-v1.4 (check_ignore_mounts returns Ok(None) -> Skip);
        // Some(Some(_)) = supported with an outcome. Mirrors the method's
        // `Result<Option<CommandOutcome>, String>` return, hence Option<Option<_>>.
        #[allow(clippy::option_option)]
        ignore_mounts: Option<Option<CommandOutcome>>,
        rpm_plugin: Option<bool>,
        fs_space: Option<FsSpace>,
        denials: Option<DenialStats>,
        conf: Option<FapolicydConf>,
    }

    impl SystemProbe for FakeProbe {
        fn service_state(&self) -> Result<ServiceState, String> {
            self.service
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn kernel_release(&self) -> Result<String, String> {
            self.kernel
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn audit_rule_count(&self) -> Result<u32, String> {
            self.audit_count.ok_or_else(|| "not configured".to_string())
        }
        fn check_config(&self) -> Result<CommandOutcome, String> {
            self.config
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn lint_rules(&self, _rules_dir: &Path) -> Result<LintCounts, String> {
            self.lint
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_trustdb(&self) -> Result<CommandOutcome, String> {
            self.trustdb
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_watch_fs(&self) -> Result<CommandOutcome, String> {
            self.watch_fs
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_ignore_mounts(&self) -> Result<Option<CommandOutcome>, String> {
            self.ignore_mounts
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn rpm_plugin_installed(&self) -> Result<bool, String> {
            self.rpm_plugin.ok_or_else(|| "not configured".to_string())
        }
        fn fapolicyd_db_space(&self) -> Result<FsSpace, String> {
            self.fs_space
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn denial_stats(&self) -> Result<DenialStats, String> {
            self.denials
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn fapolicyd_conf(&self, _rules_dir: &Path) -> Result<FapolicydConf, String> {
            self.conf
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
    }

    fn fake_path() -> PathBuf {
        PathBuf::from("/fake/rules.d")
    }

    // -------------------------------------------------------------------------
    // Check 1: service status
    // -------------------------------------------------------------------------

    #[test]
    fn check_service_not_running_is_fail() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: false,
                enabled: false,
                mode: None,
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("not running"), "{}", result.detail);
        assert!(result.remediation.is_some());
    }

    #[test]
    fn check_service_running_enforcing_is_ok() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("enforcing".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.remediation.is_none());
        // The Ok detail must report the ACTUAL mode, not a hard-coded literal.
        assert!(
            result.detail.contains("mode=enforcing"),
            "enforcing detail: {}",
            result.detail
        );
    }

    #[test]
    fn check_service_running_unknown_mode_is_reported_verbatim() {
        // A non-permissive mode string that is NOT "enforcing" must be surfaced
        // verbatim in the detail (Ok), never mislabeled as "mode=enforcing".
        // Kills a mutant that hard-codes the mode label in the Ok branch.
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("disabled".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            result.detail.contains("mode=disabled"),
            "detail must report the real mode verbatim, got: {}",
            result.detail
        );
        assert!(
            !result.detail.contains("mode=enforcing"),
            "detail must NOT falsely claim enforcing for an arbitrary mode: {}",
            result.detail
        );
    }

    #[test]
    fn check_service_permissive_is_warn() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("permissive".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.remediation.is_some());
    }

    #[test]
    fn check_service_probe_error_is_unknown() {
        let probe = FakeProbe::default(); // no service configured
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
        assert!(result.remediation.is_none());
    }

    // -------------------------------------------------------------------------
    // Check 2: kernel version
    // -------------------------------------------------------------------------

    #[test]
    fn check_kernel_below_4_20_is_fail() {
        let probe = FakeProbe {
            kernel: Some("4.18.0-513.el8.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("4.20"), "{}", result.detail);
    }

    #[test]
    fn check_kernel_4_20_to_6_2_is_warn() {
        let probe = FakeProbe {
            kernel: Some("5.14.0-427.el9.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(result.detail.contains("6.3"), "{}", result.detail);
    }

    #[test]
    fn check_kernel_6_3_plus_is_ok() {
        let probe = FakeProbe {
            kernel: Some("6.3.0-0.rc1.el10.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Ok, "{}", result.detail);
    }

    #[test]
    fn check_kernel_exact_4_20_is_warn_not_fail() {
        // 4.20 meets the fanotify floor but is below 6.3 -> Warn, not Fail.
        let probe = FakeProbe {
            kernel: Some("4.20.0".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
    }

    #[test]
    fn check_kernel_probe_error_is_unknown() {
        let probe = FakeProbe::default();
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
    }

    // -------------------------------------------------------------------------
    // Check 3: audit syscall rules
    // -------------------------------------------------------------------------

    #[test]
    fn check_audit_rules_zero_is_fail_with_remediation() {
        let probe = FakeProbe {
            audit_count: Some(0),
            ..Default::default()
        };
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .remediation
                .as_deref()
                .unwrap_or("")
                .contains("auditctl"),
            "{:?}",
            result.remediation
        );
    }

    #[test]
    fn check_audit_rules_nonzero_is_ok() {
        let probe = FakeProbe {
            audit_count: Some(5),
            ..Default::default()
        };
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains('5'), "{}", result.detail);
    }

    #[test]
    fn check_audit_rules_probe_error_is_unknown() {
        let probe = FakeProbe::default();
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
    }

    // -------------------------------------------------------------------------
    // Check 4: config check
    // -------------------------------------------------------------------------

    #[test]
    fn check_config_success_is_ok() {
        let probe = FakeProbe {
            config: Some(CommandOutcome {
                success: true,
                message: "config ok".to_string(),
            }),
            ..Default::default()
        };
        let result = check_config_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    #[test]
    fn check_config_failure_is_fail() {
        let probe = FakeProbe {
            config: Some(CommandOutcome {
                success: false,
                message: "syntax error on line 5".to_string(),
            }),
            ..Default::default()
        };
        let result = check_config_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("syntax error"), "{}", result.detail);
    }

    // -------------------------------------------------------------------------
    // Check 5: lint
    // -------------------------------------------------------------------------

    #[test]
    fn check_lint_errors_is_fail() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 2,
                warnings: 1,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains('2'), "{}", result.detail);
    }

    #[test]
    fn check_lint_warnings_only_is_warn() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 0,
                warnings: 3,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
    }

    #[test]
    fn check_lint_clean_is_ok() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 0,
                warnings: 0,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Ok);
    }

    // -------------------------------------------------------------------------
    // Check 8: ignore_mounts (Skip when unsupported)
    // -------------------------------------------------------------------------

    #[test]
    fn check_ignore_mounts_skip_when_pre_v1_4() {
        let probe = FakeProbe {
            ignore_mounts: Some(None), // None = pre-v1.4 not supported
            ..Default::default()
        };
        let result = check_ignore_mounts_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Skip);
        assert!(
            result.detail.contains("1.4"),
            "detail should mention v1.4 requirement: {}",
            result.detail
        );
    }

    #[test]
    fn check_ignore_mounts_success_is_ok() {
        let probe = FakeProbe {
            ignore_mounts: Some(Some(CommandOutcome {
                success: true,
                message: String::new(),
            })),
            ..Default::default()
        };
        let result = check_ignore_mounts_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    // -------------------------------------------------------------------------
    // Check 9: container-check always Skip (design decision #4)
    // -------------------------------------------------------------------------

    #[test]
    fn check_container_is_always_skip() {
        let probe = FakeProbe::default();
        let result = check_container(&probe);
        assert_eq!(result.status, CheckStatus::Skip);
        assert!(
            result.detail.contains("not yet implemented"),
            "{}",
            result.detail
        );
    }

    // -------------------------------------------------------------------------
    // Check 10: rpm-plugin
    // -------------------------------------------------------------------------

    #[test]
    fn check_rpm_plugin_present_is_ok() {
        let probe = FakeProbe {
            rpm_plugin: Some(true),
            ..Default::default()
        };
        assert_eq!(check_rpm_plugin(&probe).status, CheckStatus::Ok);
    }

    #[test]
    fn check_rpm_plugin_absent_is_warn() {
        let probe = FakeProbe {
            rpm_plugin: Some(false),
            ..Default::default()
        };
        let result = check_rpm_plugin(&probe);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.remediation.is_some());
    }

    // -------------------------------------------------------------------------
    // Check 11: disk space
    // -------------------------------------------------------------------------

    #[test]
    fn check_disk_space_plenty_is_ok() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 512 * 1024 * 1024, // 512 MiB
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Ok);
    }

    #[test]
    fn check_disk_space_below_128_mib_is_warn() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 120 * 1024 * 1024, // 120 MiB -- between FAIL and WARN threshold
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Warn);
    }

    #[test]
    fn check_disk_space_below_100_mib_is_fail() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 50 * 1024 * 1024, // 50 MiB
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Fail);
    }

    // -------------------------------------------------------------------------
    // Check 12: denial rate (informational)
    // -------------------------------------------------------------------------

    #[test]
    fn check_denial_rate_zero_is_ok() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 0,
                count_7d: 0,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains("24h"), "{}", result.detail);
    }

    #[test]
    fn check_denial_rate_nonzero_is_ok_with_count_in_detail() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 42,
                count_7d: 300,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains("42"), "{}", result.detail);
    }

    // -------------------------------------------------------------------------
    // Check 13: misconfiguration
    // -------------------------------------------------------------------------

    #[test]
    fn check_misconfig_clean_is_ok() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: false,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_misconfig(&probe, &fake_path()).status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn check_misconfig_permissive_flag_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: false,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_deprecated_sha256hash_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: true,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_both_layouts_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: false,
                both_layouts_present: true,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("fapd-F02"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_multiple_issues_combined_in_detail() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: true,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        // Both issues should appear in the detail.
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_all_three_independent_and_unmasked() {
        // All three sub-conditions true: EACH must appear in the detail.
        // Pins sub-condition independence -- kills a mutant that makes any one
        // condition contingent on the others being absent (e.g. only pushing
        // `both_layouts` when no other issue is present), which the
        // single-condition + permissive+sha256hash tests cannot detect.
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: true,
                both_layouts_present: true,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
        assert!(
            result.detail.contains("fapd-F02"),
            "both-layouts (fapd-F02) must not be masked by the other two: {}",
            result.detail
        );
    }

    // -------------------------------------------------------------------------
    // worst_exit_code
    // -------------------------------------------------------------------------

    fn result(status: CheckStatus) -> CheckResult {
        CheckResult {
            name: "test",
            status,
            detail: String::new(),
            remediation: None,
        }
    }

    #[test]
    fn worst_exit_code_all_ok_is_clean() {
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Ok), result(CheckStatus::Ok)]),
            EXIT_CLEAN
        );
    }

    #[test]
    fn worst_exit_code_warn_only_is_warnings() {
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Ok), result(CheckStatus::Warn)]),
            EXIT_WARNINGS
        );
    }

    #[test]
    fn worst_exit_code_fail_overrides_warn() {
        assert_eq!(
            worst_exit_code(&[
                result(CheckStatus::Warn),
                result(CheckStatus::Fail),
                result(CheckStatus::Ok)
            ]),
            EXIT_ERRORS
        );
    }

    #[test]
    fn worst_exit_code_skip_unknown_do_not_escalate() {
        // Skip and Unknown alone must not escalate above clean.
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Skip), result(CheckStatus::Unknown)]),
            EXIT_CLEAN
        );
    }

    // -------------------------------------------------------------------------
    // run_checks emits 13 checks
    // -------------------------------------------------------------------------

    #[test]
    fn run_checks_returns_exactly_13_results() {
        // All probe methods unconfigured -- every check returns Unknown or Skip.
        let probe = FakeProbe::default();
        let results = run_checks(&probe, &fake_path());
        assert_eq!(results.len(), 13, "doctor must run exactly 13 checks");
    }

    #[test]
    fn run_checks_container_check_is_skip_regardless_of_probe() {
        // Container-check (#9, index 8) is always Skip (design decision #4).
        let probe = FakeProbe::default();
        let results = run_checks(&probe, &fake_path());
        let cc = &results[8];
        assert_eq!(
            cc.name, "container-check",
            "index 8 must be container-check"
        );
        assert_eq!(cc.status, CheckStatus::Skip, "container-check must be Skip");
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
    // parse_kernel_version
    // -------------------------------------------------------------------------

    #[test]
    fn parse_kernel_version_standard_el_release_strings() {
        assert_eq!(
            parse_kernel_version("6.3.0-0.rc1.el10.x86_64"),
            Some((6, 3))
        );
        assert_eq!(parse_kernel_version("5.14.0-427.el9.x86_64"), Some((5, 14)));
        assert_eq!(parse_kernel_version("4.18.0-513.el8.x86_64"), Some((4, 18)));
    }

    #[test]
    fn parse_kernel_version_plain_strings() {
        assert_eq!(parse_kernel_version("6.3.1"), Some((6, 3)));
        assert_eq!(parse_kernel_version("4.20.0"), Some((4, 20)));
        assert_eq!(parse_kernel_version("4.19.0"), Some((4, 19)));
    }

    #[test]
    fn parse_kernel_version_garbage_returns_none() {
        assert_eq!(parse_kernel_version("not-a-kernel"), None);
        assert_eq!(parse_kernel_version(""), None);
    }

    // -------------------------------------------------------------------------
    // parse_lint_counts
    // -------------------------------------------------------------------------

    #[test]
    fn parse_lint_counts_counts_errors_and_warnings() {
        let json = r#"{"schemaVersion":1,"kind":"lint","diagnostics":[
            {"severity":"Error"},
            {"severity":"Fatal"},
            {"severity":"Warning"},
            {"severity":"Convention"}
        ]}"#;
        let counts = parse_lint_counts(json).expect("parse ok");
        assert_eq!(counts.errors, 2, "Error + Fatal = 2 errors");
        assert_eq!(counts.warnings, 1);
    }

    #[test]
    fn parse_lint_counts_empty_diagnostics() {
        let json = r#"{"schemaVersion":1,"kind":"lint","diagnostics":[]}"#;
        let counts = parse_lint_counts(json).expect("parse ok");
        assert_eq!(counts.errors, 0);
        assert_eq!(counts.warnings, 0);
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

    // -------------------------------------------------------------------------
    // JOB 1B: check_disk_space boundary tests
    //
    // Kills survivors on the `< FAIL_BYTES` / `< WARN_BYTES` boundaries
    // (`<` vs `<=` / `==` / `>`) and the `bytes_free / (1024*1024)` arithmetic.
    // -------------------------------------------------------------------------

    #[test]
    fn check_disk_space_exactly_fail_bytes_is_warn_not_fail() {
        // bytes_free == FAIL_BYTES (100 MiB exactly) is NOT below FAIL_BYTES,
        // so it must be Warn (between FAIL and WARN thresholds), not Fail.
        // Kills a `< -> <=` mutant on the first branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: FAIL_BYTES,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Warn,
            "exactly FAIL_BYTES must be Warn, not Fail"
        );
    }

    #[test]
    fn check_disk_space_one_byte_below_fail_bytes_is_fail() {
        // bytes_free == FAIL_BYTES - 1 is strictly below FAIL_BYTES -> Fail.
        // Kills a `< -> ==` or `< -> >` mutant on the first branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: FAIL_BYTES - 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Fail,
            "FAIL_BYTES-1 must be Fail"
        );
    }

    #[test]
    fn check_disk_space_exactly_warn_bytes_is_ok_not_warn() {
        // bytes_free == WARN_BYTES (128 MiB exactly) is NOT below WARN_BYTES,
        // so it must be Ok, not Warn.
        // Kills a `< -> <=` mutant on the second branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: WARN_BYTES,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Ok,
            "exactly WARN_BYTES must be Ok, not Warn"
        );
    }

    #[test]
    fn check_disk_space_one_byte_below_warn_bytes_is_warn() {
        // WARN_BYTES - 1 is strictly below WARN_BYTES but above FAIL_BYTES -> Warn.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: WARN_BYTES - 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Warn,
            "WARN_BYTES-1 must be Warn"
        );
    }

    #[test]
    fn check_disk_space_detail_reports_correct_mib() {
        // 200 MiB exactly: detail must say "200 MiB".
        //
        // Pins the `/ (1024 * 1024)` arithmetic.  Two tricky mutants:
        //   - `replace / with *`:  bytes * 1048576 = 219902325555200 -> "219902325555200 MiB"
        //     which contains the substring "200 MiB" -- so `contains("200 MiB")` is too weak.
        //     We assert `contains(" 200 MiB")` (leading space) AND that the value parses to
        //     exactly 200 to force both mutations to fail.
        //   - `replace * with /`:  bytes / (1024/1024) = bytes / 1 = 209715200 -> not 200.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 200 * 1024 * 1024,
            }),
            ..Default::default()
        };
        let result = check_disk_space(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        // Leading-space prefix prevents "219902325555200 MiB" from matching " 200 MiB".
        assert!(
            result.detail.contains(" 200 MiB"),
            "detail must report exactly 200 MiB (with leading space), got: {}",
            result.detail
        );
        // Additionally assert the numeric value parses to 200 from the detail.
        let mib_val: u64 = result
            .detail
            .split_whitespace()
            .find_map(|tok| tok.parse().ok())
            .expect("detail must contain a parseable MiB number");
        assert_eq!(
            mib_val, 200,
            "MiB value in detail must be exactly 200, got {mib_val}"
        );
    }

    // -------------------------------------------------------------------------
    // JOB 1C: check_denial_rate top_denied section
    //
    // Kills the `delete !` survivor on `!stats.top_denied.is_empty()`.
    // Without the `!`, the top-denied section would be appended when the list
    // IS empty and omitted when it is NOT empty -- both assertions below would
    // fail.
    // -------------------------------------------------------------------------

    #[test]
    fn check_denial_rate_nonempty_top_denied_includes_top_section() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 5,
                count_7d: 50,
                top_denied: vec![
                    ("/usr/bin/python3".to_string(), "/etc/shadow".to_string(), 3),
                    ("/usr/bin/bash".to_string(), "/tmp/secret".to_string(), 2),
                ],
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            result.detail.contains("top denied:"),
            "non-empty top_denied must include 'top denied:' in detail: {}",
            result.detail
        );
        assert!(
            result.detail.contains("/usr/bin/python3"),
            "detail must include the top subject: {}",
            result.detail
        );
        assert!(
            result.detail.contains("/etc/shadow"),
            "detail must include the top object: {}",
            result.detail
        );
    }

    #[test]
    fn check_denial_rate_empty_top_denied_excludes_top_section() {
        // When top_denied is empty the "top denied:" section must be absent.
        // A `delete !` mutant would incorrectly append it even for an empty list.
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 0,
                count_7d: 0,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            !result.detail.contains("top denied:"),
            "empty top_denied must NOT include 'top denied:' in detail: {}",
            result.detail
        );
    }

    // -------------------------------------------------------------------------
    // JOB 1D: read_fapolicyd_mode_from + check_sha256hash_in_dir
    //
    // Tempfile-based unit tests that kill the file-IO helper survivors.
    // -------------------------------------------------------------------------

    #[test]
    fn read_fapolicyd_mode_from_permissive_one_returns_permissive() {
        // `permissive=1` -> Some("permissive").
        // Kills mutants on the `== "1"` guard and on the return-value string.
        let dir = tempfile::tempdir().expect("tempdir");
        let conf = dir.path().join("fapolicyd.conf");
        std::fs::write(&conf, "# comment\npermissive=1\nsome_other=0\n").unwrap();
        assert_eq!(
            read_fapolicyd_mode_from(&conf),
            Some("permissive".to_string())
        );
    }

    #[test]
    fn read_fapolicyd_mode_from_permissive_zero_returns_enforcing() {
        // `permissive=0` -> not "1" -> returns Some("enforcing"), not None.
        // Kills a mutant that converts the `!= "1"` path to None.
        let dir = tempfile::tempdir().expect("tempdir");
        let conf = dir.path().join("fapolicyd.conf");
        std::fs::write(&conf, "permissive=0\n").unwrap();
        assert_eq!(
            read_fapolicyd_mode_from(&conf),
            Some("enforcing".to_string())
        );
    }

    #[test]
    fn read_fapolicyd_mode_from_absent_key_returns_enforcing() {
        // No `permissive=` line at all -> Some("enforcing").
        // Kills a mutant that short-circuits the fallthrough to None.
        let dir = tempfile::tempdir().expect("tempdir");
        let conf = dir.path().join("fapolicyd.conf");
        std::fs::write(&conf, "integrity=sha256\nrpm_integrity_check=1\n").unwrap();
        assert_eq!(
            read_fapolicyd_mode_from(&conf),
            Some("enforcing".to_string())
        );
    }

    #[test]
    fn read_fapolicyd_mode_from_missing_file_returns_none() {
        // A non-existent file -> None (the `?` operator in the impl).
        let path = Path::new("/nonexistent/path/to/fapolicyd.conf");
        assert_eq!(read_fapolicyd_mode_from(path), None);
    }

    #[test]
    fn read_fapolicyd_mode_from_permissive_with_spaces_returns_permissive() {
        // `permissive = 1` (spaces around `=`) -> permissive.
        // The impl uses `split('=').nth(1)?.trim()` so this works; this test
        // pins that the trim() call is not accidentally mutated away.
        let dir = tempfile::tempdir().expect("tempdir");
        let conf = dir.path().join("fapolicyd.conf");
        std::fs::write(&conf, "permissive = 1\n").unwrap();
        assert_eq!(
            read_fapolicyd_mode_from(&conf),
            Some("permissive".to_string())
        );
    }

    #[test]
    fn check_sha256hash_in_dir_returns_true_when_present() {
        // A `.rules` file containing `sha256hash=` -> true.
        // Kills the `!= -> ==` return-value mutant.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("10-test.rules"),
            "allow exe=/usr/bin/cat : sha256hash=abc123\n",
        )
        .unwrap();
        assert!(
            check_sha256hash_in_dir(dir.path()),
            "must return true when sha256hash= is present"
        );
    }

    #[test]
    fn check_sha256hash_in_dir_returns_false_when_absent() {
        // A `.rules` file without `sha256hash=` -> false.
        // Kills a mutant that always returns true.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("10-test.rules"),
            "allow exe=/usr/bin/cat : filehash=abc123\n",
        )
        .unwrap();
        assert!(
            !check_sha256hash_in_dir(dir.path()),
            "must return false when no sha256hash= is present"
        );
    }

    #[test]
    fn check_sha256hash_in_dir_ignores_non_rules_files() {
        // A `.txt` file containing `sha256hash=` must NOT trigger a true return.
        // Kills a mutant that drops the `.rules` extension filter.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("notes.txt"),
            "allow exe=/usr/bin/cat : sha256hash=abc123\n",
        )
        .unwrap();
        assert!(
            !check_sha256hash_in_dir(dir.path()),
            "non-.rules files must be ignored"
        );
    }

    #[test]
    fn check_sha256hash_in_dir_nonexistent_dir_returns_false() {
        let path = Path::new("/nonexistent/rules.d");
        assert!(
            !check_sha256hash_in_dir(path),
            "non-existent dir must return false"
        );
    }

    // -------------------------------------------------------------------------
    // JOB 2: parse_fanotify_denials pure parser
    //
    // Tests use representative ausearch output derived from the era1/era2 fixtures
    // in crates/rulesteward-fapolicyd/tests/fixtures/explain/.
    // -------------------------------------------------------------------------

    /// Representative era1 ausearch block (resp=2 = DENY).
    const ERA1_DENY: &str = r#"----
type=PROCTITLE msg=audit(1600385000.000:100): proctitle=636174002F6574632F686F73746E616D65
type=PATH msg=audit(1600385000.000:100): item=0 name="/etc/hostname" inode=100 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1600385000.000:100): cwd="/root"
type=SYSCALL msg=audit(1600385000.000:100): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=55a5d1234560 a2=0 a3=0 items=1 ppid=1 pid=51 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="cat" exe="/usr/bin/coreutils" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=FANOTIFY msg=audit(1600385000.000:100): resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2
"#;

    /// Era2 block with resp=1 (ALLOW) -- must NOT be counted.
    const ERA2_ALLOW: &str = r#"----
type=PROCTITLE msg=audit(1600385147.372:590): proctitle=636174002F6574632F686F73746E616D65
type=PATH msg=audit(1600385147.372:590): item=0 name="/etc/hostname" inode=100 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1600385147.372:590): cwd="/root"
type=SYSCALL msg=audit(1600385147.372:590): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=55a5d1234560 a2=0 a3=0 items=1 ppid=1 pid=52 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="cat" exe="/usr/bin/coreutils" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=FANOTIFY msg=audit(1600385147.372:590): resp=1 fan_type=1 fan_info=1 subj_trust=1 obj_trust=0
"#;

    #[test]
    fn parse_fanotify_denials_empty_input_is_zero() {
        let (count, pairs) = parse_fanotify_denials("");
        assert_eq!(count, 0);
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_fanotify_denials_single_deny_block_counts_one() {
        let (count, pairs) = parse_fanotify_denials(ERA1_DENY);
        assert_eq!(count, 1, "one DENY block -> count 1");
        assert_eq!(pairs.len(), 1);
        let (subj, obj, c) = &pairs[0];
        assert_eq!(subj, "/usr/bin/coreutils");
        assert_eq!(obj, "/etc/hostname");
        assert_eq!(*c, 1);
    }

    #[test]
    fn parse_fanotify_denials_allow_block_not_counted() {
        // ALLOW (resp=1) blocks must be ignored -- count stays 0.
        let (count, pairs) = parse_fanotify_denials(ERA2_ALLOW);
        assert_eq!(count, 0, "ALLOW block must not increment count");
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_fanotify_denials_deny_and_allow_mixed() {
        let input = format!("{ERA1_DENY}{ERA2_ALLOW}");
        let (count, pairs) = parse_fanotify_denials(&input);
        assert_eq!(count, 1, "only the DENY block counts");
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn parse_fanotify_denials_two_deny_blocks_same_pair_accumulates() {
        // Two DENY blocks with the same (subj, obj) pair -> count 2, one pair
        // with tally 2.  Kills a mutant that resets the counter instead of
        // accumulating.
        let input = format!("{ERA1_DENY}{ERA1_DENY}");
        let (count, pairs) = parse_fanotify_denials(&input);
        assert_eq!(count, 2, "two identical DENY blocks -> count 2");
        assert_eq!(pairs.len(), 1, "same pair appears once in the tally");
        assert_eq!(pairs[0].2, 2, "tally for the pair must be 2");
    }

    #[test]
    fn parse_fanotify_denials_top_pairs_sorted_descending_by_count() {
        // Build input: python3 denied 3x, bash denied 1x.
        // After parsing, python3 must appear first (higher count).
        let python_deny = |serial: u32| {
            format!(
                "----\ntype=SYSCALL msg=audit(1.0:{serial}): exe=\"/usr/bin/python3\" pid=1 auid=4294967295\ntype=PATH msg=audit(1.0:{serial}): item=0 name=\"/etc/shadow\"\ntype=FANOTIFY msg=audit(1.0:{serial}): resp=2 fan_type=0 fan_info=0 subj_trust=0 obj_trust=0\n"
            )
        };
        let bash_deny = || {
            "----\ntype=SYSCALL msg=audit(2.0:200): exe=\"/usr/bin/bash\" pid=2 auid=4294967295\ntype=PATH msg=audit(2.0:200): item=0 name=\"/tmp/secret\"\ntype=FANOTIFY msg=audit(2.0:200): resp=2 fan_type=0 fan_info=0 subj_trust=0 obj_trust=0\n".to_string()
        };
        let input = format!(
            "{}{}{}{}",
            python_deny(1),
            python_deny(2),
            python_deny(3),
            bash_deny()
        );
        let (count, pairs) = parse_fanotify_denials(&input);
        assert_eq!(count, 4);
        assert_eq!(pairs.len(), 2);
        // First pair (highest count) must be python3.
        assert_eq!(pairs[0].0, "/usr/bin/python3");
        assert_eq!(pairs[0].2, 3);
        // Second pair must be bash.
        assert_eq!(pairs[1].0, "/usr/bin/bash");
        assert_eq!(pairs[1].2, 1);
    }

    #[test]
    fn parse_fanotify_denials_no_syscall_subject_is_unknown() {
        // A bare FANOTIFY-only deny block (no SYSCALL line) -> subject "(unknown)".
        let bare = "type=FANOTIFY msg=audit(1.0:1): resp=2 fan_type=0 fan_info=0 subj_trust=0 obj_trust=0\n";
        let (count, pairs) = parse_fanotify_denials(bare);
        assert_eq!(count, 1);
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].0, "(unknown)",
            "no SYSCALL -> subject is (unknown)"
        );
    }
}
