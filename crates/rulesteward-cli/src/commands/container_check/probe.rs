//! The live `ContainerProbe` implementation plus the pure parsers it consumes.
//!
//! `LiveContainerProbe` shells out to the OS (which/systemctl/test/rpm/ausearch/
//! fapolicyd-cli) and is excluded from the mutation gate by name. The pure
//! parsers (`parse_effective_conf`, `crun_covered_in_rules`, `dump_db_trusted`,
//! `count_runtime_denials`) carry the real logic and are unit-tested here.

use std::path::Path;
use std::process::{Command, Stdio};

use rulesteward_fapolicyd::{Attr, AttrValue, Decision, Entry, parse_rules_file};

use super::model::{
    ContainerProbe, CrunRuleCoverage, DeepDenials, DeepTrust, EffectiveConf, FapolicydState,
    RhcosStatus, RuntimeBinaries, RuntimeStatus,
};
use crate::commands::doctor::parse_fanotify_denials;

const DEFAULT_CONF: &str = "/etc/fapolicyd/fapolicyd.conf";
const RUNTIME_BINS: [&str; 3] = ["/usr/bin/crun", "/usr/bin/runc", "/usr/bin/conmon"];

// ===========================================================================
// Pure parsers (unit-tested; in the mutation gate)
// ===========================================================================

/// Parse `watch_fs=` and `allow_filesystem_mark=` out of fapolicyd.conf text.
///
/// `watch_fs` is a comma-separated list (e.g. `watch_fs = ext4,tmpfs,xfs`);
/// `allow_filesystem_mark = 1` enables overlay marking. Lines may have spaces
/// around `=` and may be commented with a leading `#` (ignored).
#[must_use]
pub fn parse_effective_conf(conf_text: &str, readable: bool) -> EffectiveConf {
    let mut watch_fs = Vec::new();
    let mut allow_filesystem_mark = false;
    for line in conf_text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix("watch_fs") {
            if let Some(val) = rest.trim_start().strip_prefix('=') {
                watch_fs = val
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        } else if let Some(rest) = t.strip_prefix("allow_filesystem_mark")
            && let Some(val) = rest.trim_start().strip_prefix('=')
        {
            allow_filesystem_mark = val.trim() == "1";
        }
    }
    EffectiveConf {
        watch_fs,
        allow_filesystem_mark,
        readable,
    }
}

/// Scan rules text for an allow rule that covers `exe=/usr/bin/crun` (or runc).
///
/// Coverage (per the locked decision) is "any allow rule covering crun": an
/// `allow*` rule whose subject either names `exe=/usr/bin/crun`/`runc` or is the
/// catch-all `all` (which permits the runtime by default). A spawning-UID-scoped
/// rule still counts (we treat "any allow rule covering crun" as coverage).
#[must_use]
pub fn crun_covered_in_rules(rules_text: &str) -> CrunRuleCoverage {
    let Ok(entries) = parse_rules_file(rules_text, Path::new("<rules>")) else {
        return CrunRuleCoverage {
            covered: false,
            detail: "rules could not be parsed".to_string(),
        };
    };

    for entry in &entries {
        let Entry::Rule(rule) = entry else { continue };
        if !is_allow(rule.decision) {
            continue;
        }
        for attr in &rule.subject {
            match attr {
                Attr::All => {
                    return CrunRuleCoverage {
                        covered: true,
                        detail: format!("allow-all rule on line {} covers the runtime", rule.line),
                    };
                }
                Attr::Kv { key, value, .. } if key == "exe" => {
                    if let AttrValue::Str(path) = value
                        && (path == "/usr/bin/crun" || path == "/usr/bin/runc")
                    {
                        return CrunRuleCoverage {
                            covered: true,
                            detail: format!("allow rule on line {} covers {path}", rule.line),
                        };
                    }
                }
                // Any other subject attr (a non-exe Kv) does not establish crun coverage.
                Attr::Kv { .. } => {}
            }
        }
    }

    CrunRuleCoverage {
        covered: false,
        detail: "no allow rule for exe=/usr/bin/crun (or runc) found".to_string(),
    }
}

fn is_allow(d: Decision) -> bool {
    matches!(
        d,
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog
    )
}

/// Given `fapolicyd-cli --dump-db` text and which runtime binaries are present
/// on the host, return per-binary trust (present in the trust DB).
///
/// dump-db lines are `<source> <path> <size> <sha256>`; a binary is "trusted"
/// if its absolute path appears as the second whitespace field. `None` means
/// the binary is not installed (trust is not applicable).
#[must_use]
pub fn dump_db_trusted(dump_db_text: &str, bins: &RuntimeBinaries) -> DeepTrust {
    let trusted = |path: &str| {
        dump_db_text
            .lines()
            .any(|l| l.split_whitespace().nth(1) == Some(path))
    };
    DeepTrust {
        crun_trusted: bins.crun.then(|| trusted("/usr/bin/crun")),
        runc_trusted: bins.runc.then(|| trusted("/usr/bin/runc")),
        conmon_trusted: bins.conmon.then(|| trusted("/usr/bin/conmon")),
    }
}

/// Of the denial `(subject, object, count)` tally from `parse_fanotify_denials`,
/// count those whose subject is a container-runtime binary.
#[must_use]
pub fn count_runtime_denials(pairs: &[(String, String, u64)]) -> u64 {
    pairs
        .iter()
        .filter(|(subj, _, _)| RUNTIME_BINS.contains(&subj.as_str()) || subj == "/usr/bin/podman")
        .map(|(_, _, c)| c)
        .sum()
}

// ===========================================================================
// LiveContainerProbe -- real OS access (NOT unit-tested; mutation-excluded)
// ===========================================================================

/// Real probe that shells out to the OS. On a host without the relevant tools
/// each method degrades to "not detected" rather than erroring.
pub struct LiveContainerProbe;

/// Run a command and report whether it exited 0 (stdout/stderr suppressed).
fn ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}

/// A directory that exists and has at least one entry.
fn dir_nonempty(p: &str) -> bool {
    std::fs::read_dir(p).is_ok_and(|mut rd| rd.next().is_some())
}

fn capture(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn status(name: &'static str, present: bool, active: bool, informational: bool) -> RuntimeStatus {
    RuntimeStatus {
        name,
        present,
        active,
        informational,
        detail: String::new(),
    }
}

impl ContainerProbe for LiveContainerProbe {
    fn podman_rootful(&self) -> RuntimeStatus {
        let active = dir_nonempty("/var/lib/containers/storage/overlay");
        let present = active
            || ok("which", &["podman"])
            || path_exists("/var/lib/containers/storage/overlay");
        status("podman-rootful", present, active, false)
    }

    fn podman_rootless(&self) -> RuntimeStatus {
        // Look for any user's rootless storage under /home/*/.local/share/containers/storage.
        let mut present = false;
        let mut active = false;
        if let Ok(rd) = std::fs::read_dir("/home") {
            for user in rd.flatten() {
                let store = user.path().join(".local/share/containers/storage");
                if store.is_dir() {
                    present = true;
                    if dir_nonempty(&store.join("overlay").to_string_lossy()) {
                        active = true;
                    }
                }
            }
        }
        status("podman-rootless", present, active, false)
    }

    fn docker(&self) -> RuntimeStatus {
        let active = ok("systemctl", &["is-active", "--quiet", "docker"]);
        let present = active
            || path_exists("/var/run/docker.sock")
            || ok("systemctl", &["is-enabled", "--quiet", "docker"])
            || ok("rpm", &["-q", "docker-ce"]);
        status("docker", present, active, false)
    }

    fn containerd(&self) -> RuntimeStatus {
        // Standalone containerd only: when docker is present, an active
        // containerd is docker's backend, not a standalone runtime. The
        // `!docker` gate applies to BOTH present and active so they stay
        // consistent (active implies present).
        let standalone = !ok("which", &["docker"]);
        let active = standalone && ok("systemctl", &["is-active", "--quiet", "containerd"]);
        let present = active || (standalone && path_exists("/run/containerd/containerd.sock"));
        status("containerd", present, active, false)
    }

    fn crio(&self) -> RuntimeStatus {
        let active = ok("systemctl", &["is-active", "--quiet", "crio"]);
        let present = active
            || path_exists("/var/run/crio/crio.sock")
            || ok("systemctl", &["is-enabled", "--quiet", "crio"]);
        status("crio", present, active, false)
    }

    fn kubelet(&self) -> RuntimeStatus {
        let active = ok("systemctl", &["is-active", "--quiet", "kubelet"]);
        let present = active
            || ok("systemctl", &["is-enabled", "--quiet", "kubelet"])
            || path_exists("/etc/kubernetes/kubelet.conf")
            || path_exists("/var/lib/kubelet");
        status("kubelet", present, active, false)
    }

    fn cni_configured(&self) -> RuntimeStatus {
        let present = dir_nonempty("/etc/cni/net.d");
        status("cni", present, present, true)
    }

    fn rhcos_status(&self) -> RhcosStatus {
        let os = capture("cat", &["/etc/os-release"]);
        let is_rhcos = os
            .lines()
            .any(|l| l.trim() == "ID=rhcos" || l.trim() == "ID=\"rhcos\"")
            || capture("rpm-ostree", &["status"])
                .to_lowercase()
                .contains("rhcos");
        RhcosStatus {
            is_rhcos,
            detail: if is_rhcos {
                "Red Hat CoreOS / OpenShift node detected".to_string()
            } else {
                "not a Red Hat CoreOS node".to_string()
            },
        }
    }

    fn fapolicyd_state(&self) -> FapolicydState {
        FapolicydState {
            running: ok("systemctl", &["is-active", "--quiet", "fapolicyd"]),
            enabled: ok("systemctl", &["is-enabled", "--quiet", "fapolicyd"]),
        }
    }

    fn effective_conf(&self, _rules_dir: &Path) -> EffectiveConf {
        match std::fs::read_to_string(DEFAULT_CONF) {
            Ok(text) => parse_effective_conf(&text, true),
            Err(_) => parse_effective_conf("", false),
        }
    }

    fn runtime_binaries(&self) -> RuntimeBinaries {
        RuntimeBinaries {
            crun: path_exists("/usr/bin/crun"),
            runc: path_exists("/usr/bin/runc"),
            conmon: path_exists("/usr/bin/conmon"),
        }
    }

    fn crun_rule_coverage(&self, rules_dir: &Path) -> CrunRuleCoverage {
        // Concatenate all .rules files in rules_dir and scan them as one source.
        let mut combined = String::new();
        if let Ok(rd) = std::fs::read_dir(rules_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("rules")
                    && let Ok(text) = std::fs::read_to_string(&p)
                {
                    combined.push_str(&text);
                    combined.push('\n');
                }
            }
        }
        crun_covered_in_rules(&combined)
    }

    fn deep_trust(&self) -> DeepTrust {
        let dump = capture("fapolicyd-cli", &["--dump-db"]);
        dump_db_trusted(&dump, &self.runtime_binaries())
    }

    fn deep_denials(&self) -> DeepDenials {
        let raw = capture("ausearch", &["-m", "FANOTIFY", "--start", "today", "--raw"]);
        let (total, pairs) = parse_fanotify_denials(&raw);
        DeepDenials {
            total,
            runtime_denials: count_runtime_denials(&pairs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_conf_extracts_watch_fs_and_mark() {
        let conf =
            "watch_fs = ext2,ext3,ext4,tmpfs,xfs,vfat,iso9660,btrfs\nallow_filesystem_mark = 0\n";
        let c = parse_effective_conf(conf, true);
        assert!(c.watch_fs.contains(&"tmpfs".to_string()));
        assert!(c.watch_fs.contains(&"xfs".to_string()));
        assert!(!c.allow_filesystem_mark);
        assert!(c.readable);
    }

    #[test]
    fn parse_conf_detects_mark_enabled() {
        let c = parse_effective_conf("allow_filesystem_mark = 1\n", true);
        assert!(c.allow_filesystem_mark);
    }

    #[test]
    fn parse_conf_ignores_commented_lines() {
        let c = parse_effective_conf("# watch_fs = tmpfs\n#allow_filesystem_mark = 1\n", true);
        assert!(c.watch_fs.is_empty());
        assert!(!c.allow_filesystem_mark);
    }

    #[test]
    fn crun_coverage_found_via_exe_rule() {
        let rules = "allow perm=execute exe=/usr/bin/crun : all\n";
        let c = crun_covered_in_rules(rules);
        assert!(
            c.covered,
            "exe=/usr/bin/crun allow rule must count as coverage"
        );
    }

    #[test]
    fn crun_coverage_found_via_allow_all() {
        let rules = "allow perm=any all : all\n";
        let c = crun_covered_in_rules(rules);
        assert!(c.covered, "allow-all must count as coverage");
    }

    #[test]
    fn crun_coverage_absent_when_only_deny_or_unrelated() {
        let rules =
            "deny perm=execute exe=/usr/bin/crun : all\nallow perm=open exe=/usr/bin/rpm : all\n";
        let c = crun_covered_in_rules(rules);
        assert!(
            !c.covered,
            "a deny rule for crun + an allow rule for rpm is not coverage"
        );
    }

    #[test]
    fn dump_db_trust_detects_trusted_and_untrusted() {
        let dump = "rpmdb /usr/bin/crun 578552 abc123\nrpmdb /usr/bin/conmon 170984 def456\n";
        let bins = RuntimeBinaries {
            crun: true,
            runc: true,
            conmon: true,
        };
        let t = dump_db_trusted(dump, &bins);
        assert_eq!(t.crun_trusted, Some(true), "crun present in dump-db");
        assert_eq!(t.runc_trusted, Some(false), "runc absent from dump-db");
        assert_eq!(t.conmon_trusted, Some(true));
    }

    #[test]
    fn dump_db_trust_is_none_when_binary_absent() {
        let dump = "rpmdb /usr/bin/crun 1 a\n";
        let bins = RuntimeBinaries {
            crun: true,
            runc: false,
            conmon: false,
        };
        let t = dump_db_trusted(dump, &bins);
        assert_eq!(t.runc_trusted, None, "runc not installed -> trust N/A");
    }

    #[test]
    fn count_runtime_denials_sums_only_runtime_subjects() {
        let pairs = vec![
            ("/usr/bin/crun".to_string(), "/x".to_string(), 3),
            ("/usr/bin/bash".to_string(), "/y".to_string(), 9),
            ("/usr/bin/podman".to_string(), "/z".to_string(), 2),
        ];
        assert_eq!(
            count_runtime_denials(&pairs),
            5,
            "crun(3) + podman(2), not bash"
        );
    }
}
