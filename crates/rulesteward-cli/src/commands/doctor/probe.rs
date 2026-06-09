//! The live `SystemProbe` implementation plus the raw-output parsers it consumes.
//!
//! `LiveProbe` shells out to the OS (systemctl/uname/auditctl/fapolicyd-cli/rpm/
//! df/ausearch/conf) and is excluded from the mutation gate by name; the pure
//! parsers (`parse_fanotify_denials`, `parse_lint_counts`, the config helpers)
//! are unit-tested and stay in scope.

use std::path::Path;
use std::process::Stdio;

use super::model::{
    CommandOutcome, DenialStats, FapolicydConf, FsSpace, LintCounts, ServiceState, SystemProbe,
};

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn extract_kv_matches_key_at_position_zero() {
        // The key sits at byte 0 (no preceding whitespace), exercising the
        // `pos == 0` arm of the word-boundary guard. Kills the `== 0 -> != 0`
        // mutant (which would underflow/miss the position-0 key and return None).
        assert_eq!(extract_kv("resp=2 fan_type=0", "resp"), Some("2"));
    }

    #[test]
    fn extract_kv_respects_word_boundary() {
        // `subj_trust=2` must NOT match a search for `trust` (no whitespace
        // before `trust=`): pins the boundary guard's whitespace arm.
        assert_eq!(extract_kv("resp=2 subj_trust=2", "trust"), None);
        // But a real whitespace-preceded `trust=` does match.
        assert_eq!(extract_kv("resp=2 trust=1", "trust"), Some("1"));
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
