//! The live `SelinuxProbe` implementation (#520): shells out to
//! `getenforce`/`sestatus`/`rpm -q`/the faillock locator/`ls -Zd`. EXCLUDED
//! from the mutation gate by name (see `.cargo/mutants.toml`'s
//! `<impl SelinuxProbe for LiveSelinuxProbe>` entry) - mirrors fapolicyd
//! doctor's `LiveProbe` (no unit-test seam for real OS access; covered by the
//! e2e graceful-degradation test + live VM smoke). Implemented against the
//! grounding in `grounding/g4-g6-selinux-config.md` sections G5/G6.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::model::SelinuxProbe;

/// Default faillock config file (G6.1).
const FAILLOCK_CONF: &str = "/etc/security/faillock.conf";
/// RHEL8 <8.2 fallback locator file (G6.2).
const PASSWORD_AUTH: &str = "/etc/pam.d/password-auth";

/// Real probe that shells out to the OS. On a host without `SELinux` tooling,
/// each method returns an `Err` string that the check functions map to
/// `CheckStatus::Unknown` (mirrors fapolicyd doctor's `LiveProbe`).
pub(super) struct LiveSelinuxProbe;

impl SelinuxProbe for LiveSelinuxProbe {
    fn enforce_status(&self) -> Result<String, String> {
        let out = Command::new("getenforce")
            .output()
            .map_err(|e| format!("spawn getenforce (is it installed?): {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "getenforce exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // G5.1: exactly one of `Enforcing`/`Permissive`/`Disabled`, via `puts()`
        // (always a trailing newline); trim it off.
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn loaded_policy_name(&self) -> Result<Option<String>, String> {
        let out = Command::new("sestatus")
            .output()
            .map_err(|e| format!("spawn sestatus (is it installed?): {e}"))?;
        if !out.status.success() {
            // G5.2: sestatus exits 0 even when SELinux is disabled (a single
            // "SELinux status: disabled" line, no "Loaded policy name" line at
            // all - handled below by the loop simply finding nothing). A
            // non-zero exit here is a real error (e.g. selinuxfs not mounted).
            return Err(format!(
                "sestatus exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Anchor on the label + a whitespace run (G5.2's durable contract,
        // not a hardcoded column count): the disabled state omits this line
        // entirely, which the loop finding nothing already models as `None`.
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("Loaded policy name:") {
                let name = rest.trim();
                if !name.is_empty() {
                    return Ok(Some(name.to_string()));
                }
            }
        }
        Ok(None)
    }

    fn package_installed(&self, name: &str) -> Result<bool, String> {
        // Exit-status-only, no stdout parsing: mirrors fapolicyd doctor's
        // `rpm_plugin_installed`.
        let out = Command::new("rpm")
            .args(["-q", name])
            .output()
            .map_err(|e| format!("spawn rpm -q {name} (is rpm installed?): {e}"))?;
        Ok(out.status.success())
    }

    fn faillock_dir(&self) -> Result<Option<PathBuf>, String> {
        // G6.3 NA condition: this whole family is Not Applicable unless
        // SELinux is enabled, Enforcing, AND running the targeted policy.
        match (self.enforce_status(), self.loaded_policy_name()) {
            (Ok(mode), Ok(Some(policy))) if mode == "Enforcing" && policy == "targeted" => {}
            _ => return Ok(None),
        }

        if let Some(dir) = read_faillock_conf_dir() {
            return Ok(Some(dir));
        }
        Ok(read_password_auth_dir())
    }

    fn dir_context_type(&self, dir: &Path) -> Result<Option<String>, String> {
        let out = Command::new("ls")
            .arg("-Zd")
            .arg(dir)
            .output()
            .map_err(|e| format!("spawn ls -Zd {} (is ls installed?): {e}", dir.display()))?;
        if !out.status.success() {
            // A nonexistent directory (or an inaccessible one) makes `ls -Zd`
            // fail with a nonzero exit - the trait contract maps that to
            // "directory absent", not a hard probe error.
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // G6.4: `<context><SPACE><path>`; context is the first
        // whitespace-separated field.
        let context = stdout.split_whitespace().next().unwrap_or("");
        if context.is_empty() || context == "?" {
            return Err(format!(
                "could not parse `ls -Zd {}` output: {stdout:?}",
                dir.display()
            ));
        }
        // Type is the THIRD colon-segment counting from the LEFT
        // (user:role:type:level); the level may itself contain `:`/`,`.
        match context.split(':').nth(2) {
            Some(ty) => Ok(Some(ty.to_string())),
            None => Err(format!(
                "unexpected SELinux context shape for {}: {context:?}",
                dir.display()
            )),
        }
    }
}

/// Parse `/etc/security/faillock.conf`'s `dir` directive per G6.1: an inline
/// `#`-to-EOL comment is stripped FIRST, then the line is trimmed; the key
/// ends at the first space or `=`; whitespace around `=` is ignored; the LAST
/// `dir` line wins; a non-absolute value is rejected (the module keeps its
/// current default, mirroring `set_conf_opt`'s "keeping default" behavior).
/// Returns `Ok(None)` when the file is absent/unreadable or no `dir` line
/// resolves to an absolute path (the compiled-in default
/// `/var/run/faillock` is in effect - not a "configured" non-default dir; a
/// stock system ships this directive commented out).
fn read_faillock_conf_dir() -> Option<PathBuf> {
    let text = std::fs::read_to_string(FAILLOCK_CONF).ok()?;

    let mut winner: Option<PathBuf> = None;
    for raw_line in text.lines() {
        let no_comment = raw_line.split('#').next().unwrap_or("");
        let trimmed = no_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key_end = trimmed
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(trimmed.len());
        if &trimmed[..key_end] != "dir" {
            continue;
        }
        let rest = trimmed[key_end..].trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
        if rest.starts_with('/') {
            winner = Some(PathBuf::from(rest));
        }
    }
    winner
}

/// Fallback locator for RHEL8 <8.2 (G6.2): a whitespace-separated
/// `dir=/path` token on a `pam_faillock.so` line in
/// `/etc/pam.d/password-auth`.
fn read_password_auth_dir() -> Option<PathBuf> {
    let text = std::fs::read_to_string(PASSWORD_AUTH).ok()?;
    for line in text.lines() {
        if !line.contains("pam_faillock.so") {
            continue;
        }
        if let Some(path) = line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("dir="))
        {
            return Some(PathBuf::from(path));
        }
    }
    None
}
