//! The live `SelinuxProbe` implementation (#520): shells out to
//! `getenforce`/`sestatus`/`rpm -q`/the faillock locator/`ls -Zd`. EXCLUDED
//! from the mutation gate by name (see `.cargo/mutants.toml`'s
//! `<impl SelinuxProbe for LiveSelinuxProbe>` entry) - mirrors fapolicyd
//! doctor's `LiveProbe` (no unit-test seam for real OS access; covered by the
//! e2e graceful-degradation test + live VM smoke). Implemented against the
//! grounding in `grounding/g4-g6-selinux-config.md` sections G5/G6.
//!
//! The faillock locator helpers (`read_faillock_conf_dir_from`/
//! `read_password_auth_dir_from`) are pure-parsing free functions OUTSIDE
//! that excluded impl block, so they stay in scope for the mutation gate.
//! Each takes an explicit `path: &Path` argument (mirroring the SHAPE of
//! `doctor::probe::read_fapolicyd_mode_from`, PR #133/#173) so it can be
//! unit-tested against a tempfile - see the `tests` module below (mutation
//! round 1, session 9d lane 2b). Unlike that precedent, there is no separate
//! 0-arg hardcoded-path wrapper: `LiveSelinuxProbe::faillock_dir` (inside the
//! already-excluded impl block above) passes `Path::new(FAILLOCK_CONF)` /
//! `Path::new(PASSWORD_AUTH)` directly at its one call site. A thin wrapper
//! was tried first and reintroduced two mutation survivors (the wrapper's
//! own `None`/`Some(Default::default())` constant-replacement, never
//! observed by any test since nothing calls a 0-arg wrapper directly) that
//! could only be silenced via a new `.cargo/mutants.toml` `exclude_re` entry -
//! out of scope for this lane. Inlining the hardcoded path removes that
//! mutation surface entirely instead of asking for a new exclusion.

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

        if let Some(dir) = read_faillock_conf_dir_from(Path::new(FAILLOCK_CONF)) {
            return Ok(Some(dir));
        }
        Ok(read_password_auth_dir_from(Path::new(PASSWORD_AUTH)))
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

/// Parse a faillock.conf-shaped file's `dir` directive per G6.1: an inline
/// `#`-to-EOL comment is stripped FIRST, then the line is trimmed; the key
/// ends at the first space or `=`; whitespace around `=` is ignored; the LAST
/// `dir` line wins; a non-absolute value is rejected (the module keeps its
/// current default, mirroring `set_conf_opt`'s "keeping default" behavior).
/// Returns `None` when the file is absent/unreadable or no `dir` line
/// resolves to an absolute path (the compiled-in default
/// `/var/run/faillock` is in effect - not a "configured" non-default dir; a
/// stock system ships this directive commented out).
fn read_faillock_conf_dir_from(conf_path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(conf_path).ok()?;

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
/// `dir=/path` token on a `pam_faillock.so` line in a
/// password-auth-shaped file.
fn read_password_auth_dir_from(pam_path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(pam_path).ok()?;
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

// ---------------------------------------------------------------------------
// Direct unit tests for the faillock locator helpers (mutation round 1,
// session 9d lane 2b; orchestrator-authorized exception to the "no probe.rs
// impl changes" scope note - see commit message). `read_faillock_conf_dir_from`/
// `read_password_auth_dir_from` are pure-parsing free functions OUTSIDE the
// mutation-excluded `impl SelinuxProbe for LiveSelinuxProbe` block (project
// precedent: "private fns need direct tests", #373); each takes an explicit
// `path: &Path` argument (SHAPE mirrors `doctor::probe::
// read_fapolicyd_mode_from`, PR #133/#173) so a tempfile can stand in for
// the real system file. No separate 0-arg wrapper exists - see the
// file-level doc comment above for why.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `contents` to a fresh tempfile and return the guard (dropped ->
    /// deleted) plus its path.
    fn write_temp(contents: &str) -> (tempfile::NamedTempFile, std::path::PathBuf) {
        let mut f = tempfile::NamedTempFile::new().expect("create tempfile");
        f.write_all(contents.as_bytes()).expect("write tempfile");
        let path = f.path().to_path_buf();
        (f, path)
    }

    // --- read_faillock_conf_dir_from (G6.1) --------------------------------

    #[test]
    fn faillock_conf_uncommented_absolute_dir_is_found() {
        let (_g, path) = write_temp("dir = /var/log/faillock\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            Some(PathBuf::from("/var/log/faillock")),
            "an uncommented `dir = /absolute/path` line resolves to that \
             path (G6.1)"
        );
    }

    #[test]
    fn faillock_conf_commented_default_is_none() {
        // The stock shipped file has this directive COMMENTED (G6.1): "on a
        // stock system, `grep -w dir /etc/security/faillock.conf` matches
        // only a comment -> effective dir remains the default" - must NOT
        // count as a configured dir.
        let (_g, path) = write_temp("# dir = /var/run/faillock\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            None,
            "a commented-out `dir` directive (the stock default shape) \
             must not be treated as a configured tally dir"
        );
    }

    #[test]
    fn faillock_conf_last_duplicate_dir_wins() {
        // G6.1: "Duplicate `dir`: LAST occurrence wins (each parse frees +
        // replaces `opts->dir`)."
        let (_g, path) = write_temp("dir = /var/log/faillock\ndir = /var/log/other\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            Some(PathBuf::from("/var/log/other")),
            "the LAST `dir` line wins, mirroring pam_faillock's \
             free+replace duplicate handling (G6.1)"
        );
    }

    #[test]
    fn faillock_conf_non_absolute_value_is_rejected() {
        // G6.1: "Non-absolute value: syslog error, KEEP DEFAULT (not
        // fatal)." This reader models "keep default" as leaving `winner`
        // unset (None), not as a hard parse error.
        let (_g, path) = write_temp("dir = relative/path\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            None,
            "a non-absolute `dir` value is rejected and the default stays \
             in effect (G6.1) - not a fatal parse error"
        );
    }

    #[test]
    fn faillock_conf_inline_comment_is_stripped_before_value() {
        // G6.1: "INLINE `#` comments ARE supported (unlike libselinux):
        // `dir = /var/log/faillock # x` -> value `/var/log/faillock` (the
        // `#` truncates first, THEN whitespace is trimmed)."
        let (_g, path) = write_temp("dir = /var/log/faillock # tally here\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            Some(PathBuf::from("/var/log/faillock")),
            "an inline `#` comment is stripped before the value is taken \
             (G6.1) - OPPOSITE of the selinux/config reader's SELINUXTYPE= \
             rule, which keeps inline comment text as part of the value"
        );
    }

    #[test]
    fn faillock_conf_missing_file_is_none() {
        let missing = std::path::Path::new("/nonexistent/9d-lane-2b/faillock.conf");
        assert_eq!(
            read_faillock_conf_dir_from(missing),
            None,
            "an absent/unreadable config file yields None, never a panic \
             or fatal (G6.1)"
        );
    }

    #[test]
    fn faillock_conf_no_dir_key_is_none() {
        let (_g, path) = write_temp("deny = 3\nunlock_time = 600\n");
        assert_eq!(
            read_faillock_conf_dir_from(&path),
            None,
            "a file with no `dir` key at all yields None"
        );
    }

    // --- read_password_auth_dir_from (G6.2) --------------------------------

    #[test]
    fn password_auth_finds_dir_token_on_pam_faillock_line() {
        let (_g, path) = write_temp(
            "auth        required      pam_faillock.so preauth silent deny=3 dir=/var/log/faillock\n",
        );
        assert_eq!(
            read_password_auth_dir_from(&path),
            Some(PathBuf::from("/var/log/faillock")),
            "a whitespace-separated `dir=/path` token on a pam_faillock.so \
             line is the RHEL8 <8.2 fallback locator (G6.2)"
        );
    }

    #[test]
    fn password_auth_ignores_dir_token_on_non_faillock_lines() {
        let (_g, path) = write_temp("auth required pam_unix.so dir=/should/not/match\n");
        assert_eq!(
            read_password_auth_dir_from(&path),
            None,
            "a `dir=` token on a line that is not a pam_faillock.so line \
             must not be picked up (G6.2 is specific to the pam_faillock \
             module line)"
        );
    }

    #[test]
    fn password_auth_first_dir_bearing_faillock_line_wins() {
        // A pam_faillock.so line with no `dir=` token does not stop the
        // scan; the loop must continue to a later pam_faillock.so line that
        // does carry one.
        let (_g, path) = write_temp(
            "auth required pam_faillock.so preauth silent\nauth [default=die] pam_faillock.so authfail deny=3 dir=/var/log/faillock\n",
        );
        assert_eq!(
            read_password_auth_dir_from(&path),
            Some(PathBuf::from("/var/log/faillock")),
            "a pam_faillock.so line without a `dir=` token must not stop \
             the scan (G6.2)"
        );
    }

    #[test]
    fn password_auth_missing_file_is_none() {
        let missing = std::path::Path::new("/nonexistent/9d-lane-2b/password-auth");
        assert_eq!(
            read_password_auth_dir_from(missing),
            None,
            "an absent/unreadable pam file yields None, never a panic or \
             fatal"
        );
    }

    #[test]
    fn password_auth_no_pam_faillock_line_is_none() {
        let (_g, path) = write_temp("auth required pam_unix.so\n");
        assert_eq!(
            read_password_auth_dir_from(&path),
            None,
            "a file with no pam_faillock.so line at all yields None"
        );
    }
}
