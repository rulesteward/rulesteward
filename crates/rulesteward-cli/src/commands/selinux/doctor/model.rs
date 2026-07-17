//! The `SelinuxProbe` dependency-injection seam for `rulesteward selinux
//! doctor` (#520).
//!
//! Mirrors fapolicyd doctor's `SystemProbe` (PR #133/#173): all environment
//! I/O (`getenforce`, `sestatus`, `rpm -q`, the faillock locator, `ls -Zd`) is
//! routed through this trait so the 5 check-classification functions in
//! `checks.rs` are pure over plain data and unit-testable with a `FakeProbe`,
//! without touching the real OS. See
//! `grounding/g4-g6-selinux-config.md` sections G5/G6 for the exact output
//! shapes each method must parse.

use std::path::{Path, PathBuf};

/// Trait for all environment I/O the selinux doctor checks use.
pub(super) trait SelinuxProbe {
    /// `getenforce` output: exactly one of `"Enforcing"` / `"Permissive"` /
    /// `"Disabled"` (capitalized, G5.1). `Err` on a non-zero exit / absent
    /// binary.
    fn enforce_status(&self) -> Result<String, String>;

    /// The `sestatus` "Loaded policy name:" value (G5.2). `None` when
    /// `SELinux` is disabled (`sestatus` omits the line entirely in that
    /// state - NOT a parse failure). `Err` on a non-zero exit / absent binary.
    fn loaded_policy_name(&self) -> Result<Option<String>, String>;

    /// Whether the named RPM package is installed (`rpm -q <name>`).
    fn package_installed(&self, name: &str) -> Result<bool, String>;

    /// The faillock tally directory to inspect (G6.1/G6.2 locator:
    /// `faillock.conf`'s `dir=`, falling back to the RHEL8<8.2 `pam.d`
    /// inline form). `Ok(None)` means "not applicable" (the STIG NA
    /// condition, G6.3) - maps to `CheckStatus::Skip`, NOT `Unknown`.
    fn faillock_dir(&self) -> Result<Option<PathBuf>, String>;

    /// The `SELinux` type segment of `ls -Zd <dir>`'s context (G6.4: the
    /// THIRD colon-separated segment counting from the left). `Ok(None)`
    /// means the directory does not exist on disk.
    fn dir_context_type(&self, dir: &Path) -> Result<Option<String>, String>;
}
