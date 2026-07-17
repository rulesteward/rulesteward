//! The live `SelinuxProbe` implementation (#520): shells out to
//! `getenforce`/`sestatus`/`rpm -q`/the faillock locator/`ls -Zd`. EXCLUDED
//! from the mutation gate by name (see `.cargo/mutants.toml`'s
//! `<impl SelinuxProbe for LiveSelinuxProbe>` entry) - mirrors fapolicyd
//! doctor's `LiveProbe` (no unit-test seam for real OS access; covered by the
//! e2e graceful-degradation test + live VM smoke). Implemented against the
//! grounding in `grounding/g4-g6-selinux-config.md` sections G5/G6.

use std::path::{Path, PathBuf};

use super::model::SelinuxProbe;

/// Real probe that shells out to the OS. On a host without `SELinux` tooling,
/// each method returns an `Err` string that the check functions map to
/// `CheckStatus::Unknown` (mirrors fapolicyd doctor's `LiveProbe`).
pub(super) struct LiveSelinuxProbe;

impl SelinuxProbe for LiveSelinuxProbe {
    fn enforce_status(&self) -> Result<String, String> {
        todo!("shell out to `getenforce`; parse per G5.1")
    }

    fn loaded_policy_name(&self) -> Result<Option<String>, String> {
        todo!("shell out to `sestatus`; parse the \"Loaded policy name:\" line per G5.2")
    }

    fn package_installed(&self, _name: &str) -> Result<bool, String> {
        todo!("`rpm -q <name>`; exit-status-only, mirrors doctor's rpm_plugin_installed")
    }

    fn faillock_dir(&self) -> Result<Option<PathBuf>, String> {
        todo!(
            "faillock.conf `dir=` locator, falling back to the RHEL8<8.2 pam.d inline form; G6.1/G6.2"
        )
    }

    fn dir_context_type(&self, _dir: &Path) -> Result<Option<String>, String> {
        todo!("`ls -Zd <dir>`; parse the third colon-segment from the left; G6.4")
    }
}
