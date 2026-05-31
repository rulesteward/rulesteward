//! fapd-W05: validate `uid=` / `gid=` literals against the host identity database
//! by shelling out to `getent passwd` / `getent group` (read-only, opt-in).
//!
//! Shelling out to `getent` resolves through the host NSS stack (SSSD/LDAP/AD
//! included) and works in the static musl binary, which cannot `dlopen` NSS
//! modules - the reason a direct `/etc/passwd` parse is insufficient.
//!
//! Phase-0 stub: the W05 impl pipeline fills the getent shell-out + per-attribute
//! checks. The signature is frozen here so the fan-out edits only this file's
//! body (plus its helper) and not the shared `lints/mod.rs` dispatcher. Gated by
//! `LintContext.check_identities`.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;

/// Validate `uid=` / `gid=` literals against the host identity database.
/// Phase-0 stub returns no diagnostics; the impl fills the getent-backed check.
#[must_use]
pub(crate) fn walk(_entries: &[Entry], _file: &Path) -> Vec<Diagnostic> {
    Vec::new()
}
