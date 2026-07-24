//! The live fetch seam: download a DISA STIG zip, unzip it, and read out the
//! `*Manual-xccdf.xml`. Isolated here (a `curl` + `unzip` shell-out) so the
//! derivation core ([`crate::xccdf`]) stays offline-testable with fixtures;
//! this module is exercised only by the live `check` / `derive` runs.
//!
//! STUBBED (9j lane 6, RED phase, #551): neither function is called by any
//! offline test in this crate (mirroring `tools/sshd-stig-update`'s own
//! convention that `source.rs` carries no unit tests and is excluded from the
//! mutation gate, see `.cargo/mutants.toml`), so the test-author leaves this
//! as a `todo!()` stub rather than duplicating the sibling tools'
//! curl-plus-unzip shell-out ahead of an actual GREEN implementation pass.
//! A correct implementation mirrors
//! `tools/sshd-stig-update/src/source.rs` / `tools/auditd-stig-update/src/source.rs`
//! verbatim (same seam, same convention).

use std::path::Path;

/// Download the DISA STIG zip at `url`, unzip it, and return the contents of the
/// single `*Manual-xccdf.xml` inside.
pub fn fetch_xccdf(_url: &str) -> Result<String, String> {
    todo!(
        "GREEN: curl+unzip the DISA zip and return the *Manual-xccdf.xml contents; \
         mirror tools/sshd-stig-update/src/source.rs::fetch_xccdf verbatim (same seam)"
    )
}

/// Read a local XCCDF xml file (the offline `derive --file <path>` / `check --file <path>` path).
pub fn read_local(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}
