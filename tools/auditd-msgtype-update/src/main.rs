//! `auditd-msgtype-update` - derive + drift-check the auditd msgtype tables
//! (`crates/rulesteward-auditd/src/lints/value/msgtype.rs`) against upstream
//! audit-userspace + kernel uapi headers.
//!
//! Subcommands:
//!   auditd-msgtype-update check [--fixtures DIR]
//!                                  # drift gate: derive (fetched, or read from
//!                                  # --fixtures for offline use) and diff vs
//!                                  # the shipped tables (exit 1 on drift)
//!   auditd-msgtype-update derive [--fixtures DIR]
//!                                  # print the derived tables for review
//! Common flags: --config <msgtype-refs.toml> (default: the committed file
//! next to the crate, via CARGO_MANIFEST_DIR).
//!
//! Exit codes (mirrors `tools/{stig,sshd-stig,fapolicyd-attr}-update`):
//! 0 in sync, 1 on drift, 2 on error (bad args, unreadable source, sha256
//! pin mismatch, parse failure, cross-source number conflict, unresolvable
//! constant).
//!
//! `--fixtures DIR` expects the committed `tests/fixtures/` shape, with the
//! subdirectory names derived from the config pins (so the layout tracks a
//! pin bump automatically):
//!   `<DIR>/<audit-userspace.commit>/msg_typetab.h`
//!   `<DIR>/<audit-userspace.commit>/audit-records.h`
//!   `<DIR>/linux-<kernel.tag>/audit.h`
//! (today: `<DIR>/3bfa048/{msg_typetab.h,audit-records.h}` +
//! `<DIR>/linux-v6.6/audit.h`).
//!
//! PROVENANCE CONTRACT: the offline `--fixtures` path must verify each file's
//! bytes against the config's sha256 pins via the SAME
//! [`auditd_msgtype_update::source::verify_sha256`] guard the live fetch path
//! uses. Without it, a `check --fixtures` PR gate would report "OK (0 drift)"
//! on corrupted or stale fixture bytes - a fail-OPEN divorcing the gate from
//! the pinned upstream provenance (the exact fail-open the sibling
//! fapolicyd-attr-update's ATL round-1 adversary found).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("auditd-msgtype-update: {e}");
            ExitCode::from(2)
        }
    }
}

/// Dispatch `check` / `derive` / help; an unknown subcommand is an `Err`
/// (exit 2). The implementer structures the subcommand bodies (mirroring
/// `tools/fapolicyd-attr-update/src/main.rs`'s `cmd_check` / `cmd_derive` /
/// `derive_version` / `read_and_verify` split); the frozen `tests/cli.rs`
/// suite pins the behavior:
/// * `check --fixtures` on the real committed fixtures + committed config:
///   exit 0, stdout carries `OK (0 drift`.
/// * `check` with a doctored (renamed-entry) fixture + pin-matching config:
///   exit 1, stdout carries `DRIFT` and names the entry.
/// * `check` with tampered fixture bytes (either upstream's file) against the
///   committed pins: exit 2, stderr names the sha256 mismatch.
/// * `check` with a cross-source number conflict: exit 2, stderr names the
///   conflicting constant.
/// * a missing fixture directory/file: exit 2.
/// * `derive --fixtures`: exit 0, prints both derived tables (entry names,
///   numbers, and the 189/8 counts).
/// * `--help`/`-h`/no args: exit 0, usage on stderr naming both subcommands
///   and both flags.
fn run(_args: &[String]) -> Result<ExitCode, String> {
    todo!("implementer: dispatch check/derive/help per the frozen tests/cli.rs contract")
}
