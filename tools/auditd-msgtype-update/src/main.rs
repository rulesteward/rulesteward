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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use auditd_msgtype_update::config::Config;
use auditd_msgtype_update::parse::{self, DerivedTables};
use auditd_msgtype_update::{registry, source};

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
fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("check") => cmd_check(&args[1..]),
        Some("derive") => cmd_derive(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown subcommand {other:?}; try --help")),
    }
}

fn print_help() {
    eprintln!(
        "auditd-msgtype-update - derive + drift-check the auditd msgtype tables\n\
         \n\
         USAGE:\n  \
           auditd-msgtype-update check [--fixtures DIR]   drift gate (exit 1 on drift)\n  \
           auditd-msgtype-update derive [--fixtures DIR]  print the derived tables\n\
         \n\
         FLAGS:\n  \
           --fixtures DIR   read the pinned headers from DIR instead of fetching\n  \
           --config PATH    path to msgtype-refs.toml (default: next to the crate)"
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let fixtures = flag(args, "--fixtures");

    let derived = derive_tables(&cfg, fixtures.as_deref())?;
    let shipped = registry::shipped_tables();
    let d = registry::drift(&derived, &shipped);

    if d.is_empty() {
        println!(
            "OK (0 drift; base {} + apparmor {} entries)",
            derived.base.len(),
            derived.apparmor.len()
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!("DRIFT ({} entries) vs the shipped tables:", d.len());
        for line in &d {
            println!("  {line}");
        }
        println!(
            "\nUpstream audit-userspace/kernel headers changed. Run `derive`, review the diff, \
             update crates/rulesteward-auditd/src/lints/value/msgtype.rs, then re-copy \
             tests/fixtures/ from the new pins."
        );
        Ok(ExitCode::from(1))
    }
}

fn cmd_derive(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let fixtures = flag(args, "--fixtures");

    let derived = derive_tables(&cfg, fixtures.as_deref())?;
    println!("# base ({} entries)", derived.base.len());
    for (name, num) in &derived.base {
        println!("    ({name:?}, {num}),");
    }
    println!();
    println!("# apparmor ({} entries)", derived.apparmor.len());
    for (name, num) in &derived.apparmor {
        println!("    ({name:?}, {num}),");
    }
    Ok(ExitCode::SUCCESS)
}

// --- glue --------------------------------------------------------------------

/// Derive the (base, apparmor) tables, either from `<fixtures>/...` (a
/// `tests/fixtures/`-shaped root - the offline path every test in this crate
/// uses) or, when `fixtures` is `None`, by fetching + sha256-verifying the
/// live upstream sources (see [`auditd_msgtype_update::source`]).
///
/// The offline `--fixtures` path verifies each file's bytes against `cfg`'s
/// sha256 pins via the SAME [`source::verify_sha256`] guard the live fetch
/// path uses, fed by [`read_and_verify`] - a single seam shared by both
/// `check` and `derive`. Without it, a `check --fixtures` PR gate would
/// report "OK (0 drift)" on corrupted or stale fixture bytes that happen to
/// parse to the same tables: a fail-OPEN divorcing the gate from the pinned
/// upstream provenance.
fn derive_tables(cfg: &Config, fixtures: Option<&str>) -> Result<DerivedTables, String> {
    let (typetab_src, records_src, kernel_src) = match fixtures {
        Some(dir) => {
            let root = PathBuf::from(dir);
            let userspace_dir = root.join(&cfg.audit_userspace.commit);
            let kernel_dir = root.join(format!("linux-{}", cfg.kernel.tag));
            (
                read_and_verify(
                    &userspace_dir.join("msg_typetab.h"),
                    &cfg.audit_userspace.msg_typetab_sha256,
                    "msg_typetab.h",
                )?,
                read_and_verify(
                    &userspace_dir.join("audit-records.h"),
                    &cfg.audit_userspace.audit_records_sha256,
                    "audit-records.h",
                )?,
                read_and_verify(
                    &kernel_dir.join("audit.h"),
                    &cfg.kernel.audit_h_sha256,
                    "audit.h",
                )?,
            )
        }
        None => (
            source::fetch_userspace_source(
                &cfg.audit_userspace.commit,
                "msg_typetab.h",
                &cfg.audit_userspace.msg_typetab_sha256,
            )?,
            source::fetch_userspace_source(
                &cfg.audit_userspace.commit,
                "audit-records.h",
                &cfg.audit_userspace.audit_records_sha256,
            )?,
            source::fetch_kernel_header(&cfg.kernel.tag, &cfg.kernel.audit_h_sha256)?,
        ),
    };

    let typetab = parse::parse_typetab(&typetab_src)?;
    let records = parse::parse_defines(&records_src)?;
    let kernel = parse::parse_defines(&kernel_src)?;
    parse::resolve(&typetab, &records, &kernel)
}

/// Read `path` and verify its bytes against `expected_sha256` via
/// [`source::verify_sha256`] before returning it - the fail-closed offline
/// counterpart to the live fetch functions' own verification. `file` is
/// folded into any error for a message that names which of the three pinned
/// files failed.
fn read_and_verify(path: &Path, expected_sha256: &str, file: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {file}: {e}"))?;
    source::verify_sha256(&content, expected_sha256).map_err(|e| format!("{file}: {e}"))?;
    Ok(content)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn config_path(args: &[String]) -> PathBuf {
    flag(args, "--config").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("msgtype-refs.toml"),
        PathBuf::from,
    )
}
