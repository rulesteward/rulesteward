//! `cis-update` - derive + drift-check the per-backend CIS control tables against
//! ComplianceAsCode/content.
//!
//! Subcommands:
//!   cis-update check [--latest]         # drift gate: derive at the pinned (or
//!                                       # latest) ref, verify anchors, diff vs the
//!                                       # shipped per-backend tables (or SKIP)
//!   cis-update derive [--product P] [--ref R] [--family F] [--values]
//!                                       # print the derived per-family tables
//! Common flags: --config <cis-refs.toml>

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cis-update: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("-h" | "--help" | "help") | None => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown subcommand {other:?}; try --help")),
    }
}

fn print_help() {
    eprintln!(
        "cis-update - derive + drift-check the per-backend CIS control tables\n\
         \n\
         USAGE:\n  \
           cis-update check [--latest]             drift gate (exit 1 on drift)\n  \
           cis-update derive [--product P] [--ref R] [--family F] [--values]\n\
         \n\
         FLAGS:\n  \
           --latest         derive at the latest CaC release tag (vs the pinned ref)\n  \
           --product P      rhel8 | rhel9 | rhel10 (default: all)\n  \
           --ref R          override the upstream ref (commit/tag)\n  \
           --family F       sshd | sudoers | sysctld | auditd (default: all)\n  \
           --values         also derive sysctl VALUES for the sysctld family\n  \
           --config PATH    path to cis-refs.toml (default: next to the crate)"
    );
}
