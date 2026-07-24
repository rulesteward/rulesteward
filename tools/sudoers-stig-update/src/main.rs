//! `sudoers-stig-update` - derive + drift-check the sudo-W04 DISA STIG
//! control-id families (`!authenticate`, the `targetpw`/`rootpw`/`runaspw`
//! pw-family, and `timestamp_timeout`) against the official DISA XCCDF (#551).
//!
//! DISA ONLY: this tool does NOT cover the sudo-CIS baseline
//! (`tools/cis-update check --family sudoers` already drift-checks that half)
//! or sudo-W06 (pinned inline in
//! `crates/rulesteward-sudoers/src/lints/tags.rs`'s `w06_stig_drift_tests`
//! module, a LOCKED 2026-07-15 decision). See `lib.rs`'s crate doc for the
//! full scope rationale.
//!
//! Subcommands:
//!   sudoers-stig-update check [--product P]
//!                                # drift gate: derive at the pinned DISA zips and
//!                                # diff vs the shipped tables (exit 1 on drift)
//!   sudoers-stig-update derive [--product P] [--file XCCDF]
//!                                # print the derived table + diff
//! Common flags: --config <stig-refs.toml>
//!
//! The subcommand dispatch below is pure glue, mirroring
//! `tools/sshd-stig-update/src/main.rs`; the actual derivation logic lives in
//! [`sudoers_stig_update::xccdf::parse_controls`] /
//! [`sudoers_stig_update::derive::code_table`] /
//! [`sudoers_stig_update::derive::diff_controls`] -- see those modules' doc
//! comments.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rulesteward_sudoers::TargetVersion;
use sudoers_stig_update::config::{Config, Product};
use sudoers_stig_update::derive::diff_controls;
use sudoers_stig_update::{derive, source, xccdf};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sudoers-stig-update: {e}");
            ExitCode::from(2)
        }
    }
}

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
        "sudoers-stig-update - derive + drift-check the sudo-W04 DISA STIG control-id \
         families\n\
         \n\
         DISA-only: does NOT cover the sudo-CIS baseline (see tools/cis-update) or \
         sudo-W06 (pinned inline in crates/rulesteward-sudoers/src/lints/tags.rs).\n\
         \n\
         USAGE:\n  \
           sudoers-stig-update check [--product P] [--file X]   drift gate (exit 1 on drift)\n  \
           sudoers-stig-update derive [--product P] [--file X]  print derived table + diff\n\
         \n\
         FLAGS:\n  \
           --product P      rhel8 | rhel9 | rhel10 (default: all)\n  \
           --file XCCDF     use a local XCCDF xml instead of fetching (needs --product)\n  \
           --config PATH    path to stig-refs.toml (default: next to the crate)"
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let file = flag(args, "--file");
    let products = selected_products(&cfg, args)?;
    if file.is_some() && products.len() != 1 {
        return Err("--file requires exactly one --product (a file is one product's XCCDF)".into());
    }
    let mut drift = false;
    for (name, product) in products {
        let target = target_of(&name)?;
        let xml = match &file {
            Some(path) => source::read_local(Path::new(path))?,
            None => {
                let url = cfg.zip_url(product);
                eprintln!("checking {name} @ {} ({url}) ...", product.benchmark);
                source::fetch_xccdf(&url)?
            }
        };
        let derived = xccdf::parse_controls(&xml)?;
        let diff = diff_controls(&derived, &derive::code_table(target));
        if diff.is_empty() {
            println!("{name}: OK (0 drift, {} controls)", derived.len());
        } else {
            drift = true;
            println!("{name}: DRIFT ({} change(s))", diff.len());
            for line in diff {
                println!("  {line}");
            }
        }
    }
    if drift {
        println!(
            "\nThe DISA XCCDF changed since the shipped tables. Run `derive`, review, and \
             update crates/rulesteward-sudoers/src/lints/stig.rs (PW_FAMILY_CONTROLS / \
             AUTHENTICATE_CONTROLS / TIMESTAMP_TIMEOUT_CONTROLS), then re-run `check`."
        );
    }
    Ok(if drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_derive(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let file = flag(args, "--file");
    let products = selected_products(&cfg, args)?;
    if file.is_some() && products.len() != 1 {
        return Err("--file requires exactly one --product (a file is one product's XCCDF)".into());
    }

    for (name, product) in products {
        let target = target_of(&name)?;
        let xml = match &file {
            Some(path) => source::read_local(Path::new(path))?,
            None => {
                let url = cfg.zip_url(product);
                eprintln!("deriving {name} @ {} ({url}) ...", product.benchmark);
                source::fetch_xccdf(&url)?
            }
        };
        let derived = xccdf::parse_controls(&xml)?;
        let diff = diff_controls(&derived, &derive::code_table(target));

        println!(
            "# {name} @ {} ({} controls)",
            product.benchmark,
            derived.len()
        );
        if diff.is_empty() {
            println!("# (no drift vs the shipped table)");
        } else {
            println!("# drift vs the shipped table:");
            for line in &diff {
                println!("#   {line}");
            }
        }
        for c in &derived {
            println!(
                "    ({:?}, {:?}), // {} ({})",
                c.family.as_str(),
                c.rule_id,
                c.title,
                c.v_number
            );
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- glue --------------------------------------------------------------------

fn selected_products<'a>(
    cfg: &'a Config,
    args: &[String],
) -> Result<Vec<(String, &'a Product)>, String> {
    match flag(args, "--product") {
        Some(p) => {
            let product = cfg
                .products
                .get(&p)
                .ok_or_else(|| format!("unknown product {p:?} (expected rhel8|rhel9|rhel10)"))?;
            Ok(vec![(p, product)])
        }
        None => Ok(cfg.products.iter().map(|(k, v)| (k.clone(), v)).collect()),
    }
}

fn target_of(product: &str) -> Result<TargetVersion, String> {
    match product {
        "rhel8" => Ok(TargetVersion::Rhel8),
        "rhel9" => Ok(TargetVersion::Rhel9),
        "rhel10" => Ok(TargetVersion::Rhel10),
        other => Err(format!(
            "unknown product {other:?} (expected rhel8|rhel9|rhel10)"
        )),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn config_path(args: &[String]) -> PathBuf {
    flag(args, "--config").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("stig-refs.toml"),
        PathBuf::from,
    )
}
