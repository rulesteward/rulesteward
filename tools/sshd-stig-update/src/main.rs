//! `sshd-stig-update` - derive + drift-check the sshd W01/W02 STIG baseline tables
//! against the official DISA XCCDF.
//!
//! Subcommands:
//!   sshd-stig-update check [--product P]
//!                                # drift gate: derive at the pinned DISA zips and
//!                                # diff vs the shipped tables (exit 1 on drift)
//!   sshd-stig-update derive [--product P] [--file XCCDF]
//!                                # print the derived table + diff + paste-ready lines
//! Common flags: --config <stig-refs.toml>

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rulesteward_sshd::TargetVersion;
use sshd_stig_update::config::{Config, Product};
use sshd_stig_update::derive::{DerivedControl, code_table, diff_controls};
use sshd_stig_update::{source, xccdf};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshd-stig-update: {e}");
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
        "sshd-stig-update - derive + drift-check the sshd W01/W02 STIG baselines\n\
         \n\
         USAGE:\n  \
           sshd-stig-update check [--product P] [--file X]   drift gate (exit 1 on drift)\n  \
           sshd-stig-update derive [--product P] [--file X]  print derived table + diff\n\
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
        let diff = diff_controls(&derived, &code_table(target));
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
             update crates/rulesteward-sshd/src/lints/stig.rs (required arrays + RHEL*_VNUM \
             + w02_rule), then re-run `check`."
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
        let diff = diff_controls(&derived, &code_table(target));

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
        print_paste_ready(&name, &derived);
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- rendering ---------------------------------------------------------------

/// Print paste-ready Rust for a human to reconcile `stig.rs` against: the required
/// array (keyword + V-number comment), the `RHEL*_VNUM` provenance rows, and the
/// derived value rule per keyword (to reconcile `w02_rule`).
fn print_paste_ready(name: &str, derived: &[DerivedControl]) {
    let major = name.strip_prefix("rhel").unwrap_or(name);
    println!("# paste-ready RHEL{major}_REQUIRED (keyword + V-number comment):");
    for c in derived {
        println!("    {:?}, // {}", c.keyword, c.v_number);
    }
    println!("# paste-ready RHEL{major}_VNUM (provenance map):");
    for c in derived {
        println!("    ({:?}, {:?}),", c.keyword, c.v_number);
    }
    println!("# derived value rules (reconcile w02_rule):");
    for c in derived {
        println!("#   {} -> {}", c.keyword, c.value_rule);
    }
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
