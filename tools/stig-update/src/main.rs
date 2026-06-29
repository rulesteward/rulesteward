//! `stig-update` - derive + drift-check the sysctld STIG baseline tables against
//! ComplianceAsCode/content.
//!
//! Subcommands:
//!   stig-update check [--latest]        # drift gate: derive at the pinned (or
//!                                       # latest) ref and diff vs the shipped tables
//!   stig-update derive [--product P] [--ref R]
//!                                       # print the derived table + diff + paste-
//!                                       # ready k(...) lines for review
//! Common flags: --config <stig-refs.toml>

use std::path::PathBuf;
use std::process::ExitCode;

use rulesteward_sysctld::TargetVersion;
use stig_update::config::Config;
use stig_update::derive::{self, DerivedKey};
use stig_update::source;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stig-update: {e}");
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
        "stig-update - derive + drift-check the sysctld STIG baselines\n\
         \n\
         USAGE:\n  \
           stig-update check [--latest]            drift gate (exit 1 on drift)\n  \
           stig-update derive [--product P] [--ref R]   print derived table + diff\n\
         \n\
         FLAGS:\n  \
           --latest         derive at the latest CaC release tag (vs the pinned ref)\n  \
           --product P      rhel8 | rhel9 | rhel10 (default: all)\n  \
           --ref R          override the upstream ref (commit/tag)\n  \
           --config PATH    path to stig-refs.toml (default: next to the crate)"
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let latest = args.iter().any(|a| a == "--latest");
    let cfg = Config::load(&config_path(args))?;
    let upstream = if latest {
        Some(source::latest_release()?)
    } else {
        None
    };

    let mut drift = false;
    for (product, pinned) in &cfg.products {
        let reff = upstream.as_deref().unwrap_or(pinned);
        eprintln!("checking {product} @ {reff} ...");
        let diff = derive::diff_tables(&derive_for(&cfg, product, reff)?, &code_table(product)?);
        if diff.is_empty() {
            println!("{product}: OK (0 drift)");
        } else {
            drift = true;
            println!("{product}: DRIFT ({} change(s)) @ {reff}", diff.len());
            for line in diff {
                println!("  {line}");
            }
        }
    }
    if drift && latest {
        println!(
            "\nUpstream changed since the pinned refs. Run `derive`, review, update \
             baseline.rs, and bump stig-refs.toml."
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
    let ref_override = flag(args, "--ref");
    let products: Vec<String> = match flag(args, "--product") {
        Some(p) => vec![p],
        None => cfg.products.keys().cloned().collect(),
    };

    for product in &products {
        let reff = ref_override
            .clone()
            .or_else(|| cfg.products.get(product).cloned())
            .ok_or_else(|| format!("no ref for {product} (pass --ref)"))?;
        eprintln!("deriving {product} @ {reff} ...");
        let derived = derive_for(&cfg, product, &reff)?;
        let diff = derive::diff_tables(&derived, &code_table(product)?);

        println!("# {product} @ {reff}  ({} keys)", derived.len());
        if diff.is_empty() {
            println!("# (no drift vs the shipped table)");
        } else {
            println!("# drift vs the shipped table:");
            for line in &diff {
                println!("#   {line}");
            }
        }
        println!(
            "# paste-ready (verbatim into RHEL{}_BASELINE):",
            major(product)
        );
        for entry in &derived {
            println!("{}", render_k(entry));
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- glue --------------------------------------------------------------------

/// Derive a product's table at `reff` (controls + git-tree + each rule.yml).
fn derive_for(cfg: &Config, product: &str, reff: &str) -> Result<Vec<DerivedKey>, String> {
    let controls = source::controls(reff, product)?;
    let tree = source::tree(reff)?;
    let get_rule = source::rule_fetcher(reff, &tree);
    derive::derive_table(&controls, product, &cfg.exclude_rules, get_rule)
}

/// The shipped Rust const table for `product`, projected into the comparison shape.
fn code_table(product: &str) -> Result<Vec<DerivedKey>, String> {
    let target = target_of(product)?;
    Ok(rulesteward_sysctld::stig_baseline(target)
        .into_iter()
        .map(|e| DerivedKey {
            key: e.key.to_string(),
            accepted: derive::normalize_set(e.accepted.iter().map(|s| (*s).to_string()).collect()),
            stig_id: e.stig_id.to_string(),
            numeric: e.numeric,
        })
        .collect())
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

fn major(product: &str) -> &str {
    product.strip_prefix("rhel").unwrap_or(product)
}

/// Render one derived row as a `baseline.rs` `k(...)` / `k_exact(...)` line, picking
/// the named accepted-set const when it matches (else an inline literal).
fn render_k(e: &DerivedKey) -> String {
    let ctor = if e.numeric { "k" } else { "k_exact" };
    let set = match e
        .accepted
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["0"] => "DISABLE".to_string(),
        ["1"] => "ENABLE".to_string(),
        ["2"] => "VALUE_2".to_string(),
        ["1", "2"] => "ONE_OR_TWO".to_string(),
        ["|/bin/false"] => "NO_CORE_DUMP".to_string(),
        other => format!(
            "&[{}]",
            other
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    format!("    {ctor}({:?}, {set}, {:?}),", e.key, e.stig_id)
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
