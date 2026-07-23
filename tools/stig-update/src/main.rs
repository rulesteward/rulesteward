//! `stig-update` - derive + drift-check the sysctld-W02 STIG baseline tables against
//! the official DISA XCCDF.
//!
//! Subcommands:
//!   stig-update check [--product P]
//!                                # drift gate: derive at the pinned DISA zips and
//!                                # diff vs the shipped tables (exit 1 on drift)
//!   stig-update derive [--product P] [--file XCCDF]
//!                                # print the derived table + diff + paste-ready lines
//! Common flags: --config <stig-refs.toml>
//!
//! Mirrors `tools/sshd-stig-update/src/main.rs` / `tools/auditd-stig-update/src/main.rs`'s
//! exit-code contract (0 in-sync / 1 drift / 2 any `Err`) and subcommand shape (#512,
//! session 9h-v0_8-wave4 Lane B - the CaC-fetch-based `check`/`derive` wiring this
//! binary previously had is replaced by the DISA zip/base_url path those two tools
//! already use).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rulesteward_sysctld::TargetVersion;
use stig_update::config::{Config, Product};
use stig_update::derive::{DerivedKey, code_table, diff_tables};
use stig_update::{source, xccdf};

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
        "stig-update - derive + drift-check the sysctld-W02 STIG baselines\n\
         \n\
         USAGE:\n  \
           stig-update check [--product P] [--file X]   drift gate (exit 1 on drift)\n  \
           stig-update derive [--product P] [--file X]  print derived table + diff\n\
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
        let derived = xccdf::parse_baseline(&xml)?;
        let diff = diff_tables(&derived, &code_table(target));
        if diff.is_empty() {
            println!("{name}: OK (0 drift, {} keys)", derived.len());
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
             update crates/rulesteward-sysctld/src/lints/baseline.rs (the RHEL*_BASELINE \
             tables), then re-run `check`."
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
        let derived = xccdf::parse_baseline(&xml)?;
        let diff = diff_tables(&derived, &code_table(target));

        println!("# {name} @ {} ({} keys)", product.benchmark, derived.len());
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

/// Print paste-ready Rust for a human to reconcile `baseline.rs`'s `RHEL*_BASELINE`
/// const table against: one `k`/`k_exact` call per derived row (`k_exact` for the
/// one string-typed `kernel.core_pattern`, `k` for every numeric key - see
/// `crates/rulesteward-sysctld/src/lints/baseline.rs`'s own constructors).
fn print_paste_ready(name: &str, derived: &[DerivedKey]) {
    let major = name.strip_prefix("rhel").unwrap_or(name);
    println!("# paste-ready RHEL{major}_BASELINE entries:");
    for e in derived {
        let ctor = if e.numeric { "k" } else { "k_exact" };
        println!(
            "    {ctor}({:?}, &{:?}, {:?}),",
            e.key, e.accepted, e.stig_id
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    // Bonus hardening (post-GREEN Adversarial Testing Loop mutation-strengthening
    // round, session 9h-v0_8-wave4 Lane B, 2026-07-23): main.rs's small pure glue
    // functions have no dedicated tests in the sshd/auditd precedent tools either
    // (per the coordinator dispatch: "the sshd/auditd precedent tools have no
    // main.rs tests, these are bonus hardening, not gate items"), but they were
    // quick to add and cheaply lock down behavior a future edit could silently
    // break.

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn synthetic_cfg() -> Config {
        Config::parse(
            "base_url = \"https://example.test\"\n\
             [products.rhel8]\nzip = \"a.zip\"\nbenchmark = \"A\"\n\
             [products.rhel9]\nzip = \"b.zip\"\nbenchmark = \"B\"\n\
             [products.rhel10]\nzip = \"c.zip\"\nbenchmark = \"C\"\n",
        )
        .expect("valid synthetic config")
    }

    #[test]
    fn flag_finds_the_value_immediately_after_the_named_flag() {
        assert_eq!(
            flag(&args(&["--product", "rhel9"]), "--product"),
            Some("rhel9".to_string())
        );
    }

    #[test]
    fn flag_returns_none_when_the_named_flag_is_absent() {
        assert_eq!(flag(&args(&["--other", "x"]), "--product"), None);
    }

    #[test]
    fn flag_returns_none_when_the_named_flag_is_the_last_argument() {
        // A trailing flag with no following value must not panic (args.get(i+1)
        // is out of bounds) or fall back to returning the flag's own name.
        assert_eq!(flag(&args(&["--product"]), "--product"), None);
    }

    #[test]
    fn selected_products_with_no_flag_returns_every_configured_product() {
        let cfg = synthetic_cfg();
        let got = selected_products(&cfg, &[]).expect("ok");
        assert_eq!(got.len(), 3, "{got:?}");
    }

    #[test]
    fn selected_products_with_a_product_flag_returns_only_that_one() {
        let cfg = synthetic_cfg();
        let got = selected_products(&cfg, &args(&["--product", "rhel9"])).expect("ok");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "rhel9");
    }

    #[test]
    fn selected_products_with_an_unknown_product_errors() {
        let cfg = synthetic_cfg();
        let err = selected_products(&cfg, &args(&["--product", "rhel7"]))
            .expect_err("an unconfigured product must error");
        assert!(err.contains("rhel7"), "{err}");
    }

    #[test]
    fn config_path_defaults_to_stig_refs_toml_next_to_the_crate() {
        let p = config_path(&[]);
        assert!(p.ends_with("stig-refs.toml"), "{p:?}");
        assert!(
            p.starts_with(env!("CARGO_MANIFEST_DIR")),
            "default path must live next to the crate: {p:?}"
        );
    }

    #[test]
    fn config_path_honors_an_explicit_config_flag() {
        let p = config_path(&args(&["--config", "/tmp/custom-stig-refs.toml"]));
        assert_eq!(p, PathBuf::from("/tmp/custom-stig-refs.toml"));
    }

    #[test]
    fn cmd_check_file_flag_without_exactly_one_product_errors_before_any_fetch() {
        // Guards the arg-guard at cmd_check's `file.is_some() && products.len() !=
        // 1` check: --file supplied but --product omitted means `selected_products`
        // returns ALL 3 configured products, which is ambiguous against a single
        // local XCCDF file - this must error BEFORE the loop ever reaches
        // `source::fetch_xccdf`/`source::read_local` (no network, no real file
        // needed for this test - the guard fires first using the real, offline,
        // committed stig-refs.toml, which has 3 products).
        let err = cmd_check(&args(&["--file", "whatever.xml"]))
            .expect_err("must error: --file requires exactly one --product");
        assert!(
            err.contains("--file requires exactly one --product"),
            "{err}"
        );
    }
}
