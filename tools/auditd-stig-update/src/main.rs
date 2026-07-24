//! `auditd-stig-update` - derive + drift-check the auditd au-W06 STIG baseline
//! tables against the official DISA XCCDF.
//!
//! Subcommands:
//!   auditd-stig-update check [--product P]
//!                                # drift gate: derive at the pinned DISA zips and
//!                                # diff vs the shipped tables (exit 1 on drift)
//!   auditd-stig-update derive [--product P] [--file XCCDF]
//!                                # print the derived table + diff + paste-ready lines
//! Common flags: --config <stig-refs.toml>
//!
//! Mirrors `tools/sshd-stig-update/src/main.rs`'s exit-code contract EXACTLY
//! (0 in-sync / 1 drift / 2 any `Err`): see `tests/cli.rs` for the frozen proof.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use auditd_stig_update::config::{Config, Product};
use auditd_stig_update::derive::{DerivedRule, code_table, diff_rules};
use auditd_stig_update::pin::{self, Probe, ProbeError, Prober};
use auditd_stig_update::{source, xccdf};
use rulesteward_auditd::TargetVersion;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("auditd-stig-update: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("check") => cmd_check(&args[1..]),
        Some("derive") => cmd_derive(&args[1..]),
        Some("check-pin") => cmd_check_pin(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown subcommand {other:?}; try --help")),
    }
}

fn print_help() {
    eprintln!(
        "auditd-stig-update - derive + drift-check the auditd au-W06 STIG baselines\n\
         \n\
         USAGE:\n  \
           auditd-stig-update check [--product P] [--file X]   drift gate (exit 1 on drift)\n  \
           auditd-stig-update derive [--product P] [--file X]  print derived table + diff\n  \
           auditd-stig-update check-pin [--product P]          upstream-pin staleness (#550, \
             exit 0 always)\n\
         \n\
         FLAGS:\n  \
           --product P      rhel8 | rhel9 | rhel10 (default: all)\n  \
           --file XCCDF     use a local XCCDF xml instead of fetching (needs --product)\n  \
           --fixture PATH   check-pin only: scripted probe answers instead of live curl \
             (needs --product)\n  \
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
        let derived = xccdf::parse_requirements(&xml)?;
        let diff = diff_rules(&derived, &code_table(target));
        if diff.is_empty() {
            println!("{name}: OK (0 drift, {} rules)", derived.len());
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
             update crates/rulesteward-auditd/src/lints/stig_required.rs (the RHEL*_REQUIRED \
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
        let derived = xccdf::parse_requirements(&xml)?;
        let diff = diff_rules(&derived, &code_table(target));

        println!("# {name} @ {} ({} rules)", product.benchmark, derived.len());
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

/// Upstream-pin staleness check (#550): report whether a newer DISA STIG
/// revision than the pinned zip exists, per product. Non-blocking by design -
/// see `pin.rs`'s module doc - so this ALWAYS returns `Ok(ExitCode::SUCCESS)`;
/// `pin::PinStatus` (including `Unavailable`) is never converted into this
/// function's `Err` path, which `run`'s caller maps to exit 2 (see
/// `check_pin_unavailable_prober_still_exits_0_not_2` in `tests/cli.rs`).
/// `Config::load`/`selected_products` failures (a broken `stig-refs.toml`, an
/// unknown `--product`) are genuine tool errors and DO propagate as `Err`.
fn cmd_check_pin(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let fixture = flag(args, "--fixture");
    let products = selected_products(&cfg, args)?;
    if fixture.is_some() && products.len() != 1 {
        return Err(
            "--fixture requires exactly one --product (a fixture answers one product's \
             probe sequence)"
                .into(),
        );
    }

    match fixture {
        Some(path) => {
            // Checked above: exactly one product when --fixture is given.
            let (name, product) = &products[0];
            let mut prober = FixtureProber::load(Path::new(&path))?;
            let status = pin::find_latest(&cfg.base_url, &product.zip, &mut prober);
            let (msg, _code) = pin::report(name, &status);
            println!("{msg}");
        }
        None => {
            for (name, product) in &products {
                let mut prober = source::CurlProber;
                let status = pin::find_latest(&cfg.base_url, &product.zip, &mut prober);
                let (msg, _code) = pin::report(name, &status);
                println!("{msg}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// --- rendering ---------------------------------------------------------------

/// Print paste-ready Rust for a human to reconcile `stig_required.rs` against:
/// one `BaselineRule { v_number, stig_id, line }` literal per derived row.
fn print_paste_ready(name: &str, derived: &[DerivedRule]) {
    let major = name.strip_prefix("rhel").unwrap_or(name);
    println!("# paste-ready RHEL{major}_REQUIRED entries:");
    for r in derived {
        println!(
            "    BaselineRule {{ v_number: {:?}, stig_id: {:?}, line: {:?} }},",
            r.v_number, r.stig_id, r.line
        );
    }
}

// --- check-pin plumbing -------------------------------------------------------

/// A [`Prober`] driven by canned answers read from a `--fixture` file, one
/// line per probe IN ORDER: `FOUND`, `NOTFOUND`, or `ERR:<message>` - so
/// `check-pin` can be exercised end to end (`tests/cli.rs`) without CI ever
/// depending on the network (#550's central constraint). Production
/// `check-pin` runs (no `--fixture`) use `source::CurlProber` instead - see
/// `cmd_check_pin`.
struct FixtureProber {
    lines: std::collections::VecDeque<String>,
}

impl FixtureProber {
    fn load(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("read fixture {}: {e}", path.display()))?;
        Ok(FixtureProber {
            lines: s.lines().map(str::to_string).collect(),
        })
    }
}

impl Prober for FixtureProber {
    fn probe(&mut self, url: &str) -> Result<Probe, ProbeError> {
        let line = self
            .lines
            .pop_front()
            .ok_or_else(|| ProbeError(format!("fixture exhausted before probing {url}")))?;
        if line == "FOUND" {
            Ok(Probe::Found)
        } else if line == "NOTFOUND" {
            Ok(Probe::NotFound)
        } else if let Some(msg) = line.strip_prefix("ERR:") {
            Err(ProbeError(msg.to_string()))
        } else {
            Err(ProbeError(format!("unrecognized fixture line: {line:?}")))
        }
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
