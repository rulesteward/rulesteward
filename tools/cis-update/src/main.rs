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
//!
//! This file is thin dispatch only (stig-update precedent): every decision that
//! matters - skip/OK/DRIFT wording, the automated-only diff, anchor pairs, the
//! pinned-vs-latest health classification - is unit-locked in the lib modules.

use std::path::PathBuf;
use std::process::ExitCode;

use cis_update::config::Config;
use cis_update::family::{self, Family};
use cis_update::report::{self, HealthFailure};
use cis_update::{controls, registry, source, values};
use stig_update::source as stig_source;

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

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let latest = args.iter().any(|a| a == "--latest");
    let cfg = Config::load(&config_path(args))?;
    let upstream = if latest {
        Some(stig_source::latest_release()?)
    } else {
        None
    };

    let mut drift = false;
    for (product, pinned) in &cfg.products {
        let reff = upstream.as_deref().unwrap_or(pinned);
        eprintln!("checking {product} @ {reff} ...");
        let Some(text) = source::controls_optional(reff, product)? else {
            if latest {
                println!("{product}: not present at {reff} (not yet released); skipped");
                continue;
            }
            return Err(format!(
                "{product}: CIS controls file not found at the pinned ref {reff}"
            ));
        };
        let (_header, parsed) = controls::parse(product, &text)?;
        let groups = family::group(&parsed);

        // Health: all four families derive non-empty AND the sudoers anchors are
        // present. At a pinned ref a failure is a misconfiguration (exit 2); under
        // --latest it is upstream drift (renumbering) and joins the report.
        let health = report::family_health(&groups, product).and_then(|()| {
            report::verify_anchors(
                product,
                groups.get(&Family::Sudoers).map_or(&[], Vec::as_slice),
            )
        });
        if let Err(msg) = health {
            match report::classify_health_failure(latest, msg) {
                HealthFailure::PinnedMisconfiguration(m) => return Err(m),
                HealthFailure::UpstreamDrift(m) => {
                    drift = true;
                    println!("{product}: {m}");
                }
            }
        }

        for fam in Family::ALL {
            let rows = groups.get(&fam).map_or(&[][..], Vec::as_slice);
            let shipped = registry::shipped(fam, product)?;
            let (lines, fam_drift) = report::check_family(product, fam, rows, &shipped);
            for line in lines {
                println!("{line}");
            }
            drift |= fam_drift;
        }
    }
    if drift && latest {
        println!(
            "\nUpstream changed since the pinned refs. Run `derive`, review, update \
             the per-backend CIS tables, and bump cis-refs.toml."
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
    let family_filter = flag(args, "--family")
        .map(|f| Family::parse(&f))
        .transpose()?;
    let want_values = args.iter().any(|a| a == "--values");
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
        let text = source::controls_optional(&reff, product)?
            .ok_or_else(|| format!("{product}: CIS controls file not found at {reff}"))?;
        let (header, parsed) = controls::parse(product, &text)?;
        let groups = family::group(&parsed);
        print!(
            "{}",
            report::render_derive(product, &reff, &header, &groups, family_filter)
        );

        if want_values {
            if family_filter.is_some_and(|f| f != Family::Sysctld) {
                eprintln!("--values applies to the sysctld family only; ignored for this filter");
            } else {
                let tree = stig_source::tree(&reff)?;
                let get_rule = stig_source::rule_fetcher(&reff, &tree);
                let vals = values::sysctl_values(&parsed, product, &cfg.exclude_rules, get_rule)?;
                print!("{}", report::render_values(&vals));
            }
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- glue --------------------------------------------------------------------

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn config_path(args: &[String]) -> PathBuf {
    flag(args, "--config").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cis-refs.toml"),
        PathBuf::from,
    )
}

#[cfg(test)]
mod tests {
    use super::{config_path, flag, run};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flag_returns_the_value_after_the_name() {
        let a = args(&["derive", "--product", "rhel9", "--ref", "abc"]);
        assert_eq!(flag(&a, "--product").as_deref(), Some("rhel9"));
        assert_eq!(flag(&a, "--ref").as_deref(), Some("abc"));
        assert_eq!(flag(&a, "--config"), None);
        // A flag at the end with no value yields None, not a panic.
        assert_eq!(flag(&args(&["check", "--config"]), "--config"), None);
    }

    #[test]
    fn config_path_defaults_beside_the_crate_and_honors_override() {
        assert!(config_path(&[]).ends_with("cis-refs.toml"));
        assert_eq!(
            config_path(&args(&["--config", "/tmp/other.toml"])),
            std::path::PathBuf::from("/tmp/other.toml")
        );
    }

    #[test]
    fn run_rejects_unknown_subcommands_and_accepts_help() {
        let e = run(&args(&["frobnicate"])).unwrap_err();
        assert!(e.contains("frobnicate"), "{e}");
        assert!(run(&args(&["--help"])).is_ok());
        assert!(run(&[]).is_ok());
    }
}
