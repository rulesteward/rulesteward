//! `fapolicyd-probe-update` - probe fapolicyd8/9/10 and drift-check the shipped
//! version-map / pattern= value-set / fapd-E07 type-category tables against what the
//! daemon actually does (#478).
//!
//! Subcommands:
//!   fapolicyd-probe-update check  [--target T] [--transcript-dir DIR]
//!                                # drift gate: LIVE (docker probe) by default, or
//!                                # OFFLINE against a captured transcript directory.
//!                                # exit 0 in sync, 1 on drift, 2 on error.
//!   fapolicyd-probe-update derive [--target T] [--transcript-dir DIR]
//!                                # print the probe-derived sets + diff.
//! Flags: --target rhel8|rhel9|rhel10 (default: all); --transcript-dir DIR (offline;
//! requires exactly one --target; reads DIR/fapolicyd<N>-{version,pattern,e07}.tsv).
//!
//! This file is CLI plumbing only (arg parsing, subcommand dispatch, rendering); the
//! parse/derive/check LOGIC it calls into ([`fapolicyd_probe_update::transcript`],
//! [`fapolicyd_probe_update::derive`]) was `todo!()`-stubbed during the
//! RED-test-authoring pass (issue #478) and filled in by a later implementer pass.
//! `tests/cli.rs` pins the exit-code / output contract.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fapolicyd_probe_update::derive::{CheckReport, check_target};
use fapolicyd_probe_update::{probe, transcript};
use rulesteward_fapolicyd::TargetVersion;

/// One probeable product: its `--target` name, backend `TargetVersion`, and the
/// prebuilt docker image name (see `src/probe.rs` - unlike
/// `tools/sshd-probe-update`, these images are NOT built by this tool).
struct Product {
    name: &'static str,
    target: TargetVersion,
    image: &'static str,
}

const PRODUCTS: [Product; 3] = [
    Product {
        name: "rhel8",
        target: TargetVersion::Rhel8,
        image: "fapolicyd8",
    },
    Product {
        name: "rhel9",
        target: TargetVersion::Rhel9,
        image: "fapolicyd9",
    },
    Product {
        name: "rhel10",
        target: TargetVersion::Rhel10,
        image: "fapolicyd10",
    },
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fapolicyd-probe-update: {e}");
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
        "fapolicyd-probe-update - probe fapolicyd8/9/10 and drift-check the version-map / \
         pattern= value-set / fapd-E07 type-category tables\n\
         \n\
         USAGE:\n  \
           fapolicyd-probe-update check  [--target T] [--transcript-dir DIR]  drift gate (exit 1 on drift)\n  \
           fapolicyd-probe-update derive [--target T] [--transcript-dir DIR]  print derived sets + diff\n\
         \n\
         FLAGS:\n  \
           --target T           rhel8 | rhel9 | rhel10 (default: all)\n  \
           --transcript-dir DIR offline: read DIR/fapolicyd<N>-{{version,pattern,e07}}.tsv (needs one --target)\n\
         \n\
         Without --transcript-dir, `check`/`derive` probe LIVE via the prebuilt docker\n  \
         images fapolicyd8 / fapolicyd9 / fapolicyd10 (see this repo's CLAUDE.md\n  \
         \"Differential verification\" section)."
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let products = selected_products(args)?;
    let dir = transcript_dir_flag(args);
    require_single_product_for_transcript_dir(dir.as_deref(), &products)?;

    let mut any_drift = false;
    for p in &products {
        let report = report_for(p, dir.as_deref())?;
        print_check(&report, p.name);
        if !report.is_in_sync() {
            any_drift = true;
        }
    }
    if any_drift {
        println!(
            "\nThe live daemon disagrees with the shipped tables. Update \
             crates/rulesteward-fapolicyd (version.rs / lints/version_target.rs / \
             attrs.rs) to match, then re-run `check`."
        );
    }
    Ok(if any_drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_derive(args: &[String]) -> Result<ExitCode, String> {
    let products = selected_products(args)?;
    let dir = transcript_dir_flag(args);
    require_single_product_for_transcript_dir(dir.as_deref(), &products)?;

    for p in &products {
        let report = report_for(p, dir.as_deref())?;
        print_derive(&report, p.name);
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- report acquisition ------------------------------------------------------

/// Obtain the combined drift report for one product: read the 3 offline fixture
/// files under `dir` (`--transcript-dir`), or probe the product's docker image live.
fn report_for(p: &Product, dir: Option<&str>) -> Result<CheckReport, String> {
    let (version, pattern, e07) = match dir {
        Some(d) => {
            let base = Path::new(d);
            (
                transcript::read_transcript(&fixture_path(base, p.name, "version"))?,
                transcript::read_transcript(&fixture_path(base, p.name, "pattern"))?,
                transcript::read_transcript(&fixture_path(base, p.name, "e07"))?,
            )
        }
        None => {
            eprintln!("probing {} via docker image {} ...", p.name, p.image);
            (
                probe::probe_live(p.image, "version")?,
                probe::probe_live(p.image, "pattern")?,
                probe::probe_live(p.image, "e07")?,
            )
        }
    };
    check_target(&version, &pattern, &e07, p.target)
}

/// The committed/offline fixture path for one product's dataset, e.g.
/// `<dir>/fapolicyd8-pattern.tsv` for `product_name = "rhel8"`,
/// `dataset = "pattern"` (matches `tests/fixtures/`'s naming).
fn fixture_path(dir: &Path, product_name: &str, dataset: &str) -> PathBuf {
    let n = product_name.trim_start_matches("rhel");
    dir.join(format!("fapolicyd{n}-{dataset}.tsv"))
}

// --- rendering ---------------------------------------------------------------

fn print_check(report: &CheckReport, name: &str) {
    if report.is_in_sync() {
        println!("{name}: OK (0 drift)");
    } else {
        println!("{name}: DRIFT ({} change(s))", report.drift_count());
        for line in report.drift_lines() {
            println!("  {line}");
        }
    }
}

/// Print the probe-derived diff for one product: in-sync note or the drift lines.
fn print_derive(report: &CheckReport, name: &str) {
    println!("# {name}");
    if report.is_in_sync() {
        println!("# (no drift vs the shipped tables)");
    } else {
        println!("# drift vs the shipped tables:");
        for line in report.drift_lines() {
            println!("#   {line}");
        }
    }
}

// --- glue --------------------------------------------------------------------

fn selected_products(args: &[String]) -> Result<Vec<&'static Product>, String> {
    match flag(args, "--target") {
        Some(t) => {
            let product = PRODUCTS
                .iter()
                .find(|x| x.name == t)
                .ok_or_else(|| format!("unknown target {t:?} (expected rhel8|rhel9|rhel10)"))?;
            Ok(vec![product])
        }
        None => Ok(PRODUCTS.iter().collect()),
    }
}

/// A transcript directory is one product's probe, so `--transcript-dir` needs
/// exactly one `--target` selected.
fn require_single_product_for_transcript_dir(
    dir: Option<&str>,
    products: &[&Product],
) -> Result<(), String> {
    if dir.is_some() && products.len() != 1 {
        return Err(
            "--transcript-dir requires exactly one --target (a transcript directory \
             is one target's probe)"
                .into(),
        );
    }
    Ok(())
}

fn transcript_dir_flag(args: &[String]) -> Option<String> {
    flag(args, "--transcript-dir")
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// NOTE (RED-test-authoring pass, issue #478): the plumbing helpers above (`flag`,
// `selected_products`, `transcript_dir_flag`, `require_single_product_for_transcript_dir`,
// `fixture_path`) are fully implemented, not `todo!()` stubs - they are pure CLI-arg
// parsing, outside the "parse/derive/check" domain-logic scope this pass excludes.
// They intentionally have NO unit tests here: this session's gate requires every
// authored test in this crate to currently FAIL (a mechanical 100%-RED barrier
// check), and a test asserting these already-correct functions' current behavior
// would pass today. `tests/cli.rs` exercises the full pipeline (which panics inside
// the still-`todo!()` transcript::parse_tsv / derive::check_* core) so every
// authored test in this crate is RED. A future implementer session is free to add
// direct unit tests for this plumbing alongside filling in the stubs.
