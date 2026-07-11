//! `sshd-probe-update` - probe a real `sshd` binary in Rocky 8/9/10 containers and
//! drift-check the shipped sshd E01/E04/W04 lint tables against what the daemon does.
//!
//! Subcommands:
//!   sshd-probe-update check  [--product P] [--transcript F]
//!                                # drift gate: LIVE (docker probe) by default, or
//!                                # OFFLINE against a captured transcript F.
//!                                # exit 0 in sync, 1 on drift, 2 on error.
//!   sshd-probe-update derive [--product P] [--transcript F]
//!                                # print the probe-derived sets + diff + paste-ready lines.
//! Flags: --product rhel8|rhel9|rhel10 (default: all); --transcript F (offline
//! JSONL; requires exactly one --product); --file F (alias for --transcript).

use std::path::Path;
use std::process::ExitCode;

use rulesteward_sshd::TargetVersion;
use rulesteward_sshd::lints::registry::known_keywords;
use sshd_probe_update::derive::{DriftReport, diff_target};
use sshd_probe_update::{discover, probe, transcript};

/// A guaranteed-unrecognized keyword seeded into the candidate list so every run
/// exercises the "unknown" classification path end to end.
const BOGUS: &str = "zzzz_rulesteward_probe_bogus";

/// One probeable product: its `--product` name, backend `TargetVersion`, and the
/// local docker image (built from `dockerfiles/<n>/Dockerfile`).
struct Product {
    name: &'static str,
    target: TargetVersion,
    image: &'static str,
}

const PRODUCTS: [Product; 3] = [
    Product {
        name: "rhel8",
        target: TargetVersion::Rhel8,
        image: "sshd-probe8",
    },
    Product {
        name: "rhel9",
        target: TargetVersion::Rhel9,
        image: "sshd-probe9",
    },
    Product {
        name: "rhel10",
        target: TargetVersion::Rhel10,
        image: "sshd-probe10",
    },
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshd-probe-update: {e}");
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
        "sshd-probe-update - probe a real sshd binary and drift-check the sshd E01/E04/W04 tables\n\
         \n\
         USAGE:\n  \
           sshd-probe-update check  [--product P] [--transcript F]  drift gate (exit 1 on drift)\n  \
           sshd-probe-update derive [--product P] [--transcript F]  print derived sets + diff\n\
         \n\
         FLAGS:\n  \
           --product P       rhel8 | rhel9 | rhel10 (default: all)\n  \
           --transcript F    offline: read a captured JSONL probe transcript (needs one --product)\n  \
           --file F          alias for --transcript\n\
         \n\
         Without --transcript, `check`/`derive` probe LIVE via docker images\n  \
         sshd-probe8 / sshd-probe9 / sshd-probe10 (build from dockerfiles/<n>/Dockerfile).\n  \
         A best-effort `man sshd_config` keyword-discovery pass (#471) widens the\n  \
         LIVE candidate universe beyond known_keywords plus a bogus sentinel and\n  \
         reports any man-listed keyword absent from the registry as an advisory\n  \
         (never gate-failing; not run over an offline --transcript)."
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let products = selected_products(args)?;
    let transcript_path = transcript_flag(args);
    require_single_product_for_transcript(transcript_path.as_deref(), &products)?;

    let mut any_drift = false;
    for p in &products {
        let report = report_for(p, transcript_path.as_deref())?;
        print_check(&report, p.name);
        if !report.is_in_sync() {
            any_drift = true;
        }
    }
    if any_drift {
        println!(
            "\nThe live daemon disagrees with the shipped tables. Update \
             crates/rulesteward-sshd (registry.rs / structural/e04.rs / deprecation.rs) \
             to match, then re-run `check`."
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
    let transcript_path = transcript_flag(args);
    require_single_product_for_transcript(transcript_path.as_deref(), &products)?;

    for p in &products {
        let report = report_for(p, transcript_path.as_deref())?;
        print_derive(&report, p.name);
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// --- report acquisition ------------------------------------------------------

/// Obtain the drift report for one product: read `transcript_path` (offline) or
/// probe the product's docker image live.
fn report_for(p: &Product, transcript_path: Option<&str>) -> Result<DriftReport, String> {
    match transcript_path {
        Some(path) => {
            let t = transcript::read_transcript(Path::new(path))?;
            Ok(diff_target(&t, p.target))
        }
        None => {
            eprintln!("probing {} via docker image {} ...", p.name, p.image);
            live_report(p)
        }
    }
}

/// Live-probe `p`'s docker image, running the best-effort `man sshd_config`
/// keyword-discovery pass (#471) alongside the normal E01/W04/E04 probe.
///
/// Discovered keywords are appended to the candidate universe so the daemon
/// probes them like any other candidate, but their transcript records are
/// held OUT of `diff_target`'s E01/W04/E04 comparison (they are never in the
/// shipped tables by construction) and instead reported as one advisory line
/// each - discovery never affects `is_in_sync()`/exit codes. Only the
/// fetch/probe steps here touch docker; the discovery split + advisory
/// assembly is the pure, offline-testable `discover::assemble_discovery`.
fn live_report(p: &Product) -> Result<DriftReport, String> {
    let cands = candidates(p.target);

    let mut discovered: Vec<String> = Vec::new();
    let mut unavailable_reason: Option<String> = None;
    // Always true by construction (report_for's None arm is the only caller);
    // kept as the tested LIVE-only predicate seam.
    if discovery_enabled(None) {
        match discover_man_keywords(p.image) {
            Ok(extracted) => {
                discovered = discover::man_only_keywords(&extracted, &known_keywords(p.target));
            }
            Err(reason) => unavailable_reason = Some(reason),
        }
    }

    let mut probe_cands: Vec<&str> = cands;
    probe_cands.extend(discovered.iter().map(String::as_str));
    let t = probe::probe_live(p.image, &probe_cands)?;

    let (core, mut advisories) = discover::assemble_discovery(t, &discovered);
    let mut report = diff_target(&core, p.target);
    report.advisories.append(&mut advisories);
    if let Some(reason) = unavailable_reason {
        report
            .advisories
            .push(discover::discovery_unavailable_advisory(&reason));
    }
    Ok(report)
}

/// Fetch the LIVE `sshd_config(5)` man page source from `image` (docker) and
/// delegate to the pure `discover::keywords_from_roff` for extraction. `Err`
/// names why discovery could not run this time (man page absent/unreadable,
/// or zero top-level `.It Cm` entries found) - a normal, expected,
/// non-gate-failing outcome, never a hard tool error.
fn discover_man_keywords(image: &str) -> Result<Vec<String>, String> {
    let roff = probe::fetch_manpage_source(image)?
        .ok_or_else(|| "man page absent or unreadable in the probe image".to_string())?;
    discover::keywords_from_roff(&roff)
}

/// The candidate keyword universe for `target`: every shipped registry keyword
/// plus a guaranteed-bogus sentinel. Boundary keywords are already covered by the
/// registry, so no extra seeds are needed (verify-only, option C).
fn candidates(target: TargetVersion) -> Vec<&'static str> {
    let mut c = known_keywords(target);
    c.push(BOGUS);
    c
}

// --- rendering ---------------------------------------------------------------

fn print_check(report: &DriftReport, name: &str) {
    if report.is_in_sync() {
        println!("{name}: OK (0 drift)");
    } else {
        println!("{name}: DRIFT ({} change(s))", report.drift_count());
        for line in report.drift_lines() {
            println!("  {line}");
        }
    }
    for a in &report.advisories {
        println!("  {a}");
    }
}

/// Print the probe-derived sets + drift + paste-ready keyword rows a maintainer
/// can reconcile the shipped tables against.
fn print_derive(report: &DriftReport, name: &str) {
    println!(
        "# {name} (E01 known={}, W04 deprecated={}, E04 permitted={})",
        report.probe.known.len(),
        report.probe.deprecated.len(),
        report.probe.permitted.len()
    );
    if report.is_in_sync() {
        println!("# (no drift vs the shipped tables)");
    } else {
        println!("# drift vs the shipped tables:");
        for line in report.drift_lines() {
            println!("#   {line}");
        }
    }
    for a in &report.advisories {
        println!("# {a}");
    }
    print_rows(
        "E01 known_keywords (probe-derived)",
        report.probe.known.iter(),
    );
    print_rows(
        "W04 deprecated (probe-derived, overlays excluded)",
        report.probe.deprecated.iter(),
    );
    print_rows(
        "E04 match-permitted (probe-derived)",
        report.probe.permitted.iter(),
    );
}

/// Print a labelled block of quoted, comma-terminated keyword rows.
fn print_rows<'a>(label: &str, rows: impl Iterator<Item = &'a String>) {
    println!("# paste-ready {label}:");
    for kw in rows {
        println!("    {kw:?},");
    }
}

// --- glue --------------------------------------------------------------------

fn selected_products(args: &[String]) -> Result<Vec<&'static Product>, String> {
    match flag(args, "--product") {
        Some(p) => {
            let product = PRODUCTS
                .iter()
                .find(|x| x.name == p)
                .ok_or_else(|| format!("unknown product {p:?} (expected rhel8|rhel9|rhel10)"))?;
            Ok(vec![product])
        }
        None => Ok(PRODUCTS.iter().collect()),
    }
}

/// A transcript is one product's probe run, so `--transcript` needs exactly one
/// `--product` selected.
fn require_single_product_for_transcript(
    transcript_path: Option<&str>,
    products: &[&Product],
) -> Result<(), String> {
    if transcript_path.is_some() && products.len() != 1 {
        return Err(
            "--transcript requires exactly one --product (a transcript is one product's probe)"
                .into(),
        );
    }
    Ok(())
}

/// The transcript path from `--transcript`, or its `--file` alias.
fn transcript_flag(args: &[String]) -> Option<String> {
    flag(args, "--transcript").or_else(|| flag(args, "--file"))
}

/// Whether the best-effort `man sshd_config` keyword-discovery pass (#471)
/// should run for this report acquisition: LIVE only. The offline
/// `--transcript`/`--file` path has no docker container to discover a man
/// page in, so discovery is gated off whenever a transcript path is given -
/// mirrors the `None` (live) vs `Some` (offline) split in `report_for`.
fn discovery_enabled(transcript_path: Option<&str>) -> bool {
    transcript_path.is_none()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flag_reads_value_after_name() {
        let a = owned(&["check", "--product", "rhel9"]);
        assert_eq!(flag(&a, "--product"), Some("rhel9".to_string()));
        assert_eq!(flag(&a, "--transcript"), None);
    }

    #[test]
    fn transcript_flag_accepts_file_alias() {
        let a = owned(&["--file", "/x.jsonl"]);
        assert_eq!(transcript_flag(&a), Some("/x.jsonl".to_string()));
    }

    #[test]
    fn selected_products_defaults_to_all_three() {
        assert_eq!(selected_products(&[]).unwrap().len(), 3);
    }

    #[test]
    fn selected_products_filters_by_name() {
        let a = owned(&["--product", "rhel10"]);
        let sel = selected_products(&a).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].name, "rhel10");
        assert_eq!(sel[0].target, TargetVersion::Rhel10);
    }

    #[test]
    fn selected_products_rejects_unknown() {
        let a = owned(&["--product", "rhel42"]);
        assert!(selected_products(&a).is_err());
    }

    #[test]
    fn transcript_requires_single_product() {
        let three: Vec<&Product> = PRODUCTS.iter().collect();
        assert!(require_single_product_for_transcript(Some("/x"), &three).is_err());
        assert!(require_single_product_for_transcript(Some("/x"), &three[..1]).is_ok());
        assert!(require_single_product_for_transcript(None, &three).is_ok());
    }

    #[test]
    fn candidates_include_registry_plus_bogus() {
        let c = candidates(TargetVersion::Rhel9);
        assert_eq!(c.len(), known_keywords(TargetVersion::Rhel9).len() + 1);
        assert!(c.contains(&BOGUS));
    }

    /// #471: man-page keyword discovery must be LIVE-only. `report_for`
    /// passes `None` for a live probe and `Some(path)` for an offline
    /// `--transcript`/`--file` run; discovery must be enabled in exactly the
    /// former case.
    #[test]
    fn discovery_enabled_only_for_live_probing() {
        assert!(
            discovery_enabled(None),
            "live probing (no transcript path) must enable discovery"
        );
        assert!(
            !discovery_enabled(Some("/x.jsonl")),
            "an offline transcript path must disable discovery"
        );
    }
}
