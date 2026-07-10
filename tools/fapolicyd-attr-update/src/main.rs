//! `fapolicyd-attr-update` - derive + drift-check the fapd-E01 attribute registry
//! (`crates/rulesteward-fapolicyd/src/attrs.rs`) against upstream fapolicyd's
//! `src/library/{subject,object}-attr.c`.
//!
//! Subcommands:
//!   fapolicyd-attr-update check [--fixtures DIR]
//!                                  # drift gate: derive at every pinned version
//!                                  # (fetched, or read from --fixtures/<version>/
//!                                  # for offline use) and diff vs the shipped
//!                                  # registry (exit 1 on drift)
//!   fapolicyd-attr-update derive [--version V] [--fixtures DIR]
//!                                  # print the derived registry per version
//! Common flags: --config <attr-refs.toml>
//!
//! Exit codes (mirrors `tools/{stig,sshd-stig}-update`): 0 in sync, 1 on drift,
//! 2 on error (bad args, unreadable/unparseable source).
//!
//! NOTE on `--fixtures DIR` vs `tools/stig-update`'s `--file FILE`: this tool
//! parses TWO files (subject + object) per pinned VERSION, not one file per
//! product, so the offline override is a directory shaped like the committed
//! `tests/fixtures/` (`DIR/<version>/subject-attr.c`, `DIR/<version>/object-attr.c`)
//! rather than a single `--file`.

use std::path::PathBuf;
use std::process::ExitCode;

use fapolicyd_attr_update::config::{Config, VersionRef};
use fapolicyd_attr_update::parse::{self, DerivedAttr};
use fapolicyd_attr_update::{registry, source};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fapolicyd-attr-update: {e}");
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
        "fapolicyd-attr-update - derive + drift-check the fapd-E01 attribute registry\n\
         \n\
         USAGE:\n  \
           fapolicyd-attr-update check [--fixtures DIR]                 drift gate (exit 1 on drift)\n  \
           fapolicyd-attr-update derive [--version V] [--fixtures DIR]  print the derived registry\n\
         \n\
         FLAGS:\n  \
           --fixtures DIR   read <DIR>/<version>/{{subject,object}}-attr.c instead of fetching\n  \
           --version V      only derive one pinned fapolicyd version (default: all)\n  \
           --config PATH    path to attr-refs.toml (default: next to the crate)"
    );
}

// --- subcommands -------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let fixtures = flag(args, "--fixtures");

    let mut derived_union: Vec<DerivedAttr> = Vec::new();
    let mut newest: Option<(String, Vec<DerivedAttr>)> = None;
    for (version, reference) in &cfg.versions {
        let attrs = derive_version(version, reference, fixtures.as_deref())?;
        derived_union.extend(attrs.clone());
        // `cfg.versions` is a `BTreeMap`, so this loop visits versions in
        // ascending string order. For the two versions pinned today ("1.3.2" <
        // "1.4.5" lexically matches release order), the LAST iteration is the
        // newest - the version the side-level drift check runs against (see
        // `crate::registry`'s module doc for why side drift is single-version).
        // Revisit this ordering assumption if a future pin ever needs a
        // non-lexical release ordering (e.g. a "1.10.0").
        newest = Some((version.clone(), attrs));
    }
    let (newest_version, newest_attrs) = newest.ok_or("attr-refs.toml has no pinned [versions]")?;

    let shipped = registry::shipped_registry();
    let name_drift = registry::name_drift(&parse::names(&derived_union), &parse::names(&shipped));
    let side_drift = registry::side_drift(&newest_attrs, &shipped);

    if name_drift.is_empty() && side_drift.is_empty() {
        println!(
            "OK (0 drift; {} version(s) checked, side check @ {newest_version})",
            cfg.versions.len()
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "DRIFT ({} name, {} side) vs the shipped registry:",
            name_drift.len(),
            side_drift.len()
        );
        for line in name_drift.iter().chain(side_drift.iter()) {
            println!("  {line}");
        }
        println!(
            "\nUpstream fapolicyd's attribute tables changed. Run `derive`, review, and update \
             crates/rulesteward-fapolicyd/src/attrs.rs, then re-copy tests/fixtures/<version>/*.c."
        );
        Ok(ExitCode::from(1))
    }
}

fn cmd_derive(args: &[String]) -> Result<ExitCode, String> {
    let cfg = Config::load(&config_path(args))?;
    let fixtures = flag(args, "--fixtures");
    let only_version = flag(args, "--version");

    let mut printed_any = false;
    for (version, reference) in &cfg.versions {
        if let Some(want) = &only_version
            && want != version
        {
            continue;
        }
        printed_any = true;
        let attrs = derive_version(version, reference, fixtures.as_deref())?;
        println!("# fapolicyd {version} ({} names)", attrs.len());
        for a in &attrs {
            println!("{}", render_row(a));
        }
        println!();
    }
    if !printed_any && let Some(want) = &only_version {
        return Err(format!(
            "unknown --version {want:?} (not in attr-refs.toml's [versions])"
        ));
    }
    Ok(ExitCode::SUCCESS)
}

// --- glue --------------------------------------------------------------------

/// Derive one pinned version's registry, either from `<fixtures>/<version>/` (a
/// `tests/fixtures/`-shaped directory - the offline path every test in this
/// crate uses) or, when `fixtures` is `None`, by fetching + sha256-verifying the
/// live upstream source (see [`fapolicyd_attr_update::source`]).
///
/// The offline `--fixtures` path verifies each file's bytes against `reference`'s
/// sha256 pins via the SAME [`source::verify_sha256`] guard the live fetch path
/// uses (via [`source::fetch_source`]), fed by [`read_and_verify`] - a single
/// seam shared by both `check` and `derive` (both call this function). Without
/// it, a `check --fixtures` PR gate would report "OK (0 drift)" on corrupted or
/// stale fixture bytes that happen to parse to the same registry: a fail-OPEN
/// divorcing the gate from the pinned upstream provenance.
fn derive_version(
    version: &str,
    reference: &VersionRef,
    fixtures: Option<&str>,
) -> Result<Vec<DerivedAttr>, String> {
    let (subject_src, object_src) = match fixtures {
        Some(dir) => {
            let root = PathBuf::from(dir).join(version);
            (
                read_and_verify(
                    &root.join("subject-attr.c"),
                    &reference.subject_sha256,
                    version,
                    "subject-attr.c",
                )?,
                read_and_verify(
                    &root.join("object-attr.c"),
                    &reference.object_sha256,
                    version,
                    "object-attr.c",
                )?,
            )
        }
        None => (
            source::fetch_source(&reference.tag, "subject-attr.c", &reference.subject_sha256)?,
            source::fetch_source(&reference.tag, "object-attr.c", &reference.object_sha256)?,
        ),
    };

    let subject = parse::parse_subject_table2(&subject_src)?;
    let object_literal = parse::parse_object_table(&object_src)?;
    let object = parse::apply_object_alias_exceptions(object_literal);
    Ok(parse::classify(&subject, &object))
}

/// Read `path` and verify its bytes against `expected_sha256` via
/// [`source::verify_sha256`] before returning it - the fail-closed offline
/// counterpart to [`source::fetch_source`]'s live-fetch verification. `version`
/// and `file` are folded into any error for a message that names both which
/// pinned version and which of the two files failed.
fn read_and_verify(
    path: &std::path::Path,
    expected_sha256: &str,
    version: &str,
    file: &str,
) -> Result<String, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("{version}: read {file}: {e}"))?;
    source::verify_sha256(&content, expected_sha256)
        .map_err(|e| format!("{version}: {file}: {e}"))?;
    Ok(content)
}

fn render_row(a: &DerivedAttr) -> String {
    format!("    ({:?}, {:?}),", a.name, a.side)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn config_path(args: &[String]) -> PathBuf {
    flag(args, "--config").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("attr-refs.toml"),
        PathBuf::from,
    )
}
