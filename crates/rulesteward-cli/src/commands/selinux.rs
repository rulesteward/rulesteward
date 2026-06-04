//! Body of `rulesteward selinux <subcommand>`.
//!
//! This dispatch arm is FROZEN. The two renderer pipelines fill ONLY their own files:
//!
//! - P3 (#99) fills `rulesteward-selinux/src/triage.rs` (human + JSON-report renderers).
//! - P4 (#103) fills `rulesteward-selinux/src/te_emit.rs` (the `.te` emitter).
//!
//! Neither pipeline touches this file.

use std::path::Path;

use anyhow::anyhow;

use crate::cli::{HumanJsonFormat, SelinuxCommand, TriageArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS};
use crate::output::json::render_envelope;
use rulesteward_selinux::{build_report, emit_te, group_denials, parse_avc, render_human};

/// Schema version for the `selinux-triage` payload kind. Bumps only on a
/// breaking change (field removal, rename, or retype). Adding optional fields
/// is free (tolerant-reader contract, issue #62).
const SELINUX_TRIAGE_SCHEMA_VERSION: u32 = 1;

pub fn run(cmd: SelinuxCommand) -> anyhow::Result<i32> {
    match cmd {
        SelinuxCommand::Triage(args) => triage(&args),
    }
}

fn triage(args: &TriageArgs) -> anyhow::Result<i32> {
    // Exactly one of --record / --audit-log must be supplied.
    // clap enforces they are not BOTH set (conflicts_with); we enforce at least one.
    let input_path: &Path = match (args.record.as_deref(), args.audit_log.as_deref()) {
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => {
            eprintln!("selinux triage: one of --record or --audit-log is required");
            return Ok(EXIT_ERRORS);
        }
        (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents both"),
    };

    let input = std::fs::read_to_string(input_path)
        .map_err(|e| anyhow!("reading {}: {e}", input_path.display()))?;

    let denials = match parse_avc(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("selinux triage: parsing {}: {e}", input_path.display());
            return Ok(EXIT_ERRORS);
        }
    };

    // `--since` is accepted and stored but not yet applied; P3 wires the time filter.
    let groups = group_denials(&denials);

    let rendered = if args.emit_te {
        emit_te(&groups, args.module_name.as_deref())
    } else {
        match args.format {
            HumanJsonFormat::Human => render_human(&groups),
            HumanJsonFormat::Json => render_envelope(
                "selinux-triage",
                SELINUX_TRIAGE_SCHEMA_VERSION,
                &build_report(&groups),
            ),
        }
    };

    write_output(&rendered, args.output.as_deref())?;
    Ok(EXIT_CLEAN)
}

fn write_output(rendered: &str, output: Option<&Path>) -> anyhow::Result<()> {
    match output {
        Some(path) => std::fs::write(path, rendered)
            .map_err(|e| anyhow!("writing {}: {e}", path.display()))?,
        None => print!("{rendered}"),
    }
    Ok(())
}
