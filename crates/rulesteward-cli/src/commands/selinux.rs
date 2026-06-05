//! Body of `rulesteward selinux <subcommand>`.
//!
//! This dispatch arm is FROZEN. The two renderer pipelines fill ONLY their own files:
//!
//! - P3 (#99) fills `rulesteward-selinux/src/triage.rs` (human + JSON-report renderers).
//! - P4 (#103) fills `rulesteward-selinux/src/te_emit.rs` (the `.te` emitter).
//!
//! The `--policy` flag and the already-allows rendering for the Reason(0) sub-case
//! were added by the CODE-WIRE step (#124, #122).

use std::path::Path;

use anyhow::anyhow;

use crate::cli::{HumanJsonFormat, SelinuxCommand, TriageArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS};
use crate::output::json::render_envelope;
use rulesteward_selinux::{
    AvcDenial, DenialGroup, Policy, ReplayOutcome, build_report, categorize_with_outcome, emit_te,
    group_denials, parse_avc, render_human,
};

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
    let mut groups = group_denials(&denials);

    // When --policy is supplied, run the authoritative categorizer (#124) and
    // merge the authoritative verdict over the floor. The authoritative-categorizer
    // feature is now default-ON, so this path compiles in the default build.
    // The already-allows sub-case tracks which groups had Reason(0) so we can
    // render a DISTINCT operator message for #122.
    let already_allows_groups =
        apply_authoritative_categorizer(args.policy.as_deref(), &denials, &mut groups);

    let rendered = if args.emit_te {
        emit_te(&groups, args.module_name.as_deref())
    } else {
        match args.format {
            HumanJsonFormat::Human => {
                render_human_with_already_allows(&groups, &already_allows_groups)
            }
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

/// Apply the authoritative categorizer when `--policy` is supplied.
///
/// Returns the set of `(source_type, target_type, tclass)` triples whose
/// authoritative outcome was `Reason(0)` (the supplied policy already allows
/// the access - the "already allows" sub-case for locked decision #122).
///
/// Mutates `groups` in place: for each group where the authoritative categorizer
/// returns a result, the `kind` field is overridden with the authoritative
/// `DenialKind`. On `CategorizeError` (hard errors, not BADSCON) the group's
/// floor kind is preserved and a warning is emitted on stderr.
///
/// When `policy_path` is `None` this is a no-op that returns an empty set.
fn apply_authoritative_categorizer(
    policy_path: Option<&Path>,
    denials: &[AvcDenial],
    groups: &mut [DenialGroup],
) -> std::collections::HashSet<(String, String, String)> {
    let Some(path) = policy_path else {
        return std::collections::HashSet::new();
    };

    // Load the policy once; all group replays share the loaded policydb.
    let policy = match Policy::load(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "selinux triage: could not load policy {}: {e}",
                path.display()
            );
            return std::collections::HashSet::new();
        }
    };

    let mut already_allows: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();

    for group in groups.iter_mut() {
        // Find the first AvcDenial for this group to get representative raw contexts.
        // All denials in a group share (source_type, target_type, tclass); the first
        // one's raw contexts are the representative contexts for the authoritative replay.
        let Some(rep) = denials.iter().find(|d| {
            d.source_type == group.source_type
                && d.target_type == group.target_type
                && d.tclass == group.tclass
        }) else {
            // No matching denial found (should not happen in normal flow); keep floor.
            continue;
        };

        // Build a synthetic AvcDenial using the group's UNIONED perms + the
        // representative raw contexts. The authoritative categorizer reads only
        // scontext_raw, tcontext_raw, tclass, and perms.
        let synthetic = AvcDenial {
            perms: group.perms.iter().cloned().collect(),
            scontext_raw: rep.scontext_raw.clone(),
            tcontext_raw: rep.tcontext_raw.clone(),
            tclass: group.tclass.clone(),
            source_type: group.source_type.clone(),
            target_type: group.target_type.clone(),
            verdict: rep.verdict,
            permissive: rep.permissive,
            pid: None,
            comm: None,
            exe: None,
            path: None,
            name: None,
            serial: None,
            timestamp: None,
        };

        match categorize_with_outcome(&synthetic, &policy) {
            Ok((kind, outcome)) => {
                group.kind = kind;
                // Track the Reason(0) "already allows" sub-case for #122.
                if matches!(outcome, ReplayOutcome::Reason(0)) {
                    already_allows.insert((
                        group.source_type.clone(),
                        group.target_type.clone(),
                        group.tclass.clone(),
                    ));
                }
            }
            Err(e) => {
                // Hard error (unknown class/perm, compute failure): keep floor,
                // emit a warning so the operator knows the replay failed.
                eprintln!(
                    "selinux triage: authoritative categorize failed for \
                     ({} -> {} : {}): {e}; falling back to floor",
                    group.source_type, group.target_type, group.tclass,
                );
            }
        }
    }

    already_allows
}

/// Render the human-readable triage output, substituting the Reason(0) "already
/// allows" message for groups in `already_allows_groups` instead of the standard
/// `ContextInvalid` "does not define" template (#122).
///
/// For all other groups, delegates to `render_human` (the selinux crate's
/// renderer) so that no existing rendering logic is duplicated here.
fn render_human_with_already_allows(
    groups: &[DenialGroup],
    already_allows_groups: &std::collections::HashSet<(String, String, String)>,
) -> String {
    if already_allows_groups.is_empty() {
        // Fast path: no already-allows groups, delegate entirely to the standard renderer.
        return render_human(groups);
    }

    // Partition: render already-allows groups here; render all others via `render_human`.
    // We preserve the original group ORDER for output stability.
    let mut parts: Vec<String> = Vec::with_capacity(groups.len());
    for group in groups {
        let key = (
            group.source_type.clone(),
            group.target_type.clone(),
            group.tclass.clone(),
        );
        if already_allows_groups.contains(&key) {
            parts.push(render_already_allows_group(group));
        } else {
            // Re-use the selinux crate's renderer for this one group by passing a
            // single-element slice. `render_human` adds a trailing '\n' to the whole
            // output; strip it here so our join('\n\n') produces correct spacing.
            let single = render_human(std::slice::from_ref(group));
            // `render_human` always ends with '\n'; trim exactly that one trailing newline.
            parts.push(single.trim_end_matches('\n').to_string());
        }
    }

    if parts.is_empty() {
        return String::new();
    }
    let mut out = parts.join("\n\n");
    out.push('\n');
    out
}

/// Render the "already allows" message for a `Reason(0)` group (#122).
///
/// The supplied policy ALREADY ALLOWS this access - the denial came from a
/// different policy version or a different host. The operator message is
/// DISTINCT from the `ContextInvalid` / BADSCON template ("does not define"),
/// satisfying the #122 requirement without adding a new `DenialKind` variant.
fn render_already_allows_group(group: &DenialGroup) -> String {
    let src = &group.source_type;
    let tgt = &group.target_type;
    let cls = &group.tclass;
    let perms: Vec<&str> = group.perms.iter().map(String::as_str).collect();
    let perm_display = if perms.len() == 1 {
        perms[0].to_string()
    } else {
        format!("{{ {} }}", perms.join(" "))
    };
    format!(
        "NOTED (policy mismatch): domain '{src}' was denied {perm_display} \
         on {cls} '{tgt}', but the supplied policy already allows this access. \
         The denial likely came from a different policy version or a different host. \
         No allow rule is needed for the supplied policy; \
         verify you are analyzing the policy that was active when the denial occurred."
    )
}

fn write_output(rendered: &str, output: Option<&Path>) -> anyhow::Result<()> {
    match output {
        Some(path) => std::fs::write(path, rendered)
            .map_err(|e| anyhow!("writing {}: {e}", path.display()))?,
        None => print!("{rendered}"),
    }
    Ok(())
}
