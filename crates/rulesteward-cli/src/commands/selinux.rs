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
// Floor (always-on) surface: parse / group / emit / build + render the report.
// These compile in BOTH the default build and the clean Apache-2.0-only
// `--no-default-features` build (no libsepol).
use rulesteward_selinux::{
    emit_te, group_denials, parse_avc, policy_reclassification_hint, render_human,
};

// Floor report builder, used directly only by the clean Apache-2.0-only build
// (the feature-on path renders via `build_report_with_already_allows`).
#[cfg(not(feature = "authoritative-categorizer"))]
use rulesteward_selinux::build_report;

// Authoritative (`--policy`) surface, gated on the `authoritative-categorizer`
// feature (default-ON, #124). Pulled in only for the libsepol-backed default
// build; absent from the clean Apache-2.0-only `--no-default-features` build.
#[cfg(feature = "authoritative-categorizer")]
use rulesteward_selinux::{
    AvcDenial, DenialGroup, DenialKind, Policy, ReplayOutcome, build_report_with_already_allows,
    categorize_with_outcome,
};
#[cfg(feature = "authoritative-categorizer")]
use std::collections::HashSet;

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
    #[cfg_attr(not(feature = "authoritative-categorizer"), allow(unused_mut))]
    let mut groups = group_denials(&denials);

    // When --policy is supplied, run the authoritative categorizer (#124) and
    // merge the authoritative verdict over the floor. The already-allows sub-case
    // tracks which groups had Reason(0) so we can render a DISTINCT operator
    // message for #122.
    //
    // A FAILED `--policy` load is a loud error (round-2 decision): we must NOT
    // silently fall back to the floor with exit 0. Report it and return
    // EXIT_ERRORS, staying read-only (no panic).
    //
    // This whole block is gated on `authoritative-categorizer` (default-ON, #124).
    // In the clean Apache-2.0-only `--no-default-features` build the `--policy`
    // flag does not exist (see `TriageArgs`) and there is no authoritative layer,
    // so `triage` runs floor-only.
    #[cfg(feature = "authoritative-categorizer")]
    let already_allows_groups =
        match apply_authoritative_categorizer(args.policy.as_deref(), &denials, &mut groups) {
            Ok(set) => set,
            Err(e) => {
                eprintln!("selinux triage: {e:#}");
                return Ok(EXIT_ERRORS);
            }
        };

    let rendered = if args.emit_te {
        emit_te(&groups, args.module_name.as_deref())
    } else {
        match args.format {
            #[cfg(feature = "authoritative-categorizer")]
            HumanJsonFormat::Human => {
                render_human_with_already_allows(&groups, &already_allows_groups)
            }
            #[cfg(feature = "authoritative-categorizer")]
            HumanJsonFormat::Json => render_envelope(
                "selinux-triage",
                SELINUX_TRIAGE_SCHEMA_VERSION,
                // Thread the Reason(0) "already allows" distinction into the JSON
                // path too (#122), mirroring `render_human_with_already_allows`:
                // a group whose authoritative replay was the Reason(0) sub-case
                // gets the DISTINCT "policy already allows" explanation instead of
                // the BADSCON "does not define" template. The signal is carried by
                // `already_allows_groups` (from `ReplayOutcome`), NOT by
                // `DenialKind`, which stays frozen.
                &build_report_with_already_allows(&groups, |group| {
                    already_allows_groups.contains(&(
                        group.source_type.clone(),
                        group.target_type.clone(),
                        group.tclass.clone(),
                    ))
                }),
            ),
            // Floor-only renderers for the clean Apache-2.0-only build: no
            // authoritative replay, so there is no "already allows" distinction
            // to thread (every group renders via the standard floor templates).
            #[cfg(not(feature = "authoritative-categorizer"))]
            HumanJsonFormat::Human => render_human(&groups),
            #[cfg(not(feature = "authoritative-categorizer"))]
            HumanJsonFormat::Json => render_envelope(
                "selinux-triage",
                SELINUX_TRIAGE_SCHEMA_VERSION,
                &build_report(&groups),
            ),
        }
    };

    // #166: on the FLOOR path (no --policy) surface a hint that --policy would
    // likely reclassify the floor's least-precise MlsSuspected/RoleSuspected
    // declines. Output-only and emitted to STDERR so it never pollutes the stdout
    // report (or a -o file). Not applicable to --emit-te (a distinct output mode).
    // When --policy WAS supplied, `groups` were already reclassified, so we skip.
    #[cfg(feature = "authoritative-categorizer")]
    let policy_supplied = args.policy.is_some();
    #[cfg(not(feature = "authoritative-categorizer"))]
    let policy_supplied = false;
    if !args.emit_te
        && !policy_supplied
        && let Some(hint) = policy_reclassification_hint(&groups)
    {
        eprintln!("{hint}");
    }

    write_output(&rendered, args.output.as_deref())?;
    Ok(EXIT_CLEAN)
}

/// How "actionable" / important-to-surface an authoritative per-context verdict
/// is. Used to pick the verdict shown for a HETEROGENEOUS group (one whose
/// members share the `(source_type, target_type, tclass)` triple but carry
/// DIFFERENT raw contexts - e.g. differing MLS levels). A higher rank wins.
///
/// The load-bearing ordering: a genuinely-blocked member (TE gap / constraint /
/// bounds / bad-context) MUST outrank the `Reason(0)` "already allows" member, so
/// the output never tells the operator the policy "already allows" a group that
/// in fact contains an enforced block (the round-2 grounded bug).
#[cfg(feature = "authoritative-categorizer")]
fn verdict_rank(kind: DenialKind, outcome: ReplayOutcome) -> u8 {
    match (kind, outcome) {
        // A real TE allow gap: most actionable (the operator likely wants the allow).
        (DenialKind::TeAllowable, _) => 5,
        // Hard blocks that need a policy-structure fix, not a plain allow.
        (DenialKind::Constraint | DenialKind::Bounds, _) => 4,
        // A bad/undefined context in the supplied policy ("does not define").
        (DenialKind::ContextInvalid, ReplayOutcome::BadContext) => 3,
        // Reason(0) -> ContextInvalid: the supplied policy ALREADY ALLOWS this.
        // LEAST actionable; must lose to any blocked member above.
        (DenialKind::ContextInvalid, ReplayOutcome::Reason(0)) => 1,
        // Any other floor verdict the authoritative layer left in place.
        _ => 2,
    }
}

/// Apply the authoritative categorizer when `--policy` is supplied.
///
/// Returns the set of `(source_type, target_type, tclass)` triples whose
/// authoritative outcome was the `Reason(0)` "already allows" sub-case for ALL of
/// the group's distinct contexts (locked decision #122).
///
/// Mutates `groups` in place: for each group, the authoritative categorizer is
/// replayed ONCE PER DISTINCT raw `(scontext, tcontext)` pair in the group (not
/// just the first representative). A `(source_type, target_type, tclass)` triple
/// is only as coarse as `group_denials` - two AVCs differing only in MLS level
/// land in ONE group - so replaying a single representative would let a
/// `Reason(0)` member mask a constraint-blocked member (the round-2 grounded
/// bug). The group's `kind` is set to the MOST ACTIONABLE per-context verdict
/// (see [`verdict_rank`]); a group is reported "already allows" ONLY when EVERY
/// distinct context replays to `Reason(0)`.
///
/// On `CategorizeError` (hard errors, not BADSCON) that context is skipped with a
/// warning on stderr (the floor kind is preserved if no context classified).
///
/// When `policy_path` is `None` this is a no-op that returns an empty set.
///
/// # Errors
///
/// Returns `Err` when an explicitly-supplied `--policy` cannot be loaded
/// (`Policy::load` failed). The caller maps this to `EXIT_ERRORS` - a failed
/// `--policy` load must FAIL LOUD, never silently fall back to the floor
/// (round-2 decision). The run stays read-only and does not panic.
#[cfg(feature = "authoritative-categorizer")]
fn apply_authoritative_categorizer(
    policy_path: Option<&Path>,
    denials: &[AvcDenial],
    groups: &mut [DenialGroup],
) -> anyhow::Result<HashSet<(String, String, String)>> {
    let Some(path) = policy_path else {
        return Ok(HashSet::new());
    };

    // Load the policy once; all group replays share the loaded policydb. A load
    // failure is propagated to the caller (-> EXIT_ERRORS), NOT swallowed.
    let policy =
        Policy::load(path).map_err(|e| anyhow!("could not load policy {}: {e}", path.display()))?;

    let mut already_allows: HashSet<(String, String, String)> = HashSet::new();

    for group in groups.iter_mut() {
        // Collect the DISTINCT raw context pairs for this group. Two AVCs that
        // share the (source_type, target_type, tclass) triple but differ in MLS
        // level / role land in ONE group, yet replay to DIFFERENT verdicts; we
        // must replay each distinct context, not just the first representative.
        let mut seen_contexts: HashSet<(String, String)> = HashSet::new();
        let context_pairs: Vec<(String, String)> = denials
            .iter()
            .filter(|d| {
                d.source_type == group.source_type
                    && d.target_type == group.target_type
                    && d.tclass == group.tclass
            })
            .filter_map(|d| {
                let key = (d.scontext_raw.clone(), d.tcontext_raw.clone());
                seen_contexts.insert(key.clone()).then_some(key)
            })
            .collect();

        // A representative for the fields the categorizer does NOT read (verdict /
        // permissive); replay uses only the contexts, class, and perms.
        let Some(rep) = denials.iter().find(|d| {
            d.source_type == group.source_type
                && d.target_type == group.target_type
                && d.tclass == group.tclass
        }) else {
            // No matching denial found (should not happen in normal flow); keep floor.
            continue;
        };
        // `rep` found implies `context_pairs` is non-empty (same triple filter).

        // Replay each distinct context with the group's UNIONED perms. Track the
        // winning (most-actionable) verdict and whether EVERY context was the
        // Reason(0) "already allows" sub-case.
        let mut best: Option<(u8, DenialKind)> = None;
        let mut classified_any = false;
        let mut all_already_allows = true;

        for (scontext_raw, tcontext_raw) in context_pairs {
            // The authoritative categorizer reads only scontext_raw, tcontext_raw,
            // tclass, and perms; the remaining fields are inert for replay.
            let synthetic = AvcDenial {
                perms: group.perms.iter().cloned().collect(),
                scontext_raw,
                tcontext_raw,
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
                    classified_any = true;
                    if !matches!(outcome, ReplayOutcome::Reason(0)) {
                        all_already_allows = false;
                    }
                    let rank = verdict_rank(kind, outcome);
                    if best.is_none_or(|(best_rank, _)| rank > best_rank) {
                        best = Some((rank, kind));
                    }
                }
                Err(e) => {
                    // Hard error (unknown class/perm, compute failure): skip this
                    // context, warn. A context that cannot replay is conservatively
                    // NOT treated as "already allows".
                    all_already_allows = false;
                    eprintln!(
                        "selinux triage: authoritative categorize failed for \
                         ({} -> {} : {}): {e}; falling back to floor for this context",
                        group.source_type, group.target_type, group.tclass,
                    );
                }
            }
        }

        if let Some((_, kind)) = best {
            group.kind = kind;
        }

        // Report "already allows" ONLY when every distinct context replayed to
        // Reason(0). A heterogeneous group with any blocked member is NEVER
        // reported as already-allows (the actionable member's verdict won above).
        if classified_any && all_already_allows {
            already_allows.insert((
                group.source_type.clone(),
                group.target_type.clone(),
                group.tclass.clone(),
            ));
        }
    }

    Ok(already_allows)
}

/// Render the human-readable triage output, substituting the Reason(0) "already
/// allows" message for groups in `already_allows_groups` instead of the standard
/// `ContextInvalid` "does not define" template (#122).
///
/// For all other groups, delegates to `render_human` (the selinux crate's
/// renderer) so that no existing rendering logic is duplicated here.
#[cfg(feature = "authoritative-categorizer")]
fn render_human_with_already_allows(
    groups: &[DenialGroup],
    already_allows_groups: &HashSet<(String, String, String)>,
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
#[cfg(feature = "authoritative-categorizer")]
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
