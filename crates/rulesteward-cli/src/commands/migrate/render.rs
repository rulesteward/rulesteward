//! Renderer functions for `rulesteward fapolicyd migrate` (#187): Markdown
//! report, human text, and JSON output for a computed `MigratePlan` (#434
//! split out of `mod.rs` as a pure move, no behavior change).

use super::{LEGACY_FILE, MIGRATE_SCHEMA_VERSION, MigratePlan};
use crate::cli::HumanJsonFormat;
use crate::output::json::render_envelope;

/// Render the migration plan as a standalone Markdown report (#212).
///
/// Includes the migration version pair, the legacy -> target move, a per-rewrite
/// table (1-based line number, before, after), the rewritten/unchanged counts,
/// the resulting layout, and -- only when the post-apply verification ran -- a
/// fagenrules section. Deliberately carries NO timestamp (owner decision D1) so
/// the report is reproducible and diff-stable.
pub(crate) fn render_markdown_report(plan: &MigratePlan) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let mode = if plan.dry_run {
        "dry-run plan"
    } else {
        "applied"
    };

    let _ = writeln!(s, "# fapolicyd rule migration report ({mode})");
    let _ = writeln!(s);
    let _ = writeln!(s, "- Migration: {} -> {}", plan.from, plan.to);
    let _ = writeln!(s, "- Config directory: {}", plan.rules_dir);
    let _ = writeln!(s, "- Resulting layout: {}", plan.layout);
    let _ = writeln!(s);

    let _ = writeln!(s, "## Files");
    if let (Some(legacy), Some(target)) = (&plan.legacy_file, &plan.target_file) {
        let verb = if plan.legacy_deleted {
            "Moved"
        } else {
            "Would move"
        };
        let _ = writeln!(s, "{verb} `{legacy}` -> `{target}`");
    }
    let _ = writeln!(s);

    let rewritten = plan.transformations.len();
    let unchanged = plan.rules_migrated.saturating_sub(rewritten);
    let _ = writeln!(s, "## Rewrites");
    if plan.transformations.is_empty() {
        let _ = writeln!(s, "No attribute rewrites were needed.");
    } else {
        let _ = writeln!(s, "| line | before | after |");
        let _ = writeln!(s, "|------|--------|-------|");
        for t in &plan.transformations {
            let _ = writeln!(s, "| {} | `{}` | `{}` |", t.line, t.before, t.after);
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "- Rules migrated: {}", plan.rules_migrated);
    let _ = writeln!(s, "- Rules rewritten: {rewritten}");
    let _ = writeln!(s, "- Rules unchanged: {unchanged}");

    // #211 verification section: present only when the post-apply check ran.
    if let Some(check) = &plan.check_rules {
        let _ = writeln!(s);
        let _ = writeln!(s, "## Verification (fapolicyd-cli --check-rules)");
        let _ = writeln!(s, "- Status: {}", check.status);
        if !check.detail.is_empty() {
            let _ = writeln!(s, "- Detail: {}", check.detail);
        }
    }
    s
}

pub(super) fn render_human(plan: &MigratePlan) -> String {
    use std::fmt::Write as _;
    match plan.layout {
        "nothing-to-migrate" => {
            let mut s = String::new();
            let _ = writeln!(
                s,
                "Nothing to migrate: no legacy {LEGACY_FILE} found in {}.",
                plan.rules_dir
            );
            s
        }
        "already-modern" => {
            let mut s = String::new();
            let _ = writeln!(
                s,
                "Already migrated: {}/rules.d/ has rule files and there is no legacy {LEGACY_FILE}.",
                plan.rules_dir
            );
            s
        }
        // Only the two real-migration layouts render the summary block. Every
        // error / refusal layout (coexistence-trap-blocked, read/parse/mkdir/write/
        // remove-error, and the version-downgrade "error") reports its reason on
        // stderr in run_with_probe_to_plan() and emits NO stdout header, so a
        // command that migrated nothing never prints "Migration applied" (#315).
        // The summary is OPT-IN (only the success layouts) rather than opt-out, so
        // any future error layout defaults here to clean (empty) stdout.
        "legacy-only" | "coexistence-trap" => render_migration_summary(plan),
        _ => String::new(),
    }
}

/// Render the multi-line migration summary shown for the two success layouts
/// (`legacy-only` / `coexistence-trap`): the applied / dry-run header, the legacy
/// and target file lines, the `sha256hash=` -> `filehash=` rewrite summary, the
/// coexistence-trap and legacy-removal notes, and the #211 verification result.
fn render_migration_summary(plan: &MigratePlan) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let header = if plan.dry_run {
        "Migration plan (dry-run)"
    } else {
        "Migration applied"
    };
    let _ = writeln!(
        s,
        "{header}: {} -> {}, {}",
        plan.from, plan.to, plan.rules_dir
    );
    if let Some(legacy) = &plan.legacy_file {
        let _ = writeln!(s, "  Legacy file: {legacy} ({} rules)", plan.rules_migrated);
    }
    if let Some(target) = &plan.target_file {
        let _ = writeln!(s, "  Target:      {target}");
    }
    if plan.transformations.is_empty() {
        let _ = writeln!(s, "  Rewrites:    none");
    } else {
        let lines: Vec<String> = plan
            .transformations
            .iter()
            .map(|t| t.line.to_string())
            .collect();
        let _ = writeln!(
            s,
            "  Rewrites:    {} sha256hash= -> filehash= (line{} {})",
            plan.transformations.len(),
            if plan.transformations.len() == 1 {
                ""
            } else {
                "s"
            },
            lines.join(", ")
        );
    }
    if plan.coexistence_trap {
        let _ = writeln!(
            s,
            "  Coexistence trap: rules.d/ already had rules; --delete-legacy confirmed."
        );
    }
    // Move semantics: the legacy file is removed on apply (or would be on a
    // dry-run apply) so the migration never leaves both layouts behind.
    if let Some(legacy) = &plan.legacy_file {
        if plan.legacy_deleted {
            let _ = writeln!(s, "  Removed legacy file: {legacy}");
        } else if plan.dry_run {
            let _ = writeln!(
                s,
                "  Would remove legacy file: {legacy} (migrate moves it into rules.d/)."
            );
        }
    }
    if plan.dry_run {
        let _ = writeln!(s, "  Re-run with --apply to write.");
    }
    // #211: emit verification result when the check ran.
    if let Some(ref check) = plan.check_rules {
        let label = match check.status {
            "passed" => "Verification passed",
            "failed" => "Verification FAILED",
            _ => "Verification unavailable (fapolicyd-cli absent or too old; skipped)",
        };
        let _ = writeln!(s, "  {label}");
        if !check.detail.is_empty() && check.status != "unavailable" {
            let _ = writeln!(s, "    {}", check.detail);
        }
    }
    s
}

pub(super) fn render_json(plan: &MigratePlan) -> String {
    render_envelope("migrate", MIGRATE_SCHEMA_VERSION, plan)
}

/// Print the plan in the requested format.
pub(super) fn emit(plan: &MigratePlan, format: HumanJsonFormat) {
    match format {
        HumanJsonFormat::Human => print!("{}", render_human(plan)),
        HumanJsonFormat::Json => print!("{}", render_json(plan)),
    }
}
