//! Body of `rulesteward fapolicyd migrate` (#187): migrate a legacy single-file
//! `fapolicyd.rules` into the modern `rules.d/` layout across a RHEL upgrade.
//!
//! Read-only by default: [`run`] prints the migration plan and writes nothing
//! unless `--apply` is given. With `--apply` it MOVES the legacy file: writes
//! `rules.d/99-migrated.rules` and then removes `fapolicyd.rules`, so the end
//! state is a clean modern layout (leaving it would re-create the trap).
//! `--delete-legacy` is required only to proceed when both layouts already exist.
//! The write precedes the delete and each is error-checked, so an interruption
//! between them leaves the legacy file intact (the safe failure mode).
//!
//! The migration is LINE-PRESERVING: the legacy file's bytes (comments, blanks,
//! ordering) are kept verbatim except for the surgical `sha256hash=` ->
//! `filehash=` deprecation rewrite on non-comment lines. `format.rs`'s `Display`
//! would drop comments, so re-emitting from the parsed AST is deliberately NOT
//! used; the parser is used only to VALIDATE the legacy file before migrating.

use std::path::Path;

use rulesteward_fapolicyd::{Entry, directory_has_rules_files, parse_rules_file};
use serde::Serialize;

use crate::cli::{HumanJsonFormat, MigrateArgs, TargetVersionArg};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;

/// Schema version for the `migrate` kind. Bumps only on a breaking payload change.
const MIGRATE_SCHEMA_VERSION: u32 = 1;

/// Canonical drop-in filename for the migrated legacy rules (spec §6.1).
const TARGET_FILE: &str = "99-migrated.rules";

/// Legacy single-file rule set name.
const LEGACY_FILE: &str = "fapolicyd.rules";

/// The deprecated attribute and its modern replacement.
const DEPRECATED_HASH: &str = "sha256hash=";
const MODERN_HASH: &str = "filehash=";

/// One surgical source-line rewrite applied during migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Transformation {
    /// 1-based source line number in the legacy file.
    line: usize,
    /// What was rewritten (currently only `"sha256hash->filehash"`).
    kind: &'static str,
    before: String,
    after: String,
}

/// The migrated file content plus the rewrites applied, computed purely from the
/// legacy file text (no I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationContent {
    content: String,
    transformations: Vec<Transformation>,
}

/// The on-disk layout of a fapolicyd config directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// No legacy `fapolicyd.rules` and no `rules.d/*.rules`.
    Neither,
    /// `rules.d/*.rules` present, no legacy file (already modern).
    ModernOnly,
    /// Legacy file present, no `rules.d/*.rules`.
    LegacyOnly,
    /// Both present: the coexistence trap (daemon refuses to start).
    Both,
}

/// Everything needed to render the migration outcome (human or JSON).
///
/// A flat report DTO serialized straight to the JSON envelope. The bools are
/// independent, well-named output facts (the mode + what happened on disk), not
/// interacting state, so a state machine would obscure rather than clarify.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MigratePlan {
    from: &'static str,
    to: &'static str,
    rules_dir: String,
    /// `legacy-only` | `coexistence-trap` | `already-modern` | `nothing-to-migrate`.
    layout: &'static str,
    coexistence_trap: bool,
    legacy_file: Option<String>,
    target_file: Option<String>,
    rules_migrated: usize,
    transformations: Vec<Transformation>,
    /// True when no `--apply` was given (nothing was written).
    dry_run: bool,
    /// Echo of the `--delete-legacy` flag; post-move-semantics it gates only the
    /// coexistence-trap (`Both`) case, surfaced here for JSON consumers.
    delete_legacy: bool,
    /// True when the migrated file was written to disk.
    applied: bool,
    /// True when the legacy file was removed from disk.
    legacy_deleted: bool,
}

/// Map a `--from`/`--to` value to its display string.
fn version_str(v: TargetVersionArg) -> &'static str {
    match v {
        TargetVersionArg::Rhel8 => "rhel8",
        TargetVersionArg::Rhel9 => "rhel9",
        TargetVersionArg::Rhel10 => "rhel10",
    }
}

/// Map a `--from`/`--to` value to its numeric rank (8/9/10) for direction checks.
fn version_rank(v: TargetVersionArg) -> u8 {
    match v {
        TargetVersionArg::Rhel8 => 8,
        TargetVersionArg::Rhel9 => 9,
        TargetVersionArg::Rhel10 => 10,
    }
}

// ---------------------------------------------------------------------------
// Pure logic (unit + tempdir tested; in the mutation gate)
// ---------------------------------------------------------------------------

/// Rewrite a legacy rule set line-by-line, preserving comments/blanks/order and
/// surgically rewriting the deprecated `sha256hash=` attribute to `filehash=`.
fn compute_migration(legacy: &str) -> MigrationContent {
    let mut transformations = Vec::new();
    let mut out_lines: Vec<String> = Vec::new();
    for (idx, line) in legacy.lines().enumerate() {
        // Comment lines (first non-blank char is `#`) are preserved verbatim:
        // fapolicyd honors only whole-line comments, and a `sha256hash=` inside a
        // comment is prose, not an attribute. Lines without the token are kept as-is.
        if line.trim_start().starts_with('#') || !line.contains(DEPRECATED_HASH) {
            out_lines.push(line.to_string());
            continue;
        }
        let rewritten = line.replace(DEPRECATED_HASH, MODERN_HASH);
        transformations.push(Transformation {
            line: idx + 1,
            kind: "sha256hash->filehash",
            before: line.to_string(),
            after: rewritten.clone(),
        });
        out_lines.push(rewritten);
    }
    let mut content = out_lines.join("\n");
    // `str::lines()` drops the trailing newline; restore it so a file that ended
    // in `\n` still does (POSIX text-file convention; fagenrules concatenation).
    if legacy.ends_with('\n') && !content.is_empty() {
        content.push('\n');
    }
    MigrationContent {
        content,
        transformations,
    }
}

/// Detect the on-disk layout of a fapolicyd config directory.
fn detect_layout(rules_dir: &Path) -> Layout {
    let legacy = rules_dir.join(LEGACY_FILE).is_file();
    // Reuse the grounded fagenrules-loadability check (dotfile + subdirectory
    // guards) that the fapd-F02 layout lint uses, so migrate and the lint agree
    // on what counts as a modern rules.d/ -- a divergent copy here mis-detected a
    // dotfile-only rules.d/ as the coexistence trap (issue #187 adversarial review).
    let modern = directory_has_rules_files(&rules_dir.join("rules.d"));
    match (legacy, modern) {
        (false, false) => Layout::Neither,
        (false, true) => Layout::ModernOnly,
        (true, false) => Layout::LegacyOnly,
        (true, true) => Layout::Both,
    }
}

fn render_human(plan: &MigratePlan) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    match plan.layout {
        "nothing-to-migrate" => {
            let _ = writeln!(
                s,
                "Nothing to migrate: no legacy {LEGACY_FILE} found in {}.",
                plan.rules_dir
            );
            return s;
        }
        "already-modern" => {
            let _ = writeln!(
                s,
                "Already migrated: {}/rules.d/ has rule files and there is no legacy {LEGACY_FILE}.",
                plan.rules_dir
            );
            return s;
        }
        _ => {}
    }
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
    s
}

fn render_json(plan: &MigratePlan) -> String {
    render_envelope("migrate", MIGRATE_SCHEMA_VERSION, plan)
}

// ---------------------------------------------------------------------------
// Orchestration (I/O on --rules-dir; tempdir-tested)
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
pub fn run(args: MigrateArgs) -> anyhow::Result<i32> {
    let from = version_str(args.from);
    let to = version_str(args.to);
    if version_rank(args.from) > version_rank(args.to) {
        eprintln!(
            "error: --from {from} is newer than --to {to}; migrate does not downgrade rulesets"
        );
        return Ok(EXIT_TOOL_FAILURE);
    }

    let rules_dir = args.rules_dir.display().to_string();
    let dry_run = !args.apply;
    let layout = detect_layout(&args.rules_dir);

    // No-work cases: render a plain plan and return clean.
    let no_work = |layout_str: &'static str| MigratePlan {
        from,
        to,
        rules_dir: rules_dir.clone(),
        layout: layout_str,
        coexistence_trap: false,
        legacy_file: None,
        target_file: None,
        rules_migrated: 0,
        transformations: Vec::new(),
        dry_run,
        delete_legacy: args.delete_legacy,
        applied: false,
        legacy_deleted: false,
    };
    match layout {
        Layout::Neither => {
            emit(&no_work("nothing-to-migrate"), args.format);
            return Ok(EXIT_CLEAN);
        }
        Layout::ModernOnly => {
            emit(&no_work("already-modern"), args.format);
            return Ok(EXIT_CLEAN);
        }
        Layout::Both if !args.delete_legacy => {
            eprintln!(
                "error: coexistence trap: both {LEGACY_FILE} and rules.d/*.rules exist in {rules_dir}.\n\
                 fapolicyd refuses to start with both present. Re-run with --delete-legacy to migrate\n\
                 the legacy file into rules.d/{TARGET_FILE} and remove it."
            );
            return Ok(EXIT_ERRORS);
        }
        Layout::LegacyOnly | Layout::Both => {}
    }

    // LegacyOnly, or Both with --delete-legacy: read, validate, migrate.
    let legacy_path = args.rules_dir.join(LEGACY_FILE);
    let legacy = match std::fs::read_to_string(&legacy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading {}: {e}", legacy_path.display());
            return Ok(EXIT_TOOL_FAILURE);
        }
    };
    let entries = match parse_rules_file(&legacy, &legacy_path) {
        Ok(entries) => entries,
        Err(_diags) => {
            eprintln!(
                "error: {} does not parse (fapd-F01); fix it (try `rulesteward fapolicyd lint --file {}`) before migrating",
                legacy_path.display(),
                legacy_path.display()
            );
            return Ok(EXIT_RULE_PARSE_ERROR);
        }
    };
    let rules_migrated = entries
        .iter()
        .filter(|e| matches!(e, Entry::Rule(_)))
        .count();
    let migration = compute_migration(&legacy);
    let target_path = args.rules_dir.join("rules.d").join(TARGET_FILE);
    let coexistence_trap = layout == Layout::Both;

    let mut applied = false;
    let mut legacy_deleted = false;
    if args.apply {
        let rules_d = args.rules_dir.join("rules.d");
        if let Err(e) = std::fs::create_dir_all(&rules_d) {
            eprintln!("error: creating {}: {e}", rules_d.display());
            return Ok(EXIT_TOOL_FAILURE);
        }
        if let Err(e) = std::fs::write(&target_path, &migration.content) {
            eprintln!("error: writing {}: {e}", target_path.display());
            return Ok(EXIT_TOOL_FAILURE);
        }
        applied = true;
        // Move semantics (#187 owner decision): the migration ALWAYS removes the
        // legacy file on --apply so the end state is a clean modern layout;
        // leaving it would re-create the coexistence trap migrate exists to
        // prevent. The Both case already required --delete-legacy to reach here.
        if let Err(e) = std::fs::remove_file(&legacy_path) {
            eprintln!("error: deleting {}: {e}", legacy_path.display());
            return Ok(EXIT_TOOL_FAILURE);
        }
        legacy_deleted = true;
    }

    let plan = MigratePlan {
        from,
        to,
        rules_dir,
        layout: if coexistence_trap {
            "coexistence-trap"
        } else {
            "legacy-only"
        },
        coexistence_trap,
        legacy_file: Some(legacy_path.display().to_string()),
        target_file: Some(target_path.display().to_string()),
        rules_migrated,
        transformations: migration.transformations,
        dry_run,
        delete_legacy: args.delete_legacy,
        applied,
        legacy_deleted,
    };
    emit(&plan, args.format);
    Ok(EXIT_CLEAN)
}

/// Print the plan in the requested format.
fn emit(plan: &MigratePlan, format: HumanJsonFormat) {
    match format {
        HumanJsonFormat::Human => print!("{}", render_human(plan)),
        HumanJsonFormat::Json => print!("{}", render_json(plan)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // --- helpers ---

    fn args(rules_dir: &Path, apply: bool, delete_legacy: bool) -> MigrateArgs {
        MigrateArgs {
            from: TargetVersionArg::Rhel8,
            to: TargetVersionArg::Rhel9,
            rules_dir: rules_dir.to_path_buf(),
            apply,
            delete_legacy,
            format: HumanJsonFormat::Human,
        }
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    const LEGACY_WITH_HASH: &str = "# my custom rules\nallow perm=execute exe=/usr/bin/cat : sha256hash=abc123\ndeny perm=any all : all\n";

    fn sample_plan() -> MigratePlan {
        MigratePlan {
            from: "rhel8",
            to: "rhel9",
            rules_dir: "/etc/fapolicyd".to_string(),
            layout: "legacy-only",
            coexistence_trap: false,
            legacy_file: Some("/etc/fapolicyd/fapolicyd.rules".to_string()),
            target_file: Some("/etc/fapolicyd/rules.d/99-migrated.rules".to_string()),
            rules_migrated: 2,
            transformations: vec![Transformation {
                line: 2,
                kind: "sha256hash->filehash",
                before: "allow perm=execute exe=/usr/bin/cat : sha256hash=abc123".to_string(),
                after: "allow perm=execute exe=/usr/bin/cat : filehash=abc123".to_string(),
            }],
            dry_run: true,
            delete_legacy: false,
            applied: false,
            legacy_deleted: false,
        }
    }

    // --- compute_migration ---

    #[test]
    fn compute_migration_rewrites_sha256hash_to_filehash() {
        let c = compute_migration("allow perm=execute exe=/x : sha256hash=abc\n");
        assert!(
            c.content.contains("filehash=abc"),
            "content must rewrite the hash: {}",
            c.content
        );
        assert!(
            !c.content.contains("sha256hash="),
            "sha256hash must be gone"
        );
        assert_eq!(c.transformations.len(), 1);
        assert_eq!(c.transformations[0].line, 1);
        assert_eq!(c.transformations[0].kind, "sha256hash->filehash");
    }

    #[test]
    fn compute_migration_no_hash_is_unchanged_with_empty_transforms() {
        let src = "# a comment\nallow perm=any all : all\n";
        let c = compute_migration(src);
        assert_eq!(c.content, src);
        assert!(c.transformations.is_empty());
    }

    #[test]
    fn compute_migration_preserves_comments_and_blanks() {
        let src = "# header\n\nallow perm=open exe=/x : sha256hash=ff\n\n# tail\n";
        let c = compute_migration(src);
        assert!(c.content.starts_with("# header\n\n"), "{}", c.content);
        assert!(c.content.contains("\n\n# tail\n"), "{}", c.content);
        assert!(c.content.contains("filehash=ff"));
        assert_eq!(c.transformations.len(), 1, "only the rule line rewritten");
    }

    #[test]
    fn compute_migration_skips_comment_lines_containing_the_token() {
        // A comment that mentions `sha256hash=` must NOT be rewritten.
        let src = "# do not use sha256hash= any more\nallow perm=any all : all\n";
        let c = compute_migration(src);
        assert_eq!(c.content, src, "comment line preserved verbatim");
        assert!(c.transformations.is_empty());
    }

    #[test]
    fn compute_migration_preserves_trailing_newline_presence() {
        let with = compute_migration("allow perm=any all : all\n");
        assert!(with.content.ends_with('\n'));
        let without = compute_migration("allow perm=any all : all");
        assert!(!without.content.ends_with('\n'), "{:?}", without.content);
    }

    // --- detect_layout ---

    #[test]
    fn detect_layout_neither_for_empty_dir() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(detect_layout(d.path()), Layout::Neither);
    }

    #[test]
    fn detect_layout_legacy_only() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        assert_eq!(detect_layout(d.path()), Layout::LegacyOnly);
    }

    #[test]
    fn detect_layout_modern_only() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        assert_eq!(detect_layout(d.path()), Layout::ModernOnly);
    }

    #[test]
    fn detect_layout_both_is_trap() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        write(d.path(), "rules.d/10-x.rules", "deny perm=any all : all\n");
        assert_eq!(detect_layout(d.path()), Layout::Both);
    }

    // --- render ---

    #[test]
    fn render_json_emits_migrate_envelope_with_camelcase_keys() {
        let out = render_json(&sample_plan());
        assert!(out.ends_with('\n'), "JSON must end with newline");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse json");
        assert_eq!(v["kind"], serde_json::json!("migrate"));
        assert_eq!(v["schemaVersion"], serde_json::json!(1));
        // Multi-word payload keys are camelCase, matching every other envelope kind.
        assert_eq!(v["rulesMigrated"], serde_json::json!(2), "{out}");
        assert!(v.get("rulesDir").is_some(), "rulesDir key present: {out}");
        assert!(v.get("rules_dir").is_none(), "no snake_case keys: {out}");
    }

    #[test]
    fn render_human_dry_run_mentions_target_and_rewrite() {
        let out = render_human(&sample_plan());
        assert!(out.contains("99-migrated.rules"), "{out}");
        assert!(out.contains("sha256hash"), "{out}");
        assert!(out.to_lowercase().contains("dry"), "dry-run wording: {out}");
    }

    // --- run (tempdir integration) ---

    #[test]
    fn run_dry_run_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        let code = run(args(d.path(), false, false)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert!(
            !d.path().join("rules.d").join(TARGET_FILE).exists(),
            "dry-run must not write the migrated file"
        );
    }

    #[test]
    fn run_apply_legacy_only_moves_file_and_rewrites_hash() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        let target = d.path().join("rules.d").join(TARGET_FILE);
        let written = std::fs::read_to_string(&target).expect("migrated file written");
        assert!(written.contains("filehash=abc123"), "{written}");
        assert!(!written.contains("sha256hash="), "{written}");
        // Move semantics (#187): the legacy file is removed on --apply (no
        // --delete-legacy needed for a legacy-only dir), so applying the migration
        // never leaves a coexistence trap behind.
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "legacy file must be moved (deleted) on apply"
        );
    }

    #[test]
    fn run_coexistence_trap_without_delete_legacy_refuses() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(
            code, EXIT_ERRORS,
            "trap without --delete-legacy must refuse"
        );
        assert!(
            !d.path().join("rules.d").join(TARGET_FILE).exists(),
            "must not write on a refused migration"
        );
        assert!(
            d.path().join("fapolicyd.rules").exists(),
            "legacy untouched"
        );
    }

    #[test]
    fn run_apply_overwrites_preexisting_target_file() {
        // `99-migrated.rules` is the tool's canonical drop-in name; re-migrating
        // overwrites it idempotently (the dry-run preview shows the target). A
        // pre-existing target + a real rules.d file makes this the Both case.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        write(
            d.path(),
            "rules.d/99-migrated.rules",
            "stale junk content\n",
        );
        let code = run(args(d.path(), true, true)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        let target = std::fs::read_to_string(d.path().join("rules.d").join(TARGET_FILE)).unwrap();
        assert!(target.contains("filehash=abc123"), "overwritten: {target}");
        assert!(
            !target.contains("stale junk"),
            "stale content gone: {target}"
        );
        assert!(!d.path().join("fapolicyd.rules").exists(), "legacy moved");
    }

    #[test]
    fn run_coexistence_trap_with_delete_legacy_applies_and_deletes() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        let code = run(args(d.path(), true, true)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert!(
            d.path().join("rules.d").join(TARGET_FILE).exists(),
            "wrote drop-in"
        );
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "--delete-legacy must remove the legacy file on apply"
        );
    }

    #[test]
    fn run_dry_run_trap_with_delete_legacy_still_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        let code = run(args(d.path(), false, true)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert!(!d.path().join("rules.d").join(TARGET_FILE).exists());
        assert!(
            d.path().join("fapolicyd.rules").exists(),
            "dry-run must not delete even with --delete-legacy"
        );
    }

    #[test]
    fn run_parse_error_in_legacy_refuses() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "fapolicyd.rules",
            "garbage line with no decision keyword\n",
        );
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(code, EXIT_RULE_PARSE_ERROR);
        assert!(!d.path().join("rules.d").join(TARGET_FILE).exists());
    }

    #[test]
    fn run_modern_only_reports_already_migrated() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert!(!d.path().join("rules.d").join(TARGET_FILE).exists());
    }

    #[test]
    fn run_from_newer_than_to_is_usage_error() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        let mut a = args(d.path(), true, false);
        a.from = TargetVersionArg::Rhel10;
        a.to = TargetVersionArg::Rhel8;
        let code = run(a).unwrap();
        assert_eq!(code, EXIT_TOOL_FAILURE, "a downgrade is a usage error");
    }

    #[test]
    fn run_from_equals_to_is_allowed() {
        // from == to (no version change) still migrates a legacy-only layout.
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        let mut a = args(d.path(), false, false);
        a.from = TargetVersionArg::Rhel9;
        a.to = TargetVersionArg::Rhel9;
        assert_eq!(run(a).unwrap(), EXIT_CLEAN, "from == to must be allowed");
    }

    #[test]
    fn detect_layout_dotfile_in_rules_d_is_legacy_only_not_trap() {
        // A `.40-x.rules` dotfile in rules.d/ is NOT loaded by fagenrules
        // (`ls -1v` omits dotfiles), so a legacy file + a dotfile-only rules.d/ is
        // LegacyOnly, NOT the coexistence trap (issue #187 adversarial finding).
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        write(d.path(), "rules.d/.40-x.rules", "deny perm=any all : all\n");
        assert_eq!(detect_layout(d.path()), Layout::LegacyOnly);
    }

    #[test]
    fn render_human_nothing_to_migrate_message() {
        let mut p = sample_plan();
        p.layout = "nothing-to-migrate";
        p.legacy_file = None;
        p.target_file = None;
        let out = render_human(&p);
        assert!(out.to_lowercase().contains("nothing to migrate"), "{out}");
    }

    #[test]
    fn render_human_already_modern_message() {
        let mut p = sample_plan();
        p.layout = "already-modern";
        let out = render_human(&p);
        assert!(out.to_lowercase().contains("already migrated"), "{out}");
    }
}
