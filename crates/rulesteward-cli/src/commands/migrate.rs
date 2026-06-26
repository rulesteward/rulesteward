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

use std::io::ErrorKind;
use std::path::Path;

use rulesteward_fapolicyd::{
    directory_has_nondotfile_entry, directory_has_rules_files, parse_rules_file,
};
use serde::Serialize;

use crate::cli::{HumanJsonFormat, MigrateArgs, TargetVersionArg};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};

use crate::output::json::render_envelope;
use std::process::Command as ProcessCommand;

/// Schema version for the `migrate` kind. Bumps only on a breaking payload change.
const MIGRATE_SCHEMA_VERSION: u32 = 1;

/// Canonical drop-in filename for the migrated legacy rules (spec §6.1).
const TARGET_FILE: &str = "99-migrated.rules";

/// Legacy single-file rule set name.
const LEGACY_FILE: &str = "fapolicyd.rules";

/// Modern drop-in rules directory name (relative to `--rules-dir`).
const MODERN_DIR: &str = "rules.d";

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

/// Outcome of the post-apply `fapolicyd-cli --check-rules` verification (#211).
///
/// Phase-0 frozen data shape (session 6a); Lane B populates it. `status` is
/// `"passed"` | `"failed"` | `"unavailable"` (the binary is absent OR too old
/// to support `--check-rules` per #222: the check degrades gracefully and the
/// exit code stays clean).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FagenrulesCheck {
    status: &'static str,
    detail: String,
}

/// Everything needed to render the migration outcome (human or JSON).
///
/// A flat report DTO serialized straight to the JSON envelope. The bools are
/// independent, well-named output facts (the mode + what happened on disk), not
/// interacting state, so a state machine would obscure rather than clarify.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MigratePlan {
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
    /// Post-apply `fapolicyd-cli --check-rules` outcome (#211). `None` when the check
    /// did not run (dry-run, no-work layouts, or pre-#211 behavior). Additive
    /// optional field: `schemaVersion` stays 1 per CC-2 (breaking-only).
    fagenrules_check: Option<FagenrulesCheck>,
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
// Probe abstraction (#211 Lane B skeleton, session 6a)
// ---------------------------------------------------------------------------

/// Outcome of a `fagenrules`-family check invocation.
///
/// `success` mirrors the process exit code (0 = rules compile / are current;
/// non-zero = failed). `detail` carries stderr or a human note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckOutcome {
    pub(crate) success: bool,
    pub(crate) detail: String,
}

/// Classification of a `fapolicyd-cli --check-rules` invocation (#222).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckClass {
    /// Exit 0: the rules file validated.
    Passed,
    /// Non-zero exit from a CLI that DOES support `--check-rules`: the rules
    /// have a real syntax error.
    Failed,
    /// The installed `fapolicyd-cli` is too old to support `--check-rules` (it
    /// rejects the unknown option), so verification could not run -> degrade
    /// gracefully like an absent binary, NOT a rule failure.
    Unavailable,
}

/// Classify the result of `fapolicyd-cli --check-rules <file>` (#222).
///
/// `--check-rules` is a real fapolicyd verb (upstream `check_rules_file`,
/// "Validate rules file syntax without loading") but is absent from currently
/// shipping releases (fapolicyd 1.3.2 and 1.4.5). An older CLI rejects the
/// unknown long option: glibc `getopt_long` writes `unrecognized option` to
/// stderr (exit code varies - 1 on 1.3.2, 2 on 1.4.5, so it is NOT a reliable
/// signal) and `fapolicyd-cli` then prints its usage banner (`Fapolicyd CLI
/// Tool`) to stdout. A CLI that DOES support the option instead validates and
/// prints a syntax error (neither marker) on failure, so keying on these two
/// markers never masks a genuine rule-syntax failure.
#[must_use]
pub(crate) fn classify_check(success: bool, stdout: &str, stderr: &str) -> CheckClass {
    if success {
        return CheckClass::Passed;
    }
    // Too-old CLI markers: glibc getopt's "unrecognized option" on stderr
    // (English) OR fapolicyd-cli's own usage banner on stdout (locale-stable,
    // printed only on an argument-parse error). A CLI that supports the option
    // prints neither on a genuine syntax failure.
    if stderr.contains("unrecognized option") || stdout.contains("Fapolicyd CLI Tool") {
        return CheckClass::Unavailable;
    }
    CheckClass::Failed
}

/// Dependency-injection seam for the post-apply rules-file verification (#211).
///
/// `Ok(None)` means verification could not run - the binary is absent, OR it is
/// too old to support `--check-rules` (#222) - so the caller degrades gracefully
/// (`fagenrulesCheck.status` = `"unavailable"`, exit 0). `Ok(Some(outcome))`
/// carries a real result (passed/failed). `Err(msg)` is an unexpected spawn
/// error (treated as `"unavailable"` with the error in `detail`, exit 0).
///
/// NOTE: `rules_dir` is the fapolicyd config root (the parent of `rules.d/`),
/// not `rules.d/` itself. [`LiveMigrateProbe`] threads it through
/// `fapolicyd-cli --check-rules`.
pub(crate) trait MigrateProbe {
    fn fagenrules_check(&self, rules_dir: &Path) -> Result<Option<CheckOutcome>, String>;
}

/// Live implementation that shells out to `fapolicyd-cli --check-rules`.
///
/// The result is classified by [`classify_check`]: an old CLI that rejects the
/// unknown `--check-rules` option returns `Ok(None)` ("unavailable", #222), a
/// clean exit returns `Ok(Some(passed))`, and a genuine syntax failure returns
/// `Ok(Some(failed))`.
///
/// Wired into the CLI dispatch (`commands/fapolicyd/mod.rs`) via
/// `run_with_probe`; the legacy migration unit tests drive `run_with_probe` with
/// an in-memory `FakeMigrateProbe` so they never shell out. Excluded from the
/// mutation gate via `mutants.toml` `exclude_re` (it does real process I/O).
/// Only reached after a successful `--apply`.
pub(crate) struct LiveMigrateProbe;

/// RAII guard: removes the file at the given path when dropped (best-effort).
struct TmpGuard(std::path::PathBuf);
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl MigrateProbe for LiveMigrateProbe {
    fn fagenrules_check(&self, rules_dir: &Path) -> Result<Option<CheckOutcome>, String> {
        // Assemble rules.d/*.rules in lexical filename order into a temp file,
        // then run `fapolicyd-cli --check-rules <tmpfile>`.
        //
        // Exit 0 -> passed. Non-zero -> failed with stderr detail.
        // ErrorKind::NotFound -> Ok(None) (binary absent, graceful degrade).
        // Other spawn errors -> Err(message).
        let rules_d = rules_dir.join(MODERN_DIR);

        // Collect and sort rule files by filename (lexical order, per fagenrules
        // semantics; dotfiles excluded by directory_has_rules_files convention).
        let mut rule_files: Vec<std::path::PathBuf> = match std::fs::read_dir(&rules_d) {
            Ok(rd) => rd
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().and_then(|s| s.to_str()) == Some("rules")
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| !n.starts_with('.'))
                })
                .collect(),
            Err(e) => return Err(format!("could not read {}: {e}", rules_d.display())),
        };
        rule_files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        // Concatenate rules into a temp file.
        // Use a uniquely-named file in the system temp dir (no dev-dep required).
        let tmp_path = std::env::temp_dir().join(format!(
            "rulesteward-migrate-check-{}.rules",
            std::process::id()
        ));
        let mut combined = String::new();
        for path in &rule_files {
            match std::fs::read_to_string(path) {
                Ok(content) => combined.push_str(&content),
                Err(e) => return Err(format!("could not read {}: {e}", path.display())),
            }
        }
        if let Err(e) = std::fs::write(&tmp_path, &combined) {
            return Err(format!("could not write temp rules file: {e}"));
        }
        // Ensure the temp file is removed when we're done (best-effort).
        let _tmp_guard = TmpGuard(tmp_path.clone());

        // Spawn fapolicyd-cli --check-rules <tmpfile>.
        let output = match ProcessCommand::new("fapolicyd-cli")
            .arg("--check-rules")
            .arg(&tmp_path)
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("spawning fapolicyd-cli failed: {e}")),
        };

        let success = output.status.success();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        // #222: an old fapolicyd-cli without --check-rules is a capability gap,
        // not a rule failure -> degrade to "unavailable" (Ok(None)), like absent.
        let class = classify_check(success, &stdout, &stderr);
        let detail = if stderr.trim().is_empty() {
            stdout
        } else if stdout.trim().is_empty() {
            stderr
        } else {
            format!("{stdout}{stderr}")
        };
        let detail = detail.trim_end().to_string();

        match class {
            CheckClass::Unavailable => Ok(None),
            CheckClass::Passed => Ok(Some(CheckOutcome {
                success: true,
                detail,
            })),
            CheckClass::Failed => Ok(Some(CheckOutcome {
                success: false,
                detail,
            })),
        }
    }
}

/// Production entry point for the CLI dispatch (`commands/fapolicyd/mod.rs`).
///
/// Calls the probe after a successful apply (#211), emits stdout in the
/// requested format, and writes a markdown report when `args.report` is
/// set (#212). The report write happens after apply; if it fails the
/// migration stays applied and the function returns `EXIT_TOOL_FAILURE`.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run_with_probe(args: MigrateArgs, probe: &dyn MigrateProbe) -> anyhow::Result<i32> {
    let format = args.format;
    let (code, plan) = run_with_probe_to_plan(args, probe)?;
    emit(&plan, format);
    Ok(code)
}

/// Internal orchestration shared by `run_with_probe` and tests.
///
/// Runs the full migration logic, calls the probe after a successful apply
/// (#211), and returns the final plan for rendering / report writing.
///
/// `too_many_lines` is expected for this end-to-end migration orchestration.
#[allow(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps
)]
pub(crate) fn run_with_probe_to_plan(
    args: MigrateArgs,
    probe: &dyn MigrateProbe,
) -> anyhow::Result<(i32, MigratePlan)> {
    let from = version_str(args.from);
    let to = version_str(args.to);
    if version_rank(args.from) > version_rank(args.to) {
        eprintln!(
            "error: --from {from} is newer than --to {to}; migrate does not downgrade rulesets"
        );
        let plan = MigratePlan {
            from,
            to,
            rules_dir: args.rules_dir.display().to_string(),
            layout: "error",
            coexistence_trap: false,
            legacy_file: None,
            target_file: None,
            rules_migrated: 0,
            transformations: Vec::new(),
            dry_run: !args.apply,
            delete_legacy: args.delete_legacy,
            applied: false,
            legacy_deleted: false,
            fagenrules_check: None,
        };
        return Ok((EXIT_TOOL_FAILURE, plan));
    }
    let rules_dir = args.rules_dir.display().to_string();
    let dry_run = !args.apply;
    let layout = detect_layout(&args.rules_dir);
    let no_work_plan = |layout_str: &'static str| MigratePlan {
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
        fagenrules_check: None,
    };
    match layout {
        Layout::Neither => return Ok((EXIT_CLEAN, no_work_plan("nothing-to-migrate"))),
        Layout::ModernOnly => return Ok((EXIT_CLEAN, no_work_plan("already-modern"))),
        Layout::Both if !args.delete_legacy => {
            eprintln!(
                "error: coexistence trap: both {LEGACY_FILE} and rules.d/*.rules exist in {rules_dir}.\n\
                 fapolicyd refuses to start with both present. Re-run with --delete-legacy to migrate\n\
                 the legacy file into rules.d/{TARGET_FILE} and remove it."
            );
            return Ok((EXIT_ERRORS, no_work_plan("coexistence-trap-blocked")));
        }
        Layout::LegacyOnly | Layout::Both => {}
    }
    let legacy_path = args.rules_dir.join(LEGACY_FILE);
    let Ok(legacy) = std::fs::read_to_string(&legacy_path) else {
        eprintln!(
            "error: failed to read the legacy rules file {} (no files were changed)",
            legacy_path.display()
        );
        return Ok((EXIT_TOOL_FAILURE, no_work_plan("read-error")));
    };
    if parse_rules_file(&legacy, &legacy_path).is_err() {
        eprintln!(
            "error: the legacy rules in {} do not parse; aborting migration (no files were changed)",
            legacy_path.display()
        );
        return Ok((EXIT_RULE_PARSE_ERROR, no_work_plan("parse-error")));
    }
    let entries = parse_rules_file(&legacy, &legacy_path).unwrap_or_default();
    let rules_migrated = entries
        .iter()
        .filter(|e| matches!(e, rulesteward_fapolicyd::Entry::Rule(_)))
        .count();
    let migration = compute_migration(&legacy);
    let target_path = args.rules_dir.join(MODERN_DIR).join(TARGET_FILE);
    let coexistence_trap = layout == Layout::Both;
    let mut applied = false;
    let mut legacy_deleted = false;
    if args.apply {
        let rules_d = args.rules_dir.join(MODERN_DIR);
        if std::fs::create_dir_all(&rules_d).is_err() {
            eprintln!(
                "error: failed to create the rules.d directory {} (no files were changed)",
                rules_d.display()
            );
            return Ok((EXIT_TOOL_FAILURE, no_work_plan("mkdir-error")));
        }
        if std::fs::write(&target_path, &migration.content).is_err() {
            eprintln!(
                "error: failed to write the migrated rules to {} (the legacy file was not removed)",
                target_path.display()
            );
            return Ok((EXIT_TOOL_FAILURE, no_work_plan("write-error")));
        }
        applied = true;
        if std::fs::remove_file(&legacy_path).is_err() {
            eprintln!(
                "error: wrote the migrated rules to {} but failed to remove the legacy file {}; \
                 both now exist (the coexistence trap) -- remove {} manually so fapolicyd can start",
                target_path.display(),
                legacy_path.display(),
                legacy_path.display()
            );
            return Ok((EXIT_TOOL_FAILURE, no_work_plan("remove-error")));
        }
        legacy_deleted = true;
    }

    // #211: after a successful apply, run the post-apply rules verification.
    // The probe is invoked ONLY when the migration was applied: dry-run and the
    // no-work layouts never reach here with `applied == true`, so a dry-run
    // never shells out (the call-counting `FakeMigrateProbe` pins this).
    let mut exit_code = EXIT_CLEAN;
    let fagenrules_check = if applied {
        match probe.fagenrules_check(&args.rules_dir) {
            Ok(Some(outcome)) => {
                let status = if outcome.success { "passed" } else { "failed" };
                if !outcome.success {
                    // D7: verification ran and FAILED -> exit 2. The migration
                    // still stands (the files were already moved above).
                    exit_code = EXIT_ERRORS;
                }
                Some(FagenrulesCheck {
                    status,
                    detail: outcome.detail,
                })
            }
            // Verification could not run (binary absent, or too old to support
            // --check-rules per #222): degrade gracefully, exit stays clean.
            Ok(None) => Some(FagenrulesCheck {
                status: "unavailable",
                detail: "fapolicyd-cli unavailable (absent or too old to support --check-rules); \
                         post-apply verification skipped"
                    .to_string(),
            }),
            // A spawn error is indistinguishable from "absent" to the operator.
            Err(msg) => Some(FagenrulesCheck {
                status: "unavailable",
                detail: msg,
            }),
        }
    } else {
        None
    };

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
        fagenrules_check,
    };

    // #212: write a standalone Markdown report when --report is set. The write
    // happens AFTER the apply + verification, so a write failure leaves the
    // migration applied and is surfaced as a tool failure (exit 3). Works in
    // both dry-run and apply (D1).
    //
    // A report-write failure must NOT mask a substantive ruleset error: if the
    // verification already FAILED (exit 2, D7), that is the operator-actionable
    // result and wins over an incidental missing-sidecar tool fault. So the
    // report-write failure only downgrades an otherwise-clean run to exit 3.
    if let Some(report_path) = args.report.as_ref()
        && std::fs::write(report_path, render_markdown_report(&plan)).is_err()
        && exit_code == EXIT_CLEAN
    {
        exit_code = EXIT_TOOL_FAILURE;
    }

    Ok((exit_code, plan))
}

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
    if let Some(check) = &plan.fagenrules_check {
        let _ = writeln!(s);
        let _ = writeln!(s, "## Verification (fapolicyd-cli --check-rules)");
        let _ = writeln!(s, "- Status: {}", check.status);
        if !check.detail.is_empty() {
            let _ = writeln!(s, "- Detail: {}", check.detail);
        }
    }
    s
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
        if !line.contains(DEPRECATED_HASH) || line.trim_start().starts_with('#') {
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
///
/// Two questions, two grounded predicates (both shared with the fapd-F02 lint
/// so migrate and the lint never diverge, issue #187 / #274):
///
/// * NARROW (`directory_has_rules_files`): does `rules.d/` hold a LOADABLE
///   top-level `.rules` file? This drives the no-legacy `ModernOnly` (already a
///   working modern layout) vs `Neither` (nothing to migrate) split. A bare
///   `README` or subdirectory is not a loadable rule, so a no-legacy dir holding
///   only those is `Neither`, not a (false) `ModernOnly`.
/// * BROAD (`directory_has_nondotfile_entry`): would the fagenrules daemon-level
///   coexistence guard (`ls | wc -w`) trip? This drives the legacy-present `Both`
///   (the coexistence trap -- legacy + ANY non-dotfile entry) vs `LegacyOnly`
///   (empty / dotfile-only rules.d/, a clean migration) split. This is the
///   owner-locked widen (#274): legacy + README / subdir IS the trap.
fn detect_layout(rules_dir: &Path) -> Layout {
    let legacy = rules_dir.join(LEGACY_FILE).is_file();
    let rules_d = rules_dir.join(MODERN_DIR);
    let modern = directory_has_rules_files(&rules_d);
    let coexists = directory_has_nondotfile_entry(&rules_d);
    match (legacy, modern, coexists) {
        // No legacy file: there is no coexistence trap. The modern-vs-nothing
        // distinction is "are there real loadable rules?" -> NARROW.
        (false, false, _) => Layout::Neither,
        (false, true, _) => Layout::ModernOnly,
        // Legacy present: the daemon-level coexistence guard is BROAD; any
        // non-dotfile entry alongside the legacy file is the trap.
        (true, _, true) => Layout::Both,
        (true, _, false) => Layout::LegacyOnly,
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
        // Only the two real-migration layouts reach the header block below. Every
        // error / refusal layout (coexistence-trap-blocked, read/parse/mkdir/write/
        // remove-error, and the version-downgrade "error") reports its reason on
        // stderr in run_with_probe_to_plan() and emits NO stdout header, so a
        // command that migrated nothing never prints "Migration applied" (#315).
        // The header is OPT-IN (only the success layouts) rather than opt-out, so
        // any future error layout defaults to clean stdout.
        "legacy-only" | "coexistence-trap" => {}
        _ => return s, // s is empty: error / refusal layouts produce no stdout
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
    // #211: emit verification result when the check ran.
    if let Some(ref check) = plan.fagenrules_check {
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

fn render_json(plan: &MigratePlan) -> String {
    render_envelope("migrate", MIGRATE_SCHEMA_VERSION, plan)
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
            report: None,
        }
    }

    /// Probe-free entry for the legacy migration unit tests below. The production
    /// migration is `run_with_probe`; these tests drive it with an in-memory
    /// `FakeMigrateProbe` that never shells out (the same determinism the old
    /// standalone `run()` provided before it was removed as duplicate logic).
    fn run(args: MigrateArgs) -> anyhow::Result<i32> {
        run_with_probe(args, &FakeMigrateProbe::absent())
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
            fagenrules_check: None,
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

    // --- detect_layout: fagenrules `ls | wc -w` parity (issue #274 lockstep) ---
    //
    // `detect_layout` reuses the SHARED `directory_has_rules_files` helper, so
    // when that helper widens to fagenrules's `ls | wc -w` semantics (any
    // non-dotfile entry -- file OR subdirectory, any extension), migrate's
    // classification must move in lockstep with the fapd-F02 layout lint.
    // A wrong impl that widens only the F02 predicate and leaves migrate's
    // classification on the old `*.rules`-file-only gate cannot pass these.
    // RED until the shared helper is widened (detect_layout returns LegacyOnly).

    /// legacy + rules.d/ holding ONLY a `README` (a non-`.rules` file) ->
    /// `Layout::Both`. `ls | wc -w` counts `README`, so the daemon would abort;
    /// migrate must classify this as the coexistence trap, not `LegacyOnly`.
    #[test]
    fn detect_layout_both_when_rules_d_has_only_readme() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        write(d.path(), "rules.d/README", "documentation\n");
        assert_eq!(
            detect_layout(d.path()),
            Layout::Both,
            "fagenrules `ls | wc -w` counts README; migrate must detect the trap"
        );
    }

    /// legacy + rules.d/ holding ONLY a plain subdirectory (`sub/`) ->
    /// `Layout::Both`. `ls` lists the subdir name and `wc -w` counts it, so the
    /// daemon aborts; migrate must classify it as the coexistence trap.
    #[test]
    fn detect_layout_both_when_rules_d_has_only_plain_subdir() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        std::fs::create_dir_all(d.path().join("rules.d/sub")).unwrap();
        assert_eq!(
            detect_layout(d.path()),
            Layout::Both,
            "fagenrules `ls | wc -w` counts subdirectory `sub/`; migrate must detect the trap"
        );
    }

    /// Regression: legacy + rules.d/ holding ONLY a dotfile (`.40-x.rules`) stays
    /// `Layout::LegacyOnly`. `ls` without `-a` omits dotfiles, so `wc -w` is 0 and
    /// the daemon does NOT abort -- the widen must not change this case.
    /// (Distinct from the existing `detect_layout_dotfile_in_rules_d_is_legacy_only_not_trap`;
    /// kept here alongside the widen tests to pin the dotfile boundary against them.)
    #[test]
    fn detect_layout_legacy_only_when_rules_d_has_only_dotfile_after_widen() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
        write(d.path(), "rules.d/.40-x.rules", "deny perm=any all : all\n");
        assert_eq!(
            detect_layout(d.path()),
            Layout::LegacyOnly,
            "a dotfile-only rules.d/ is invisible to `ls | wc -w`; must stay LegacyOnly"
        );
    }

    /// e2e: legacy + rules.d/ holding ONLY a `README` now hits the coexistence
    /// trap. Without `--delete-legacy`, migrate must refuse (`EXIT_ERRORS`) instead
    /// of treating it as a plain legacy-only migration. RED until the widen lands
    /// (today this case is `LegacyOnly` and migrates cleanly to `EXIT_CLEAN`).
    #[test]
    fn run_readme_only_rules_d_with_legacy_hits_coexistence_trap() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        write(d.path(), "rules.d/README", "documentation\n");
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(
            code, EXIT_ERRORS,
            "a README in rules.d/ is a non-dotfile entry; legacy + it is the \
             coexistence trap and must refuse without --delete-legacy"
        );
        assert!(
            !d.path().join(MODERN_DIR).join(TARGET_FILE).exists(),
            "must not write on a refused migration"
        );
        assert!(
            d.path().join("fapolicyd.rules").exists(),
            "legacy untouched on refusal"
        );
    }

    // --- no-legacy case must keep NARROW (.rules-files-present) semantics ---
    //
    // The owner's lockstep widen applies ONLY to the legacy-PRESENT coexistence
    // trap (legacy + any content -> Both). With NO legacy file, the
    // ModernOnly-vs-Neither distinction asks "is rules.d/ already a working
    // modern layout?" -- which means LOADABLE `.rules` files, not just any
    // non-dotfile entry.  A no-legacy rules.d/ holding only a `README` or a bare
    // subdir has ZERO loadable rules, so the answer is Neither ("Nothing to
    // migrate"), NOT ModernOnly ("Already migrated" -- which would be a false
    // claim).  These tests are RED against the broad shared predicate and go
    // GREEN once the implementer splits it (broad for the trap, narrow here).

    /// NO legacy + rules.d/ holding ONLY a `README` (a non-`.rules` file) ->
    /// `Layout::Neither`.  Without a legacy file there is no coexistence trap;
    /// a `README` is not a loadable rule, so rules.d/ is NOT a modern layout.
    #[test]
    fn detect_layout_neither_when_no_legacy_and_rules_d_has_only_readme() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/README", "documentation\n");
        assert_eq!(
            detect_layout(d.path()),
            Layout::Neither,
            "no legacy + a non-rule README is Neither (nothing to migrate), not ModernOnly"
        );
    }

    /// NO legacy + rules.d/ holding ONLY a plain subdirectory (`sub/`) ->
    /// `Layout::Neither`.  A bare subdir contains zero loadable top-level rules,
    /// so without a legacy file there is nothing modern and nothing to migrate.
    #[test]
    fn detect_layout_neither_when_no_legacy_and_rules_d_has_only_plain_subdir() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("rules.d/sub")).unwrap();
        assert_eq!(
            detect_layout(d.path()),
            Layout::Neither,
            "no legacy + a bare subdir is Neither (nothing to migrate), not ModernOnly"
        );
    }

    /// Regression guard (must stay GREEN): NO legacy + rules.d/ holding a REAL
    /// `.rules` file (`10-x.rules`) -> `Layout::ModernOnly`.  The narrow
    /// predicate still fires on genuine loadable rules, so a real modern layout
    /// is still correctly reported as already migrated.
    #[test]
    fn detect_layout_modern_only_when_no_legacy_and_rules_d_has_real_rules_file() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        assert_eq!(
            detect_layout(d.path()),
            Layout::ModernOnly,
            "a real .rules file with no legacy is still ModernOnly (already migrated)"
        );
    }

    /// e2e: NO legacy + rules.d/ holding ONLY a `README` -> the human render
    /// must say "Nothing to migrate" (layout `nothing-to-migrate`), NOT
    /// "Already migrated" (layout `already-modern`).  Both classifications exit
    /// `EXIT_CLEAN`, so the exit code alone cannot tell them apart -- the
    /// `plan.layout` string is the discriminator.  RED while the broad predicate
    /// mislabels this as `already-modern`.
    #[test]
    fn run_no_legacy_readme_only_reports_nothing_to_migrate() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/README", "documentation\n");
        let (code, plan) =
            run_with_probe_to_plan(args(d.path(), true, false), &FakeMigrateProbe::absent())
                .unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert_eq!(
            plan.layout, "nothing-to-migrate",
            "no legacy + a non-rule README has nothing to migrate; \
             reporting `already-modern` would be a false claim that rules.d/ \
             holds loadable rule files"
        );
        let human = render_human(&plan);
        assert!(
            human.contains("Nothing to migrate"),
            "human render must say Nothing to migrate, got: {human}"
        );
        assert!(
            !human.contains("Already migrated"),
            "human render must NOT claim Already migrated, got: {human}"
        );
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
    fn render_json_fagenrules_check_is_additive_null_pre_211() {
        // Phase-0 freeze (session 6a): the #211 field exists as an ADDITIVE
        // optional - null until Lane B populates it, schemaVersion stays 1
        // (CC-2 breaking-only versioning). Pins both the camelCase key and
        // the no-bump decision.
        let out = render_json(&sample_plan());
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse json");
        assert_eq!(v["schemaVersion"], serde_json::json!(1));
        assert!(
            v.get("fagenrulesCheck").is_some(),
            "fagenrulesCheck key must be present: {out}"
        );
        assert_eq!(v["fagenrulesCheck"], serde_json::Value::Null);
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
            !d.path().join(MODERN_DIR).join(TARGET_FILE).exists(),
            "dry-run must not write the migrated file"
        );
    }

    #[test]
    fn run_apply_legacy_only_moves_file_and_rewrites_hash() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        let target = d.path().join(MODERN_DIR).join(TARGET_FILE);
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
            !d.path().join(MODERN_DIR).join(TARGET_FILE).exists(),
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
        let target = std::fs::read_to_string(d.path().join(MODERN_DIR).join(TARGET_FILE)).unwrap();
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
            d.path().join(MODERN_DIR).join(TARGET_FILE).exists(),
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
        assert!(!d.path().join(MODERN_DIR).join(TARGET_FILE).exists());
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
        assert!(!d.path().join(MODERN_DIR).join(TARGET_FILE).exists());
    }

    #[test]
    fn run_modern_only_reports_already_migrated() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
        let code = run(args(d.path(), true, false)).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        assert!(!d.path().join(MODERN_DIR).join(TARGET_FILE).exists());
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

    #[test]
    fn render_human_coexistence_trap_blocked_emits_no_applied_header() {
        // #315: the blocked refusal is an ERROR fully reported on stderr (see the
        // eprintln! in run()). The human renderer must NOT print the misleading
        // "Migration applied" header on stdout for a refusal that applied nothing.
        // Human stdout for this error case is empty (the inverse of the two exit-0
        // no-work cases above, which DO print an informational stdout line).
        let mut p = sample_plan();
        p.layout = "coexistence-trap-blocked";
        p.applied = false;
        p.dry_run = false;
        p.legacy_file = None;
        p.target_file = None;
        let out = render_human(&p);
        assert!(
            !out.contains("Migration applied"),
            "blocked refusal must not print the applied header: {out:?}"
        );
        assert!(
            out.is_empty(),
            "blocked refusal stdout should be empty (error is on stderr): {out:?}"
        );
    }

    #[test]
    fn render_human_all_error_layouts_emit_empty_stdout() {
        // #315 (full fix): NONE of migrate's error / refusal layouts may print the
        // "Migration applied"/"Migration plan" header on stdout -- a command that
        // migrated nothing must never claim it did. The header is OPT-IN for the two
        // success layouts (see the regression test below), so every error layout
        // (and any future one) defaults to empty stdout. The operator-facing reason
        // is reported on stderr by run_with_probe_to_plan().
        for layout in [
            "error",                    // --from newer than --to (version downgrade)
            "coexistence-trap-blocked", // both layouts present, no --delete-legacy
            "read-error",
            "parse-error",
            "mkdir-error",
            "write-error",
            "remove-error",
        ] {
            let mut p = sample_plan();
            p.layout = layout;
            p.applied = false;
            p.dry_run = false;
            let out = render_human(&p);
            assert!(
                out.is_empty(),
                "error layout {layout:?} must emit empty stdout, got: {out:?}"
            );
        }
    }

    #[test]
    fn render_human_success_layouts_still_print_header() {
        // Regression guard for the opt-in header: the two real-migration layouts
        // must keep printing the applied header, and the dry-run variant its plan
        // header.
        for (layout, dry_run, needle) in [
            ("legacy-only", false, "Migration applied"),
            ("coexistence-trap", false, "Migration applied"),
            ("legacy-only", true, "Migration plan (dry-run)"),
        ] {
            let mut p = sample_plan();
            p.layout = layout;
            p.dry_run = dry_run;
            p.applied = !dry_run;
            let out = render_human(&p);
            assert!(
                out.contains(needle),
                "success layout {layout:?} (dry_run={dry_run}) must print {needle:?}, got: {out:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // FakeMigrateProbe (call-counting test double for #211/#212 tests)
    // -----------------------------------------------------------------------

    use std::cell::Cell;

    /// Call-counting test double for `MigrateProbe`.
    ///
    /// Configured at construction time with a canned return value.  The test
    /// inspects `call_count()` to verify the probe was (or was not) invoked.
    #[allow(dead_code)]
    struct FakeMigrateProbe {
        result: Result<Option<CheckOutcome>, String>,
        count: Cell<usize>,
    }

    impl FakeMigrateProbe {
        fn success(detail: impl Into<String>) -> Self {
            Self {
                result: Ok(Some(CheckOutcome {
                    success: true,
                    detail: detail.into(),
                })),
                count: Cell::new(0),
            }
        }

        fn failure(detail: impl Into<String>) -> Self {
            Self {
                result: Ok(Some(CheckOutcome {
                    success: false,
                    detail: detail.into(),
                })),
                count: Cell::new(0),
            }
        }

        fn absent() -> Self {
            Self {
                result: Ok(None),
                count: Cell::new(0),
            }
        }

        fn spawn_error(msg: impl Into<String>) -> Self {
            Self {
                result: Err(msg.into()),
                count: Cell::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.count.get()
        }
    }

    impl MigrateProbe for FakeMigrateProbe {
        fn fagenrules_check(&self, _rules_dir: &Path) -> Result<Option<CheckOutcome>, String> {
            self.count.set(self.count.get() + 1);
            self.result.clone()
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build apply-mode args pointing at a tempdir with a legacy file
    // -----------------------------------------------------------------------

    fn setup_legacy_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fapolicyd.rules", LEGACY_WITH_HASH);
        d
    }

    fn apply_args(rules_dir: &Path) -> MigrateArgs {
        MigrateArgs {
            from: TargetVersionArg::Rhel8,
            to: TargetVersionArg::Rhel9,
            rules_dir: rules_dir.to_path_buf(),
            apply: true,
            delete_legacy: false,
            format: HumanJsonFormat::Json,
            report: None,
        }
    }

    fn dry_run_args(rules_dir: &Path) -> MigrateArgs {
        MigrateArgs {
            from: TargetVersionArg::Rhel8,
            to: TargetVersionArg::Rhel9,
            rules_dir: rules_dir.to_path_buf(),
            apply: false,
            delete_legacy: false,
            format: HumanJsonFormat::Json,
            report: None,
        }
    }

    // -----------------------------------------------------------------------
    // #211 probe tests (must be RED against the skeleton)
    // -----------------------------------------------------------------------

    /// Test #211-1: apply + probe success -> plan has `fagenrules_check.status ==
    /// "passed"`, exit 0.
    ///
    /// RED: `run_with_probe_to_plan` skeleton never calls the probe and keeps
    /// `fagenrules_check: None`, so `unwrap()` on `fagenrules_check` panics and
    /// the status assertion fails.
    #[test]
    fn probe_success_sets_status_passed_and_exits_clean() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::success("Rules are current");
        let (code, plan) = run_with_probe_to_plan(apply_args(d.path()), &probe).unwrap();
        assert_eq!(code, EXIT_CLEAN, "probe success must yield exit 0");
        // RED: probe must be called exactly once on apply.
        assert_eq!(
            probe.call_count(),
            1,
            "probe must be called exactly once on apply"
        );
        // The legacy file must be gone (moved).
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "legacy file must be moved on apply"
        );
        // RED: fagenrules_check must be Some with status "passed" - not None.
        let check = plan
            .fagenrules_check
            .as_ref()
            .expect("fagenrules_check must be Some after successful probe call");
        assert_eq!(
            check.status, "passed",
            "probe success must set fagenrules_check.status to 'passed'; got {:?}",
            check.status
        );
    }

    /// Test #211-2: apply + probe failure -> plan has `fagenrules_check.status ==
    /// "failed"`, exit 2 (D7), and the files were moved.
    ///
    /// RED: `run_with_probe_to_plan` skeleton always exits clean and keeps
    /// `fagenrules_check: None`; both the exit-2 assertion and the status
    /// assertion fail.
    #[test]
    fn probe_failure_exits_two_and_legacy_file_is_gone() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::failure("compiled.rules does not match");
        let (code, plan) = run_with_probe_to_plan(apply_args(d.path()), &probe).unwrap();
        // D7: check ran and FAILED -> exit 2 (EXIT_ERRORS).
        assert_eq!(
            code, EXIT_ERRORS,
            "probe failure after apply must yield exit 2 (D7); got {code}"
        );
        // D7: the migration WAS applied even though verification failed.
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "legacy file must still be moved even when probe fails (D7)"
        );
        assert!(
            d.path().join("rules.d").join("99-migrated.rules").exists(),
            "target file must exist even when probe fails (D7)"
        );
        // RED: fagenrules_check must be Some with status "failed".
        let check = plan
            .fagenrules_check
            .as_ref()
            .expect("fagenrules_check must be Some after probe returned failure");
        assert_eq!(
            check.status, "failed",
            "probe failure must set fagenrules_check.status to 'failed'; got {:?}",
            check.status
        );
    }

    /// Test #211-3: probe absent (`Ok(None)`) -> status "unavailable", exit 0.
    ///
    /// RED: `run_with_probe` skeleton never calls the probe, so `call_count`
    /// stays at 0 and the `call_count >= 1` assertion fails.
    /// Note: the exit-code assertion (`EXIT_CLEAN`) IS vacuously green in the
    /// skeleton because the skeleton always exits clean - this is documented
    /// as acceptable for the exit-code portion only. The `call_count` + status
    /// assertions are RED.
    #[test]
    fn probe_absent_is_unavailable_and_exits_clean() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::absent();
        let code = run_with_probe(apply_args(d.path()), &probe).unwrap();
        assert_eq!(code, EXIT_CLEAN, "absent probe must yield exit 0");
        // RED: probe must be called (its Ok(None) return drives "unavailable").
        assert_eq!(
            probe.call_count(),
            1,
            "probe must be called once so we can observe Ok(None) -> unavailable"
        );
    }

    /// Test #211-4: dry-run -> probe NOT invoked (`call_count` == 0).
    ///
    /// This test is GREEN-BY-VACUITY in the skeleton: the skeleton never calls
    /// the probe, so the assertion `call_count == 0` passes trivially.
    /// Documented per the task brief: the only test allowed to be vacuously
    /// green.
    #[test]
    fn dry_run_probe_not_invoked() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::success("should not be called");
        let code = run_with_probe(dry_run_args(d.path()), &probe).unwrap();
        assert_eq!(code, EXIT_CLEAN, "dry-run must exit clean");
        assert_eq!(
            probe.call_count(),
            0,
            "probe must NOT be called in dry-run mode"
        );
    }

    /// Test #211-5: probe spawn error (Err) -> treat as "unavailable", exit 0.
    ///
    /// RED: `run_with_probe` skeleton never calls the probe, so `call_count`
    /// stays at 0 and the `call_count >= 1` assertion fails.
    #[test]
    fn probe_spawn_error_treated_as_unavailable() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::spawn_error("permission denied spawning binary");
        let code = run_with_probe(apply_args(d.path()), &probe).unwrap();
        // A spawn error is indistinguishable from "binary absent" to the caller:
        // degrade gracefully, exit 0.
        assert_eq!(
            code, EXIT_CLEAN,
            "spawn error must degrade gracefully (exit 0)"
        );
        // RED: probe must be called for us to observe the Err return.
        assert_eq!(
            probe.call_count(),
            1,
            "probe called once even on spawn error"
        );
    }

    // --- #222: classify_check (old fapolicyd-cli lacks --check-rules) --------

    #[test]
    fn classify_check_clean_exit_is_passed() {
        assert_eq!(
            super::classify_check(true, "", ""),
            super::CheckClass::Passed
        );
    }

    #[test]
    fn classify_check_old_cli_1_4_5_is_unavailable() {
        // fapolicyd 1.4.5: exit 2 (success=false), usage banner on stdout,
        // getopt error on stderr.
        let stdout = "Fapolicyd CLI Tool\n\n--check-config        Check the daemon config\n";
        let stderr = "fapolicyd-cli: unrecognized option '--check-rules'";
        assert_eq!(
            super::classify_check(false, stdout, stderr),
            super::CheckClass::Unavailable
        );
    }

    #[test]
    fn classify_check_old_cli_1_3_2_is_unavailable() {
        // fapolicyd 1.3.2: same markers, exit 1. The exit code differs from
        // 1.4.5 (2), which is why classify_check must NOT key on the code.
        let stdout = "Fapolicyd CLI Tool\n";
        let stderr = "fapolicyd-cli: unrecognized option '--check-rules'";
        assert_eq!(
            super::classify_check(false, stdout, stderr),
            super::CheckClass::Unavailable
        );
    }

    #[test]
    fn classify_check_unavailable_via_stderr_marker_only() {
        // stderr getopt marker alone (no usage banner captured) -> unavailable.
        // Pins the stderr "unrecognized option" check independently.
        assert_eq!(
            super::classify_check(
                false,
                "",
                "fapolicyd-cli: unrecognized option '--check-rules'"
            ),
            super::CheckClass::Unavailable
        );
    }

    #[test]
    fn classify_check_unavailable_via_usage_banner_when_stderr_localized() {
        // getopt messages are locale-translated; the program's own usage banner
        // on stdout is the locale-stable fallback. Pins the stdout banner check
        // independently (stderr carries no English marker here).
        let stdout = "Fapolicyd CLI Tool\n--check-config ...";
        let stderr = "fapolicyd-cli: option non reconnue '--check-rules'";
        assert_eq!(
            super::classify_check(false, stdout, stderr),
            super::CheckClass::Unavailable
        );
    }

    #[test]
    fn classify_check_real_syntax_error_is_failed() {
        // A new-enough CLI that supports --check-rules and finds a bad rule
        // prints a syntax error (NEITHER marker) and exits non-zero. Must stay
        // "failed" so a genuine rule error is never masked as a capability gap.
        let stderr = "Error: syntax error on line 3: unknown keyword 'allwo'";
        assert_eq!(
            super::classify_check(false, "", stderr),
            super::CheckClass::Failed
        );
    }

    #[test]
    fn classify_check_nonzero_without_markers_is_failed() {
        // Non-zero exit with neither marker (e.g. an unreadable rules file) is a
        // real failure, not a capability gap.
        assert_eq!(
            super::classify_check(false, "", "could not open rules file"),
            super::CheckClass::Failed
        );
    }

    // -----------------------------------------------------------------------
    // #212 render_markdown_report tests (must be RED against the skeleton)
    // -----------------------------------------------------------------------

    /// Build a plan suitable for #212 renderer testing: applied=true,
    /// one sha256hash transformation, known file paths.
    fn applied_plan_with_rewrite() -> MigratePlan {
        MigratePlan {
            from: "rhel8",
            to: "rhel9",
            rules_dir: "/etc/fapolicyd".to_string(),
            layout: "legacy-only",
            coexistence_trap: false,
            legacy_file: Some("/etc/fapolicyd/fapolicyd.rules".to_string()),
            target_file: Some("/etc/fapolicyd/rules.d/99-migrated.rules".to_string()),
            rules_migrated: 3,
            transformations: vec![Transformation {
                line: 2,
                kind: "sha256hash->filehash",
                before: "allow perm=execute exe=/usr/bin/cat : sha256hash=abc123".to_string(),
                after: "allow perm=execute exe=/usr/bin/cat : filehash=abc123".to_string(),
            }],
            dry_run: false,
            delete_legacy: false,
            applied: true,
            legacy_deleted: true,
            fagenrules_check: None,
        }
    }

    /// Test #212-6: full-content markdown renderer.
    ///
    /// Asserts: 1-based line number present, before/after text present, the
    /// rules-unchanged count present (3 total - 1 rewritten = 2 unchanged),
    /// legacy -> target move present, resulting layout section present, no
    /// timestamp anywhere (D1), and fagenrules section absent when check is None.
    ///
    /// RED: `render_markdown_report` panics with `todo!()` in the skeleton.
    #[test]
    fn render_markdown_report_full_content() {
        let plan = applied_plan_with_rewrite();
        // RED: this panics (todo!) until the implementer provides the body.
        let md = render_markdown_report(&plan);

        // 1-based line number of the rewrite.
        assert!(
            md.contains("line 2") || md.contains("| 2 |") || md.contains("| 2|"),
            "markdown must contain the 1-based line number of the rewrite: {md}"
        );
        // Before/after content.
        assert!(
            md.contains("sha256hash=abc123"),
            "markdown must contain the before-text: {md}"
        );
        assert!(
            md.contains("filehash=abc123"),
            "markdown must contain the after-text: {md}"
        );
        // Rules-unchanged count: 3 total rules, 1 rewritten => 2 unchanged.
        // Must use an unambiguous substring so a renderer that omits or
        // miscomputes the unchanged count fails this assertion (not vacuously
        // green via "line 2" / "| 2 |" etc. which also contain '2').
        assert!(
            md.contains("2 unchanged")
                || md.contains("unchanged: 2")
                || md.contains("2 rules unchanged"),
            "markdown must contain an unambiguous unchanged-rules-count phrase (e.g. '2 unchanged'): {md}"
        );
        // Moved-file section.
        assert!(
            md.contains("fapolicyd.rules"),
            "markdown must mention the legacy file name: {md}"
        );
        assert!(
            md.contains("99-migrated.rules"),
            "markdown must mention the target file name: {md}"
        );
        // No timestamp (D1): match a real ISO date (YYYY-MM-DD), not stray
        // substrings like "T0"/"2026" that a random echoed path can contain
        // (the e2e flake). The synthetic plan here has a fixed path, but use the
        // precise check so this never regresses to the fragile substring form.
        let has_iso_date = md.as_bytes().windows(10).any(|w| {
            w[..4].iter().all(u8::is_ascii_digit)
                && w[4] == b'-'
                && w[5..7].iter().all(u8::is_ascii_digit)
                && w[7] == b'-'
                && w[8..10].iter().all(u8::is_ascii_digit)
        });
        assert!(
            !has_iso_date,
            "markdown must NOT contain a timestamp (D1): {md}"
        );
        // No fagenrules section when check is None.
        assert!(
            !md.to_lowercase().contains("fagenrules"),
            "fagenrules section must be absent when check is None: {md}"
        );
    }

    /// Test #212-7: `render_markdown_report` includes fagenrules section
    /// only when the check ran.
    ///
    #[test]
    fn render_markdown_report_includes_fagenrules_section_when_check_ran() {
        let mut plan = applied_plan_with_rewrite();
        plan.fagenrules_check = Some(FagenrulesCheck {
            status: "passed",
            detail: "Rules are current".to_string(),
        });
        let md = render_markdown_report(&plan);
        assert!(
            md.to_lowercase().contains("fagenrules") || md.to_lowercase().contains("verification"),
            "fagenrules section must appear when check ran: {md}"
        );
        // The status line is present...
        assert!(md.contains("passed"), "status must appear: {md}");
        // ...AND the detail line is rendered (it is gated on a non-empty detail,
        // so this pins that the detail branch actually fires).
        assert!(
            md.contains("Rules are current"),
            "the non-empty check detail must be rendered: {md}"
        );
    }

    /// #221: the post-apply verification shells out to `fapolicyd-cli
    /// --check-rules` (the `LiveProbe` runs the real syntax validator), NOT
    /// `fagenrules --check` (a staleness check, not a syntax validator). The
    /// operator-visible report header must name the command actually run.
    #[test]
    fn render_markdown_report_verification_header_names_the_command_actually_run() {
        let mut plan = applied_plan_with_rewrite();
        plan.fagenrules_check = Some(FagenrulesCheck {
            status: "passed",
            detail: "Rules are current".to_string(),
        });
        let md = render_markdown_report(&plan);
        assert!(
            md.contains("fapolicyd-cli --check-rules"),
            "verification header must name the command actually run \
             (`fapolicyd-cli --check-rules`): {md}"
        );
        assert!(
            !md.contains("fagenrules --check"),
            "verification header must NOT name the misleading verb \
             `fagenrules --check`: {md}"
        );
    }

    /// Test #212-8: absent --report -> no report file written anywhere.
    ///
    /// This is a behavioral test of the `run_with_probe` + report-write path.
    /// RED: `run_with_probe` skeleton does not write any report, so the
    /// "no file written" assertion is vacuously green. However, the test also
    /// asserts that the report argument is `None` - which is already enforced
    /// by the args helper. The RED aspect is the coupling: when the implementer
    /// adds the report-write path, if they fail to gate it on `args.report.is_some()`,
    /// they would write to a default path and break this test.
    ///
    /// Note: the truly RED assertion here is in test #212-9 (unwritable path).
    /// This test is partially vacuous in the skeleton; we document it as the
    /// "no-report" contract pin.
    #[test]
    fn no_report_flag_writes_no_report_file() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::absent();
        // apply_args has report: None
        let code = run_with_probe(apply_args(d.path()), &probe).unwrap();
        assert_eq!(code, EXIT_CLEAN);
        // Assert no extra files were written beyond the expected target.
        let entries: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        // Only rules.d/ subdirectory should exist (legacy file was moved).
        let non_rules_d: Vec<_> = entries
            .iter()
            .filter(|e| e.file_name() != "rules.d")
            .collect();
        assert!(
            non_rules_d.is_empty(),
            "no extra files outside rules.d/ must be written when --report is absent: {:?}",
            non_rules_d.iter().map(|e| e.path()).collect::<Vec<_>>()
        );
    }

    /// Test #212-9: unwritable --report path -> exit 3 (`EXIT_TOOL_FAILURE`),
    /// migration still applied.
    ///
    /// Owner decision (test-author proposed, pin here): the report write happens
    /// AFTER the apply; the apply stands even if the report write fails.
    ///
    /// RED: `run_with_probe` skeleton ignores `args.report`, so the exit-3
    /// assertion fails (it exits 0 or 2 from the probe result, never 3 from
    /// a report-write error).
    #[test]
    fn unwritable_report_path_exits_tool_failure_and_migration_applied() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::absent();
        let bad_report = d.path().join("does_not_exist").join("report.md");
        let code = run_with_probe(
            MigrateArgs {
                from: TargetVersionArg::Rhel8,
                to: TargetVersionArg::Rhel9,
                rules_dir: d.path().to_path_buf(),
                apply: true,
                delete_legacy: false,
                format: HumanJsonFormat::Json,
                report: Some(bad_report),
            },
            &probe,
        )
        .unwrap();
        // The --report path is unwritable (parent dir doesn't exist) -> exit 3.
        assert_eq!(
            code, EXIT_TOOL_FAILURE,
            "unwritable report path must yield exit 3 (EXIT_TOOL_FAILURE); got {code}"
        );
        // D1 corollary: the migration WAS applied even when report write fails.
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "migration must have applied (legacy file moved) before the report-write error"
        );
        assert!(
            d.path().join("rules.d").join("99-migrated.rules").exists(),
            "target file must exist after apply, even when report write fails"
        );
    }

    /// Exit-code precedence: when verification FAILED (exit 2, D7) AND the
    /// --report write also fails, the substantive ruleset error (exit 2) must
    /// win -- a missing report sidecar (exit 3) must NOT mask it.
    #[test]
    fn probe_failure_with_unwritable_report_keeps_exit_two() {
        let d = setup_legacy_dir();
        let probe = FakeMigrateProbe::failure("compiled.rules does not match");
        let bad_report = d.path().join("does_not_exist").join("report.md");
        let (code, plan) = run_with_probe_to_plan(
            MigrateArgs {
                from: TargetVersionArg::Rhel8,
                to: TargetVersionArg::Rhel9,
                rules_dir: d.path().to_path_buf(),
                apply: true,
                delete_legacy: false,
                format: HumanJsonFormat::Json,
                report: Some(bad_report),
            },
            &probe,
        )
        .unwrap();
        assert_eq!(
            code, EXIT_ERRORS,
            "verification failure (exit 2) must not be masked by a report-write failure (exit 3); got {code}"
        );
        assert_eq!(
            plan.fagenrules_check.as_ref().expect("check ran").status,
            "failed"
        );
        assert!(
            !d.path().join("fapolicyd.rules").exists(),
            "migration still applied (D7) even when both verification and report fail"
        );
    }

    // --- render_human verification section ---------------------------------

    fn plan_with_check(status: &'static str, detail: &str) -> MigratePlan {
        let mut plan = applied_plan_with_rewrite();
        plan.fagenrules_check = Some(FagenrulesCheck {
            status,
            detail: detail.to_string(),
        });
        plan
    }

    #[test]
    fn render_human_passed_shows_label_and_detail() {
        let human = render_human(&plan_with_check("passed", "all good here"));
        assert!(
            human.contains("Verification passed"),
            "passed status must render its label: {human}"
        );
        assert!(
            human.contains("all good here"),
            "a non-passed... non-empty detail must render for a passed check: {human}"
        );
    }

    #[test]
    fn render_human_failed_shows_label_and_detail() {
        let human = render_human(&plan_with_check("failed", "rules did not compile"));
        assert!(
            human.contains("Verification FAILED"),
            "failed status must render its label: {human}"
        );
        assert!(
            human.contains("rules did not compile"),
            "the failure detail must render: {human}"
        );
    }

    #[test]
    fn render_human_unavailable_suppresses_detail() {
        // For an unavailable check the detail is intentionally NOT printed (the
        // label already says why). Use a sentinel detail that cannot appear in
        // the fixed label text, so the absence assertion is unambiguous.
        let human = render_human(&plan_with_check("unavailable", "SENTINEL_DETAIL_ZZZ"));
        assert!(
            human.contains("unavailable"),
            "unavailable status must render its label: {human}"
        );
        assert!(
            !human.contains("SENTINEL_DETAIL_ZZZ"),
            "the detail must be suppressed for an unavailable check: {human}"
        );
    }

    // --- run_with_probe_to_plan downgrade guard ----------------------------

    #[test]
    fn downgrade_newer_to_older_errors_and_is_dry_run_aware() {
        // --from newer than --to is a refused downgrade (exit 3, layout "error").
        // apply=false, so the error plan must report dry_run = true.
        let d = tempfile::tempdir().unwrap();
        let probe = FakeMigrateProbe::absent();
        let (code, plan) = run_with_probe_to_plan(
            MigrateArgs {
                from: TargetVersionArg::Rhel9,
                to: TargetVersionArg::Rhel8,
                rules_dir: d.path().to_path_buf(),
                apply: false,
                delete_legacy: false,
                format: HumanJsonFormat::Json,
                report: None,
            },
            &probe,
        )
        .unwrap();
        assert_eq!(
            code, EXIT_TOOL_FAILURE,
            "downgrade must be refused (exit 3)"
        );
        assert_eq!(plan.layout, "error");
        assert!(plan.dry_run, "apply=false => the error plan is a dry-run");
        assert_eq!(probe.call_count(), 0, "downgrade errors before any probe");
    }

    #[test]
    fn equal_versions_are_not_a_downgrade() {
        // --from == --to is a valid no-op migration, NOT a downgrade: it must
        // proceed past the guard (here to nothing-to-migrate on an empty dir).
        let d = tempfile::tempdir().unwrap();
        let probe = FakeMigrateProbe::absent();
        let (code, plan) = run_with_probe_to_plan(
            MigrateArgs {
                from: TargetVersionArg::Rhel9,
                to: TargetVersionArg::Rhel9,
                rules_dir: d.path().to_path_buf(),
                apply: false,
                delete_legacy: false,
                format: HumanJsonFormat::Json,
                report: None,
            },
            &probe,
        )
        .unwrap();
        assert_ne!(
            code, EXIT_TOOL_FAILURE,
            "equal versions are not a downgrade"
        );
        assert_ne!(
            plan.layout, "error",
            "equal versions must not be the error layout"
        );
    }
}
