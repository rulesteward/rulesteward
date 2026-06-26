//! Cross-file drop-in override lint: sshd-F02.
//!
//! sshd-F02 (Fatal): a distro-shipped `sshd_config.d/*.conf` drop-in silently
//! beats the operator's hardened main `sshd_config`. This is a CROSS-FILE check
//! (it parallels the fapolicyd `fapd-F02` rules.d-vs-flat-file lint) and is the
//! one directory-mode sshd lint, so it is a SEPARATE entrypoint
//! ([`lint_drop_in`]) rather than a pass in the single-file [`crate::lints::lint`]
//! dispatcher.
//!
//! # Effective-value precedence (grounded on rocky9 / OpenSSH 9.9p1, 2026-06-26)
//!
//! sshd resolves directives by FIRST-VALUE-WINS, expanding `Include` inline at
//! its position in the main file; drop-ins are read in LEXICAL (glob) order. The
//! real RHEL `/etc/ssh/sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf`
//! near the TOP (before the hardening block), so a drop-in's value wins over a
//! later main-file setting. Verified with `sudo sshd -T -f <main>`:
//!
//! * Include (line 1) then `PermitRootLogin no` (line 2) + drop-in `yes`
//!   -> effective `yes` (drop-in wins).
//! * `PermitRootLogin no` (line 1) then Include (line 2) + drop-in `yes`
//!   -> effective `no` (main wins; it is first).
//! * two drop-ins `10-first.conf` (`yes`) + `90-last.conf` (`no`)
//!   -> effective `yes` (lexically-first wins).
//!
//! # Firing rule (LOCKED scope, W01-scoped)
//!
//! F02 fires when, for a W02-controlled STIG directive D set in 2+ locations, the
//! EFFECTIVE value (the one sshd actually uses) comes from a drop-in (not the main
//! `sshd_config`) AND FAILS [`crate::lints::stig::baseline_check`].
//!
//! # Shipped algorithm
//!
//! [`lint_drop_in`] builds the effective-config directive STREAM in sshd's read
//! order: it parses the main `sshd_config`, walks its global directives top to
//! bottom, and where it meets an `Include`, splices in the directives of every
//! matching drop-in (glob resolved relative to the main file, drop-ins sorted
//! LEXICALLY) at that position. Each stream entry records its SOURCE file and
//! whether it came from a `Match all` block. Then, for every W02-controlled
//! directive that appears 2+ times, it selects the EFFECTIVE entry (see below): if
//! that entry lives in a drop-in (not the main file) and FAILS
//! [`crate::lints::stig::baseline_check`], it emits one Fatal `sshd-F02` anchored
//! to that drop-in file + line.
//!
//! Each file contributes the directives of its `Block::Global` AND of any
//! UNCONDITIONAL `Match all` block (exactly one criterion whose keyword is
//! case-insensitively `all`), in SOURCE order (a file's global directives precede
//! its `Match all` directives). CONDITIONAL `Match` blocks
//! (`User`/`Group`/`Address`/`Host`/...) are per-connection and stay OUT of scope
//! (a future Match-aware cross-file lint).
//!
//! An `Include` is expanded whether it appears at top level OR inside an
//! unconditional `Match all` block (both are unconditionally active, verified
//! rocky9 `sudo sshd -T -f`); the spliced drop-in directives inherit the enclosing
//! `Match all`'s always-active status. An `Include` inside a CONDITIONAL `Match`
//! is NOT folded (the conditional block is excluded before the Include is ever
//! reached), so a drop-in pulled in only for `Match User root` stays out of scope.
//!
//! # `Match all` override precedence (verified rocky9 `sudo sshd -T -f`)
//!
//! An ACTIVE `Match all` block overrides the global section REGARDLESS of textual
//! position (it is not a flat first-value-wins). So the effective entry for a
//! directive is:
//!
//! * the FIRST `Match all` occurrence, if any occurrence is in a `Match all` block
//!   (first-`Match all`-wins among multiple, confirmed on rocky9 with two
//!   competing `Match all` blocks);
//! * otherwise the FIRST occurrence overall (global first-value-wins).
//!
//! This catches a `Match all` drop-in that beats a global `no` set BEFORE the
//! Include (a flat model's false negative), and spares a drop-in whose own
//! `Match all` re-hardens its earlier permissive global (a flat model's false
//! positive).
//!
//! # Known limitations (deferred follow-ups)
//!
//! * ONE level of `Include` only: a drop-in that itself `Include`s another file
//!   is not recursively resolved. The standard `/etc/ssh` layout does not nest
//!   drop-ins, so this covers the real distro layout; deep nesting is a deferred
//!   follow-up.
//! * Directory mode currently runs the F02 cross-file check ONLY. Running the
//!   single-file lint suite (sshd-E0x / W0x) over the merged effective config is a
//!   deferred follow-up; this PR keeps directory mode F02-only.

use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, MatchBlock};
use crate::lints::stig::{BaselineCheck, baseline_check};
use crate::lints::{SshdLintContext, anchored};

/// sshd-F02: a drop-in `sshd_config.d/*.conf` fragment overrides a W01/W02-scoped
/// global directive with a baseline-failing value that WINS by first-value-wins
/// precedence.
///
/// `dir` is the standard `/etc/ssh`-layout directory: it contains the main
/// `sshd_config` plus a `sshd_config.d/` directory of `*.conf` drop-ins. The
/// returned diagnostics are anchored to the WINNING drop-in file (the source the
/// operator must edit), one per offending directive.
#[must_use]
pub fn lint_drop_in(dir: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let main_path = dir.join("sshd_config");
    let Ok(main_src) = std::fs::read_to_string(&main_path) else {
        // No readable main `sshd_config` -> nothing to evaluate. (A directory the
        // operator points at but that has no main file is not an F02 concern; the
        // CLI's directory routing only reaches here for the /etc/ssh layout.)
        return Vec::new();
    };

    // Build the effective directive stream in sshd's read order (main top to
    // bottom, with each Include expanded inline to its lexically-sorted drop-ins).
    // Each entry is tagged whether it came from an unconditional `Match all` block.
    let stream = build_stream(&main_path, &main_src);

    // For each W02-controlled directive set in 2+ locations, fire when the
    // EFFECTIVE entry (the value sshd actually uses) is a drop-in whose value fails
    // baseline. `seen` ensures one decision per directive (at its first appearance).
    let mut diags = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for entry in &stream {
        if !seen.insert(entry.keyword_lower.as_str()) {
            continue;
        }
        // The directive must be set in 2+ locations (something to override).
        let occurrences: Vec<&StreamEntry> = stream
            .iter()
            .filter(|e| e.keyword_lower == entry.keyword_lower)
            .collect();
        if occurrences.len() < 2 {
            continue;
        }
        let effective = effective_entry(&occurrences);
        // The effective value must come from a drop-in, not the operator's main
        // `sshd_config` (the main file holding is the operator's hardening intact).
        if effective.source == main_path {
            continue;
        }
        // The effective drop-in value must fail the STIG baseline.
        let BaselineCheck::Violation {
            displayed_value, ..
        } = baseline_check(&effective.keyword_lower, &effective.args, ctx.target)
        else {
            continue;
        };
        let file_name = effective.source.file_name().map_or_else(
            || effective.source.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        diags.push(anchored(
            Severity::Fatal,
            "sshd-F02",
            effective.span.clone(),
            format!(
                "drop-in '{file_name}' overrides '{}' with the baseline-failing value '{displayed_value}', \
                 which is the effective value (wins over the main sshd_config)",
                effective.keyword,
            ),
            &effective.source,
            effective.line,
        ));
    }
    diags
}

/// The EFFECTIVE entry among all occurrences of one directive, mirroring sshd's
/// real precedence (verified rocky9 / OpenSSH 9.9p1 `sudo sshd -T -f`):
///
/// * If ANY occurrence is in an active `Match all` block, an active Match block
///   OVERRIDES the global section regardless of textual position, so the effective
///   value is the FIRST `Match all` occurrence (first-Match-all-wins, confirmed on
///   rocky9 with two competing `Match all` blocks).
/// * Otherwise the global section is first-value-wins, so the effective value is
///   the FIRST occurrence overall.
///
/// `occurrences` is in Include-expanded source order; callers pass 2+ entries.
fn effective_entry<'a>(occurrences: &[&'a StreamEntry]) -> &'a StreamEntry {
    occurrences
        .iter()
        .find(|e| e.is_match_all)
        .copied()
        .unwrap_or_else(|| {
            occurrences
                .first()
                .copied()
                .expect("caller passes 2+ occurrences")
        })
}

/// One directive in the effective-config stream, tagged with the file it came
/// from (so an F02 diagnostic can anchor to the effective drop-in) and whether it
/// is effective within an always-active `Match all` block (so the effective-value
/// selection can apply Match-all override precedence).
struct StreamEntry {
    keyword: String,
    keyword_lower: String,
    args: Vec<String>,
    source: PathBuf,
    line: usize,
    span: rulesteward_core::Span,
    /// True when this directive is effective within an always-active `Match all`
    /// block (an always-active block that overrides the global section): either it
    /// sits directly in a `Match all`, or it is a drop-in directive spliced in by
    /// an `Include` placed inside a `Match all`.
    is_match_all: bool,
}

/// Build the effective directive stream: the main file's global directives in
/// order, with each `Include` replaced inline by the directives of its matching
/// drop-ins (glob resolved relative to the main file, drop-ins read in LEXICAL
/// order, matching sshd's first-value-wins read of `sshd_config.d/*.conf`).
///
/// Each file contributes its GLOBAL block plus any UNCONDITIONAL `Match all`
/// block (in source order). Drop-in precedence is a daemon-level concern: the
/// global block and an always-active `Match all` both apply unconditionally,
/// whereas conditional Match blocks are per-connection and excluded. A file that
/// fails to parse contributes nothing (a parse error is sshd-F01's province, not
/// F02's). One level of Include is expanded (the standard layout does not nest).
///
/// An `Include` is expanded whether it appears at top level OR inside an
/// unconditional `Match all` block (both are unconditionally active, verified
/// rocky9 `sudo sshd -T -f`): in the `Match all` case the spliced drop-in
/// directives are effective WITHIN that always-active block, so the parent's
/// `is_match_all` is OR-ed onto each spliced directive's own flag. An `Include`
/// inside a CONDITIONAL `Match` is per-connection and never reaches this loop
/// (`effective_directives_of` excludes conditional Match blocks), so it is not
/// folded.
fn build_stream(main_path: &Path, main_src: &str) -> Vec<StreamEntry> {
    let mut stream = Vec::new();
    let base_dir = main_path.parent().unwrap_or_else(|| Path::new("."));

    for (directive, is_match_all) in effective_directives_of(main_src, main_path) {
        if directive.keyword.eq_ignore_ascii_case("include") {
            for pattern in &directive.args {
                for dropin_path in resolve_dropins(base_dir, pattern) {
                    let Ok(src) = std::fs::read_to_string(&dropin_path) else {
                        continue;
                    };
                    for (d, dropin_is_match_all) in effective_directives_of(&src, &dropin_path) {
                        // The spliced directive is unconditionally active iff the
                        // Include itself is unconditionally active (top-level OR in
                        // a `Match all`) AND its own origin is unconditional.
                        stream.push(entry_from(
                            d,
                            &dropin_path,
                            is_match_all || dropin_is_match_all,
                        ));
                    }
                }
            }
        } else {
            stream.push(entry_from(directive, main_path, is_match_all));
        }
    }
    stream
}

/// Parse `src` and return its UNCONDITIONALLY-active directives tagged with their
/// origin: the GLOBAL block (tag `false`) followed by any `Match all` block bodies
/// (tag `true`), in SOURCE order (global first, then each `Match all` in the order
/// it appears). Conditional Match blocks are excluded (per-connection, out of F02
/// scope). Empty when the file fails to parse (F02 does not surface parse errors;
/// sshd-F01 owns those).
fn effective_directives_of(src: &str, file: &Path) -> Vec<(crate::ast::Directive, bool)> {
    let Ok(blocks) = crate::parser::parse_config_str_located(src, file) else {
        return Vec::new();
    };
    let mut directives = Vec::new();
    for block in blocks {
        match block {
            Block::Global(global) => directives.extend(global.into_iter().map(|d| (d, false))),
            Block::Match(match_block) if is_unconditional_match_all(&match_block) => {
                directives.extend(match_block.body.into_iter().map(|d| (d, true)));
            }
            // Conditional Match block: per-connection, not part of the
            // unconditional effective config F02 reasons about.
            Block::Match(_) => {}
        }
    }
    directives
}

/// Whether a Match block is the unconditional `Match all`: exactly one criterion
/// whose keyword is case-insensitively `all`. `all` is always active (verified
/// rocky9 `sshd -T`); any other criterion (or `all` combined with another) is
/// connection-conditional and out of scope.
fn is_unconditional_match_all(block: &MatchBlock) -> bool {
    block.criteria.len() == 1 && block.criteria[0].keyword.eq_ignore_ascii_case("all")
}

/// Build a [`StreamEntry`] from a parsed directive, the file it came from, and
/// whether it originated in an unconditional `Match all` block.
fn entry_from(directive: crate::ast::Directive, source: &Path, is_match_all: bool) -> StreamEntry {
    StreamEntry {
        keyword_lower: directive.keyword.to_ascii_lowercase(),
        keyword: directive.keyword,
        args: directive.args,
        source: source.to_path_buf(),
        line: directive.line,
        span: directive.span,
        is_match_all,
    }
}

/// Resolve one `Include` glob pattern (relative to the main file's directory, per
/// sshd) to the matching FILES, sorted LEXICALLY by their full path. Mirrors the
/// glob resolution sshd-E03 uses (the `glob` crate); a literal path resolves to
/// itself. Non-file matches and unparseable patterns are skipped.
fn resolve_dropins(base_dir: &Path, pattern: &str) -> Vec<PathBuf> {
    let resolved = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base_dir.join(pattern)
    };
    let Ok(matches) = glob::glob(&resolved.to_string_lossy()) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = matches.flatten().filter(|p| p.is_file()).collect();
    // `glob` returns paths in sorted order already, but sort explicitly so the
    // lexical drop-in precedence is not implicitly dependent on that behavior.
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::lint_drop_in;
    use crate::lints::{SshdLintContext, TargetVersion};
    use rulesteward_core::{Diagnostic, Severity};

    fn ctx() -> SshdLintContext {
        SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: false,
        }
    }

    /// Build an `/etc/ssh`-layout directory and run the F02 lint over it.
    ///
    /// Writes the main `sshd_config` (with the `{DIR}` placeholder replaced by the
    /// tempdir's `sshd_config.d/*.conf` glob, so any `Include` in the template
    /// resolves to the just-written drop-ins) plus one `<name> -> <body>` drop-in
    /// per entry into `sshd_config.d/`. Returns the diagnostics. The tempdir is
    /// kept alive until after the lint call, then cleaned up.
    fn f02_diags(main: &str, dropins: &[(&str, &str)]) -> Vec<Diagnostic> {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        let include_glob = dropin_dir.join("*.conf").display().to_string();
        let main_resolved = main.replace("{DIR}", &include_glob);
        std::fs::write(dir.path().join("sshd_config"), &main_resolved).expect("write main");
        for (name, body) in dropins {
            std::fs::write(dropin_dir.join(name), body).expect("write drop-in");
        }
        lint_drop_in(dir.path(), &ctx())
    }

    // ----------------------------------------------------------------------
    // F02 FIRES
    // ----------------------------------------------------------------------

    #[test]
    fn scenario_a_dropin_wins_over_later_main_setting_fires() {
        // Scenario A (VERIFIED rocky9 / OpenSSH 9.9p1): main has the Include FIRST
        // (line 1), then `PermitRootLogin no` (line 2); the drop-in sets
        // `PermitRootLogin yes`. Effective value = yes (drop-in wins) and yes
        // FAILS baseline (requires 'no'). F02 MUST fire.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "Scenario A: drop-in's baseline-failing value wins over the later \
             main-file setting -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        // The diagnostic names the offending drop-in file, the directive, and the
        // winning value (stable substrings the operator can grep).
        assert!(
            d.message.contains("50-x.conf"),
            "names the winning drop-in file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "names the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "names the winning value: {}",
            d.message
        );
        // Anchored to the drop-in file (the source the operator must edit), not
        // the main sshd_config.
        assert!(
            d.file.to_string_lossy().contains("50-x.conf"),
            "diagnostic file is the winning drop-in: {}",
            d.file.display()
        );
    }

    #[test]
    fn scenario_c_lexically_first_dropin_wins_fires() {
        // Scenario C (VERIFIED rocky9): two drop-ins, 10-first.conf=yes,
        // 90-last.conf=no; main only Includes them. Effective = yes (lexically
        // first wins); yes FAILS baseline. F02 fires and the WINNING drop-in is
        // 10-first.conf, NOT 90-last.conf.
        let main = "Include {DIR}\n";
        let diags = f02_diags(
            main,
            &[
                ("10-first.conf", "PermitRootLogin yes\n"),
                ("90-last.conf", "PermitRootLogin no\n"),
            ],
        );
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "Scenario C: lexically-first drop-in (10-first.conf=yes) wins -> one \
             sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert!(
            d.message.contains("10-first.conf"),
            "the WINNING (lexically first) drop-in is named, not 90-last.conf: {}",
            d.message
        );
        assert!(
            !d.message.contains("90-last.conf"),
            "the losing (lexically last, compliant) drop-in is NOT named: {}",
            d.message
        );
    }

    #[test]
    fn unconditional_match_all_dropin_block_overrides_global_fires() {
        // An UNCONDITIONAL `Match all` block in a drop-in is always active
        // (verified rocky9 / OpenSSH 9.9p1 `sshd -T`: a `Match all` body applies to
        // every connection), so a `PermitRootLogin yes` inside a drop-in's
        // `Match all` block beats the main file's hardened `PermitRootLogin no`.
        // main Includes the drop-in dir FIRST then sets `no`; the drop-in's
        // `Match all` sets `yes`, which is the EFFECTIVE value and FAILS baseline.
        // F02 MUST fire, anchored to the drop-in file, naming the directive + value.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "Match all\nPermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "an unconditional `Match all` drop-in block overriding a hardened global \
             -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        assert!(
            d.message.contains("50-x.conf"),
            "names the winning drop-in file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "names the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "names the winning value: {}",
            d.message
        );
    }

    #[test]
    fn dropin_match_all_overrides_main_global_set_before_include_fires() {
        // PRECEDENCE (verified rocky9 `sudo sshd -T -f`): an ACTIVE `Match all`
        // block overrides the global section REGARDLESS of textual position. Here
        // the main file sets `PermitRootLogin no` on line 1 BEFORE the Include, then
        // the drop-in's `Match all` sets `yes`. Real sshd effective value = `yes`
        // (Match-all overrides the earlier global no), and `yes` FAILS baseline, so
        // F02 MUST fire anchored to the drop-in. A FLAT first-value-wins model
        // wrongly picks the earlier global `no` (a FALSE NEGATIVE) -> this is the
        // killing test for that bug.
        let main = "PermitRootLogin no\nInclude {DIR}\n";
        let diags = f02_diags(main, &[("50-x.conf", "Match all\nPermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "an active `Match all` drop-in overrides the earlier global `no` \
             (effective = yes) -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        assert!(
            d.message.contains("50-x.conf"),
            "anchored to the winning drop-in file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "names the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "names the effective (winning) value: {}",
            d.message
        );
    }

    #[test]
    fn include_inside_main_match_all_block_folds_dropin_fires() {
        // PRECEDENCE (verified rocky9 `sudo sshd -T -f`): an `Include` placed INSIDE
        // an unconditional `Match all` block in the main file is unconditionally
        // active, so the drop-in's directives are effective within that always-active
        // block. Here main sets `PermitRootLogin no` (global, line 1) then opens
        // `Match all` and Includes the drop-in dir; the drop-in sets
        // `PermitRootLogin yes`. Real sshd effective = `yes` (the Match-all Include's
        // drop-in beats the earlier global no) and `yes` FAILS baseline -> F02 MUST
        // fire anchored to the drop-in. This is the round-3 killing test: an impl
        // that only expands TOP-LEVEL global Includes misses it (FALSE NEGATIVE).
        let main = "PermitRootLogin no\nMatch all\nInclude {DIR}\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "an Include inside a `Match all` block folds the drop-in (effective = yes) \
             -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        assert!(
            d.message.contains("50-x.conf"),
            "anchored to the winning drop-in file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "names the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "names the effective (winning) value: {}",
            d.message
        );
    }

    #[test]
    fn include_inside_main_match_all_block_with_top_level_global_fires() {
        // Variant of the above with the hardened value at TOP LEVEL only (no
        // duplicate global before the Match-all Include): main sets a top-level
        // `PermitRootLogin no`, then a `Match all` block Includes the drop-in dir,
        // and the drop-in sets `PermitRootLogin yes`. Two occurrences (top-level no +
        // Match-all-folded yes); the Match-all-folded drop-in value wins (effective =
        // yes, verified rocky9), fails baseline -> exactly one F02 anchored to the
        // drop-in. Confirms the fold works regardless of whether the main file also
        // repeats the directive before the Include.
        let main = "PermitRootLogin no\nMatch all\nInclude {DIR}\n";
        let diags = f02_diags(main, &[("60-y.conf", "PermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "a top-level hardened global beaten by a Match-all Include drop-in \
             -> exactly one sshd-F02; got {diags:?}"
        );
        assert!(
            f02[0].message.contains("60-y.conf"),
            "anchored to the winning drop-in file: {}",
            f02[0].message
        );
    }

    // ----------------------------------------------------------------------
    // F02 does NOT fire
    // ----------------------------------------------------------------------

    #[test]
    fn conditional_match_user_dropin_block_does_not_fire() {
        // A CONDITIONAL `Match User root` block is per-connection: it applies only
        // to that user's sessions, NOT to the daemon's unconditional effective
        // config. So a `PermitRootLogin yes` inside a drop-in's `Match User root`
        // block does NOT unconditionally weaken the hardened global `no`, and F02
        // (which reasons about the unconditional effective config) must NOT fire. A
        // future Match-aware cross-file lint may flag conditional escapes; F02 does
        // not. This kills an impl that pulls in EVERY Match block regardless of its
        // criteria.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(
            main,
            &[("50-x.conf", "Match User root\nPermitRootLogin yes\n")],
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "a conditional `Match User root` drop-in block is per-connection and \
             out of F02 scope; F02 must NOT fire; got {diags:?}"
        );
    }

    #[test]
    fn dropin_match_all_overrides_its_own_global_to_compliant_does_not_fire() {
        // PRECEDENCE (verified rocky9 `sudo sshd -T -f`): a drop-in's OWN active
        // `Match all` block overrides the drop-in's OWN earlier global section. Here
        // the drop-in sets `PermitRootLogin yes` in its global section then `no`
        // inside its `Match all` block. Real sshd effective value = `no` (the
        // Match-all `no` overrides the earlier global `yes`), which PASSES baseline,
        // so F02 must NOT fire. A FLAT first-value-wins model wrongly picks the
        // drop-in's first global `yes` and fires (a FALSE POSITIVE) -> this is the
        // killing test for that bug.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(
            main,
            &[(
                "50-x.conf",
                "PermitRootLogin yes\nMatch all\nPermitRootLogin no\n",
            )],
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "the drop-in's own `Match all no` overrides its earlier global `yes` \
             (effective = no, compliant) -> F02 must NOT fire; got {diags:?}"
        );
    }

    #[test]
    fn include_inside_conditional_match_block_is_not_folded_does_not_fire() {
        // CRITICAL DISCRIMINATOR (verified rocky9 `sudo sshd -T -f`): an `Include`
        // placed inside a CONDITIONAL `Match User root` block is per-connection. Its
        // drop-in directives apply ONLY when the connection matches user=root, NOT to
        // the daemon's unconditional effective config. Verified: plain
        // `sudo sshd -T -f` reports `permitrootlogin no` (the hardened global holds);
        // only `sudo sshd -T -C user=root` reports `yes`. So F02 (which reasons about
        // the UNCONDITIONAL effective config) must NOT fire. This kills an impl that
        // expands EVERY Include regardless of the enclosing Match's criteria.
        let main = "PermitRootLogin no\nMatch User root\nInclude {DIR}\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin yes\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "an Include inside a CONDITIONAL `Match User root` block is per-connection \
             and out of F02 scope; F02 must NOT fire; got {diags:?}"
        );
    }

    #[test]
    fn scenario_b_main_setting_before_include_does_not_fire() {
        // Scenario B (VERIFIED rocky9): main has `PermitRootLogin no` FIRST (line
        // 1), then the Include (line 2). The drop-in's `yes` LOSES (main is first
        // -> effective no, operator hardening holds). F02 MUST NOT fire. This is
        // the discriminator that kills a "fire whenever any drop-in sets a
        // controlled directive, ignoring precedence" impl.
        let main = "PermitRootLogin no\nInclude {DIR}\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin yes\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "Scenario B: the main-file setting precedes the Include so it wins; \
             F02 must NOT fire; got {diags:?}"
        );
    }

    #[test]
    fn compliant_dropin_value_does_not_fire() {
        // The drop-in WINS (Include is first) but its value is COMPLIANT
        // (PermitRootLogin no passes baseline). F02 must NOT fire. This is the
        // discriminator that kills a "fire whenever a drop-in overrides, ignoring
        // the baseline" impl.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin no\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "a winning drop-in with a COMPLIANT value is not a finding; got {diags:?}"
        );
    }

    #[test]
    fn dropin_agrees_with_main_does_not_fire() {
        // The drop-in sets the SAME compliant value the main file already has.
        // No weakening occurs; F02 must NOT fire.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin no\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "a drop-in that agrees with the main file is not a finding; got {diags:?}"
        );
    }

    #[test]
    fn dropin_for_non_w02_directive_does_not_fire() {
        // The drop-in WINS (Include first) but sets a directive that is NOT a
        // W02-controlled STIG value check (MaxAuthTries is a CIS control, absent
        // from the STIG set -> baseline_check returns NotControlled). F02 is
        // W01/W02-scoped, so it must NOT fire for it. Kills an impl that flags any
        // overriding drop-in regardless of whether the directive is in scope.
        let main = "Include {DIR}\nMaxAuthTries 4\n";
        let diags = f02_diags(main, &[("50-x.conf", "MaxAuthTries 99\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "MaxAuthTries is not a W02-controlled STIG directive; F02 must not \
             fire; got {diags:?}"
        );
    }

    #[test]
    fn no_dropins_present_does_not_fire() {
        // A directory whose main file sets a baseline-FAILING value but has no
        // drop-ins overriding it: that is a single-file W02 concern, not F02. With
        // no drop-in present, F02 has nothing to fire on.
        let main = "PermitRootLogin yes\n";
        let diags = f02_diags(main, &[]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "no drop-ins present -> F02 cannot fire (single-file W02 territory); \
             got {diags:?}"
        );
    }

    #[test]
    fn dropin_directive_absent_from_main_does_not_fire() {
        // The drop-in sets a baseline-failing value for a directive the MAIN file
        // never sets. F02 is an OVERRIDE check: it requires the main file to also
        // set the directive (the drop-in beating the operator's setting). A
        // directive only the drop-in sets is not an override, so F02 must NOT
        // fire. Kills an impl that flags any baseline-failing drop-in value
        // without checking the main file sets the same directive.
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "X11Forwarding yes\n")]);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "the drop-in sets a directive absent from the main file -> not an \
             override -> F02 must not fire; got {diags:?}"
        );
    }
}
