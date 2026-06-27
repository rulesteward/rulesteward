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
//! # Nested `Include` resolution (issue #323)
//!
//! `Include` is resolved RECURSIVELY to arbitrary depth, mirroring OpenSSH
//! `servconf.c` (which expands includes recursively up to `SERVCONF_MAX_DEPTH`).
//! A drop-in that itself `Include`s a second file has that second file's
//! directives spliced in at the nested `Include`'s position; each spliced entry
//! is stamped with the file it ACTUALLY came from (the deepest file containing the
//! directive), so F02 anchors to the true source rather than the intermediate
//! file. The enclosing-block `is_match_all` tag is OR-ed DOWN through every include
//! level, and the "global + unconditional `Match all` only" effective-directive
//! filter applies at every level (a directive inside a CONDITIONAL `Match` is
//! excluded before its enclosing `Include` is ever reached). A cycle guard
//! (canonicalized-path ancestry chain plus a depth cap mirroring OpenSSH's
//! `SERVCONF_MAX_DEPTH`) keeps a recursive/cyclic include set terminating; see
//! [`build_stream`].
//!
//! # Merged-effective single-file suite over a directory (issue #324)
//!
//! Directory mode also runs the single-file lint suite (sshd-E01 / W01..W04 / W06)
//! over the MERGED EFFECTIVE config (base `sshd_config` + drop-ins resolved by
//! sshd's real precedence), in ADDITION to the cross-file F02 pass. See
//! [`lint_merged`] for the entrypoint and [`build_merged`] for the synthetic-block
//! + provenance-map construction. F02 (`lint_drop_in`) stays a SEPARATE call.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity, Span};

use crate::ast::{Block, Directive, MatchBlock};
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
        // Name what the winning drop-in beats: the operator's main sshd_config (the
        // canonical F02), or a lower-precedence drop-in. Never claim "the main
        // sshd_config" when the main file does not set this directive.
        let beaten = if occurrences.iter().any(|e| e.source == main_path) {
            "the main sshd_config"
        } else {
            "a lower-precedence drop-in"
        };
        diags.push(anchored(
            Severity::Fatal,
            "sshd-F02",
            effective.span.clone(),
            format!(
                "drop-in '{file_name}' overrides '{}' with the baseline-failing value '{displayed_value}', \
                 which is the effective value (wins over {beaten})",
                effective.keyword,
            ),
            &effective.source,
            effective.line,
        ));
    }
    diags
}

/// Provenance of one synthetic merged directive: the REAL file, line, and span
/// the effective value came from (a drop-in, the base, or a nested include),
/// keyed by the synthetic directive's 1-based line in the merged global block.
struct Provenance {
    source: PathBuf,
    line: usize,
    span: Span,
}

/// Run the single-file lint suite over the MERGED config of a `/etc/ssh`-layout
/// directory, with each directive-anchored finding REMAPPED to the real drop-in
/// file + line it came from (issue #324, including the conditional-`Match` follow-up).
///
/// `dir` is the standard layout: a main `sshd_config` plus a `sshd_config.d/`
/// directory of `*.conf` drop-ins. The synthetic view is built by [`build_merged`]:
/// a leading `Block::Global` of one EFFECTIVE `Directive` per keyword (deduped via
/// sshd's first-occurrence / first-`Match all` precedence, reusing
/// [`effective_entry`]), FOLLOWED BY the conditional `Match` blocks gathered from
/// base + drop-ins (bodies as-written). This split is what makes the two pass
/// families correct at once:
///
/// * EFFECTIVE-value passes -- sshd-W01 (required-missing) and sshd-W02
///   (weaker-than-baseline) -- read `blocks[0]` (the global) ONLY, so a value set
///   only inside a conditional `Match` block never satisfies W01 nor triggers W02
///   (it is per-connection, not the daemon baseline).
/// * AS-WRITTEN passes -- sshd-E01 / W03 / W04 / W06 and the Match-oriented
///   sshd-E04 / W05 -- scan every `Block::Match` body, so conditional-`Match`
///   content that single-file mode reports is reached in dir mode too (the #324
///   parity fix), anchored to the real file + line via the remap.
///
/// Suppressed by construction: sshd-E02 stays quiet on the deduped global (it may
/// still fire on a within-Match duplicate -- correct parity); sshd-E03 finds no
/// `Include` (they are resolved away). The whole [`crate::lints::lint`] dispatcher
/// is reused UNCHANGED.
///
/// Anchoring: the base `sshd_config` path is the sentinel source, so file-level
/// findings (sshd-W01 absent-directive, `line == 0`) already anchor to the base and
/// need no remap. Each directive-anchored finding (`line > 0`) is remapped to its
/// real source file + line + span via the provenance map; a `line > 0` not in the
/// map (should not happen) falls back to the base path rather than panicking.
#[must_use]
pub fn lint_merged(dir: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let base_path = dir.join("sshd_config");
    let Ok(base_src) = std::fs::read_to_string(&base_path) else {
        // No readable main `sshd_config` -> nothing to evaluate (matches
        // `lint_drop_in`'s tolerance of a directory with no main file).
        return Vec::new();
    };

    let (blocks, provenance) = build_merged(&base_path, &base_src);

    // The merged suite runs the single-file dispatcher over the synthetic global,
    // anchored (by sentinel) to the base file so W01's `line == 0` findings land on
    // the base path; directive-anchored findings are remapped below.
    let raw = crate::lints::lint(&blocks, &base_path, ctx);

    raw.into_iter()
        .map(|mut diag| {
            if diag.line == 0 {
                // File-level finding (sshd-W01 absent directive): already anchored
                // to the base `sshd_config` via the sentinel. Leave as-is.
                return diag;
            }
            // Directive-anchored finding: remap to the real winning source.
            if let Some(prov) = provenance.get(&diag.line) {
                let source_id = prov.source.display().to_string();
                diag.file = prov.source.clone();
                diag.line = prov.line;
                diag.span = prov.span.clone();
                diag.source_id = Some(source_id);
            } else {
                // A `line > 0` with no provenance entry should not occur (every
                // synthetic directive is registered), but never panic: fall back to
                // anchoring at the base file.
                diag.file.clone_from(&base_path);
                diag.source_id = Some(base_path.display().to_string());
            }
            diag
        })
        .collect()
}

/// One conditional `Match` block gathered from the Include-expanded config, with
/// its real source file recorded so its synthetic copy can be remapped back. The
/// header and every body directive keep their REAL `line` / `span`; the synthetic
/// renumbering and provenance happen in [`build_merged`].
struct MergedMatch {
    /// The original parsed Match block (criteria + body + header line/span), kept
    /// verbatim so the as-written passes see exactly what the operator wrote.
    block: MatchBlock,
    /// The real file the block was written in (base or a drop-in), for remap.
    source: PathBuf,
}

/// Build the synthetic MERGED view of a `/etc/ssh` layout. Two parts:
///
/// 1. A leading `Block::Global` holding ONE effective `Directive` per keyword (in
///    first-seen emission order), chosen by [`effective_entry`] over the
///    Include-expanded stream (F02 precedence: first `Match all` wins, else global
///    first-value-wins). This is the EFFECTIVE-value view the W01/W02 passes read
///    (they read `blocks[0]` only), so per-connection `Match` values never reach
///    them.
/// 2. The CONDITIONAL `Match` blocks (`User`/`Group`/`Address`/...; NOT the
///    unconditional `Match all`, which is already folded into the effective global)
///    gathered from the base file and every Include-reachable drop-in, in source
///    order, with their bodies preserved AS WRITTEN. These feed the "as-written"
///    passes (E01/E04/W03/W04/W05/W06), which scan `Block::Match` bodies -- so
///    dir mode reaches conditional-Match content that single-file mode reports
///    (issue #324 parity), instead of silently dropping it.
///
/// Returns the synthetic blocks plus a provenance map from each synthetic 1-based
/// `line` (the global directives are numbered 1..G, then the Match headers + bodies
/// continue G+1..N -- no collisions) to the REAL source file / line / span. Every
/// directive's synthetic `span` is `0..0`; the real span is restored by the remap
/// in [`lint_merged`]. The Match HEADER also gets a synthetic line + provenance,
/// so a future pass anchoring to the header line still remaps correctly (no current
/// pass does; E04/W05 anchor to the body directive line).
fn build_merged(base_path: &Path, base_src: &str) -> (Vec<Block>, HashMap<usize, Provenance>) {
    let stream = build_stream(base_path, base_src);

    let mut provenance: HashMap<usize, Provenance> = HashMap::new();
    // A monotonically increasing synthetic 1-based line, shared across the global
    // directives and the Match headers + bodies so every number is unique.
    let mut next_line: usize = 0;
    let mut alloc = |source: &Path, line: usize, span: &Span| -> usize {
        next_line += 1;
        provenance.insert(
            next_line,
            Provenance {
                source: source.to_path_buf(),
                line,
                span: span.clone(),
            },
        );
        next_line
    };

    // Part 1: the effective global (one directive per keyword, F02 precedence).
    let mut directives: Vec<Directive> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for entry in &stream {
        // One effective directive per keyword, at its first appearance (the same
        // dedup discipline F02 uses).
        if !seen.insert(entry.keyword_lower.as_str()) {
            continue;
        }
        let occurrences: Vec<&StreamEntry> = stream
            .iter()
            .filter(|e| e.keyword_lower == entry.keyword_lower)
            .collect();
        let effective = effective_entry(&occurrences);
        let synthetic_line = alloc(&effective.source, effective.line, &effective.span);
        directives.push(Directive {
            keyword: effective.keyword.clone(),
            args: effective.args.clone(),
            line: synthetic_line,
            span: 0..0,
        });
    }

    let mut blocks: Vec<Block> = vec![Block::Global(directives)];

    // Part 2: the conditional Match blocks, gathered from base + Include-reachable
    // drop-ins, bodies preserved as-written, each header + directive renumbered to
    // a fresh synthetic line with provenance to its real source.
    for merged in collect_conditional_matches(base_path, base_src) {
        let MergedMatch { block, source } = merged;
        let header_line = alloc(&source, block.line, &block.span);
        let body: Vec<Directive> = block
            .body
            .into_iter()
            .map(|d| {
                let line = alloc(&source, d.line, &d.span);
                Directive {
                    keyword: d.keyword,
                    args: d.args,
                    line,
                    span: 0..0,
                }
            })
            .collect();
        blocks.push(Block::Match(MatchBlock {
            criteria: block.criteria,
            body,
            line: header_line,
            span: 0..0,
        }));
    }

    (blocks, provenance)
}

/// Gather the CONDITIONAL `Match` blocks (NOT the unconditional `Match all`) of the
/// base file and every Include-reachable drop-in, in source order, each tagged with
/// its real source file. Mirrors [`build_stream`]'s Include reachability (top-level
/// Includes and Includes inside a `Match all`, recursively, with the same cycle
/// guard and depth cap), but COLLECTS the conditional `Match` blocks the
/// effective-stream build deliberately drops. Bodies are kept verbatim (Includes
/// inside a conditional `Match` are NOT expanded -- they are per-connection, and the
/// as-written single-file passes never expand Includes either).
fn collect_conditional_matches(base_path: &Path, base_src: &str) -> Vec<MergedMatch> {
    let mut matches = Vec::new();
    let mut chain = vec![canonical_or_as_is(base_path)];
    // Across-walk physical-identity dedup: a drop-in reachable via two Include edges
    // (overlapping globs, glob + explicit, or a diamond) must lint each PHYSICAL
    // conditional `Match` block ONCE, not once per edge (single-file parity; F02's
    // own stream walk dedups the same way). Keyed by (canonical source path, Match
    // header line): canonicalize so symlinks / relative paths to the same file
    // collapse, and use the header line so two DISTINCT blocks in the same file (or
    // identical text in different files / lines) are both kept -- dedup is by
    // physical identity, never by content. The per-ancestry `chain` cycle guard and
    // the depth cap are unchanged; this only suppresses re-collection across edges.
    let mut seen: std::collections::HashSet<(PathBuf, usize)> = std::collections::HashSet::new();
    collect_matches_in(base_path, base_src, &mut chain, &mut seen, &mut matches);
    matches
}

/// Recursive worker for [`collect_conditional_matches`]: append this file's
/// conditional `Match` blocks (in source order, deduped by physical identity via
/// `seen`) and follow its top-level / `Match all` Includes, sharing the same cycle
/// guard and depth cap as [`splice_effective`].
fn collect_matches_in(
    file: &Path,
    src: &str,
    chain: &mut Vec<PathBuf>,
    seen: &mut std::collections::HashSet<(PathBuf, usize)>,
    matches: &mut Vec<MergedMatch>,
) {
    let Ok(blocks) = crate::parser::parse_config_str_located(src, file) else {
        return;
    };
    let base_dir = file.parent().unwrap_or_else(|| Path::new("."));
    for block in blocks {
        match block {
            Block::Global(global) => {
                follow_includes(base_dir, &global, chain, seen, matches);
            }
            Block::Match(match_block) if super::is_unconditional_match_all(&match_block) => {
                // `Match all` is folded into the effective global, not a conditional
                // block; but an Include inside it is still reachable (matches
                // build_stream), so follow those.
                follow_includes(base_dir, &match_block.body, chain, seen, matches);
            }
            Block::Match(match_block) => {
                // A genuine conditional Match block: keep it verbatim, tagged with
                // this file. Skip it if this PHYSICAL block (canonical source +
                // header line) was already collected via another Include edge. Its
                // body Includes (if any) are per-connection and not expanded (parity
                // with single-file, which never resolves Includes).
                let key = (canonical_or_as_is(file), match_block.line);
                if !seen.insert(key) {
                    continue;
                }
                matches.push(MergedMatch {
                    block: match_block,
                    source: file.to_path_buf(),
                });
            }
        }
    }
}

/// Follow every `Include` directive in `directives` (top-level or `Match all`
/// scoped), recursing into each resolved drop-in to gather its conditional `Match`
/// blocks. Shares [`splice_effective`]'s cycle guard and depth cap, and threads the
/// across-walk `seen` dedup set through every level.
fn follow_includes(
    base_dir: &Path,
    directives: &[Directive],
    chain: &mut Vec<PathBuf>,
    seen: &mut std::collections::HashSet<(PathBuf, usize)>,
    matches: &mut Vec<MergedMatch>,
) {
    for directive in directives {
        if !directive.keyword.eq_ignore_ascii_case("include") {
            continue;
        }
        if chain.len() > SERVCONF_MAX_DEPTH {
            continue;
        }
        for pattern in &directive.args {
            for dropin_path in resolve_dropins(base_dir, pattern) {
                let canon = canonical_or_as_is(&dropin_path);
                if chain.contains(&canon) {
                    continue;
                }
                let Ok(nested_src) = std::fs::read_to_string(&dropin_path) else {
                    continue;
                };
                chain.push(canon);
                collect_matches_in(&dropin_path, &nested_src, chain, seen, matches);
                chain.pop();
            }
        }
    }
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

/// Maximum `Include` recursion depth, mirroring OpenSSH `servconf.c`'s
/// `SERVCONF_MAX_DEPTH` (16). OpenSSH `fatal()`s past this; `RuleSteward` is a
/// tolerant linter, so it instead stops recursing (a pathological non-cyclic
/// nest terminates without panicking). The cycle guard normally breaks cycles
/// first; this cap is a backstop for a deeply-nested-but-acyclic include set.
const SERVCONF_MAX_DEPTH: usize = 16;

/// Build the effective directive stream: the main file's global directives in
/// order, with each `Include` replaced inline by the directives of its matching
/// drop-ins (glob resolved relative to the including file, drop-ins read in
/// LEXICAL order, matching sshd's first-value-wins read of `sshd_config.d/*.conf`),
/// RECURSIVELY to arbitrary depth (a drop-in that itself `Include`s another file
/// has that file expanded too; issue #323).
///
/// Each file contributes its GLOBAL block plus any UNCONDITIONAL `Match all`
/// block (in source order). Drop-in precedence is a daemon-level concern: the
/// global block and an always-active `Match all` both apply unconditionally,
/// whereas conditional Match blocks are per-connection and excluded. A file that
/// fails to parse contributes nothing (a parse error is sshd-F01's province, not
/// F02's).
///
/// An `Include` is expanded whether it appears at top level OR inside an
/// unconditional `Match all` block (both are unconditionally active, verified
/// rocky9 `sudo sshd -T -f`): in the `Match all` case the spliced drop-in
/// directives are effective WITHIN that always-active block, so the parent's
/// `is_match_all` is OR-ed onto each spliced directive's own flag. This OR is
/// chained through EVERY include level, so a directive reached via an `Include`
/// chain that began inside a `Match all` inherits `is_match_all = true`. An
/// `Include` inside a CONDITIONAL `Match` is per-connection and never reaches the
/// expansion (`effective_directives_of` excludes conditional Match blocks), so it
/// is not folded.
///
/// Cycle guard (mirrors OpenSSH `servconf.c`, which caps recursion at
/// `SERVCONF_MAX_DEPTH` and `fatal()`s on overflow): the current include CHAIN of
/// canonicalized file paths is tracked; a file already on the chain is NOT
/// re-expanded (a cycle terminates gracefully). A legitimate DIAMOND (the same
/// file reached via two non-cyclic branches) still expands, matching sshd. A
/// depth cap of [`SERVCONF_MAX_DEPTH`] backstops a pathological acyclic nest. As a
/// tolerant linter `RuleSteward` never `fatal()`s; it just stops recursing.
fn build_stream(main_path: &Path, main_src: &str) -> Vec<StreamEntry> {
    let mut stream = Vec::new();
    // Ancestry chain of canonicalized include paths (the main file is the root).
    let mut chain = vec![canonical_or_as_is(main_path)];
    splice_effective(main_path, main_src, false, &mut chain, &mut stream);
    stream
}

/// Splice one file's effective directives into `stream`, expanding every
/// `Include` recursively. `enclosing_is_match_all` is OR-ed onto each directive's
/// own `is_match_all` flag (so a `Match all` enclosing an `Include` chain
/// propagates DOWN through every level). `chain` is the canonicalized ancestry of
/// include paths from the root to (and including) this file; a candidate already
/// on it is skipped (cycle guard), and recursion stops past
/// [`SERVCONF_MAX_DEPTH`].
fn splice_effective(
    file: &Path,
    src: &str,
    enclosing_is_match_all: bool,
    chain: &mut Vec<PathBuf>,
    stream: &mut Vec<StreamEntry>,
) {
    let base_dir = file.parent().unwrap_or_else(|| Path::new("."));

    for (directive, dir_is_match_all) in effective_directives_of(src, file) {
        // The directive is unconditionally active iff its own origin is
        // unconditional AND the enclosing context is (top-level OR `Match all`).
        let is_match_all = enclosing_is_match_all || dir_is_match_all;
        if directive.keyword.eq_ignore_ascii_case("include") {
            // Depth cap backstop: OpenSSH fatal()s past SERVCONF_MAX_DEPTH; we
            // just stop recursing (`chain` already holds the root, so its length
            // is depth + 1).
            if chain.len() > SERVCONF_MAX_DEPTH {
                continue;
            }
            for pattern in &directive.args {
                for dropin_path in resolve_dropins(base_dir, pattern) {
                    let canon = canonical_or_as_is(&dropin_path);
                    // Cycle guard: a file already on the current include chain is
                    // not re-expanded (breaks cycles; a non-cyclic diamond, reached
                    // via a sibling branch not on this chain, still expands).
                    if chain.contains(&canon) {
                        continue;
                    }
                    let Ok(nested_src) = std::fs::read_to_string(&dropin_path) else {
                        continue;
                    };
                    chain.push(canon);
                    splice_effective(&dropin_path, &nested_src, is_match_all, chain, stream);
                    chain.pop();
                }
            }
        } else {
            stream.push(entry_from(directive, file, is_match_all));
        }
    }
}

/// Canonicalize a path for cycle-guard comparison; fall back to the path as-is
/// when canonicalization fails (e.g. the path does not exist) so a missing or
/// odd path is compared structurally rather than panicking.
fn canonical_or_as_is(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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
            Block::Match(match_block) if super::is_unconditional_match_all(&match_block) => {
                directives.extend(match_block.body.into_iter().map(|d| (d, true)));
            }
            // Conditional Match block: per-connection, not part of the
            // unconditional effective config F02 reasons about.
            Block::Match(_) => {}
        }
    }
    directives
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

    /// A fully STIG-complete RHEL9 base (every required directive present +
    /// compliant, no weak crypto / deprecated keywords) so the merged W01/W02
    /// passes stay quiet and a diamond / depth test's only finding is the deep
    /// weak-cipher W03. Mirrors the CLI e2e `CLEAN_CONFIG`.
    const CLEAN_CONFIG: &str = "\
Banner /etc/issue.net
LogLevel VERBOSE
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
HostbasedAuthentication no
PermitUserEnvironment no
RekeyLimit 1G 1h
ClientAliveCountMax 1
ClientAliveInterval 300
Compression no
GSSAPIAuthentication no
KerberosAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
X11Forwarding no
StrictModes yes
PrintLastLog yes
X11UseLocalhost yes
";

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
    fn dropin_vs_dropin_override_message_does_not_claim_main() {
        // When the winning drop-in overrides ANOTHER drop-in (the main file does
        // not set the directive), the message must NOT claim it "wins over the main
        // sshd_config" -- the main sets nothing here. (scenario_c-style layout.)
        let main = "Include {DIR}\n";
        let diags = f02_diags(
            main,
            &[
                ("10-a.conf", "PermitRootLogin yes\n"),
                ("90-b.conf", "PermitRootLogin no\n"),
            ],
        );
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "drop-in vs drop-in override fires exactly once; got {diags:?}"
        );
        assert!(
            !f02[0].message.contains("main sshd_config"),
            "must not claim it overrides the main file when main sets nothing: {}",
            f02[0].message
        );
    }

    #[test]
    fn dropin_vs_main_override_message_names_main() {
        // The canonical F02: the winning drop-in overrides a directive the MAIN
        // file sets, so the message names "the main sshd_config".
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(main, &[("50-x.conf", "PermitRootLogin yes\n")]);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(f02.len(), 1);
        assert!(
            f02[0].message.contains("the main sshd_config"),
            "a drop-in overriding the main file names the main: {}",
            f02[0].message
        );
    }

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
    fn directive_set_in_three_locations_fires_exactly_once() {
        // A W02-controlled directive set in 3+ locations (two drop-ins + the main
        // file) must yield EXACTLY ONE sshd-F02, not one per occurrence. The
        // effective value is the lexically-first drop-in (`10-a.conf` yes); the
        // dedup guard processes each directive once at its first appearance.
        // (Kills the `delete !` mutant on the seen-set dedup guard, which would
        // re-process every occurrence after the first and emit duplicate F02s.)
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let diags = f02_diags(
            main,
            &[
                ("10-a.conf", "PermitRootLogin yes\n"),
                ("20-b.conf", "PermitRootLogin yes\n"),
            ],
        );
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "a directive set in 3 locations fires exactly one sshd-F02 (no \
             per-occurrence duplicates); got {diags:?}"
        );
        assert!(
            f02[0].message.contains("10-a.conf"),
            "anchored to the lexically-first (winning) drop-in: {}",
            f02[0].message
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

    // ----------------------------------------------------------------------
    // NESTED INCLUDE TESTS (issue #323)
    // ----------------------------------------------------------------------
    //
    // Background: build_stream() PREVIOUSLY expanded Include one level deep only
    // (main -> sshd_config.d/*.conf).  A drop-in that itself contained an Include
    // of a SECOND file was NOT followed, so a baseline-failing value set in that
    // second-level file was a silent false negative.
    //
    // This fix makes build_stream() resolve Include recursively with a cycle
    // guard, propagating the enclosing is_match_all tag and stamping each spliced
    // directive with the file it actually came from.
    //
    // Tests #1 and #2 below WERE RED under the old one-level impl and are now
    // GREEN under the recursive impl.  Test #3 is a safety guard (green both
    // before and after the fix).  Test #4 references an existing test that already
    // covers the non-nested baseline.

    /// Build a layout where drop-in A itself contains a verbatim `Include` of a
    /// second file (by absolute path) that is NOT inside the `*.conf` glob pattern.
    /// Returns (tempdir-kept-alive, diagnostics).
    ///
    /// Layout written to disk:
    ///   `<tmpdir>/sshd_config`              -- the main file
    ///   `<tmpdir>/sshd_config.d/10-a.conf`  -- drop-in A (contains Include of second)
    ///   `<tmpdir>/second.conf`              -- the second-level file
    ///
    /// `main_tmpl`     -- main `sshd_config` body; `{DIR}` -> `sshd_config.d/*.conf`
    /// `dropin_a_tmpl` -- drop-in A body; `{SECOND}` -> absolute path of `second.conf`
    /// `second_body` -- body of the second-level file
    fn f02_diags_nested(
        main_tmpl: &str,
        dropin_a_tmpl: &str,
        second_body: &str,
    ) -> (tempfile::TempDir, Vec<rulesteward_core::Diagnostic>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        let second_path = dir.path().join("second.conf");

        // Resolve {DIR} in the main template and {SECOND} in the drop-in template.
        let include_glob = dropin_dir.join("*.conf").display().to_string();
        let main_resolved = main_tmpl.replace("{DIR}", &include_glob);
        let dropin_a_resolved =
            dropin_a_tmpl.replace("{SECOND}", &second_path.display().to_string());

        std::fs::write(dir.path().join("sshd_config"), &main_resolved).expect("write main");
        std::fs::write(dropin_dir.join("10-a.conf"), &dropin_a_resolved).expect("write dropin A");
        std::fs::write(&second_path, second_body).expect("write second.conf");

        let diags = lint_drop_in(dir.path(), &ctx());
        (dir, diags)
    }

    // -- Test #1 (was RED under the old one-level impl; now GREEN) ------------

    #[test]
    fn nested_include_baseline_override_fires_f02() {
        // Was RED under the old one-level impl; now GREEN under the recursive impl.
        //
        // Layout:
        //   sshd_config:       Include sshd_config.d/*.conf
        //                      PermitRootLogin no          <- baseline-passing (operator hardening)
        //   sshd_config.d/10-a.conf:
        //                      Include <second.conf>        <- second-level include
        //   second.conf:       PermitRootLogin yes          <- baseline-FAILING override
        //
        // Grounded on rocky9 / OpenSSH 9.9p1: sshd resolves Include recursively,
        // so second.conf's `PermitRootLogin yes` is effectively spliced at the
        // position of 10-a.conf's Include, BEFORE the main file's `no` -> effective
        // value is `yes` (drop-in chain wins), which FAILS baseline_check.
        //
        // Exact F02 firing condition encoded here:
        //   * directive: PermitRootLogin
        //   * baseline requirement: value must be "no" (prohibitprohibited)
        //   * effective value: "yes" (from second.conf, via 10-a.conf's Include)
        //   * set in 2+ locations: second.conf (via nested include) + main file
        //   * effective source: second.conf (a drop-in-chain file, NOT the main file)
        //
        // Under the OLD one-level impl, 10-a.conf's Include directive was
        // treated as an unknown directive (or skipped) and second.conf was never
        // read, so the only location for PermitRootLogin was the main file (`no`),
        // the 2+ location requirement was not met, and F02 did NOT fire (RED).
        let main = "Include {DIR}\nPermitRootLogin no\n";
        let dropin_a = "Include {SECOND}\n";
        let second = "PermitRootLogin yes\n";

        let (_dir, diags) = f02_diags_nested(main, dropin_a, second);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();

        assert_eq!(
            f02.len(),
            1,
            "nested include: second-level file sets baseline-failing PermitRootLogin yes \
             -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        // The diagnostic must name the SECOND-LEVEL file (the actual source of the
        // override), not drop-in A (which only contains an Include directive) and
        // not the main sshd_config.
        assert!(
            d.file.to_string_lossy().contains("second.conf"),
            "diagnostic file must point at the second-level file (second.conf), \
             not drop-in A or the main file: {}",
            d.file.display()
        );
        assert!(
            d.message.contains("second.conf"),
            "diagnostic message must name the second-level file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "diagnostic message must name the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "diagnostic message must name the winning (baseline-failing) value: {}",
            d.message
        );
    }

    // -- Test #2 (was RED under the old one-level impl; now GREEN) ------------

    #[test]
    fn nested_include_inside_match_all_propagates_tag() {
        // Was RED under the old one-level impl; now GREEN under the recursive impl.
        //
        // Layout:
        //   sshd_config:       PermitRootLogin no          <- baseline-passing global
        //                      Match all
        //                        Include sshd_config.d/*.conf
        //   sshd_config.d/10-a.conf:
        //                      Include <second.conf>        <- second-level include
        //   second.conf:       PermitRootLogin yes          <- baseline-FAILING override
        //
        // The Include inside the main file's `Match all` block propagates
        // is_match_all=true to the spliced drop-in A directives (verified by the
        // existing `include_inside_main_match_all_block_folds_dropin_fires` test).
        // Because the recursive build_stream() follows drop-in A's own Include,
        // the second-level Include is encountered while is_match_all is already
        // true (inherited from the enclosing Match all), so second.conf's
        // directives also carry is_match_all=true.
        //
        // With is_match_all=true on second.conf's `PermitRootLogin yes`, the
        // effective_entry() function picks it over the global `no` (Match-all
        // overrides global regardless of textual position, per the locked doc
        // comment at ~:173).  The effective value is `yes` from second.conf, which
        // is NOT the main file, and FAILS baseline -> F02 MUST fire.
        //
        // Exact F02 firing condition encoded here:
        //   * directive: PermitRootLogin
        //   * baseline requirement: value must be "no"
        //   * effective value: "yes" (from second.conf, is_match_all=true inherited
        //     from the outer `Match all` via drop-in A's Include)
        //   * set in 2+ locations: main global (no) + second.conf (yes)
        //   * effective source: second.conf (a drop-in-chain file, not main)
        //
        // Under the OLD one-level impl, 10-a.conf's Include was not followed,
        // second.conf was never read, only the main file's global `no` existed, the
        // 2+ location requirement was unmet, and F02 did NOT fire (RED).
        let main = "PermitRootLogin no\nMatch all\nInclude {DIR}\n";
        let dropin_a = "Include {SECOND}\n";
        let second = "PermitRootLogin yes\n";

        let (_dir, diags) = f02_diags_nested(main, dropin_a, second);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();

        assert_eq!(
            f02.len(),
            1,
            "nested include inside Match all: second-level file sets baseline-failing \
             PermitRootLogin yes with inherited is_match_all=true -> exactly one \
             sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        assert!(
            d.file.to_string_lossy().contains("second.conf"),
            "diagnostic file must point at the second-level file (second.conf): {}",
            d.file.display()
        );
        assert!(
            d.message.contains("second.conf"),
            "diagnostic message must name the second-level file: {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "diagnostic message must name the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "diagnostic message must name the winning value: {}",
            d.message
        );
    }

    // -- Test #3 (safety guard -- GREEN before AND after the fix) ------------

    #[test]
    fn include_cycle_terminates() {
        // SAFETY GUARD: tests that the recursive Include resolver does NOT loop
        // infinitely when there is a 2-cycle in the Include graph.
        //
        // Layout:
        //   sshd_config:       Include sshd_config.d/*.conf
        //                      PermitRootLogin no
        //   sshd_config.d/10-a.conf:
        //                      Include <second.conf>    <- points at second.conf
        //   second.conf:       Include <10-a.conf>     <- points back at 10-a.conf
        //                      PermitRootLogin yes
        //
        // Under the OLD one-level impl this trivially terminated (10-a.conf's
        // Include was not followed at all).  The recursive impl requires a cycle
        // guard to terminate.  The test asserts:
        //   (a) lint_drop_in returns (does not hang / panic / stack-overflow), and
        //   (b) the directive is not double-counted (at most one F02).
        //
        // Termination relies on the implementation's cycle guard / depth cap (the
        // recursive impl ships one); a guarded impl returns immediately.
        // NOTE: the CI gate runs `cargo test` (libtest), which has NO per-test
        // timeout -- so an unguarded recursive impl would not "time out" but would
        // spin and WEDGE this test until the runner is killed.  That wedge IS the
        // intended regression signal if the cycle guard / depth cap ever regresses.
        let dir = tempfile::tempdir().expect("tempdir");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        let dropin_a_path = dropin_dir.join("10-a.conf");
        let second_path = dir.path().join("second.conf");

        // Write main: Include the *.conf glob then set baseline-passing value.
        let include_glob = dropin_dir.join("*.conf").display().to_string();
        std::fs::write(
            dir.path().join("sshd_config"),
            format!("Include {include_glob}\nPermitRootLogin no\n"),
        )
        .expect("write main");

        // Drop-in A Includes second.conf (absolute path).
        std::fs::write(
            &dropin_a_path,
            format!("Include {}\n", second_path.display()),
        )
        .expect("write 10-a.conf");

        // second.conf Includes drop-in A back (the cycle), then sets a value.
        std::fs::write(
            &second_path,
            format!("Include {}\nPermitRootLogin yes\n", dropin_a_path.display()),
        )
        .expect("write second.conf");

        // This call must RETURN (no infinite loop, no panic).
        let diags = lint_drop_in(dir.path(), &ctx());

        // Under the recursive impl, at most one F02 is expected (the cycle must
        // not cause double-counting); under the old one-level impl it was zero
        // (second.conf was never read).  Either way, assert no panics and no more
        // than one F02.
        let f02_count = diags.iter().filter(|d| d.code == "sshd-F02").count();
        assert!(
            f02_count <= 1,
            "include cycle must not produce duplicate F02 diagnostics (dedup / cycle \
             guard); got {f02_count} sshd-F02 in {diags:?}"
        );
        // (No assertion that f02_count == 1 here: it may be 0 or 1 depending on
        // cycle-guard semantics.  The load-bearing invariant is termination + no
        // duplication.  A separate post-GREEN test pins the exact-1 case.)
    }

    // -- Depth-cap boundary (post-GREEN strengthening; kills off-by-one mutants) --
    //
    // The recursive Include resolver caps depth at `SERVCONF_MAX_DEPTH` via
    // `if chain.len() > SERVCONF_MAX_DEPTH { continue; }` (drop_in.rs ~:298),
    // mirroring OpenSSH `servconf.c`.  `chain` holds the canonicalized ancestry
    // including the root main file, so `chain.len()` is (include-hop depth + 1).
    //
    // The boundary: the Include in a file reached at `chain.len() == L` is
    // FOLLOWED iff `L > SERVCONF_MAX_DEPTH` is false (L <= cap).  The deepest
    // Include actually followed is the one at `chain.len() == SERVCONF_MAX_DEPTH`;
    // it splices a file entered at `chain.len() == SERVCONF_MAX_DEPTH + 1`.  So a
    // chain of exactly `SERVCONF_MAX_DEPTH` Include hops from the main file
    // reaches its deepest file (and any override there); one more hop does not.
    //
    // Mutants on `>`:
    //   * `>= SERVCONF_MAX_DEPTH` caps at `chain.len() == cap` (one level early);
    //   * `== SERVCONF_MAX_DEPTH` likewise stops following the include at
    //     `chain.len() == cap`.
    // Either mutant never reaches the deepest-allowed file, so the override there
    // is never spliced and NO F02 fires -> the deepest-allowed-fires test below
    // fails for the mutant but passes for the correct impl.  That is the kill.

    /// Build a straight nested-`Include` chain of `hops` files under a fresh
    /// tempdir and run the F02 lint over it.  Layout:
    ///
    ///   `sshd_config`         -- main: `Include <inc-1.conf>` then `PermitRootLogin no`
    ///   `inc-1.conf`          -- `Include <inc-2.conf>`
    ///   ...
    ///   `inc-{hops-1}.conf`   -- `Include <inc-{hops}.conf>`
    ///   `inc-{hops}.conf`     -- `PermitRootLogin yes`   (the baseline-FAILING override)
    ///
    /// so the override sits exactly `hops` Include hops below the main file.  Each
    /// `Include` uses an ABSOLUTE path (not a glob), so there is exactly one edge
    /// per level and the chain depth is deterministic.  Returns
    /// (tempdir-kept-alive, diagnostics).
    fn f02_diags_chain(hops: usize) -> (tempfile::TempDir, Vec<rulesteward_core::Diagnostic>) {
        assert!(hops >= 1, "a chain needs at least one hop");
        let dir = tempfile::tempdir().expect("tempdir");
        // Pre-compute every file path so each file can reference the next.
        let inc_path = |i: usize| dir.path().join(format!("inc-{i}.conf"));

        // Main: Include the first chain file, then set the hardened baseline value.
        std::fs::write(
            dir.path().join("sshd_config"),
            format!("Include {}\nPermitRootLogin no\n", inc_path(1).display()),
        )
        .expect("write main");

        // Intermediate files 1..hops-1 each Include the next; the last sets the
        // baseline-failing override.
        for i in 1..hops {
            std::fs::write(
                inc_path(i),
                format!("Include {}\n", inc_path(i + 1).display()),
            )
            .unwrap_or_else(|e| panic!("write inc-{i}.conf: {e}"));
        }
        std::fs::write(inc_path(hops), "PermitRootLogin yes\n")
            .unwrap_or_else(|e| panic!("write inc-{hops}.conf: {e}"));

        let diags = lint_drop_in(dir.path(), &ctx());
        (dir, diags)
    }

    #[test]
    fn nested_include_at_max_depth_fires_f02() {
        // GREEN against the correct impl; KILLS the `> -> >=` and `> -> ==`
        // depth-cap mutants at drop_in.rs:298.
        //
        // A chain of EXACTLY `SERVCONF_MAX_DEPTH` Include hops places the
        // baseline-failing `PermitRootLogin yes` at the deepest level the resolver
        // is still allowed to follow (the include at `chain.len() == cap` is
        // followed because `cap > cap` is false).  The correct impl reaches that
        // override -> effective value `yes` from the deepest file (a non-main
        // source), fails baseline -> exactly one F02 anchored to the deepest file.
        //
        // A `>=`/`==` mutant stops one hop short, never reads the deepest file,
        // finds only the main file's `no` (single location) and emits NO F02 ->
        // this assertion fails for the mutant.  Computed from the depth CONSTANT,
        // not a hardcoded 16, so it tracks the cap if it changes.
        let hops = super::SERVCONF_MAX_DEPTH;
        let (_dir, diags) = f02_diags_chain(hops);
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sshd-F02").collect();

        assert_eq!(
            f02.len(),
            1,
            "an override at exactly SERVCONF_MAX_DEPTH ({hops}) Include hops is \
             reached -> exactly one sshd-F02; got {diags:?}"
        );
        let d = f02[0];
        assert_eq!(d.severity, Severity::Fatal, "sshd-F02 is a Fatal");
        let deepest = format!("inc-{hops}.conf");
        assert!(
            d.file.to_string_lossy().contains(&deepest),
            "diagnostic must anchor to the deepest file ({deepest}): {}",
            d.file.display()
        );
        assert!(
            d.message.contains(&deepest),
            "message must name the deepest file ({deepest}): {}",
            d.message
        );
        assert!(
            d.message.to_ascii_lowercase().contains("permitrootlogin"),
            "message must name the directive: {}",
            d.message
        );
        assert!(
            d.message.contains("yes"),
            "message must name the winning value: {}",
            d.message
        );
    }

    #[test]
    fn nested_include_one_past_max_depth_does_not_fire() {
        // Pins the UPPER edge of the cap: an override placed one Include hop BEYOND
        // `SERVCONF_MAX_DEPTH` is NOT reached (the include at `chain.len() == cap+1`
        // is skipped because `cap + 1 > cap`), so its deepest file is never spliced,
        // the override never enters the stream, and F02 does NOT fire.  Guards
        // against a future `> -> >=`-in-the-other-direction drift that would over-
        // expand by one level.
        let hops = super::SERVCONF_MAX_DEPTH + 1;
        let (_dir, diags) = f02_diags_chain(hops);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-F02"),
            "an override one hop past SERVCONF_MAX_DEPTH ({hops}) is beyond the cap \
             and must NOT be reached -> F02 must not fire; got {diags:?}"
        );
    }

    // -- Test #4 (regression guard -- already covered by existing test) -------
    //
    // The non-nested one-level layout regression is already covered by
    // `scenario_a_dropin_wins_over_later_main_setting_fires` (above).  No new
    // test needed here; the existing test acts as the regression guard that a
    // correct recursive implementation must not break.

    // ----------------------------------------------------------------------
    // MERGED-EFFECTIVE SINGLE-FILE SUITE (issue #324)
    // ----------------------------------------------------------------------
    //
    // `lint_merged` runs the single-file dispatcher over the synthetic merged
    // view and remaps each directive-anchored finding to its real source file +
    // line. These tests pin the build_merged / remap invariants directly (the CLI
    // e2e tests in rulesteward-cli/tests/e2e_sshd_lint.rs pin the end-to-end
    // behavior; these pin the crate-internal contract).

    use super::lint_merged;

    /// Build an `/etc/ssh`-layout directory and run the MERGED single-file suite.
    /// Mirrors `f02_diags` but calls `lint_merged` instead of `lint_drop_in`.
    fn merged_diags(main: &str, dropins: &[(&str, &str)]) -> Vec<Diagnostic> {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        let include_glob = dropin_dir.join("*.conf").display().to_string();
        let main_resolved = main.replace("{DIR}", &include_glob);
        std::fs::write(dir.path().join("sshd_config"), &main_resolved).expect("write main");
        for (name, body) in dropins {
            std::fs::write(dropin_dir.join(name), body).expect("write drop-in");
        }
        lint_merged(dir.path(), &ctx())
    }

    #[test]
    fn merged_w03_weak_dropin_cipher_anchors_to_dropin() {
        // The base is fine; a drop-in sets a weak CBC cipher. The merged W03 pass
        // must fire and the finding must anchor to the DROP-IN file + its own line
        // 1, NOT the base sshd_config -- the remap provenance must survive.
        let diags = merged_diags(
            "Include {DIR}\n",
            &[("50-weak.conf", "Ciphers aes256-cbc\n")],
        );
        let w03: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W03").collect();
        assert_eq!(
            w03.len(),
            1,
            "merged W03 fires once for the weak cipher; got {diags:?}"
        );
        let d = w03[0];
        assert!(
            d.file.to_string_lossy().ends_with("50-weak.conf"),
            "W03 anchors to the drop-in holding the weak cipher: {}",
            d.file.display()
        );
        assert!(
            !d.file.to_string_lossy().ends_with("/sshd_config"),
            "W03 does not anchor to the base sshd_config: {}",
            d.file.display()
        );
        assert_eq!(
            d.line, 1,
            "W03 line is the directive's line within the drop-in (1)"
        );
        assert_eq!(
            d.source_id.as_deref(),
            Some(d.file.display().to_string().as_str()),
            "source_id is remapped to the same winning drop-in as file"
        );
    }

    #[test]
    fn merged_suite_does_not_fire_e02_e03_on_synthetic_view() {
        // The synthetic merged view is deduped to one directive per keyword and
        // has every Include resolved away, so the duplicate (E02) and Include (E03)
        // structural passes must NEVER fire over it -- even when the on-disk layout
        // has a duplicate keyword across files AND an Include directive. A drop-in
        // duplicates PermitRootLogin (present in the base too) to exercise the dedup.
        let diags = merged_diags(
            "PermitRootLogin no\nInclude {DIR}\n",
            &[("50-x.conf", "PermitRootLogin no\n")],
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-E02"),
            "merged synthetic view is deduped -> sshd-E02 must not fire; got {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code == "sshd-E03"),
            "Include is resolved away in the merged view -> sshd-E03 must not fire; got {diags:?}"
        );
    }

    #[test]
    fn merged_follows_match_all_include_to_collect_nested_conditional_match() {
        // An `Include` INSIDE an unconditional `Match all` is unconditionally active,
        // so `collect_conditional_matches` must FOLLOW it and gather the genuine
        // CONDITIONAL `Match` block in the included drop-in. That conditional Match
        // sets a global-only directive (`Ciphers`), which the merged single-file
        // suite flags as sshd-E04. If `Match all` were instead collected AS a
        // conditional block (so its Includes were never followed), this nested E04
        // would be silently dropped.
        //
        // In-crate (not only the CLI e2e) so the per-package mutation run -- which
        // does not execute the rulesteward-cli e2e tests -- still kills the
        // `collect_matches_in` `Match all`-guard mutant. (issue #336)
        let diags = merged_diags(
            "PermitRootLogin no\nMatch all\nInclude {DIR}\n",
            &[("50-x.conf", "Match User bob\n    Ciphers aes256-ctr\n")],
        );
        assert!(
            diags.iter().any(|d| d.code == "sshd-E04"),
            "a conditional Match reached via a `Match all` Include must be linted \
             (E04 on the global-only Ciphers); got {diags:?}"
        );
    }

    #[test]
    fn merged_w01_absent_directive_anchors_to_base_at_line_zero() {
        // A STIG-required directive absent from the merged view fires W01 at
        // line 0 (file-level), anchored to the BASE sshd_config (no remap). The
        // base here sets only PermitRootLogin (so Banner et al. are missing).
        let diags = merged_diags("PermitRootLogin no\nInclude {DIR}\n", &[]);
        let w01: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W01").collect();
        assert!(
            !w01.is_empty(),
            "absent required directives fire W01; got {diags:?}"
        );
        for d in &w01 {
            assert_eq!(
                d.line, 0,
                "W01 absent-directive findings are file-level (line 0)"
            );
            assert!(
                d.file.to_string_lossy().ends_with("/sshd_config"),
                "W01 anchors to the base sshd_config, not a drop-in: {}",
                d.file.display()
            );
        }
    }

    #[test]
    fn merged_w02_remaps_to_effective_dropin_not_base() {
        // The base sets the strong value; a FIRST-included drop-in weakens it. The
        // effective value is the drop-in's, so merged W02 must fire anchored to the
        // drop-in (line 1), proving the remap targets the EFFECTIVE source, not the
        // base where the directive also appears.
        let diags = merged_diags(
            "Include {DIR}\nPermitRootLogin no\n",
            &[("10-weaken.conf", "PermitRootLogin yes\n")],
        );
        let w02: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.code == "sshd-W02" && d.message.to_ascii_lowercase().contains("permitrootlogin")
            })
            .collect();
        assert_eq!(
            w02.len(),
            1,
            "merged W02 fires once for the weakened value; got {diags:?}"
        );
        let d = w02[0];
        assert!(
            d.file.to_string_lossy().ends_with("10-weaken.conf"),
            "W02 anchors to the effective (winning) drop-in, not the base: {}",
            d.file.display()
        );
        assert_eq!(
            d.line, 1,
            "W02 line is the directive's line within the drop-in (1)"
        );
    }

    #[test]
    fn merged_w03_fires_inside_conditional_match_block_anchored_to_real_line() {
        // The as-written W03 pass must reach a weak cipher inside a CONDITIONAL
        // Match block in the base, anchored to the real Match-body line. The base
        // is `PermitRootLogin no` (line 1), `Match Address ...` (line 2), then
        // `    Ciphers aes256-cbc` (line 3) -- so W03 anchors to line 3 of the base.
        let diags = merged_diags(
            "PermitRootLogin no\nMatch Address 192.168.1.0/24\n    Ciphers aes256-cbc\n",
            &[],
        );
        let w03: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W03").collect();
        assert_eq!(
            w03.len(),
            1,
            "merged W03 reaches the conditional-Match weak cipher; got {diags:?}"
        );
        let d = w03[0];
        assert!(
            d.file.to_string_lossy().ends_with("/sshd_config"),
            "the weak cipher lives in the base sshd_config: {}",
            d.file.display()
        );
        assert_eq!(d.line, 3, "W03 anchors to the real Match-body line (3)");
    }

    #[test]
    fn merged_conditional_match_value_does_not_fold_into_global_w02() {
        // The conditional-Match content feeds the as-written passes but must NOT
        // reach the effective-value W02 pass (it reads blocks[0] only). A
        // `PermitRootLogin yes` set ONLY inside a conditional Match block is
        // per-connection, so W02 must stay silent for it at the global baseline.
        let diags = merged_diags(
            "PermitRootLogin no\nMatch User someuser\n    PermitRootLogin yes\n",
            &[],
        );
        let w02_prl: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.code == "sshd-W02" && d.message.to_ascii_lowercase().contains("permitrootlogin")
            })
            .collect();
        assert!(
            w02_prl.is_empty(),
            "a conditional-Match PermitRootLogin value must not fold into the global \
             W02 view; got {diags:?}"
        );
    }

    #[test]
    fn merged_conditional_match_in_dropin_anchors_to_dropin() {
        // Provenance through the Match path: a conditional Match block with a weak
        // cipher lives in a DROP-IN, Included from the base. The W03 finding must
        // anchor to the drop-in (line 2: Match header is line 1, Ciphers is line 2),
        // not the base.
        let diags = merged_diags(
            "PermitRootLogin no\nInclude {DIR}\n",
            &[(
                "50-match.conf",
                "Match Address 192.168.1.0/24\n    Ciphers aes256-cbc\n",
            )],
        );
        let w03: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W03").collect();
        assert_eq!(
            w03.len(),
            1,
            "merged W03 reaches a drop-in Match body; got {diags:?}"
        );
        let d = w03[0];
        assert!(
            d.file.to_string_lossy().ends_with("50-match.conf"),
            "W03 anchors to the drop-in holding the Match block, not the base: {}",
            d.file.display()
        );
        assert_eq!(
            d.line, 2,
            "W03 anchors to the real Ciphers line in the drop-in (2)"
        );
        assert_eq!(
            d.source_id.as_deref(),
            Some(d.file.display().to_string().as_str()),
            "source_id is remapped to the same winning drop-in as file"
        );
    }

    #[test]
    fn merged_match_all_not_re_emitted_as_conditional_block() {
        // An unconditional `Match all` is folded into the effective global, NOT
        // re-emitted as a conditional Match block. So a `Match all` setting a strong
        // effective value must not produce an E04/W05 Match finding, and there is no
        // synthetic Block::Match for it. We assert no E04/W05 here (Ciphers in a
        // `Match all` is the effective global value, evaluated by the global passes).
        let diags = merged_diags("Match all\n    Ciphers aes256-ctr\n", &[]);
        assert!(
            !diags
                .iter()
                .any(|d| d.code == "sshd-E04" || d.code == "sshd-W05"),
            "Match all is folded into the global, not a conditional Match block, so \
             no E04/W05 Match finding; got {diags:?}"
        );
    }

    // ------------------------------------------------------------------
    // #324 round-2: diamond / double-Include dedup + depth-cap boundary
    // on the conditional-Match collection path (`collect_conditional_matches`
    // / `follow_includes`). Crate-level mirrors of the CLI e2e tests.
    // ------------------------------------------------------------------

    #[test]
    fn merged_diamond_include_conditional_match_reported_once() {
        // FINDING 1 (RED today, count == 2): one drop-in `50-m.conf` reachable via
        // TWO overlapping Include globs (`*.conf` and `5*.conf`, both matching it)
        // holds a conditional `Match User alice` block with a weak cipher. The
        // merged single-file W03 pass must report that one physical Match-body
        // finding EXACTLY ONCE. `collect_conditional_matches` has a per-ANCESTRY
        // cycle guard but no across-walk file dedup, so it visits `50-m.conf` once
        // per Include edge and collects the conditional Match block TWICE -> two
        // identical W03s. This asserts count == 1, so it is RED until the dedup lands.
        let dir = tempfile::tempdir().expect("tempdir");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        // Two overlapping globs in ONE Include line, both matching `50-m.conf`.
        // The base is STIG-complete so the only findings are the deep Match-body
        // W03 (and the co-firing E04); each must appear exactly once, not per edge.
        let glob_all = dropin_dir.join("*.conf").display().to_string();
        let glob_five = dropin_dir.join("5*.conf").display().to_string();
        std::fs::write(
            dir.path().join("sshd_config"),
            format!("{CLEAN_CONFIG}Include {glob_all} {glob_five}\n"),
        )
        .expect("write main");
        std::fs::write(
            dropin_dir.join("50-m.conf"),
            "Match User alice\n    Ciphers aes256-cbc\n",
        )
        .expect("write drop-in");

        let diags = lint_merged(dir.path(), &ctx());
        let w03: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W03").collect();
        assert_eq!(
            w03.len(),
            1,
            "a drop-in reached via two overlapping Include globs holds ONE \
             conditional Match weak-cipher finding; merged W03 must report it \
             EXACTLY ONCE (no per-edge duplication); got {diags:?}"
        );
        let d = w03[0];
        assert!(
            d.file.to_string_lossy().ends_with("50-m.conf"),
            "W03 anchors to the drop-in holding the conditional Match block: {}",
            d.file.display()
        );
        assert_eq!(
            d.line, 2,
            "W03 anchors to the real `Ciphers` line in the Match body (2)"
        );
    }

    /// Build a straight nested-`Include` chain of `hops` files whose DEEPEST file
    /// holds a conditional `Match User alice` block with a weak cipher, so the
    /// chain is followed on the conditional-Match collection path (exercising
    /// `follow_includes`). The base is STIG-complete so the only finding is the
    /// deep W03. Returns (tempdir-kept-alive, merged diagnostics).
    fn merged_conditional_match_chain(hops: usize) -> (tempfile::TempDir, Vec<Diagnostic>) {
        assert!(hops >= 1, "a chain needs at least one hop");
        let dir = tempfile::tempdir().expect("tempdir");
        let inc_path = |i: usize| dir.path().join(format!("inc-{i}.conf"));
        std::fs::write(
            dir.path().join("sshd_config"),
            format!("{CLEAN_CONFIG}Include {}\n", inc_path(1).display()),
        )
        .expect("write main");
        for i in 1..hops {
            std::fs::write(
                inc_path(i),
                format!("Include {}\n", inc_path(i + 1).display()),
            )
            .unwrap_or_else(|e| panic!("write inc-{i}.conf: {e}"));
        }
        std::fs::write(inc_path(hops), "Match User alice\n    Ciphers aes256-cbc\n")
            .unwrap_or_else(|e| panic!("write inc-{hops}.conf: {e}"));
        let diags = lint_merged(dir.path(), &ctx());
        (dir, diags)
    }

    #[test]
    fn merged_conditional_match_at_max_depth_fires_w03() {
        // FINDING 2, lower edge (kills `> -> >=` and `> -> ==` at follow_includes).
        // A chain of EXACTLY SERVCONF_MAX_DEPTH hops places the conditional Match
        // weak cipher at the deepest level the resolver still follows (`cap > cap`
        // is false). The correct `>` impl reaches it -> one W03 anchored to the
        // deepest file. A `>=`/`==` mutant stops one hop short -> NO W03 -> fails.
        let hops = super::SERVCONF_MAX_DEPTH;
        let (_dir, diags) = merged_conditional_match_chain(hops);
        let w03: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W03").collect();
        assert_eq!(
            w03.len(),
            1,
            "a conditional-Match weak cipher at exactly SERVCONF_MAX_DEPTH ({hops}) \
             Include hops is reached on the conditional-Match path -> one sshd-W03; \
             got {diags:?}"
        );
        let deepest = format!("inc-{hops}.conf");
        assert!(
            w03[0].file.to_string_lossy().ends_with(&deepest),
            "W03 anchors to the deepest file ({deepest}): {}",
            w03[0].file.display()
        );
    }

    #[test]
    fn merged_conditional_match_one_past_max_depth_does_not_fire_w03() {
        // FINDING 2, upper edge: a conditional Match finding one Include hop BEYOND
        // SERVCONF_MAX_DEPTH is NOT reached (`cap + 1 > cap` skips the include), so
        // no W03 fires. Together with the at-max-depth test this straddles the exact
        // boundary, so a `>=` mutant (which also cuts at the cap) cannot survive.
        let hops = super::SERVCONF_MAX_DEPTH + 1;
        let (_dir, diags) = merged_conditional_match_chain(hops);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-W03"),
            "a conditional-Match weak cipher one hop past SERVCONF_MAX_DEPTH ({hops}) \
             is beyond the cap and must NOT be reached -> no sshd-W03; got {diags:?}"
        );
    }
}
