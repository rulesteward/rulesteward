//! Include / directory resolution seam (#334).
//!
//! Freezes the entrypoint the CLI calls so the body can fill in without touching
//! the CLI. [`resolve_target`] turns a path into the FULL ordered list of
//! [`SudoersFile`]s to lint, FOLLOWING `@include` / `@includedir` directives so
//! the lint slice covers the whole resolved tree in sudo's evaluation order:
//! * a single FILE -> the file, with each `@include`/`@includedir` directive it
//!   contains resolved (recursively) and inserted AT THE DIRECTIVE'S POSITION;
//! * a DIRECTORY -> each eligible drop-in, in sorted lexical order, each itself
//!   resolved for its own include directives.
//!
//! # Grounding (`sudoers(5)`, sudo 1.9.17p2; verified against `visudo -c -f`)
//! * `@include PATH` / `#include PATH`: the included file's content is inserted at
//!   the directive's position in evaluation order. A non-absolute path is resolved
//!   RELATIVE TO THE DIRECTORY of the file that contained the directive (not the
//!   cwd).
//! * `@includedir DIR` / `#includedir DIR`: read DIR, SKIP names ending in `~` or
//!   CONTAINING a `.`, parse the rest in sorted LEXICAL order (FILES only - a
//!   nested subdirectory is not visited), each recursively resolved.
//! * `%h` escape: expands to the short host name; a `/` in the host name becomes
//!   `_` (man page). The real host name is injected by [`resolve_target`];
//!   [`resolve_target_with_host`] takes it explicitly for testability.
//! * 128 nested-include hard limit ([`MAX_INCLUDE_DEPTH`]): visudo enforces a cap
//!   "to prevent include file loops". A self/mutual include cycle MUST terminate;
//!   past the cap this stops descending and surfaces a Malformed line (sudo-F01),
//!   mirroring visudo's "too many levels of includes" error rather than hanging.
//! * Missing `@include` target: visudo ERRORS (`No such file or directory`); we
//!   surface it as a Malformed line (sudo-F01 Fatal), NOT a silent skip.
//! * Missing/unreadable `@includedir`: visudo ACCEPTS it (parsed OK); we skip it
//!   silently.

use std::io;
use std::path::{Path, PathBuf};

use rulesteward_core::Span;

use crate::ast::{IncludeKind, LineKind, LogicalLine, SudoersFile};
use crate::parser::parse;

/// Maximum `@include` nesting depth (`sudoers(5)`: "a limit of 128 nested include
/// files is enforced to prevent include file loops"). The cycle guard normally
/// breaks an actual cycle first; this cap is the backstop visudo uses, and the
/// point past which a too-deep chain stops descending with a Malformed line.
pub const MAX_INCLUDE_DEPTH: usize = 128;

/// Resolve a lint target path into the FULL ordered [`SudoersFile`]s to lint,
/// following `@include` / `@includedir` directives recursively.
///
/// A FILE is parsed, then each `@include`/`@includedir` directive it contains is
/// resolved (recursively) and inserted at the directive's position in evaluation
/// order. A DIRECTORY is enumerated: each `sudoers.d`-eligible entry (does not end
/// in `~`, does not contain a `.`) is resolved in sorted lexical order, and any
/// include directives inside those drop-ins are followed too.
///
/// The short host name (for the `%h` include-path escape) is read from the system
/// and threaded through resolution; [`resolve_target_with_host`] takes it
/// explicitly for testing.
///
/// # Errors
/// Returns the underlying [`io::Error`] if the TOP-LEVEL path cannot be read (an
/// unreadable file, or a directory that cannot be enumerated). A missing nested
/// `@include` target is NOT an `io::Error`: it is surfaced as a Malformed line
/// (sudo-F01), mirroring `visudo -c`. An unreadable drop-in inside a directory or
/// a missing `@includedir` is skipped best-effort (the rest still lints).
pub fn resolve_target(path: &Path) -> io::Result<Vec<SudoersFile>> {
    resolve_target_with_host(path, &short_hostname())
}

/// [`resolve_target`] with the short host name injected, so the `%h` include-path
/// escape can be exercised deterministically in tests. The public
/// [`resolve_target`] calls this with the real host name.
///
/// # Errors
/// Same as [`resolve_target`].
pub fn resolve_target_with_host(path: &Path, host: &str) -> io::Result<Vec<SudoersFile>> {
    let mut out = Vec::new();
    if path.is_dir() {
        // A directory target: each eligible drop-in is a resolution ROOT (its own
        // include directives are followed). The chain starts fresh per drop-in.
        for dropin in eligible_dropins(path)? {
            let mut chain: Vec<PathBuf> = Vec::new();
            resolve_file(&dropin, host, &mut chain, &mut out);
        }
    } else {
        // A single file: read it up front so a missing/unreadable TOP-LEVEL target
        // is an io::Error (a tool failure the CLI maps), distinct from a missing
        // nested @include (which becomes a Malformed line).
        let source = std::fs::read_to_string(path)?;
        let mut chain: Vec<PathBuf> = vec![canonical_or_as_is(path)];
        resolve_parsed(&parse(&source, path), path, host, &mut chain, &mut out);
    }
    Ok(out)
}

/// Read `file`, parse it, and resolve its include directives into `out`, with the
/// cycle guard `chain` already holding `file`'s ancestry. A read failure here is a
/// MISSING/unreadable nested include: it is surfaced by the caller as a Malformed
/// line, never an `io::Error` (only the top-level target read can be an error).
///
/// There is intentionally NO across-resolution physical-identity dedup: sudo
/// applies an included file's rules ONCE PER `@include` EDGE (grounded on
/// `cvtsudoers -f sudoers`: a doubly-included file and a non-cyclic diamond both
/// emit the file's rules twice), which last-match-wins ordering depends on. Cycles
/// are broken solely by the per-ancestry `chain` guard, which (being pushed/popped)
/// blocks a true loop while still letting a non-cyclic diamond expand each branch.
fn resolve_file(file: &Path, host: &str, chain: &mut Vec<PathBuf>, out: &mut Vec<SudoersFile>) {
    let Ok(source) = std::fs::read_to_string(file) else {
        // An unreadable drop-in is skipped best-effort (matches the prior Phase-0
        // directory behavior; a top-level read error is handled by the caller).
        return;
    };
    chain.push(canonical_or_as_is(file));
    resolve_parsed(&parse(&source, file), file, host, chain, out);
    chain.pop();
}

/// Walk `parsed`'s logical lines in source order, emitting each contiguous run of
/// the file's OWN (non-include) lines as a [`SudoersFile`] segment and, AT each
/// `@include`/`@includedir` directive's position, splicing the directive's resolved
/// files in between. This makes the resolved `Vec` reflect sudo's true evaluation
/// order: a parent rule written AFTER an `@include` comes AFTER the included file's
/// rules (grounded on `cvtsudoers -f sudoers`). `chain` is the canonicalized
/// ancestry from the root to (and including) `parsed`'s file; a candidate already
/// on it is a cycle and is surfaced as a Malformed line rather than re-expanded.
fn resolve_parsed(
    parsed: &SudoersFile,
    file: &Path,
    host: &str,
    chain: &mut Vec<PathBuf>,
    out: &mut Vec<SudoersFile>,
) {
    let base_dir = file.parent().unwrap_or_else(|| Path::new("."));
    // Accumulate this file's own (non-include) lines into a pending segment; flush
    // it as a SudoersFile each time an include directive splits the file, so the
    // file's pre-include and post-include lines land on the correct side of the
    // included content. Each segment keeps `parsed`'s path + full source so the
    // CLI's source-id staging and ariadne rendering still resolve (the segments
    // share one source keyed by path; that is idempotent in the CLI's BTreeMap).
    let mut pending: Vec<LogicalLine> = Vec::new();
    let flush = |pending: &mut Vec<LogicalLine>, out: &mut Vec<SudoersFile>| {
        // Only emit a segment that carries a semantically meaningful line. A run of
        // purely [`LineKind::Blank`] lines (e.g. the trailing empty segment a final
        // `\n` produces, or blank lines between two adjacent `@include`s) has no
        // findings and no ordering significance, so it is dropped rather than
        // emitted as an empty file segment.
        if pending.iter().any(|l| !matches!(l.kind, LineKind::Blank)) {
            out.push(SudoersFile {
                path: parsed.path.clone(),
                source: parsed.source.clone(),
                lines: std::mem::take(pending),
            });
        } else {
            pending.clear();
        }
    };

    for line in &parsed.lines {
        let LineKind::Include(inc) = &line.kind else {
            pending.push(line.clone());
            continue;
        };
        // An include directive splits the file: flush the lines before it, then
        // splice the resolved include at this position.
        flush(&mut pending, out);
        let resolved_path = resolve_include_path(base_dir, &inc.path, host);
        match inc.kind {
            IncludeKind::Include => {
                // A missing @include target ERRORS in visudo; surface it (a
                // Malformed sudo-F01) rather than silently skipping.
                if !resolved_path.is_file() {
                    out.push(missing_include_file(&resolved_path, line, file));
                    continue;
                }
                // Cycle / depth guard: a file already on the ancestry chain (a
                // cycle) or a chain past the nested limit terminates with a
                // Malformed line, mirroring visudo's "too many levels of includes".
                if chain.contains(&canonical_or_as_is(&resolved_path))
                    || chain.len() > MAX_INCLUDE_DEPTH
                {
                    out.push(too_many_levels(&resolved_path, line, file));
                    continue;
                }
                resolve_file(&resolved_path, host, chain, out);
            }
            IncludeKind::IncludeDir => {
                // A missing/unreadable @includedir is ACCEPTED by visudo: skip it
                // silently. Each eligible drop-in is resolved (sorted, `.`/`~`
                // skipped), and its own includes are followed.
                let Ok(dropins) = eligible_dropins(&resolved_path) else {
                    continue;
                };
                for dropin in dropins {
                    if chain.contains(&canonical_or_as_is(&dropin))
                        || chain.len() > MAX_INCLUDE_DEPTH
                    {
                        out.push(too_many_levels(&dropin, line, file));
                        continue;
                    }
                    resolve_file(&dropin, host, chain, out);
                }
            }
        }
    }
    // Flush any trailing lines after the last include (or the whole file if it had
    // no includes).
    flush(&mut pending, out);
}

/// Resolve an include path: expand the `%h` host escape, then anchor a non-absolute
/// path to `base_dir` (the including file's directory), per `sudoers(5)`.
fn resolve_include_path(base_dir: &Path, raw: &str, host: &str) -> PathBuf {
    let expanded = expand_host_escape(raw, host);
    let p = Path::new(&expanded);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Expand the `%h` escape in an include path to the short host name. Per the
/// `sudoers(5)` man page, any path-separator `/` present in the host name is
/// replaced with an underbar `_` during expansion (so the host name cannot inject
/// extra path components). Every `%h` occurrence is expanded.
fn expand_host_escape(raw: &str, host: &str) -> String {
    if !raw.contains("%h") {
        return raw.to_string();
    }
    let safe_host = host.replace('/', "_");
    raw.replace("%h", &safe_host)
}

/// The short host name (everything before the first `.`), for the `%h` escape.
///
/// Read from `/proc/sys/kernel/hostname` (the Linux distribution target, the same
/// value `gethostname(2)` returns), with the `HOSTNAME` environment variable as a
/// fallback. Falls back to an empty string if neither is available, so resolution
/// degrades gracefully rather than panicking (a `%h` path then resolves to a file
/// that almost certainly does not exist, which is surfaced as a missing-include
/// Malformed - the same defensible behavior as any bad include path).
fn short_hostname() -> String {
    let full = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    full.split('.').next().unwrap_or("").to_string()
}

/// Enumerate a `sudoers.d`-style directory's eligible drop-in FILES in sorted
/// lexical order (skipping `~`-suffixed and `.`-containing names, and any nested
/// subdirectory). Returns an `io::Error` only if the directory cannot be read.
fn eligible_dropins(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_eligible_dropin(p))
        .collect();
    // sudoers(5): files are parsed in sorted lexical order.
    names.sort();
    Ok(names)
}

/// Canonicalize a path for cycle-guard comparison; fall back to the path as-is when
/// canonicalization fails (e.g. the path does not exist) so a missing or odd path
/// is compared structurally rather than panicking.
fn canonical_or_as_is(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Build a synthetic single-line [`SudoersFile`] carrying one Malformed line, so a
/// missing-include / cycle condition flows through the normal sudo-F01 emitter
/// (the lint passes never special-case resolution errors). The synthetic file is
/// attributed to the INCLUDING file + the directive's line so the operator sees
/// where the bad directive sits; its `source` is empty (sudo-F01 is unanchored).
fn malformed_marker(
    message: String,
    including: &Path,
    directive_line: &LogicalLine,
) -> SudoersFile {
    SudoersFile {
        path: including.to_path_buf(),
        source: String::new(),
        lines: vec![LogicalLine {
            line: directive_line.line,
            span: Span::default(),
            kind: LineKind::Malformed(message),
        }],
    }
}

/// A Malformed marker for a missing `@include` target (visudo errors on this).
fn missing_include_file(
    missing: &Path,
    directive_line: &LogicalLine,
    including: &Path,
) -> SudoersFile {
    malformed_marker(
        format!(
            "@include target '{}' does not exist (no such file or directory)",
            missing.display()
        ),
        including,
        directive_line,
    )
}

/// A Malformed marker for an include cycle / over-depth chain (visudo: "too many
/// levels of includes"). Surfaced rather than hung-on or silently dropped.
fn too_many_levels(target: &Path, directive_line: &LogicalLine, including: &Path) -> SudoersFile {
    malformed_marker(
        format!(
            "too many levels of includes resolving '{}' (include loop or depth limit \
             of {MAX_INCLUDE_DEPTH} exceeded)",
            target.display()
        ),
        including,
        directive_line,
    )
}

/// Whether a directory entry's file name is an eligible `sudoers.d` drop-in.
///
/// `sudoers(5)` (`@includedir`): skip names that END IN `~` (editor backups) or
/// CONTAIN a `.` (e.g. RPM `.rpmsave` / `.rpmnew` / dotted package names). A name
/// that is not valid UTF-8 is treated as ineligible (conservative).
fn is_eligible_dropin(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => !name.ends_with('~') && !name.contains('.'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_INCLUDE_DEPTH, expand_host_escape, is_eligible_dropin, resolve_target,
        resolve_target_with_host,
    };
    use crate::ast::LineKind;
    use std::path::Path;

    /// Collect the resolved file paths (as their file-name strings) for terse
    /// order assertions.
    fn names(files: &[crate::ast::SudoersFile]) -> Vec<String> {
        files
            .iter()
            .map(|f| {
                f.path
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            })
            .collect()
    }

    /// True if any file in the resolved set carries a Malformed line (sudo-F01
    /// surfaces these; a missing `@include` / over-limit recursion lands here).
    fn any_malformed(files: &[crate::ast::SudoersFile]) -> bool {
        files.iter().any(|f| {
            f.lines
                .iter()
                .any(|l| matches!(l.kind, LineKind::Malformed(_)))
        })
    }

    /// The FLATTENED per-line user-spec subject order across the whole resolved set
    /// (each `UserSpec`'s first user token, in resolution order). This is sudo's
    /// EVALUATION order: an `@include`'s content is spliced at the directive's
    /// textual position, so a parent rule written AFTER an `@include` comes AFTER
    /// the included file's rules. Used to pin ordering fidelity (last-match-wins
    /// depends on it), which a file-granular `names()` check cannot see.
    fn user_order(files: &[crate::ast::SudoersFile]) -> Vec<String> {
        files
            .iter()
            .flat_map(|f| f.lines.iter())
            .filter_map(|l| match &l.kind {
                LineKind::UserSpec(s) => s.users.first().cloned(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn single_file_resolves_to_one_parsed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "root ALL=(ALL) ALL\n").expect("write");
        let files = resolve_target(&f).expect("resolve a file");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, f);
        assert!(matches!(
            files[0].lines[0].kind,
            crate::ast::LineKind::UserSpec(_)
        ));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = resolve_target(Path::new("/nonexistent/329/sudoers"));
        assert!(err.is_err(), "a missing file propagates the io::Error");
    }

    #[test]
    fn directory_parses_eligible_dropins_in_sorted_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Eligible drop-ins (no `.`, no trailing `~`), written out of order.
        std::fs::write(dir.path().join("20-bob"), "bob ALL=(ALL) ALL\n").expect("w");
        std::fs::write(dir.path().join("10-alice"), "alice ALL=(ALL) ALL\n").expect("w");
        // Ineligible: a `.`-containing name (RPM leftover) and a `~` backup.
        std::fs::write(dir.path().join("10-alice.rpmsave"), "garbage\n").expect("w");
        std::fs::write(dir.path().join("30-carol~"), "garbage\n").expect("w");

        let files = resolve_target(dir.path()).expect("resolve a dir");
        // Only the two eligible files, in sorted order: 10-alice then 20-bob.
        assert_eq!(files.len(), 2, "ineligible names are skipped: {files:?}");
        assert!(files[0].path.ends_with("10-alice"));
        assert!(files[1].path.ends_with("20-bob"));
    }

    #[test]
    fn dropin_eligibility_skips_dot_and_tilde_names() {
        assert!(is_eligible_dropin(Path::new("/etc/sudoers.d/10-foo")));
        assert!(!is_eligible_dropin(Path::new(
            "/etc/sudoers.d/10-foo.rpmnew"
        )));
        assert!(!is_eligible_dropin(Path::new("/etc/sudoers.d/10-foo~")));
        assert!(!is_eligible_dropin(Path::new("/etc/sudoers.d/.hidden")));
    }

    #[test]
    fn empty_directory_resolves_to_no_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = resolve_target(dir.path()).expect("resolve empty dir");
        assert!(files.is_empty());
    }

    /// Regression guard for the `flush` closure inside `resolve_parsed` (this
    /// module): it must stay CONDITIONAL (`if pending.iter().any(|l|
    /// !matches!(l.kind, LineKind::Blank))`), never an unconditional push. A
    /// parent file carries one real rule AND an `@includedir` pointing at an
    /// EMPTY directory (so the includedir contributes no drop-ins). `flush`
    /// runs TWICE while resolving this file: once for the parent's own rule
    /// (before the directive; `pending` is non-empty, correctly pushes one
    /// segment), and once for the trailing empty `pending` after the
    /// directive is processed (correctly a no-op). An "always-push" mutant of
    /// `flush` -- one that drops the `if` guard and pushes on every call --
    /// would push a SECOND, spurious empty segment on that trailing call,
    /// inflating the resolved slice to two files instead of one.
    ///
    /// This fixture's `out` is NEVER empty at the point where #485's BROAD
    /// top-level-zero-result fix would run (the parent's real rule guarantees
    /// at least one segment), so this test does NOT exercise that fork; it is
    /// pinned separately by `crate::lints::stig::tests::
    /// file_with_only_empty_includedir_fires_all_three_absence_findings_via_resolver`,
    /// whose fixture has no content besides the `@includedir`.
    #[test]
    fn empty_includedir_directive_synthesizes_no_phantom_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let empty_inc = root.path().join("empty.d");
        std::fs::create_dir_all(&empty_inc).expect("mkdir empty.d");
        std::fs::write(
            root.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@includedir empty.d\n",
        )
        .expect("w parent");

        let files = resolve_target(&root.path().join("parent")).expect("resolve");
        assert_eq!(
            files.len(),
            1,
            "an empty @includedir contributes NO entry (no phantom synthesized \
             for it); only the parent's own content segment appears; got {files:?}"
        );
        assert_eq!(
            names(&files),
            vec!["parent".to_string()],
            "only the parent's own content segment should appear; got {files:?}"
        );
    }

    // ---- #334: @include directive following + ordering --------------------
    //
    // Every fixture below was grounded against `visudo -c -f <parent>` on
    // sudo 1.9.17p2 (see the resolve.rs module doc): visudo follows the include
    // tree, resolves a non-absolute path relative to the INCLUDING file's
    // directory, reads an @includedir in sorted lexical order skipping `~`/`.`
    // names, errors on a missing @include target, and terminates a self-include
    // cycle ("too many levels of includes").

    #[test]
    fn at_include_inserts_the_included_file_at_the_directive_position() {
        // visudo -c accepts: parent @includes a child; the child's content is
        // inserted at the directive's position in evaluation order. So the
        // resolved Vec is [parent, child] (parent's pre-include content, then the
        // child spliced where the @include sat).
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@include child\n",
        )
        .expect("w parent");
        std::fs::write(dir.path().join("child"), "alice ALL=(ALL) NOPASSWD: ALL\n")
            .expect("w child");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert_eq!(
            names(&files),
            vec!["parent".to_string(), "child".to_string()],
            "the @included file is inserted at the directive position; got {files:?}"
        );
        assert!(!any_malformed(&files), "a present @include is not an error");
    }

    #[test]
    fn include_evaluation_order_splices_child_between_parents_own_rules() {
        // GROUNDED (cvtsudoers -f sudoers, sudo 1.9.17p2): the @included file
        // evaluates AT THE DIRECTIVE'S TEXTUAL POSITION, so a parent rule written
        // AFTER the @include comes AFTER the child's rules. Parent has rule `a`,
        // then `@include child` (child = `b`), then rule `c`. The correct flattened
        // evaluation order is a, b, c -- NOT a, c, b. sudo is last-match-wins, so
        // this ordering is load-bearing: a downstream lint reasoning about the
        // effective rule depends on it.
        //
        // cvtsudoers -f sudoers on this exact fixture emits, in order:
        //   alice ... /bin/ls        (parent line 1, `a`)
        //   alice ... PASSWD: /bin/ls (child, `b`)
        //   alice ... NOPASSWD: /bin/ls (parent line 3, `c`)
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "a ALL=(ALL:ALL) /bin/ls\n@include child\nc ALL=(ALL:ALL) NOPASSWD: /bin/ls\n",
        )
        .expect("w parent");
        std::fs::write(
            dir.path().join("child"),
            "b ALL=(ALL:ALL) PASSWD: /bin/ls\n",
        )
        .expect("w child");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert_eq!(
            user_order(&files),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "the @included child must splice BETWEEN the parent's pre- and \
             post-include rules (a, b, c), not after them (a, c, b); got {files:?}"
        );
    }

    #[test]
    fn legacy_hash_include_is_followed_like_at_include() {
        // The legacy `#include PATH` spelling is followed identically (it is NOT a
        // comment; visudo -c accepts and follows it).
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n#include child\n",
        )
        .expect("w");
        std::fs::write(dir.path().join("child"), "bob ALL=(ALL) ALL\n").expect("w");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert_eq!(
            names(&files),
            vec!["parent".to_string(), "child".to_string()]
        );
    }

    #[test]
    fn include_position_is_honored_between_two_includes() {
        // Two @includes in order: child_a then child_b. The resolved order is
        // [parent, child_a, child_b] - each child spliced at its directive's
        // position, preserving source order (last-match-wins downstream depends on
        // this ordering being faithful).
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "@include child_a\n@include child_b\n",
        )
        .expect("w");
        std::fs::write(dir.path().join("child_a"), "a ALL=(ALL) ALL\n").expect("w");
        std::fs::write(dir.path().join("child_b"), "b ALL=(ALL) ALL\n").expect("w");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        // The parent is ONLY include directives (no rules of its own), so it
        // contributes no content segment; the two children appear in source order.
        assert_eq!(
            names(&files),
            vec!["child_a".to_string(), "child_b".to_string()],
            "includes are spliced in source order; got {files:?}"
        );
    }

    #[test]
    fn relative_include_resolves_against_the_including_files_directory() {
        // GROUNDED (visudo -c): a non-absolute @include path is resolved relative
        // to the directory of the file that CONTAINED the directive, NOT the cwd.
        // Put the parent in a subdir and the child beside it; the resolution must
        // find the child via the parent's dir even though the cwd differs.
        let root = tempfile::tempdir().expect("tempdir");
        let sub = root.path().join("etc");
        std::fs::create_dir_all(&sub).expect("mkdir etc");
        std::fs::write(sub.join("parent"), "@include child_rel\n").expect("w parent");
        std::fs::write(sub.join("child_rel"), "alice ALL=(ALL) ALL\n").expect("w child");
        // A decoy `child_rel` in the cwd-root that must NOT be picked (proves the
        // relative path is anchored to the parent's dir, not the process cwd/root).
        std::fs::write(
            root.path().join("child_rel"),
            "MALFORMED garbage no equals\n",
        )
        .expect("w decoy");

        let files = resolve_target(&sub.join("parent")).expect("resolve");
        // The parent is only the include directive, so only the resolved child
        // contributes a content segment.
        assert_eq!(names(&files), vec!["child_rel".to_string()]);
        // The child we resolved is the GOOD one (in etc/), not the malformed decoy.
        assert!(
            !any_malformed(&files),
            "the parent-relative child (not the cwd decoy) must be resolved; got {files:?}"
        );
    }

    #[test]
    fn absolute_include_path_is_used_as_written() {
        // An absolute @include path is used verbatim (not joined to the parent dir).
        let dir = tempfile::tempdir().expect("tempdir");
        let child = dir.path().join("abs_child");
        std::fs::write(&child, "carol ALL=(ALL) ALL\n").expect("w child");
        std::fs::write(
            dir.path().join("parent"),
            format!("@include {}\n", child.display()),
        )
        .expect("w parent");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        // The parent is only the include directive; only the resolved child shows.
        assert_eq!(names(&files), vec!["abs_child".to_string()]);
    }

    #[test]
    fn nested_includes_resolve_recursively_each_relative_to_its_own_file() {
        // a @includes b (relative to a's dir); b @includes c (relative to b's dir).
        // `a` and `b` are only include directives, so the only content segment is
        // the deepest file `c`. Each relative path is anchored to its OWN including
        // file's directory (the chain still resolves through a -> b -> c).
        let root = tempfile::tempdir().expect("tempdir");
        let d1 = root.path().join("d1");
        let d2 = d1.join("d2");
        std::fs::create_dir_all(&d2).expect("mkdirs");
        std::fs::write(root.path().join("a"), "@include d1/b\n").expect("w a");
        std::fs::write(d1.join("b"), "@include d2/c\n").expect("w b");
        std::fs::write(d2.join("c"), "deep ALL=(ALL) ALL\n").expect("w c");

        let files = resolve_target(&root.path().join("a")).expect("resolve");
        assert_eq!(
            names(&files),
            vec!["c".to_string()],
            "the include chain resolves recursively, each path relative to its own \
             including file; the include-only a/b contribute no content; got {files:?}"
        );
        // The deepest file's rule was reached (proves the full a -> b -> c descent).
        assert_eq!(user_order(&files), vec!["deep".to_string()]);
    }

    #[test]
    fn includedir_parses_eligible_drop_ins_sorted_skipping_dot_and_tilde() {
        // GROUNDED (visudo -c): @includedir reads each file in the dir, SKIPPING
        // names ending in `~` or CONTAINING a `.`, in sorted LEXICAL order. Written
        // out of order; resolved as [parent, 10-carol, 20-bob]. The `.rpmnew` and
        // `~` entries are skipped.
        let root = tempfile::tempdir().expect("tempdir");
        let incdir = root.path().join("inc.d");
        std::fs::create_dir_all(&incdir).expect("mkdir inc.d");
        std::fs::write(incdir.join("20-bob"), "bob ALL=(ALL) ALL\n").expect("w");
        std::fs::write(incdir.join("10-carol"), "carol ALL=(ALL) ALL\n").expect("w");
        std::fs::write(incdir.join("30-skip.rpmnew"), "GARBAGE\n").expect("w");
        std::fs::write(incdir.join("40-skip~"), "GARBAGE\n").expect("w");
        std::fs::write(
            root.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@includedir inc.d\n",
        )
        .expect("w parent");

        let files = resolve_target(&root.path().join("parent")).expect("resolve");
        assert_eq!(
            names(&files),
            vec![
                "parent".to_string(),
                "10-carol".to_string(),
                "20-bob".to_string()
            ],
            "includedir entries are sorted lexically, `.`/`~` skipped; got {files:?}"
        );
        assert!(
            !any_malformed(&files),
            "the skipped GARBAGE drop-ins must not be parsed; got {files:?}"
        );
    }

    #[test]
    fn includedir_path_is_relative_to_the_including_file() {
        // The @includedir DIR path obeys the same relative-to-including-file rule.
        let root = tempfile::tempdir().expect("tempdir");
        let sub = root.path().join("place");
        let incdir = sub.join("drop");
        std::fs::create_dir_all(&incdir).expect("mkdirs");
        std::fs::write(incdir.join("10-x"), "x ALL=(ALL) ALL\n").expect("w");
        std::fs::write(sub.join("parent"), "@includedir drop\n").expect("w parent");

        let files = resolve_target(&sub.join("parent")).expect("resolve");
        // The parent is only the @includedir directive; only the drop-in shows.
        assert_eq!(names(&files), vec!["10-x".to_string()]);
    }

    #[test]
    fn includedir_does_not_recurse_into_subdirectories() {
        // GROUNDED (visudo -c): @includedir reads FILES in the dir only; a nested
        // SUBDIRECTORY's files are not visited.
        let root = tempfile::tempdir().expect("tempdir");
        let incdir = root.path().join("inc.d");
        let nested = incdir.join("nested");
        std::fs::create_dir_all(&nested).expect("mkdirs");
        std::fs::write(incdir.join("10-top"), "top ALL=(ALL) ALL\n").expect("w");
        std::fs::write(nested.join("inner"), "MALFORMED garbage\n").expect("w");
        std::fs::write(root.path().join("parent"), "@includedir inc.d\n").expect("w parent");

        let files = resolve_target(&root.path().join("parent")).expect("resolve");
        // The parent is only the @includedir; only the top-level drop-in shows (the
        // nested subdir is not visited).
        assert_eq!(
            names(&files),
            vec!["10-top".to_string()],
            "a nested subdir under an includedir is not visited; got {files:?}"
        );
        assert!(!any_malformed(&files));
    }

    #[test]
    fn missing_include_target_surfaces_a_malformed_diagnostic() {
        // GROUNDED (visudo -c on a missing @include target: rc=1,
        // "No such file or directory"). visudo ERRORS on a missing @include, so we
        // mirror the most defensible behavior: surface it (a Malformed line that
        // sudo-F01 turns into a Fatal), NOT a silent skip. The resolved set still
        // contains the parent so the rest of it lints.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@include does_not_exist\n",
        )
        .expect("w");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a missing @include target must surface (mirroring visudo's error), not be \
             silently skipped; got {files:?}"
        );
    }

    #[test]
    fn missing_includedir_is_silently_skipped() {
        // GROUNDED (visudo -c on a missing @includedir: rc=0, "parsed OK"). visudo
        // ACCEPTS a missing/unreadable @includedir, so we skip it silently (no
        // Malformed). The parent still lints.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@includedir no_such_dir\n",
        )
        .expect("w");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert!(
            !any_malformed(&files),
            "a missing @includedir is accepted by visudo and skipped silently; got {files:?}"
        );
        assert_eq!(names(&files), vec!["parent".to_string()]);
    }

    #[test]
    fn self_include_cycle_terminates_and_surfaces_a_malformed_diagnostic() {
        // GROUNDED (visudo -c on a self-@include: rc=1, "too many levels of
        // includes" - it TERMINATES). A cycle must NOT hang or stack-overflow; the
        // depth cap stops it and surfaces a Malformed (sudo-F01) at the offending
        // directive. This is the security-relevant termination proof.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("loop"),
            "root ALL=(ALL:ALL) ALL\n@include loop\n",
        )
        .expect("w");

        // If this hangs, the test harness times out (the bug we are guarding
        // against). A clean return is the termination proof.
        let files = resolve_target(&dir.path().join("loop")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a self-include cycle terminates and surfaces a too-many-levels Malformed; \
             got {files:?}"
        );
    }

    #[test]
    fn mutual_include_cycle_terminates() {
        // a @includes b, b @includes a. The mutual cycle must terminate (not hang),
        // and the over-limit branch surfaces a Malformed.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a"), "@include b\n").expect("w a");
        std::fs::write(dir.path().join("b"), "@include a\n").expect("w b");

        let files = resolve_target(&dir.path().join("a")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a mutual include cycle terminates with a too-many-levels Malformed; got {files:?}"
        );
    }

    #[test]
    fn deep_acyclic_include_chain_is_capped_at_the_nested_limit() {
        // A pathological but ACYCLIC chain longer than MAX_INCLUDE_DEPTH must stop
        // descending at the limit (mirroring visudo's 128 nested-include cap) and
        // surface a Malformed, without recursing unboundedly. Build a chain of
        // MAX_INCLUDE_DEPTH + 5 files f0 -> f1 -> ... each @including the next.
        let dir = tempfile::tempdir().expect("tempdir");
        let total = MAX_INCLUDE_DEPTH + 5;
        for i in 0..total {
            let body = if i + 1 < total {
                format!("@include f{}\n", i + 1)
            } else {
                "deepest ALL=(ALL) ALL\n".to_string()
            };
            std::fs::write(dir.path().join(format!("f{i}")), body).expect("w");
        }
        let files = resolve_target(&dir.path().join("f0")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a chain deeper than the nested limit is capped with a Malformed; got {} files",
            files.len()
        );
        // It stopped early: it did not resolve every one of the `total` files.
        assert!(
            files.len() <= MAX_INCLUDE_DEPTH + 2,
            "the depth cap stops descent near the limit, not the full chain; got {} files",
            files.len()
        );
    }

    #[test]
    fn include_depth_cap_boundary_is_exact() {
        // Pin the EXACT depth boundary so an off-by-one (`>` vs `>=` vs `==`) in the
        // `chain.len() > MAX_INCLUDE_DEPTH` guard fails. Each file f_i carries a rule
        // `r{i}` AND `@include f{i+1}`, so the count of resolved rules is exactly the
        // number of files whose body was reached. The root f0 is on the chain at
        // chain.len()==1; f_i's `@include f{i+1}` is evaluated with chain.len()==i+1,
        // and the guard blocks the next file once chain.len() > MAX_INCLUDE_DEPTH.
        // So files f0..f_MAX (MAX+1 files, indices 0..=MAX) are resolved and
        // f_{MAX+1} is blocked -> exactly MAX_INCLUDE_DEPTH + 1 rules. `>=`/`==`
        // mutants shift this count and fail.
        let dir = tempfile::tempdir().expect("tempdir");
        let total = MAX_INCLUDE_DEPTH + 4; // a few past the cap so the block triggers
        for i in 0..total {
            let next = if i + 1 < total {
                format!("@include f{}\n", i + 1)
            } else {
                String::new()
            };
            let body = format!("r{i} ALL=(ALL) ALL\n{next}");
            std::fs::write(dir.path().join(format!("f{i}")), body).expect("w");
        }
        let files = resolve_target(&dir.path().join("f0")).expect("resolve");
        let rules = user_order(&files);
        assert_eq!(
            rules.len(),
            MAX_INCLUDE_DEPTH + 1,
            "exactly MAX_INCLUDE_DEPTH+1 files are resolved before the cap blocks the \
             next; an off-by-one in the `> MAX` guard shifts this; got {} rules",
            rules.len()
        );
        // The deepest resolved rule is r{MAX} and r{MAX+1} is NOT present (it was the
        // blocked one). This pins which side of the boundary was reached.
        assert_eq!(
            rules.last().map(String::as_str),
            Some(format!("r{MAX_INCLUDE_DEPTH}").as_str()),
            "the last resolved rule is r{{MAX}}; got {:?}",
            rules.last()
        );
        assert!(
            !rules.contains(&format!("r{}", MAX_INCLUDE_DEPTH + 1)),
            "r{{MAX+1}} must be blocked by the cap; got {rules:?}"
        );
        assert!(any_malformed(&files), "the cap surfaces a Malformed");
    }

    #[test]
    fn includedir_self_cycle_terminates_and_surfaces_a_malformed() {
        // GROUNDED termination: an @includedir whose directory contains a drop-in
        // that @includes back into the directory's own file forms a cycle through
        // the @includedir branch (resolve.rs line ~194), distinct from the plain
        // @include branch (~178). It MUST terminate and surface a Malformed. This
        // exercises the includedir guard's `chain.contains(...) || depth` disjunction
        // (a `&&` mutant would require BOTH a cycle AND over-depth, so a pure cycle
        // through the includedir branch would wrongly recurse / not surface).
        let root = tempfile::tempdir().expect("tempdir");
        let incdir = root.path().join("inc.d");
        std::fs::create_dir_all(&incdir).expect("mkdir");
        // The drop-in @includes the PARENT, which @includedirs back -> a cycle that
        // passes through the @includedir branch when the parent is re-reached.
        std::fs::write(incdir.join("10-loop"), "@include ../parent\n").expect("w");
        std::fs::write(root.path().join("parent"), "@includedir inc.d\n").expect("w parent");

        // Must terminate (no hang / overflow) and surface a Malformed.
        let files = resolve_target(&root.path().join("parent")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a cycle through the @includedir branch terminates with a too-many-levels \
             Malformed; got {files:?}"
        );
    }

    #[test]
    fn includedir_dropin_revisited_via_chain_is_surfaced_not_reexpanded() {
        // Pin the includedir-branch cycle guard (`chain.contains(&dropin) || ...` at
        // resolve.rs line ~194) on the DROP-IN path itself, so the `chain.contains`
        // disjunct is load-bearing (kills the `|| -> &&` mutant: with `&&` a drop-in
        // already on the ancestry chain but not over-depth would be wrongly
        // re-expanded into an infinite loop instead of surfaced). Layout: drop-in
        // `g` @includedirs the SAME directory it lives in, so when the includedir is
        // re-scanned, `g` is reached as a drop-in while already on the chain.
        let root = tempfile::tempdir().expect("tempdir");
        let incdir = root.path().join("d");
        std::fs::create_dir_all(&incdir).expect("mkdir d");
        // `g` re-includedirs its own directory `d` (relative to g's dir = d), so `g`
        // is re-reached as a drop-in of `d` while `g` is on the ancestry chain.
        std::fs::write(incdir.join("g"), "@includedir .\n").expect("w g");
        std::fs::write(root.path().join("parent"), "@includedir d\n").expect("w parent");

        // Must terminate and surface a Malformed via the includedir-branch chain
        // check, NOT hang / re-expand `g` forever.
        let files = resolve_target(&root.path().join("parent")).expect("resolve");
        assert!(
            any_malformed(&files),
            "a drop-in revisited via the @includedir branch's chain guard is surfaced \
             (not re-expanded); got {files:?}"
        );
    }

    #[test]
    fn includedir_depth_cap_boundary_is_exact() {
        // Pin the EXACT depth boundary of the @includedir-branch guard (resolve.rs
        // line ~194: `chain.len() > MAX_INCLUDE_DEPTH`), so an off-by-one (`>` vs
        // `>=` vs `==`) there fails. Each level is a directory d{i} holding ONE
        // drop-in `g{i}` that carries a rule `r{i}` AND `@includedir ../d{i+1}`. The
        // root file `f0` @includedirs d0. Each g{i} pushes onto the chain, so the
        // includedir depth check at line ~194 governs how deep the chain descends.
        // f0 (chain.len() 1 at its includedir) -> g0 (2) -> g1 (3) -> ... The drop-in
        // g{i} is resolved while chain.len() == i+2 (f0 + g0..g{i}); the guard blocks
        // the NEXT drop-in once chain.len() > MAX. So exactly MAX_INCLUDE_DEPTH rules
        // r0..r{MAX-1} are resolved; an off-by-one shifts the count.
        let root = tempfile::tempdir().expect("tempdir");
        let total = MAX_INCLUDE_DEPTH + 4;
        for i in 0..total {
            let di = root.path().join(format!("d{i}"));
            std::fs::create_dir_all(&di).expect("mkdir d{i}");
            let next = if i + 1 < total {
                format!("@includedir ../d{}\n", i + 1)
            } else {
                String::new()
            };
            let body = format!("r{i} ALL=(ALL) ALL\n{next}");
            std::fs::write(di.join(format!("g{i}")), body).expect("w g{i}");
        }
        std::fs::write(root.path().join("f0"), "@includedir d0\n").expect("w f0");

        let files = resolve_target(&root.path().join("f0")).expect("resolve");
        let rules = user_order(&files);
        assert_eq!(
            rules.len(),
            MAX_INCLUDE_DEPTH,
            "exactly MAX_INCLUDE_DEPTH drop-ins resolve through the @includedir chain \
             before the depth guard blocks the next; an off-by-one in the `> MAX` \
             guard shifts this; got {} rules",
            rules.len()
        );
        assert_eq!(
            rules.last().map(String::as_str),
            Some(format!("r{}", MAX_INCLUDE_DEPTH - 1).as_str()),
            "the last resolved drop-in rule is r{{MAX-1}}; got {:?}",
            rules.last()
        );
        assert!(
            any_malformed(&files),
            "the includedir depth cap surfaces a Malformed"
        );
    }

    #[test]
    fn host_escape_expands_to_short_hostname() {
        // GROUNDED (sudoers(5) man page + visudo -c): `%h` expands to the SHORT host
        // name; path separators `/` in the hostname become `_`. Test the expansion
        // function directly (the resolve_target seam injects the real hostname).
        assert_eq!(expand_host_escape("host_%h", "xerxes"), "host_xerxes");
        assert_eq!(
            expand_host_escape("/etc/sudoers.%h", "web1"),
            "/etc/sudoers.web1"
        );
        // A `/` in the hostname is replaced with `_` (man page: "Any path name
        // separator characters ('/') ... will be replaced with an underbar ('_')").
        assert_eq!(expand_host_escape("p_%h", "a/b"), "p_a_b");
        // No `%h` -> path unchanged. Multiple `%h` -> all expanded.
        assert_eq!(expand_host_escape("plain/path", "h"), "plain/path");
        assert_eq!(expand_host_escape("%h-%h", "x"), "x-x");
    }

    #[test]
    fn include_with_host_escape_resolves_via_injected_hostname() {
        // The injectable-host variant resolves a `%h`-bearing @include path using
        // the provided hostname (the public resolve_target uses the real one). Build
        // a child named after the injected host and confirm the chain resolves.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("parent"), "@include host_%h\n").expect("w parent");
        std::fs::write(dir.path().join("host_myhost"), "h ALL=(ALL) ALL\n").expect("w child");

        let files =
            resolve_target_with_host(&dir.path().join("parent"), "myhost").expect("resolve");
        // The parent is only the %h include; only the resolved child shows.
        assert_eq!(
            names(&files),
            vec!["host_myhost".to_string()],
            "a %h include resolves via the injected hostname; got {files:?}"
        );
    }

    #[test]
    fn directory_target_with_drop_in_include_follows_the_directive() {
        // The directory CLI target (lint /etc/sudoers.d/) from Phase 0 stays, AND a
        // drop-in inside it that itself @includes a file follows that directive.
        // Layout: a sudoers.d dir with one drop-in (`10-main`) that @includes a
        // sibling file (`extra`). `extra` is ALSO an eligible directory entry, so it
        // is reached via TWO edges: the @include in 10-main AND the directory
        // enumeration. GROUNDED (cvtsudoers -f sudoers) that an included file is
        // applied once PER EDGE (no physical-identity dedup in sudo's evaluation),
        // so `extra` appears TWICE in resolution order: 10-main pulls it via the
        // @include, then the directory enumeration reaches it directly.
        let root = tempfile::tempdir().expect("tempdir");
        let dropin_dir = root.path().join("sudoers.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir");
        // `10-main` has a rule of its own AND @includes `extra`, so it contributes a
        // content segment AND pulls `extra` in. `extra` is also a direct dir entry,
        // so it is reached via TWO edges and applied once per edge (no dedup):
        // 10-main's content, then extra (via 10-main's @include), then extra again
        // (the direct directory enumeration).
        std::fs::write(
            dropin_dir.join("10-main"),
            "m ALL=(ALL) ALL\n@include extra\n",
        )
        .expect("w dropin");
        std::fs::write(dropin_dir.join("extra"), "x ALL=(ALL) ALL\n").expect("w extra");

        let files = resolve_target(&dropin_dir).expect("resolve dir");
        assert_eq!(
            names(&files),
            vec![
                "10-main".to_string(),
                "extra".to_string(),
                "extra".to_string()
            ],
            "a directory target follows @include directives inside its drop-ins; an \
             included file reached via two edges is applied once per edge (no dedup); \
             got {files:?}"
        );
        assert_eq!(
            user_order(&files),
            vec!["m".to_string(), "x".to_string(), "x".to_string()],
            "10-main's own rule, then extra via the @include, then extra via the \
             directory enumeration; got {files:?}"
        );
    }

    #[test]
    fn same_file_included_twice_is_applied_once_per_directive() {
        // GROUNDED (cvtsudoers -f sudoers, sudo 1.9.17p2): the same file @included
        // TWICE is applied TWICE, once at each directive's position (sudo does NOT
        // dedup by physical identity; each @include edge re-applies the file's rules
        // for last-match-wins). Parent: rule `p1`, @include c3, rule `p2`, @include
        // c3. c3 = rule `s`. Correct evaluation order: p1, s, p2, s.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "p1 ALL=(ALL) ALL\n@include c3\np2 ALL=(ALL) ALL\n@include c3\n",
        )
        .expect("w parent");
        std::fs::write(dir.path().join("c3"), "s ALL=(ALL) ALL\n").expect("w c3");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert_eq!(
            user_order(&files),
            vec![
                "p1".to_string(),
                "s".to_string(),
                "p2".to_string(),
                "s".to_string()
            ],
            "a file @included twice is applied once per directive (p1, s, p2, s); \
             got {files:?}"
        );
    }

    #[test]
    fn non_cyclic_diamond_applies_the_shared_file_once_per_branch() {
        // GROUNDED (cvtsudoers -f sudoers): a non-cyclic DIAMOND (parent @includes a
        // and b; a and b each @include the same `shared`) applies `shared` TWICE,
        // once per branch -- this is NOT a cycle and must NOT be capped/deduped. The
        // per-ancestry chain guard (pushed/popped) correctly allows the second
        // branch (shared is not on b's ancestry chain), unlike a global seen-set.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("parent"), "@include a\n@include b\n").expect("w");
        std::fs::write(dir.path().join("a"), "@include shared\n").expect("w a");
        std::fs::write(dir.path().join("b"), "@include shared\n").expect("w b");
        std::fs::write(dir.path().join("shared"), "s ALL=(ALL) ALL\n").expect("w shared");

        let files = resolve_target(&dir.path().join("parent")).expect("resolve");
        assert!(
            !any_malformed(&files),
            "a non-cyclic diamond is not a loop; no too-many-levels Malformed; got {files:?}"
        );
        assert_eq!(
            user_order(&files),
            vec!["s".to_string(), "s".to_string()],
            "the shared file is applied once per diamond branch (s, s); got {files:?}"
        );
    }
}
