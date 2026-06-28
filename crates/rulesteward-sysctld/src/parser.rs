//! `sysctl.d`/`sysctl.conf` line parser + the F01/W01 lint passes (issue #150).
//!
//! `sysctl.conf(5)` / `sysctl.d(5)` syntax is a sequence of newline-separated
//! lines, each one of:
//! * a whole-line comment - first non-whitespace char is `#` or `;`,
//! * a blank / whitespace-only line,
//! * an assignment - `key = value` or `key=value`, with arbitrary surrounding
//!   whitespace; a leading `-` on the key ("ignore set errors") is still a valid
//!   assignment, stripped for the key identity,
//! * a bare glob-exclusion - a `-key` with NO `=` (man page: "prefixed with a
//!   '-' character and not followed by '='"), valid,
//! * anything else (a bare key, a space-separated `key value`, an empty key) is
//!   malformed -> `sysctld-F01`.
//!
//! Separator canonicalization (sysctl.d(5)): `/` and `.` are interchangeable, but
//! ASYMMETRICALLY - "if the first separator is a slash, remaining slashes and dots
//! are left intact; if the first separator is a dot, dots and slashes are
//! interchanged." So [`canonical_key`] maps a key to its `/proc/sys` path form: a
//! slash-first key is left as-is, a dot-first key swaps every `.`<->`/`. Thus
//! `net/ipv4/ip_forward` and `net.ipv4.ip_forward` are the same key, while
//! `net/ipv4/conf/enp3s0.200/forwarding` (interface `enp3s0.200`) and
//! `net.ipv4.conf.enp3s0.200.forwarding` (`enp3s0/200`) are DISTINCT keys.
//!
//! The last assignment of a (canonical) key wins; an earlier assignment of the
//! same key to a DIFFERENT value is dead -> `sysctld-W01`, anchored at the dead
//! (overridden) earlier line - the actionable surprise the operator must remove.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use rulesteward_core::span::Span;
use rulesteward_core::{Diagnostic, Severity, anchored};

use crate::lints::baseline::{TargetVersion, w02_baseline};

/// One classified non-trivial line: an assignment or a parse failure. Comments,
/// blank lines, and bare glob-exclusions carry no semantic payload and are not
/// represented here (they emit nothing).
enum LineKind {
    /// A `key = value` assignment.
    /// * `canonical` is the `/proc/sys` path form used for key IDENTITY (leading
    ///   `-` stripped, asymmetric first-separator rule applied).
    /// * `display` is the key as the operator WROTE it (leading `-` stripped, but
    ///   separators left untouched), for operator-facing messages.
    /// * `value` is the trimmed raw value text.
    Assignment {
        canonical: String,
        display: String,
        value: String,
    },
    /// A malformed line: not a comment, not blank, not a bare glob-exclusion, and
    /// carrying no `=` assignment. Emits `sysctld-F01`.
    Malformed,
}

/// Canonicalize a key to its `/proc/sys` path form for identity comparison.
///
/// sysctl.d(5) defines an ASYMMETRIC separator rule, NOT a blanket `/`<->`.`
/// swap: "If the first separator is a slash, remaining slashes and dots are left
/// intact. If the first separator is a dot, dots and slashes are interchanged."
/// The man page's worked example: both `net.ipv4.conf.enp3s0/200.forwarding` and
/// `net/ipv4/conf/enp3s0.200/forwarding` name `.../enp3s0.200/forwarding`.
///
/// So the canonical (path) form is derived from the FIRST separator:
/// * first separator `/`  -> leave the key as-is (the path form already),
/// * first separator `.`  -> interchange EVERY `.`<->`/` in one pass (a literal
///   dot inside a path component, e.g. the VLAN id in `enp3s0.200`, becomes a
///   path `/`, which is exactly the man page's intent for a dot-first key),
/// * no separator         -> as-is.
///
/// Consequence (the false-positive this fixes): `net.ipv4.conf.enp3s0.200.forwarding`
/// (dot-first -> swap -> `.../enp3s0/200/forwarding`) is a DIFFERENT key from
/// `net/ipv4/conf/enp3s0.200/forwarding` (slash-first -> as-is ->
/// `.../enp3s0.200/forwarding`); a blanket `/`->`.` rule wrongly collapses them.
pub(crate) fn canonical_key(raw: &str) -> String {
    // `raw` is the assignment key with the leading ignore-error `-` already
    // stripped by the caller; canonicalization keys off the first separator only.
    match raw.find(['/', '.']) {
        Some(i) if raw.as_bytes()[i] == b'.' => raw
            .chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                other => other,
            })
            .collect(),
        // First separator is `/`, or there is no separator: the key is already
        // in (or trivially is) its path form.
        _ => raw.to_string(),
    }
}

/// Classify a single source line. Returns `None` for lines that emit nothing
/// (comments, blank lines, bare `-key` glob-exclusions); `Some` for an
/// assignment or a malformed line.
fn classify_line(line: &str) -> Option<LineKind> {
    let trimmed = line.trim();

    // Blank / whitespace-only -> ignored.
    if trimmed.is_empty() {
        return None;
    }

    // Whole-line comment: first non-whitespace char is `#` or `;`. (No inline
    // comments: a `#` mid-value is part of the value.)
    let first = trimmed.as_bytes()[0];
    if first == b'#' || first == b';' {
        return None;
    }

    // An assignment is signalled by a `=`. Split on the FIRST `=`: everything
    // before is the key, everything after is the value (a `=` mid-value stays in
    // the value).
    if let Some(eq) = trimmed.find('=') {
        let key_raw = trimmed[..eq].trim();
        let value = trimmed[eq + 1..].trim();
        // Strip the single leading ignore-error `-` FIRST, THEN check emptiness:
        // an empty key is malformed REGARDLESS of a leading `-`. This makes `= 1`,
        // `- = 1`, and `-=1` all F01 (consistent), and prevents a degenerate W01
        // with an empty key name. A non-empty post-dash key (`-kernel.x`) stays a
        // valid ignore-error assignment.
        let key_body = key_raw.strip_prefix('-').unwrap_or(key_raw).trim();
        if key_body.is_empty() {
            return Some(LineKind::Malformed);
        }
        return Some(LineKind::Assignment {
            canonical: canonical_key(key_body),
            display: key_body.to_string(),
            value: value.to_string(),
        });
    }

    // No `=`. A bare `-key` is a valid glob-exclusion (emits nothing); anything
    // else without an `=` (a bare key, a space-separated `key value`) is
    // malformed.
    if trimmed.starts_with('-') {
        return None;
    }
    Some(LineKind::Malformed)
}

/// One parsed assignment with its 1-based source line, for cross-line/file W01
/// and the W02 baseline check. `pub(crate)` so the `lints::baseline` pass can read
/// the effective value, file, line, and span of each assignment.
pub(crate) struct ParsedAssignment {
    /// `/proc/sys` path form, used for last-wins key IDENTITY and W02 lookup.
    pub(crate) canonical: String,
    /// The key as the operator wrote it (dash-stripped), for the W01/W02 message.
    pub(crate) display: String,
    pub(crate) value: String,
    pub(crate) file: PathBuf,
    pub(crate) line: usize,
    /// Byte range of the assignment's source line within its file. When this
    /// assignment is the OVERRIDDEN (dead) one, W01 anchors at this span so the
    /// human renderer shows an ariadne snippet on the right line (issue #337); a
    /// present-but-insecure W02 anchors at the same span.
    pub(crate) span: Span,
}

/// Parse `source` into its assignments and the F01 diagnostics for any malformed
/// lines. F01 diagnostics are anchored to `path`; assignments carry `path` too so
/// the caller can run W01 across one or many files uniformly.
fn parse_file(source: &str, path: &Path) -> (Vec<ParsedAssignment>, Vec<Diagnostic>) {
    let mut assignments = Vec::new();
    let mut f01s = Vec::new();
    // Track a running byte offset so each finding carries the real byte range of its
    // line (issue #337): the human renderer derives the ariadne snippet header from the
    // byte SPAN, so a degenerate `0..0` would mis-anchor every finding at line 1.
    // Iterate `split('\n')` (not `lines()`) to keep the offsets exact -- each segment is
    // exactly the bytes between newlines. `classify_line` trims, so a trailing `\r` on
    // CRLF and the trailing empty segment from a final `\n` classify to `None` (harmless),
    // and the 1-based line numbers match `lines()`.
    let mut offset = 0usize;
    for (idx, raw_line) in source.split('\n').enumerate() {
        let lineno = idx + 1; // 1-based
        let span = offset..offset + raw_line.len();
        offset += raw_line.len() + 1; // +1 for the consumed '\n'
        match classify_line(raw_line) {
            None => {}
            Some(LineKind::Assignment {
                canonical,
                display,
                value,
            }) => {
                assignments.push(ParsedAssignment {
                    canonical,
                    display,
                    value,
                    file: path.to_path_buf(),
                    line: lineno,
                    span,
                });
            }
            Some(LineKind::Malformed) => {
                f01s.push(anchored(
                    Severity::Fatal,
                    "sysctld-F01",
                    span,
                    "malformed sysctl line: expected `key = value`, a `#`/`;` comment, or a bare \
                     `-key` glob-exclusion",
                    path.to_path_buf(),
                    lineno,
                ));
            }
        }
    }
    (assignments, f01s)
}

/// Run the last-wins (`sysctld-W01`) pass over an ordered list of assignments.
///
/// The assignments are in precedence order: LATER entries win. For each key, an
/// earlier assignment whose value DIFFERS from the final (winning) value for that
/// key is dead -> one W01 anchored at the dead earlier line, naming the key and
/// the winning value/location. Same key + same value, or an earlier entry that is
/// itself the eventual winner, never fires.
/// The winning (last) assignment index for each canonical key, in precedence
/// order (later wins). The single source of the effective-value map shared by the
/// W01 last-wins pass and the W02 baseline pass, so both reason over identical
/// key IDENTITY (the canonical `/proc/sys` path form).
pub(crate) fn effective_values(assignments: &[ParsedAssignment]) -> HashMap<&str, usize> {
    let mut winner: HashMap<&str, usize> = HashMap::new();
    for (idx, a) in assignments.iter().enumerate() {
        winner.insert(a.canonical.as_str(), idx);
    }
    winner
}

fn w01_last_wins(assignments: &[ParsedAssignment]) -> Vec<Diagnostic> {
    // Key IDENTITY is the canonical /proc/sys path form; the winner for each key
    // is its LAST assignment (highest index).
    let winner = effective_values(assignments);

    let mut diags = Vec::new();
    for (idx, a) in assignments.iter().enumerate() {
        let win_idx = winner[a.canonical.as_str()];
        // This assignment is dead iff it is not the winner AND the winner sets a
        // DIFFERENT value (same value = redundant, not a conflict).
        if win_idx != idx {
            let win = &assignments[win_idx];
            if win.value != a.value {
                // Message names the key as the operator WROTE it (display form),
                // not the canonical path form, so the finding is readable.
                diags.push(anchored(
                    Severity::Warning,
                    "sysctld-W01",
                    a.span.clone(),
                    format!(
                        "last-wins conflict: `{}` here (= {}) is overridden by the later \
                         assignment (= {}) at {}:{}",
                        a.display,
                        a.value,
                        win.value,
                        win.file.display(),
                        win.line,
                    ),
                    a.file.clone(),
                    a.line,
                ));
            }
        }
    }
    diags
}

/// Parse `source` (the contents of a `sysctl.d`/`sysctl.conf` file at `path`) and
/// run the version-agnostic `sysctld-` lint passes over it: every malformed line's
/// `sysctld-F01`, then the within-file last-wins `sysctld-W01`. A thin wrapper over
/// [`lint_str_with_target`] with no STIG baseline selected.
#[must_use]
pub fn lint_str(source: &str, path: &Path) -> Vec<Diagnostic> {
    lint_str_with_target(source, path, None)
}

/// As [`lint_str`], plus the version-aware `sysctld-W02` STIG baseline pass when
/// `target` is `Some`. A MISSING required key is anchored at `path` (file mode); a
/// present-but-insecure key is anchored at its real assignment line/span.
#[must_use]
pub fn lint_str_with_target(
    source: &str,
    path: &Path,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    let (assignments, mut diags) = parse_file(source, path);
    diags.extend(w01_last_wins(&assignments));
    if let Some(t) = target {
        diags.extend(w02_baseline(&assignments, t, path));
    }
    diags
}

/// Lint a directory of `*.conf` drop-ins as one precedence-ordered set.
///
/// Files apply in lexicographic filename order (the lexicographically-LATEST file
/// wins, mirroring systemd's drop-in precedence within a single directory). Each
/// file is parsed for `sysctld-F01` independently; the cross-file `sysctld-W01`
/// last-wins pass then runs over the concatenated, order-preserved assignment
/// list, so a dead assignment is anchored to its real file + line.
///
/// Cross-DIRECTORY masking (the `/etc` vs `/run` vs `/usr/lib` search path) is out
/// of v1 scope (deferred, issue #150); this reasons within one directory only.
///
/// On a directory it cannot enumerate (e.g. an unreadable dir), returns a single
/// file-level `sysctld-F01` rather than panicking.
///
/// Also returns the staged source of every successfully-read `*.conf`, keyed by its
/// display path (the `source_id` convention `anchored` sets). The CLI passes this map
/// to the human renderer so a cross-file `sysctld-W01` shows an ariadne snippet
/// anchored in the drop-in that holds the dead line (issue #337). The file-level F01s
/// (unreadable dir / file) carry no `source_id`, so they need no staged source; an
/// unreadable directory returns an empty map alongside the single file-level F01.
#[must_use]
pub fn lint_dir(dir: &Path) -> (Vec<Diagnostic>, BTreeMap<String, String>) {
    lint_dir_with_target(dir, None)
}

/// As [`lint_dir`], plus the version-aware `sysctld-W02` STIG baseline pass when
/// `target` is `Some`. A MISSING required key is anchored at `dir` (the drop-in
/// set has no single source line); a present-but-insecure key is anchored at the
/// real drop-in file it came from (whose source is staged, so the human renderer
/// shows a snippet).
#[must_use]
pub fn lint_dir_with_target(
    dir: &Path,
    target: Option<TargetVersion>,
) -> (Vec<Diagnostic>, BTreeMap<String, String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return (
                vec![Diagnostic::new(
                    Severity::Fatal,
                    "sysctld-F01",
                    0..0,
                    format!("cannot read sysctl.d directory {}: {e}", dir.display()),
                    dir.to_path_buf(),
                    0,
                    0,
                )],
                BTreeMap::new(),
            );
        }
    };

    // Collect the `*.conf` files, sorted lexicographically by file name. A
    // non-`*.conf` entry (README, a subdirectory) is ignored, matching systemd's
    // drop-in enumeration.
    let mut conf_files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "conf"))
        .collect();
    conf_files.sort();

    let mut all_assignments: Vec<ParsedAssignment> = Vec::new();
    let mut diags: Vec<Diagnostic> = Vec::new();
    // Stage each successfully-read drop-in's source, keyed by its display path (the
    // `source_id` convention), so the human renderer can resolve a cross-file W01
    // snippet against the file that holds the dead line (issue #337).
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for path in &conf_files {
        match std::fs::read_to_string(path) {
            Ok(source) => {
                let (assignments, f01s) = parse_file(&source, path);
                diags.extend(f01s);
                all_assignments.extend(assignments);
                sources.insert(path.display().to_string(), source);
            }
            Err(e) => {
                // An unreadable / non-UTF8 drop-in is a parse failure for that
                // file, not a panic; the rest of the directory still lints. This
                // file-level F01 carries no `source_id`, so it needs no staged source.
                diags.push(Diagnostic::new(
                    Severity::Fatal,
                    "sysctld-F01",
                    0..0,
                    format!("cannot read {}: {e}", path.display()),
                    path.clone(),
                    0,
                    0,
                ));
            }
        }
    }
    diags.extend(w01_last_wins(&all_assignments));
    if let Some(t) = target {
        diags.extend(w02_baseline(&all_assignments, t, dir));
    }
    (diags, sources)
}

#[cfg(test)]
mod tests {
    use super::{LineKind, canonical_key, classify_line};

    #[test]
    fn canonical_key_applies_the_asymmetric_first_separator_rule() {
        // Slash-first: left as-is (already the /proc/sys path form).
        assert_eq!(
            canonical_key("net/ipv4/conf/enp3s0.200/forwarding"),
            "net/ipv4/conf/enp3s0.200/forwarding"
        );
        // Dot-first: interchange EVERY `.`<->`/` in one pass, so a literal dot
        // inside a path component (the VLAN id) becomes a path `/`.
        assert_eq!(
            canonical_key("net.ipv4.conf.enp3s0.200.forwarding"),
            "net/ipv4/conf/enp3s0/200/forwarding"
        );
        // The easy equivalence the man page pins: dot-first and slash-first forms
        // of a key with no in-component dots canonicalize to the SAME path form.
        assert_eq!(canonical_key("net.ipv4.ip_forward"), "net/ipv4/ip_forward");
        assert_eq!(canonical_key("net/ipv4/ip_forward"), "net/ipv4/ip_forward");
        // No separator: as-is.
        assert_eq!(canonical_key("solitary"), "solitary");
    }

    #[test]
    fn classify_comment_blank_and_glob_exclusion_emit_nothing() {
        assert!(classify_line("# comment").is_none());
        assert!(classify_line("   ; comment").is_none());
        assert!(classify_line("").is_none());
        assert!(classify_line("   \t  ").is_none());
        assert!(classify_line("-net.ipv4.conf.eth0.rp_filter").is_none());
    }

    #[test]
    fn classify_assignment_extracts_canonical_and_display_keys() {
        // Slash-first key: canonical is left as-is (already the path form); display
        // is the written form (identical here). Whitespace tolerated.
        match classify_line("  net/ipv4/ip_forward  =  1  ") {
            Some(LineKind::Assignment {
                canonical,
                display,
                value,
            }) => {
                assert_eq!(canonical, "net/ipv4/ip_forward");
                assert_eq!(display, "net/ipv4/ip_forward");
                assert_eq!(value, "1");
            }
            _ => panic!("expected an assignment for a slash-first `key = value` line"),
        }
    }

    #[test]
    fn classify_ignore_error_prefix_is_an_assignment() {
        // The leading `-` is stripped; the dot-first key's canonical form swaps to
        // the path form, while the display form keeps the written dots.
        match classify_line("-kernel.dmesg_restrict = 1") {
            Some(LineKind::Assignment {
                canonical,
                display,
                value,
            }) => {
                assert_eq!(canonical, "kernel/dmesg_restrict");
                assert_eq!(display, "kernel.dmesg_restrict");
                assert_eq!(value, "1");
            }
            _ => panic!("a `-key = value` line is a valid assignment"),
        }
    }

    #[test]
    fn classify_value_keeps_mid_value_hash_and_equals() {
        // No inline comments: a `#` in the value stays; a second `=` stays too.
        match classify_line("kernel.x = a#b=c") {
            Some(LineKind::Assignment {
                canonical,
                display,
                value,
            }) => {
                assert_eq!(canonical, "kernel/x");
                assert_eq!(display, "kernel.x");
                assert_eq!(value, "a#b=c");
            }
            _ => panic!("expected assignment"),
        }
    }

    #[test]
    fn classify_malformed_lines() {
        assert!(matches!(
            classify_line("kernel.dmesg_restrict"),
            Some(LineKind::Malformed)
        ));
        assert!(matches!(
            classify_line("net.ipv4.ip_forward 1"),
            Some(LineKind::Malformed)
        ));
        assert!(matches!(classify_line("= 1"), Some(LineKind::Malformed)));
    }

    #[test]
    fn classify_empty_key_after_ignore_error_dash_is_malformed() {
        // FIX 2: the dash is stripped BEFORE the emptiness check, so an empty key
        // is malformed regardless of the leading `-`.
        assert!(matches!(classify_line("- = 1"), Some(LineKind::Malformed)));
        assert!(matches!(classify_line("-=1"), Some(LineKind::Malformed)));
    }
}
