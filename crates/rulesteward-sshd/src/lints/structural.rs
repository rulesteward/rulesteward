//! Structural lints: directive identity, duplication, Include resolution, and
//! Match-block legality. These need no STIG/crypto baseline tables, so the
//! parallel pipelines for sshd-E02/E03/E04 (Wave A) can start the moment the
//! Phase-0 foundation merges. sshd-E01 (registry-gated) and sshd-W05 (which
//! reuses the W01 required-set) are grouped here as the structural family.
//!
//! sshd-E01, -E02, -E03, and -E04 ship real bodies here; only `sshd-W05`
//! remains a `Vec::new()` stub (Wave C, #149). The lint codes are children
//! of epic #149.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, Directive};
use crate::lints::{SshdLintContext, anchored, registry};

/// Keywords sshd accumulates (unions) across multiple lines rather than
/// first-value-wins, so a repeat is legitimate and must NOT be flagged by
/// sshd-E02. Lowercased and sorted (matched via [`slice::contains`] on the
/// lowercased keyword).
///
/// Grounded in `sshd_config(5)` (OpenSSH 10.2p1) and confirmed with an `sshd -T`
/// effective-config differential: each keyword below shows BOTH values when set
/// twice. `SetEnv` is deliberately ABSENT - the differential showed a second
/// `SetEnv` line is dropped (first wins), so a repeated `SetEnv` IS a shadow.
///
/// `Subsystem` is also absent: it accumulates across DIFFERENT names but is
/// first-value-wins for the SAME name, so it gets name-keyed handling in [`e02`]
/// rather than a blanket exemption.
const E02_ALLOW_REPEAT: &[&str] = &[
    "acceptenv",
    "allowgroups",
    "allowusers",
    "denygroups",
    "denyusers",
    "hostkey",
    "include",
    "listenaddress",
    "port",
];

/// Keywords permitted on the lines following a `Match` keyword that the daemon
/// honors on EVERY supported OpenSSH version (8.0p1 / 9.9p1). These are the
/// `SSHCFG_ALL` / `SSHCFG_MATCH` opcodes that have carried that flag across all
/// builds we ground against, so they are Match-permitted regardless of `--target`.
///
/// Lowercased and sorted (matched via [`slice::contains`]). Started from the
/// `sshd_config(5)` "Available keywords are ..." paragraph (OpenSSH 10.2p1) and
/// corrected against the real daemon: the man-page paragraph is an incomplete
/// rendering of the `servconf.c` opcode table, so the version-split keywords
/// (`subsystem`, `requiredrsasize`, ...) live in the per-version additions below
/// rather than here.
///
/// `pubkeyacceptedkeytypes` / `hostbasedacceptedkeytypes` (the pre-8.5 rename
/// aliases) are `SSHCFG_ALL` on every version, so they belong here even though the
/// man page omits the aliases.
///
/// # Provenance (hand-authored; do not edit without re-grounding on the VMs)
///
/// Snapshot-dated 2026-06-29. Rocky 8.10 / 9.8 / 10.2 (OpenSSH 8.0p1 / 9.9p1 /
/// 9.9p1). The Match-legality oracle is the daemon's FATAL MESSAGE for a keyword
/// inside a NON-ACTIVATING Match block, NOT an exit code and NOT `-o`/`-C`.
/// `servconf.c` emits "Directive '...' is not allowed within a Match block" only
/// when the Match is inactive AND no connection spec is supplied. So for each
/// keyword KW, on each VM:
///   1. Write a CONFIG FILE whose body is a non-activating Match plus KW inside it:
///      a line `Match User nomatch_zz_user`, then a line `KW yes`.
///   2. Run plain `sshd -t -f <file>` (no `-o`, no `-C` connection spec, so
///      `connectinfo == NULL` and the fatal can fire). Classify by the MESSAGE:
///      - "Bad configuration option: KW" => UNKNOWN to this build (E01's province,
///        not these sets). TEST THIS FIRST: 8.0p1 emits BOTH the unknown message
///        AND the "not allowed within a Match block" message for an unknown
///        keyword, so the unknown check must short-circuit before the global check.
///      - "...is not allowed within a Match block" => `SSHCFG_GLOBAL` (global-only;
///        belongs in NEITHER set so it keeps firing E04 inside a Match).
///      - parses clean (no fatal) => `SSHCFG_ALL`/`SSHCFG_MATCH` (Match-permitted;
///        goes here if honored on every version, else in the 9.9p1 set).
///
/// Do NOT use `sshd -t -o "KW=yes"`: `-o` injects KW into GLOBAL context and
/// bypasses the Match block, so nearly every recognized keyword false-reports as
/// permitted. Do NOT use `sshd -T -C user=...` as the take-effect check either: it
/// folds Match values into the flat dump WITHOUT the `SSHCFG_MATCH` filter, so it
/// false-reports global-only keywords (Ciphers/Port/...) as honored-in-Match. Both
/// are the documented wrong oracles.
///
/// A keyword fires sshd-E04 iff it is in neither set AND is recognized by the
/// target registry. A set edit must be accompanied by a corresponding guard-test
/// update (see `e04_set_guard_tests` below) and VM re-verification on Rocky
/// 8.10 / 9.8 / 10.2. See also depth-sshd-sets.md FINDING 1 (2026-06-17, the
/// non-activating-Match oracle) and issue #356 live differential
/// (gssapienablek5users, 2026-06-29).
const E04_PERMITTED_BASE: &[&str] = &[
    "acceptenv",
    "allowagentforwarding",
    "allowgroups",
    "allowstreamlocalforwarding",
    "allowtcpforwarding",
    "allowusers",
    "authenticationmethods",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "authorizedkeysfile",
    "authorizedprincipalscommand",
    "authorizedprincipalscommanduser",
    "authorizedprincipalsfile",
    "banner",
    "casignaturealgorithms",
    "channeltimeout",
    "chrootdirectory",
    "clientalivecountmax",
    "clientaliveinterval",
    "denygroups",
    "denyusers",
    "disableforwarding",
    "exposeauthinfo",
    "forcecommand",
    "gatewayports",
    "gssapiauthentication",
    "gssapienablek5users",
    "hostbasedacceptedalgorithms",
    "hostbasedacceptedkeytypes",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "include",
    "ipqos",
    "kbdinteractiveauthentication",
    "kerberosauthentication",
    "kerberosusekuserok",
    "loglevel",
    "maxauthtries",
    "maxsessions",
    "pamservicename",
    "passwordauthentication",
    "permitemptypasswords",
    "permitlisten",
    "permitopen",
    "permitrootlogin",
    "permittty",
    "permittunnel",
    "permituserrc",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "pubkeyauthentication",
    "pubkeyauthoptions",
    "rdomain",
    "refuseconnection",
    "rekeylimit",
    "revokedkeys",
    "setenv",
    "streamlocalbindmask",
    "streamlocalbindunlink",
    "trustedusercakeys",
    "unusedconnectiontimeout",
    "x11displayoffset",
    "x11forwarding",
    "x11maxdisplays",
    "x11uselocalhost",
];

/// Match-permitted keywords the OpenSSH 9.9p1 daemon (RHEL 9 / RHEL 10) honors in
/// a `Match` block but the 8.0p1 daemon (RHEL 8) does NOT. Each changed its
/// `servconf.c` opcode flag to `SSHCFG_ALL` at or after 9.x, or is a 9.x-only
/// keyword. Lowercased and sorted.
///
/// `subsystem` and `ignorerhosts` are the canonical cases: `SSHCFG_GLOBAL` on
/// 8.0p1 (so each fires E04 inside a Match under `--target rhel8`) but `SSHCFG_ALL`
/// from 9.x. The 9.x-only keywords (`requiredrsasize`, `rsaminsize`, `logverbose`)
/// are simply unknown to the 8.0p1 registry, so they never reach this set under
/// `--target rhel8` (E01 owns them there); they are Match-permitted on 9/10 and the
/// no-target union.
///
/// Source: depth-sshd-sets.md FINDING 1 (servconf.c `V_9_9_P1` `SSHCFG_ALL` flags +
/// non-activating-Match `sshd -t` per VM, 2026-06-17). `ignorerhosts` is the
/// `{ "ignorerhosts", sIgnoreRhosts, SSHCFG_GLOBAL }` entry at `V_8_0_P1` vs
/// `SSHCFG_ALL` at `V_9_9_P1`, identical in shape to `subsystem`.
///
/// # Provenance (hand-authored; do not edit without re-grounding on the VMs)
///
/// Snapshot-dated 2026-06-29. Rocky 8.10 / 9.8 / 10.2 (OpenSSH 8.0p1 / 9.9p1 /
/// 9.9p1). Same non-activating-Match fatal-message oracle as `E04_PERMITTED_BASE`
/// above (a config file with `Match User nomatch_zz_user` then `KW yes`, plain
/// `sshd -t -f <file>`, classify by the fatal message - test the UNKNOWN message
/// first; do NOT use `-o` or `-T -C`). The split between the two sets is per
/// version: a keyword goes HERE (not in BASE) when it is `SSHCFG_GLOBAL` on 8.0p1
/// but `SSHCFG_ALL` from 9.x, or is a 9.x-only keyword. Keywords here are either
/// (a) in `RHEL8_BASE` but `SSHCFG_GLOBAL` on 8.0p1 / `SSHCFG_ALL` from 9.x
/// (subsystem, ignorerhosts, challengeresponseauthentication, skeyauthentication),
/// or (b) 9.x-only keywords (logverbose, requiredrsasize, rsaminsize) that are
/// unknown to the 8.0p1 registry (E01 owns them there; they reach this set only at
/// --target rhel9/rhel10 or no-target).
///
/// A set edit must be accompanied by a guard-test update (see `e04_set_guard_tests`
/// below) and VM re-verification on Rocky 8.10 / 9.8 / 10.2.
const E04_PERMITTED_ADDED_9_9P1: &[&str] = &[
    "challengeresponseauthentication",
    "ignorerhosts",
    "logverbose",
    "requiredrsasize",
    "rsaminsize",
    "skeyauthentication",
    "subsystem",
];

/// Whether `keyword_lower` (already ASCII-lowercased by the caller) is permitted
/// inside a `Match` block for `target`. Mirrors [`registry::is_known`]: a base set
/// honored on every version, plus the 9.9p1 additions for rhel9/rhel10. With no
/// `--target` the most-permissive 9.9p1 union is used (OWNER DECISION #267=A), so
/// E04 leans false-negative rather than false-positive on the newest dialect.
fn e04_match_permitted(keyword_lower: &str, target: Option<crate::lints::TargetVersion>) -> bool {
    use crate::lints::TargetVersion;
    if E04_PERMITTED_BASE.contains(&keyword_lower) {
        return true;
    }
    match target {
        // 8.0p1: only the base set is Match-permitted (subsystem etc. are
        // SSHCFG_GLOBAL there and must still fire E04).
        Some(TargetVersion::Rhel8) => false,
        // 9.9p1 (rhel9/rhel10) and the no-target union both honor the additions.
        Some(TargetVersion::Rhel9 | TargetVersion::Rhel10) | None => {
            E04_PERMITTED_ADDED_9_9P1.contains(&keyword_lower)
        }
    }
}

/// sshd-E01: unknown directive (keyword not recognized for the target OpenSSH
/// version). The per-version valid-keyword table and its live-daemon grounding
/// live in [`crate::lints::registry`].
///
/// Every directive in the file is checked - the global block AND each `Match`
/// body - because an unrecognized keyword is invalid anywhere. With no `--target`
/// the union of all supported versions is used, so only a keyword unknown to
/// every supported RHEL is flagged. Recognized-but-deprecated keywords are NOT
/// E01 (they are sshd-W04, #243); the registry treats them as known.
#[must_use]
pub fn e01(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            let keyword = directive.keyword_lower();
            let known = match ctx.target {
                Some(target) => registry::is_known(&keyword, target),
                None => registry::is_known_any(&keyword),
            };
            if !known {
                diags.push(anchored(
                    Severity::Error,
                    "sshd-E01",
                    directive.span.clone(),
                    format!(
                        "unknown directive '{}': not a recognized sshd_config keyword for the target OpenSSH version",
                        directive.keyword
                    ),
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

/// sshd-E02: duplicate directive (sshd's first-value-wins silently shadows the
/// later line for most keywords).
///
/// Checked in the global block AND, independently, within each Match block: each
/// scope is its own first-value-wins namespace. So a global directive overridden
/// inside a Match block is NOT a duplicate (that override is the intended
/// mechanism), and the same keyword repeated across two DIFFERENT Match blocks is
/// left to #302 (it needs Match-criteria overlap analysis to avoid false
/// positives on the normal non-overlapping pattern).
#[must_use]
pub fn e02(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        e02_scan_scope(directives, file, &mut diags);
    }
    diags
}

/// Flag first-value-wins duplicates within a SINGLE directive scope (the global
/// block or one Match body). A fresh `seen` set per call keeps each scope
/// independent, so a duplicate never crosses a scope boundary.
fn e02_scan_scope(directives: &[Directive], file: &Path, diags: &mut Vec<Diagnostic>) {
    let mut seen: HashSet<String> = HashSet::new();
    for directive in directives {
        let keyword = directive.keyword_lower();
        if E02_ALLOW_REPEAT.contains(&keyword.as_str()) {
            // Accumulates (unions) across lines: a repeat is legitimate, not a shadow.
            continue;
        }
        let Some(dedup_key) = e02_dedup_key(&keyword, directive) else {
            // A malformed `Subsystem` with no name carries no value to shadow.
            continue;
        };
        // `insert` returns false when the key was already present, i.e. this line
        // is the duplicate that sshd silently ignores (first value wins).
        if !seen.insert(dedup_key) {
            diags.push(anchored(
                Severity::Error,
                "sshd-E02",
                directive.span.clone(),
                format!(
                    "duplicate directive '{}': sshd uses the first value, so this line is silently ignored",
                    directive.keyword
                ),
                file,
                directive.line,
            ));
        }
    }
}

/// The key that decides whether a global directive is a first-value-wins
/// duplicate. Most keywords key on the keyword alone. `Subsystem` is the one
/// exception: it accumulates across DIFFERENT subsystem names but is
/// first-value-wins for the SAME name (verified via `sshd -T`), so it keys on
/// `subsystem` plus the name (its first, case-sensitive argument). Returns `None`
/// for a `Subsystem` line with no name (nothing to shadow).
fn e02_dedup_key(keyword: &str, directive: &Directive) -> Option<String> {
    if keyword == "subsystem" {
        let name = directive.args.first()?;
        // NUL separates the keyword from the name: it cannot appear in a parsed
        // keyword or argument, so the key cannot collide with a plain keyword.
        Some(format!("subsystem\u{0}{name}"))
    } else {
        Some(keyword.to_string())
    }
}

/// sshd-E03: `Include` references a path or glob that resolves to nothing.
///
/// TODO(#149, Wave A): resolves the literal `Include` argument against
/// `/etc/ssh/` (or the config's directory) and checks the glob matches.
#[must_use]
pub fn e03(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    // Relative includes resolve against the directory of the file being linted,
    // which equals sshd's "/etc/ssh" rule for the real /etc/ssh/sshd_config.
    let base_dir = include_base_dir(file);

    let mut diags = Vec::new();
    for block in blocks {
        // Include directives may appear in the global block AND inside Match blocks.
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            if !directive.keyword.eq_ignore_ascii_case("include") {
                continue;
            }
            // One Include line may carry several patterns; flag each that resolves
            // to nothing. sshd silently ignores a broken Include, so this surfaces
            // otherwise-invisible config drift.
            for pattern in &directive.args {
                if !include_pattern_resolves(&base_dir, pattern) {
                    diags.push(anchored(
                        Severity::Error,
                        "sshd-E03",
                        directive.span.clone(),
                        format!("Include '{pattern}' resolves to no files"),
                        file,
                        directive.line,
                    ));
                }
            }
        }
    }
    diags
}

/// The directory a relative `Include` resolves against: the linted file's parent,
/// or the current directory when the path has no parent component.
fn include_base_dir(file: &Path) -> PathBuf {
    match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Whether an `Include` pattern resolves to at least one existing FILE, applying
/// the operator-chosen "skip benign empty-glob" rule: a glob whose directory
/// exists but currently matches no files is treated as resolved (the stock
/// `Include /etc/ssh/sshd_config.d/*.conf` on a system with no drop-ins).
///
/// sshd includes configuration FILES, not directories: an `Include` that resolves
/// only to a directory loads nothing (verified with `sshd -T`), so a match must be
/// a regular file (`is_file` follows symlinks) to count as resolved.
fn include_pattern_resolves(base_dir: &Path, pattern: &str) -> bool {
    let resolved = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base_dir.join(pattern)
    };

    // `glob` resolves a literal path (no metacharacters) and a wildcard pattern
    // uniformly, yielding only paths that exist on disk.
    let Ok(matches) = glob::glob(&resolved.to_string_lossy()) else {
        // An unparseable glob pattern is not E03's concern; do not flag it.
        return true;
    };
    // `flatten` deliberately skips per-entry `GlobError`s (e.g. an unreadable
    // directory during the walk): an I/O hiccup mid-walk must not manufacture an
    // E03 finding for a config that may be perfectly valid.
    if matches.flatten().any(|p| p.is_file()) {
        return true;
    }

    // No file matched. A literal path is simply missing/not-a-file (a finding). A
    // glob is benign only when the directory it expands within exists.
    if has_glob_metacharacters(pattern) {
        glob_is_benign_empty(&resolved)
    } else {
        false
    }
}

/// Whether a pattern contains a glob(7) metacharacter (`*`, `?`, or `[`).
fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

/// Whether a zero-match glob is the benign "directory present, no files yet" case
/// rather than drift. True only for a trailing-filename glob (`<dir>/<glob>`)
/// whose containing directory exists. A glob in a parent component (`sub*/x.conf`)
/// has no single literal containing directory, so a zero match there is treated as
/// a finding (the intended directory structure did not expand to anything).
fn glob_is_benign_empty(resolved: &Path) -> bool {
    let Some(parent) = resolved.parent() else {
        return false;
    };
    if has_glob_metacharacters(&parent.to_string_lossy()) {
        return false;
    }
    parent.is_dir()
}

/// sshd-E04: a directive not permitted inside a `Match` block (silently ignored
/// by sshd at runtime).
///
/// Only keywords that ARE recognized by the TARGET sshd version (or by ANY version
/// if no target is set) are checked against the Match-permitted set. A
/// truly-unknown keyword inside a Match block is sshd-E01's sole responsibility:
/// the daemon REJECTS it outright rather than silently ignoring it, so the
/// "silently ignored at runtime" message would be incorrect. Skipping unknown
/// keywords here prevents the double-fire. When a target version is specified,
/// we use `is_known(keyword, target)` to check version-awareness; when no target
/// is given, we use `is_known_any` to check against the union of all versions.
#[must_use]
pub fn e04(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let Block::Match(match_block) = block else {
            // E04 only inspects Match bodies; the global block has no restriction.
            continue;
        };
        if super::is_unconditional_match_all(match_block) {
            // `Match all` is always active -- its body IS global context, not a
            // conditional Match, so no directive in it is "illegal in a Match
            // block". The global-only directives there are valid. (issue #336)
            continue;
        }
        for directive in &match_block.body {
            let keyword = directive.keyword_lower();
            // Skip keywords that are unknown to the target sshd version (or to any
            // version if no target): those belong exclusively to sshd-E01 (daemon
            // rejects them, does not silently ignore them). Only known-but-not-
            // Match-permitted keywords warrant an E04 diagnostic.
            let is_known = match ctx.target {
                Some(target) => registry::is_known(&keyword, target),
                None => registry::is_known_any(&keyword),
            };
            if !is_known {
                continue;
            }
            if !e04_match_permitted(&keyword, ctx.target) {
                diags.push(anchored(
                    Severity::Error,
                    "sshd-E04",
                    directive.span.clone(),
                    format!(
                        "directive '{}' is not permitted inside a Match block and is silently ignored at runtime",
                        directive.keyword
                    ),
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

/// sshd-W05: a `Match` block overrides a required global directive in a more
/// permissive direction (a STIG escape hatch).
///
/// Fires once per Match-body directive whose value fails the W02 STIG baseline
/// for the given target. Does NOT fire for the global block (that is W02's job).
///
/// Only directives the daemon actually HONORS inside a `Match` block are
/// evaluated (gated on [`e04_match_permitted`]). A STIG-controlled directive
/// that sshd rejects in a Match block (e.g. `StrictModes`, `PermitUserEnvironment`
/// -- `sshd -t` exits 255 with "not allowed within a Match block") is a sshd-E04
/// finding, not a W05 one: it never takes effect, so calling it "a more permissive
/// value" would be wrong. Skipping those here avoids a contradictory double-fire
/// alongside E04.
#[must_use]
pub fn w05(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    use crate::lints::stig::{BaselineCheck, baseline_check};

    let mut diags = Vec::new();
    for block in blocks {
        let Block::Match(match_block) = block else {
            continue;
        };
        if super::is_unconditional_match_all(match_block) {
            // `Match all` is global context, not a conditional override; a weak
            // value there is a global sshd-W02 finding, not a W05 escape hatch.
            // (issue #336)
            continue;
        }
        for directive in &match_block.body {
            let kw = directive.keyword_lower();
            // A Match-illegal directive never takes effect inside the block, so
            // it cannot be a "more permissive override"; that is E04's finding.
            if !e04_match_permitted(&kw, ctx.target) {
                continue;
            }
            if let BaselineCheck::Violation {
                requirement,
                displayed_value,
            } = baseline_check(&kw, &directive.args, ctx.target)
            {
                diags.push(anchored(
                    Severity::Warning,
                    "sshd-W05",
                    directive.span.clone(),
                    format!(
                        "Match block sets STIG-controlled directive '{}' to '{displayed_value}', \
                         a more permissive value; STIG baseline requires {requirement}",
                        directive.keyword,
                    ),
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

#[cfg(test)]
mod e03_helper_tests {
    //! Unit tests for the E03 filesystem helpers (the path/glob cases that need
    //! real directory state live in `tests/test_lints_e03_include.rs`).

    use super::{glob_is_benign_empty, include_base_dir};
    use std::path::{Path, PathBuf};

    #[test]
    fn base_dir_is_the_parent_directory() {
        assert_eq!(
            include_base_dir(Path::new("/etc/ssh/sshd_config")),
            PathBuf::from("/etc/ssh")
        );
    }

    #[test]
    fn base_dir_falls_back_to_dot_for_a_bare_filename() {
        // A path with no directory component (parent is the empty string) must
        // resolve relative includes against ".", not "".
        assert_eq!(
            include_base_dir(Path::new("sshd_config")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn benign_empty_is_true_only_for_a_trailing_glob_over_an_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("dropin.d");
        std::fs::create_dir(&existing).unwrap();
        // Trailing-filename glob over an existing directory: benign.
        assert!(glob_is_benign_empty(&existing.join("*.conf")));
        // Trailing glob over a missing directory: not benign (a finding).
        assert!(!glob_is_benign_empty(&dir.path().join("missing.d/*.conf")));
        // Glob in a parent component: never benign (no single literal dir).
        assert!(!glob_is_benign_empty(&dir.path().join("sub*/x.conf")));
    }
}

#[cfg(test)]
mod e04_tests {
    //! sshd-E04: a directive not permitted inside a `Match` block.
    //!
    //! # Grounding (`sshd_config(5)`, OpenSSH 10.2p1)
    //! "Only a subset of keywords may be used on the lines following a Match
    //! keyword. Available keywords are `AcceptEnv`, ... `X11UseLocalhost`." A
    //! directive whose keyword is outside that set is silently ignored by sshd
    //! at runtime. Wave A uses the 10.2p1 superset list (the Match-allowed set
    //! only grows across OpenSSH releases, so the superset flags only keywords
    //! illegal in every version: false-negative-leaning = safe for a linter).

    use super::e04;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, TargetVersion};
    use rulesteward_core::Diagnostic;
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str) -> Vec<Diagnostic> {
        e04(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
    }

    fn run_with_target(src: &str, target: TargetVersion) -> Vec<Diagnostic> {
        e04(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext {
                target: Some(target),
                single_file: true,
            },
        )
    }

    #[test]
    fn flags_directive_not_permitted_in_match() {
        // Ciphers is global-only; inside Match it is silently ignored.
        let diags = run("Match User bob\n    Ciphers aes256-ctr\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E04");
        assert_eq!(diags[0].line, 2, "flagged at the offending directive line");
    }

    #[test]
    fn permitted_directives_in_match_are_clean() {
        let src = "Match User bob\n    PasswordAuthentication no\n    X11Forwarding no\n    Banner /etc/issue.net\n    ForceCommand internal-sftp\n";
        assert!(
            run(src).is_empty(),
            "all four are in the Match-permitted set"
        );
    }

    #[test]
    fn keyword_match_is_case_insensitive() {
        let diags = run("Match User bob\n    ciphers aes256-ctr\n");
        assert_eq!(diags.len(), 1, "lowercased lookup still flags");
    }

    #[test]
    fn global_block_is_not_checked() {
        // Ciphers is perfectly legal in the global block; E04 only inspects Match.
        assert!(run("Ciphers aes256-ctr\n").is_empty());
    }

    // --- issue #336: unconditional `Match all` is GLOBAL context, not conditional ---

    #[test]
    fn unconditional_match_all_is_global_context_no_e04() {
        // `Match all` is always active, so its body IS global context. A global-only
        // directive (Ciphers) there is valid and must NOT fire E04 (issue #336).
        assert!(
            run("Match all\n    Ciphers aes256-ctr\n").is_empty(),
            "Ciphers under unconditional `Match all` is global context; E04 must not fire"
        );
    }

    #[test]
    fn match_all_keyword_is_case_insensitive_for_e04_skip() {
        // The `all` criterion is case-insensitive; `Match All` is still the
        // unconditional global block and must be skipped by E04.
        assert!(
            run("Match All\n    Ciphers aes256-ctr\n").is_empty(),
            "`Match All` (capitalized) is the unconditional global context; E04 must not fire"
        );
    }

    #[test]
    fn conditional_match_still_fires_e04_after_match_all_fix() {
        // Regression guard: a GENUINE conditional Match still flags a global-only
        // directive. The `Match all` skip must not over-suppress conditional Matches.
        let diags = run("Match User bob\n    Ciphers aes256-ctr\n");
        assert_eq!(diags.len(), 1, "conditional Match must still fire E04");
        assert_eq!(diags[0].code, "sshd-E04");
    }

    #[test]
    fn match_all_with_extra_criterion_is_conditional_fires_e04() {
        // `all` combined with another criterion is connection-conditional (two
        // criteria), NOT the unconditional `Match all`, so E04 still applies.
        let diags = run("Match all User bob\n    Ciphers aes256-ctr\n");
        assert_eq!(
            diags.len(),
            1,
            "`Match all User bob` has two criteria (conditional); E04 still fires"
        );
        assert_eq!(diags[0].code, "sshd-E04");
    }

    #[test]
    fn match_all_with_equals_glued_token_is_not_unconditional() {
        // `Match all=` is NOT the unconditional `Match all`: real sshd rejects
        // `all=` as an unsupported Match attribute (servconf.c `match_cfg_line`,
        // rc 255). The tolerant parser yields a single criterion whose value is the
        // empty string (`{keyword:"all", values:[""]}`); the NON-empty value marks
        // it as NOT the valueless `all`, so it stays conditional and E04 still fires
        // on the Match-illegal `Ciphers` directive. (issue #336 adversarial finding)
        let diags = run("Match all=\n    Ciphers aes256-ctr\n");
        assert_eq!(
            diags.len(),
            1,
            "`Match all=` is malformed, not unconditional `all`; E04 must still fire"
        );
        assert_eq!(diags[0].code, "sshd-E04");
    }

    #[test]
    fn each_illegal_directive_in_a_match_is_flagged() {
        // RE-GROUNDED for #267 (per-version E04 Match-permitted sets).
        //
        // The OLD assertion expected Ciphers(2), ListenAddress(3), AND Subsystem(4)
        // to fire at no-target. That is WRONG under the corrected per-version model:
        // `Subsystem` is SSHCFG_ALL (Match-permitted) on OpenSSH 9.x, and the
        // no-target oracle is the most-permissive 9.9p1 union (OWNER DECISION #267=A),
        // so `Subsystem` inside a Match is HONORED at runtime on 9/10 and must NOT
        // fire E04 at no-target.
        //   Source: depth-sshd-sets.md FINDING 1 (servconf.c V_9_9_P1 SSHCFG_ALL
        //   flags; non-activating-Match + `sshd -t` per VM, 2026-06-17): subsystem
        //   = GLOBALONLY on 8.0p1, MATCH_OK on 9.9p1/el9 + el10.
        //
        // Ciphers and ListenAddress are global-only on EVERY version (not in any
        // per-version Match-permitted set), so they still fire on every line.
        let src = "Match User bob\n    Ciphers aes256-ctr\n    ListenAddress 0.0.0.0\n    Subsystem sftp /x\n";
        // No --target -> 9.9p1 union: Subsystem is Match-permitted, so only the two
        // genuinely-global-only directives fire.
        let lines: Vec<usize> = run(src).iter().map(|d| d.line).collect();
        assert_eq!(
            lines,
            vec![2, 3],
            "at no-target (9.9p1 union), Ciphers + ListenAddress fire but Subsystem \
             is Match-permitted on 9.x and must NOT fire; got lines {lines:?}"
        );
        // --target rhel8 (OpenSSH 8.0p1): Subsystem is SSHCFG_GLOBAL there, so all
        // three illegal lines fire.
        let lines8: Vec<usize> = run_with_target(src, TargetVersion::Rhel8)
            .iter()
            .map(|d| d.line)
            .collect();
        assert_eq!(
            lines8,
            vec![2, 3, 4],
            "with --target rhel8 (8.0p1), Subsystem is global-only and DOES fire E04, \
             so all three illegal lines are flagged; got lines {lines8:?}"
        );
    }

    #[test]
    fn illegal_directive_in_a_later_match_block_is_flagged() {
        let src = "Match User alice\n    PasswordAuthentication no\nMatch User bob\n    Ciphers aes256-ctr\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "every Match block is inspected, not just the first"
        );
        assert_eq!(diags[0].line, 4);
    }

    #[test]
    fn include_is_permitted_inside_match() {
        // Include is in the Match-permitted list (conditional inclusion).
        assert!(run("Match User bob\n    Include /etc/ssh/x.conf\n").is_empty());
    }

    // ----- double-fire tests (the sshd-E04 + sshd-E01 interaction) -----
    //
    // A keyword that is truly unknown (not recognized by any supported sshd) inside
    // a Match block belongs to sshd-E01, not sshd-E04. sshd-E04's message is
    // "silently ignored at runtime" - but a truly-unknown keyword is NOT silently
    // ignored; the daemon REJECTS it. The locked fix (option a): e04() must call
    // registry::is_known_any and skip any keyword that returns false.

    #[test]
    fn unknown_keyword_in_match_does_not_fire_e04() {
        // ZZBogus is not recognized by any supported sshd version (is_known_any ->
        // false). It is NOT in E04_MATCH_PERMITTED either, so without the fix e04()
        // fires sshd-E04 for it (double-fire with sshd-E01). After the fix, e04()
        // must return EMPTY for this config because the unknown keyword is E01's
        // sole responsibility.
        //
        // RED before fix: e04() currently emits sshd-E04 -> len() == 1, not 0.
        let diags = run("Match User bob\n    ZZBogus yes\n");
        assert!(
            diags.is_empty(),
            "a truly-unknown keyword inside Match belongs to sshd-E01, not sshd-E04; \
             got {diags:?}"
        );
    }

    #[test]
    fn multiple_distinct_unknown_keywords_in_match_do_not_fire_e04() {
        // Parametrized over several distinct truly-unknown keyword tokens (none are in
        // sshd's keyword table for any supported version, so is_known_any -> false for
        // each). This list is ILLUSTRATIVE and OPEN-ENDED: the correct impl must route
        // EVERY registry-unknown keyword to E01 via `!is_known_any(&keyword)`, so a
        // hardcoded skip-list of these specific literals (a 1- OR N-element
        // `["zzbogus", "foobarbaz", ...].contains(...)`) is NOT a valid implementation
        // and would mis-handle any other unknown keyword an operator writes.
        //
        // After the fix, e04() must return EMPTY for every one of these configs.
        // RED before fix: e04() emits sshd-E04 for each unknown -> len() == 1.
        let unknown_tokens = [
            "FooBarBaz",
            "NotAKeyword",
            "Wibble",
            "QuuxNotReal",
            "GribbleFrotz",
            "XyzzyPlugh",
        ];
        for kw in unknown_tokens {
            let src = format!("Match User bob\n    {kw} yes\n");
            let diags = run(&src);
            assert!(
                diags.is_empty(),
                "truly-unknown keyword '{kw}' inside Match must NOT produce sshd-E04 \
                 (belongs to sshd-E01); got {diags:?}"
            );
        }
    }

    #[test]
    fn multiple_unknown_keywords_via_full_dispatcher_get_e01_not_e04() {
        // Full-dispatcher variant: with all lints running, each unknown keyword inside
        // a Match block must yield EXACTLY sshd-E01 (from e01()) and NO sshd-E04.
        // Tested against distinct out-of-the-other-fixture tokens to defeat both a
        // single-literal AND an N-element hardcoded skip-list (the impl must do a real
        // is_known_any lookup, which generalizes to any unknown keyword).
        //
        // RED before fix: the dispatcher emits both sshd-E01 AND sshd-E04 for each.
        let unknown_tokens = ["ZorbleQuux", "FloopDingle", "Wibble"];
        for kw in unknown_tokens {
            let src = format!("Match User bob\n    {kw} yes\n");
            let blocks =
                crate::parser::parse_config_str_located(&src, Path::new("/etc/ssh/sshd_config"))
                    .expect("fixture parses");
            let ctx = SshdLintContext::default();
            let diags = crate::lints::lint(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);

            let has_e01 = diags.iter().any(|d| d.code == "sshd-E01");
            let has_e04 = diags.iter().any(|d| d.code == "sshd-E04");
            assert!(
                has_e01,
                "sshd-E01 must fire for unknown keyword '{kw}' inside Match; got {diags:?}"
            );
            assert!(
                !has_e04,
                "sshd-E04 must NOT fire for unknown keyword '{kw}' inside Match; got {diags:?}"
            );
        }
    }

    #[test]
    fn requiredrsasize_in_match_is_match_permitted_at_no_target_so_neither_e04_nor_e01() {
        // RE-GROUNDED for #267 (per-version E04 Match-permitted sets).
        //
        // The OLD assertion expected RequiredRSASize inside a Match to fire exactly
        // one sshd-E04 at no-target. That is WRONG: FINDING 1 shows RequiredRSASize
        // is SSHCFG_ALL (Match-permitted) on OpenSSH 9.9p1, and the no-target oracle
        // is the most-permissive 9.9p1 union (OWNER DECISION #267=A). So at no-target
        // the daemon HONORS RequiredRSASize inside a Match; E04's "silently ignored
        // at runtime" message would be a false positive.
        //   Source: depth-sshd-sets.md FINDING 1 (servconf.c V_9_9_P1 SSHCFG_ALL;
        //   non-activating-Match + `sshd -t` on Rocky 9/10, 2026-06-17). On 8.0p1 the
        //   keyword is UNKNOWN entirely (it is an ADDED_RHEL9 keyword).
        //
        // Correct no-target routing: RequiredRSASize is known (in the 9.9p1 union)
        // AND Match-permitted on 9.x, so NEITHER e04() NOR e01() fires.
        let src = "Match User bob\n    RequiredRSASize 2048\n";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "RequiredRSASize is Match-permitted on 9.9p1 (the no-target union), so it \
             must NOT fire sshd-E04; got {diags:?}"
        );
        // Via the full dispatcher at no-target: neither E04 (Match-permitted) nor E01
        // (known in the union) may fire.
        let blocks =
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses");
        let ctx = SshdLintContext::default();
        let all_diags = crate::lints::lint(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        let has_e01 = all_diags.iter().any(|d| d.code == "sshd-E01");
        let has_e04 = all_diags.iter().any(|d| d.code == "sshd-E04");
        assert!(
            !has_e04,
            "RequiredRSASize is Match-permitted on the 9.9p1 union, so sshd-E04 must \
             NOT fire at no-target; got {all_diags:?}"
        );
        assert!(
            !has_e01,
            "RequiredRSASize is known in the no-target union, so sshd-E01 must NOT \
             fire; got {all_diags:?}"
        );
    }

    #[test]
    fn requiredrsasize_in_match_does_not_fire_e04_on_rhel9_or_rhel10() {
        // Per-version precision: RequiredRSASize is SSHCFG_ALL (Match-permitted) on
        // OpenSSH 9.9p1, which both rhel9 and rhel10 ship. Under --target rhel9 /
        // rhel10 it must NOT fire E04 (the daemon honors it inside a Match).
        //   Source: depth-sshd-sets.md FINDING 1 (rocky9/rocky10 = MATCH_OK).
        let src = "Match User bob\n    RequiredRSASize 2048\n";
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target(src, target);
            assert!(
                diags.is_empty(),
                "RequiredRSASize is Match-permitted on 9.9p1, so --target {target:?} \
                 must NOT fire sshd-E04; got {diags:?}"
            );
        }
    }

    #[test]
    fn unknown_keyword_in_match_fires_e01_not_e04_via_full_dispatcher() {
        // Full dispatcher test: with both e01() and e04() running, the combined
        // output for an unknown keyword inside a Match block must contain exactly
        // one diagnostic, code sshd-E01, and must NOT contain sshd-E04.
        //
        // RED before fix: currently the dispatcher emits both sshd-E01 (correct)
        // AND sshd-E04 (wrong double-fire), so the `no E04` assertion below fails.
        let src = "Match User bob\n    ZZBogus yes\n";
        let blocks =
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses");
        let ctx = SshdLintContext::default();
        let diags = crate::lints::lint(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);

        let has_e01 = diags.iter().any(|d| d.code == "sshd-E01");
        let has_e04 = diags.iter().any(|d| d.code == "sshd-E04");
        assert!(
            has_e01,
            "sshd-E01 must fire for an unknown keyword inside Match; got {diags:?}"
        );
        assert!(
            !has_e04,
            "sshd-E04 must NOT fire when the keyword is unknown to every sshd version; \
             got {diags:?}"
        );
    }

    // ----- regression guard (must stay GREEN before and after the fix) -----

    #[test]
    fn known_keyword_not_match_permitted_still_fires_e04() {
        // Ciphers IS recognized by all sshd versions (is_known_any -> true) but is
        // NOT in E04_MATCH_PERMITTED. After the fix, e04() may only skip UNKNOWN
        // keywords; a known-but-not-permitted keyword must still fire sshd-E04.
        //
        // GREEN before fix (existing behaviour); must remain GREEN after fix.
        let diags = run("Match User bob\n    Ciphers aes256-ctr\n");
        assert_eq!(
            diags.len(),
            1,
            "Ciphers is known but not Match-permitted -> sshd-E04"
        );
        assert_eq!(diags[0].code, "sshd-E04");
    }

    #[test]
    fn listenaddress_global_only_keyword_still_fires_e04_on_every_target() {
        // RE-GROUNDED for #267. ListenAddress is SSHCFG_GLOBAL on EVERY OpenSSH
        // version (never in any per-version Match-permitted set), so it must fire
        // exactly one sshd-E04 inside a Match block at no-target AND under every
        // --target. The per-version fix must NOT over-skip a genuinely global-only
        // directive.
        //   Source: ListenAddress is not in any FINDING 1 Match-permitted set; it is
        //   a listener-socket directive, global-only on all versions.
        let src = "Match User bob\n    ListenAddress 0.0.0.0\n";
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target(src, t),
                None => run(src),
            };
            assert_eq!(
                diags.len(),
                1,
                "ListenAddress is global-only on all versions -> exactly one sshd-E04 \
                 for target {target:?}; got {diags:?}"
            );
            assert_eq!(
                diags[0].code, "sshd-E04",
                "wrong code for target {target:?}"
            );
        }
    }

    #[test]
    fn subsystem_in_match_fires_e04_only_on_rhel8() {
        // RE-GROUNDED for #267. The OLD assertion treated Subsystem as a
        // global-only directive that always fires E04. That is WRONG: Subsystem
        // changed flag across versions - SSHCFG_GLOBAL on 8.0p1 (global-only there)
        // but SSHCFG_ALL (Match-permitted) from 9.x onward.
        //   Source: depth-sshd-sets.md FINDING 1 (subsystem: GLOBALONLY on rocky8 /
        //   8.0p1, MATCH_OK on rocky9 + rocky10 / 9.9p1; servconf.c flag change).
        //
        // So inside a Match block, Subsystem must fire E04 ONLY under --target rhel8;
        // it must NOT fire at no-target (9.9p1 union) nor under --target rhel9/rhel10.
        let src = "Match User bob\n    Subsystem sftp /usr/libexec/openssh/sftp-server\n";

        // rhel8 (8.0p1): SSHCFG_GLOBAL -> fires exactly one E04.
        let diags8 = run_with_target(src, TargetVersion::Rhel8);
        assert_eq!(
            diags8.len(),
            1,
            "Subsystem is global-only on 8.0p1 -> exactly one sshd-E04 under \
             --target rhel8; got {diags8:?}"
        );
        assert_eq!(diags8[0].code, "sshd-E04");

        // no-target (9.9p1 union) + rhel9 + rhel10: SSHCFG_ALL -> Match-permitted,
        // so NO E04.
        assert!(
            run(src).is_empty(),
            "Subsystem is Match-permitted on the 9.9p1 union -> no E04 at no-target; \
             got {:?}",
            run(src)
        );
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target(src, target);
            assert!(
                diags.is_empty(),
                "Subsystem is Match-permitted on 9.9p1 -> no E04 under --target \
                 {target:?}; got {diags:?}"
            );
        }
    }

    #[test]
    fn ignorerhosts_in_match_fires_e04_only_on_rhel8() {
        // RE-GROUNDED for #267. IgnoreRhosts has the EXACT version-split shape as
        // Subsystem: SSHCFG_GLOBAL on 8.0p1 (global-only there -> fires E04 inside a
        // Match under --target rhel8) but SSHCFG_ALL (Match-permitted) from 9.x.
        //   Source: depth-sshd-sets.md FINDING 1, servconf.c keyword table -
        //   { "ignorerhosts", sIgnoreRhosts, SSHCFG_GLOBAL } at V_8_0_P1 vs
        //   { ..., SSHCFG_ALL } at V_9_9_P1.
        // FINDING 1 originally mis-dismissed this ("ignorerhosts unknown to reg8" is
        // FALSE - it IS in RHEL8_BASE, so the is_known gate does not skip it).
        let src = "Match User bob\n    IgnoreRhosts yes\n";

        // rhel8 (8.0p1): SSHCFG_GLOBAL -> fires exactly one E04.
        let diags8 = run_with_target(src, TargetVersion::Rhel8);
        assert_eq!(
            diags8.len(),
            1,
            "IgnoreRhosts is global-only on 8.0p1 -> exactly one sshd-E04 under \
             --target rhel8; got {diags8:?}"
        );
        assert_eq!(diags8[0].code, "sshd-E04");

        // no-target (9.9p1 union) + rhel9 + rhel10: SSHCFG_ALL -> Match-permitted,
        // so NO E04.
        assert!(
            run(src).is_empty(),
            "IgnoreRhosts is Match-permitted on the 9.9p1 union -> no E04 at \
             no-target; got {:?}",
            run(src)
        );
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target(src, target);
            assert!(
                diags.is_empty(),
                "IgnoreRhosts is Match-permitted on 9.9p1 -> no E04 under --target \
                 {target:?}; got {diags:?}"
            );
        }
    }

    #[test]
    fn gssapidelegatecredentials_in_match_fires_e04_on_rhel10() {
        // GROUNDING-LOCK (no impl change - the impl is already correct here).
        // GSSAPIDelegateCredentials is the lone 9->10 registry addition AND it is
        // SSHCFG_GLOBAL (global-only) on rocky10 9.9p1: confirmed LIVE that `sshd -t`
        // rejects it inside a Match block ("Directive 'GSSAPIDelegateCredentials' is
        // not allowed within a Match block"), while the Subsystem control passes.
        //   Source: live `sshd -t` on rocky10 9.9p1, 2026-06-17.
        // It is known on rhel10 (ADDED_RHEL10) but in neither E04 permitted set, so
        // it must fire exactly one E04 there. On rhel8/rhel9 it is UNKNOWN, so it
        // would route to E01 (not E04); only the rhel10 known-but-global-only case
        // is asserted here. This locks the grounded behavior against regression.
        let diags = run_with_target(
            "Match User bob\n    GSSAPIDelegateCredentials yes\n",
            TargetVersion::Rhel10,
        );
        assert_eq!(
            diags.len(),
            1,
            "GSSAPIDelegateCredentials is known-but-global-only on rhel10 (9.9p1) -> \
             exactly one sshd-E04 inside a Match block; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-E04");
    }

    // ----- #267 per-version Match-permitted set tests (FINDING 1) -----
    //
    // FINDING 1 (depth-sshd-sets.md, servconf.c SSHCFG_ALL flags + live
    // non-activating-Match `sshd -t` per VM, 2026-06-17) corrected 8 false-positive
    // keywords that the flat union E04_MATCH_PERMITTED wrongly flagged inside a
    // Match block. OWNER DECISION #267=A: rebuild E04_MATCH_PERMITTED as PER-version
    // sets mirroring registry.rs; no --target = the most-permissive 9.9p1 union.

    #[test]
    fn rename_alias_keytypes_are_match_permitted_on_every_target() {
        // pubkeyacceptedkeytypes / hostbasedacceptedkeytypes are the pre-8.5 rename
        // aliases; SSHCFG_ALL on ALL versions -> Match-permitted everywhere. They
        // are in RHEL8_BASE (known on every target), so inside a Match block they
        // must NEVER fire E04 - at no-target or under any --target.
        //   Source: FINDING 1 (MATCH_OK rocky8/rocky9/rocky10 for both).
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for kw in ["PubkeyAcceptedKeyTypes", "HostbasedAcceptedKeyTypes"] {
            let src = format!("Match User bob\n    {kw} ssh-ed25519\n");
            for target in contexts {
                let diags = match target {
                    Some(t) => run_with_target(&src, t),
                    None => run(&src),
                };
                assert!(
                    diags.is_empty(),
                    "'{kw}' is Match-permitted on every version (SSHCFG_ALL) -> no E04 \
                     for target {target:?}; got {diags:?}"
                );
            }
        }
    }

    #[test]
    fn gssapienablek5users_in_match_is_match_permitted_on_every_target() {
        // REGRESSION (#356): GSSAPIEnableK5Users is SSHCFG_ALL on BOTH 8.0p1 and
        // 9.9p1, so the daemon honors it inside a Match block on every supported
        // version. It is in RHEL8_BASE (known on every target), so the is_known gate
        // does NOT skip it; it must therefore live in E04_PERMITTED_BASE and NEVER
        // fire E04 inside a Match block - at no-target or under any --target. Before
        // the fix it was absent from both E04 permitted sets, so it false-positived
        // (exit 2) on a config the daemon accepts AND honors.
        //   Source: depth-sshd-sets.md FINDING 1 (GSSAPIEnableK5Users SSHCFG_ALL on
        //   8.0p1 and 9.9p1) + issue #356 live differential, 2026-06-29: `sshd -t`
        //   rc=0; `sshd -T -C user=alice` -> yes, user=bob -> no (Match-scoped and
        //   take-effect) on rocky8 8.0p1 and rocky9 9.9p1.
        let src = "Match User svc\n    GSSAPIEnableK5Users yes\n";
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target(src, t),
                None => run(src),
            };
            assert!(
                diags.is_empty(),
                "GSSAPIEnableK5Users is Match-permitted on every version \
                 (SSHCFG_ALL) -> no sshd-E04 for target {target:?}; got {diags:?}"
            );
        }
    }

    #[test]
    fn logverbose_in_match_is_match_permitted_on_rhel9_rhel10_and_no_target() {
        // logverbose is an ADDED_RHEL9 keyword (unknown on 8.0p1) and is SSHCFG_ALL
        // on 9.9p1 -> Match-permitted on rhel9/rhel10 and the no-target 9.9p1 union.
        // It must NOT fire E04 in those contexts.
        //   Source: FINDING 1 (logverbose: UNKNOWN(8.0), MATCH_OK 9.9p1).
        let src = "Match User bob\n    LogVerbose kex.c:*:1000\n";
        assert!(
            run(src).is_empty(),
            "LogVerbose is Match-permitted on the 9.9p1 union -> no E04 at no-target; \
             got {:?}",
            run(src)
        );
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target(src, target);
            assert!(
                diags.is_empty(),
                "LogVerbose is Match-permitted on 9.9p1 -> no E04 under --target \
                 {target:?}; got {diags:?}"
            );
        }
        // On --target rhel8 LogVerbose is UNKNOWN (ADDED_RHEL9), so it is the daemon-
        // rejected case: E04 must NOT fire (it belongs to E01, "Bad configuration
        // option"). The registry `is_known(kw, Rhel8)` gate handles this.
        assert!(
            run_with_target(src, TargetVersion::Rhel8).is_empty(),
            "LogVerbose is unknown on 8.0p1 -> E04 must NOT fire under --target rhel8 \
             (the daemon rejects it; that is E01's province); got {:?}",
            run_with_target(src, TargetVersion::Rhel8)
        );
    }

    #[test]
    fn challengeresponse_and_skey_in_match_are_match_permitted_on_9_9p1_union() {
        // challengeresponseauthentication and skeyauthentication are in RHEL8_BASE
        // (known on all targets) and SSHCFG_ALL on 9.9p1 -> Match-permitted on the
        // no-target union and under --target rhel9/rhel10. They must NOT fire E04
        // there.
        //   Source: FINDING 1 (both: GLOBALONLY on 8.0p1, MATCH_OK on 9.9p1).
        for kw in ["ChallengeResponseAuthentication", "SKeyAuthentication"] {
            let src = format!("Match User bob\n    {kw} yes\n");
            assert!(
                run(&src).is_empty(),
                "'{kw}' is Match-permitted on the 9.9p1 union -> no E04 at no-target; \
                 got {:?}",
                run(&src)
            );
            for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
                let diags = run_with_target(&src, target);
                assert!(
                    diags.is_empty(),
                    "'{kw}' is Match-permitted on 9.9p1 -> no E04 under --target \
                     {target:?}; got {diags:?}"
                );
            }
        }
    }

    #[test]
    fn challengeresponse_and_skey_in_match_fire_e04_on_rhel8() {
        // On 8.0p1 both challengeresponseauthentication and skeyauthentication are
        // SSHCFG_GLOBAL (global-only) AND known (RHEL8_BASE), so inside a Match block
        // under --target rhel8 the daemon silently ignores them -> exactly one E04.
        //   Source: FINDING 1 (GLOBALONLY on rocky8 / 8.0p1).
        for kw in ["ChallengeResponseAuthentication", "SKeyAuthentication"] {
            let src = format!("Match User bob\n    {kw} yes\n");
            let diags = run_with_target(&src, TargetVersion::Rhel8);
            assert_eq!(
                diags.len(),
                1,
                "'{kw}' is global-only on 8.0p1 -> exactly one sshd-E04 under \
                 --target rhel8; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-E04");
        }
    }

    #[test]
    fn genuinely_unknown_in_match_directive_still_fires_when_not_a_keyword() {
        // Guard against an over-broad permitted set: a keyword that is genuinely
        // global-only on EVERY version (here Ciphers, in RHEL8_BASE on all targets,
        // never SSHCFG_ALL) must still fire exactly one E04 inside a Match block at
        // no-target and under every --target. The per-version rebuild must not turn
        // the permitted set into a catch-all.
        let src = "Match User bob\n    Ciphers aes256-ctr\n";
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target(src, t),
                None => run(src),
            };
            assert_eq!(
                diags.len(),
                1,
                "Ciphers is global-only on every version -> exactly one sshd-E04 for \
                 target {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-E04");
        }
    }

    // ----- target-aware skip oracle tests (the miss-case from the adversarial review) -----
    //
    // The no-target fix above uses `registry::is_known_any` (the RHEL10 union) to
    // decide whether a keyword inside a Match block belongs to E01. That is correct
    // for the no-target case (where e01() also uses the union), but WRONG when a
    // `--target` is set: with `--target rhel8`, `RequiredRSASize` is NOT recognized
    // by OpenSSH 8.0p1 (it is in ADDED_RHEL9), so `is_known_any` returns true (the
    // RHEL10 union includes it) while `is_known("requiredrsasize", Rhel8)` returns
    // false. The daemon REJECTS the keyword on RHEL8, so the correct message is
    // E01's "unknown directive", not E04's "silently ignored at runtime".
    //
    // Grounding: `sshd -t -o 'RequiredRSASize=yes'` on Rocky 8.10 (OpenSSH 8.0p1):
    //   "Bad configuration option: RequiredRSASize" (exit 1)
    // On Rocky 9.8 (OpenSSH 9.9p1): "Value too small" (accepted, exit 0).
    // See rulesteward-docs/sshd-stig-version-grounding.md section 8.
    //
    // The fix must change e04()'s skip oracle from `is_known_any` to a
    // context-aware check: `is_known(keyword, target)` when a target is set, and
    // `is_known_any(keyword)` only when no target. A wrong impl that always uses
    // `is_known_any` passes the no-target tests above but FAILS these target tests.

    #[test]
    fn version_rejected_keyword_in_match_with_target_routes_only_to_e01() {
        // RequiredRSASize is in ADDED_RHEL9: unknown on RHEL 8 (sshd answers "Bad
        // configuration option"), known on RHEL 9/10. Inside a Match block with
        // `--target rhel8`:
        //   - sshd-E01 fires (daemon rejects it on RHEL 8: !is_known(kw, Rhel8)).
        //   - sshd-E04 must NOT fire (daemon does not silently ignore it; it rejects
        //     it entirely, so "silently ignored at runtime" is factually wrong).
        //
        // RED before fix: e04() uses is_known_any, which returns true for
        // RequiredRSASize (known via the RHEL10 superset), so e04() emits sshd-E04
        // even under --target rhel8 -> double-fire.
        // Correct: e04() should use is_known(kw, target) when a target is set; that
        // returns false for RequiredRSASize + Rhel8, so e04() skips it.
        let src = "Match User bob\n    RequiredRSASize 2048\n";
        let diags = run_with_target(src, TargetVersion::Rhel8);
        assert!(
            diags.is_empty(),
            "RequiredRSASize is unknown on RHEL 8 (sshd rejects it): \
             e04 must NOT fire because the keyword belongs to sshd-E01, \
             not the 'silently ignored' category; got {diags:?}"
        );
    }

    #[test]
    fn version_rejected_keyword_in_match_with_target_full_dispatcher_has_e01_not_e04() {
        // Full-dispatcher variant of the above: running both e01() and e04() together
        // with `--target rhel8` on `RequiredRSASize` inside a Match block must yield
        // EXACTLY sshd-E01 and ZERO sshd-E04.
        //
        // This is the primary killing test: it verifies the double-fire the
        // adversarial reviewer observed: `target=rhel8, Match User bob,
        // RequiredRSASize 2048 -> codes = ["sshd-E01", "sshd-E04"]`.
        // Correct: codes = ["sshd-E01"] only.
        //
        // RED before fix: dispatcher emits both sshd-E01 (correct) and sshd-E04
        // (wrong double-fire, because e04 uses is_known_any not is_known(kw, Rhel8)).
        let src = "Match User bob\n    RequiredRSASize 2048\n";
        let blocks =
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses");
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel8),
            single_file: true,
        };
        let diags = crate::lints::lint(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);

        let has_e01 = diags.iter().any(|d| d.code == "sshd-E01");
        let has_e04 = diags.iter().any(|d| d.code == "sshd-E04");
        assert!(
            has_e01,
            "sshd-E01 must fire for RequiredRSASize inside Match with --target rhel8 \
             (daemon answers 'Bad configuration option' on 8.0p1); got {diags:?}"
        );
        assert!(
            !has_e04,
            "sshd-E04 must NOT fire for RequiredRSASize with --target rhel8: \
             the daemon REJECTS the keyword, so 'silently ignored at runtime' is factually \
             wrong; e04 must use is_known(kw, target) not is_known_any; got {diags:?}"
        );
    }

    #[test]
    fn all_added_rhel9_keywords_absent_from_match_permitted_route_only_to_e01_on_rhel8_target() {
        // Parametrized over all ADDED_RHEL9 keywords that are NOT in E04_MATCH_PERMITTED:
        // each is unknown on RHEL 8, so with --target rhel8 inside a Match block they
        // belong exclusively to sshd-E01. e04() must not emit sshd-E04 for any of them.
        //
        // This pins the general rule, not just the RequiredRSASize boundary case:
        // the fix must use is_known(kw, target) for EVERY keyword when a target is set.
        // A hardcoded skip-list of "requiredrsasize" would pass the single keyword test
        // but fail this parametrized sweep.
        //
        // The keywords NOT in E04_MATCH_PERMITTED are the ones that would reach the
        // sshd-E04 emission path IF e04() incorrectly uses is_known_any:
        //   - canonicalmatchuser, gssapiindicators, logverbose, modulifile,
        //     persourcemaxstartups, persourcenetblocksize, persourcepenalties,
        //     persourcepenaltyexemptlist, requiredrsasize, rsaminsize, securitykeyprovider,
        //     sshdsessionpath.
        // (channeltimeout, hostbasedacceptedalgorithms, pamservicename,
        //  pubkeyacceptedalgorithms, pubkeyauthoptions, refuseconnection,
        //  unusedconnectiontimeout are in both ADDED_RHEL9 AND E04_MATCH_PERMITTED, so
        //  they never reach the E04 emission path and are not listed here.)
        //
        // RED before fix: e04() uses is_known_any -> true for every ADDED_RHEL9 keyword
        // -> emits sshd-E04 for each of the non-permitted ones with --target rhel8.
        let rhel9_only_non_permitted = [
            "CanonicalMatchUser",
            "GSSAPIIndicators",
            "LogVerbose",
            "ModuliFile",
            "PerSourceMaxStartups",
            "PerSourceNetblockSize",
            "PerSourcePenalties",
            "PerSourcePenaltyExemptList",
            "RequiredRSASize",
            "RSAMinSize",
            "SecurityKeyProvider",
            "SshdSessionPath",
        ];
        for kw in rhel9_only_non_permitted {
            let src = format!("Match User bob\n    {kw} yes\n");
            let diags = run_with_target(&src, TargetVersion::Rhel8);
            assert!(
                diags.is_empty(),
                "'{kw}' is unknown on RHEL 8 (ADDED_RHEL9, not in E04_MATCH_PERMITTED): \
                 e04 must NOT fire with --target rhel8 because the daemon REJECTS it; \
                 got {diags:?}"
            );
        }
    }
}

#[cfg(test)]
mod e02_tests {
    //! sshd-E02: duplicate directive (first-value-wins shadow), in the global
    //! block and within each Match block (#247).
    //!
    //! # Grounding (`sshd_config(5)`, OpenSSH 10.2p1)
    //! DESCRIPTION: "Unless noted otherwise, for each keyword, the first obtained
    //! value will be used." So a keyword repeated in the global block silently
    //! shadows every later line. The allow-repeat exemptions were confirmed with
    //! an `sshd -T` effective-config differential against OpenSSH 10.2p1:
    //! `Port`/`ListenAddress`/`AcceptEnv`/`HostKey`/`Subsystem` and the
    //! `Allow*`/`Deny*` user/group keywords show BOTH values (accumulate);
    //! `SetEnv`/`PermitRootLogin`/`MaxAuthTries` show only the FIRST (shadow).
    //! `SetEnv` is therefore NOT in the allow-repeat set despite the man page's
    //! "one or more variables" wording (that is one line, not multiple lines).

    use super::e02;
    use crate::ast::Block;
    use crate::lints::SshdLintContext;
    use rulesteward_core::Diagnostic;
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str) -> Vec<Diagnostic> {
        e02(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
    }

    #[test]
    fn flags_duplicate_first_value_wins_keyword() {
        let diags = run("PermitRootLogin no\nPermitRootLogin yes\n");
        assert_eq!(diags.len(), 1, "one shadowed line");
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 2, "the LATER (shadowed) line is flagged");
    }

    #[test]
    fn single_occurrence_is_clean() {
        assert!(run("PermitRootLogin no\n").is_empty());
    }

    #[test]
    fn allow_repeat_keywords_are_not_flagged() {
        // Each verified accumulate via `sshd -T` (or man page, for Include).
        let src = "Port 22\nPort 2222\n\
                   ListenAddress 0.0.0.0\nListenAddress 127.0.0.1\n\
                   HostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key\n\
                   AcceptEnv LANG\nAcceptEnv LC_ALL\n\
                   AllowUsers alice\nAllowUsers bob\n\
                   AllowGroups g1\nAllowGroups g2\n\
                   DenyUsers carol\nDenyUsers dave\n\
                   DenyGroups d1\nDenyGroups d2\n\
                   Include /etc/ssh/a.conf\nInclude /etc/ssh/b.conf\n\
                   Subsystem sftp /a\nSubsystem backup /b\n";
        assert!(
            run(src).is_empty(),
            "allow-repeat keywords accumulate, not shadow"
        );
    }

    #[test]
    fn setenv_is_flagged_because_it_shadows() {
        // `sshd -T` differential: a second SetEnv line is dropped (first wins),
        // so SetEnv is NOT in the allow-repeat set.
        let diags = run("SetEnv FOO=1\nSetEnv BAR=2\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn keyword_match_is_case_insensitive() {
        let diags = run("permitrootlogin no\nPermitRootLogin yes\n");
        assert_eq!(diags.len(), 1, "case-insensitive keyword dedup");
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn three_occurrences_flag_the_two_shadowed_lines() {
        let diags = run("X11Forwarding yes\nX11Forwarding no\nX11Forwarding yes\n");
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![2, 3], "every line after the first is shadowed");
    }

    #[test]
    fn global_and_match_same_keyword_is_not_a_duplicate() {
        // A Match override of a global keyword is the intended mechanism, not a
        // duplicate: each scope (global vs a Match body) dedups independently, so
        // a global directive plus a differing Match value stays clean.
        let src = "PasswordAuthentication yes\nMatch User bob\n    PasswordAuthentication no\n";
        assert!(run(src).is_empty());
    }

    #[test]
    fn duplicate_inside_match_body_is_flagged() {
        // #247: within ONE Match block, first-value-wins shadows the later line,
        // exactly like the global block (live-confirmed on rocky9, OpenSSH 9.9p1).
        let src = "Match User bob\n    PasswordAuthentication yes\n    PasswordAuthentication no\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "the shadowed intra-Match line fires one sshd-E02"
        );
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(
            diags[0].line, 3,
            "the LATER (shadowed) line inside the Match body"
        );
    }

    #[test]
    fn subsystem_repeated_with_the_same_name_is_flagged() {
        // `sshd -T` differential: a second `Subsystem sftp` line is dropped (first
        // value wins per name), so it is a shadow even though Subsystem accumulates
        // across DIFFERENT names.
        let diags = run("Subsystem sftp /a\nSubsystem sftp /b\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn subsystem_with_different_names_is_clean() {
        // Distinct subsystems legitimately accumulate (both appear in `sshd -T`).
        assert!(run("Subsystem sftp /a\nSubsystem backup /b\n").is_empty());
    }

    #[test]
    fn subsystem_name_match_is_case_sensitive() {
        // Subsystem names are case-sensitive arguments: `sftp` and `SFTP` are two
        // different subsystems, not a shadow.
        assert!(run("Subsystem sftp /a\nSubsystem SFTP /b\n").is_empty());
    }

    // ---- #247: intra-Match-block duplicate detection ----

    #[test]
    fn allow_repeat_keyword_inside_match_is_not_flagged() {
        // AcceptEnv accumulates inside a Match body too (live rocky9: both LANG
        // and LC_ALL are retained), so a repeat is legitimate, not a shadow.
        let src = "Match User bob\n    AcceptEnv LANG\n    AcceptEnv LC_ALL\n";
        assert!(
            run(src).is_empty(),
            "allow-repeat keywords accumulate inside a Match body"
        );
    }

    #[test]
    fn subsystem_repeated_same_name_inside_match_is_flagged() {
        // Same name-keyed first-value-wins rule as the global block, applied
        // within a Match body.
        let src = "Match User bob\n    Subsystem sftp /a\n    Subsystem sftp /b\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 3);
    }

    #[test]
    fn subsystem_different_names_inside_match_is_clean() {
        assert!(run("Match User bob\n    Subsystem sftp /a\n    Subsystem backup /b\n").is_empty());
    }

    #[test]
    fn cross_match_block_duplicate_is_not_flagged() {
        // sshd-E02 stays scope-independent BY DESIGN: each Match body is its own
        // first-value-wins namespace, so E02 never reaches across a Match boundary.
        // The cross-Match OVERLAP shadow (the same first-value-wins keyword set in
        // two simultaneously-satisfiable Match blocks) is now sshd-W07's job (#302),
        // a separate advisory pass. This alice/bob fixture has DISJOINT criteria (no
        // single connection is both alice and bob), so it is the normal
        // non-overlapping pattern and stays clean under W07 too -- and E02 leaves it
        // clean here regardless.
        let src = "Match User alice\n    X11Forwarding yes\nMatch User bob\n    X11Forwarding no\n";
        assert!(
            run(src).is_empty(),
            "cross-Match-block duplicates are not an E02 concern (W07 handles the overlapping case)"
        );
    }

    #[test]
    fn match_scope_is_independent_of_global() {
        // The global directive plus the FIRST Match value is the intended override
        // (clean); only the repeat WITHIN the Match body shadows.
        let src = "PasswordAuthentication yes\n\
                   Match User bob\n    PasswordAuthentication no\n    PasswordAuthentication yes\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "only the intra-Match duplicate fires, not the global-vs-Match override"
        );
        assert_eq!(diags[0].line, 4, "the shadowed line inside the Match body");
    }

    #[test]
    fn each_match_block_has_its_own_dedup_scope() {
        // A fresh `seen` set per block: a dup in block A and a dup in block B each
        // fire once.
        let src = "Match User alice\n    X11Forwarding yes\n    X11Forwarding no\n\
                   Match User bob\n    AllowTcpForwarding yes\n    AllowTcpForwarding no\n";
        let diags = run(src);
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![3, 6], "each Match body dedups independently");
    }

    #[test]
    fn nameless_subsystem_inside_match_does_not_poison_named_dup() {
        // A nameless `Subsystem` inside a Match body has no name to key on
        // (`e02_dedup_key` -> None) so it is skipped, and it must not swallow a
        // genuine same-name Subsystem duplicate in the same scope.
        let src = "Match User bob\n    Subsystem\n    Subsystem sftp /a\n    Subsystem sftp /b\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1, "only the genuine same-name dup fires");
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 4);
    }

    #[test]
    fn keyword_dedup_inside_match_is_case_insensitive() {
        // Keyword matching is case-insensitive inside a Match body too.
        let src = "Match User bob\n    permitrootlogin no\n    PermitRootLogin yes\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E02");
        assert_eq!(diags[0].line, 3);
    }
}

#[cfg(test)]
mod e01_tests {
    //! sshd-E01: unknown directive (not a recognized keyword for the `--target`
    //! OpenSSH version).
    //!
    //! # Grounding (live `sshd -t -o "KW=yes"` differential, 2026-06-15)
    //! The authoritative oracle is the daemon: a keyword sshd answers with
    //! "Bad configuration option: KW" is unknown (E01 fires); ANY other response -
    //! accepted, a value error, "Deprecated option", "Unsupported option", or a
    //! platform-unsupported error - means the keyword is RECOGNIZED, so E01 must
    //! NOT fire. Measured on Rocky 8.10 / 9.8 / 10.2 (OpenSSH 8.0p1 / 9.9p1 /
    //! 9.9p1): the valid set is RHEL8 (119) subset of RHEL9 (138) subset of RHEL10
    //! (139), with no removals across versions. The keyword universe is sshd's own
    //! keyword table (extracted from the binary - a superset of upstream
    //! `servconf.c` plus RHEL patches, including keywords the man page drops),
    //! classified by the live daemon. Each boundary keyword below is cited in
    //! `rulesteward-docs/sshd-stig-version-grounding.md`.

    use super::e01;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, TargetVersion};
    use rulesteward_core::{Diagnostic, Severity};
    use std::path::Path;

    const ALL_TARGETS: [Option<TargetVersion>; 4] = [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ];

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str, target: Option<TargetVersion>) -> Vec<Diagnostic> {
        e01(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext {
                target,
                single_file: true,
            },
        )
    }

    #[test]
    fn unknown_keyword_fires_on_every_target() {
        for target in ALL_TARGETS {
            let diags = run("ZZBogusDirective yes\n", target);
            assert_eq!(diags.len(), 1, "unknown keyword fires for {target:?}");
            assert_eq!(diags[0].code, "sshd-E01");
            assert_eq!(diags[0].severity, Severity::Error);
            assert_eq!(diags[0].line, 1);
            assert!(
                diags[0].message.contains("ZZBogusDirective"),
                "message names the offending keyword as written: {}",
                diags[0].message
            );
        }
    }

    #[test]
    fn core_keyword_is_clean_on_every_target() {
        for target in ALL_TARGETS {
            assert!(
                run("PermitRootLogin no\n", target).is_empty(),
                "a core keyword is valid for {target:?}"
            );
        }
    }

    #[test]
    fn quoted_recognized_keyword_does_not_fire_e01() {
        // #388: sshd's keyword tokenizer (strdelim) strips a BALANCED double-quote
        // span, so `"Ciphers"` unquotes to the recognized directive `Ciphers` and
        // LOADS (real sshd -T, OpenSSH 10.2p1: rc 0, `ciphers aes128-cbc`). Before the
        // fix read_keyword kept the quotes, the keyword classified as unknown, and E01
        // fired -- a false positive that ALSO masked the weak-cipher W03 finding.
        // After the fix the keyword resolves to a recognized keyword -> no E01.
        for target in ALL_TARGETS {
            assert!(
                run("\"Ciphers\" aes128-cbc\n", target).is_empty(),
                "a balanced-quoted recognized keyword must not fire E01 for {target:?}"
            );
        }
    }

    #[test]
    fn single_quoted_keyword_is_unknown_e01() {
        // strdelim does NOT strip single quotes: `'Ciphers'` stays literal and is an
        // unknown keyword -> real sshd rc 255 "Bad configuration option: 'Ciphers'".
        // E01 fires (the quotes are NOT part of a recognized directive).
        for target in ALL_TARGETS {
            let diags = run("'Ciphers' aes128-cbc\n", target);
            assert_eq!(
                diags.len(),
                1,
                "single-quoted keyword is unknown for {target:?}"
            );
            assert_eq!(diags[0].code, "sshd-E01");
        }
    }

    #[test]
    fn requiredrsasize_is_unknown_on_rhel8_only() {
        // The sharpest boundary: added in 9.9p1. Probe: "Bad configuration option"
        // on 8.0p1, accepted on 9.9p1. A single-global-keyword-set impl passes every
        // other test but fails this one.
        assert_eq!(
            run("RequiredRSASize 2048\n", Some(TargetVersion::Rhel8)).len(),
            1,
            "RequiredRSASize is unknown on 8.0p1"
        );
        assert!(run("RequiredRSASize 2048\n", Some(TargetVersion::Rhel9)).is_empty());
        assert!(run("RequiredRSASize 2048\n", Some(TargetVersion::Rhel10)).is_empty());
        // No --target uses the union (= RHEL10 superset); valid on 9/10, so clean.
        assert!(run("RequiredRSASize 2048\n", None).is_empty());
    }

    #[test]
    fn gssapidelegatecredentials_is_known_only_on_rhel10() {
        // The lone 9->10 addition. Probe: "Bad configuration option" on 8.0p1 and
        // 9.9p1-el9, accepted on 9.9p1-el10.
        assert_eq!(
            run(
                "GSSAPIDelegateCredentials yes\n",
                Some(TargetVersion::Rhel8)
            )
            .len(),
            1
        );
        assert_eq!(
            run(
                "GSSAPIDelegateCredentials yes\n",
                Some(TargetVersion::Rhel9)
            )
            .len(),
            1
        );
        assert!(
            run(
                "GSSAPIDelegateCredentials yes\n",
                Some(TargetVersion::Rhel10)
            )
            .is_empty()
        );
        assert!(
            run("GSSAPIDelegateCredentials yes\n", None).is_empty(),
            "present in the union via RHEL10"
        );
    }

    #[test]
    fn pubkey_algorithms_rename_is_version_aware() {
        // Modern *Algorithms name (renamed in 8.5): unknown on 8.0p1, valid on 9/10.
        assert_eq!(
            run(
                "PubkeyAcceptedAlgorithms ssh-ed25519\n",
                Some(TargetVersion::Rhel8)
            )
            .len(),
            1,
            "the post-8.5 name is unknown on 8.0p1"
        );
        assert!(
            run(
                "PubkeyAcceptedAlgorithms ssh-ed25519\n",
                Some(TargetVersion::Rhel9)
            )
            .is_empty()
        );
        // The pre-8.5 *KeyTypes alias is still recognized on EVERY version.
        for target in [
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            assert!(
                run("PubkeyAcceptedKeyTypes ssh-ed25519\n", target).is_empty(),
                "the pre-8.5 alias stays valid for {target:?}"
            );
        }
    }

    #[test]
    fn rhel_gssapi_patch_keywords_are_not_flagged() {
        // RHEL carries out-of-tree GSSAPI patches, so these keywords are valid on
        // every RHEL build though absent from upstream OpenSSH - and
        // GSSAPIUseSessionCredCache appears only in the binary, not even the RHEL
        // man page. An upstream-only or man-page-only registry false-positives.
        for kw in [
            "GSSAPIKeyExchange",
            "GSSAPIStoreCredentialsOnRekey",
            "GSSAPIUseSessionCredCache",
        ] {
            for target in ALL_TARGETS {
                assert!(
                    run(&format!("{kw} yes\n"), target).is_empty(),
                    "{kw} is a RHEL GSSAPI-patch keyword on {target:?}"
                );
            }
        }
    }

    #[test]
    fn deprecated_keyword_is_not_e01() {
        // "Deprecated option uselogin" - recognized (sshd -t exits 0). That is
        // sshd-W04's concern (#243), not E01's "unknown directive".
        for target in ALL_TARGETS {
            assert!(
                run("UseLogin yes\n", target).is_empty(),
                "UseLogin is recognized-but-deprecated, not unknown, on {target:?}"
            );
        }
    }

    #[test]
    fn legacy_recognized_keywords_are_not_e01() {
        // Deprecated / compiled-out keywords the daemon still RECOGNIZES (probe:
        // "Deprecated option" or "Unsupported option", never "Bad configuration
        // option"). The man page drops them, but they remain in sshd's keyword
        // table, so E01 must NOT fire - sshd-W04 (#243) handles the deprecated
        // subset. Regression guard: a man-page-only registry omitted all of these.
        let legacy = [
            "AFSTokenPassing",
            "AuthorizedKeysFile2",
            "CheckMail",
            "DSAAuthentication",
            "HostDSAKey",
            "KeepAlive",
            "KerberosTgtPassing",
            "PAMAuthenticationViaKBDInt",
            "ReverseMappingCheck",
            "RhostsAuthentication",
            "SKeyAuthentication",
            "VerifyReverseMapping",
        ];
        for kw in legacy {
            for target in ALL_TARGETS {
                assert!(
                    run(&format!("{kw} yes\n"), target).is_empty(),
                    "{kw} is a recognized legacy keyword, not unknown, on {target:?}"
                );
            }
        }
    }

    #[test]
    fn client_only_gssapi_option_is_unknown() {
        // GSSAPIClientIdentity lives in ssh_config(5); the server daemon answers
        // "Bad configuration option" on every version -> E01.
        for target in ALL_TARGETS {
            assert_eq!(
                run("GSSAPIClientIdentity any\n", target).len(),
                1,
                "client-only option is not an sshd keyword on {target:?}"
            );
        }
    }

    #[test]
    fn unknown_keyword_inside_match_is_flagged() {
        // E01 inspects Match bodies too, not just the global block.
        let diags = run(
            "Match User bob\n    ZZBogusDirective yes\n",
            Some(TargetVersion::Rhel9),
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-E01");
        assert_eq!(
            diags[0].line, 2,
            "flagged at its line inside the Match block"
        );
    }

    #[test]
    fn keyword_match_is_case_insensitive() {
        // Lookup lowercases the keyword, so a valid keyword in any case is clean.
        assert!(run("PERMITROOTLOGIN no\n", Some(TargetVersion::Rhel9)).is_empty());
        assert!(run("permitrootlogin no\n", Some(TargetVersion::Rhel9)).is_empty());
    }

    #[test]
    fn flags_each_unknown_line_at_its_own_location() {
        let src = "PermitRootLogin no\nZZBogusOne x\nMaxAuthTries 3\nZZBogusTwo y\n";
        let lines: Vec<usize> = run(src, Some(TargetVersion::Rhel9))
            .iter()
            .map(|d| d.line)
            .collect();
        assert_eq!(
            lines,
            vec![2, 4],
            "only the two unknown lines, at their lines"
        );
    }

    #[test]
    fn fully_valid_config_is_clean() {
        let src = "Port 22\nPermitRootLogin no\nMaxAuthTries 3\nCiphers aes256-ctr\n\
                   Match User bob\n    PasswordAuthentication no\n";
        assert!(run(src, Some(TargetVersion::Rhel9)).is_empty());
    }
}

// ---------------------------------------------------------------------------
// sshd-W05 tests
// ---------------------------------------------------------------------------
//
// W05 fires when a Match block body directive has
// `baseline_check(keyword_lower, args, target) == BaselineCheck::Violation`.
// This is inherently W01-scoped: `baseline_check` returns `Violation` only for
// W02-controlled STIG directives, which are a subset of the required set.
//
// Firing rule (reading A, DECIDED): independent of whether the global block
// sets the directive -- a Match override that fails the baseline is the escape
// hatch and always fires W05.
//
// Non-STIG directives (e.g. PasswordAuthentication) return `NotControlled` from
// `baseline_check` and must NEVER trigger W05.
//
// Each test MUST be RED against the empty stub (`w05` returns `Vec::new()`).

#[cfg(test)]
mod w05_tests {
    //! sshd-W05: Match block overrides a STIG-required directive in a more
    //! permissive direction (STIG escape hatch).

    use super::w05;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, TargetVersion};
    use rulesteward_core::Diagnostic;
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str) -> Vec<Diagnostic> {
        w05(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
    }

    fn run_with_target(src: &str, target: TargetVersion) -> Vec<Diagnostic> {
        w05(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext {
                target: Some(target),
                single_file: true,
            },
        )
    }

    // --- FIRES: ExactLower("no") baseline violation via PermitRootLogin yes ---
    //
    // PermitRootLogin must be "no" (W02 rule: ExactLower("no"), universal floor).
    // A Match block setting PermitRootLogin yes is a STIG escape hatch -> W05.
    // This is also the canonical example from the task spec.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_permitrootlogin_yes_in_match_rhel9() {
        // Line layout:
        //   1: PermitRootLogin no   (global, compliant -- W05 must NOT see this)
        //   2: Match Group admins
        //   3:     PermitRootLogin yes   (Match body, violates baseline -> W05)
        let src = "PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            1,
            "exactly one W05 for a PermitRootLogin yes in a Match body; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05", "must carry code sshd-W05");
        assert_eq!(
            diags[0].line, 3,
            "diagnostic must anchor at the Match-body directive line (line 3)"
        );
        // Message must name the offending directive and the violating value.
        assert!(
            diags[0].message.contains("PermitRootLogin"),
            "message must name the directive; got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains("yes"),
            "message must name the violating value; got: {}",
            diags[0].message
        );
    }

    // --- issue #336: unconditional `Match all` is NOT a conditional override ---

    #[test]
    fn unconditional_match_all_is_not_a_w05_override() {
        // `Match all` is always-active global context, not a conditional override.
        // A weak STIG value there is a GLOBAL weakness (W02's job), never W05.
        let src = "PermitRootLogin no\nMatch all\n    PermitRootLogin yes\n";
        assert!(
            run_with_target(src, TargetVersion::Rhel9).is_empty(),
            "`Match all` is not a Match override; W05 must not fire"
        );
    }

    #[test]
    fn match_all_case_insensitive_is_not_a_w05_override() {
        // `Match All` (capitalized) is still the unconditional global block.
        let src = "PermitRootLogin no\nMatch All\n    PermitRootLogin yes\n";
        assert!(
            run_with_target(src, TargetVersion::Rhel9).is_empty(),
            "`Match All` is the unconditional global block; W05 must not fire"
        );
    }

    #[test]
    fn conditional_match_still_fires_w05_after_match_all_fix() {
        // Regression guard: a genuine conditional Match override still fires W05.
        let src = "PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(diags.len(), 1, "conditional Match override still fires W05");
        assert_eq!(diags[0].code, "sshd-W05");
    }

    // --- FIRES: NumericCeiling(600) baseline violation via ClientAliveInterval ---
    //
    // ClientAliveInterval must be > 0 and <= 600 (universal floor).
    // A Match block setting ClientAliveInterval 900 exceeds the ceiling -> W05.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_clientaliveinterval_too_large_in_match() {
        // Line layout:
        //   1: ClientAliveInterval 300   (global, compliant)
        //   2: Match Group ops
        //   3:     ClientAliveInterval 900   (exceeds 600 ceiling -> Violation)
        let src = "ClientAliveInterval 300\nMatch Group ops\n    ClientAliveInterval 900\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "exactly one W05 for ClientAliveInterval 900 in a Match body; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(
            diags[0].line, 3,
            "diagnostic must anchor at the Match-body directive line"
        );
        assert!(
            diags[0].message.contains("ClientAliveInterval"),
            "message must name the directive; got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains("900"),
            "message must echo the violating value; got: {}",
            diags[0].message
        );
    }

    // --- FIRES: reading-A semantics -- no global block entry required ---
    //
    // Reading A: W05 fires regardless of whether the global block sets the
    // directive. This test has NO global PermitRootLogin; the Match body alone
    // triggers W05 because the override fails the baseline.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_even_when_global_block_does_not_set_the_directive() {
        // No global PermitRootLogin. Match body sets it to a violating value.
        let src = "Match User root\n    PermitRootLogin yes\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "W05 must fire on the Match body directive regardless of global absence; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 2);
    }

    // --- FIRES: target=None (floor) for a universal STIG directive ---
    //
    // PermitRootLogin is controlled at the floor (RHEL8 required set, which
    // is the floor). W05 must fire even without --target.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_floor_target_none_universal_directive() {
        let src = "PermitRootLogin no\nMatch Group ops\n    PermitRootLogin yes\n";
        // target=None uses the conservative floor (RHEL8 required set)
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "PermitRootLogin is in the floor required set; W05 must fire at target=None; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 3);
    }

    // --- FIRES: multiple Match blocks, only the violating one fires ---
    //
    // First Match block: PermitRootLogin no (compliant, no W05).
    // Second Match block: PermitRootLogin yes (violating, fires W05).
    // Total: exactly one diagnostic on the second block's directive line.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_only_for_the_violating_match_block() {
        // Line layout:
        //   1: Match User alice
        //   2:     PermitRootLogin no        (compliant; no W05)
        //   3: Match Group admins
        //   4:     PermitRootLogin yes       (violating -> W05)
        let src = "Match User alice\n    PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            1,
            "only the violating Match block (line 4) must fire; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(
            diags[0].line, 4,
            "diagnostic must anchor at line 4 (the violating block's directive)"
        );
    }

    // --- FIRES: one diagnostic per violating directive in the same Match block ---
    //
    // Two STIG-controlled directives in the same Match body both violate:
    // PermitRootLogin yes (must be "no") and X11Forwarding yes (must be "no").
    // Each violating directive produces its own W05 diagnostic.
    //
    // The stub returns Vec::new() -> "fires" assertion (len 2) fails RED.
    #[test]
    fn fires_once_per_violating_directive_in_a_single_match() {
        // Line layout:
        //   1: Match Group dev
        //   2:     PermitRootLogin yes    (Violation -> W05)
        //   3:     X11Forwarding yes      (Violation -> W05)
        let src = "Match Group dev\n    PermitRootLogin yes\n    X11Forwarding yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            2,
            "two violating directives in the same Match body yield two W05 diagnostics; \
             got {diags:?}"
        );
        let codes: Vec<&str> = diags.iter().map(|d| &d.code[..]).collect();
        assert!(
            codes.iter().all(|c| *c == "sshd-W05"),
            "all diagnostics must carry code sshd-W05; got {codes:?}"
        );
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert!(
            lines.contains(&2),
            "PermitRootLogin yes must be flagged at line 2; lines = {lines:?}"
        );
        assert!(
            lines.contains(&3),
            "X11Forwarding yes must be flagged at line 3; lines = {lines:?}"
        );
    }

    // --- DOES NOT FIRE: compliant value in Match body (tightening / exact match) ---
    //
    // PermitRootLogin no inside a Match: this IS the required value.
    // baseline_check returns Ok -> no W05.
    #[test]
    fn does_not_fire_for_compliant_value_in_match() {
        let src = "Match Group sftp\n    PermitRootLogin no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PermitRootLogin no is compliant; W05 must not fire; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: tightening a numeric (below ceiling) ---
    //
    // ClientAliveInterval 300 in a Match: the ceiling is 600 and 300 <= 600 -> Ok.
    // W05 must not fire for a value that satisfies the baseline.
    #[test]
    fn does_not_fire_for_numeric_tightening_in_match() {
        let src = "ClientAliveInterval 600\nMatch Group ops\n    ClientAliveInterval 300\n";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "ClientAliveInterval 300 satisfies the <=600 baseline; W05 must not fire; \
             got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: non-STIG directive (PasswordAuthentication) ---
    //
    // #244's example: PasswordAuthentication is NOT in the W02 controlled set.
    // baseline_check("passwordauthentication", ...) returns NotControlled.
    // W05 must not fire even though the Match sets a looser value.
    //
    // This pins the W01-scoped decision: only W02-controlled directives are in scope.
    #[test]
    fn does_not_fire_for_non_stig_directive_in_match() {
        // PasswordAuthentication has no W02 rule; baseline_check -> NotControlled.
        let src = "Match Group sftp\n    PasswordAuthentication yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PasswordAuthentication is not a W02-controlled directive; \
             W05 must not fire (issue #244 example); got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: global block directive (W02's responsibility, not W05) ---
    //
    // A violating directive in the GLOBAL block must produce NO W05 diagnostic.
    // (That is W02's job, tested elsewhere.) W05 is Match-only.
    //
    // This pins the non-double-fire property.
    #[test]
    fn does_not_fire_for_global_block_violation() {
        // Global PermitRootLogin yes is a W02 finding, not W05.
        // No Match blocks -> no Match body to inspect.
        let src = "PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "a violating directive in the global block is a W02 finding, not W05; \
             W05 must return empty for a config with no Match blocks; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: global block has violating value BUT Match body is compliant ---
    //
    // The global block has PermitRootLogin yes (a W02 issue). The Match block sets
    // PermitRootLogin no (compliant). W05 must NOT fire for the Match body.
    #[test]
    fn does_not_fire_when_match_body_is_compliant_even_if_global_violates() {
        // Line layout:
        //   1: PermitRootLogin yes    (W02 concern, not W05)
        //   2: Match Group audit
        //   3:     PermitRootLogin no  (compliant in Match body -> no W05)
        let src = "PermitRootLogin yes\nMatch Group audit\n    PermitRootLogin no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "Match body sets the compliant value; W05 must not fire; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: Compression yes in Match under --target rhel10 ---
    //
    // Compression is a RHEL8/9-only W02 control (RHEL10 V1R1 dropped it).
    // Under --target rhel10, baseline_check("compression", ...) returns
    // NotControlled, so a Match setting Compression yes must NOT fire W05.
    //
    // This pins the target-aware W02 rule propagation through baseline_check.
    #[test]
    fn does_not_fire_for_compression_in_match_under_rhel10() {
        let src = "Compression no\nMatch Group sftp\n    Compression yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel10);
        assert!(
            diags.is_empty(),
            "Compression is not a RHEL10 STIG control (V1R1 dropped it); \
             W05 must not fire under --target rhel10; got {diags:?}"
        );
    }

    // --- Discriminating: trivial "always empty" impl fails the fires tests above.
    //     Trivial "fire on every Match directive" impl fails the no-fire tests above.
    //     Trivial "fire ignoring baseline" impl fails does_not_fire_for_compliant_value.
    //     This test pins an additional discriminating property: the ClientAliveCountMax
    //     exact-1 rule (NumericExact). Zero is NOT a valid value (not > 0); W05 fires.
    //
    //     The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_clientalivecountmax_zero_in_match() {
        // ClientAliveCountMax must be exactly 1 (W02Rule::NumericExact(1)).
        // ClientAliveCountMax 0 fails: parse::<u64>() ok but != 1 -> Violation.
        let src = "ClientAliveCountMax 1\nMatch Group ops\n    ClientAliveCountMax 0\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "ClientAliveCountMax 0 violates the exact-1 STIG rule; W05 must fire; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 3);
        assert!(
            diags[0].message.contains("ClientAliveCountMax"),
            "message must name the directive; got: {}",
            diags[0].message
        );
    }

    // --- DOES NOT FIRE: STIG-controlled but Match-ILLEGAL directive (StrictModes) ---
    //
    // StrictModes is a W02-controlled directive (must be "yes"), so a Match body
    // setting `StrictModes no` is a baseline FAILURE. But sshd does NOT honor
    // StrictModes inside a Match block: `sshd -t` rejects the config with
    // "StrictModes ... not allowed within a Match block" (rc 255, verified on
    // live rocky9 OpenSSH 9.9p1). The correct finding is sshd-E04 (which already
    // fires); W05 must NOT double-fire with a contradictory "more permissive
    // value" message. W05 only evaluates directives sshd actually honors in a
    // Match block (gated on e04_match_permitted).
    #[test]
    fn does_not_fire_for_match_illegal_strictmodes_floor() {
        // StrictModes no inside a Match: baseline-failing AND Match-illegal.
        let src = "Match Group sftp\n    StrictModes no\n";
        // target=None (floor): StrictModes is a universal W02 control, but it is
        // Match-illegal on every version, so W05 must not fire.
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "StrictModes is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire at target=None; got {diags:?}"
        );
    }

    #[test]
    fn does_not_fire_for_match_illegal_strictmodes_rhel9() {
        let src = "Match Group sftp\n    StrictModes no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "StrictModes is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire under --target rhel9; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: STIG-controlled but Match-ILLEGAL (PermitUserEnvironment) ---
    //
    // PermitUserEnvironment is a W02-controlled directive (must be "no"), so a
    // Match body setting `PermitUserEnvironment yes` is a baseline FAILURE. But
    // sshd does NOT honor it inside a Match block (rejected by `sshd -t`, rc 255,
    // verified on live rocky9 OpenSSH 9.9p1). The correct finding is sshd-E04;
    // W05 must NOT double-fire.
    #[test]
    fn does_not_fire_for_match_illegal_permituserenvironment_floor() {
        let src = "Match User svc\n    PermitUserEnvironment yes\n";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "PermitUserEnvironment is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire at target=None; got {diags:?}"
        );
    }

    #[test]
    fn does_not_fire_for_match_illegal_permituserenvironment_rhel9() {
        let src = "Match User svc\n    PermitUserEnvironment yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PermitUserEnvironment is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire under --target rhel9; got {diags:?}"
        );
    }
}

#[cfg(test)]
mod e04_set_guard_tests {
    //! Golden-snapshot size + membership guards for the E04 Match-permitted sets.
    //!
    //! These tests pin the exact cardinality and key members of
    //! `E04_PERMITTED_BASE` and `E04_PERMITTED_ADDED_9_9P1` so that a silent
    //! addition or removal is immediately caught by CI -- the same pattern the
    //! `registry.rs` `measured_set_sizes` and `grounded_membership_spot_checks`
    //! tests use for the E01 keyword registry.
    //!
    //! Grounding: 2026-06-29 snapshot on Rocky 8.10 / 9.8 / 10.2 (OpenSSH
    //! 8.0p1 / 9.9p1 / 9.9p1). The Match-legality oracle is the daemon's FATAL
    //! MESSAGE for a keyword inside a NON-ACTIVATING Match block: a config file
    //! with `Match User nomatch_zz_user` then `KW yes`, run plain `sshd -t -f
    //! <file>` (no `-o`, no `-C`). "Bad configuration option" = UNKNOWN (E01,
    //! tested first); "...is not allowed within a Match block" = `SSHCFG_GLOBAL`
    //! (in NEITHER set); parses clean = Match-permitted. Do NOT use `-o` (injects
    //! into global context, bypasses the Match) or `-T -C` (folds without the
    //! `SSHCFG_MATCH` filter). See the provenance doc-comments above the constants.
    //!
    //! # How to update
    //! When a keyword is added or removed from either set, update BOTH the set
    //! constant AND the full-membership golden literal below, and re-ground on the
    //! Rocky VMs using the recipe in the provenance doc-comments above the
    //! constants. Failure here means the set has drifted from the pinned snapshot.

    use super::{E04_PERMITTED_ADDED_9_9P1, E04_PERMITTED_BASE};

    /// The complete, sorted `E04_PERMITTED_BASE` membership as of the 2026-06-29
    /// snapshot. A full golden literal (not just a count + spot-checks) is what
    /// catches a count-preserving 1-in/1-out swap: removing one keyword and adding
    /// another in the same sort slot keeps the length, sortedness, and
    /// lowercase-ness intact but silently changes E04 behavior.
    const EXPECTED_BASE: &[&str] = &[
        "acceptenv",
        "allowagentforwarding",
        "allowgroups",
        "allowstreamlocalforwarding",
        "allowtcpforwarding",
        "allowusers",
        "authenticationmethods",
        "authorizedkeyscommand",
        "authorizedkeyscommanduser",
        "authorizedkeysfile",
        "authorizedprincipalscommand",
        "authorizedprincipalscommanduser",
        "authorizedprincipalsfile",
        "banner",
        "casignaturealgorithms",
        "channeltimeout",
        "chrootdirectory",
        "clientalivecountmax",
        "clientaliveinterval",
        "denygroups",
        "denyusers",
        "disableforwarding",
        "exposeauthinfo",
        "forcecommand",
        "gatewayports",
        "gssapiauthentication",
        "gssapienablek5users",
        "hostbasedacceptedalgorithms",
        "hostbasedacceptedkeytypes",
        "hostbasedauthentication",
        "hostbasedusesnamefrompacketonly",
        "include",
        "ipqos",
        "kbdinteractiveauthentication",
        "kerberosauthentication",
        "kerberosusekuserok",
        "loglevel",
        "maxauthtries",
        "maxsessions",
        "pamservicename",
        "passwordauthentication",
        "permitemptypasswords",
        "permitlisten",
        "permitopen",
        "permitrootlogin",
        "permittty",
        "permittunnel",
        "permituserrc",
        "pubkeyacceptedalgorithms",
        "pubkeyacceptedkeytypes",
        "pubkeyauthentication",
        "pubkeyauthoptions",
        "rdomain",
        "refuseconnection",
        "rekeylimit",
        "revokedkeys",
        "setenv",
        "streamlocalbindmask",
        "streamlocalbindunlink",
        "trustedusercakeys",
        "unusedconnectiontimeout",
        "x11displayoffset",
        "x11forwarding",
        "x11maxdisplays",
        "x11uselocalhost",
    ];

    /// The complete, sorted `E04_PERMITTED_ADDED_9_9P1` membership as of the
    /// 2026-06-29 snapshot.
    const EXPECTED_ADDED_9_9P1: &[&str] = &[
        "challengeresponseauthentication",
        "ignorerhosts",
        "logverbose",
        "requiredrsasize",
        "rsaminsize",
        "skeyauthentication",
        "subsystem",
    ];

    #[test]
    fn e04_permitted_base_equals_full_golden_membership() {
        // FULL-ARRAY golden assertion: catches any content drift, including a
        // count-preserving 1-in/1-out swap that a `.len()` + spot-check guard
        // misses (e.g. removing `channeltimeout` and adding `channelfoo` in the
        // same sort slot keeps count=65, sorted, lowercase, unique). The 65
        // members are the 2026-06-29 snapshot grounded on Rocky 8.10/9.8/10.2 via
        // the non-activating-Match fatal-message oracle (see the doc-comment above
        // E04_PERMITTED_BASE). gssapienablek5users is the issue #356/#362 keyword.
        assert_eq!(
            E04_PERMITTED_BASE, EXPECTED_BASE,
            "E04_PERMITTED_BASE drifted from the 2026-06-29 golden snapshot; \
             re-ground on Rocky 8.10/9.8/10.2 (non-activating-Match `sshd -t -f`, \
             NOT `-o`/`-T -C`) and update both the set and EXPECTED_BASE"
        );
    }

    #[test]
    fn e04_permitted_added_9_9p1_equals_full_golden_membership() {
        // FULL-ARRAY golden assertion for the per-version 9.9p1 additions.
        assert_eq!(
            E04_PERMITTED_ADDED_9_9P1, EXPECTED_ADDED_9_9P1,
            "E04_PERMITTED_ADDED_9_9P1 drifted from the 2026-06-29 golden snapshot; \
             re-ground on Rocky 8.10/9.8/10.2 and update both the set and \
             EXPECTED_ADDED_9_9P1"
        );
    }

    #[test]
    fn e04_permitted_set_sizes_are_pinned() {
        // Cardinality pin (a faster-to-read companion to the full golden
        // assertions above). E04_PERMITTED_BASE: 65; E04_PERMITTED_ADDED_9_9P1: 7.
        assert_eq!(
            E04_PERMITTED_BASE.len(),
            65,
            "E04_PERMITTED_BASE size changed from the 2026-06-29 snapshot (65); \
             re-ground on Rocky 8.10/9.8/10.2 and update both the set and this count"
        );
        assert_eq!(
            E04_PERMITTED_ADDED_9_9P1.len(),
            7,
            "E04_PERMITTED_ADDED_9_9P1 size changed from the 2026-06-29 snapshot (7); \
             re-ground on Rocky 8.10/9.8/10.2 and update both the set and this count"
        );
    }

    #[test]
    fn e04_permitted_sets_are_sorted_ascending_and_lowercase() {
        // Both arrays must be sorted (ascending, unique) and all-lowercase for
        // the `slice::contains` search to be correct and for reviewers to verify
        // membership at a glance.
        assert!(
            E04_PERMITTED_BASE.windows(2).all(|w| w[0] < w[1]),
            "E04_PERMITTED_BASE is not sorted and unique ascending"
        );
        assert!(
            E04_PERMITTED_BASE
                .iter()
                .all(|k| !k.is_empty() && !k.contains(|c: char| c.is_ascii_uppercase())),
            "E04_PERMITTED_BASE has an empty or non-lowercase entry"
        );
        assert!(
            E04_PERMITTED_ADDED_9_9P1.windows(2).all(|w| w[0] < w[1]),
            "E04_PERMITTED_ADDED_9_9P1 is not sorted and unique ascending"
        );
        assert!(
            E04_PERMITTED_ADDED_9_9P1
                .iter()
                .all(|k| !k.is_empty() && !k.contains(|c: char| c.is_ascii_uppercase())),
            "E04_PERMITTED_ADDED_9_9P1 has an empty or non-lowercase entry"
        );
    }

    #[test]
    fn e04_base_and_added_are_disjoint() {
        // A keyword in BOTH sets re-introduces the rhel8 over-permit bug: in
        // `e04_match_permitted`, `E04_PERMITTED_BASE.contains` short-circuits and
        // returns true for EVERY target, so a keyword also kept in ADDED (e.g.
        // `subsystem`) would be wrongly Match-permitted under --target rhel8 where
        // it is SSHCFG_GLOBAL and must still fire E04. Mirrors registry.rs's
        // `additions_are_disjoint_from_lower_tiers`.
        for k in E04_PERMITTED_ADDED_9_9P1 {
            assert!(
                !E04_PERMITTED_BASE.contains(k),
                "'{k}' is double-listed in E04_PERMITTED_BASE and \
                 E04_PERMITTED_ADDED_9_9P1; a base entry is Match-permitted on EVERY \
                 target, which would defeat its rhel8-only restriction"
            );
        }
    }
}

#[cfg(test)]
mod w07_tests {
    //! sshd-W07: a first-value-wins keyword set in TWO `Match` blocks whose
    //! criteria can be simultaneously satisfied by one connection. sshd applies
    //! only the FIRST satisfied block's value and silently drops the later one, so
    //! the later (shadowed) instance is a real - if approximate - hardening hazard
    //! (#302, deferred from #247). Severity Warning: criteria-overlap is a static
    //! approximation, so the pass is advisory.
    //!
    //! # Grounding (`sshd_config(5)`; live rocky9 `OpenSSH_9.9p1` differential 2026-06-20)
    //! - Under `Match`: "If a keyword appears in multiple Match blocks that are
    //!   satisfied, only the first instance of the keyword is applied." So two
    //!   simultaneously-satisfied blocks setting the same first-value-wins keyword
    //!   to different values -> the later value is silently dropped (the shadow this
    //!   pass reports; it flags the LATER instance, matching sshd-E02's convention).
    //! - `Match` criteria: "The criteria ... are used only if all of the criteria on
    //!   the line are satisfied." A single connection carries ONE user, its groups,
    //!   one source/local address, and one local port, so it can satisfy two blocks
    //!   at once whenever their criteria are not provably disjoint.
    //! - Overlap is decided per criterion by `sshd_config(5)` pattern semantics:
    //!   comma lists are OR within a criterion; `*`/`?` are wildcards; a leading `!`
    //!   negates, and a pattern-list matches only if some POSITIVE pattern matches
    //!   and no negated pattern matches (OpenSSH `match_pattern_list`), so `!bob,*`
    //!   means "every user except bob"; `Address` accepts CIDR, so a supernet
    //!   contains a host address. Two blocks are flagged only when their criteria
    //!   CAN co-satisfy one connection; provably-disjoint criteria (`User alice` vs
    //!   `User bob`) are the normal, intended pattern and are never flagged - the
    //!   false positive the issue explicitly guards against.
    //!
    //! These tests drive the full dispatcher `lint()` and filter to `sshd-W07`, so
    //! they pin the observable end-to-end contract regardless of which pass emits
    //! it. Every fixture uses same-criterion-TYPE overlaps (or structural cases)
    //! whose overlap/disjointness is decidable from the pattern text alone; the
    //! separate question of CROSS-type overlap (e.g. `User` vs `Group`, which no
    //! static linter can prove or disprove) is intentionally NOT pinned here (see
    //! the lane's open QUESTION for #302).

    use crate::lints::{SshdLintContext, lint};
    use rulesteward_core::{Diagnostic, Severity};
    use std::path::Path;

    /// Parse `src`, run every single-file lint pass with the default (target=None)
    /// context, and keep only the `sshd-W07` diagnostics. Other passes' codes
    /// (e.g. sshd-W01 required-directive on this minimal fixture) are filtered out,
    /// so each assertion pins W07 alone.
    fn w07_diags(src: &str) -> Vec<Diagnostic> {
        let blocks =
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses");
        lint(
            &blocks,
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
        .into_iter()
        .filter(|d| d.code == "sshd-W07")
        .collect()
    }

    // ---- POSITIVE: overlapping same-type criteria + a shared first-value-wins keyword ----

    #[test]
    fn identical_match_criteria_shadow_flags_w07() {
        // Two blocks with IDENTICAL criteria (`User alice`) are trivially
        // co-satisfiable, so the same first-value-wins keyword set to two different
        // values shadows the later line.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User alice\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "exactly one cross-Match shadow");
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn identical_group_criteria_shadow_flags_w07() {
        // Overlap is not User-specific: two identical `Group admins` blocks also
        // co-satisfy (any connection whose user is in admins), so the pass must
        // handle every criterion type uniformly, not just `User`.
        let d = w07_diags(
            "Match Group admins\n    X11Forwarding yes\n\
             Match Group admins\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "identical Group criteria co-satisfy -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn same_type_lists_sharing_a_value_flags_w07() {
        // Comma lists are OR within a criterion. `alice,carol` and `carol,dave`
        // share `carol`, so a carol connection satisfies both blocks.
        let d = w07_diags(
            "Match User alice,carol\n    X11Forwarding yes\n\
             Match User carol,dave\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "intersecting user lists co-satisfy -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn wildcard_user_overlaps_specific_user_flags_w07() {
        // `*` matches any user, so `User *` and `User bob` co-satisfy for a bob
        // connection. A correct impl must expand the wildcard, not compare the
        // literal `*` against `bob`.
        let d = w07_diags(
            "Match User *\n    X11Forwarding yes\n\
             Match User bob\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "wildcard overlaps the specific user -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn cidr_supernet_contains_host_address_flags_w07() {
        // `Address` accepts CIDR. 10.1.2.3 is inside 10.0.0.0/8, so a connection
        // from 10.1.2.3 satisfies both blocks.
        let d = w07_diags(
            "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match Address 10.1.2.3\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "host address inside the supernet -> one W07");
        assert_eq!(d[0].line, 4);
    }

    // ---- NEGATIVE: provably-disjoint criteria, or nothing actually shadowed ----

    #[test]
    fn disjoint_users_do_not_flag_w07() {
        // The canonical false positive to avoid: no single connection is both
        // alice and bob, so the two blocks are never both applied. This is the
        // normal, intended per-user pattern the issue calls out.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint same-type user literals never co-satisfy"
        );
    }

    #[test]
    fn disjoint_user_lists_do_not_flag_w07() {
        // `alice,carol` and `bob,dave` share no value and use no wildcard, so no
        // user matches both lists.
        assert!(
            w07_diags(
                "Match User alice,carol\n    X11Forwarding yes\n\
                 Match User bob,dave\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint user lists never co-satisfy"
        );
    }

    #[test]
    fn disjoint_cidrs_do_not_flag_w07() {
        // 192.168.0.0/16 neither contains nor intersects 10.0.0.0/8, so no source
        // address satisfies both blocks.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match Address 192.168.0.0/16\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint CIDR ranges never co-satisfy"
        );
    }

    #[test]
    fn disjoint_localports_do_not_flag_w07() {
        // A connection arrives on ONE local port, so `LocalPort 22` and
        // `LocalPort 2222` are mutually exclusive.
        assert!(
            w07_diags(
                "Match LocalPort 22\n    X11Forwarding yes\n\
                 Match LocalPort 2222\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint local ports never co-satisfy"
        );
    }

    #[test]
    fn negated_pattern_excluding_the_user_is_clean() {
        // `!bob,*` matches every user EXCEPT bob (OpenSSH `match_pattern_list`: the
        // negated `!bob` excludes bob, and the positive `*` admits everyone else).
        // It is therefore DISJOINT from `User bob`. A naive impl that reads `*` as
        // "matches everything including bob" would raise a false positive here.
        assert!(
            w07_diags(
                "Match User !bob,*\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a pattern-list that negates the other block's sole user is disjoint"
        );
    }

    #[test]
    fn global_then_single_match_override_is_clean() {
        // A global directive overridden inside ONE Match block is the intended
        // mechanism, not a cross-Match shadow: only one Match block sets the
        // keyword, so there is no second satisfiable Match instance to drop.
        assert!(
            w07_diags(
                "X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "global + a single Match override is the intended pattern, not a shadow"
        );
    }

    #[test]
    fn different_keywords_in_overlapping_blocks_are_clean() {
        // Even with IDENTICAL (fully overlapping) `User alice` criteria, the two
        // blocks set DIFFERENT keywords, so neither value is shadowed. W07 must key
        // on a shared first-value-wins keyword, not merely on two overlapping blocks.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User alice\n    PasswordAuthentication no\n",
            )
            .is_empty(),
            "no keyword is shared across the two blocks, so nothing is shadowed"
        );
    }
}
