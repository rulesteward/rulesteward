//! Structural lints: directive identity, duplication, Include resolution, and
//! Match-block legality. These need no STIG/crypto baseline tables, so the
//! parallel pipelines for sshd-E02/E03/E04 (Wave A) can start the moment the
//! Phase-0 foundation merges. sshd-E01 (registry-gated) and sshd-W05 (which
//! reuses the W01 required-set) are grouped here as the structural family.
//!
//! Phase 0: every pass is a `Vec::new()` stub with a frozen signature. The
//! tracking issues are children of epic #149.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored};

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

/// Keywords permitted on the lines following a `Match` keyword, per the
/// "Available keywords are ..." paragraph of `sshd_config(5)` (OpenSSH 10.2p1).
/// Any directive inside a `Match` body whose keyword is NOT in this set is
/// silently ignored by sshd at runtime - that is the sshd-E04 finding.
///
/// Lowercased and sorted (matched via [`slice::contains`]). This is the 10.2p1
/// superset; the set grows across OpenSSH releases, so using the newest list
/// flags only keywords illegal in EVERY version (false-negative-leaning, which
/// avoids telling an operator a valid config is broken). Extracted verbatim from
/// the man page, not hand-transcribed.
const E04_MATCH_PERMITTED: &[&str] = &[
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
    "hostbasedacceptedalgorithms",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "ignorerhosts",
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

/// sshd-E01: unknown directive (not a recognized keyword for the target).
///
/// TODO(#149, Wave B): requires the per-OpenSSH-version directive registry from
/// the STIG/version grounding task.
#[must_use]
pub fn e01(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-E02: duplicate global directive (sshd's first-value-wins silently shadows
/// the later line for most keywords).
///
/// TODO(#149, Wave A): pure structural; no baseline data needed.
#[must_use]
pub fn e02(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    // Wave A scopes E02 to the global (pre-Match) block, matching the catalog's
    // "duplicate global directive". `blocks[0]` is always the global block.
    let Some(Block::Global(directives)) = blocks.first() else {
        return Vec::new();
    };

    let mut diags = Vec::new();
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
    diags
}

/// The key that decides whether a global directive is a first-value-wins
/// duplicate. Most keywords key on the keyword alone. `Subsystem` is the one
/// exception: it accumulates across DIFFERENT subsystem names but is
/// first-value-wins for the SAME name (verified via `sshd -T`), so it keys on
/// `subsystem` plus the name (its first, case-sensitive argument). Returns `None`
/// for a `Subsystem` line with no name (nothing to shadow).
fn e02_dedup_key(keyword: &str, directive: &crate::ast::Directive) -> Option<String> {
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
/// TODO(#149, Wave A): checks each Match body against the small static set of
/// Match-permitted keywords from `sshd_config(5)`.
#[must_use]
pub fn e04(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let Block::Match(match_block) = block else {
            // E04 only inspects Match bodies; the global block has no restriction.
            continue;
        };
        for directive in &match_block.body {
            let keyword = directive.keyword_lower();
            if !E04_MATCH_PERMITTED.contains(&keyword.as_str()) {
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
/// TODO(#149, Wave C): depends on the W01 required-directive set.
#[must_use]
pub fn w05(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
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
    use crate::lints::SshdLintContext;
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

    #[test]
    fn each_illegal_directive_in_a_match_is_flagged() {
        let src = "Match User bob\n    Ciphers aes256-ctr\n    ListenAddress 0.0.0.0\n    Subsystem sftp /x\n";
        let lines: Vec<usize> = run(src).iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![2, 3, 4], "all three illegal lines flagged");
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
}

#[cfg(test)]
mod e02_tests {
    //! sshd-E02: duplicate global directive (first-value-wins shadow).
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
        // E02 is global-scope only: a Match override of a global keyword is the
        // intended mechanism, not a duplicate (follow-up issue tracks intra-Match
        // duplicate detection).
        let src = "PasswordAuthentication yes\nMatch User bob\n    PasswordAuthentication no\n";
        assert!(run(src).is_empty());
    }

    #[test]
    fn duplicate_inside_match_body_is_not_e02_in_wave_a() {
        // Intra-Match duplicates are out of Wave-A scope (tracked as a follow-up).
        let src = "Match User bob\n    PasswordAuthentication yes\n    PasswordAuthentication no\n";
        assert!(run(src).is_empty(), "Wave A scopes E02 to the global block");
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
}
