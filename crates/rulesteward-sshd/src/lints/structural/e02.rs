//! sshd-E02: duplicate directive. See [`e02`].

use std::collections::HashSet;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, Directive};
use crate::lints::{SshdLintContext, anchored};

use super::E02_ALLOW_REPEAT;

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
