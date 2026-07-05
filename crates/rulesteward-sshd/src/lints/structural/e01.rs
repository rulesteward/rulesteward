//! sshd-E01: unknown directive. See [`e01`].

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored, registry};

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
