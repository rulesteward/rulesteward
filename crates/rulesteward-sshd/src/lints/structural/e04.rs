//! sshd-E04: directive illegal inside a `Match` block. See [`e04`].

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored, is_unconditional_match_all, registry};

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
///
/// #372 (2026-07-07): a full-registry `sshd-probe-update` daemon probe (Rocky
/// 8/9/10, same non-activating-Match oracle) found four keywords the daemon HONORS
/// in Match that were still firing sshd-E04 as false positives. Honored on every
/// version and added here: `authorizedkeysfile2`, `rhostsrsaauthentication`,
/// `rsaauthentication`. The 9.x-only `gssapiindicators` went to the additions below.
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
    "authorizedkeysfile2",
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
    "rhostsrsaauthentication",
    "rsaauthentication",
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
///
/// #372 (2026-07-07): `gssapiindicators` added here (a RHEL GSSAPI-patch keyword,
/// UNKNOWN on 8.0p1, Match-honored on 9.9p1) after the full-registry
/// `sshd-probe-update` probe found it firing sshd-E04 as a false positive on 9/10.
const E04_PERMITTED_ADDED_9_9P1: &[&str] = &[
    "challengeresponseauthentication",
    "gssapiindicators",
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
pub(super) fn e04_match_permitted(
    keyword_lower: &str,
    target: Option<crate::lints::TargetVersion>,
) -> bool {
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

/// The full set of `Match`-block-permitted keywords for `target`, enumerated for
/// the out-of-tree `sshd-probe-update` drift tool. Mirrors [`e04_match_permitted`]:
/// the base set on every version plus the 9.9p1 additions for rhel9/rhel10 (68 /
/// 76 / 76 for RHEL 8 / 9 / 10). Order is unspecified.
#[must_use]
pub fn match_permitted_keywords(target: crate::lints::TargetVersion) -> Vec<&'static str> {
    use crate::lints::TargetVersion;
    let mut out: Vec<&'static str> = E04_PERMITTED_BASE.to_vec();
    if !matches!(target, TargetVersion::Rhel8) {
        out.extend_from_slice(E04_PERMITTED_ADDED_9_9P1);
    }
    out
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
        if is_unconditional_match_all(match_block) {
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

    #[test]
    fn e04_does_not_fire_on_daemon_honored_deprecated_keywords_in_match() {
        // #372: AuthorizedKeysFile2, RSAAuthentication, RhostsRSAAuthentication are
        // recognized-but-deprecated on 8/9/10 and the daemon HONORS them inside a
        // Match block (`sshd -t -f`: "Deprecated option", rc 0 -- NOT "not allowed
        // within a Match block"), so E04's "silently ignored at runtime" was a false
        // positive. Grounded 2026-07-07 on Rocky 8/9/10 (sshd-probe-update capture).
        for kw in [
            "AuthorizedKeysFile2",
            "RSAAuthentication",
            "RhostsRSAAuthentication",
        ] {
            let src = format!("Match User bob\n    {kw} yes\n");
            for target in [
                TargetVersion::Rhel8,
                TargetVersion::Rhel9,
                TargetVersion::Rhel10,
            ] {
                let diags = run_with_target(&src, target);
                assert!(
                    diags.is_empty(),
                    "sshd-E04 must NOT fire on '{kw}' in a Match block ({target:?}): the \
                     daemon honors it (rc 0, 'Deprecated option'); got {diags:?}"
                );
            }
        }
    }

    #[test]
    fn e04_does_not_fire_on_gssapiindicators_in_match_on_rhel9_rhel10() {
        // #372: GSSAPIIndicators is a RHEL GSSAPI-patch keyword -- UNKNOWN on rhel8
        // (the is_known gate already suppresses E04 there) but recognized and
        // Match-honored on 9.9p1 (rc 0, clean parse). It must not fire E04 on
        // rhel9/rhel10. Grounded 2026-07-07 on Rocky 9/10 (sshd-probe-update capture).
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target("Match User bob\n    GSSAPIIndicators yes\n", target);
            assert!(
                diags.is_empty(),
                "sshd-E04 must NOT fire on GSSAPIIndicators in a Match block ({target:?}); \
                 got {diags:?}"
            );
        }
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
    //! Grounding: 2026-06-29 snapshot + #372 2026-07-07 additions, Rocky 8.10 / 9.8 / 10.2 (OpenSSH
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
        "authorizedkeysfile2",
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
        "rhostsrsaauthentication",
        "rsaauthentication",
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
        "gssapiindicators",
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
            68,
            "E04_PERMITTED_BASE size changed from the pinned snapshot (68); \
             re-ground on Rocky 8.10/9.8/10.2 and update both the set and this count"
        );
        assert_eq!(
            E04_PERMITTED_ADDED_9_9P1.len(),
            8,
            "E04_PERMITTED_ADDED_9_9P1 size changed from the pinned snapshot (8); \
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
mod projection_tests {
    use super::{e04_match_permitted, match_permitted_keywords};
    use crate::lints::TargetVersion;

    #[test]
    fn match_permitted_keyword_sizes() {
        assert_eq!(match_permitted_keywords(TargetVersion::Rhel8).len(), 68);
        assert_eq!(match_permitted_keywords(TargetVersion::Rhel9).len(), 76);
        assert_eq!(match_permitted_keywords(TargetVersion::Rhel10).len(), 76);
    }

    #[test]
    fn every_enumerated_keyword_is_match_permitted_on_its_tier() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            for kw in match_permitted_keywords(target) {
                assert!(
                    e04_match_permitted(kw, Some(target)),
                    "{kw} enumerated but e04_match_permitted=false at {target:?}"
                );
            }
        }
    }
}
