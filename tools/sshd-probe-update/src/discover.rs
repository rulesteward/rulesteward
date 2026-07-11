//! Best-effort `man sshd_config` keyword-discovery pass (#471).
//!
//! LIVE-only, advisory, NEVER gate-failing: widens the candidate universe
//! beyond `known_keywords(target)` plus the bogus sentinel (see
//! `probe::fetch_manpage_source`) by parsing the roff/mdoc SOURCE of the
//! in-container
//! `/usr/share/man/man5/sshd_config.5.gz`, extracting every keyword named in
//! the man page's TOP-LEVEL keyword-enumeration list, and flagging any that
//! the shipped `rulesteward_sshd::lints::registry::known_keywords(target)`
//! table does not know. Such a keyword is appended to the LIVE probe's
//! candidate list (main.rs), probed against the daemon like any other
//! candidate, and reported as an advisory (never as E01/W04/E04 drift).
//!
//! # Only ONE direction is reportable
//! The man page is a documentation source, not ground truth (the daemon is -
//! see `classify.rs`), and it is KNOWN to omit real, daemon-recognized
//! keywords: the RHEL out-of-tree GSSAPI patch keywords and other
//! deprecated-but-still-accepted aliases the shipped registry already knows
//! from live-probing the daemon directly. So `registry-minus-man` (a
//! `known_keywords` entry the man page does not list) is EXPECTED and never
//! computed or reported here - only `man-minus-registry` (a man-listed
//! keyword the registry does not know) is a discovery finding.
//!
//! # The offline path never runs this
//! `check --transcript` / `derive --transcript` have no docker container to
//! discover a man page in, so discovery is gated LIVE-only; see
//! `discovery_enabled` in `main.rs` and the comment at `derive.rs` around the
//! `diff_target` advisory-building loop.

/// Parse the roff/mdoc SOURCE of `sshd_config(5)` (already gunzipped/decoded
/// to a `&str`, e.g. via `gunzip -c sshd_config.5.gz`) and return every
/// keyword name from a `.It Cm <Keyword>` line in the TOP-LEVEL
/// keyword-enumeration list, preserving each name's ORIGINAL casing exactly
/// as it appears on the `.It Cm` line (comparison against the registry is
/// case-insensitive - see `man_only_keywords` - but extraction itself does
/// not normalize case).
///
/// "Top-level" means: the FIRST `.Bl`/`.El` span in the document (the
/// keyword-enumeration list always opens immediately after "keywords and
/// their meanings are as follows" and is the first list in the whole man
/// page). Two kinds of `.It Cm` line are EXCLUDED:
/// - a suboption `.It Cm` nested INSIDE that first list (e.g. a channel-type
///   or Kerberos-indicator name documented inside one keyword's own
///   description, at `.Bl`/`.El` nesting depth 2+);
/// - a `.It Cm` line belonging to a SIBLING top-level list that appears
///   AFTER the keyword list's closing `.El` (e.g. the `TIME FORMATS`
///   section's `s|S`/`m|M`/... unit-suffix table, which sits at the SAME
///   nesting depth as the keyword list but is a different `.Sh` section
///   entirely and lists time-unit suffixes, not `sshd_config` keywords).
///
/// A `.It Cm <Keyword>` line may carry trailing macro tokens after the bare
/// keyword (e.g. an argument-type placeholder); only the token immediately
/// following `Cm` is the keyword name.
///
/// Returns an empty `Vec` (never an error) if no top-level `.It Cm` entries
/// are found; the caller treats an empty result as advisory-worthy
/// ("discovery unavailable") rather than a hard failure - see
/// `discovery_unavailable_advisory`.
pub fn extract_manpage_keywords(roff: &str) -> Vec<String> {
    let mut depth: u32 = 0;
    let mut first_list_started = false;
    let mut in_first_list = false;
    let mut finished = false;
    let mut out = Vec::new();

    for line in roff.lines() {
        if finished {
            break;
        }
        let mut tokens = line.split_whitespace();
        let Some(macro_name) = tokens.next() else {
            continue;
        };
        match macro_name {
            ".Bl" => {
                depth += 1;
                if !first_list_started {
                    first_list_started = true;
                    in_first_list = true;
                }
            }
            ".El" => {
                depth = depth.saturating_sub(1);
                if in_first_list && depth == 0 {
                    // The FIRST top-level list just closed - stop before any
                    // sibling top-level list (e.g. TIME FORMATS) is reached.
                    finished = true;
                }
            }
            // Only a bare `.It Cm <Keyword>` at the first list's OWN depth
            // (not a nested suboption list) names an sshd_config keyword;
            // only the token immediately after `Cm` is the keyword name.
            ".It" if in_first_list && depth == 1 && tokens.next() == Some("Cm") => {
                if let Some(kw) = tokens.next() {
                    out.push(kw.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// Case-insensitively compare `man_keywords` (as returned by
/// `extract_manpage_keywords`) against `known` (typically
/// `rulesteward_sshd::lints::registry::known_keywords(target)`), returning
/// the man-listed names ABSENT from `known` - the candidates this discovery
/// pass adds to the live probe's candidate universe.
///
/// Returned names preserve their casing as they appeared in `man_keywords`.
/// The reverse direction (a `known` entry the man page does not list) is
/// NEVER computed here - see the module doc for why that divergence is
/// expected, not a discovery finding.
pub fn man_only_keywords(man_keywords: &[String], known: &[&str]) -> Vec<String> {
    man_keywords
        .iter()
        .filter(|kw| !known.iter().any(|k| k.eq_ignore_ascii_case(kw)))
        .cloned()
        .collect()
}

/// The live daemon's verdict on a man-page-discovered keyword, once probed
/// (`sshd -t -o KW=yes`), for the discovery advisory text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonVerdict {
    /// The daemon did not reject the keyword (mirrors `classify::e01_known`).
    Recognized,
    /// The daemon rejected it as a `Bad configuration option`.
    Rejected,
}

/// Render ONE advisory line (never gate-failing) for a keyword the man page
/// lists but the shipped registry does not know: names `kw`, states that the
/// man page lists it and the registry lacks it, and reports the live
/// daemon's verdict on it.
pub fn discovery_advisory(kw: &str, verdict: DaemonVerdict) -> String {
    let verdict_desc = match verdict {
        DaemonVerdict::Recognized => "the live daemon recognized it",
        DaemonVerdict::Rejected => "the live daemon rejected it as unknown",
    };
    format!(
        "advisory: man-page discovery: `{kw}` is listed in the man page but absent \
         from the shipped registry; {verdict_desc}"
    )
}

/// Render the single advisory line emitted when the LIVE man-page-discovery
/// pass itself could not run or its source could not be parsed (man-db /
/// the man page absent from the image, `gunzip` failure, zero top-level
/// `.It Cm` entries found). Always exactly one advisory; discovery failure
/// NEVER produces a gate-failing error (exit stays 0=in-sync / 1=drift; exit
/// 2 is reserved for genuine tool errors unrelated to this best-effort pass).
pub fn discovery_unavailable_advisory(reason: &str) -> String {
    format!("advisory: man-page keyword discovery unavailable: {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{DriftReport, FamilyDrift, ProbeSets};
    use rulesteward_sshd::TargetVersion;

    // --- real-fixture roff sources (RHEL 8 / 9 / 10 `sshd_config(5)`; see
    // tests/fixtures/README.md for capture provenance + sha256 pins) --------

    const RHEL8_ROFF: &str = include_str!("../tests/fixtures/rhel8_sshd_config.5.roff");
    const RHEL9_ROFF: &str = include_str!("../tests/fixtures/rhel9_sshd_config.5.roff");
    const RHEL10_ROFF: &str = include_str!("../tests/fixtures/rhel10_sshd_config.5.roff");

    fn contains_ci(haystack: &[String], needle: &str) -> bool {
        haystack.iter().any(|k| k.eq_ignore_ascii_case(needle))
    }

    // --- 1. roff extraction (real fixtures) ---------------------------------

    /// `PasswordAuthentication` and `X11Forwarding` are ordinary top-level
    /// keywords present, verbatim-cased, in EVERY committed product fixture
    /// (rhel8 lines 1247/1692; rhel9 lines 1451/2113; rhel10 lines
    /// 1454/2116 - confirmed via `grep -n '^\.It Cm PasswordAuthentication$'`
    /// / `X11Forwarding` against each committed fixture at authoring time).
    #[test]
    fn extract_manpage_keywords_finds_known_keywords_in_every_product() {
        for (name, roff) in [
            ("rhel8", RHEL8_ROFF),
            ("rhel9", RHEL9_ROFF),
            ("rhel10", RHEL10_ROFF),
        ] {
            let extracted = extract_manpage_keywords(roff);
            assert!(
                extracted.iter().any(|k| k == "PasswordAuthentication"),
                "{name}: expected literal \"PasswordAuthentication\" in {extracted:?}"
            );
            assert!(
                extracted.iter().any(|k| k == "X11Forwarding"),
                "{name}: expected literal \"X11Forwarding\" in {extracted:?}"
            );
        }
    }

    /// A real NESTED `.It Cm` entry must NOT be extracted. In the committed
    /// rhel9 fixture, `ChannelTimeout` is a top-level keyword at line 400;
    /// its own description opens a NESTED list (`.Bl -tag -width Ds` at line
    /// 433, `.El` at line 464) naming channel TYPES, not `sshd_config`
    /// keywords - `.It Cm agent-connection` at line 434 is the first of
    /// those. `ChannelTimeout` must be extracted; `agent-connection` must
    /// not (checked case-insensitively since the extractor's casing
    /// contract for this doc-comment-only edge case is otherwise unpinned).
    #[test]
    fn extract_manpage_keywords_excludes_real_nested_suboption() {
        let extracted = extract_manpage_keywords(RHEL9_ROFF);
        assert!(
            extracted.iter().any(|k| k == "ChannelTimeout"),
            "expected top-level ChannelTimeout (line 400) in {extracted:?}"
        );
        assert!(
            !contains_ci(&extracted, "agent-connection"),
            "agent-connection (line 434) is nested under ChannelTimeout's own \
             description (lines 433-464) and must not be extracted; got {extracted:?}"
        );
    }

    /// A real SIBLING top-level list must also be excluded. In every
    /// committed fixture, the keyword-enumeration list closes right before
    /// `.Sh TIME FORMATS` (rhel9: keyword list closes at line 2177, `.Sh
    /// TIME FORMATS` at line 2178). That section opens its OWN `.Bl` (rhel9
    /// line 2191) at the SAME nesting depth as the keyword list and lists
    /// time-unit suffixes via `.It Cm s | Cm S` (line 2194), `.It Cm m | Cm
    /// M` (line 2196), etc. - these are not `sshd_config` keywords and a
    /// depth-only (rather than first-list-only) extractor would wrongly
    /// include them.
    #[test]
    fn extract_manpage_keywords_excludes_real_sibling_time_formats_list() {
        let extracted = extract_manpage_keywords(RHEL9_ROFF);
        for bogus in ["s", "S", "m", "M", "h", "H", "d", "D", "w", "W"] {
            assert!(
                !extracted.iter().any(|k| k == bogus),
                "TIME FORMATS suffix {bogus:?} (rhel9 lines 2194-2202) must not be \
                 extracted as an sshd_config keyword; got {extracted:?}"
            );
        }
    }

    /// Count sanity for the rhel9 fixture, as specified by #471: the
    /// top-level keyword-enumeration list must extract more than 100 and
    /// fewer than 400 entries (a naive whole-document `.It Cm` scan would
    /// overshoot toward ~139; an over-narrow scan that also excludes valid
    /// entries would undershoot).
    #[test]
    fn extract_manpage_keywords_rhel9_count_sanity() {
        let extracted = extract_manpage_keywords(RHEL9_ROFF);
        assert!(
            extracted.len() > 100 && extracted.len() < 400,
            "expected 100 < count < 400, got {} ({extracted:?})",
            extracted.len()
        );
    }

    /// Precise regression pin for every product, computed by manually
    /// depth-tracking `.Bl`/`.El` nesting over the committed fixture and
    /// counting `.It Cm <token>` lines strictly inside the FIRST top-level
    /// list only (script-verified at authoring time; zero duplicate
    /// keyword names within any one product's count). A correct
    /// implementation that scopes to the main list only, extracts one
    /// keyword per top-level `.It Cm` line, and drops the two known false
    /// sources (nested suboptions, the TIME FORMATS sibling list) will
    /// reproduce these exact counts: rhel8 = 97, rhel9 = 112, rhel10 = 113.
    #[test]
    fn extract_manpage_keywords_exact_counts_per_product() {
        assert_eq!(extract_manpage_keywords(RHEL8_ROFF).len(), 97, "rhel8");
        assert_eq!(extract_manpage_keywords(RHEL9_ROFF).len(), 112, "rhel9");
        assert_eq!(extract_manpage_keywords(RHEL10_ROFF).len(), 113, "rhel10");
    }

    // --- 1b. roff extraction (synthetic snippets: edge cases real fixtures
    // don't happen to exercise in isolation) ---------------------------------

    /// Minimal synthetic roff isolating the nested-list exclusion in a
    /// self-contained snippet (independent of any real fixture's exact
    /// line numbers): three top-level keywords, the middle one's
    /// description opening a nested list with one suboption.
    #[test]
    fn extract_manpage_keywords_synthetic_nested_list_excluded() {
        let roff = "\
.Sh DESCRIPTION
The possible keywords are as follows:
.Bl -tag -width Ds
.It Cm ZzzKeywordOne
Description one.
.It Cm ZzzKeywordTwo
Description two, with a nested list of sub-items:
.Bl -item -compact -offset indent
.It Cm zzz_nested_suboption
Not a real keyword - nested inside ZzzKeywordTwo's own description.
.El
.It Cm ZzzKeywordThree
Description three.
.El
";
        let extracted = extract_manpage_keywords(roff);
        let want = ["ZzzKeywordOne", "ZzzKeywordTwo", "ZzzKeywordThree"];
        for kw in want {
            assert!(
                extracted.iter().any(|k| k == kw),
                "expected {kw:?} in {extracted:?}"
            );
        }
        assert!(
            !contains_ci(&extracted, "zzz_nested_suboption"),
            "nested suboption must be excluded; got {extracted:?}"
        );
        assert_eq!(extracted.len(), 3, "extracted={extracted:?}");
    }

    /// Minimal synthetic roff isolating the sibling-top-level-list exclusion:
    /// the main keyword list closes, then a SECOND top-level list (mirroring
    /// the real TIME FORMATS section) opens at the same nesting depth. Only
    /// entries from the FIRST list may be extracted.
    #[test]
    fn extract_manpage_keywords_synthetic_sibling_list_excluded() {
        let roff = "\
.Sh DESCRIPTION
The possible keywords are as follows:
.Bl -tag -width Ds
.It Cm ZzzMainKeyword
The only real keyword in this snippet.
.El
.Sh TIME FORMATS
.Bl -tag -width Ds -compact -offset indent
.It Cm s | Cm S
seconds
.It Cm m | Cm M
minutes
.El
";
        let extracted = extract_manpage_keywords(roff);
        assert_eq!(
            extracted,
            vec!["ZzzMainKeyword".to_string()],
            "only the main list's single entry may be extracted; got {extracted:?}"
        );
    }

    /// A `.It Cm <Keyword>` line may carry trailing macro tokens after the
    /// bare keyword (an argument-type placeholder in this synthetic case);
    /// only the token immediately after `Cm` is the keyword name.
    #[test]
    fn extract_manpage_keywords_synthetic_trailing_macro_args() {
        let roff = "\
.Sh DESCRIPTION
The possible keywords are as follows:
.Bl -tag -width Ds
.It Cm ZzzArgKeyword Ar value
Description mentioning an inline argument placeholder.
.El
";
        let extracted = extract_manpage_keywords(roff);
        assert_eq!(
            extracted,
            vec!["ZzzArgKeyword".to_string()],
            "trailing ` Ar value` must not become part of (or a second) keyword; \
             got {extracted:?}"
        );
    }

    /// Extraction preserves each keyword's ORIGINAL casing verbatim (no
    /// forced lower/upper-casing) - case-insensitive matching is the
    /// registry-COMPARE step's job (`man_only_keywords`), not extraction's.
    #[test]
    fn extract_manpage_keywords_synthetic_preserves_original_casing() {
        let roff = "\
.Sh DESCRIPTION
The possible keywords are as follows:
.Bl -tag -width Ds
.It Cm ZzzWeirdlyCasedKeyword
Description.
.El
";
        let extracted = extract_manpage_keywords(roff);
        assert_eq!(extracted, vec!["ZzzWeirdlyCasedKeyword".to_string()]);
    }

    // --- 2. registry compare -------------------------------------------------

    /// Case-insensitive matching: man-listed `PasswordAuthentication` /
    /// `X11Forwarding` (CamelCase, as the man page writes them) must be
    /// excluded when the registry holds their lowercase equivalents
    /// (`registry.rs` stores every keyword lowercased - confirmed via
    /// `grep '"passwordauthentication"'` / `'"x11forwarding"'` against the
    /// committed `crates/rulesteward-sshd/src/lints/registry.rs`).
    #[test]
    fn man_only_keywords_case_insensitive_match_excludes_known() {
        let man = vec![
            "PasswordAuthentication".to_string(),
            "X11Forwarding".to_string(),
        ];
        let known = ["passwordauthentication", "x11forwarding"];
        assert!(
            man_only_keywords(&man, &known).is_empty(),
            "both man entries case-insensitively match the registry"
        );
    }

    /// `registry-minus-man` must NEVER be reported. Grounded in the real
    /// rhel9 divergence: the shipped registry knows 26 keywords the rhel9
    /// man page does not list at all (RHEL out-of-tree GSSAPI patch
    /// keywords and legacy aliases, e.g. `protocol`, `rsaauthentication`,
    /// `hostbasedacceptedkeytypes` - computed by diffing the extracted
    /// rhel9 man set against `known_keywords(Rhel9)` at authoring time).
    /// Even though `known` here includes many entries `man` lacks, the
    /// function's output must be empty: it only ever computes man-minus-known.
    #[test]
    fn man_only_keywords_registry_minus_man_produces_nothing() {
        let man = vec![
            "PasswordAuthentication".to_string(),
            "X11Forwarding".to_string(),
            "ChannelTimeout".to_string(),
        ];
        // A representative slice of the real rhel9 registry, including
        // entries the rhel9 man page genuinely does not list (protocol,
        // rsaauthentication, hostbasedacceptedkeytypes - see the module doc
        // and registry.rs's own "RHEL out-of-tree GSSAPI" provenance note).
        let known = [
            "passwordauthentication",
            "x11forwarding",
            "channeltimeout",
            "protocol",
            "rsaauthentication",
            "hostbasedacceptedkeytypes",
            "gssapikeyexchange",
        ];
        assert!(
            man_only_keywords(&man, &known).is_empty(),
            "registry-only entries (protocol, rsaauthentication, ...) must never \
             surface from man_only_keywords"
        );
    }

    /// `man-minus-registry` DOES surface: no real committed fixture happens
    /// to exhibit this direction today (every keyword all three man pages
    /// list is already in the registry - verified by diffing all three
    /// extracted sets against their respective `known_keywords(target)` at
    /// authoring time, all three empty), so this is a synthetic case per
    /// #471's explicit allowance for synthetic-roff edge-case fixtures. It
    /// exercises exactly the scenario the whole feature exists for: a
    /// brand-new upstream keyword the registry has never seen.
    #[test]
    fn man_only_keywords_man_minus_registry_reports_new_candidate() {
        let man = vec!["ZzzTestNewKeyword".to_string()];
        let known = ["passwordauthentication", "x11forwarding"];
        let result = man_only_keywords(&man, &known);
        assert_eq!(result, vec!["ZzzTestNewKeyword".to_string()]);
    }

    // --- 3. advisory plumbing -------------------------------------------------

    #[test]
    fn discovery_advisory_recognized_names_keyword_and_registry_and_man() {
        let line = discovery_advisory("ZzzNewFutureKeyword", DaemonVerdict::Recognized);
        assert!(line.contains("ZzzNewFutureKeyword"), "line={line}");
        assert!(line.to_lowercase().contains("man"), "line={line}");
        assert!(line.to_lowercase().contains("registry"), "line={line}");
        assert!(line.to_lowercase().contains("recognized"), "line={line}");
    }

    #[test]
    fn discovery_advisory_rejected_names_keyword_and_verdict() {
        let line = discovery_advisory("ZzzNewFutureKeyword", DaemonVerdict::Rejected);
        assert!(line.contains("ZzzNewFutureKeyword"), "line={line}");
        assert!(line.to_lowercase().contains("reject"), "line={line}");
    }

    #[test]
    fn discovery_unavailable_advisory_mentions_unavailable_and_reason() {
        let line = discovery_unavailable_advisory("man page missing from image");
        assert!(line.to_lowercase().contains("unavailable"), "line={line}");
        assert!(line.contains("man page missing from image"), "line={line}");
    }

    /// A drift-free `DriftReport` carrying a discovery advisory must stay
    /// `is_in_sync() == true` (advisories never gate; `main.rs`'s `cmd_check`
    /// derives its `ExitCode` directly from `is_in_sync()`, so this pins the
    /// "advisory-only reports exit 0" contract at the report level, since
    /// the LIVE docker path itself is not exercised by these offline tests).
    #[test]
    fn discovery_advisory_in_report_keeps_is_in_sync_true() {
        let report = DriftReport {
            target: TargetVersion::Rhel9,
            e01: FamilyDrift {
                family: "E01",
                added: vec![],
                removed: vec![],
            },
            w04: FamilyDrift {
                family: "W04",
                added: vec![],
                removed: vec![],
            },
            e04: FamilyDrift {
                family: "E04",
                added: vec![],
                removed: vec![],
            },
            advisories: vec![discovery_advisory(
                "ZzzNewFutureKeyword",
                DaemonVerdict::Recognized,
            )],
            probe: ProbeSets::default(),
        };
        assert!(
            report.is_in_sync(),
            "a discovery advisory must not flip is_in_sync to false"
        );
        assert_eq!(report.drift_count(), 0);
    }

    /// Same "never gates" contract for the discovery-UNAVAILABLE advisory
    /// (man page missing / unparseable in the container): the report stays
    /// in sync and thus main.rs still exits 0, never the tool-error exit 2.
    #[test]
    fn discovery_unavailable_advisory_in_report_keeps_is_in_sync_true() {
        let report = DriftReport {
            target: TargetVersion::Rhel9,
            e01: FamilyDrift {
                family: "E01",
                added: vec![],
                removed: vec![],
            },
            w04: FamilyDrift {
                family: "W04",
                added: vec![],
                removed: vec![],
            },
            e04: FamilyDrift {
                family: "E04",
                added: vec![],
                removed: vec![],
            },
            advisories: vec![discovery_unavailable_advisory(
                "gunzip failed: no such file",
            )],
            probe: ProbeSets::default(),
        };
        assert!(report.is_in_sync());
    }
}
