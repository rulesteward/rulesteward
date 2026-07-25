//! The offline derivation core: parse an official DISA XCCDF benchmark into
//! the normalized [`DerivedControl`] table for the sudo-W04 DISA control-id
//! families (`!authenticate`, the `targetpw`/`rootpw`/`runaspw` pw-family, and
//! `timestamp_timeout`).
//!
//! This is the testable heart of the tool - it takes raw XCCDF text and
//! returns the derived controls, with NO network or filesystem. The live
//! fetch that hands it the XCCDF bytes lives behind the seam in
//! [`crate::source`].
//!
//! # How a control is selected + classified (#551)
//!
//! Grounded in the fixtures in `tests/fixtures/rhelN_sudoers_controls.xml`
//! (real DISA XCCDF extracts, in TRUE document order, verbatim
//! `check-content`/`fixtext`/titles; see that directory's `README.md` for full
//! provenance):
//!
//! * Select a `<Group>`/`<Rule>` as a sudo-W04 control IFF its `check-content`
//!   (or `fixtext`) contains one of the three families' distinguishing text:
//!   - [`crate::derive::Family::Authenticate`][]: `!authenticate` (case-insensitive).
//!   - [`crate::derive::Family::PwFamily`][]: `targetpw` / `rootpw` / `runaspw`
//!     (any of the three; a single DISA Rule covers all three settings together).
//!   - [`crate::derive::Family::TimestampTimeout`][]: `timestamp_timeout`.
//!
//!   This selection MUST be content-based, never positional/ordinal: the
//!   fixtures deliberately do NOT present the 3 real families first, or in
//!   `Family::ALL` order -- see `tests::selector_is_content_based_not_positional`.
//! * EXCLUDE a `NOPASSWD`-checking Rule (the sudo-W01/W05 sibling control,
//!   present as a decoy in every fixture) -- it shares the same `/etc/sudoers`
//!   check-content idiom but is a DIFFERENT lint (`sudo-W01`/`sudo-W05`, not
//!   `sudo-W04`), and must never be misclassified into one of the three
//!   families above. The rhel8 fixture ALSO carries 3 Groups with no bearing
//!   on sudo AT ALL, preceding even the NOPASSWD decoy.
//! * The V-number is `<Group id="...">`; the STIG Rule id is `<Rule><version>`
//!   (mirrors `tools/sshd-stig-update`'s `#507` convention); the title is the
//!   Rule's OWN `<title>` (the one immediately after `<version>`) -- NOT the
//!   `<Group>`-level `<title>`, which on RHEL 8/9/10's real XCCDF instead
//!   carries the SRG requirement id (e.g. `SRG-OS-000373-GPOS-00156`), not a
//!   human title. The committed fixtures deliberately KEEP the `<Group>`-level
//!   title verbatim (it is real DISA content) specifically so this distinction
//!   is a live trap a wrong implementation can fall into, not an untested
//!   claim -- see `tests::group_level_title_is_never_used_as_the_control_title`.
//! * Fail CLOSED (return `Err`, never a silently-empty `Ok`) when FEWER than
//!   all 3 DISTINCT families are matched -- see
//!   `tests::zero_matched_families_is_an_error`,
//!   `tests::fewer_than_three_matched_families_is_an_error`, and
//!   `tests::three_rows_of_one_family_is_an_error` (3 rows can still be only 1
//!   distinct family) below. A parse regression (or a wrong file being fed
//!   in) must never present as "0 drift, 0 controls" -- that is a silent
//!   false pass, not a clean one. The error text must contain the literal
//!   substring `"found N"` where `N` is the actual count (see those tests for
//!   why a looser substring check is not enough).
//! * Fail CLOSED, symmetrically, when a family is matched MORE than once (a
//!   future DISA revision adds a second Rule for an already-matched family) --
//!   see `tests::duplicate_family_is_an_error`. Resolving the collision
//!   silently (e.g. first-wins) would let an upstream addition vanish from the
//!   derived table and present as a false "0 drift" clean pass, which is worse
//!   than a loud error.
//!
//! # What this tool provably CANNOT see (not drift)
//!
//! [`crate::derive::diff_controls`] compares `rule_id` ONLY (per
//! [`DerivedControl::rule_id`]'s doc). A changed Rule `<title>`, a changed
//! `<Group>` V-number, or a changed `severity` attribute are NOT drift signals
//! this tool detects -- unlike `tools/sshd-stig-update`, which DOES diff
//! `v_number` (its `DerivedControl::v_number` is populated on both the
//! upstream AND code side; sudo-W04's shipped consts carry no V-number to
//! compare against). Only a changed STIG Rule id is drift.

use regex::Regex;

use crate::derive::{DerivedControl, Family};

/// DISA's `<Group id="V-...">...</Group>` element; captures the V-number in group 1
/// and the full inner content (Group-level title + the nested `<Rule>...</Rule>`) in
/// group 2. Groups never nest in these benchmarks, so a non-greedy match up to the
/// first `</Group>` is unambiguous.
const GROUP_PATTERN: &str = r#"(?s)<Group id="(V-\d+)">(.*?)</Group>"#;

/// Parse a full DISA XCCDF benchmark into the normalized sudo-W04 control
/// table (exactly 3 rows: one per [`Family`], on success). Fails CLOSED
/// (returns `Err`) when fewer than all 3 DISTINCT families are found -- see
/// the module doc's anti-vacuity requirement. The error text must contain the
/// literal substring `"found N"` (`N` = the actual count), per
/// `tests::zero_matched_families_is_an_error` /
/// `tests::fewer_than_three_matched_families_is_an_error` /
/// `tests::three_rows_of_one_family_is_an_error`. Also fails CLOSED, the other
/// direction, when the SAME family is matched by two different Rules -- see
/// `tests::duplicate_family_is_an_error`.
pub fn parse_controls(xccdf: &str) -> Result<Vec<DerivedControl>, String> {
    // Fixed regexes, compiled once. `unwrap` on a literal pattern is an invariant.
    let group_re = Regex::new(GROUP_PATTERN).unwrap();
    let version_re = Regex::new(r"<version>([^<]+)</version>").unwrap();
    let title_re = Regex::new(r"<title>([^<]+)</title>").unwrap();
    let check_re = Regex::new(r"(?s)<check-content[^>]*>(.*?)</check-content>").unwrap();
    let fixtext_re = Regex::new(r"(?s)<fixtext[^>]*>(.*?)</fixtext>").unwrap();

    let mut out: Vec<DerivedControl> = Vec::new();
    for caps in group_re.captures_iter(xccdf) {
        let v_number = caps[1].to_string();
        let group_body = &caps[2];

        // Scope every subsequent extraction to the Rule's OWN content (everything
        // after the literal `<Rule` tag), never the Group-level `<title>` that
        // precedes it -- the Group-level title carries the SRG requirement id
        // (e.g. `SRG-OS-000373-GPOS-00156`), a same-tag-different-meaning trap for
        // a selector that reads "the first <title> in the Group" (see
        // `tests::group_level_title_is_never_used_as_the_control_title`).
        let Some((_, rule_body)) = group_body.split_once("<Rule") else {
            continue; // no Rule element in this Group at all -- not a control.
        };

        let check = check_re
            .captures(rule_body)
            .map_or("", |c| c.get(1).map_or("", |m| m.as_str()));
        let fixtext = fixtext_re
            .captures(rule_body)
            .map_or("", |c| c.get(1).map_or("", |m| m.as_str()));

        // Selector: content-based, never positional (see module doc + BLOCKER 1 --
        // `tests::selector_is_content_based_not_positional`). Checked against BOTH
        // check-content and fixtext, case-insensitively.
        let haystack = format!("{check} {fixtext}").to_lowercase();
        let family = if haystack.contains("!authenticate") {
            Family::Authenticate
        } else if haystack.contains("targetpw")
            || haystack.contains("rootpw")
            || haystack.contains("runaspw")
        {
            Family::PwFamily
        } else if haystack.contains("timestamp_timeout") {
            Family::TimestampTimeout
        } else {
            continue; // decoy (NOPASSWD) or wholly-unrelated Group -- excluded.
        };

        let rule_id = version_re
            .captures(rule_body)
            .map(|c| c[1].trim().to_string())
            .ok_or_else(|| {
                format!(
                    "{v_number} ({}): no <version> (STIG Rule id) found",
                    family.as_str()
                )
            })?;
        let title = title_re
            .captures(rule_body)
            .map(|c| c[1].trim().to_string())
            .ok_or_else(|| format!("{v_number} ({}): no Rule <title> found", family.as_str()))?;

        out.push(DerivedControl {
            family,
            v_number,
            rule_id,
            title,
        });
    }

    // Anti-vacuity FIRST: count DISTINCT families present, not rows -- 3 rows
    // can still be only 1 distinct family (see
    // `tests::three_rows_of_one_family_is_an_error`), so this must run before
    // the duplicate-family check below, or a document missing 2 of the 3
    // mandatory families entirely (with the one present family repeated)
    // would be misreported as an over-match rather than the more fundamental
    // "found N" under-match (see `tests::fewer_than_three_matched_
    // families_is_an_error`).
    let matched_families = Family::ALL
        .iter()
        .filter(|f| out.iter().any(|c| c.family == **f))
        .count();
    if matched_families < Family::ALL.len() {
        return Err(format!(
            "sudo-W04: expected all {} families ({}), found {} in the XCCDF",
            Family::ALL.len(),
            Family::ALL
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            matched_families
        ));
    }

    // All 3 mandatory families ARE present -- now check the OTHER direction:
    // a family matched by MORE than one Rule means the selector over-matched
    // (an upstream revision added a second Rule for an already-covered
    // family) -- fail closed rather than silently resolve the collision
    // (e.g. via first-wins) and emit an ambiguous table that drops the new
    // Rule. Mirrors `tools/sshd-stig-update`'s `duplicate directive ...;
    // selector over-matched` guard, keyed by `Family` instead of keyword
    // (see `tests::duplicate_family_is_an_error`).
    for dup_family in Family::ALL {
        let rows: Vec<&DerivedControl> = out.iter().filter(|c| c.family == dup_family).collect();
        if rows.len() > 1 {
            return Err(format!(
                "sudo-W04: duplicate family {:?} ({} and {}); selector over-matched",
                dup_family.as_str(),
                rows[0].v_number,
                rows[1].v_number
            ));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{Family, code_table, diff_controls};
    use rulesteward_sudoers::TargetVersion;

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_sudoers_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_sudoers_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_sudoers_controls.xml");

    fn find(t: &[DerivedControl], family: Family) -> DerivedControl {
        t.iter()
            .find(|c| c.family == family)
            .unwrap_or_else(|| panic!("{:?} present in derived table {t:?}", family))
            .clone()
    }

    // -----------------------------------------------------------------------
    // Item 1: offline derive correctness -- exact ids/titles per product.
    // Real, verbatim DISA XCCDF content verified at authoring time against
    // /home/runner/rulesteward-docs/grounding/auditd-stig/stig_research/
    // (the SAME cached XCCDF documents crates/rulesteward-sudoers/src/lints/
    // stig.rs's PW_FAMILY_CONTROLS / AUTHENTICATE_CONTROLS /
    // TIMESTAMP_TIMEOUT_CONTROLS ids are grounded against; RHEL-10 explicitly
    // per #563 / 9i lane-7's citations table, RHEL-08/09 mechanically
    // cross-checked by grep at authoring time; adversarial round: an
    // independent reviewer additionally fetched and byte-verified all nine
    // ids AND every fixture Group against the current V2R8/V2R9/V1R2 DISA
    // revisions -- see this crate's stig-refs.toml).
    //
    // Each fixture is now in TRUE DOCUMENT ORDER (adversarial round, BLOCKER
    // 1): a wrong impl that assigns Groups to families POSITIONALLY (e.g.
    // "the Nth Group is the Nth family") must fail these, since the real
    // per-product ordering is auth/ts/pw (rhel10), ts/pw/auth (rhel9), and
    // [3 unrelated]/decoy/auth/pw/ts (rhel8) -- never `Family::ALL`'s own
    // auth/pw/ts order in any fixture.
    // -----------------------------------------------------------------------

    #[test]
    fn rhel8_fixture_extracts_exact_controls() {
        let d = parse_controls(RHEL8_FIXTURE).expect("parses");
        let auth = find(&d, Family::Authenticate);
        assert_eq!(auth.v_number, "V-230272");
        assert_eq!(auth.rule_id, "RHEL-08-010381");
        assert_eq!(
            auth.title,
            "RHEL 8 must require users to reauthenticate for privilege escalation."
        );

        let pw = find(&d, Family::PwFamily);
        assert_eq!(pw.v_number, "V-237642");
        assert_eq!(pw.rule_id, "RHEL-08-010383");
        assert_eq!(
            pw.title,
            "RHEL 8 must use the invoking user's password for privilege escalation when using \"sudo\"."
        );

        let ts = find(&d, Family::TimestampTimeout);
        assert_eq!(ts.v_number, "V-237643");
        assert_eq!(ts.rule_id, "RHEL-08-010384");
        // RHEL 8's own hyphenation ("re-authentication") DIFFERS from RHEL
        // 9/10's ("reauthentication") -- a real DISA wording quirk, verbatim.
        assert_eq!(
            ts.title,
            "RHEL 8 must require re-authentication when using the \"sudo\" command."
        );
    }

    #[test]
    fn rhel9_fixture_extracts_exact_controls() {
        let d = parse_controls(RHEL9_FIXTURE).expect("parses");
        let auth = find(&d, Family::Authenticate);
        assert_eq!(auth.v_number, "V-258086");
        assert_eq!(auth.rule_id, "RHEL-09-432025");
        assert_eq!(
            auth.title,
            "RHEL 9 must require users to reauthenticate for privilege escalation."
        );

        let pw = find(&d, Family::PwFamily);
        assert_eq!(pw.v_number, "V-258085");
        assert_eq!(pw.rule_id, "RHEL-09-432020");
        assert_eq!(
            pw.title,
            "RHEL 9 must use the invoking user's password for privilege escalation when using \"sudo\"."
        );

        let ts = find(&d, Family::TimestampTimeout);
        assert_eq!(ts.v_number, "V-258084");
        assert_eq!(ts.rule_id, "RHEL-09-432015");
        assert_eq!(
            ts.title,
            "RHEL 9 must require reauthentication when using the \"sudo\" command."
        );
    }

    #[test]
    fn rhel10_fixture_extracts_exact_controls() {
        let d = parse_controls(RHEL10_FIXTURE).expect("parses");
        let auth = find(&d, Family::Authenticate);
        assert_eq!(auth.v_number, "V-281208");
        assert_eq!(auth.rule_id, "RHEL-10-600530");
        assert_eq!(
            auth.title,
            "RHEL 10 must require users to reauthenticate for privilege escalation."
        );

        let pw = find(&d, Family::PwFamily);
        assert_eq!(pw.v_number, "V-281210");
        assert_eq!(pw.rule_id, "RHEL-10-600550");
        assert_eq!(
            pw.title,
            "RHEL 10 must use the invoking user's password for privilege escalation when using \"sudo\"."
        );

        let ts = find(&d, Family::TimestampTimeout);
        assert_eq!(ts.v_number, "V-281209");
        assert_eq!(ts.rule_id, "RHEL-10-600540");
        assert_eq!(
            ts.title,
            "RHEL 10 must require reauthentication when using the \"sudo\" command."
        );
    }

    // -----------------------------------------------------------------------
    // Item 3 (no-drift) + BLOCKER 3: the golden cross-check. The XCCDF-derived
    // table for EACH of the three RHEL targets must reproduce
    // `derive::code_table(target)` EXACTLY (0 drift) -- mirrors
    // `tools/sshd-stig-update`'s `rhelN_fixture_reproduces_code_table_exactly`
    // trio. Covering all THREE targets (not just rhel10) closes the gap a
    // `code_table` that ignores its `target` argument (always returning one
    // target's rows) would otherwise slip through undetected.
    // -----------------------------------------------------------------------

    #[test]
    fn rhel8_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL8_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel8);
        let diff = diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "rhel8 fixture must reproduce the shipped code_table(Rhel8) exactly: {diff:?}"
        );
    }

    #[test]
    fn rhel9_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL9_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel9);
        let diff = diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "rhel9 fixture must reproduce the shipped code_table(Rhel9) exactly: {diff:?}"
        );
    }

    #[test]
    fn rhel10_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL10_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel10);
        let diff = diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "rhel10 fixture must reproduce the shipped code_table(Rhel10) exactly: {diff:?}"
        );
    }

    // -----------------------------------------------------------------------
    // BLOCKER 1 (adversarial round): the selector must be CONTENT-based, never
    // positional/ordinal. A wrong impl that assigns `Family::ALL[0..3]` to the
    // first 3 `<Group>` blocks in document order passes every test ABOVE this
    // point ONLY if every fixture happens to present the families in
    // `Family::ALL` order with no other Groups mixed in -- which none of them
    // do (see the per-fixture ordering note above `rhel8_fixture_extracts_
    // exact_controls`). This test makes the requirement explicit and
    // self-checking: assert the RAW document order of `<Group id="...">`
    // never matches `Family::ALL`'s own order, so a future fixture edit that
    // accidentally "fixes" the ordering back into alignment is caught here,
    // not just silently re-opened.
    // -----------------------------------------------------------------------

    #[test]
    fn selector_is_content_based_not_positional() {
        // Each fixture's first three real <Group id="..."> V-numbers, in
        // RAW document order (via a simple linear scan, independent of
        // `parse_controls` itself).
        fn first_three_group_ids(xccdf: &str) -> Vec<&str> {
            let mut out = Vec::new();
            let mut rest = xccdf;
            while out.len() < 3 {
                let Some(start) = rest.find("<Group id=\"") else {
                    break;
                };
                let after = &rest[start + "<Group id=\"".len()..];
                let Some(end) = after.find('"') else { break };
                out.push(&after[..end]);
                rest = &after[end..];
            }
            out
        }

        // rhel10's raw document order is auth, ts, pw (V-281208, V-281209,
        // V-281210) -- the first 3 Groups ARE the 3 real families, but in
        // auth/ts/pw order, NOT `Family::ALL`'s auth/pw/ts order. A
        // positional impl mapping Family::ALL[0..3] onto document order 0..3
        // would assign V-281209 (the REAL timestamp_timeout Group) to
        // Family::PwFamily, and V-281210 (the REAL pw_family Group) to
        // Family::TimestampTimeout -- both wrong.
        assert_eq!(
            first_three_group_ids(RHEL10_FIXTURE),
            vec!["V-281208", "V-281209", "V-281210"],
            "rhel10's raw document order must be auth, ts, pw -- NOT Family::ALL's auth/pw/ts \
             order -- so a positional selector is caught"
        );

        // rhel9's raw document order is ts, pw, auth (V-258084, V-258085,
        // V-258086) -- fully reversed relative to Family::ALL.
        assert_eq!(
            first_three_group_ids(RHEL9_FIXTURE),
            vec!["V-258084", "V-258085", "V-258086"],
            "rhel9's raw document order must be ts, pw, auth"
        );

        // rhel8's first three Groups are NOT sudo-W04 controls AT ALL (3
        // wholly-unrelated Groups precede even the NOPASSWD decoy) -- a
        // positional impl taking "the first 3 Groups" fails immediately and
        // obviously here.
        assert_eq!(
            first_three_group_ids(RHEL8_FIXTURE),
            vec!["V-230221", "V-230222", "V-230223"],
            "rhel8's first three Groups must be wholly unrelated to sudo-W04"
        );
    }

    // -----------------------------------------------------------------------
    // BLOCKER 2 (adversarial round): the Group-level <title> trap. Every
    // fixture Group carries its REAL `<Group><title>` (the SRG requirement
    // id, e.g. "SRG-OS-000373-GPOS-00156"), immediately followed by the
    // Rule's own <title> (the real human-readable title). A selector reading
    // "the first <title> inside the Group" (rather than the Rule's own
    // <title>, after <version>) would extract the SRG id as the "title" --
    // this test catches that directly.
    // -----------------------------------------------------------------------

    #[test]
    fn group_level_title_is_never_used_as_the_control_title() {
        for fixture in [RHEL8_FIXTURE, RHEL9_FIXTURE, RHEL10_FIXTURE] {
            let d = parse_controls(fixture).expect("parses");
            for c in &d {
                assert!(
                    !c.title.starts_with("SRG-OS-"),
                    "a derived control's title must be the Rule's OWN human-readable \
                     title, never the Group-level SRG requirement id; got {:?}",
                    c.title
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decoy exclusion: every fixture carries at least one non-W04 Group (real
    // DISA content, the sudo-W01/W05 NOPASSWD control); rhel8 additionally
    // carries 3 further Groups with no bearing on sudo at all. A
    // correctly-scoped selector must EXCLUDE all of them. Exact-count
    // assertion (not just "NOPASSWD's id is absent") so a selector that
    // over-matches some OTHER, unexpected row also fails.
    // -----------------------------------------------------------------------

    #[test]
    fn decoys_excluded_exact_counts() {
        assert_eq!(
            parse_controls(RHEL8_FIXTURE).unwrap().len(),
            3,
            "rhel8: exactly 3 families out of 7 total Groups (3 unrelated + the NOPASSWD \
             decoy V-230271/RHEL-08-010380 all excluded)"
        );
        assert_eq!(
            parse_controls(RHEL9_FIXTURE).unwrap().len(),
            3,
            "rhel9: exactly 3 families, the NOPASSWD decoy (V-258106 / RHEL-09-611085) excluded"
        );
        assert_eq!(
            parse_controls(RHEL10_FIXTURE).unwrap().len(),
            3,
            "rhel10: exactly 3 families, the NOPASSWD decoy (V-281211 / RHEL-10-600560) excluded"
        );
    }

    #[test]
    fn decoy_rule_ids_never_appear_in_derived_table() {
        for (fixture, decoy_ids) in [
            (
                RHEL8_FIXTURE,
                vec![
                    "RHEL-08-010380",
                    "RHEL-08-010000",
                    "RHEL-08-010010",
                    "RHEL-08-010020",
                ],
            ),
            (RHEL9_FIXTURE, vec!["RHEL-09-611085"]),
            (RHEL10_FIXTURE, vec!["RHEL-10-600560"]),
        ] {
            let d = parse_controls(fixture).unwrap();
            for decoy_id in decoy_ids {
                assert!(
                    d.iter().all(|c| c.rule_id != decoy_id),
                    "the decoy id {decoy_id:?} must never appear in the derived W04 table; got {d:?}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Item 4: anti-vacuity. A parse bug (or a wrong file) that finds 0 -- or
    // fewer than the mandatory 3 -- sudo-W04 families must fail CLOSED, never
    // silently report an empty/partial `Ok` that a caller could mistake for
    // "0 drift". CONCERN (adversarial round): the error text must contain the
    // literal substring "found 0" / "found 1" -- a looser `err.contains('0')`
    // is satisfied by unrelated digits echoed into the message (e.g. the
    // substring "sudo-W04" itself contains a '0'; any echoed "RHEL-10-..."
    // contains a '1'), so a wrong impl that always reports "found 1" (never
    // actually counting) could pass a weaker assertion for BOTH the zero and
    // the one-of-three cases.
    // -----------------------------------------------------------------------

    #[test]
    fn zero_matched_families_is_an_error() {
        // A well-formed XCCDF Group carrying NONE of the 3 sudo-W04 families'
        // distinguishing text (not `!authenticate`, not targetpw/rootpw/runaspw,
        // not timestamp_timeout) -- e.g. an unrelated control.
        let doc = r#"<Benchmark><Group id="V-1"><Rule id="SV-1_rule"><version>RHEL-10-999999</version>
            <title>An unrelated control with no bearing on sudo-W04.</title>
            <fixtext>Do something unrelated to sudo.</fixtext>
            <check system="C-1"><check-content>Verify something unrelated to sudo entirely.
            If not configured, this is a finding.</check-content></check>
            </Rule></Group></Benchmark>"#;
        let err = parse_controls(doc)
            .expect_err("zero matched sudo-W04 families must fail closed, not Ok(empty)");
        assert!(
            err.contains("found 0"),
            "the error must literally contain \"found 0\" (not merely SOME digit 0 \
             somewhere in unrelated text); got {err:?}"
        );
    }

    /// A weaker parser regression than total vacuity: only 1 of the 3
    /// MANDATORY families found (using the REAL rhel10 `!authenticate` Group,
    /// verbatim, standalone) must ALSO fail closed, not silently return a
    /// 1-row `Ok` that a caller could mistake for "found everything, 0
    /// drift". W04 is exactly 3 families, always -- a partial match is never
    /// a valid steady state.
    #[test]
    fn fewer_than_three_matched_families_is_an_error() {
        let doc = r#"<Benchmark>
            <Group id="V-281208"><Rule id="SV-281208r1166576_rule" weight="10.0" severity="medium"><version>RHEL-10-600530</version><title>RHEL 10 must require users to reauthenticate for privilege escalation.</title><fixtext fixref="F-85674r1166575_fix">Configure RHEL 10 to not allow users to execute privileged actions without authenticating.

Remove any occurrence of "!authenticate" found in the "/etc/sudoers" file or files in the "/etc/sudoers.d" directory:

$ sudo sed -i '/\!authenticate/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*</fixtext><check system="C-85769r1166574_chk"><check-content>Verify RHEL 10 "/etc/sudoers" has no occurrences of "!authenticate" with the following command:

$ sudo grep -ir '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" are returned, this is a finding.</check-content></check></Rule></Group>
            </Benchmark>"#;
        let err = parse_controls(doc)
            .expect_err("only 1 of 3 mandatory families found must fail closed, not Ok(1 row)");
        assert!(
            err.contains("found 1"),
            "the error must literally contain \"found 1\" (not merely SOME digit 1 \
             somewhere in echoed text, e.g. from \"RHEL-10-...\"); got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Impl-aware adversarial review, post-#551 GREEN (round 1): the anti-vacuity
    // guard above (`out.len() < Family::ALL.len()`) counts ROWS, not DISTINCT
    // families, so it is completely unguarded against the OVER-match direction.
    // These two tests close that gap.
    // -----------------------------------------------------------------------

    /// MISS 1 (the serious one): a future DISA revision that ADDS a second
    /// Rule to an already-matched family (two `!authenticate` Rules, plus one
    /// Rule each for the other two mandatory families -- 4 rows, all 3
    /// families "covered") must fail CLOSED, never silently resolve the
    /// duplicate via first-wins and report a clean `Ok(4 rows)`. A
    /// drift-detection tool reporting "no drift" when upstream added a
    /// control it silently dropped is worse than useless. Mirrors
    /// `tools/sshd-stig-update`'s `duplicate_keyword_is_error` (same shape,
    /// keyed by `Family` instead of keyword): fail closed naming the
    /// over-matched family and BOTH V-numbers.
    #[test]
    fn duplicate_family_is_an_error() {
        let doc = r#"<Benchmark>
            <Group id="V-281208"><Rule id="SV-281208r1166576_rule"><version>RHEL-10-600530</version>
            <title>RHEL 10 must require users to reauthenticate for privilege escalation.</title>
            <fixtext>Remove any occurrence of "!authenticate" found in "/etc/sudoers".</fixtext>
            <check><check-content>Verify RHEL 10 "/etc/sudoers" has no occurrences of "!authenticate".
            If any occurrences of "!authenticate" are returned, this is a finding.</check-content></check>
            </Rule></Group>
            <Group id="V-281299"><Rule id="SV-281299r9999999_rule"><version>RHEL-10-600535</version>
            <title>RHEL 10 sudoers.d drop-in files must not contain "!authenticate".</title>
            <fixtext>Remove any occurrence of "!authenticate" found in files in "/etc/sudoers.d".</fixtext>
            <check><check-content>Verify RHEL 10 "/etc/sudoers.d" has no occurrences of "!authenticate".
            If any occurrences of "!authenticate" are returned, this is a finding.</check-content></check>
            </Rule></Group>
            <Group id="V-281210"><Rule id="SV-281210r1166582_rule"><version>RHEL-10-600550</version>
            <title>RHEL 10 must use the invoking user's password for privilege escalation.</title>
            <fixtext>Defaults !targetpw
            Defaults !rootpw
            Defaults !runaspw</fixtext>
            <check><check-content>Verify RHEL 10 sudoers uses targetpw/rootpw/runaspw.
            If no results are returned, this is a finding.</check-content></check></Rule></Group>
            <Group id="V-281209"><Rule id="SV-281209r1166579_rule"><version>RHEL-10-600540</version>
            <title>RHEL 10 must require reauthentication when using the "sudo" command.</title>
            <fixtext>Defaults timestamp_timeout=0</fixtext>
            <check><check-content>Verify RHEL 10 requires reauthentication via timestamp_timeout.
            If "timestamp_timeout" is set to a negative number, this is a finding.</check-content></check>
            </Rule></Group>
            </Benchmark>"#;
        let err = parse_controls(doc).expect_err(
            "a duplicated family (2 Rules for Authenticate) must fail closed, not Ok(4 rows)",
        );
        assert!(
            err.contains("authenticate"),
            "the error must name the over-matched family; got {err:?}"
        );
        assert!(
            err.contains("V-281208") && err.contains("V-281299"),
            "the error must name BOTH V-numbers of the duplicated family; got {err:?}"
        );
    }

    /// MISS 2: a weaker but still-wrong classification. Three rows, but ALL
    /// belonging to the SAME single family (Authenticate) -- 1 DISTINCT
    /// family, 3 rows. The row-counting guard (`out.len() < 3`) sees 3 rows
    /// and lets this through as `Ok`, which upstream's `diff_controls`
    /// (keyed by `Family`, `.find()`) then reports as 3 `~`/`-`/`+` lines --
    /// actively instructing a maintainer to DELETE two real, still-present
    /// DISA citations for families this document never touched. The guard
    /// must count DISTINCT families, not rows, and fail closed with the
    /// literal substring "found 1" (the actual family count).
    #[test]
    fn three_rows_of_one_family_is_an_error() {
        let one = |v: &str, rule_id: &str| {
            format!(
                r#"<Group id="{v}"><Rule id="SV-{v}_rule"><version>{rule_id}</version>
                <title>t</title><fixtext>f</fixtext>
                <check><check-content>!authenticate. If found, this is a finding.</check-content></check>
                </Rule></Group>"#
            )
        };
        let doc = format!(
            "<Benchmark>{}{}{}</Benchmark>",
            one("V-1", "RHEL-10-900000"),
            one("V-2", "RHEL-10-900001"),
            one("V-3", "RHEL-10-900002")
        );
        let err = parse_controls(&doc).expect_err(
            "3 rows of ONE family (2 mandatory families entirely missing) must fail closed",
        );
        assert!(
            err.contains("found 1"),
            "the error must literally contain \"found 1\" (the DISTINCT family count, not \
             the 3-row count); got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Mutation-gate hardening (post-#551 GREEN, round 2): the PwFamily branch
    // is a 3-way disjunction (`targetpw || rootpw || runaspw`), but every real
    // DISA fixture's pw-family Rule enumerates ALL THREE keywords in the same
    // check-content/fixtext (measured: rhel8/9/10 each contain targetpw=4,
    // rootpw=4, runaspw=4 occurrences), so replacing either `||` with `&&`
    // still matches every fixture-driven test above and survives mutation
    // testing -- the disjunction's branching is never actually exercised by
    // any of them. These three tests use a synthetic Rule whose check-content
    // mentions ONLY ONE of the three keywords -- the realistic case of a
    // future DISA revision rewording the check text down to a single option
    // -- and assert the classifier still resolves it to `Family::PwFamily`.
    // Each synthetic document also carries a real Authenticate and
    // TimestampTimeout Rule so the mandatory-3-family anti-vacuity gate above
    // is satisfied and `parse_controls` reaches `Ok` rather than failing
    // closed on an unrelated ground (see `fewer_than_three_matched_families_
    // is_an_error`, which already covers the "too few families" path).
    // -----------------------------------------------------------------------

    /// Build a synthetic 3-family XCCDF document where the pw-family Rule's
    /// check-content is exactly `pw_check_content` (so the caller controls
    /// which of the three keywords, if any, appear). The other two Rules
    /// (Authenticate, TimestampTimeout) are fixed and unrelated to the pw
    /// keywords, so only the pw-family classification varies across callers.
    fn synthetic_doc_with_pw_check_content(pw_check_content: &str) -> String {
        format!(
            r#"<Benchmark>
            <Group id="V-900001"><Rule id="SV-900001_rule"><version>RHEL-10-900010</version>
            <title>Synthetic authenticate control.</title>
            <fixtext>Remove any occurrence of "!authenticate" found in "/etc/sudoers".</fixtext>
            <check><check-content>Verify no occurrences of "!authenticate" are present.
            If any occurrences of "!authenticate" are returned, this is a finding.</check-content></check>
            </Rule></Group>
            <Group id="V-900002"><Rule id="SV-900002_rule"><version>RHEL-10-900020</version>
            <title>Synthetic pw-family control.</title>
            <fixtext>Synthetic fixtext, deliberately naming none of the three pw keywords itself.</fixtext>
            <check><check-content>{pw_check_content}</check-content></check>
            </Rule></Group>
            <Group id="V-900003"><Rule id="SV-900003_rule"><version>RHEL-10-900030</version>
            <title>Synthetic timestamp_timeout control.</title>
            <fixtext>Defaults timestamp_timeout=0</fixtext>
            <check><check-content>Verify timestamp_timeout is set appropriately.
            If "timestamp_timeout" is set to a negative number, this is a finding.</check-content></check>
            </Rule></Group>
            </Benchmark>"#
        )
    }

    #[test]
    fn pw_family_matches_on_targetpw_alone() {
        let doc = synthetic_doc_with_pw_check_content(
            "Verify sudoers uses targetpw. If no results are returned, this is a finding.",
        );
        let d = parse_controls(&doc)
            .expect("all 3 mandatory families present (one keyword each) -- must parse");
        let pw = find(&d, Family::PwFamily);
        assert_eq!(
            pw.rule_id, "RHEL-10-900020",
            "a check-content naming ONLY \"targetpw\" (no rootpw, no runaspw) must still \
             classify as Family::PwFamily"
        );
    }

    #[test]
    fn pw_family_matches_on_rootpw_alone() {
        let doc = synthetic_doc_with_pw_check_content(
            "Verify sudoers uses rootpw. If no results are returned, this is a finding.",
        );
        let d = parse_controls(&doc)
            .expect("all 3 mandatory families present (one keyword each) -- must parse");
        let pw = find(&d, Family::PwFamily);
        assert_eq!(
            pw.rule_id, "RHEL-10-900020",
            "a check-content naming ONLY \"rootpw\" (no targetpw, no runaspw) must still \
             classify as Family::PwFamily"
        );
    }

    #[test]
    fn pw_family_matches_on_runaspw_alone() {
        let doc = synthetic_doc_with_pw_check_content(
            "Verify sudoers uses runaspw. If no results are returned, this is a finding.",
        );
        let d = parse_controls(&doc)
            .expect("all 3 mandatory families present (one keyword each) -- must parse");
        let pw = find(&d, Family::PwFamily);
        assert_eq!(
            pw.rule_id, "RHEL-10-900020",
            "a check-content naming ONLY \"runaspw\" (no targetpw, no rootpw) must still \
             classify as Family::PwFamily"
        );
    }
}
