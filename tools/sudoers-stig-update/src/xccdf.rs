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
//! # STUBBED (9j lane 6, RED phase, #551)
//!
//! [`parse_controls`] is `todo!()`: this lane authors the RED test contract
//! only. A GREEN implementation must, per the fixtures in
//! `tests/fixtures/rhelN_sudoers_controls.xml` (real, trimmed DISA XCCDF
//! extracts, verbatim `check-content`/`fixtext`, verified at authoring time):
//!
//! * Select a `<Group>`/`<Rule>` as a sudo-W04 control IFF its `check-content`
//!   (or `fixtext`) contains one of the three families' distinguishing text:
//!   - [`crate::derive::Family::Authenticate`][]: `!authenticate` (case-insensitive).
//!   - [`crate::derive::Family::PwFamily`][]: `targetpw` / `rootpw` / `runaspw`
//!     (any of the three; a single DISA Rule covers all three settings together).
//!   - [`crate::derive::Family::TimestampTimeout`][]: `timestamp_timeout`.
//! * EXCLUDE a `NOPASSWD`-checking Rule (the sudo-W01/W05 sibling control,
//!   present as a decoy in every fixture) -- it shares the same `/etc/sudoers`
//!   check-content idiom but is a DIFFERENT lint (`sudo-W01`/`sudo-W05`, not
//!   `sudo-W04`), and must never be misclassified into one of the three
//!   families above.
//! * The V-number is `<Group id="...">`; the STIG Rule id is `<Rule><version>`
//!   (mirrors `tools/sshd-stig-update`'s `#507` convention); the title is
//!   `<Rule><title>` (the FIRST `<title>` inside `<Rule>`, immediately after
//!   `<version>` -- NOT the `<Group>`-level `<title>` on RHEL 8/9/10's real
//!   XCCDF, which instead carries the SRG requirement id, not a human title;
//!   verified against the committed fixtures at authoring time).
//! * Fail CLOSED (return `Err`, never a silently-empty `Ok`) when FEWER than
//!   all 3 families are matched -- see
//!   `tests::zero_matched_families_is_an_error` and
//!   `tests::fewer_than_three_matched_families_is_an_error` below. A parse
//!   regression (or a wrong file being fed in) must never present as "0
//!   drift, 0 controls" -- that is a silent false pass, not a clean one.

use crate::derive::DerivedControl;

/// Parse a full DISA XCCDF benchmark into the normalized sudo-W04 control
/// table (exactly 3 rows: one per [`Family`]). Fails CLOSED (returns `Err`)
/// when fewer than all 3 families are found -- see the module doc's
/// anti-vacuity requirement.
pub fn parse_controls(_xccdf: &str) -> Result<Vec<DerivedControl>, String> {
    todo!(
        "GREEN (#551): select each of the 3 sudo-W04 families' Group/Rule by \
         check-content keyword, extract v_number (<Group id>) / rule_id (<version>) / \
         title (<Rule><title>), EXCLUDE the NOPASSWD decoy, and fail closed (Err) on \
         fewer than 3 matched families -- see this module's doc comment"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::Family;

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
    // cross-checked by grep at authoring time -- see this crate's
    // stig-refs.toml CURRENCY NOTE for what is / is not independently
    // re-verified against the newer V2R8/V2R9/V1R2 revisions).
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
    // Decoy exclusion: every fixture carries a 4th Group (real DISA content,
    // the sudo-W01/W05 NOPASSWD control) that a correctly-scoped selector must
    // EXCLUDE. Exact-count assertion (not just "NOPASSWD's id is absent") so a
    // selector that over-matches some OTHER, unexpected 4th row also fails.
    // -----------------------------------------------------------------------

    #[test]
    fn decoy_nopasswd_group_excluded_exact_counts() {
        assert_eq!(
            parse_controls(RHEL8_FIXTURE).unwrap().len(),
            3,
            "rhel8: exactly 3 families, the NOPASSWD decoy (V-230271 / RHEL-08-010380) excluded"
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
    fn decoy_nopasswd_rule_id_never_appears_in_derived_table() {
        for (fixture, decoy_id) in [
            (RHEL8_FIXTURE, "RHEL-08-010380"),
            (RHEL9_FIXTURE, "RHEL-09-611085"),
            (RHEL10_FIXTURE, "RHEL-10-600560"),
        ] {
            let d = parse_controls(fixture).unwrap();
            assert!(
                d.iter().all(|c| c.rule_id != decoy_id),
                "the NOPASSWD decoy id {decoy_id:?} must never appear in the derived W04 table; got {d:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Item 4: anti-vacuity. A parse bug (or a wrong file) that finds 0 -- or
    // fewer than the mandatory 3 -- sudo-W04 families must fail CLOSED, never
    // silently report an empty/partial `Ok` that a caller could mistake for
    // "0 drift".
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
            err.contains('0'),
            "the error must name the count found (0); got {err:?}"
        );
        assert!(
            err.to_lowercase().contains("sudo-w04")
                || err.to_lowercase().contains("authenticate")
                || err.to_lowercase().contains("family")
                || err.to_lowercase().contains("families"),
            "the error must explain what was being looked for; got {err:?}"
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
            err.contains('1'),
            "the error must name the count found (1); got {err:?}"
        );
    }
}
