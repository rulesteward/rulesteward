//! CIS-baseline projection for `sshd_config`: a per-product CIS Benchmark
//! control table, plus `Framework::Cis` [`ControlRef`] attachment onto the
//! sshd-W01/W02 findings whose directive is ALSO a CIS-controlled keyword
//! (issue #525, v0.8 Wave 3).
//!
//! Grounded in the `tools/cis-update` `derive` output for the `sshd` family at
//! the ComplianceAsCode pin `519b5fe8ce338cfa25d53065bcb3759aafe8d36d`:
//! `derive-rhel{8,9,10}-sshd.txt` (session `9f-v0_8-wave3-cis` grounding). Every
//! product carries the SAME shape -- 15 controls, 16 rule mappings, 2 variable
//! selections -- but DIFFERENT control ids per product (CIS Benchmark v4.0.0 /
//! v2.0.0 / v1.0.1 for RHEL 8 / 9 / 10 respectively renumber the same rule).
//!
//! # Row granularity: one row per RULE MAPPING, not per control
//!
//! [`cis_baseline`] returns 16 rows (matching the grounding's "16 rule
//! mappings"), because two controls each cover two directives: `5.1.9` covers
//! both `ClientAliveInterval` (rule `sshd_set_idle_timeout`) and
//! `ClientAliveCountMax` (rule `sshd_set_keepalive`). The `MaxAuthTries` control
//! also has a `sshd_max_auth_tries_value=4` variable SELECTION alongside its
//! `sshd_set_max_auth_tries` rule; the selection is excluded here (selections are
//! the benchmark's explicit value choice, not a rule, and this lane attaches no
//! new value-comparison lint). 15 distinct control ids result from those 16 rows.
//!
//! # Scope: attachment happens only at EXISTING attach sites
//!
//! Only sshd-W01 (required-directive-missing) and sshd-W02 (weaker-than-baseline
//! value) currently call [`crate::lints::stig`]'s `stig_control_ref` to attach a
//! typed control; sshd-W05 (Match override) and sshd-F02 (drop-in override) reuse
//! `baseline_check`'s comparison LOGIC but attach no `ControlRef` at all today, so
//! there is nothing to double-attach there. Ten of the sixteen CIS-mapped
//! directives overlap the STIG-required set (on the targets where STIG requires
//! them) and therefore gain a `Cis` ref alongside the existing `Stig` ref: `banner`,
//! `clientaliveinterval`, `clientalivecountmax`, `gssapiauthentication`,
//! `permitemptypasswords`, `permitrootlogin`, and `permituserenvironment` on EVERY
//! target; `ignorerhosts`, `loglevel`, and `usepam` on RHEL9/RHEL10 only (STIG
//! never required them on RHEL8, so RHEL8's W01/W02 emit nothing for them to
//! attach to). The remaining six CIS rules (`sshd_limit_user_access`,
//! `sshd_disable_forwarding`, `sshd_set_login_grace_time`, `sshd_set_max_auth_tries`,
//! `sshd_set_max_sessions`, `sshd_set_maxstartups`) have NO existing sshd lint
//! emitting a diagnostic for their directive(s) -- the `sshd-` code taxonomy is
//! FROZEN (`catalog.rs`, epic #149) and adding a new pass is out of this lane's
//! scope, so [`cis_control_ref`] returns `None` for them on every target.
//!
//! # License discipline
//!
//! Only CIS control ids and the CaC `title:` field (the short "Ensure sshd X is
//! configured (Automated)" string, itself BSD-3-Clause-sourced and printed
//! verbatim by `tools/cis-update derive`) appear anywhere in this module. No
//! benchmark rationale/prose.
// Directive keyword names appear as plain identifiers in prose throughout this
// module (e.g. `PermitRootLogin`, `ClientAliveInterval`); see stig.rs for the
// same allow + rationale.
#![allow(clippy::doc_markdown)]

use rulesteward_core::ControlRef;

use crate::lints::TargetVersion;

/// One CIS-Benchmark-controlled sshd rule, projected for [`cis_baseline`] and the
/// future `cis-update` drift tool: the control id (product-specific), the CaC rule
/// identifier (`sshd_*`, verbatim from the pinned controls file), and the control's
/// `title:` field (verbatim, `(Automated)`/etc. suffix included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CisControl {
    /// CIS Benchmark control id for the target product (e.g. `"5.1.22"`).
    /// DIFFERS across rhel8/rhel9/rhel10 for the same rule -- see module doc.
    pub id: &'static str,
    /// The ComplianceAsCode rule identifier (e.g. `"sshd_disable_root_login"`).
    pub rule: &'static str,
    /// The control's CaC `title:` field, verbatim (e.g.
    /// `"Ensure sshd PermitRootLogin is disabled (Automated)"`).
    pub title: &'static str,
}

/// The full sshd CIS Benchmark table for `target`: 16 rows (one per rule
/// mapping; two controls each cover two directives, so this is one row PER RULE,
/// not per control -- 15 distinct `id`s result). Grounded verbatim in
/// `derive-rhel{8,9,10}-sshd.txt` (pin `519b5fe8ce338cfa25d53065bcb3759aafe8d36d`).
///
/// Excludes the two `name=option` variable SELECTIONS (`sshd_idle_timeout_value=
/// 5_minutes`, `sshd_max_auth_tries_value=4`): those are the benchmark's explicit
/// value choice for an existing rule, not a rule of their own, and this lane adds
/// no new value-comparison lint that would consume them.
#[must_use]
pub fn cis_baseline(_target: TargetVersion) -> &'static [CisControl] {
    todo!("issue #525: populate the per-product sshd CIS table")
}

/// Build the typed CIS [`ControlRef`] for `keyword_lower` on `target`, or `None`
/// when the keyword has no EXISTING sshd attach site for CIS (either because no
/// sshd lint emits a diagnostic for it at all, or -- for `ignorerhosts`/
/// `loglevel`/`usepam` -- because STIG (and therefore W01/W02) does not check it
/// on this particular target). `target = None` uses the RHEL8 floor, mirroring
/// [`crate::lints::stig::baseline_check`]'s `target=None` convention.
///
/// `pub(crate)` so sshd-W01/W02 (in `stig.rs`) can attach this CIS ref ALONGSIDE
/// the existing `stig_control_ref` result, never replacing it (issue #525's
/// no-double-attach / no-dropped-Stig requirement).
///
/// Not yet called from `stig.rs`'s W01/W02 emit sites (that wiring is the
/// implementer's job, not this test-author lane's); `#[allow(dead_code)]` keeps
/// the non-test build (which doesn't see this module's `#[cfg(test)]` callers)
/// clean of a false "never used" until that wiring lands.
#[allow(dead_code)]
pub(crate) fn cis_control_ref(
    _keyword_lower: &str,
    _target: Option<TargetVersion>,
) -> Option<ControlRef> {
    todo!("issue #525: resolve the CIS ControlRef for a STIG-overlap keyword")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Framework;

    // --- cis_baseline: single-source table, grounded verbatim -----------------

    #[test]
    fn cis_baseline_has_sixteen_rule_mappings_and_fifteen_distinct_ids() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let table = cis_baseline(target);
            assert_eq!(
                table.len(),
                16,
                "sshd CIS table must have 16 rule-mapping rows ({target:?})"
            );
            let unique_ids: std::collections::BTreeSet<&str> = table.iter().map(|c| c.id).collect();
            assert_eq!(
                unique_ids.len(),
                15,
                "sshd CIS table must resolve to 15 distinct control ids ({target:?})"
            );
        }
    }

    #[test]
    fn cis_baseline_matches_grounding_for_permitrootlogin() {
        // `sshd_disable_root_login` / "Ensure sshd PermitRootLogin is disabled
        // (Automated)": id DIFFERS rhel8 vs rhel9/rhel10 (5.1.22 vs 5.1.20), title
        // is uniform. Straight from derive-rhel{8,9,10}-sshd.txt.
        for (target, expect_id) in [
            (TargetVersion::Rhel8, "5.1.22"),
            (TargetVersion::Rhel9, "5.1.20"),
            (TargetVersion::Rhel10, "5.1.20"),
        ] {
            let table = cis_baseline(target);
            let row = table
                .iter()
                .find(|c| c.rule == "sshd_disable_root_login")
                .unwrap_or_else(|| panic!("sshd_disable_root_login present ({target:?})"));
            assert_eq!(row.id, expect_id, "control id ({target:?})");
            assert_eq!(
                row.title, "Ensure sshd PermitRootLogin is disabled (Automated)",
                "title ({target:?})"
            );
        }
    }

    #[test]
    fn cis_baseline_matches_grounding_for_banner_three_way() {
        // Banner is the sharpest 3-way differentiator: EVERY product assigns it a
        // DISTINCT id (5.1.7 / 5.1.8 / 5.1.5), so a wrong impl that hardcodes one
        // id (or ignores `target` entirely) fails this test on at least one arm.
        for (target, expect_id) in [
            (TargetVersion::Rhel8, "5.1.7"),
            (TargetVersion::Rhel9, "5.1.8"),
            (TargetVersion::Rhel10, "5.1.5"),
        ] {
            let table = cis_baseline(target);
            let row = table
                .iter()
                .find(|c| c.rule == "sshd_enable_warning_banner_net")
                .unwrap_or_else(|| panic!("sshd_enable_warning_banner_net present ({target:?})"));
            assert_eq!(row.id, expect_id, "control id ({target:?})");
            assert_eq!(
                row.title, "Ensure sshd Banner is configured (Automated)",
                "title ({target:?})"
            );
        }
    }

    #[test]
    fn cis_baseline_multi_directive_control_covers_both_clientalive_rules() {
        // Control 5.1.9 (rhel8/rhel9) / 5.1.7 (rhel10) covers TWO rules
        // (`sshd_set_idle_timeout` -> ClientAliveInterval, `sshd_set_keepalive` ->
        // ClientAliveCountMax) sharing one id and title -- the reason the table has
        // 16 rows but only 15 distinct ids.
        let table = cis_baseline(TargetVersion::Rhel9);
        let idle = table
            .iter()
            .find(|c| c.rule == "sshd_set_idle_timeout")
            .expect("sshd_set_idle_timeout present");
        let keepalive = table
            .iter()
            .find(|c| c.rule == "sshd_set_keepalive")
            .expect("sshd_set_keepalive present");
        assert_eq!(idle.id, "5.1.9");
        assert_eq!(keepalive.id, "5.1.9");
        assert_eq!(idle.title, keepalive.title);
        assert_eq!(
            idle.title,
            "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (Automated)"
        );
    }

    // --- cis_control_ref: the runtime attach lookup ----------------------------

    #[test]
    fn cis_control_ref_resolves_banner_on_every_product_with_its_title() {
        for (target, expect_id) in [
            (TargetVersion::Rhel8, "5.1.7"),
            (TargetVersion::Rhel9, "5.1.8"),
            (TargetVersion::Rhel10, "5.1.5"),
        ] {
            let control = cis_control_ref("banner", Some(target))
                .unwrap_or_else(|| panic!("banner resolves a CIS control ({target:?})"));
            assert_eq!(control.framework, Framework::Cis);
            assert_eq!(control.id, expect_id, "id ({target:?})");
            assert_eq!(
                control.name,
                Some("Ensure sshd Banner is configured (Automated)".to_string()),
                "the CaC title must surface via ControlRef::name ({target:?})"
            );
        }
    }

    #[test]
    fn cis_control_ref_none_target_mirrors_rhel8_floor() {
        // Matches `stig_control_ref`'s `target.unwrap_or(TargetVersion::Rhel8)`
        // convention (stig.rs).
        let floor =
            cis_control_ref("permitrootlogin", None).expect("floor resolves permitrootlogin");
        let rhel8 = cis_control_ref("permitrootlogin", Some(TargetVersion::Rhel8))
            .expect("rhel8 resolves permitrootlogin");
        assert_eq!(floor, rhel8, "target=None must equal the RHEL8 result");
    }

    #[test]
    fn cis_control_ref_scoped_to_rhel9_10_for_stig_gated_keywords() {
        // ignorerhosts/loglevel/usepam only have a STIG (and therefore CIS) attach
        // site on RHEL9/RHEL10 -- RHEL8's W01/W02 never check them (stig.rs
        // `RHEL8_REQUIRED` omits all three), so there is no diagnostic on RHEL8 to
        // attach a Cis ref to.
        assert!(
            cis_control_ref("ignorerhosts", Some(TargetVersion::Rhel8)).is_none(),
            "ignorerhosts has no RHEL8 attach site"
        );
        let ignorerhosts9 = cis_control_ref("ignorerhosts", Some(TargetVersion::Rhel9))
            .expect("ignorerhosts resolves on rhel9");
        assert_eq!(ignorerhosts9.id, "5.1.13");
        assert_eq!(
            ignorerhosts9.name,
            Some("Ensure sshd IgnoreRhosts is enabled (Automated)".to_string())
        );

        assert!(
            cis_control_ref("usepam", Some(TargetVersion::Rhel8)).is_none(),
            "usepam has no RHEL8 attach site"
        );
        let usepam9 = cis_control_ref("usepam", Some(TargetVersion::Rhel9))
            .expect("usepam resolves on rhel9");
        assert_eq!(usepam9.id, "5.1.22");

        assert!(
            cis_control_ref("loglevel", Some(TargetVersion::Rhel8)).is_none(),
            "loglevel has no RHEL8 attach site"
        );
        let loglevel10 = cis_control_ref("loglevel", Some(TargetVersion::Rhel10))
            .expect("loglevel resolves on rhel10");
        assert_eq!(loglevel10.id, "5.1.14");
    }

    #[test]
    fn cis_control_ref_none_for_directives_without_an_existing_attach_site() {
        // These six are real CIS controls (present in `cis_baseline`), but no sshd
        // lint currently emits ANY diagnostic for maxauthtries/logingracetime/
        // maxsessions/maxstartups/disableforwarding/the access-control directives
        // -- the sshd- taxonomy is FROZEN (catalog.rs) and this lane adds no new
        // pass. `cis_control_ref` must return `None` on every target: there is no
        // finding to attach to.
        for kw in [
            "maxauthtries",
            "logingracetime",
            "maxsessions",
            "maxstartups",
            "disableforwarding",
            "allowusers",
        ] {
            for target in [
                TargetVersion::Rhel8,
                TargetVersion::Rhel9,
                TargetVersion::Rhel10,
            ] {
                assert!(
                    cis_control_ref(kw, Some(target)).is_none(),
                    "{kw} has no existing sshd attach site; must be None ({target:?})"
                );
            }
        }
    }
}
