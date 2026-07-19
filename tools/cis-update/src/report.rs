//! Pure rendering, health, and drift logic for the `derive` / `check`
//! subcommands. Everything user-visible is produced here so the exact wording -
//! parsed by CI and read by humans - is unit-locked; `main.rs` stays glue.

use std::collections::BTreeMap;

use stig_update::derive::DerivedKey;

use crate::controls::{CisControl, Header, Status};
use crate::family::Family;
use crate::registry::{Shipped, ShippedControl};

/// The live anchor pairs `check` asserts inside the derived sudoers family:
/// (control id, mapped rule). Uniform across rhel8 v4.0.0 / rhel9 v2.0.0 /
/// rhel10 v1.0.1 at the pinned ref (grounded 2026-07-18). The ids sudo-W04
/// currently ships (1.3.2/1.3.3) are the OLDER benchmark generation - lane #526
/// absorbs that renumber; the gate pins the pinned-CaC truth.
pub const ANCHORS: [(&str, &str); 2] = [
    ("5.2.2", "sudo_add_use_pty"),
    ("5.2.3", "sudo_custom_logfile"),
];

/// A health failure's severity depends on where it happened: at a PINNED ref the
/// derivation is supposed to be reproducible, so a missing family/anchor is a
/// tool or pin misconfiguration (exit 2); under `--latest` it is upstream change
/// (a restructure/renumber that invalidates shipped ControlRef ids), which is
/// exactly what the drift report exists to surface (exit 1).
#[derive(Debug, PartialEq, Eq)]
pub enum HealthFailure {
    PinnedMisconfiguration(String),
    UpstreamDrift(String),
}

pub fn classify_health_failure(latest: bool, msg: String) -> HealthFailure {
    if latest {
        HealthFailure::UpstreamDrift(msg)
    } else {
        HealthFailure::PinnedMisconfiguration(msg)
    }
}

/// Assert every family derived at least one control for `product`.
pub fn family_health(
    groups: &BTreeMap<Family, Vec<CisControl>>,
    product: &str,
) -> Result<(), String> {
    let missing: Vec<&str> = Family::ALL
        .into_iter()
        .filter(|f| groups.get(f).is_none_or(Vec::is_empty))
        .map(Family::as_str)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{product}: empty families in the derived table: {}",
            missing.join(", ")
        ))
    }
}

/// Assert the derived sudoers rows contain every [`ANCHORS`] pair.
pub fn verify_anchors(product: &str, sudoers_rows: &[CisControl]) -> Result<(), String> {
    let missing: Vec<String> = ANCHORS
        .into_iter()
        .filter(|(id, rule)| {
            !sudoers_rows
                .iter()
                .any(|c| c.id == *id && c.rules.iter().any(|r| r == rule))
        })
        .map(|(id, rule)| format!("{id} -> {rule}"))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{product}/sudoers: anchor control(s) missing from the derived table: {}",
            missing.join(", ")
        ))
    }
}

/// The exact per-family skip line for a `Pending` registry slot.
#[must_use]
pub fn skip_line(product: &str, family: Family, derived_count: usize, lane_issue: u32) -> String {
    format!(
        "{product}/{}: no shipped table yet - SKIPPED ({derived_count} controls derived, awaiting lane #{lane_issue})",
        family.as_str()
    )
}

/// Drift lines for one family: AUTOMATED-status derived ids vs shipped ids.
/// (`manual`/`partial`/... controls are not shipped as lint coverage by default,
/// so they do not count against the shipped table.) Empty result == no drift.
#[must_use]
pub fn diff_family(derived: &[CisControl], shipped: &[ShippedControl]) -> Vec<String> {
    let automated: BTreeMap<&str, &CisControl> = derived
        .iter()
        .filter(|c| c.status == Status::Automated)
        .map(|c| (c.id.as_str(), c))
        .collect();
    let shipped_ids: std::collections::BTreeSet<&str> =
        shipped.iter().map(|s| s.id.as_str()).collect();

    let mut ids: Vec<&str> = automated
        .keys()
        .chain(shipped_ids.iter())
        .copied()
        .collect();
    ids.sort_unstable();
    ids.dedup();

    let mut out = Vec::new();
    for id in ids {
        match (shipped_ids.contains(id), automated.get(id)) {
            (true, None) => out.push(format!("- {id}  (in code, absent upstream)")),
            (false, Some(c)) => out.push(format!("+ {id} [{}]  (new upstream)", c.rules.join(","))),
            _ => {}
        }
    }
    out
}

/// The `check` report block for one (product, family): the lines to print and
/// whether they represent drift.
#[must_use]
pub fn check_family(
    product: &str,
    family: Family,
    rows: &[CisControl],
    shipped: &Shipped,
) -> (Vec<String>, bool) {
    match shipped {
        Shipped::Pending { lane_issue } => (
            vec![skip_line(product, family, rows.len(), *lane_issue)],
            false,
        ),
        Shipped::Table(table) => {
            let diff = diff_family(rows, table);
            if diff.is_empty() {
                (
                    vec![format!("{product}/{}: OK (0 drift)", family.as_str())],
                    false,
                )
            } else {
                let mut lines = vec![format!(
                    "{product}/{}: DRIFT ({} change(s))",
                    family.as_str(),
                    diff.len()
                )];
                lines.extend(diff.into_iter().map(|l| format!("  {l}")));
                (lines, true)
            }
        }
    }
}

/// The `derive` output for one product: a provenance header plus one
/// tab-separated line per (control, family-rule) pair, sectioned per family.
/// Families are always printed (0-row sections included) so an empty family is
/// visible; `family_filter` narrows to one section.
#[must_use]
pub fn render_derive(
    product: &str,
    reff: &str,
    header: &Header,
    groups: &BTreeMap<Family, Vec<CisControl>>,
    family_filter: Option<Family>,
) -> String {
    let families: Vec<Family> = match family_filter {
        Some(f) => vec![f],
        None => Family::ALL.to_vec(),
    };

    let mut total_rows = 0usize;
    let mut sections = String::new();
    for family in families {
        let rows: &[CisControl] = groups.get(&family).map_or(&[], Vec::as_slice);
        total_rows += rows.len();
        let mappings: usize = rows.iter().map(|c| c.rules.len()).sum();
        let selections: usize = rows.iter().map(|c| c.selections.len()).sum();
        sections.push_str(&format!(
            "## {} ({} controls, {} rule mappings, {} selections)\n",
            family.as_str(),
            rows.len(),
            mappings,
            selections
        ));
        for c in rows {
            for rule in &c.rules {
                sections.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\n",
                    c.id,
                    c.status.as_str(),
                    c.levels.join(" "),
                    rule,
                    c.title
                ));
            }
            for s in &c.selections {
                sections.push_str(&format!(
                    "{}\t{}\t{}\t{}={}\t{}\n",
                    c.id,
                    c.status.as_str(),
                    c.levels.join(" "),
                    s.name,
                    s.option,
                    c.title
                ));
            }
        }
    }

    format!(
        "# {product} @ {reff}  cis v{}  ({total_rows} family-relevant controls)\n{sections}",
        header.version
    )
}

/// The `derive --stig-refs` section: one tab-separated line per (CIS control,
/// auditd rule) join row; an empty join renders `-` (CIS-only rule). The joined
/// count in the header makes partial STIG coverage visible at a glance.
#[must_use]
pub fn render_stig_refs(rows: &[crate::stig_refs::StigRefRow]) -> String {
    let joined = rows.iter().filter(|r| !r.stig_ids.is_empty()).count();
    let mut out = format!(
        "## auditd stig-refs ({} rows, {joined} joined)\n",
        rows.len()
    );
    for r in rows {
        let ids = if r.stig_ids.is_empty() {
            "-".to_string()
        } else {
            r.stig_ids.join(",")
        };
        out.push_str(&format!("{}\t{}\t{}\n", r.cis_id, r.rule, ids));
    }
    out
}

/// The `derive --values` section: one line per derived sysctl key.
#[must_use]
pub fn render_values(rows: &[DerivedKey]) -> String {
    let mut out = format!("## sysctld values ({} keys)\n", rows.len());
    for d in rows {
        out.push_str(&format!(
            "{} = {:?}  ({}, {})\n",
            d.key,
            d.accepted,
            d.stig_id,
            if d.numeric { "numeric" } else { "string" }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stig_update::derive::DerivedKey;

    use super::{
        HealthFailure, check_family, classify_health_failure, diff_family, family_health,
        render_derive, render_stig_refs, render_values, skip_line, verify_anchors,
    };
    use crate::controls::{CisControl, Header, Status};
    use crate::family::Family;
    use crate::registry::{Shipped, ShippedControl};
    use crate::stig_refs::StigRefRow;

    fn control(id: &str, status: Status, rules: &[&str]) -> CisControl {
        CisControl {
            id: id.to_string(),
            title: format!("Ensure {id} is configured (Automated)"),
            levels: vec!["l1_server".to_string(), "l1_workstation".to_string()],
            status,
            rules: rules.iter().map(|r| (*r).to_string()).collect(),
            selections: Vec::new(),
        }
    }

    fn shipped_ids(ids: &[&str]) -> Vec<ShippedControl> {
        ids.iter()
            .map(|i| ShippedControl {
                id: (*i).to_string(),
            })
            .collect()
    }

    #[test]
    fn render_stig_refs_tabs_rows_and_counts_joined() {
        let rows = vec![
            StigRefRow {
                cis_id: "6.3.3.18".to_string(),
                rule: "audit_rules_privileged_commands_usermod".to_string(),
                stig_ids: vec!["RHEL-08-030560".to_string(), "RHEL-08-030561".to_string()],
            },
            StigRefRow {
                cis_id: "6.3.3.1".to_string(),
                rule: "audit_rules_sysadmin_actions".to_string(),
                stig_ids: Vec::new(),
            },
        ];
        assert_eq!(
            render_stig_refs(&rows),
            "## auditd stig-refs (2 rows, 1 joined)\n\
             6.3.3.18\taudit_rules_privileged_commands_usermod\tRHEL-08-030560,RHEL-08-030561\n\
             6.3.3.1\taudit_rules_sysadmin_actions\t-\n"
        );
    }

    fn anchor_rows() -> Vec<CisControl> {
        vec![
            control("5.2.2", Status::Automated, &["sudo_add_use_pty"]),
            control("5.2.3", Status::Automated, &["sudo_custom_logfile"]),
        ]
    }

    #[test]
    fn skip_line_exact_wording() {
        assert_eq!(
            skip_line("rhel9", Family::Sudoers, 5, 526),
            "rhel9/sudoers: no shipped table yet - SKIPPED (5 controls derived, awaiting lane #526)"
        );
    }

    #[test]
    fn check_family_pending_is_skip_not_drift() {
        let rows = anchor_rows();
        let (lines, drift) = check_family(
            "rhel9",
            Family::Sudoers,
            &rows,
            &Shipped::Pending { lane_issue: 526 },
        );
        assert_eq!(
            lines,
            vec![
                "rhel9/sudoers: no shipped table yet - SKIPPED (2 controls derived, awaiting lane #526)"
            ]
        );
        assert!(!drift);
    }

    #[test]
    fn check_family_table_ok_zero_drift() {
        let rows = anchor_rows();
        let (lines, drift) = check_family(
            "rhel9",
            Family::Sudoers,
            &rows,
            &Shipped::Table(shipped_ids(&["5.2.2", "5.2.3"])),
        );
        assert_eq!(lines, vec!["rhel9/sudoers: OK (0 drift)"]);
        assert!(!drift);
    }

    #[test]
    fn check_family_table_drift_lists_changes_indented() {
        let rows = anchor_rows();
        let (lines, drift) = check_family(
            "rhel9",
            Family::Sudoers,
            &rows,
            &Shipped::Table(shipped_ids(&["5.2.2", "1.3.3"])),
        );
        assert!(drift);
        assert_eq!(lines[0], "rhel9/sudoers: DRIFT (2 change(s))");
        assert!(
            lines.iter().any(|l| l.starts_with("  + 5.2.3")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("  - 1.3.3")),
            "{lines:?}"
        );
    }

    #[test]
    fn diff_family_reports_add_and_remove_deterministically() {
        let derived = vec![
            control("5.2.4", Status::Automated, &["sudo_remove_no_authenticate"]),
            control("5.2.2", Status::Automated, &["sudo_add_use_pty"]),
        ];
        let d = diff_family(&derived, &shipped_ids(&["5.2.2", "1.3.9"]));
        assert_eq!(
            d,
            vec![
                "- 1.3.9  (in code, absent upstream)",
                "+ 5.2.4 [sudo_remove_no_authenticate]  (new upstream)",
            ]
        );
        assert!(diff_family(&derived, &shipped_ids(&["5.2.2", "5.2.4"])).is_empty());
    }

    #[test]
    fn diff_family_counts_only_automated_derived_controls() {
        let derived = vec![
            control("5.2.2", Status::Automated, &["sudo_add_use_pty"]),
            control("5.9.9", Status::Manual, &["sudo_manual_thing"]),
        ];
        // The manual control neither demands a shipped row nor forgives one.
        assert!(diff_family(&derived, &shipped_ids(&["5.2.2"])).is_empty());
        let d = diff_family(&derived, &shipped_ids(&["5.2.2", "5.9.9"]));
        assert_eq!(d, vec!["- 5.9.9  (in code, absent upstream)"]);
    }

    #[test]
    fn verify_anchors_passes_on_the_real_pair() {
        assert_eq!(verify_anchors("rhel9", &anchor_rows()), Ok(()));
    }

    #[test]
    fn verify_anchors_reports_missing_id_and_wrong_rule() {
        let missing = verify_anchors("rhel8", &anchor_rows()[..1]).unwrap_err();
        assert!(missing.contains("rhel8"), "{missing}");
        assert!(missing.contains("5.2.3"), "{missing}");
        assert!(missing.contains("sudo_custom_logfile"), "{missing}");

        let wrong_rule = vec![
            control("5.2.2", Status::Automated, &["sudo_add_use_pty"]),
            control("5.2.3", Status::Automated, &["sudo_wrong_rule"]),
        ];
        assert!(verify_anchors("rhel9", &wrong_rule).is_err());
    }

    #[test]
    fn family_health_requires_all_four_families() {
        let mut groups: BTreeMap<Family, Vec<CisControl>> = BTreeMap::new();
        for f in Family::ALL {
            groups.insert(f, anchor_rows());
        }
        assert_eq!(family_health(&groups, "rhel9"), Ok(()));
        groups.remove(&Family::Sshd);
        let e = family_health(&groups, "rhel9").unwrap_err();
        assert!(e.contains("rhel9"), "{e}");
        assert!(e.contains("sshd"), "{e}");
    }

    #[test]
    fn health_failure_classification_depends_on_latest() {
        assert_eq!(
            classify_health_failure(false, "m".to_string()),
            HealthFailure::PinnedMisconfiguration("m".to_string())
        );
        assert_eq!(
            classify_health_failure(true, "m".to_string()),
            HealthFailure::UpstreamDrift("m".to_string())
        );
    }

    #[test]
    fn render_derive_exact_small_case() {
        let header = Header {
            policy: "CIS Red Hat Enterprise Linux 9 Benchmark".to_string(),
            version: "2.0.0".to_string(),
        };
        let mut groups: BTreeMap<Family, Vec<CisControl>> = BTreeMap::new();
        groups.insert(
            Family::Sudoers,
            vec![control("5.2.2", Status::Automated, &["sudo_add_use_pty"])],
        );
        groups.insert(
            Family::Sysctld,
            vec![control(
                "3.3.9",
                Status::Automated,
                &[
                    "sysctl_net_ipv4_conf_all_log_martians",
                    "sysctl_net_ipv4_conf_default_log_martians",
                ],
            )],
        );

        groups.get_mut(&Family::Sysctld).unwrap()[0].selections =
            vec![crate::controls::Selection {
                name: "sysctl_net_ipv4_conf_all_log_martians_value".to_string(),
                option: "enabled".to_string(),
            }];

        let all = render_derive("rhel9", "abc123", &header, &groups, None);
        let expected = "\
# rhel9 @ abc123  cis v2.0.0  (2 family-relevant controls)
## auditd (0 controls, 0 rule mappings, 0 selections)
## sshd (0 controls, 0 rule mappings, 0 selections)
## sudoers (1 controls, 1 rule mappings, 0 selections)
5.2.2\tautomated\tl1_server l1_workstation\tsudo_add_use_pty\tEnsure 5.2.2 is configured (Automated)
## sysctld (1 controls, 2 rule mappings, 1 selections)
3.3.9\tautomated\tl1_server l1_workstation\tsysctl_net_ipv4_conf_all_log_martians\tEnsure 3.3.9 is configured (Automated)
3.3.9\tautomated\tl1_server l1_workstation\tsysctl_net_ipv4_conf_default_log_martians\tEnsure 3.3.9 is configured (Automated)
3.3.9\tautomated\tl1_server l1_workstation\tsysctl_net_ipv4_conf_all_log_martians_value=enabled\tEnsure 3.3.9 is configured (Automated)
";
        assert_eq!(all, expected);

        let one = render_derive("rhel9", "abc123", &header, &groups, Some(Family::Sudoers));
        assert!(
            one.contains("## sudoers (1 controls, 1 rule mappings, 0 selections)"),
            "{one}"
        );
        assert!(!one.contains("## sysctld"), "{one}");
        assert!(
            one.starts_with("# rhel9 @ abc123  cis v2.0.0  (1 family-relevant controls)\n"),
            "filtered header counts only printed rows: {one}"
        );
    }

    #[test]
    fn render_values_lists_keys_with_cis_id_and_kind() {
        let rows = vec![
            DerivedKey {
                key: "net.ipv4.conf.all.log_martians".to_string(),
                accepted: vec!["1".to_string()],
                stig_id: "3.3.9".to_string(),
                numeric: true,
            },
            DerivedKey {
                key: "kernel.core_pattern".to_string(),
                accepted: vec!["|/bin/false".to_string()],
                stig_id: "1.6.4".to_string(),
                numeric: false,
            },
        ];
        let out = render_values(&rows);
        let expected = "\
## sysctld values (2 keys)
net.ipv4.conf.all.log_martians = [\"1\"]  (3.3.9, numeric)
kernel.core_pattern = [\"|/bin/false\"]  (1.6.4, string)
";
        assert_eq!(out, expected);
    }
}
