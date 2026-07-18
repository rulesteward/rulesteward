//! Group parsed CIS controls into per-backend families by rule-name prefix.
//!
//! The prefix filter is the mechanism (sshd_ / sudo_ / sysctl_ / audit_ +
//! auditd_): a control belongs to every family for which it maps at least one
//! matching rule, and its row carries ONLY that family's rules. Controls whose
//! rules match no family (package_*, kernel_module_*, ...) are out of scope for
//! RuleSteward's backends and dropped from the grouping.

use std::collections::BTreeMap;

use crate::controls::CisControl;

/// The four Wave-3 backend families. Declaration order is the report order
/// (alphabetical; `BTreeMap` iteration relies on the derived `Ord`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Auditd,
    Sshd,
    Sudoers,
    Sysctld,
}

impl Family {
    pub const ALL: [Family; 4] = [
        Family::Auditd,
        Family::Sshd,
        Family::Sudoers,
        Family::Sysctld,
    ];

    /// Parse a `--family` flag value.
    pub fn parse(s: &str) -> Result<Family, String> {
        match s {
            "auditd" => Ok(Family::Auditd),
            "sshd" => Ok(Family::Sshd),
            "sudoers" => Ok(Family::Sudoers),
            "sysctld" => Ok(Family::Sysctld),
            other => Err(format!(
                "unknown family {other:?} (expected auditd|sshd|sudoers|sysctld)"
            )),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Auditd => "auditd",
            Family::Sshd => "sshd",
            Family::Sudoers => "sudoers",
            Family::Sysctld => "sysctld",
        }
    }
}

/// The family a CaC rule name belongs to, by prefix; `None` when out of scope.
#[must_use]
pub fn family_of(rule: &str) -> Option<Family> {
    if rule.starts_with("sshd_") {
        Some(Family::Sshd)
    } else if rule.starts_with("sudo_") {
        Some(Family::Sudoers)
    } else if rule.starts_with("sysctl_") {
        Some(Family::Sysctld)
    } else if rule.starts_with("audit_") || rule.starts_with("auditd_") {
        Some(Family::Auditd)
    } else {
        None
    }
}

/// Group controls per family. Each returned row is the control with `rules`
/// FILTERED to that family; families with no matching controls are absent.
#[must_use]
pub fn group(controls: &[CisControl]) -> BTreeMap<Family, Vec<CisControl>> {
    let mut out: BTreeMap<Family, Vec<CisControl>> = BTreeMap::new();
    for control in controls {
        for fam in Family::ALL {
            let rules: Vec<String> = control
                .rules
                .iter()
                .filter(|r| family_of(r) == Some(fam))
                .cloned()
                .collect();
            if !rules.is_empty() {
                out.entry(fam).or_default().push(CisControl {
                    rules,
                    ..control.clone()
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Family, family_of, group};
    use crate::controls::{CisControl, Status};

    fn control(id: &str, rules: &[&str]) -> CisControl {
        CisControl {
            id: id.to_string(),
            title: format!("Ensure {id} is configured (Automated)"),
            levels: vec!["l1_server".to_string()],
            status: Status::Automated,
            rules: rules.iter().map(|r| (*r).to_string()).collect(),
        }
    }

    #[test]
    fn family_of_matches_the_four_prefixes() {
        assert_eq!(
            family_of("sshd_disable_empty_passwords"),
            Some(Family::Sshd)
        );
        assert_eq!(family_of("sudo_add_use_pty"), Some(Family::Sudoers));
        assert_eq!(
            family_of("sysctl_net_ipv4_conf_all_log_martians"),
            Some(Family::Sysctld)
        );
        assert_eq!(
            family_of("audit_rules_dac_modification_chmod"),
            Some(Family::Auditd)
        );
        assert_eq!(
            family_of("auditd_data_retention_max_log_file"),
            Some(Family::Auditd)
        );
    }

    #[test]
    fn family_of_rejects_out_of_scope_and_lookalike_rules() {
        assert_eq!(family_of("package_audit_installed"), None);
        assert_eq!(family_of("kernel_module_usb-storage_disabled"), None);
        assert_eq!(family_of("chronyd_specify_remote_server"), None);
        // "auditweb_" must not ride the "audit" stem: only audit_ / auditd_ match.
        assert_eq!(family_of("auditweb_thing"), None);
        assert_eq!(family_of("sshdx_not_a_prefix_match"), None);
    }

    #[test]
    fn group_filters_rules_to_the_family() {
        let mixed = control(
            "3.3.9",
            &[
                "sysctl_net_ipv4_conf_all_log_martians",
                "sysctl_net_ipv4_conf_default_log_martians",
                "audit_rules_networkconfig_modification",
            ],
        );
        let g = group(&[mixed]);
        assert_eq!(
            g[&Family::Sysctld][0].rules,
            vec![
                "sysctl_net_ipv4_conf_all_log_martians",
                "sysctl_net_ipv4_conf_default_log_martians"
            ]
        );
        assert_eq!(
            g[&Family::Auditd][0].rules,
            vec!["audit_rules_networkconfig_modification"]
        );
    }

    #[test]
    fn group_duplicates_multi_family_controls_and_keeps_metadata() {
        let mixed = control("3.3.9", &["sysctl_a_b", "audit_rules_c"]);
        let g = group(&[mixed]);
        for fam in [Family::Sysctld, Family::Auditd] {
            let row = &g[&fam][0];
            assert_eq!(row.id, "3.3.9");
            assert_eq!(row.title, "Ensure 3.3.9 is configured (Automated)");
            assert_eq!(row.levels, vec!["l1_server"]);
            assert_eq!(row.status, Status::Automated);
        }
    }

    #[test]
    fn group_drops_out_of_scope_controls_and_empty_families() {
        let g = group(&[
            control("1.2.1", &[]),
            control("1.1.1.1", &["kernel_module_cramfs_disabled"]),
            control("5.2.2", &["sudo_add_use_pty"]),
        ]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[&Family::Sudoers].len(), 1);
        assert!(!g.contains_key(&Family::Sshd));
    }

    #[test]
    fn group_preserves_control_order_within_a_family() {
        let g = group(&[
            control("5.2.3", &["sudo_custom_logfile"]),
            control("5.2.2", &["sudo_add_use_pty"]),
        ]);
        let ids: Vec<&str> = g[&Family::Sudoers].iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["5.2.3", "5.2.2"], "source order, not sorted");
    }

    #[test]
    fn family_parse_round_trips_and_fails_closed() {
        for f in Family::ALL {
            assert_eq!(Family::parse(f.as_str()), Ok(f));
        }
        assert!(Family::parse("selinux").is_err());
        assert!(Family::parse("Sshd").is_err(), "flag values are lowercase");
    }
}
