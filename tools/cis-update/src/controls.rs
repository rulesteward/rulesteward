//! Parse a ComplianceAsCode CIS controls file (`products/<p>/controls/cis_<p>.yml`)
//! into typed control rows, after per-product Jinja resolution.
//!
//! The controls file is the ONLY source of RHEL CIS control ids/titles (rule.yml
//! `references:` carry SLE numbering, grounded 2026-07-18). Ids are opaque strings:
//! the pin contains 3/4/5-component numeric ids AND bare word ids
//! (`enable_authselect`), so nothing here assumes numeric structure.

use stig_update::jinja::{self, ProductFacts};
use yaml_rust2::{Yaml, YamlLoader};

/// File-header fields the derive output prints for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// `policy` (e.g. `CIS Red Hat Enterprise Linux 9 Benchmark`).
    pub policy: String,
    /// Benchmark `version` (e.g. `2.0.0`); the three products version independently.
    pub version: String,
}

/// A control's `status`. Fail-closed: an unknown or absent status is a hard error
/// (mis-bucketing would silently drop controls from the automated-only drift
/// comparison). Note the upstream spelling `not applicable` HAS A SPACE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Automated,
    Manual,
    Partial,
    Pending,
    Supported,
    NotApplicable,
}

impl Status {
    pub fn parse(s: &str) -> Result<Status, String> {
        match s {
            "automated" => Ok(Status::Automated),
            "manual" => Ok(Status::Manual),
            "partial" => Ok(Status::Partial),
            "pending" => Ok(Status::Pending),
            "supported" => Ok(Status::Supported),
            "not applicable" => Ok(Status::NotApplicable),
            other => Err(format!("unknown control status {other:?}")),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Automated => "automated",
            Status::Manual => "manual",
            Status::Partial => "partial",
            Status::Pending => "pending",
            Status::Supported => "supported",
            Status::NotApplicable => "not applicable",
        }
    }
}

/// A variable selection carried inside a control's `rules:` block using CaC's
/// profile-selector syntax `name=option` (e.g.
/// `sysctl_net_ipv4_tcp_syncookies_value=enabled`, `var_selinux_state=enforcing`).
/// Selections are NOT rules: they pick an option of a CaC variable and there is no
/// rule.yml behind them. The CIS controls files use them heavily (the STIG ones do
/// not), so they are split out at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub name: String,
    pub option: String,
}

/// One parsed control. `levels` is carried as metadata verbatim (lenient: absent =
/// empty); `rules` lists ONLY the plain entries of the `rules:` block, with
/// `name=option` entries split into `selections` (`related_rules` and `notes` are
/// deliberately ignored - related rules are not the control's mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CisControl {
    pub id: String,
    /// CaC-carried title, verbatim (includes upstream suffixes like `(Automated)`).
    pub title: String,
    pub levels: Vec<String>,
    pub status: Status,
    pub rules: Vec<String>,
    pub selections: Vec<Selection>,
}

/// Resolve per-product Jinja (a no-op on today's plain-YAML controls files, but the
/// doubled `{{% if %}}` form would otherwise break the YAML parse if upstream adds
/// it), then parse the whole document.
pub fn parse(product: &str, text: &str) -> Result<(Header, Vec<CisControl>), String> {
    let facts = ProductFacts::rhel(product);
    let resolved = jinja::resolve_for_product(text, &facts)?;
    let docs = YamlLoader::load_from_str(&resolved).map_err(|e| format!("controls yaml: {e}"))?;
    let doc = docs.first().ok_or("controls yaml: empty document")?;

    let header = Header {
        policy: scalar(&doc["policy"]).ok_or("controls yaml: missing policy")?,
        version: scalar(&doc["version"]).ok_or("controls yaml: missing version")?,
    };

    let list = doc["controls"]
        .as_vec()
        .ok_or("controls yaml: missing controls: list")?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let id = scalar(&item["id"]).ok_or("controls yaml: control without id")?;
        let title = scalar(&item["title"]).ok_or_else(|| format!("control {id}: missing title"))?;
        let status_str =
            scalar(&item["status"]).ok_or_else(|| format!("control {id}: missing status"))?;
        let status = Status::parse(&status_str).map_err(|e| format!("control {id}: {e}"))?;
        let (rules, selections) = split_rules(string_list(&item["rules"]));
        out.push(CisControl {
            levels: string_list(&item["levels"]),
            rules,
            selections,
            id,
            title,
            status,
        });
    }
    Ok((header, out))
}

/// A YAML scalar as its raw string. Ids like `9.9` lex as floats (`Yaml::Real`
/// keeps the raw spelling) and a bare integer would lex as `Yaml::Integer`, so
/// both are accepted alongside plain strings. `pub(crate)`: [`crate::values`]
/// reuses it for var `options:` values (which are often bare integers).
pub(crate) fn scalar(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

fn string_list(y: &Yaml) -> Vec<String> {
    y.as_vec()
        .map(|v| v.iter().filter_map(scalar).collect())
        .unwrap_or_default()
}

/// Split a `rules:` block into plain rule names and `name=option` variable
/// selections (CaC's profile-selector syntax, split at the FIRST `=`).
fn split_rules(entries: Vec<String>) -> (Vec<String>, Vec<Selection>) {
    let mut rules = Vec::new();
    let mut selections = Vec::new();
    for entry in entries {
        match entry.split_once('=') {
            Some((name, option)) => selections.push(Selection {
                name: name.to_string(),
                option: option.to_string(),
            }),
            None => rules.push(entry),
        }
    }
    (rules, selections)
}

#[cfg(test)]
mod tests {
    use super::{CisControl, Status, parse};

    /// Hand-minimized offline fixture in the shape of
    /// `products/rhel9/controls/cis_rhel9.yml` at ComplianceAsCode/content
    /// 519b5fe8ce338cfa25d53065bcb3759aafe8d36d (BSD-3-Clause). Carries control
    /// ids/titles only - no CIS benchmark prose. The 5.2.2/5.2.3 entries are the
    /// real anchor pair the live gate asserts.
    const FIXTURE: &str = r#"policy: 'CIS Red Hat Enterprise Linux 9 Benchmark'
title: 'CIS Red Hat Enterprise Linux 9 Benchmark'
id: cis_rhel9
version: '2.0.0'
source: https://www.cisecurity.org/benchmark/red_hat_linux/
reference_type: cis
product: rhel9
levels:
    - id: l1_server
    - id: l2_server
      inherits_from:
          - l1_server
    - id: l1_workstation
    - id: l2_workstation
      inherits_from:
          - l1_workstation
controls:
    - id: 5.2.2
      title: Ensure sudo commands use pty (Automated)
      levels:
          - l1_server
          - l1_workstation
      status: automated
      rules:
          - sudo_add_use_pty
    - id: 3.3.10
      title: Ensure tcp syn cookies is enabled (Automated)
      levels:
          - l1_server
          - l1_workstation
      status: automated
      rules:
          - sysctl_net_ipv4_tcp_syncookies
          - sysctl_net_ipv4_tcp_syncookies_value=enabled
          - var_authselect_profile=sssd
    - id: 5.2.3
      title: Ensure sudo log file exists (Automated)
      levels:
          - l1_server
          - l1_workstation
      status: automated
      rules:
          - sudo_custom_logfile
    - id: 3.3.9
      title: Ensure suspicious packets are logged (Automated)
      levels:
          - l1_server
          - l1_workstation
      status: automated
      rules:
          - sysctl_net_ipv4_conf_all_log_martians
          - sysctl_net_ipv4_conf_default_log_martians
          - audit_rules_networkconfig_modification
    - id: 1.2.1
      title: Ensure GPG keys are configured (Manual)
      levels:
          - l1_server
          - l1_workstation
      status: manual
    - id: 4.1.1.1
      title: Ensure auditd is installed (Automated)
      levels:
          - l2_server
          - l2_workstation
      status: partial
      notes: |-
          A free-text implementation note that must never leak into parsed rules.
      rules:
          - package_audit_installed
      related_rules:
          - auditd_data_retention_max_log_file
    - id: 2.3.1
      title: Ensure chrony is configured (Automated)
      levels:
          - l1_server
      status: pending
      rules:
          - chronyd_specify_remote_server
    - id: 6.2.1
      title: Ensure accounts are safeguarded (Automated)
      levels:
          - l1_server
      status: supported
      rules:
          - sshd_disable_empty_passwords
    - id: 1.1.9
      title: Ensure usb-storage is handled (Automated)
      levels:
          - l2_server
      status: not applicable
      rules:
          - kernel_module_usb-storage_disabled
    - id: enable_authselect
      title: Enable authselect (Automated)
      levels:
          - l1_server
      status: automated
      rules:
          - enable_authselect
    - id: 9.9
      title: Two-component id survives as a raw string (Automated)
      levels:
          - l1_server
      status: automated
      rules:
          - sysctl_kernel_kptr_restrict
    - id: 7.7.7
      title: Product-conditional rule set (Automated)
      levels:
          - l1_server
      status: automated
      rules:
{{% if product == "rhel9" %}}
          - sudo_require_reauthentication
{{% else %}}
          - sudo_custom_logfile
{{% endif %}}
"#;

    fn fixture_controls(product: &str) -> Vec<CisControl> {
        parse(product, FIXTURE).unwrap().1
    }

    fn by_id<'a>(controls: &'a [CisControl], id: &str) -> &'a CisControl {
        controls
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("control {id} missing"))
    }

    #[test]
    fn header_policy_and_version_carried() {
        let (h, _) = parse("rhel9", FIXTURE).unwrap();
        assert_eq!(h.policy, "CIS Red Hat Enterprise Linux 9 Benchmark");
        assert_eq!(h.version, "2.0.0");
    }

    #[test]
    fn selections_split_out_of_rules_on_the_equals_sign() {
        let controls = fixture_controls("rhel9");
        let c = by_id(&controls, "3.3.10");
        assert_eq!(c.rules, vec!["sysctl_net_ipv4_tcp_syncookies"]);
        assert_eq!(
            c.selections,
            vec![
                super::Selection {
                    name: "sysctl_net_ipv4_tcp_syncookies_value".to_string(),
                    option: "enabled".to_string(),
                },
                super::Selection {
                    name: "var_authselect_profile".to_string(),
                    option: "sssd".to_string(),
                },
            ]
        );
        // Controls without selector entries have an empty selections list.
        assert!(by_id(&controls, "5.2.2").selections.is_empty());
    }

    #[test]
    fn parses_full_field_carry() {
        let controls = fixture_controls("rhel9");
        assert_eq!(controls.len(), 12);
        let anchor = by_id(&controls, "5.2.2");
        assert_eq!(anchor.title, "Ensure sudo commands use pty (Automated)");
        assert_eq!(anchor.levels, vec!["l1_server", "l1_workstation"]);
        assert_eq!(anchor.status, Status::Automated);
        assert_eq!(anchor.rules, vec!["sudo_add_use_pty"]);
        assert_eq!(by_id(&controls, "5.2.3").rules, vec!["sudo_custom_logfile"]);
        assert_eq!(by_id(&controls, "3.3.9").rules.len(), 3);
    }

    #[test]
    fn all_six_statuses_parse() {
        let controls = fixture_controls("rhel9");
        for (id, want) in [
            ("5.2.2", Status::Automated),
            ("1.2.1", Status::Manual),
            ("4.1.1.1", Status::Partial),
            ("2.3.1", Status::Pending),
            ("6.2.1", Status::Supported),
            ("1.1.9", Status::NotApplicable),
        ] {
            assert_eq!(by_id(&controls, id).status, want, "status of {id}");
        }
    }

    #[test]
    fn not_applicable_is_spelled_with_a_space() {
        assert_eq!(Status::parse("not applicable"), Ok(Status::NotApplicable));
        assert!(Status::parse("not_applicable").is_err());
    }

    #[test]
    fn unknown_status_is_a_hard_error() {
        assert!(Status::parse("automatic").is_err());
        let bad = FIXTURE.replace("status: pending", "status: automatic");
        let e = parse("rhel9", &bad).unwrap_err();
        assert!(e.contains("automatic"), "error names the bad status: {e}");
    }

    #[test]
    fn missing_status_is_a_hard_error() {
        let bad = FIXTURE.replace("      status: pending\n", "");
        let e = parse("rhel9", &bad).unwrap_err();
        assert!(e.contains("2.3.1"), "error names the control: {e}");
    }

    #[test]
    fn related_rules_and_notes_are_ignored() {
        let controls = fixture_controls("rhel9");
        let c = by_id(&controls, "4.1.1.1");
        assert_eq!(c.rules, vec!["package_audit_installed"]);
    }

    #[test]
    fn rules_less_control_yields_empty_rules() {
        let controls = fixture_controls("rhel9");
        assert!(by_id(&controls, "1.2.1").rules.is_empty());
    }

    #[test]
    fn ids_survive_verbatim_including_non_numeric_and_two_component() {
        let controls = fixture_controls("rhel9");
        assert_eq!(
            by_id(&controls, "enable_authselect").id,
            "enable_authselect"
        );
        // "9.9" is a YAML float lexically; the raw spelling must survive.
        assert_eq!(by_id(&controls, "9.9").id, "9.9");
    }

    #[test]
    fn jinja_resolves_per_product_before_yaml_parse() {
        let rhel9 = by_id(&fixture_controls("rhel9"), "7.7.7").rules.clone();
        assert_eq!(rhel9, vec!["sudo_require_reauthentication"]);
        let rhel8 = by_id(&fixture_controls("rhel8"), "7.7.7").rules.clone();
        assert_eq!(rhel8, vec!["sudo_custom_logfile"]);
    }

    #[test]
    fn missing_controls_key_errors() {
        assert!(parse("rhel9", "policy: x\nversion: '1'\n").is_err());
    }
}
