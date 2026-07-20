//! The auditd CIS<->STIG join grounding (`derive --stig-refs`).
//!
//! At the pin, rule.yml `references:` blocks carry NO per-product `stigid@`
//! keys (grounded 2026-07-19): the product STIG mapping lives in the product's
//! STIG controls file (`products/<p>/controls/stig_<p>.yml`), whose control ids
//! ARE the DISA ids (`RHEL-08-030000`) that `rulesteward-auditd`'s au-W06
//! `BaselineRule.stig_id` uses. Both controls files at the SAME pin map CaC
//! rule names, so the rule name is an upstream-maintained foreign key: this
//! module joins the two mechanically and never invents a mapping. A CIS rule
//! absent from the STIG file is a CIS-only rule (empty join, rendered `-`).

use std::collections::BTreeMap;

use stig_update::jinja::{self, ProductFacts};
use yaml_rust2::YamlLoader;

use crate::controls::CisControl;
use crate::family::{self, Family};

/// One join row: a CIS control's auditd rule and the DISA STIG id(s) that map
/// the same CaC rule in the product's STIG controls file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StigRefRow {
    pub cis_id: String,
    pub rule: String,
    /// DISA ids in STIG-file order; empty = CIS-only rule (no STIG mapping).
    pub stig_ids: Vec<String>,
}

/// Parse a product STIG controls file into `auditd rule -> [DISA control ids]`,
/// after per-product Jinja resolution. Only `rules:` entries count
/// (`related_rules:` are not the control's mapping - stig-update precedent) and
/// only auditd-family rules are kept.
pub fn stig_rule_index(
    product: &str,
    stig_controls_yaml: &str,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let facts = ProductFacts::rhel(product);
    let resolved = jinja::resolve_for_product(stig_controls_yaml, &facts)?;
    let docs =
        YamlLoader::load_from_str(&resolved).map_err(|e| format!("stig controls yaml: {e}"))?;
    let doc = docs.first().ok_or("stig controls yaml: empty document")?;
    let list = doc["controls"]
        .as_vec()
        .ok_or("stig controls yaml: missing controls: list")?;

    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in list {
        // A control without an id or rules cannot contribute a join; skip
        // (stig-update's parse_controls precedent - not a hard error).
        let Some(id) = crate::controls::scalar(&item["id"]) else {
            continue;
        };
        let Some(rules) = item["rules"].as_vec() else {
            continue;
        };
        for rule in rules.iter().filter_map(crate::controls::scalar) {
            if family::family_of(&rule) == Some(Family::Auditd) {
                out.entry(rule).or_default().push(id.clone());
            }
        }
    }
    Ok(out)
}

/// Join a product's grouped-auditd CIS rows against the STIG rule index: one
/// row per (control, rule) pair, in control order (mirroring `render_derive`).
#[must_use]
pub fn join(auditd_rows: &[CisControl], index: &BTreeMap<String, Vec<String>>) -> Vec<StigRefRow> {
    auditd_rows
        .iter()
        .flat_map(|c| {
            c.rules.iter().map(|rule| StigRefRow {
                cis_id: c.id.clone(),
                rule: rule.clone(),
                stig_ids: index.get(rule).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{join, stig_rule_index};
    use crate::controls::{CisControl, Status};

    /// Hand-minimized offline fixture in the shape of
    /// `products/rhel8/controls/stig_rhel8.yml` at
    /// 519b5fe8ce338cfa25d53065bcb3759aafe8d36d (BSD-3-Clause). DISA ids +
    /// CaC rule names only - no STIG prose.
    const STIG_FIXTURE: &str = r#"policy: 'DISA STIG for Red Hat Enterprise Linux 8'
title: 'DISA STIG for Red Hat Enterprise Linux 8'
id: stig_rhel8
version: 'V2R1'
source: https://public.cyber.mil/stigs/downloads/
levels:
    - id: high
    - id: medium
    - id: low
controls:
    - id: RHEL-08-030000
      levels:
          - medium
      title: Audit privileged function execution
      rules:
          - audit_rules_suid_privilege_function
      status: automated
    - id: RHEL-08-030171
      levels:
          - medium
      title: Audit sudoers
      rules:
          - audit_rules_sysadmin_actions_stub
          - sysctl_kernel_dmesg_restrict
      status: automated
      related_rules:
          - audit_rules_privileged_commands_usermod
    - id: RHEL-08-030560
      levels:
          - medium
      title: Audit usermod
      rules:
          - audit_rules_privileged_commands_usermod
      status: automated
    - id: RHEL-08-030561
      levels:
          - medium
      title: Audit usermod again (a second control mapping the same rule)
      rules:
          - audit_rules_privileged_commands_usermod
      status: automated
    - id: RHEL-08-030740
      levels:
          - medium
      title: Product-conditional rule
      rules:
{{% if product == "rhel8" %}}
          - audit_rules_jinja_only_rhel8
{{% else %}}
          - audit_rules_jinja_other
{{% endif %}}
      status: automated
"#;

    fn index() -> std::collections::BTreeMap<String, Vec<String>> {
        stig_rule_index("rhel8", STIG_FIXTURE).unwrap()
    }

    #[test]
    fn index_maps_auditd_rules_to_their_disa_ids() {
        let idx = index();
        assert_eq!(
            idx["audit_rules_suid_privilege_function"],
            vec!["RHEL-08-030000"]
        );
    }

    #[test]
    fn index_drops_non_auditd_rules() {
        assert!(!index().contains_key("sysctl_kernel_dmesg_restrict"));
    }

    #[test]
    fn index_ignores_related_rules() {
        // usermod appears under RHEL-08-030171 ONLY as a related_rule; the two
        // genuine `rules:` mappings are 030560/030561.
        assert_eq!(
            index()["audit_rules_privileged_commands_usermod"],
            vec!["RHEL-08-030560", "RHEL-08-030561"]
        );
    }

    #[test]
    fn index_resolves_jinja_per_product() {
        let idx = index();
        assert_eq!(idx["audit_rules_jinja_only_rhel8"], vec!["RHEL-08-030740"]);
        assert!(!idx.contains_key("audit_rules_jinja_other"));
        let other = stig_rule_index("rhel9", STIG_FIXTURE).unwrap();
        assert!(other.contains_key("audit_rules_jinja_other"));
    }

    fn cis_control(id: &str, rules: &[&str]) -> CisControl {
        CisControl {
            id: id.to_string(),
            title: format!("Ensure {id} is collected (Automated)"),
            levels: vec!["l2_server".to_string()],
            status: Status::Automated,
            rules: rules.iter().map(|r| (*r).to_string()).collect(),
            selections: Vec::new(),
        }
    }

    #[test]
    fn join_emits_one_row_per_control_rule_pair_in_control_order() {
        let rows = join(
            &[
                cis_control("6.3.3.18", &["audit_rules_privileged_commands_usermod"]),
                cis_control(
                    "6.3.3.99",
                    &[
                        "audit_rules_suid_privilege_function",
                        "audit_rules_cis_only_thing",
                    ],
                ),
            ],
            &index(),
        );
        let flat: Vec<(String, String, Vec<String>)> = rows
            .into_iter()
            .map(|r| (r.cis_id, r.rule, r.stig_ids))
            .collect();
        assert_eq!(
            flat,
            vec![
                (
                    "6.3.3.18".to_string(),
                    "audit_rules_privileged_commands_usermod".to_string(),
                    vec!["RHEL-08-030560".to_string(), "RHEL-08-030561".to_string()],
                ),
                (
                    "6.3.3.99".to_string(),
                    "audit_rules_suid_privilege_function".to_string(),
                    vec!["RHEL-08-030000".to_string()],
                ),
                (
                    "6.3.3.99".to_string(),
                    "audit_rules_cis_only_thing".to_string(),
                    Vec::new(),
                ),
            ]
        );
    }

    #[test]
    fn stig_file_without_controls_key_errors() {
        assert!(stig_rule_index("rhel8", "policy: x\nversion: '1'\n").is_err());
    }
}
