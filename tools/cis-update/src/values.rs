//! Sysctl VALUE derivation for the sysctld family (lane 3c's grounding input):
//! a thin delegation to `stig_update::derive::derive_table`, which already walks a
//! controls file's `sysctl_*` rules, fetches each rule.yml, resolves per-product
//! Jinja, and parses the sysctl template.
//!
//! The delegation is sound because stig-update's `cac::parse_controls` reads ONLY
//! `id` + `rules[]` from a controls file (ignoring the CIS-specific title / levels /
//! status fields) and itself filters to `sysctl_*` - verified by the tests below
//! against a CIS-shaped fixture. Note the returned `DerivedKey.stig_id` therefore
//! carries the CIS control id (the field name is stig-update's, the content is
//! whatever controls file was fed in).

use stig_update::derive::{self, DerivedKey};

/// Derive `(sysctl key, accepted values, cis id, numeric)` rows for every
/// non-excluded `sysctl_*` rule mapped by `controls_yaml`. `exclude_rules` skips
/// VALUE derivation only (the id-level family tables are built elsewhere and keep
/// the control either way).
pub fn sysctl_values<F>(
    controls_yaml: &str,
    product: &str,
    exclude_rules: &[String],
    get_rule: F,
) -> Result<Vec<DerivedKey>, String>
where
    F: Fn(&str) -> Result<(String, Option<String>), String>,
{
    derive::derive_table(controls_yaml, product, exclude_rules, get_rule)
}

#[cfg(test)]
mod tests {
    use super::sysctl_values;
    use std::collections::HashMap;

    /// A CIS-SHAPED controls fixture (block-style lists, title/levels/status/notes
    /// present) - the compatibility surface the delegation depends on. The 3.3.9
    /// control deliberately mixes a sysctl rule with an audit rule.
    const CIS_CONTROLS: &str = "\
controls:
    - id: 3.3.9
      title: Ensure suspicious packets are logged (Automated)
      levels:
          - l1_server
          - l1_workstation
      status: automated
      notes: |-
          Free text that must not disturb value derivation.
      rules:
          - sysctl_net_ipv4_conf_all_log_martians
          - audit_rules_networkconfig_modification
    - id: 3.3.2
      title: Ensure icmp redirects are not accepted (Automated)
      levels:
          - l1_server
      status: automated
      rules:
          - sysctl_net_ipv4_conf_all_accept_redirects
    - id: 1.6.4
      title: Ensure core dumps are restricted (Automated)
      levels:
          - l2_server
      status: automated
      rules:
          - sysctl_fips_like_no_template
";

    const LOG_MARTIANS: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: net.ipv4.conf.all.log_martians
    sysctlval: '1'
    datatype: int
";
    const ACCEPT_REDIRECTS: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: net.ipv4.conf.all.accept_redirects
    datatype: int
";
    const ACCEPT_REDIRECTS_VAR: &str = "\
options:
    default: 0
    enabled: 1
";
    const NO_TEMPLATE: &str = "\
# a sysctl_-prefixed rule with NO sysctl template (fips-style boot setting).
ocil: 'not derivable'
";

    fn fetcher() -> impl Fn(&str) -> Result<(String, Option<String>), String> {
        let map: HashMap<&str, (&str, Option<&str>)> = HashMap::from([
            (
                "sysctl_net_ipv4_conf_all_log_martians",
                (LOG_MARTIANS, None),
            ),
            (
                "sysctl_net_ipv4_conf_all_accept_redirects",
                (ACCEPT_REDIRECTS, Some(ACCEPT_REDIRECTS_VAR)),
            ),
            ("sysctl_fips_like_no_template", (NO_TEMPLATE, None)),
        ]);
        move |name: &str| {
            map.get(name)
                .map(|(r, v)| (r.to_string(), v.map(str::to_string)))
                .ok_or_else(|| format!("unexpected fetch of {name:?}"))
        }
    }

    fn excluded() -> Vec<String> {
        vec!["sysctl_fips_like_no_template".to_string()]
    }

    #[test]
    fn cis_shaped_controls_yaml_derives_values_with_cis_ids() {
        let t = sysctl_values(CIS_CONTROLS, "rhel9", &excluded(), fetcher()).unwrap();
        let martians = t
            .iter()
            .find(|d| d.key == "net.ipv4.conf.all.log_martians")
            .expect("log_martians derived");
        assert_eq!(martians.accepted, ["1"]);
        assert_eq!(martians.stig_id, "3.3.9", "carries the CIS control id");
        assert!(martians.numeric);
    }

    #[test]
    fn non_sysctl_rules_are_never_fetched() {
        // The fetcher hard-errors on any name it does not know - including the
        // audit_* rule in 3.3.9 - so success proves only sysctl_* rules are fetched.
        assert_eq!(
            sysctl_values(CIS_CONTROLS, "rhel9", &excluded(), fetcher())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn var_default_fallback_flows_through_the_delegation() {
        let t = sysctl_values(CIS_CONTROLS, "rhel9", &excluded(), fetcher()).unwrap();
        let redirects = t
            .iter()
            .find(|d| d.key == "net.ipv4.conf.all.accept_redirects")
            .expect("accept_redirects derived");
        assert_eq!(redirects.accepted, ["0"], "the _value.var options.default");
    }

    #[test]
    fn exclusion_skips_value_derivation_for_the_named_rule() {
        let t = sysctl_values(CIS_CONTROLS, "rhel9", &excluded(), fetcher()).unwrap();
        assert!(!t.iter().any(|d| d.stig_id == "1.6.4"), "{t:?}");
    }

    #[test]
    fn unexcluded_no_template_sysctl_rule_is_a_hard_error() {
        let e = sysctl_values(CIS_CONTROLS, "rhel9", &[], fetcher()).unwrap_err();
        assert!(e.contains("sysctl_fips_like_no_template"), "{e}");
    }
}
