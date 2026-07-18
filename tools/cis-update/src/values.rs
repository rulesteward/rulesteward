//! Sysctl VALUE derivation for the sysctld family (lane 3c's grounding input),
//! built on `stig_update`'s shared primitives (`cac::extract_block`,
//! `cac::parse_rule_sysctl`, `cac::parse_var_default`, `jinja`).
//!
//! This is NOT a blind delegation to `stig_update::derive::derive_table`: the
//! CIS controls files carry variable SELECTIONS (`<rule>_value=<option>`) inside
//! `rules:`, which the STIG controls files never used (caught live 2026-07-18 -
//! `derive_table` tries to fetch a rule.yml for the selector and errors). The
//! resolution order per rule is:
//!   1. the template's inline `sysctlval`;
//!   2. the control's `<rule>_value=<option>` selection, resolved against the
//!      var file's `options:` map (the benchmark's explicit choice);
//!   3. the var file's `options.default` (stig-update's behavior).

use stig_update::cac;
use stig_update::derive::{self, DerivedKey};
use stig_update::jinja::{self, ProductFacts};
use yaml_rust2::YamlLoader;

use crate::controls::CisControl;

/// Derive `(sysctl key, accepted values, cis id, numeric)` rows for every
/// non-excluded `sysctl_*` rule mapped by `controls`. `exclude_rules` skips
/// VALUE derivation only (the id-level family tables keep the control either
/// way); a non-excluded `sysctl_*` rule with no sysctl template is a hard error.
pub fn sysctl_values<F>(
    controls: &[CisControl],
    product: &str,
    exclude_rules: &[String],
    get_rule: F,
) -> Result<Vec<DerivedKey>, String>
where
    F: Fn(&str) -> Result<(String, Option<String>), String>,
{
    let facts = ProductFacts::rhel(product);
    let mut out = Vec::new();
    for control in controls {
        for rule_name in &control.rules {
            if !rule_name.starts_with("sysctl_") {
                continue;
            }
            if exclude_rules.iter().any(|r| r == rule_name) {
                continue;
            }
            let (rule_yaml, var_yaml) =
                get_rule(rule_name).map_err(|e| format!("{rule_name}: {e}"))?;
            // Parse ONLY the `template:` block - the rest of a rule.yml carries
            // `{{{ }}}` Jinja that is not valid YAML.
            let block = cac::extract_block(&rule_yaml, "template")
                .ok_or_else(|| format!("{rule_name}: no `template:` block (not a sysctl rule?)"))?;
            let resolved = jinja::resolve_for_product(&block, &facts)
                .map_err(|e| format!("{rule_name}: jinja: {e}"))?;
            let rule =
                cac::parse_rule_sysctl(&resolved).map_err(|e| format!("{rule_name}: {e}"))?;

            let accepted = match rule.sysctlval {
                Some(values) if !values.is_empty() => values,
                _ => {
                    let var = var_yaml.ok_or_else(|| {
                        format!("{rule_name}: no inline sysctlval and no _value.var fetched")
                    })?;
                    let resolved_var = jinja::resolve_for_product(&var, &facts)
                        .map_err(|e| format!("{rule_name}: var jinja: {e}"))?;
                    let selector = format!("{rule_name}_value");
                    let value = match control.selections.iter().find(|s| s.name == selector) {
                        Some(sel) => var_option(&resolved_var, &sel.option)
                            .map_err(|e| format!("{rule_name}: {e}"))?,
                        None => cac::parse_var_default(&resolved_var)
                            .map_err(|e| format!("{rule_name}: {e}"))?,
                    };
                    vec![value]
                }
            };

            out.push(DerivedKey {
                key: rule.sysctlvar,
                accepted: derive::normalize_set(accepted),
                stig_id: control.id.clone(),
                numeric: rule.datatype.as_deref() != Some("string"),
            });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Resolve a named option from a (Jinja-resolved) `_value.var` file's `options:`
/// map. Missing option = hard error (an upstream selection pointing at a
/// nonexistent option must surface, not fall back silently).
fn var_option(var_yaml: &str, option: &str) -> Result<String, String> {
    let docs = YamlLoader::load_from_str(var_yaml).map_err(|e| format!("var yaml: {e}"))?;
    let doc = docs.first().ok_or("var yaml: empty document")?;
    crate::controls::scalar(&doc["options"][option])
        .ok_or_else(|| format!("var has no option {option:?}"))
}

#[cfg(test)]
mod tests {
    use super::sysctl_values;
    use crate::controls::{CisControl, Selection, Status};
    use std::collections::HashMap;

    fn control(id: &str, rules: &[&str], selections: &[(&str, &str)]) -> CisControl {
        CisControl {
            id: id.to_string(),
            title: format!("Ensure {id} is configured (Automated)"),
            levels: vec!["l1_server".to_string()],
            status: Status::Automated,
            rules: rules.iter().map(|r| (*r).to_string()).collect(),
            selections: selections
                .iter()
                .map(|(n, o)| Selection {
                    name: (*n).to_string(),
                    option: (*o).to_string(),
                })
                .collect(),
        }
    }

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
    const SYNCOOKIES: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: net.ipv4.tcp_syncookies
    datatype: int
";
    /// `default` deliberately differs from `enabled` so a selection-aware
    /// resolution is distinguishable from stig-update's default-only behavior.
    const SYNCOOKIES_VAR: &str = "\
options:
    default: 9
    enabled: 1
    disabled: 0
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
            (
                "sysctl_net_ipv4_tcp_syncookies",
                (SYNCOOKIES, Some(SYNCOOKIES_VAR)),
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

    fn fixture() -> Vec<CisControl> {
        vec![
            control(
                "3.3.9",
                &[
                    "sysctl_net_ipv4_conf_all_log_martians",
                    "audit_rules_networkconfig_modification",
                ],
                &[],
            ),
            control("3.3.2", &["sysctl_net_ipv4_conf_all_accept_redirects"], &[]),
            control(
                "3.3.10",
                &["sysctl_net_ipv4_tcp_syncookies"],
                &[
                    ("sysctl_net_ipv4_tcp_syncookies_value", "enabled"),
                    ("var_authselect_profile", "sssd"),
                ],
            ),
            control("1.6.4", &["sysctl_fips_like_no_template"], &[]),
        ]
    }

    fn derive() -> Vec<stig_update::derive::DerivedKey> {
        sysctl_values(&fixture(), "rhel9", &excluded(), fetcher()).unwrap()
    }

    fn find(t: &[stig_update::derive::DerivedKey], key: &str) -> stig_update::derive::DerivedKey {
        t.iter()
            .find(|d| d.key == key)
            .expect("key present")
            .clone()
    }

    #[test]
    fn inline_sysctlval_carries_with_cis_id() {
        let m = find(&derive(), "net.ipv4.conf.all.log_martians");
        assert_eq!(m.accepted, ["1"]);
        assert_eq!(m.stig_id, "3.3.9", "carries the CIS control id");
        assert!(m.numeric);
    }

    #[test]
    fn selection_resolves_the_named_var_option_not_the_default() {
        let s = find(&derive(), "net.ipv4.tcp_syncookies");
        assert_eq!(
            s.accepted,
            ["1"],
            "options.enabled, NOT options.default (9)"
        );
    }

    #[test]
    fn without_a_selection_the_var_default_applies() {
        assert_eq!(
            find(&derive(), "net.ipv4.conf.all.accept_redirects").accepted,
            ["0"]
        );
    }

    #[test]
    fn inline_sysctlval_beats_a_selection() {
        let controls = vec![control(
            "9.9.9",
            &["sysctl_net_ipv4_conf_all_log_martians"],
            &[("sysctl_net_ipv4_conf_all_log_martians_value", "enabled")],
        )];
        let t = sysctl_values(&controls, "rhel9", &[], fetcher()).unwrap();
        assert_eq!(t[0].accepted, ["1"], "the template's inline value wins");
    }

    #[test]
    fn missing_var_option_is_a_hard_error() {
        let controls = vec![control(
            "3.3.10",
            &["sysctl_net_ipv4_tcp_syncookies"],
            &[("sysctl_net_ipv4_tcp_syncookies_value", "nonexistent")],
        )];
        let e = sysctl_values(&controls, "rhel9", &[], fetcher()).unwrap_err();
        assert!(e.contains("sysctl_net_ipv4_tcp_syncookies"), "{e}");
        assert!(e.contains("nonexistent"), "{e}");
    }

    #[test]
    fn non_sysctl_rules_are_never_fetched_and_output_is_key_sorted() {
        // The fetcher hard-errors on any unknown name (incl. the audit_* rule),
        // so success proves only sysctl_* rules are fetched.
        let keys: Vec<String> = derive().into_iter().map(|d| d.key).collect();
        assert_eq!(
            keys,
            vec![
                "net.ipv4.conf.all.accept_redirects",
                "net.ipv4.conf.all.log_martians",
                "net.ipv4.tcp_syncookies",
            ]
        );
    }

    #[test]
    fn exclusion_skips_value_derivation_for_the_named_rule() {
        assert!(!derive().iter().any(|d| d.stig_id == "1.6.4"));
    }

    #[test]
    fn unexcluded_no_template_sysctl_rule_is_a_hard_error() {
        let e = sysctl_values(&fixture(), "rhel9", &[], fetcher()).unwrap_err();
        assert!(e.contains("sysctl_fips_like_no_template"), "{e}");
    }
}
