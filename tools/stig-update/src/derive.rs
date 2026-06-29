//! Turn a product's controls file + its rule.yml bodies into the normalized STIG
//! baseline table. The network fetch is injected (a closure) so this core is tested
//! offline with in-memory fixtures.

use crate::cac;
use crate::jinja::{self, ProductFacts};

/// One derived baseline row, normalized for comparison against the Rust const table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKey {
    /// Dotted sysctl key (the rule's `sysctlvar`).
    pub key: String,
    /// Accepted value(s), trimmed + sorted + deduped (compared as a set).
    pub accepted: Vec<String>,
    /// The STIG control id.
    pub stig_id: String,
    /// `false` only for `datatype: string` keys (e.g. `kernel.core_pattern`).
    pub numeric: bool,
}

/// Derive the normalized baseline table for `product` from `controls_yaml`.
///
/// `get_rule(rule_name)` returns the raw `(rule.yml, Option<_value.var>)` bodies for
/// a rule (the var is fetched in case the rule has no inline `sysctlval`). Rules in
/// `exclude_rules` are skipped BEFORE parsing (they may have no sysctl template, e.g.
/// `sysctl_crypto_fips_enabled` / `sysctl_kernel_exec_shield`). A rule that is NOT
/// excluded but has no sysctl template is a hard error (surfaces a new non-settable
/// rule for a human to triage rather than silently dropping it).
pub fn derive_table<F>(
    controls_yaml: &str,
    product: &str,
    exclude_rules: &[String],
    get_rule: F,
) -> Result<Vec<DerivedKey>, String>
where
    F: Fn(&str) -> Result<(String, Option<String>), String>,
{
    let facts = ProductFacts::rhel(product);
    let controls = cac::parse_controls(controls_yaml)?;

    let mut out = Vec::new();
    for control in &controls {
        for rule_name in &control.sysctl_rules {
            if exclude_rules.iter().any(|r| r == rule_name) {
                continue;
            }
            let (rule_yaml, var_yaml) =
                get_rule(rule_name).map_err(|e| format!("{rule_name}: {e}"))?;
            // Parse ONLY the `template:` block - the rest of a rule.yml (description,
            // fixtext, srg_requirement) carries `{{{ }}}` Jinja that is not valid YAML.
            let block = cac::extract_block(&rule_yaml, "template")
                .ok_or_else(|| format!("{rule_name}: no `template:` block (not a sysctl rule?)"))?;
            let resolved = jinja::resolve_for_product(&block, &facts)
                .map_err(|e| format!("{rule_name}: jinja: {e}"))?;
            let rule =
                cac::parse_rule_sysctl(&resolved).map_err(|e| format!("{rule_name}: {e}"))?;

            let accepted = match rule.sysctlval {
                Some(values) if !values.is_empty() => values,
                _ => {
                    // No inline sysctlval -> the rule's `_value.var` default.
                    let var = var_yaml.ok_or_else(|| {
                        format!("{rule_name}: no inline sysctlval and no _value.var fetched")
                    })?;
                    let resolved_var = jinja::resolve_for_product(&var, &facts)
                        .map_err(|e| format!("{rule_name}: var jinja: {e}"))?;
                    vec![
                        cac::parse_var_default(&resolved_var)
                            .map_err(|e| format!("{rule_name}: {e}"))?,
                    ]
                }
            };

            out.push(DerivedKey {
                key: rule.sysctlvar,
                accepted: normalize_set(accepted),
                stig_id: control.id.clone(),
                numeric: rule.datatype.as_deref() != Some("string"),
            });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Trim, sort, and dedup a value set so two derivations (or a derivation vs the const
/// table) compare order-insensitively.
pub fn normalize_set(mut values: Vec<String>) -> Vec<String> {
    for v in &mut values {
        *v = v.trim().to_string();
    }
    values.sort();
    values.dedup();
    values
}

/// Human-readable diff of an upstream-`derived` table against the shipped `code`
/// table (both keyed by sysctl key). Empty result == no drift. `-` a key in code but
/// gone upstream; `+` a new upstream key; `~` a changed value / STIG id / datatype.
#[must_use]
pub fn diff_tables(derived: &[DerivedKey], code: &[DerivedKey]) -> Vec<String> {
    use std::collections::BTreeMap;
    let dmap: BTreeMap<&str, &DerivedKey> = derived.iter().map(|d| (d.key.as_str(), d)).collect();
    let cmap: BTreeMap<&str, &DerivedKey> = code.iter().map(|d| (d.key.as_str(), d)).collect();

    let mut keys: Vec<&str> = dmap.keys().chain(cmap.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut out = Vec::new();
    for k in keys {
        match (cmap.get(k), dmap.get(k)) {
            (Some(_), None) => out.push(format!("- {k}  (in code, absent upstream)")),
            (None, Some(d)) => out.push(format!(
                "+ {k} = {:?}  ({}, new upstream)",
                d.accepted, d.stig_id
            )),
            (Some(c), Some(d)) => {
                if c.accepted != d.accepted {
                    out.push(format!(
                        "~ {k} value: code {:?} -> upstream {:?}",
                        c.accepted, d.accepted
                    ));
                }
                if c.stig_id != d.stig_id {
                    out.push(format!(
                        "~ {k} stig_id: code {} -> upstream {}",
                        c.stig_id, d.stig_id
                    ));
                }
                if c.numeric != d.numeric {
                    out.push(format!(
                        "~ {k} numeric: code {} -> upstream {}",
                        c.numeric, d.numeric
                    ));
                }
            }
            (None, None) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{DerivedKey, derive_table};
    use std::collections::HashMap;

    /// A fixture fetcher: maps rule name -> (rule.yml, Option<var.yml>).
    fn fetcher(
        rules: &'static [(&'static str, &'static str, Option<&'static str>)],
    ) -> impl Fn(&str) -> Result<(String, Option<String>), String> {
        let map: HashMap<&str, (&str, Option<&str>)> =
            rules.iter().map(|(n, r, v)| (*n, (*r, *v))).collect();
        move |name: &str| {
            map.get(name)
                .map(|(r, v)| (r.to_string(), v.map(str::to_string)))
                .ok_or_else(|| format!("no fixture for {name}"))
        }
    }

    const CONTROLS: &str = "\
controls:
  - id: RHEL-09-213010
    rules: [sysctl_kernel_dmesg_restrict]
  - id: RHEL-09-213025
    rules: [sysctl_kernel_kptr_restrict]
  - id: RHEL-09-253035
    rules: [sysctl_net_ipv4_conf_all_rp_filter]
  - id: RHEL-09-213040
    rules: [sysctl_kernel_core_pattern]
  - id: RHEL-09-671010
    rules: [sysctl_crypto_fips_enabled]
";

    const KPTR: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.kptr_restrict
    {{% if product == 'rhel8' %}}
    sysctlval: '1'
    {{% elif 'ol' in families or 'rhel' in product %}}
    sysctlval:
    - '1'
    - '2'
    {{% endif %}}
    datatype: int
";
    const DMESG: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.dmesg_restrict
    sysctlval: '1'
    datatype: int
";
    const RP_FILTER: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: net.ipv4.conf.all.rp_filter
    {{% if ('ol' in families or 'rhel' in product) and product not in ['ol9','rhel9'] %}}
    sysctlval:
    - '1'
    - '2'
    {{% endif %}}
    datatype: int
";
    const RP_FILTER_VAR: &str = "\
options:
    default: 1
    enabled: 1
    loose: 2
";
    const CORE_PATTERN: &str = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.core_pattern
    sysctlval: '|/bin/false'
    datatype: string
";
    const FIPS: &str = "\
# crypto.fips_enabled has NO sysctl template (boot-time fips=1).
ocil: 'crypto.fips_enabled should be 1'
";

    fn rules() -> &'static [(&'static str, &'static str, Option<&'static str>)] {
        &[
            ("sysctl_kernel_dmesg_restrict", DMESG, None),
            ("sysctl_kernel_kptr_restrict", KPTR, None),
            (
                "sysctl_net_ipv4_conf_all_rp_filter",
                RP_FILTER,
                Some(RP_FILTER_VAR),
            ),
            ("sysctl_kernel_core_pattern", CORE_PATTERN, None),
            ("sysctl_crypto_fips_enabled", FIPS, None),
        ]
    }

    fn derive(product: &str) -> Vec<DerivedKey> {
        derive_table(
            CONTROLS,
            product,
            &["sysctl_crypto_fips_enabled".to_string()],
            fetcher(rules()),
        )
        .expect("derivation succeeds")
    }

    fn find<'a>(t: &'a [DerivedKey], key: &str) -> &'a DerivedKey {
        t.iter().find(|d| d.key == key).expect("key present")
    }

    #[test]
    fn excluded_rule_is_dropped() {
        let t = derive("rhel9");
        assert!(
            !t.iter().any(|d| d.key == "crypto.fips_enabled"),
            "the excluded fips rule must not appear: {t:?}"
        );
        // 5 controls minus the 1 excluded = 4 derived keys.
        assert_eq!(t.len(), 4, "{t:?}");
    }

    #[test]
    fn per_product_jinja_resolves_kptr_restrict() {
        assert_eq!(
            find(&derive("rhel8"), "kernel.kptr_restrict").accepted,
            ["1"]
        );
        assert_eq!(
            find(&derive("rhel9"), "kernel.kptr_restrict").accepted,
            ["1", "2"]
        );
    }

    #[test]
    fn rp_filter_diverges_rhel8_list_vs_rhel9_var_default() {
        // rhel8/rhel10 take the inline [1,2]; rhel9 falls to the var default 1.
        assert_eq!(
            find(&derive("rhel8"), "net.ipv4.conf.all.rp_filter").accepted,
            ["1", "2"]
        );
        assert_eq!(
            find(&derive("rhel9"), "net.ipv4.conf.all.rp_filter").accepted,
            ["1"]
        );
        assert_eq!(
            find(&derive("rhel10"), "net.ipv4.conf.all.rp_filter").accepted,
            ["1", "2"]
        );
    }

    #[test]
    fn datatype_drives_numeric_flag() {
        assert!(find(&derive("rhel9"), "kernel.dmesg_restrict").numeric);
        assert!(!find(&derive("rhel9"), "kernel.core_pattern").numeric);
        assert_eq!(
            find(&derive("rhel9"), "kernel.core_pattern").accepted,
            ["|/bin/false"]
        );
    }

    #[test]
    fn stig_id_carried_from_the_control() {
        assert_eq!(
            find(&derive("rhel9"), "kernel.dmesg_restrict").stig_id,
            "RHEL-09-213010"
        );
    }

    #[test]
    fn unexcluded_non_sysctl_rule_is_a_hard_error() {
        // If fips is NOT excluded, its missing sysctl template must surface as an error,
        // not be silently dropped.
        let err = derive_table(CONTROLS, "rhel9", &[], fetcher(rules())).unwrap_err();
        assert!(err.contains("sysctl_crypto_fips_enabled"), "{err}");
    }

    #[test]
    fn diff_tables_reports_add_remove_and_change() {
        use super::{DerivedKey, diff_tables};
        let mk = |key: &str, acc: &[&str], id: &str| DerivedKey {
            key: key.to_string(),
            accepted: acc.iter().map(|s| (*s).to_string()).collect(),
            stig_id: id.to_string(),
            numeric: true,
        };
        let code = vec![mk("a", &["1"], "ID-A"), mk("removed", &["0"], "ID-R")];
        let upstream = vec![mk("a", &["2"], "ID-A2"), mk("added", &["1"], "ID-N")];
        let d = diff_tables(&upstream, &code);
        // identical table -> no drift
        assert!(diff_tables(&code, &code).is_empty());
        // a: value + stig_id changed; removed: gone; added: new.
        assert!(d.iter().any(|l| l.starts_with("- removed")), "{d:?}");
        assert!(d.iter().any(|l| l.starts_with("+ added")), "{d:?}");
        assert!(
            d.iter()
                .any(|l| l.contains("a value: code [\"1\"] -> upstream [\"2\"]")),
            "{d:?}"
        );
        assert!(
            d.iter()
                .any(|l| l.contains("a stig_id: code ID-A -> upstream ID-A2")),
            "{d:?}"
        );
    }
}
