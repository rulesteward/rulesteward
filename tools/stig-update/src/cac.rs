//! Parse the (Jinja-resolved) ComplianceAsCode YAML artifacts: the product STIG
//! controls file, a sysctl `rule.yml`, and a `<rule>_value.var` default.

use yaml_rust2::{Yaml, YamlLoader};

/// One STIG control that enforces sysctl key(s): its id plus the `sysctl_*` rule
/// names under its `rules:` block (`related_rules:` are intentionally ignored).
pub struct Control {
    pub id: String,
    pub sysctl_rules: Vec<String>,
}

/// Parse the product controls file into the sysctl-bearing controls.
pub fn parse_controls(yaml: &str) -> Result<Vec<Control>, String> {
    let docs = YamlLoader::load_from_str(yaml).map_err(|e| format!("controls YAML: {e}"))?;
    let doc = docs.first().ok_or("empty controls YAML")?;
    let controls = doc["controls"]
        .as_vec()
        .ok_or("controls file has no `controls:` array")?;

    let mut out = Vec::new();
    for c in controls {
        let Some(id) = c["id"].as_str() else { continue };
        // Only `rules:` (NOT `related_rules:`); keep only the sysctl_* rules.
        let sysctl_rules: Vec<String> = c["rules"]
            .as_vec()
            .map(|v| {
                v.iter()
                    .filter_map(Yaml::as_str)
                    .filter(|r| r.starts_with("sysctl_"))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !sysctl_rules.is_empty() {
            out.push(Control {
                id: id.to_string(),
                sysctl_rules,
            });
        }
    }
    Ok(out)
}

/// Extract a top-level YAML block (the `key:` line at column 0 plus all following
/// more-indented lines, up to the next column-0 key). Used to pull just the
/// `template:` block out of a rule.yml so its prose fields - which carry `{{{ }}}`
/// Jinja expressions that are not valid standalone YAML - never reach the parser.
#[must_use]
pub fn extract_block(text: &str, key: &str) -> Option<String> {
    let header = format!("{key}:");
    let mut out: Vec<&str> = Vec::new();
    let mut started = false;
    for line in text.lines() {
        let at_col0 = !line.is_empty() && !line.starts_with([' ', '\t']);
        if started {
            if at_col0 {
                break;
            }
            out.push(line);
        } else if at_col0 && line.starts_with(&header) {
            started = true;
            out.push(line);
        }
    }
    started.then(|| out.join("\n"))
}

/// The sysctl-relevant fields of a resolved `rule.yml`.
pub struct RuleSysctl {
    pub sysctlvar: String,
    /// The accepted value(s), or `None` when the rule defers to its `_value.var`.
    pub sysctlval: Option<Vec<String>>,
    pub datatype: Option<String>,
}

/// Parse a JINJA-RESOLVED `rule.yml`'s `template: name: sysctl` block. Errors if the
/// rule is not a sysctl template (e.g. `crypto.fips_enabled` / `kernel.exec-shield`,
/// which must be excluded by rule name upstream of this call).
pub fn parse_rule_sysctl(resolved_yaml: &str) -> Result<RuleSysctl, String> {
    let docs = YamlLoader::load_from_str(resolved_yaml).map_err(|e| format!("rule YAML: {e}"))?;
    let doc = docs.first().ok_or("empty rule YAML")?;
    let template = &doc["template"];
    if template["name"].as_str() != Some("sysctl") {
        return Err("rule has no `template: name: sysctl` block".to_string());
    }
    let vars = &template["vars"];
    let sysctlvar = vars["sysctlvar"]
        .as_str()
        .ok_or("sysctl rule missing `sysctlvar`")?
        .to_string();
    Ok(RuleSysctl {
        sysctlvar,
        sysctlval: yaml_to_string_list(&vars["sysctlval"]),
        datatype: vars["datatype"].as_str().map(str::to_string),
    })
}

/// Parse the `options.default` of a `<rule>_value.var` file.
pub fn parse_var_default(var_yaml: &str) -> Result<String, String> {
    let docs = YamlLoader::load_from_str(var_yaml).map_err(|e| format!("var YAML: {e}"))?;
    let doc = docs.first().ok_or("empty var YAML")?;
    scalar_string(&doc["options"]["default"])
        .ok_or_else(|| "var missing `options.default`".to_string())
}

/// A YAML scalar (or list of scalars) rendered as owned strings, or `None` when the
/// node is absent / not a scalar.
fn yaml_to_string_list(y: &Yaml) -> Option<Vec<String>> {
    if let Some(arr) = y.as_vec() {
        let items: Vec<String> = arr.iter().filter_map(scalar_string).collect();
        (!items.is_empty()).then_some(items)
    } else {
        scalar_string(y).map(|s| vec![s])
    }
}

fn scalar_string(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(r) => Some(r.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_controls, parse_rule_sysctl, parse_var_default};

    #[test]
    fn controls_collect_only_sysctl_rules_under_rules_block() {
        let yaml = "\
controls:
  - id: RHEL-09-213010
    levels: [medium]
    rules:
      - sysctl_kernel_dmesg_restrict
    status: automated
  - id: RHEL-09-OTHER
    rules:
      - some_non_sysctl_rule
  - id: RHEL-09-213025
    rules:
      - sysctl_kernel_kptr_restrict
    related_rules:
      - sysctl_should_be_ignored
";
        let c = parse_controls(yaml).unwrap();
        assert_eq!(c.len(), 2, "only the two sysctl-bearing controls");
        assert_eq!(c[0].id, "RHEL-09-213010");
        assert_eq!(c[0].sysctl_rules, ["sysctl_kernel_dmesg_restrict"]);
        assert_eq!(c[1].sysctl_rules, ["sysctl_kernel_kptr_restrict"]);
    }

    #[test]
    fn rule_scalar_and_list_sysctlval() {
        let scalar = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.dmesg_restrict
    sysctlval: '1'
    datatype: int
";
        let r = parse_rule_sysctl(scalar).unwrap();
        assert_eq!(r.sysctlvar, "kernel.dmesg_restrict");
        assert_eq!(r.sysctlval, Some(vec!["1".to_string()]));
        assert_eq!(r.datatype.as_deref(), Some("int"));

        let list = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.kptr_restrict
    sysctlval:
    - '1'
    - '2'
    datatype: int
";
        let r = parse_rule_sysctl(list).unwrap();
        assert_eq!(r.sysctlval, Some(vec!["1".to_string(), "2".to_string()]));
    }

    #[test]
    fn rule_string_datatype_and_no_inline_value() {
        let string_typed = "\
template:
  name: sysctl
  vars:
    sysctlvar: kernel.core_pattern
    sysctlval: '|/bin/false'
    datatype: string
";
        let r = parse_rule_sysctl(string_typed).unwrap();
        assert_eq!(r.sysctlval, Some(vec!["|/bin/false".to_string()]));
        assert_eq!(r.datatype.as_deref(), Some("string"));

        let var_driven = "\
template:
  name: sysctl
  vars:
    sysctlvar: net.ipv4.conf.all.rp_filter
    datatype: int
";
        let r = parse_rule_sysctl(var_driven).unwrap();
        assert_eq!(
            r.sysctlval, None,
            "no inline sysctlval -> defers to the var"
        );
    }

    #[test]
    fn non_sysctl_template_errors() {
        let not_sysctl = "\
template:
  name: something_else
  vars: {}
";
        assert!(parse_rule_sysctl(not_sysctl).is_err());
    }

    #[test]
    fn extract_block_pulls_only_the_template() {
        use super::extract_block;
        let rule = "\
documentation_complete: true
title: 'X'
description: |-
    {{{ full_name }}} blah {{ jinja }}
template:
    name: sysctl
    vars:
        sysctlvar: kernel.x
        sysctlval: '1'
        datatype: int
fixtext: |-
    {{{ fixtext_sysctl(...) }}}
";
        let block = extract_block(rule, "template").unwrap();
        assert!(block.starts_with("template:"));
        assert!(block.contains("sysctlvar: kernel.x"));
        assert!(!block.contains("fixtext"), "stops at the next col-0 key");
        assert!(!block.contains("description"), "excludes earlier prose");
        assert!(extract_block("title: x\n", "template").is_none());
    }

    #[test]
    fn var_default_value() {
        let var = "\
title: net.ipv4.conf.all.rp_filter
type: number
options:
    default: 1
    enabled: 1
    loose: 2
";
        assert_eq!(parse_var_default(var).unwrap(), "1");
    }
}
