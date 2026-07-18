//! Parse `cis-refs.toml`: the per-product pinned upstream ref + the sysctl
//! value-derivation exclusions. Per-product refs let each RHEL CIS benchmark be
//! bumped independently (they version independently upstream).

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug)]
pub struct Config {
    /// product (`rhel8` / `rhel9` / `rhel10`) -> pinned ComplianceAsCode ref
    /// (commit SHA or release tag).
    pub products: BTreeMap<String, String>,
    /// `sysctl_*` rule names excluded from `derive --values` VALUE derivation only
    /// (rules with no `sysctl` template). Unlike stig-refs.toml's list, exclusion
    /// here does NOT remove a control from the id-level family tables.
    pub exclude_rules: Vec<String>,
}

impl Config {
    pub fn parse(toml_src: &str) -> Result<Config, String> {
        // Parse a TOML *document* (`toml::Table`), not a bare value: `Value::FromStr`
        // would read the leading `[products]` as an inline array.
        let value: toml::Table = toml_src
            .parse()
            .map_err(|e| format!("cis-refs.toml: {e}"))?;

        let products_tbl = value
            .get("products")
            .and_then(toml::Value::as_table)
            .ok_or("cis-refs.toml: missing [products] table")?;
        let mut products = BTreeMap::new();
        for (k, v) in products_tbl {
            let r = v
                .as_str()
                .ok_or_else(|| format!("products.{k} must be a string ref"))?;
            products.insert(k.clone(), r.to_string());
        }
        if products.is_empty() {
            return Err("cis-refs.toml: [products] is empty".to_string());
        }

        let exclude_rules = value
            .get("exclude_rules")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Config {
            products,
            exclude_rules,
        })
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let s =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Config::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_products_and_exclusions() {
        let src = "\
exclude_rules = [\"sysctl_example_no_template\"]

[products]
rhel8 = \"abc123\"
rhel9 = \"def456\"
rhel10 = \"abc123\"
";
        let c = Config::parse(src).unwrap();
        assert_eq!(c.products.len(), 3);
        assert_eq!(c.products["rhel9"], "def456");
        assert_eq!(c.exclude_rules, vec!["sysctl_example_no_template"]);
    }

    #[test]
    fn absent_exclude_rules_defaults_to_empty() {
        let c = Config::parse("[products]\nrhel9 = \"abc\"\n").unwrap();
        assert!(c.exclude_rules.is_empty());
        assert_eq!(c.products["rhel9"], "abc");
    }

    #[test]
    fn missing_products_table_errors() {
        let e = Config::parse("exclude_rules = []").unwrap_err();
        assert!(e.contains("cis-refs.toml"), "error names the file: {e}");
        assert!(e.contains("[products]"), "error names the table: {e}");
    }

    #[test]
    fn empty_products_table_errors() {
        assert!(Config::parse("[products]\n").is_err());
    }

    #[test]
    fn non_string_ref_errors() {
        assert!(Config::parse("[products]\nrhel9 = 7\n").is_err());
    }
}
