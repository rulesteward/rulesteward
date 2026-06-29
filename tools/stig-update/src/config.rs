//! Parse `stig-refs.toml`: the per-product pinned upstream ref + the rule-name
//! exclusions. Per-product refs let each RHEL STIG be bumped independently.

use std::collections::BTreeMap;
use std::path::Path;

pub struct Config {
    /// product (`rhel8` / `rhel9` / `rhel10`) -> pinned ComplianceAsCode ref
    /// (commit SHA or release tag).
    pub products: BTreeMap<String, String>,
    /// Rule names that are STIG-listed but NOT `/etc/sysctl.d`-settable on RHEL, so
    /// derivation skips them (e.g. `sysctl_crypto_fips_enabled`,
    /// `sysctl_kernel_exec_shield`). A non-excluded rule with no sysctl template is a
    /// hard error, so this list is the explicit allow-to-drop.
    pub exclude_rules: Vec<String>,
}

impl Config {
    pub fn parse(toml_src: &str) -> Result<Config, String> {
        // Parse a TOML *document* (`toml::Table`), not a bare value: `Value::FromStr`
        // would read the leading `[products]` as an inline array.
        let value: toml::Table = toml_src
            .parse()
            .map_err(|e| format!("stig-refs.toml: {e}"))?;

        let products_tbl = value
            .get("products")
            .and_then(toml::Value::as_table)
            .ok_or("stig-refs.toml: missing [products] table")?;
        let mut products = BTreeMap::new();
        for (k, v) in products_tbl {
            let r = v
                .as_str()
                .ok_or_else(|| format!("products.{k} must be a string ref"))?;
            products.insert(k.clone(), r.to_string());
        }
        if products.is_empty() {
            return Err("stig-refs.toml: [products] is empty".to_string());
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
exclude_rules = [\"sysctl_crypto_fips_enabled\", \"sysctl_kernel_exec_shield\"]

[products]
rhel8 = \"abc123\"
rhel9 = \"def456\"
rhel10 = \"abc123\"
";
        let c = Config::parse(src).unwrap();
        assert_eq!(c.products.len(), 3);
        assert_eq!(c.products["rhel9"], "def456");
        assert_eq!(c.exclude_rules.len(), 2);
        assert!(
            c.exclude_rules
                .iter()
                .any(|r| r == "sysctl_kernel_exec_shield")
        );
    }

    #[test]
    fn missing_products_table_errors() {
        assert!(Config::parse("exclude_rules = []").is_err());
    }
}
