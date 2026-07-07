//! Parse `stig-refs.toml`: the CDN base URL + the per-product pinned DISA STIG zip.
//! Per-product pins let each RHEL STIG be bumped independently.

use std::collections::BTreeMap;
use std::path::Path;

/// One product's pinned DISA STIG zip.
pub struct Product {
    /// The zip filename (e.g. `U_RHEL_9_V2R7_STIG.zip`).
    pub zip: String,
    /// Human label for the benchmark (e.g. `RHEL 9 STIG V2R7 (05 Jan 2026)`).
    pub benchmark: String,
}

/// Parsed `stig-refs.toml`.
pub struct Config {
    /// CDN base URL; the full zip URL is `base_url/<product.zip>`.
    pub base_url: String,
    /// product (`rhel8` / `rhel9` / `rhel10`) -> pinned zip.
    pub products: BTreeMap<String, Product>,
}

impl Config {
    pub fn parse(toml_src: &str) -> Result<Config, String> {
        let value: toml::Table = toml_src
            .parse()
            .map_err(|e| format!("stig-refs.toml: {e}"))?;

        let base_url = value
            .get("base_url")
            .and_then(toml::Value::as_str)
            .ok_or("stig-refs.toml: missing string `base_url`")?
            .to_string();

        let products_tbl = value
            .get("products")
            .and_then(toml::Value::as_table)
            .ok_or("stig-refs.toml: missing [products] table")?;
        let mut products = BTreeMap::new();
        for (name, v) in products_tbl {
            let tbl = v
                .as_table()
                .ok_or_else(|| format!("products.{name} must be a table"))?;
            let zip = tbl
                .get("zip")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("products.{name}.zip must be a string"))?
                .to_string();
            let benchmark = tbl
                .get("benchmark")
                .and_then(toml::Value::as_str)
                .unwrap_or(name)
                .to_string();
            products.insert(name.clone(), Product { zip, benchmark });
        }
        if products.is_empty() {
            return Err("stig-refs.toml: [products] is empty".to_string());
        }

        Ok(Config { base_url, products })
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let s =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Config::parse(&s)
    }

    /// The full download URL for a product's pinned zip.
    #[must_use]
    pub fn zip_url(&self, product: &Product) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), product.zip)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    const SAMPLE: &str = "\
base_url = \"https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip\"

[products.rhel8]
zip = \"U_RHEL_8_V2R4_STIG.zip\"
benchmark = \"RHEL 8 STIG V2R4\"

[products.rhel9]
zip = \"U_RHEL_9_V2R7_STIG.zip\"
benchmark = \"RHEL 9 STIG V2R7\"
";

    #[test]
    fn parses_base_url_and_products() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.products.len(), 2);
        assert_eq!(c.products["rhel9"].zip, "U_RHEL_9_V2R7_STIG.zip");
        assert_eq!(c.products["rhel9"].benchmark, "RHEL 9 STIG V2R7");
        assert_eq!(
            c.zip_url(&c.products["rhel9"]),
            "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R7_STIG.zip"
        );
    }

    #[test]
    fn missing_base_url_errors() {
        assert!(Config::parse("[products.rhel9]\nzip = \"x.zip\"").is_err());
    }

    #[test]
    fn missing_products_errors() {
        assert!(Config::parse("base_url = \"https://x\"").is_err());
    }

    #[test]
    fn benchmark_defaults_to_product_name() {
        let c = Config::parse("base_url=\"u\"\n[products.rhel9]\nzip=\"z.zip\"").unwrap();
        assert_eq!(c.products["rhel9"].benchmark, "rhel9");
    }
}
