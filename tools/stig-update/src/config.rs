//! Parse `stig-refs.toml`: the CDN base URL + the per-product pinned DISA STIG zip.
//! Per-product pins let each RHEL STIG be bumped independently.
//!
//! #512 (session 9h-v0_8-wave4 Lane B): this REPLACES the prior ComplianceAsCode
//! ref-based shape (`products: BTreeMap<String, String>` + `exclude_rules: Vec<String>`)
//! with the DISA zip/base_url/products shape `tools/sshd-stig-update/src/config.rs`
//! and `tools/auditd-stig-update/src/config.rs` already use verbatim - grounded in
//! `/mnt/side-projects/9h-v0_8-wave4/lane-b-grounding.md` section 4b: the DISA port
//! needs NO `exclude_rules` equivalent at all (both CaC-era exclusions collapse into
//! "the xccdf.rs selector simply never selects it" - see that module's doc comment).
//! `tools/cis-update` does NOT import `stig_update::config` (confirmed: only `jinja`,
//! `cac`, `derive`, `source` are on the #512 survival list per that crate's Cargo.toml
//! header and `grep -rn stig_update:: tools/cis-update/src`), so this shape change is
//! safe - nothing outside this crate depends on the old CaC-ref shape.
//!
//! `Config::parse`'s body is intentionally `todo!()`: the barrier test-author (this
//! lane) declares the target shape and pins the exact expected parse behavior in the
//! test module below; the implementer fills in the body. Mirrors the sshd/auditd
//! precedent's own historical RED state for `xccdf.rs::parse_controls` /
//! `parse_requirements` (both were `todo!()` at their own test-author barrier).

use std::collections::BTreeMap;
use std::path::Path;

/// One product's pinned DISA STIG zip.
pub struct Product {
    /// The zip filename (e.g. `U_RHEL_9_V2R9_STIG.zip`).
    pub zip: String,
    /// Human label for the benchmark (e.g. `RHEL 9 STIG V2R9 (01 Jul 2026)`).
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
    /// Parse a `stig-refs.toml` document into the DISA zip/base_url/products shape.
    ///
    /// # Errors
    /// `base_url` missing/non-string, `[products]` missing/empty, or a
    /// `products.<name>` entry missing/non-string `zip` (mirrors
    /// `tools/sshd-stig-update/src/config.rs::Config::parse` exactly - see the tests
    /// module below for the pinned error cases).
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

    // Byte-identical sample to tools/sshd-stig-update/src/config.rs's own
    // `SAMPLE` fixture (mirrors that tool's config shape exactly per #512's
    // "port to DISA XCCDF" mandate - the refs-loading half of the tool is
    // equally in scope for the port, not just the derivation core).
    const SAMPLE: &str = "\
base_url = \"https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip\"

[products.rhel8]
zip = \"U_RHEL_8_V2R8_STIG.zip\"
benchmark = \"RHEL 8 STIG V2R8\"

[products.rhel9]
zip = \"U_RHEL_9_V2R9_STIG.zip\"
benchmark = \"RHEL 9 STIG V2R9\"
";

    #[test]
    fn parses_base_url_and_products() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.products.len(), 2);
        assert_eq!(c.products["rhel9"].zip, "U_RHEL_9_V2R9_STIG.zip");
        assert_eq!(c.products["rhel9"].benchmark, "RHEL 9 STIG V2R9");
        assert_eq!(
            c.zip_url(&c.products["rhel9"]),
            "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip"
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
    fn empty_products_table_errors() {
        // An explicit but empty [products] table is still a misconfiguration - the
        // tool has nothing to derive/check without at least one product.
        assert!(
            Config::parse("base_url = \"https://x\"\n[products]\n").is_err(),
            "an empty [products] table must error, not silently succeed with zero products"
        );
    }

    #[test]
    fn benchmark_defaults_to_product_name_when_absent() {
        // Mirrors the sshd/auditd tool's own `benchmark_defaults_to_product_name`:
        // a products.<p> entry with no `benchmark` key falls back to the product
        // name itself, rather than erroring or leaving an empty string.
        let c = Config::parse("base_url=\"u\"\n[products.rhel9]\nzip=\"z.zip\"").unwrap();
        assert_eq!(c.products["rhel9"].benchmark, "rhel9");
    }

    #[test]
    fn product_entry_missing_zip_errors() {
        assert!(
            Config::parse("base_url=\"u\"\n[products.rhel9]\nbenchmark=\"RHEL 9\"").is_err(),
            "a products.<p> entry with no zip must error"
        );
    }

    #[test]
    fn the_real_pinned_stig_refs_toml_parses() {
        // The real committed tools/stig-update/stig-refs.toml (DISA form, #512) must
        // itself parse under the new shape - this is the "refs shape" acceptance test
        // the barrier brief calls for, against the actual shipped file (not just a
        // synthetic SAMPLE), mirroring the same real-file pin the sshd/auditd tools'
        // own config test modules do NOT have today but which this port's grounding
        // (grounding doc section 4b: "no exclude_rules equivalent needed") makes
        // worth asserting directly.
        let real = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/stig-refs.toml"))
            .expect("the real stig-refs.toml is readable");
        let c = Config::parse(&real).expect("the real committed stig-refs.toml must parse");
        assert_eq!(c.products.len(), 3, "rhel8/rhel9/rhel10, no more no less");
        for p in ["rhel8", "rhel9", "rhel10"] {
            assert!(c.products.contains_key(p), "missing product {p:?}");
            assert!(
                c.products[p].zip.ends_with(".zip"),
                "product {p:?} zip must be a .zip filename: {:?}",
                c.products[p].zip
            );
        }
        assert_eq!(
            c.base_url,
            "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"
        );
    }
}
