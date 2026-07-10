//! Parse `attr-refs.toml`: the per-fapolicyd-version pinned upstream tag/commit +
//! the sha256 of the fetched `subject-attr.c` / `object-attr.c` sources. Keyed by
//! fapolicyd VERSION (e.g. `"1.3.2"`), not RHEL target, since rhel9/rhel10
//! currently share a fapolicyd version - see `../attr-refs.toml`'s header comment.

use std::collections::BTreeMap;
use std::path::Path;

/// One pinned upstream fapolicyd version's fetch coordinates + expected hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRef {
    /// The upstream git tag (e.g. `"v1.3.2"`).
    pub tag: String,
    /// The tag's commit SHA, pinned for provenance independent of a mutable tag.
    pub commit: String,
    /// Expected sha256 of the fetched `subject-attr.c`.
    pub subject_sha256: String,
    /// Expected sha256 of the fetched `object-attr.c`.
    pub object_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// fapolicyd version string (`"1.3.2"`, `"1.4.5"`, ...) -> its pinned ref.
    pub versions: BTreeMap<String, VersionRef>,
}

impl Config {
    pub fn parse(toml_src: &str) -> Result<Config, String> {
        // Parse a TOML *document* (`toml::Table`), not a bare value: matches
        // `tools/stig-update/src/config.rs`'s convention.
        let value: toml::Table = toml_src
            .parse()
            .map_err(|e| format!("attr-refs.toml: {e}"))?;

        let versions_tbl = value
            .get("versions")
            .and_then(toml::Value::as_table)
            .ok_or("attr-refs.toml: missing [versions] table")?;
        if versions_tbl.is_empty() {
            return Err("attr-refs.toml: [versions] is empty".to_string());
        }

        let mut versions = BTreeMap::new();
        for (key, val) in versions_tbl {
            let tbl = val
                .as_table()
                .ok_or_else(|| format!("attr-refs.toml: versions.{key} must be a table"))?;
            let field = |name: &str| -> Result<String, String> {
                tbl.get(name)
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        format!("attr-refs.toml: versions.{key}.{name} missing or not a string")
                    })
            };
            versions.insert(
                key.clone(),
                VersionRef {
                    tag: field("tag")?,
                    commit: field("commit")?,
                    subject_sha256: field("subject_sha256")?,
                    object_sha256: field("object_sha256")?,
                },
            );
        }

        Ok(Config { versions })
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

    /// The real committed `attr-refs.toml` (not a synthetic fixture) - parsing it
    /// correctly is itself a regression guard: `main.rs`'s default `--config`
    /// path loads exactly this file, so a parse bug here would break the shipped
    /// tool, not just a test double.
    const REAL_ATTR_REFS: &str = include_str!("../attr-refs.toml");

    #[test]
    fn parses_the_real_attr_refs_toml() {
        let c = Config::parse(REAL_ATTR_REFS).expect("attr-refs.toml parses");
        assert_eq!(
            c.versions.len(),
            2,
            "{:?}",
            c.versions.keys().collect::<Vec<_>>()
        );

        let v132 = &c.versions["1.3.2"];
        assert_eq!(v132.tag, "v1.3.2");
        assert_eq!(v132.commit, "7870b72f60394c8f1f8e22db9f738bbf1855978c");
        assert_eq!(
            v132.subject_sha256,
            "40dcab75bf382ffd8967f11452ed2a9919d9640501272a62a3789cdc4a279c65"
        );
        assert_eq!(
            v132.object_sha256,
            "d0f3e5fe251e39c4cbf2116a612b45d25ba0dcf09b79dccf74159bd495e2b8aa"
        );

        let v145 = &c.versions["1.4.5"];
        assert_eq!(v145.tag, "v1.4.5");
        assert_eq!(v145.commit, "69b55c21271aa40ae24bce7e1c869a635ea08776");
        assert_eq!(
            v145.subject_sha256,
            "e6e1bef074a49ff0a7c61e902609f254cff968ee00fbb40cfe42fe053988b57d"
        );
        assert_eq!(
            v145.object_sha256,
            "74894ea4e921da62c3154a79e858482bfe51fc7351290739c56bbdb69acfea44"
        );
    }

    #[test]
    fn missing_versions_table_errors() {
        assert!(Config::parse("# no [versions] table here\n").is_err());
    }

    #[test]
    fn empty_versions_table_errors() {
        assert!(Config::parse("[versions]\n").is_err());
    }

    #[test]
    fn a_version_missing_a_required_field_errors() {
        let src = "\
[versions.\"1.3.2\"]
tag = \"v1.3.2\"
commit = \"deadbeef\"
# subject_sha256 and object_sha256 both missing
";
        assert!(Config::parse(src).is_err());
    }
}
