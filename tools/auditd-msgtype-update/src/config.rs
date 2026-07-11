//! Parse `msgtype-refs.toml`: the pinned audit-userspace commit + kernel tag
//! and the sha256 of each fetched header. TWO separate tables for the TWO
//! distinct upstreams (`[audit-userspace]` and `[kernel]`) - see
//! `../msgtype-refs.toml`'s header comment for why both sources are needed
//! and how their provenances are kept apart.

use std::path::Path;

/// The pinned audit-userspace ref: one commit carrying both
/// `lib/msg_typetab.h` and `lib/audit-records.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditUserspaceRef {
    /// The pinned upstream commit (e.g. `"3bfa048"`).
    pub commit: String,
    /// Expected sha256 of the fetched `lib/msg_typetab.h`.
    pub msg_typetab_sha256: String,
    /// Expected sha256 of the fetched `lib/audit-records.h`.
    pub audit_records_sha256: String,
}

/// The pinned Linux kernel ref: one tag carrying
/// `include/uapi/linux/audit.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRef {
    /// The pinned kernel tag (e.g. `"v6.6"`).
    pub tag: String,
    /// Expected sha256 of the fetched `include/uapi/linux/audit.h`.
    pub audit_h_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub audit_userspace: AuditUserspaceRef,
    pub kernel: KernelRef,
}

impl Config {
    /// Parse a `msgtype-refs.toml` document. Errors (with a message naming the
    /// missing piece) when the `[audit-userspace]` or `[kernel]` table is
    /// absent, or any of the five required string fields is missing or not a
    /// string. Mirrors `tools/fapolicyd-attr-update/src/config.rs`'s
    /// parse-a-TOML-document convention.
    pub fn parse(toml_src: &str) -> Result<Config, String> {
        let value: toml::Table = toml_src
            .parse()
            .map_err(|e| format!("msgtype-refs.toml: {e}"))?;

        let audit_userspace_tbl = value
            .get("audit-userspace")
            .and_then(toml::Value::as_table)
            .ok_or("msgtype-refs.toml: missing [audit-userspace] table")?;
        let au_field = |name: &str| -> Result<String, String> {
            audit_userspace_tbl
                .get(name)
                .and_then(toml::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    format!("msgtype-refs.toml: audit-userspace.{name} missing or not a string")
                })
        };
        let audit_userspace = AuditUserspaceRef {
            commit: au_field("commit")?,
            msg_typetab_sha256: au_field("msg_typetab_sha256")?,
            audit_records_sha256: au_field("audit_records_sha256")?,
        };

        let kernel_tbl = value
            .get("kernel")
            .and_then(toml::Value::as_table)
            .ok_or("msgtype-refs.toml: missing [kernel] table")?;
        let k_field = |name: &str| -> Result<String, String> {
            kernel_tbl
                .get(name)
                .and_then(toml::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("msgtype-refs.toml: kernel.{name} missing or not a string"))
        };
        let kernel = KernelRef {
            tag: k_field("tag")?,
            audit_h_sha256: k_field("audit_h_sha256")?,
        };

        Ok(Config {
            audit_userspace,
            kernel,
        })
    }

    /// Read `path` and [`Config::parse`] it, folding an IO failure into the
    /// error message.
    pub fn load(path: &Path) -> Result<Config, String> {
        let s =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Config::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    /// The real committed `msgtype-refs.toml` (not a synthetic fixture) -
    /// parsing it correctly is itself a regression guard: `main.rs`'s default
    /// `--config` path loads exactly this file, so a parse bug here would
    /// break the shipped tool, not just a test double.
    const REAL_MSGTYPE_REFS: &str = include_str!("../msgtype-refs.toml");

    #[test]
    fn parses_the_real_msgtype_refs_toml() {
        let c = Config::parse(REAL_MSGTYPE_REFS).expect("msgtype-refs.toml parses");
        assert_eq!(c.audit_userspace.commit, "3bfa048");
        assert_eq!(
            c.audit_userspace.msg_typetab_sha256,
            "9c61cd1986271e6a1028ca587f9b7b99ac0d8a6d7d10b95dd284efe45255ff87"
        );
        assert_eq!(
            c.audit_userspace.audit_records_sha256,
            "47d10faa6f222387da89549bee202b85578dd36012b4d48d229ba107a67e67ae"
        );
        assert_eq!(c.kernel.tag, "v6.6");
        assert_eq!(
            c.kernel.audit_h_sha256,
            "db86160b09c1ef7c1ac2dd59a9d6b5d19a8494739dd8d78fc0464e8bc8ad8f55"
        );
    }

    #[test]
    fn missing_audit_userspace_table_errors() {
        let src = "[kernel]\ntag = \"v6.6\"\naudit_h_sha256 = \"aa\"\n";
        assert!(Config::parse(src).is_err());
    }

    #[test]
    fn missing_kernel_table_errors() {
        let src = "[audit-userspace]\ncommit = \"3bfa048\"\n\
                   msg_typetab_sha256 = \"aa\"\naudit_records_sha256 = \"bb\"\n";
        assert!(Config::parse(src).is_err());
    }

    #[test]
    fn a_missing_required_field_errors() {
        // kernel.audit_h_sha256 deliberately absent.
        let src = "[audit-userspace]\ncommit = \"3bfa048\"\n\
                   msg_typetab_sha256 = \"aa\"\naudit_records_sha256 = \"bb\"\n\
                   [kernel]\ntag = \"v6.6\"\n";
        assert!(Config::parse(src).is_err());
    }

    #[test]
    fn a_non_string_field_errors() {
        let src = "[audit-userspace]\ncommit = 3\n\
                   msg_typetab_sha256 = \"aa\"\naudit_records_sha256 = \"bb\"\n\
                   [kernel]\ntag = \"v6.6\"\naudit_h_sha256 = \"cc\"\n";
        assert!(Config::parse(src).is_err());
    }
}
