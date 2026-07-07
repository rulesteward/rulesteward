//! The owned comparison shape ([`DerivedControl`]) plus the two sides fed to the
//! drift diff: the DISA-XCCDF-derived table (built in [`crate::xccdf`]) and the
//! shipped `rulesteward-sshd` projection ([`code_table`]). Both are `String`-owned
//! so a parsed-from-XML row compares directly against the crate's `&'static`
//! `StigControl` projection.

use std::collections::BTreeMap;
use std::fmt;

use rulesteward_sshd::TargetVersion;
use rulesteward_sshd::lints::stig::{StigControl, StigValueRule};

/// A STIG value assertion, owned so it can be built from parsed XCCDF text. Owned
/// mirror of the crate's `&'static` [`StigValueRule`]; the two compare via
/// [`OwnedValueRule::of_projection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedValueRule {
    /// Presence-only (W01): required present, no specific value (Banner).
    PresenceOnly,
    /// Exact case-insensitive literal (PermitRootLogin `no`, LogLevel `verbose`).
    ExactLower(String),
    /// Exact two-token match (RekeyLimit `1g 1h`).
    TwoTokenExact(String, String),
    /// Any of the listed lowercase values (Compression: `delayed` or `no`).
    AnyOf(Vec<String>),
    /// Numeric ceiling: value must be `> 0` and `<= N` (ClientAliveInterval `<= 600`).
    NumericCeiling(u64),
    /// Numeric exact: value must equal N exactly (ClientAliveCountMax `1`).
    NumericExact(u64),
}

impl OwnedValueRule {
    /// Widen the crate's `&'static` projection variant into the owned form.
    #[must_use]
    pub fn of_projection(rule: StigValueRule) -> OwnedValueRule {
        match rule {
            StigValueRule::PresenceOnly => OwnedValueRule::PresenceOnly,
            StigValueRule::ExactLower(s) => OwnedValueRule::ExactLower(s.to_string()),
            StigValueRule::TwoTokenExact(a, b) => {
                OwnedValueRule::TwoTokenExact(a.to_string(), b.to_string())
            }
            StigValueRule::AnyOf(v) => {
                OwnedValueRule::AnyOf(v.iter().map(|s| (*s).to_string()).collect())
            }
            StigValueRule::NumericCeiling(n) => OwnedValueRule::NumericCeiling(n),
            StigValueRule::NumericExact(n) => OwnedValueRule::NumericExact(n),
        }
    }
}

impl fmt::Display for OwnedValueRule {
    /// Compact, human-readable rendering used in the derive listing and drift diff.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwnedValueRule::PresenceOnly => write!(f, "presence-only (W01)"),
            OwnedValueRule::ExactLower(s) => write!(f, "exactly \"{s}\""),
            OwnedValueRule::TwoTokenExact(a, b) => write!(f, "exactly \"{a} {b}\""),
            OwnedValueRule::AnyOf(v) => write!(f, "one of: {}", v.join(", ")),
            OwnedValueRule::NumericCeiling(n) => write!(f, "> 0 and <= {n}"),
            OwnedValueRule::NumericExact(n) => write!(f, "exactly {n}"),
        }
    }
}

/// One derived STIG control row, normalized for comparison against the shipped
/// projection: lowercase keyword, DISA V-number, and the value assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedControl {
    /// Directive keyword, lowercase.
    pub keyword: String,
    /// DISA V-number (e.g. `V-257985`).
    pub v_number: String,
    /// The W02 value assertion, or `PresenceOnly` for a W01 presence-only control.
    pub value_rule: OwnedValueRule,
}

impl DerivedControl {
    /// Project one shipped `&'static` [`StigControl`] into the owned comparison shape.
    #[must_use]
    pub fn of_projection(c: &StigControl) -> DerivedControl {
        DerivedControl {
            keyword: c.keyword.to_string(),
            v_number: c.v_number.to_string(),
            value_rule: OwnedValueRule::of_projection(c.value_rule),
        }
    }
}

/// The shipped `rulesteward-sshd` STIG table for `target`, projected into the
/// comparison shape. This is the "code" side of the drift diff.
#[must_use]
pub fn code_table(target: TargetVersion) -> Vec<DerivedControl> {
    rulesteward_sshd::lints::stig::stig_baseline(target)
        .iter()
        .map(DerivedControl::of_projection)
        .collect()
}

/// Human-readable diff of an `upstream`-derived table against the shipped `code`
/// table, both keyed by directive keyword. Empty result == no drift.
///
/// `-` a directive in code but absent in the derived DISA set; `+` a directive new
/// in DISA; `~` a changed V-number or value rule for a shared directive.
#[must_use]
pub fn diff_controls(upstream: &[DerivedControl], code: &[DerivedControl]) -> Vec<String> {
    let umap: BTreeMap<&str, &DerivedControl> =
        upstream.iter().map(|d| (d.keyword.as_str(), d)).collect();
    let cmap: BTreeMap<&str, &DerivedControl> =
        code.iter().map(|d| (d.keyword.as_str(), d)).collect();

    let mut keys: Vec<&str> = umap.keys().chain(cmap.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut out = Vec::new();
    for k in keys {
        match (cmap.get(k), umap.get(k)) {
            (Some(_), None) => out.push(format!("- {k}  (in code, absent in the DISA XCCDF)")),
            (None, Some(u)) => out.push(format!(
                "+ {k} = {} ({}, new in the DISA XCCDF)",
                u.value_rule, u.v_number
            )),
            (Some(c), Some(u)) => {
                if c.v_number != u.v_number {
                    out.push(format!(
                        "~ {k} V-number: code {} -> DISA {}",
                        c.v_number, u.v_number
                    ));
                }
                if c.value_rule != u.value_rule {
                    out.push(format!(
                        "~ {k} value rule: code [{}] -> DISA [{}]",
                        c.value_rule, u.value_rule
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
    use super::*;

    fn ctl(kw: &str, v: &str, rule: OwnedValueRule) -> DerivedControl {
        DerivedControl {
            keyword: kw.to_string(),
            v_number: v.to_string(),
            value_rule: rule,
        }
    }

    #[test]
    fn code_table_projects_shipped_projection_faithfully() {
        // The code table must equal the crate projection, row-for-row.
        let code = code_table(TargetVersion::Rhel9);
        assert_eq!(code.len(), 20);
        let prl = code
            .iter()
            .find(|c| c.keyword == "permitrootlogin")
            .expect("permitrootlogin present");
        assert_eq!(prl.v_number, "V-257985");
        assert_eq!(prl.value_rule, OwnedValueRule::ExactLower("no".to_string()));
        // Banner is presence-only.
        assert_eq!(
            code.iter()
                .find(|c| c.keyword == "banner")
                .unwrap()
                .value_rule,
            OwnedValueRule::PresenceOnly
        );
    }

    #[test]
    fn diff_empty_when_identical() {
        let code = code_table(TargetVersion::Rhel9);
        assert!(diff_controls(&code, &code).is_empty());
    }

    #[test]
    fn diff_reports_added_removed_and_changed() {
        let code = vec![
            ctl(
                "permitrootlogin",
                "V-1",
                OwnedValueRule::ExactLower("no".into()),
            ),
            ctl("removed", "V-9", OwnedValueRule::NumericExact(1)),
        ];
        let upstream = vec![
            // permitrootlogin: same v-number, but value rule changed
            ctl(
                "permitrootlogin",
                "V-1",
                OwnedValueRule::ExactLower("prohibit-password".into()),
            ),
            // added: brand new
            ctl("added", "V-2", OwnedValueRule::PresenceOnly),
        ];
        let d = diff_controls(&upstream, &code);
        assert!(d.iter().any(|l| l.starts_with("- removed")), "{d:?}");
        assert!(d.iter().any(|l| l.starts_with("+ added")), "{d:?}");
        assert!(
            d.iter().any(|l| l.contains("permitrootlogin value rule")),
            "{d:?}"
        );
        // v-number unchanged for permitrootlogin -> no V-number drift line
        assert!(
            !d.iter().any(|l| l.contains("permitrootlogin V-number")),
            "{d:?}"
        );
    }

    #[test]
    fn diff_reports_v_number_drift() {
        let code = vec![ctl("banner", "V-257981", OwnedValueRule::PresenceOnly)];
        let upstream = vec![ctl("banner", "V-999999", OwnedValueRule::PresenceOnly)];
        let d = diff_controls(&upstream, &code);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("banner V-number: code V-257981 -> DISA V-999999"));
    }

    /// The `Display` impl renders the value rule in the `derive` paste-ready output
    /// and the drift-diff messages, so a broken rendering would ship wrong content
    /// silently. Assert every variant's exact rendering.
    #[test]
    fn owned_value_rule_display_renders_each_variant() {
        assert_eq!(
            OwnedValueRule::PresenceOnly.to_string(),
            "presence-only (W01)"
        );
        assert_eq!(
            OwnedValueRule::ExactLower("no".into()).to_string(),
            "exactly \"no\""
        );
        assert_eq!(
            OwnedValueRule::TwoTokenExact("1g".into(), "1h".into()).to_string(),
            "exactly \"1g 1h\""
        );
        assert_eq!(
            OwnedValueRule::AnyOf(vec!["delayed".into(), "no".into()]).to_string(),
            "one of: delayed, no"
        );
        assert_eq!(
            OwnedValueRule::NumericCeiling(600).to_string(),
            "> 0 and <= 600"
        );
        assert_eq!(OwnedValueRule::NumericExact(1).to_string(), "exactly 1");
    }
}
