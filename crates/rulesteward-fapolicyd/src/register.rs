//! Frozen data contract for the `report` verb's exception register (#80).
//!
//! This module freezes ONLY the serde data shape + the canonical AST-equality
//! key (fapd-C02 notion) that the `report` pipeline builds on. It deliberately
//! does NOT implement register-building, drift computation, trust-join, or any
//! renderer - those belong to the `report` pipeline. Phase-0 freezes the wire
//! contract so two later parallel features (`simulate`, `report`) can build
//! against a stable shape without editing each other's files.
//!
//! # Wire shape (camelCase, captured from the golden corpus)
//!
//! ```json
//! { "decision": "allow_audit", "perm": "open", "subject": "exe=/usr/bin/rpm",
//!   "object": "all", "subjectPaths": ["/usr/bin/rpm"], "objectPaths": [],
//!   "hash": null, "hashOrigin": "none", "hashAlgorithm": null, "scope": "path",
//!   "setExpansions": {}, "source": { "file": "34-fourdec.rules", "line": 2 },
//!   "loadIndex": 2 }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ast::{Attr, AttrValue, Decision, Perm, Rule};
use crate::facts::SetTable;

/// `kind` discriminator for the exception-register JSON envelope.
pub const EXCEPTION_REGISTER_KIND: &str = "exception-register";

/// `kind` discriminator for the exception-register drift JSON envelope.
pub const EXCEPTION_REGISTER_DRIFT_KIND: &str = "exception-register-drift";

/// Schema version for both the register and drift kinds. Bumps only on a
/// breaking change to the payload (field removal, rename, or retype).
pub const REGISTER_SCHEMA_VERSION: u32 = 1;

/// Where a register row's `hash` value originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashOrigin {
    /// No hash is associated with this grant.
    None,
    /// The hash came from a `sha256hash=`/`filehash=` literal in the rule.
    RuleFilehash,
    /// The hash came from the fapolicyd trust DB.
    Trustdb,
}

/// The hash algorithm of a register row's `hash` value, when known.
///
/// Serializes to the exact uppercase fapolicyd spellings via explicit per-variant
/// renames (so the wire form is independent of the Rust identifier casing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "MD5")]
    Md5,
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// The fapolicyd matching scope a grant was derived from (the narrowest object
/// constraint that produced the row).
///
/// # Scope precedence (narrowest wins, per f2 §2.2 / §3.2)
///
/// When a rule's object side carries multiple constraints the implementer must
/// pick the single narrowest one and record it here. Precedence, strongest first:
///
/// 1. `Hash`    - `filehash=` / `sha256hash=` literal (strongest static pin;
///    a filehash matches exactly one file version)
/// 2. `Path`    - `path=` or `exe=` literal (matches one specific filesystem path)
/// 3. `Ftype`   - `ftype=` MIME-type constraint
/// 4. `Dir`     - `dir=` directory-prefix constraint
/// 5. `Trust`   - `trust=1` (matches every entry in the trust DB)
/// 6. `Pattern` - `pattern=` `ld_so` / `mmap` / etc. (subject-side keyword match)
/// 7. `All`     - bare `all` (no object constraint at all; widest)
///
/// The corpus `combo-*` goldens pin this ordering:
/// - `combo-exe-and-filehash`  -> `hash`  (filehash beats exe= path)
/// - `combo-multi-everything`  -> `hash`  (filehash beats ftype + others)
/// - `combo-trust-and-ftype`   -> `ftype` (ftype beats trust=1)
/// - `combo-legacy-syntax-grant` -> `path` (path= literal)
/// - `combo-uid-gid-no-path`   -> `all`   (subject-only constraints, object=all)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    All,
    Path,
    Dir,
    Ftype,
    Pattern,
    Hash,
    Trust,
}

/// The rules.d source location a register row was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSource {
    pub file: String,
    pub line: usize,
}

/// One row of the exception register: a single resolved grant (allow decision)
/// with its rendered predicate, expanded paths, hash provenance, scope, and
/// source location.
///
/// `Deserialize` is derived so a previously-written register snapshot can be
/// read back for `--diff-against`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRow {
    pub decision: String,
    pub perm: String,
    pub subject: String,
    pub object: String,
    pub subject_paths: Vec<String>,
    pub object_paths: Vec<String>,
    pub hash: Option<String>,
    pub hash_origin: HashOrigin,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub scope: Scope,
    pub set_expansions: BTreeMap<String, Vec<String>>,
    pub source: RegisterSource,
    pub load_index: usize,
}

/// The kind of change a drift row represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriftKind {
    Added,
    Removed,
    Changed,
}

/// One row of an exception-register drift report (f2 §4.3).
///
/// `added`/`removed` carry one side (`to` / `from` respectively); `changed`
/// carries both `from` and `to`. `grant` is the canonical grant the row is keyed
/// on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftRow {
    pub kind: DriftKind,
    pub grant: RegisterRow,
    pub from: Option<RegisterRow>,
    pub to: Option<RegisterRow>,
}

/// Compute the canonical AST-equality key for a grant (the fapd-C02 notion).
///
/// Two rules with the same decision, perm (defaulting to `open` when absent),
/// and the same subject/object attribute SETS - order-insensitive, with any
/// `%set` reference expanded to its sorted concrete members - produce the SAME
/// key. A difference in decision, perm, subject, or object produces a DIFFERENT
/// key. This mirrors `lints::cross_file`'s C02 canonicalisation (sorted expanded
/// members, sorted `(key, value)` pairs per side) so the register's de-dup notion
/// matches the linter's duplicate-detection notion.
#[must_use]
pub fn canonical_grant_key(rule: &Rule, sets: &SetTable) -> String {
    let perm = rule.perm.unwrap_or(Perm::Open);
    format!(
        "{}|{}|{}|{}",
        decision_token(rule.decision),
        perm_token(perm),
        canonical_side(&rule.subject, sets),
        canonical_side(&rule.object, sets),
    )
}

/// Stable token for a decision (the lossless `Display` spelling).
fn decision_token(d: Decision) -> String {
    d.to_string()
}

/// Stable token for a perm (the lossless `Display` spelling).
fn perm_token(p: Perm) -> String {
    p.to_string()
}

/// Canonical, order-insensitive, set-expanded rendering of one predicate side.
///
/// `[Attr::All]` renders as the sentinel `all`. Otherwise each `Attr::Kv`
/// renders as `key=<sorted,expanded,comma-joined members>`; the pairs are then
/// sorted so attribute order within the side is insignificant (a predicate side
/// is a conjunction). Joined with `;`.
fn canonical_side(attrs: &[Attr], sets: &SetTable) -> String {
    let mut pairs: Vec<String> = Vec::with_capacity(attrs.len());
    for attr in attrs {
        match attr {
            Attr::All => pairs.push("all".to_owned()),
            Attr::Kv { key, value, .. } => {
                pairs.push(format!("{key}={}", canonical_value(value, sets)));
            }
        }
    }
    pairs.sort();
    pairs.join(";")
}

/// Canonical, order-insensitive, set-expanded rendering of one attribute value.
///
/// A `SetRef` expands to its sorted members (joined with `,`); a literal renders
/// to its single token. So `uid=%admins` (={0}) and `uid=0` produce the same
/// canonical value.
fn canonical_value(value: &AttrValue, sets: &SetTable) -> String {
    let mut members: Vec<String> = match value {
        AttrValue::SetRef(name) => sets.get(name).cloned().unwrap_or_default(),
        AttrValue::Str(s) => vec![s.clone()],
        AttrValue::Int(n) => vec![n.to_string()],
    };
    members.sort();
    members.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Entry, SyntaxFlavor};
    use rulesteward_core::span;

    // ---- serde-shape round-trip tests (the frozen wire contract) ----

    fn golden_row() -> RegisterRow {
        RegisterRow {
            decision: "allow_audit".to_owned(),
            perm: "open".to_owned(),
            subject: "exe=/usr/bin/rpm".to_owned(),
            object: "all".to_owned(),
            subject_paths: vec!["/usr/bin/rpm".to_owned()],
            object_paths: vec![],
            hash: None,
            hash_origin: HashOrigin::None,
            hash_algorithm: None,
            scope: Scope::Path,
            set_expansions: BTreeMap::new(),
            source: RegisterSource {
                file: "34-fourdec.rules".to_owned(),
                line: 2,
            },
            load_index: 2,
        }
    }

    /// The golden `RegisterRow` serializes to EXACTLY the captured camelCase JSON
    /// (every key name and value), and deserializes back to an equal value.
    #[test]
    fn register_row_serializes_to_golden_camel_case_shape() {
        let row = golden_row();
        let v = serde_json::to_value(&row).expect("serialize");
        let expected = serde_json::json!({
            "decision": "allow_audit",
            "perm": "open",
            "subject": "exe=/usr/bin/rpm",
            "object": "all",
            "subjectPaths": ["/usr/bin/rpm"],
            "objectPaths": [],
            "hash": null,
            "hashOrigin": "none",
            "hashAlgorithm": null,
            "scope": "path",
            "setExpansions": {},
            "source": { "file": "34-fourdec.rules", "line": 2 },
            "loadIndex": 2
        });
        assert_eq!(
            v, expected,
            "RegisterRow wire shape must match the golden JSON"
        );

        let back: RegisterRow =
            serde_json::from_value(v).expect("deserialize the snapshot back (for --diff-against)");
        assert_eq!(back, row, "RegisterRow must round-trip serde");
    }

    /// `HashOrigin` serializes to the exact kebab-case spellings.
    #[test]
    fn hash_origin_serializes_kebab_case() {
        for (variant, wire) in [
            (HashOrigin::None, "none"),
            (HashOrigin::RuleFilehash, "rule-filehash"),
            (HashOrigin::Trustdb, "trustdb"),
        ] {
            assert_eq!(
                serde_json::to_value(variant).unwrap(),
                serde_json::json!(wire)
            );
            let back: HashOrigin = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(back, variant, "{wire} must round-trip");
        }
    }

    /// `HashAlgorithm` serializes to the exact uppercase spellings.
    #[test]
    fn hash_algorithm_serializes_uppercase() {
        for (variant, wire) in [
            (HashAlgorithm::Md5, "MD5"),
            (HashAlgorithm::Sha1, "SHA1"),
            (HashAlgorithm::Sha256, "SHA256"),
            (HashAlgorithm::Sha512, "SHA512"),
        ] {
            assert_eq!(
                serde_json::to_value(variant).unwrap(),
                serde_json::json!(wire)
            );
            let back: HashAlgorithm = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(back, variant, "{wire} must round-trip");
        }
    }

    /// `Scope` serializes to the exact lowercase spellings.
    #[test]
    fn scope_serializes_lowercase() {
        for (variant, wire) in [
            (Scope::All, "all"),
            (Scope::Path, "path"),
            (Scope::Dir, "dir"),
            (Scope::Ftype, "ftype"),
            (Scope::Pattern, "pattern"),
            (Scope::Hash, "hash"),
            (Scope::Trust, "trust"),
        ] {
            assert_eq!(
                serde_json::to_value(variant).unwrap(),
                serde_json::json!(wire)
            );
        }
    }

    /// `DriftKind` serializes to lowercase; a `changed` `DriftRow` carries both
    /// `from` and `to`.
    #[test]
    fn drift_kind_serializes_lowercase_and_drift_row_round_trips() {
        for (variant, wire) in [
            (DriftKind::Added, "added"),
            (DriftKind::Removed, "removed"),
            (DriftKind::Changed, "changed"),
        ] {
            assert_eq!(
                serde_json::to_value(variant).unwrap(),
                serde_json::json!(wire)
            );
        }
        let row = DriftRow {
            kind: DriftKind::Changed,
            grant: golden_row(),
            from: Some(golden_row()),
            to: Some(golden_row()),
        };
        let v = serde_json::to_value(&row).expect("serialize");
        assert_eq!(v["kind"], serde_json::json!("changed"));
        assert!(v["from"].is_object() && v["to"].is_object());
        let back: DriftRow = serde_json::from_value(v).expect("round-trip");
        assert_eq!(back, row);
    }

    // ---- canonical_grant_key (real logic) tests ----

    fn kv(key: &str, value: AttrValue) -> Attr {
        Attr::Kv {
            key: key.to_owned(),
            value,
            span: span(0, 0),
        }
    }

    fn rule(decision: Decision, perm: Option<Perm>, subject: Vec<Attr>, object: Vec<Attr>) -> Rule {
        Rule {
            decision,
            perm,
            subject,
            object,
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: span(0, 0),
        }
    }

    fn empty_sets() -> SetTable {
        SetTable::from_entries(&[])
    }

    /// Same predicate, different ATTRIBUTE ORDER within a side -> SAME key.
    #[test]
    fn key_is_order_insensitive_within_a_side() {
        let a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![
                kv("uid", AttrValue::Int(0)),
                kv("exe", AttrValue::Str("/bin/sh".into())),
            ],
            vec![Attr::All],
        );
        let b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![
                kv("exe", AttrValue::Str("/bin/sh".into())),
                kv("uid", AttrValue::Int(0)),
            ],
            vec![Attr::All],
        );
        let sets = empty_sets();
        assert_eq!(
            canonical_grant_key(&a, &sets),
            canonical_grant_key(&b, &sets),
            "reordered attrs must yield the same key"
        );
    }

    /// A different DECISION yields a different key.
    #[test]
    fn key_differs_on_decision() {
        let sets = empty_sets();
        let a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        let b = rule(
            Decision::Deny,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&a, &sets),
            canonical_grant_key(&b, &sets)
        );
    }

    /// A different PERM yields a different key.
    #[test]
    fn key_differs_on_perm() {
        let sets = empty_sets();
        let a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        let b = rule(
            Decision::Allow,
            Some(Perm::Execute),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&a, &sets),
            canonical_grant_key(&b, &sets)
        );
    }

    /// A different SUBJECT yields a different key.
    #[test]
    fn key_differs_on_subject() {
        let sets = empty_sets();
        let a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::Int(0))],
            vec![Attr::All],
        );
        let b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::Int(1))],
            vec![Attr::All],
        );
        assert_ne!(
            canonical_grant_key(&a, &sets),
            canonical_grant_key(&b, &sets)
        );
    }

    /// A different OBJECT yields a different key.
    #[test]
    fn key_differs_on_object() {
        let sets = empty_sets();
        let a = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/a".into()))],
        );
        let b = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![kv("path", AttrValue::Str("/b".into()))],
        );
        assert_ne!(
            canonical_grant_key(&a, &sets),
            canonical_grant_key(&b, &sets)
        );
    }

    /// A `%set` reference expands to the SAME key as the explicit sorted members.
    #[test]
    fn key_set_ref_expands_to_member_key() {
        let sets = SetTable::from_entries(&[Entry::SetDefinition {
            name: "admins".to_owned(),
            // out-of-order to prove the expansion is sorted, not literal
            values: vec!["1".to_owned(), "0".to_owned()],
            line: 1,
            span: span(0, 0),
        }]);
        let via_ref = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::SetRef("admins".into()))],
            vec![Attr::All],
        );
        // Explicit members modeled as a literal whose canonical form is the same
        // sorted, comma-joined member list "0,1".
        let via_literal = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![kv("uid", AttrValue::Str("0,1".into()))],
            vec![Attr::All],
        );
        assert_eq!(
            canonical_grant_key(&via_ref, &sets),
            canonical_grant_key(&via_literal, &sets),
            "a %set ref must canonicalise to its sorted member list"
        );
    }

    /// An absent perm defaults to `open` (so `allow : all` keys equal
    /// `allow perm=open : all`).
    #[test]
    fn key_absent_perm_defaults_to_open() {
        let sets = empty_sets();
        let no_perm = rule(Decision::Allow, None, vec![Attr::All], vec![Attr::All]);
        let open = rule(
            Decision::Allow,
            Some(Perm::Open),
            vec![Attr::All],
            vec![Attr::All],
        );
        assert_eq!(
            canonical_grant_key(&no_perm, &sets),
            canonical_grant_key(&open, &sets),
            "absent perm must default to open"
        );
    }
}
