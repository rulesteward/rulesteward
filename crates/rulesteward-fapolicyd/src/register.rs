//! Frozen data contract + register-building / drift logic for the `report` verb
//! (issues #80/#81/#82/#83).
//!
//! Phase-0 froze the wire contract (serde shapes + `canonical_grant_key`).
//! The `feat-report` pipeline adds `build_register` and `compute_drift` here.
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

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule};
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

// ---------------------------------------------------------------------------
// Register building
// ---------------------------------------------------------------------------

/// True iff `decision` is in the allow family (allow / `allow_audit` / `allow_syslog` / `allow_log`).
///
/// Deny-family decisions are excluded from the exception register.
fn is_allow_family(d: Decision) -> bool {
    matches!(
        d,
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog
    )
}

/// Render a predicate side (subject or object) as a space-joined string of its
/// attribute tokens.
///
/// Each `Attr::Kv { key, value, .. }` renders as `key=value` (using the
/// lossless `Display for AttrValue`). `Attr::All` renders as `"all"`.
/// Multiple attrs are joined with a single space.
fn render_side(attrs: &[Attr]) -> String {
    attrs
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract all literal path values from a predicate side for `exe=`, `path=`,
/// and `dir=` keys. Set refs are NOT expanded here (paths must be literals to
/// be meaningful as filesystem paths).
fn extract_paths(attrs: &[Attr]) -> Vec<String> {
    let mut paths = Vec::new();
    for attr in attrs {
        if let Attr::Kv {
            key,
            value: AttrValue::Str(s),
            ..
        } = attr
            && matches!(key.as_str(), "exe" | "path" | "dir")
        {
            paths.push(s.clone());
        }
    }
    paths
}

/// Extract the hash value from object attrs (`filehash=` / `sha256hash=`).
/// Returns the hex string if present, else `None`.
fn extract_hash(attrs: &[Attr]) -> Option<String> {
    for attr in attrs {
        if let Attr::Kv {
            key,
            value: AttrValue::Str(s),
            ..
        } = attr
            && matches!(key.as_str(), "filehash" | "sha256hash")
        {
            return Some(s.clone());
        }
    }
    None
}

/// Determine the `HashAlgorithm` from a hex digest's length.
///
/// 32 hex chars -> MD5, 40 -> SHA1, 64 -> SHA256, 128 -> SHA512, else `None`.
fn hash_algorithm_from_len(hex: &str) -> Option<HashAlgorithm> {
    match hex.len() {
        32 => Some(HashAlgorithm::Md5),
        40 => Some(HashAlgorithm::Sha1),
        64 => Some(HashAlgorithm::Sha256),
        128 => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

/// Compute the scope for a grant by walking both subject and object attrs.
///
/// Scope precedence (narrowest/strongest wins):
///   hash (filehash=/sha256hash=) > path (path=/exe=) > ftype > dir > trust
///   > pattern > all
///
/// The scope is determined by the **narrowest** constraint found across both
/// subject and object, using a two-tier effective-priority system:
///
/// Object-side keys use their natural priority (1–6), with bare `all` at 100.
/// Subject-side keys are weaker (effective priority 50–70), so any specific
/// object constraint beats them. Subject-side exe=/path= contribute at 50
/// (scope=path), trust= at 60 (scope=trust), pattern= at 70 (scope=pattern).
/// Subject-side uid=/gid= and other keys do not contribute to scope.
///
/// Grounded from the corpus goldens:
/// - `exe=/usr/bin/rpm : all`   -> scope=path   (exe in subj beats object-all)
/// - `exe=%tools : ftype=%mimes`-> scope=ftype  (ftype in obj beats exe in subj)
/// - `uid=0 trust=1 : all`      -> scope=trust  (trust in subj beats object-all)
/// - `pattern=ld_so : all`      -> scope=pattern (pattern in subj beats object-all)
/// - `uid=0 gid=0 : all`        -> scope=all    (uid/gid don't contribute)
/// - `exe=/p : filehash=X`      -> scope=hash   (filehash in obj beats exe in subj)
fn compute_scope(subject: &[Attr], object: &[Attr]) -> Scope {
    // Returns (effective_priority, Scope) for a key on the OBJECT side.
    // Lower effective priority = narrower/stronger.
    fn obj_key_scope(key: &str) -> Option<(u8, Scope)> {
        match key {
            "filehash" | "sha256hash" => Some((1, Scope::Hash)),
            "path" | "exe" => Some((2, Scope::Path)),
            "ftype" => Some((3, Scope::Ftype)),
            "dir" => Some((4, Scope::Dir)),
            "trust" => Some((5, Scope::Trust)),
            "pattern" => Some((6, Scope::Pattern)),
            _ => None,
        }
    }

    // Returns (effective_priority, Scope) for a key on the SUBJECT side.
    // Subject keys have higher (weaker) effective priority than ANY specific
    // object key, so any object constraint beats them.
    fn subj_key_scope(key: &str) -> Option<(u8, Scope)> {
        match key {
            "exe" | "path" => Some((50, Scope::Path)),
            "trust" => Some((60, Scope::Trust)),
            "pattern" => Some((70, Scope::Pattern)),
            _ => None,
        }
    }

    let mut best_pri: u8 = 255; // sentinel for "all"
    let mut best_scope = Scope::All;

    for attr in object {
        if let Attr::Kv { key, .. } = attr
            && let Some((p, s)) = obj_key_scope(key).filter(|(p, _)| *p < best_pri)
        {
            best_pri = p;
            best_scope = s;
        }
    }

    for attr in subject {
        if let Attr::Kv { key, .. } = attr
            && let Some((p, s)) = subj_key_scope(key).filter(|(p, _)| *p < best_pri)
        {
            best_pri = p;
            best_scope = s;
        }
    }

    best_scope
}

/// Collect set expansions: for every `AttrValue::SetRef(name)` in `attrs`,
/// insert an entry `"%name"` -> sorted concrete members into `out`.
fn collect_set_expansions(
    attrs: &[Attr],
    sets: &SetTable,
    out: &mut BTreeMap<String, Vec<String>>,
) {
    for attr in attrs {
        if let Attr::Kv {
            value: AttrValue::SetRef(name),
            ..
        } = attr
        {
            let key = format!("%{name}");
            out.entry(key).or_insert_with(|| {
                let mut members = sets.get(name).cloned().unwrap_or_default();
                members.sort();
                members
            });
        }
    }
}

/// Build the exception register from a parsed `Vec<Entry>` in fagenrules
/// load order.
///
/// For each allow-family rule (allow / `allow_audit` / `allow_syslog` / `allow_log`),
/// build a `RegisterRow`. Deny-family rules are excluded.
///
/// `source_file` is the display name of the source file for each entry (just
/// the filename, not the full path). `load_index` is 1-based across the entire
/// rule set (all files in load order), counting only rules (not set-defs /
/// comments / blanks).
///
/// The returned `Vec<RegisterRow>` is in load order (fagenrules file order,
/// then line order within a file).
///
/// `files_with_entries` is a slice of `(filename, entries)` pairs in load order.
#[must_use]
pub fn build_register(files_with_entries: &[(&str, &[Entry])]) -> Vec<RegisterRow> {
    // Build the full set table from ALL entries across all files so set refs
    // defined in earlier files resolve in later files (fagenrules semantics).
    let all_entries: Vec<Entry> = files_with_entries
        .iter()
        .flat_map(|(_, entries)| entries.iter().cloned())
        .collect();
    let sets = SetTable::from_entries(&all_entries);

    let mut rows = Vec::new();
    let mut load_index = 0usize;

    for (filename, entries) in files_with_entries {
        for entry in *entries {
            if let Entry::Rule(rule) = entry {
                if !is_allow_family(rule.decision) {
                    continue;
                }
                // Only allow-family rules advance the load index.
                load_index += 1;
                let row = build_row(rule, filename, load_index, &sets);
                rows.push(row);
            }
        }
    }
    rows
}

/// Build one `RegisterRow` from a single allow-family rule.
fn build_row(rule: &Rule, filename: &str, load_index: usize, sets: &SetTable) -> RegisterRow {
    let perm = rule.perm.unwrap_or(Perm::Open);

    let subject_str = render_side(&rule.subject);
    let object_str = render_side(&rule.object);

    let subject_paths = extract_paths(&rule.subject);
    let object_paths = extract_paths(&rule.object);

    // Hash: from object `filehash=` / `sha256hash=` attrs only.
    let hash = extract_hash(&rule.object);
    let (hash_origin, hash_algorithm) = if let Some(ref h) = hash {
        (HashOrigin::RuleFilehash, hash_algorithm_from_len(h))
    } else {
        (HashOrigin::None, None)
    };

    let scope = compute_scope(&rule.subject, &rule.object);

    // Set expansions: collect from both sides.
    let mut set_expansions = BTreeMap::new();
    collect_set_expansions(&rule.subject, sets, &mut set_expansions);
    collect_set_expansions(&rule.object, sets, &mut set_expansions);

    RegisterRow {
        decision: rule.decision.to_string(),
        perm: perm.to_string(),
        subject: subject_str,
        object: object_str,
        subject_paths,
        object_paths,
        hash,
        hash_origin,
        hash_algorithm,
        scope,
        set_expansions,
        source: RegisterSource {
            file: filename.to_owned(),
            line: rule.line,
        },
        load_index,
    }
}

// ---------------------------------------------------------------------------
// Drift computation
// ---------------------------------------------------------------------------

/// Compute the drift between `current` (the freshly-built register) and
/// `snapshot` (a previously-written register, deserialized from JSON).
///
/// Diff is keyed on `canonical_grant_key`, reconstructed from the row's stored
/// `decision`, `perm`, `subject`, and `object` strings via a fast string key
/// (not the AST key - the snapshot rows were already canonicalised at write
/// time; their stored `decision`/`perm`/`subject`/`object` are the lossless
/// render). For snapshot rows, the key is the stored `decision|perm|subject|object`
/// string combination (the row was built from that AST); for current rows we
/// use the same rendered fields.
///
/// Two rows with the same key but differing `hash` / `hashOrigin` produce a
/// `DriftKind::Changed` row. A row present in `current` but absent in
/// `snapshot` is `Added`. A row in `snapshot` but absent in `current` is
/// `Removed`.
///
/// Ordering of drift rows: added first (by key), then removed, then changed -
/// consistent with the `trustdb_compute::compute_db_diff` pattern.
#[must_use]
pub fn compute_drift(current: &[RegisterRow], snapshot: &[RegisterRow]) -> Vec<DriftRow> {
    // Build key -> row maps. Key is `decision|perm|subject|object` which is
    // exactly the canonical grant key's four components joined - already
    // computed from the AST and stored in the row.
    let current_map: HashMap<String, &RegisterRow> =
        current.iter().map(|r| (row_key(r), r)).collect();
    let snapshot_map: HashMap<String, &RegisterRow> =
        snapshot.iter().map(|r| (row_key(r), r)).collect();

    // Collect all distinct keys in sorted order for deterministic output.
    let mut all_keys: Vec<String> = current_map
        .keys()
        .chain(snapshot_map.keys())
        .cloned()
        .collect();
    all_keys.sort();
    all_keys.dedup();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for key in &all_keys {
        match (current_map.get(key), snapshot_map.get(key)) {
            (Some(&cur), None) => {
                // Present in current, absent in snapshot: added.
                added.push(DriftRow {
                    kind: DriftKind::Added,
                    grant: cur.clone(),
                    from: None,
                    to: Some(cur.clone()),
                });
            }
            (None, Some(&snap)) => {
                // Absent in current, present in snapshot: removed.
                removed.push(DriftRow {
                    kind: DriftKind::Removed,
                    grant: snap.clone(),
                    from: Some(snap.clone()),
                    to: None,
                });
            }
            (Some(&cur), Some(&snap)) => {
                // Same key: check for changes (hash / hashOrigin differ).
                if rows_differ(cur, snap) {
                    changed.push(DriftRow {
                        kind: DriftKind::Changed,
                        grant: cur.clone(),
                        from: Some(snap.clone()),
                        to: Some(cur.clone()),
                    });
                }
                // No difference: no drift row.
            }
            (None, None) => unreachable!("key must appear in at least one map"),
        }
    }

    // Emit added + removed + changed (consistent ordering).
    let mut drift = added;
    drift.extend(removed);
    drift.extend(changed);
    drift
}

/// The drift comparison key for a row: `decision|perm|subject|scope`.
///
/// Drift comparison keys two grants as the "same grant" when they have the same
/// decision, perm, subject predicate, and scope - regardless of the specific
/// hash / path / ftype value in the object predicate. This means:
/// - A hash re-pin (same exe grant, filehash changed) produces a "changed" row,
///   not an add+remove pair.
/// - A trust-DB digest change (hashOrigin enriched / digest changed) produces
///   "changed" instead of add+remove.
/// - Different scope (e.g. hash vs all for the same subject) produces add+remove
///   (they are semantically distinct grants).
///
/// Note: `scope` is serialized as its lowercase string (the serde form).
fn row_key(row: &RegisterRow) -> String {
    let scope_str = match row.scope {
        Scope::All => "all",
        Scope::Path => "path",
        Scope::Dir => "dir",
        Scope::Ftype => "ftype",
        Scope::Pattern => "pattern",
        Scope::Hash => "hash",
        Scope::Trust => "trust",
    };
    format!(
        "{}|{}|{}|{}",
        row.decision, row.perm, row.subject, scope_str
    )
}

/// True iff two rows with the same canonical key have a meaningful difference.
///
/// "Changed" means: `hash` or `hash_origin` differ (the hash was re-pinned or
/// a trust-DB join enriched / dropped the hash). Source location and `load_index`
/// do NOT trigger a changed row (they are positional metadata, not semantic).
fn rows_differ(cur: &RegisterRow, snap: &RegisterRow) -> bool {
    cur.hash != snap.hash || cur.hash_origin != snap.hash_origin
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
