//! fapolicyd access-facts model for rule evaluation.
//!
//! `AccessFacts` represents what is statically knowable about one access attempt.
//! Every field is `Option<...>` or a `Vec<...>` where the daemon would derive the
//! value at runtime; `None` / empty means "fact absent" and widens the match
//! (rules.c:1374-1377: a rule field whose corresponding runtime value is NULL is
//! SKIPPED, not failed).
//!
//! `SetTable` is the compiled `%set` name->members map built from `Entry::SetDefinition`
//! entries in the loaded ruleset, used by `evaluate` to resolve `AttrValue::SetRef`.
//!
//! Filled by Phase-0 Task P0.4 (issue #67).

use std::collections::HashMap;

use crate::ast::{Entry, Perm};

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// Trust status for a subject (process) or object (file).
///
/// `Unknown` is the safe default when a trust-DB lookup is not available
/// (e.g., no `--trustdb` flag supplied to `simulate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The path is present in the fapolicyd trust DB.
    Yes,
    /// The path is absent from the fapolicyd trust DB.
    No,
    /// The trust DB was not consulted; status is indeterminate.
    Unknown,
}

// ---------------------------------------------------------------------------
// FieldEval
// ---------------------------------------------------------------------------

/// Result of evaluating a single rule attribute field against the access facts.
///
/// `NotEvaluable` corresponds to f1 §2.3: `pattern=` and unknown/absent `ftype=`
/// fields cannot be statically evaluated. A rule containing a `NotEvaluable`
/// field produces `RuleOutcome::PossibleMatch`, not `Decisive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldEval {
    /// The fact satisfies the rule's constraint.
    Match,
    /// The fact is present but does not satisfy the constraint.
    NoMatch,
    /// The constraint cannot be statically evaluated (e.g. `pattern=`, unknown ftype).
    NotEvaluable,
}

// ---------------------------------------------------------------------------
// RuleOutcome
// ---------------------------------------------------------------------------

/// The outcome of evaluating one complete rule against the access facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    /// All fields were evaluable and matched; the rule's decision is final.
    Decisive(crate::ast::Decision),
    /// All evaluated fields matched, but at least one field was `NotEvaluable`;
    /// the rule might match at runtime (f1 §2.3).
    PossibleMatch,
    /// At least one field returned `NoMatch`; this rule does not apply.
    NoMatch,
}

// ---------------------------------------------------------------------------
// SetTable
// ---------------------------------------------------------------------------

/// Compiled `%set` name->members map.
///
/// Built from the `Entry::SetDefinition` items in the loaded ruleset via
/// `SetTable::from_entries`. Used by `evaluate` to resolve `AttrValue::SetRef`.
#[derive(Debug, Default, Clone)]
pub struct SetTable {
    inner: HashMap<String, Vec<String>>,
}

impl SetTable {
    /// Build a `SetTable` from a slice of parsed ruleset entries.
    ///
    /// Only `Entry::SetDefinition` entries contribute; all others are ignored.
    /// When the same name appears more than once the last definition wins
    /// (consistent with fapolicyd's load-order behavior).
    #[must_use]
    pub fn from_entries(entries: &[Entry]) -> Self {
        let mut inner = HashMap::new();
        for entry in entries {
            if let Entry::SetDefinition { name, values, .. } = entry {
                inner.insert(name.clone(), values.clone());
            }
        }
        SetTable { inner }
    }

    /// Look up the member list for `name`, or `None` if the set is not defined.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Vec<String>> {
        self.inner.get(name)
    }
}

// ---------------------------------------------------------------------------
// AccessFacts
// ---------------------------------------------------------------------------

/// Facts about one access attempt that `evaluate` uses to walk the ruleset.
///
/// `None` on any optional field means "fact absent": the daemon skips a rule
/// field constraining that fact (rules.c:1374-1377), so `None` widens the
/// match rather than narrowing it. The caller must supply all facts it has;
/// missing facts are an honest representation of what is unknown, not an
/// optimization.
///
/// Fields mirror f1 §5.1 exactly. The comment on each field cites the
/// rules.c line(s) that implement the match for it.
#[derive(Debug, Clone)]
pub struct AccessFacts {
    /// Permission requested: `Open` or `Execute`. Always known; `Any` means
    /// the caller does not know (widens to match both).
    /// (rules.c:1340-1353, `check_access`)
    pub perm: Perm,

    /// Subject executable path.
    /// EXACT string membership match (rules.c:1443-1463).
    pub exe: Option<String>,

    /// Subject `comm` (process name, up to 15 bytes).
    /// EXACT string membership match (rules.c:1466-1475).
    pub comm: Option<String>,

    /// Object path.
    /// EXACT string membership match (rules.c:1595-1602).
    pub path: Option<String>,

    /// Object device path (e.g. `/dev/sda`).
    /// EXACT string membership match (rules.c:1603-1617).
    pub device: Option<String>,

    /// Subject UIDs: the process's full credential set (real/eff/saved/fs).
    /// ANY overlap with the rule's uid set matches (rules.c:1391-1402,
    /// `avl_intersection`). An empty `Vec` is treated as "absent" (widens).
    pub uids: Vec<u32>,

    /// Subject GIDs: all supplementary groups + primary.
    /// ANY overlap with the rule's gid set matches (rules.c:1413-1417).
    /// An empty `Vec` is treated as "absent" (widens).
    pub gids: Vec<u32>,

    /// Audit UID. Exact membership in the rule's integer set (rules.c:1384-1390).
    pub auid: Option<u32>,

    /// Session ID. Exact membership in the rule's integer set (rules.c:1384-1390).
    pub sessionid: Option<u32>,

    /// Subject PID. Exact membership in the rule's integer set (rules.c:1403-1409).
    pub pid: Option<i32>,

    /// Subject PPID. Exact membership in the rule's integer set (rules.c:1403-1409).
    pub ppid: Option<i32>,

    /// Subject trust status.
    /// Exact boolean match: `Yes` matches `trust=1`, `No` matches `trust=0`
    /// (rules.c:1435-1439).
    pub subj_trust: Trust,

    /// Object trust status.
    /// Exact boolean match: `Yes` matches `trust=1`, `No` matches `trust=0`
    /// (rules.c:1579-1584).
    pub obj_trust: Trust,

    /// Object MIME type as reported by libmagic (e.g. `text/plain`).
    /// EXACT string membership match when present; `None` means "not known
    /// statically" -> the evaluator returns `NotEvaluable` for `ftype=` rules
    /// (rules.c:1587-1591, f1 §2.3).
    pub ftype: Option<String>,

    /// Object SHA-256 hex digest.
    /// EXACT string membership match (rules.c:1603-1617).
    pub sha256: Option<String>,

    /// #127: the object path is PRESENT on disk but its hash could NOT be
    /// computed (e.g. EACCES while opening it for on-demand hashing). When
    /// `true` AND `sha256` is `None`, a `filehash=`/`sha256hash=` constraint
    /// evaluates to `NoMatch` (`FILE_HASH` error-as-denial, rules.c:1606-1611)
    /// rather than widening - DISTINCT from the object-absent case (path does
    /// not exist), where `sha256 == None` keeps the skip/widen behavior.
    ///
    /// Defaults to `false`. `explain` never sets it (it never hashes on demand),
    /// so its behavior is unchanged; only `simulate`'s on-demand hashing path
    /// sets it when `sha256_file` returns an error for a present file.
    pub sha256_unhashable: bool,
}

impl AccessFacts {
    /// Minimal constructor: supply only the fields that matter for a test.
    /// All optional fields default to `None`/empty; `subj_trust` and
    /// `obj_trust` default to `Unknown`.
    #[must_use]
    pub fn new(perm: Perm) -> Self {
        AccessFacts {
            perm,
            exe: None,
            comm: None,
            path: None,
            device: None,
            uids: Vec::new(),
            gids: Vec::new(),
            auid: None,
            sessionid: None,
            pid: None,
            ppid: None,
            subj_trust: Trust::Unknown,
            obj_trust: Trust::Unknown,
            ftype: None,
            sha256: None,
            sha256_unhashable: false,
        }
    }
}
