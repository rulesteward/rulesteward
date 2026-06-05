//! fapolicyd rule parser, AST, and lint passes.
//!
//! Public API:
//! * [`parse_rules_file`] - chumsky-driven, per-line, emits all diagnostics.
//! * [`lint`] / [`lint_file`] / [`check_layout`] - post-parse lint walker + file-layout check.
//! * AST types (`Entry`, `Rule`, `Decision`, `Perm`, `Attr`, `AttrValue`,
//!   `SyntaxFlavor`) for downstream consumers.

pub mod ast;
pub mod attrs;
pub mod evaluate;
pub mod explain;
pub mod facts;
pub mod fanotify;
pub mod format;
pub mod lints;
pub mod load_order;
pub mod parser;
pub mod register;
pub mod trustdb;
pub mod version;

pub use ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
pub use evaluate::{Source, Verdict, evaluate};
pub use explain::{
    ExplainError, ExplainResult, MatchedBy, explain_event, is_deny_decision, render_human,
    rule_text,
};
pub use facts::{AccessFacts, FieldEval, RuleOutcome, SetTable, Trust};
pub use fanotify::{
    AuditEvent, FanotifyRecord, ParseError, TrustVal, parse_audit_event, parse_fanotify_record,
};
pub use lints::cross_db::lint_orphans;
pub use lints::trust_hash::lint_weak_digests;
pub use lints::{
    LintContext, check_layout, collect_macro_names, lint, lint_cross_file, lint_file,
    lint_file_with_context, lint_with_context,
};
pub use load_order::fagenrules_cmp;
pub use parser::{inline, parse_rules_file};
pub use register::{
    DriftKind, DriftRow, EXCEPTION_REGISTER_DRIFT_KIND, EXCEPTION_REGISTER_KIND, HashAlgorithm,
    HashOrigin, REGISTER_SCHEMA_VERSION, RegisterRow, RegisterSource, Scope, canonical_grant_key,
    hash_algorithm_from_len,
};
pub use trustdb::{
    DiskVerdict, TrustDb, TrustDbError, TrustEntry, TrustSource, open_trustdb_readonly,
    verify_entry, weak_digest_algorithm,
};
pub use version::TargetVersion;

#[cfg(feature = "fuzz-targets")]
pub use trustdb::fuzz_hooks;
