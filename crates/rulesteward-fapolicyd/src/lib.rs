//! fapolicyd rule parser, AST, and lint passes.
//!
//! Public API:
//! * [`parse_rules_file`] - chumsky-driven, per-line, emits all diagnostics.
//! * [`lint`] / [`lint_file`] / [`check_layout`] - post-parse lint walker + file-layout check.
//! * AST types (`Entry`, `Rule`, `Decision`, `Perm`, `Attr`, `AttrValue`,
//!   `SyntaxFlavor`) for downstream consumers.

pub mod ast;
pub mod attrs;
pub mod format;
pub mod lints;
pub mod load_order;
pub mod parser;
pub mod trustdb;

pub use ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};
pub use lints::{check_layout, lint, lint_cross_file, lint_file};
pub use load_order::fagenrules_cmp;
pub use parser::{inline, parse_rules_file};
pub use trustdb::{open_trustdb_readonly, TrustDb, TrustDbError};
