//! `sshd_config` module - line-oriented parser and (future) STIG-aligned lint passes.
//!
//! This is the Phase-0 foundation for the `sshd_config` backend epic (#149).
//! What ships here: the AST ([`ast`]), a hand-rolled line parser ([`parser`]), the
//! frozen `sshd-` lint-code catalog ([`lints::catalog`]), and the lint dispatcher
//! ([`lints::lint`]) wired to per-family stub passes. The semantic lint LOGIC
//! (sshd-E01..E04, sshd-W01..W06, sshd-F02) lands in later parallel pipelines;
//! each fills only its own `lints/` file body, so the shared surface here is
//! frozen. Only `sshd-F01` (parse failure) is emitted today.
//!
//! Parser idiom mirrors the newer `rulesteward-auditd` crate: a hand-rolled
//! tokenizer (KISS, per CLAUDE.md), not a chumsky grammar - `sshd_config` is a flat
//! list of `Keyword arg [arg ...]` lines plus `Match` blocks, with no macros or
//! list-as-AST nodes that would justify a grammar DSL.

pub mod ast;
pub mod lints;
pub mod parser;

pub use ast::{Block, Directive, MatchBlock, MatchCriterion};
pub use lints::{SshdLintContext, TargetVersion};
pub use parser::{LocatedParseError, parse_config_str_located};
