//! Abstract syntax for an `sshd_config` file.
//!
//! # Grounding (`sshd_config(5)`, OpenBSD canonical source)
//! - A file is a flat list of `Keyword argument [argument ...]` lines, one
//!   directive per line, whitespace-separated (no `=`).
//! - Keywords are case-insensitive; arguments are case-sensitive.
//! - A `Match <criteria>` line opens a conditional block: every directive after
//!   it (until the next `Match` or EOF) belongs to that block. Blocks have no
//!   explicit delimiter, so scoping is positional (`sshd_config(5)`; E2 gotcha #1).
//!
//! # Invariants produced by [`crate::parser`]
//! - `blocks[0]` is ALWAYS the global block ([`Block::Global`]), possibly empty
//!   (a file that opens with `Match` has an empty global block at the front).
//! - Match blocks follow in source order after the global block.

use rulesteward_core::Span;

/// A single `sshd_config` directive line: `Keyword arg [arg ...]`.
///
/// The keyword is stored exactly as written (so diagnostics can echo the source
/// spelling); use [`Directive::keyword_lower`] for case-insensitive matching,
/// since sshd keywords are case-insensitive. Quoted arguments have their
/// surrounding double quotes removed by the parser; bare arguments are verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Keyword as written in the source (e.g. `"PermitRootLogin"`).
    pub keyword: String,
    /// Arguments in source order; quoted args have surrounding quotes stripped.
    pub args: Vec<String>,
    /// 1-based line number of this directive in its source file.
    pub line: usize,
    /// Byte range of the directive's raw line in the source text.
    pub span: Span,
}

impl Directive {
    /// The ASCII-lowercased keyword, for case-insensitive matching.
    ///
    /// `sshd_config` keywords are case-insensitive, so lints compare against this
    /// canonical form rather than calling `eq_ignore_ascii_case` at every site.
    /// Lowercasing needs no directive table (unlike canonicalizing to the
    /// manpage's title-case spelling, which is the registry-gated sshd-E01 work),
    /// so it is the table-free canonical form available in Phase 0.
    #[must_use]
    pub fn keyword_lower(&self) -> String {
        self.keyword.to_ascii_lowercase()
    }
}

/// One criterion of a `Match` header, e.g. `User alice,bob` or `All`.
///
/// `keyword` is the criterion name as written (`User`, `Group`, `All`, ...);
/// `values` is the comma-separated value list split into parts (empty for the
/// valueless `All` criterion). Negation (`!`) and wildcards (`*`) are kept
/// verbatim inside each value - their semantics are a lint concern, not the
/// parser's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchCriterion {
    /// Criterion keyword as written (e.g. `"User"`, `"All"`).
    pub keyword: String,
    /// Comma-split criterion values; empty for `All`.
    pub values: Vec<String>,
}

/// A `Match` conditional block: its criteria and the directives it scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchBlock {
    /// The criteria on the `Match` header line, in source order.
    pub criteria: Vec<MatchCriterion>,
    /// Directives scoped by this `Match`, until the next `Match` or EOF.
    pub body: Vec<Directive>,
    /// 1-based line number of the `Match` header.
    pub line: usize,
    /// Byte range of the `Match` header's raw line in the source text.
    pub span: Span,
}

/// A top-level region of an `sshd_config` file: the leading global section or one
/// `Match` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// The leading, unconditional directives (before the first `Match`).
    Global(Vec<Directive>),
    /// A `Match` conditional block.
    Match(MatchBlock),
}
