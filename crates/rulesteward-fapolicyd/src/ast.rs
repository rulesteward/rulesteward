//! Normalized intermediate representation for fapolicyd rule files.
//!
//! Modern (`decision[:perm] subj : obj`) and legacy
//! (`decision perm=X subj... obj...`, no colon) productions both produce
//! `Entry::Rule(Rule { ..., syntax: SyntaxFlavor::{Modern|Legacy} })`. Lint
//! passes consume the unified `Vec<Entry>` and never see raw chumsky output.

use rulesteward_core::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    Allow,
    Deny,
    AllowAudit,
    DenyAudit,
    AllowSyslog,
    DenySyslog,
    AllowLog,
    DenyLog,
}

impl Decision {
    /// Whether this decision halts further rule evaluation when matched.
    ///
    /// Invariant: All current fapolicyd decisions are terminal per
    /// `rules.c:eval_action` (the loop breaks out of `process_rules` as soon as
    /// any rule matches; the only "non-terminal" path is no match at all).
    /// This method is a single update point if a non-terminal decision is ever
    /// added to the spec; today it returns `true` unconditionally.
    ///
    /// Used by `lints::reachability` (fapd-W01): A rule can only shadow a
    /// later rule if A's decision is terminal (i.e. evaluation stops at A).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Decision::Allow
            | Decision::Deny
            | Decision::AllowAudit
            | Decision::DenyAudit
            | Decision::AllowSyslog
            | Decision::DenySyslog
            | Decision::AllowLog
            | Decision::DenyLog => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Perm {
    Open,
    Execute,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    SetRef(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    All,
    Kv { key: String, value: AttrValue },
}

/// Which front-end production produced a given `Rule`.
///
/// fapd-F03 (mixed-syntax detection) walks `Vec<Entry>` and emits a fatal
/// diagnostic when both flavors appear in one file. Future grammar variants
/// add another variant here without disturbing `Rule` or the lint walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntaxFlavor {
    Modern,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub decision: Decision,
    pub perm: Option<Perm>,
    pub subject: Vec<Attr>,
    pub object: Vec<Attr>,
    pub syntax: SyntaxFlavor,
    pub line: usize,
    /// Byte range into the file source this rule was parsed from.
    /// File-relative (not line-relative). Populated by the parser via
    /// chumsky's span capture; layout-level constructions (tests) may
    /// use [`rulesteward_core::span`] to set a placeholder.
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Rule(Rule),
    SetDefinition {
        name: String,
        values: Vec<String>,
        line: usize,
        /// Byte range into the file source this set definition was parsed
        /// from. File-relative (not line-relative). Populated by the parser
        /// via chumsky's span capture; layout-level constructions (tests,
        /// generators) may use [`rulesteward_core::span`] to set a
        /// placeholder.
        span: Span,
    },
    Comment {
        text: String,
        line: usize,
    },
    Blank {
        line: usize,
    },
}

impl Entry {
    #[must_use]
    pub fn line(&self) -> usize {
        match self {
            Entry::Rule(r) => r.line,
            Entry::SetDefinition { line, .. }
            | Entry::Comment { line, .. }
            | Entry::Blank { line } => *line,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_is_terminal_for_every_variant() {
        // All current fapolicyd decisions halt evaluation when matched.
        // Pins the invariant; a mutant that flips this to `false` for any
        // variant breaks fapd-W01 (rule shadowing) which depends on it.
        assert!(Decision::Allow.is_terminal());
        assert!(Decision::Deny.is_terminal());
        assert!(Decision::AllowAudit.is_terminal());
        assert!(Decision::DenyAudit.is_terminal());
        assert!(Decision::AllowSyslog.is_terminal());
        assert!(Decision::DenySyslog.is_terminal());
        assert!(Decision::AllowLog.is_terminal());
        assert!(Decision::DenyLog.is_terminal());
    }
}
