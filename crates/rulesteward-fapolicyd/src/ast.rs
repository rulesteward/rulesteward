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
