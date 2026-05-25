//! Normalized intermediate representation for fapolicyd rule files.
//!
//! Modern (`decision[:perm] subj : obj`) and legacy
//! (`decision perm=X subj... obj...`, no colon) productions both produce
//! `Entry::Rule(Rule { ..., syntax: SyntaxFlavor::{Modern|Legacy} })`. Lint
//! passes consume the unified `Vec<Entry>` and never see raw chumsky output.

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

#[derive(Debug, Clone, PartialEq, Eq)]
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
/// F03 (mixed-syntax detection) walks `Vec<Entry>` and emits a fatal
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Rule(Rule),
    SetDefinition {
        name: String,
        values: Vec<String>,
        line: usize,
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
