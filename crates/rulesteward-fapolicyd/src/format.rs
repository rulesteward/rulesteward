//! Lossless `Display` impls for the IR - render any `Entry` back to a
//! source line that re-parses to the same `Entry` (modulo `line`, which is
//! position-driven on re-parse). Used by the round-trip proptest property
//! and (eventually) by `simulate` for diff rendering.

use core::fmt;

use crate::ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor};

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::AllowAudit => "allow_audit",
            Decision::DenyAudit => "deny_audit",
            Decision::AllowSyslog => "allow_syslog",
            Decision::DenySyslog => "deny_syslog",
            Decision::AllowLog => "allow_log",
            Decision::DenyLog => "deny_log",
        };
        f.write_str(s)
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Perm::Open => "open",
            Perm::Execute => "execute",
            Perm::Any => "any",
        };
        f.write_str(s)
    }
}

impl fmt::Display for AttrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttrValue::Str(s) => f.write_str(s),
            AttrValue::Int(n) => write!(f, "{n}"),
            AttrValue::SetRef(name) => write!(f, "%{name}"),
        }
    }
}

impl fmt::Display for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Attr::All => f.write_str("all"),
            Attr::Kv { key, value } => write!(f, "{key}={value}"),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.decision)?;
        if let Some(perm) = self.perm {
            write!(f, " perm={perm}")?;
        }
        for a in &self.subject {
            write!(f, " {a}")?;
        }
        match self.syntax {
            SyntaxFlavor::Modern => f.write_str(" :")?,
            SyntaxFlavor::Legacy => {}
        }
        for a in &self.object {
            write!(f, " {a}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::Rule(r) => write!(f, "{r}"),
            Entry::SetDefinition { name, values, .. } => {
                write!(f, "%{name}={}", values.join(","))
            }
            Entry::Comment { text, .. } => write!(f, "#{text}"),
            Entry::Blank { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::span;

    #[test]
    fn modern_rule_renders_with_colon() {
        let r = Rule {
            decision: Decision::Allow,
            perm: Some(Perm::Open),
            subject: vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            object: vec![Attr::All],
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: span(0, 0),
        };
        assert_eq!(r.to_string(), "allow perm=open uid=0 : all");
    }

    #[test]
    fn legacy_rule_renders_without_colon() {
        let r = Rule {
            decision: Decision::Allow,
            perm: None,
            subject: vec![Attr::Kv {
                key: "uid".into(),
                value: AttrValue::Int(0),
            }],
            object: vec![Attr::Kv {
                key: "path".into(),
                value: AttrValue::Str("/x".into()),
            }],
            syntax: SyntaxFlavor::Legacy,
            line: 1,
            span: span(0, 0),
        };
        assert_eq!(r.to_string(), "allow uid=0 path=/x");
    }

    #[test]
    fn setdef_renders_with_comma_separator() {
        let e = Entry::SetDefinition {
            name: "langs".into(),
            values: vec!["ruby".into(), "perl".into()],
            line: 1,
            span: span(0, 0),
        };
        assert_eq!(e.to_string(), "%langs=ruby,perl");
    }

    #[test]
    fn comment_renders_with_leading_hash() {
        let e = Entry::Comment {
            text: " hello".into(),
            line: 1,
        };
        assert_eq!(e.to_string(), "# hello");
    }

    #[test]
    fn blank_renders_empty() {
        let e = Entry::Blank { line: 1 };
        assert_eq!(e.to_string(), "");
    }
}
