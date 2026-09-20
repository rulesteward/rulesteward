//! The rules file, parsed far enough to answer "what is rule N, and can anything we
//! emit resolve a denial by it?". Pure: the caller does the `fs::read`.
//!
//! Rule text is `String` and not `Vec<u8>`, against §4's byte rule, deliberately: the
//! text is never emitted, only quoted into a `Diagnostic.msg`, which is already a
//! `String`. Lines are converted with `String::from_utf8_lossy`, so a non-UTF-8 rule
//! shows replacement characters in a diagnostic and nothing else changes. Do not
//! "fix" this to bytes; there is nothing downstream that would use them.

/// One rule of the compiled set. Its position in the slice is the daemon's own
/// numbering: the `rule=` a record carries is 1-based, so rule `n` is index `n - 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The line as written, trimmed. Only ever quoted in a diagnostic.
    pub text: String,
    /// The first token: `allow`, `deny`, `deny_audit`, `deny_syslog`, `deny_log`.
    pub decision: String,
    /// The tokens after the decision and before the bare `:`.
    pub subject: Vec<String>,
    /// `None` when the line is ORIGINAL format, which has no object side at all and
    /// therefore can never satisfy the "object side is exactly `all`" test.
    pub object: Option<Vec<String>>,
}

/// One token of a rule, as far as `check` can evaluate it (DESIGN.md §7, #120's D4 set).
///
/// Everything outside that set is kept as `Unevaluable` rather than dropped: a rule the
/// evaluator cannot decide has to stop the walk, and a dropped token would silently make
/// the rule look broader than it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    All,
    Perm(String),
    Exe(String),
    Path(String),
    Dir(String),
    Ftype(String),
    Trust(String),
    /// A token with no `=` that is not `all`: the tail of a value containing a space,
    /// which is #120's K2. The daemon logs `'=' is missing for field ace/probe-grep`,
    /// keeps loading, counts the broken rule in `Loaded N rules` so it occupies its slot,
    /// and never matches anything with it.
    NeverMatches,
    /// `pattern=`, `uid=`, `sha256hash=`, a `%set` reference, a `dir=` keyword: real
    /// attributes whose value cannot be decided from a log record.
    Unevaluable,
}

impl Attr {
    /// One token of a rule's subject or object side. Which side it was written on is the
    /// caller's business: `perm=` on the object side is a real attribute in the wrong
    /// place, and only the matcher knows which side it is reading.
    fn new(token: &str) -> Attr {
        let Some((name, value)) = token.split_once('=') else {
            return if token == "all" {
                Attr::All
            } else {
                Attr::NeverMatches
            };
        };
        // A `%set` reference names a list this tool never expands: `ftype=%languages`
        // holds 24 media types, and comparing the record's `ftype=` against the literal
        // `%languages` would call every one of them a mismatch.
        if value.starts_with('%') {
            return Attr::Unevaluable;
        }
        let v = value.to_string();
        match name {
            "perm" => Attr::Perm(v),
            "exe" => Attr::Exe(v),
            "path" => Attr::Path(v),
            // `dir=` also takes the keywords `execdirs`, `systemdirs` and `untrusted`,
            // each naming a set of directories this tool cannot enumerate from a record.
            "dir" if value.starts_with('/') => Attr::Dir(v),
            "ftype" => Attr::Ftype(v),
            "trust" => Attr::Trust(v),
            _ => Attr::Unevaluable,
        }
    }
}

/// Every line that is not blank, `#` or `%set` is a rule; that is the whole grammar
/// (`nv_split` recognises three line shapes) and the whole of `fapolicyd-cli --list`.
///
/// A skipped line consumes no rule number. fagenrules keeps a whitespace-only line in
/// `compiled.rules` -- its `length($0) < 1` tests emptiness, not blankness -- while the
/// daemon and `--list` skip it, so the counter must skip it too.
pub fn parse(file: &[u8]) -> Vec<Rule> {
    let mut rules = Vec::new();
    for line in file.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }
        rules.push(Rule::new(line));
    }
    rules
}

/// The `%set` definitions of a file, in the order written. `parse` drops them because no
/// rule number counts them, which makes an edited set invisible to every comparison of
/// rule text -- and the rules naming it mean something different afterwards. What a set
/// *holds* is never expanded here (#139), so these are compared as bytes and nothing more.
///
/// Bytes and not `String`, against the rest of this module: a set holds paths, and §4's
/// byte rule applies to those. Through `from_utf8_lossy` two definitions differing only
/// outside UTF-8 collapse into one U+FFFD and would report agreement that is not there,
/// which is the one direction the caller must never be told (#158). The trim is
/// `parse`'s, so a CRLF file or a trailing space is not an edit.
pub fn sets(file: &[u8]) -> Vec<Vec<u8>> {
    file.split(|&b| b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| line.starts_with(b"%"))
        .map(<[u8]>::to_vec)
        .collect()
}

impl Rule {
    /// No unescaping anywhere: the rule language has no escape mechanism and no
    /// quoting, so `%set` references and `pattern=` values are stored literally.
    pub(crate) fn new(line: &str) -> Rule {
        let line = line.trim();
        let mut tokens = line.split_whitespace().map(str::to_string);
        let decision = tokens.next().unwrap_or_default();
        let rest: Vec<String> = tokens.collect();
        let (subject, object) = match rest.iter().position(|t| t == ":") {
            Some(i) => (rest[..i].to_vec(), Some(rest[i + 1..].to_vec())),
            None => (rest, None),
        };
        Rule {
            text: line.to_string(),
            decision,
            subject,
            object,
        }
    }

    /// The two sides decomposed, for `check`'s matcher. The fields stay as they are: the
    /// tokens are what `--list` shows and what a diagnostic quotes, and this is a view of
    /// them, not a second parse.
    ///
    /// ORIGINAL format -- no object side at all -- comes back as one `Unevaluable`. The
    /// grammar is a different one, no capture has a rule in it, and a rule that places no
    /// object constraint would otherwise read as matching every file.
    pub fn attrs(&self) -> (Vec<Attr>, Vec<Attr>) {
        fn side(tokens: &[String]) -> Vec<Attr> {
            tokens.iter().map(|t| Attr::new(t)).collect()
        }
        (
            side(&self.subject),
            self.object
                .as_deref()
                .map_or_else(|| vec![Attr::Unevaluable], side),
        )
    }

    /// A rule that constrains only the process refuses: nothing scoped to a path, and
    /// no trust entry, can change the outcome.
    ///
    /// `decision.starts_with("deny")` is not redundant with the record being a denial:
    /// a denial record's `rule=N` is a deny rule by construction, so a lookup landing
    /// on an `allow` says the rules file is not this log's. An object side of exactly
    /// `all` is "the rule places no constraint on the file", and the subject clause is
    /// "names anything beyond `perm=` and `all`" -- which is what keeps the
    /// denyall-shaped `deny_audit perm=execute all : all` out.
    pub fn refuses(&self) -> bool {
        self.decision.starts_with("deny")
            && self.object.as_deref().is_some_and(|o| o == ["all"])
            && self
                .subject
                .iter()
                .any(|t| t != "all" && !t.starts_with("perm="))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's own `Loading rule file:` listing on a default Rocky 9 install,
    /// verbatim, from `rocky9-base-cli-trust-daemon.log`. It reports `Loaded 14 rules`.
    const ROCKY9: &[u8] = b"\
## This file is automatically generated from /etc/fapolicyd/rules.d
%languages=application/x-bytecode.ocaml,application/x-bytecode.python,application/java-archive,text/x-java,application/x-java-applet,application/javascript,text/javascript,text/x-awk,text/x-gawk,text/x-lisp,application/x-elc,text/x-lua,text/x-m4,text/x-nftables,text/x-perl,text/x-php,text/x-script.python,text/x-python,text/x-R,text/x-ruby,text/x-script.guile,text/x-tcl,text/x-luatex,text/x-systemtap
allow perm=any uid=0 : dir=/var/tmp/
allow perm=any uid=0 trust=1 : all
allow perm=open exe=/usr/bin/rpm : all
allow perm=open exe=/usr/bin/python3.9 comm=dnf : all
deny_audit perm=any pattern=ld_so : all
deny_audit perm=any all : ftype=application/x-bad-elf
allow perm=open all : ftype=application/x-sharedlib trust=1
deny_audit perm=open all : ftype=application/x-sharedlib
allow perm=execute all : trust=1
allow perm=open all : ftype=%languages trust=1
deny_audit perm=any all : ftype=%languages
allow perm=any all : ftype=text/x-shellscript
deny_audit perm=execute all : all
allow perm=open all : all
";

    #[test]
    fn the_rocky9_ruleset_numbers_fourteen_rules() {
        let r = parse(ROCKY9);
        assert_eq!(r.len(), 14, "the daemon logged `Loaded 14 rules`");
        assert_eq!(
            r[0].text, "allow perm=any uid=0 : dir=/var/tmp/",
            "the comment and the %set consume no position"
        );
    }

    #[test]
    fn the_ld_so_deny_is_rule_five_not_six() {
        let r = parse(ROCKY9);
        assert_eq!(r[4].text, "deny_audit perm=any pattern=ld_so : all");
        assert_eq!(
            r[7].text,
            "deny_audit perm=open all : ftype=application/x-sharedlib"
        );
        assert_eq!(r[12].text, "deny_audit perm=execute all : all");
    }

    #[test]
    fn only_the_subject_side_rule_refuses() {
        for (i, r) in parse(ROCKY9).iter().enumerate() {
            assert_eq!(r.refuses(), i == 4, "rule {}: {}", i + 1, r.text);
        }
    }

    #[test]
    fn an_original_format_rule_never_refuses() {
        let r = Rule::new("deny_audit perm=any pattern=ld_so");
        assert_eq!(r.object, None);
        assert!(
            !r.refuses(),
            "original format has no object side to be `all`"
        );
    }

    #[test]
    fn an_allow_rule_never_refuses() {
        assert!(!Rule::new("allow perm=open exe=/usr/bin/rpm : all").refuses());
    }

    #[test]
    fn an_exe_only_deny_refuses() {
        assert!(Rule::new("deny perm=execute exe=/usr/bin/foo : all").refuses());
    }

    #[test]
    fn every_d4_attribute_keeps_its_value_and_its_side() {
        let (subject, object) = Rule::new(
            "allow perm=open exe=/usr/bin/cat dir=/usr/bin : path=/tmp/x dir=/tmp/ \
             ftype=text/plain trust=1",
        )
        .attrs();
        assert_eq!(
            subject,
            [
                Attr::Perm("open".into()),
                Attr::Exe("/usr/bin/cat".into()),
                Attr::Dir("/usr/bin".into()),
            ]
        );
        assert_eq!(
            object,
            [
                Attr::Path("/tmp/x".into()),
                Attr::Dir("/tmp/".into()),
                Attr::Ftype("text/plain".into()),
                Attr::Trust("1".into()),
            ]
        );
    }

    #[test]
    fn all_is_an_attribute_and_any_other_bare_token_never_matches() {
        // K2: `path=/tmp/sp ace/x` splits into a `path=` and a bare `ace/x`, which is
        // the token the daemon reports `'=' is missing for field` about.
        let (subject, object) = Rule::new("allow perm=any all : path=/tmp/sp ace/x").attrs();
        assert_eq!(subject, [Attr::Perm("any".into()), Attr::All]);
        assert_eq!(
            object,
            [Attr::Path("/tmp/sp".into()), Attr::NeverMatches],
            "the broken token is kept, because the rule still occupies its slot"
        );
    }

    #[test]
    fn what_a_log_record_cannot_decide_is_unevaluable_and_not_dropped() {
        let (subject, object) =
            Rule::new("deny_audit perm=any pattern=ld_so uid=0 : ftype=%languages dir=execdirs")
                .attrs();
        assert_eq!(
            subject,
            [
                Attr::Perm("any".into()),
                Attr::Unevaluable,
                Attr::Unevaluable
            ]
        );
        assert_eq!(object, [Attr::Unevaluable, Attr::Unevaluable]);
    }

    #[test]
    fn two_set_definitions_differing_only_outside_utf8_are_not_equal() {
        // A set holds paths, and a path is bytes (§4). Through `from_utf8_lossy` both of
        // these become the same U+FFFD, which would report agreement between two
        // definitions the daemon reads as different and hand the D3 skip a proof it does
        // not have (#158).
        assert_ne!(sets(b"%s=/opt/\xff"), sets(b"%s=/opt/\xfe"));
        // The trim is what keeps a CRLF file or a trailing space from reading as an edit.
        assert_eq!(sets(b"%s=/opt/a\r\n"), sets(b"%s=/opt/a  \n"));
    }

    #[test]
    fn an_original_format_rule_has_no_object_side_to_evaluate() {
        let (subject, object) = Rule::new("deny_audit perm=any pattern=ld_so").attrs();
        assert_eq!(subject, [Attr::Perm("any".into()), Attr::Unevaluable]);
        assert_eq!(
            object,
            [Attr::Unevaluable],
            "no object side is not the same as `all`"
        );
    }
}
