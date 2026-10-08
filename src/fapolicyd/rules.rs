//! The rules file, parsed far enough to answer "what is rule N, and can anything we
//! emit resolve a denial by it?". Pure: the caller does the `fs::read`.
//!
//! Rule text and every token are bytes, §4's byte rule: a rule's text is compared --
//! against the host's own rules in `check`, `rules_d` and `main` -- and its paths against
//! a record's raw bytes, and it reaches the `why` and `check` documents. Through
//! `from_utf8_lossy` two rules differing only outside UTF-8 would compare equal and a
//! path the daemon matches would not (#162, #174). It is decoded lossily only where it is
//! shown. Two document fields carry a `*_hex` sibling for it: `why`'s `text`, and `check`'s
//! `detail` when that quotes a rule (DESIGN.md §9.1). A reason string that quotes one --
//! `check::refused`'s, or the subject-side diagnostic -- is lossy text with no sibling.
//!
//! A rule's tokens are separated by ASCII whitespace. The daemon's `next_rule_token`
//! (upstream `src/library/rules.c`) breaks a token on the space byte only, so a vertical
//! tab, U+00A0 or U+3000 inside a value stays in the token here as it does there. A tab,
//! a form feed or a carriage return separates here and not in the daemon: that difference
//! predates byte tokens and is kept
//! because vendored fixtures carry tabs.

/// One rule of the compiled set. Its position in the slice is the daemon's own
/// numbering: the `rule=` a record carries is 1-based, so rule `n` is index `n - 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The line as written, trimmed.
    pub text: Vec<u8>,
    /// The first token: `allow`, `deny`, `deny_audit`, `deny_syslog`, `deny_log`.
    pub decision: Vec<u8>,
    /// The tokens after the decision and before the bare `:`.
    pub subject: Vec<Vec<u8>>,
    /// `None` when the line is ORIGINAL format, which has no object side at all and
    /// therefore can never satisfy the "object side is exactly `all`" test.
    pub object: Option<Vec<Vec<u8>>>,
}

/// One token of a rule, as far as `check` can evaluate it (DESIGN.md §7, #120's D4 set).
///
/// Everything outside that set is kept as `Unevaluable` rather than dropped: a rule the
/// evaluator cannot decide has to stop the walk, and a dropped token would silently make
/// the rule look broader than it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    All,
    Perm(Vec<u8>),
    Exe(Vec<u8>),
    Path(Vec<u8>),
    Dir(Vec<u8>),
    Ftype(Vec<u8>),
    Trust(Vec<u8>),
    /// A token with no `=` that is not `all`: the tail of a value containing a space,
    /// which is #120's K2. The daemon logs `'=' is missing for field ace/probe-grep`,
    /// keeps loading, counts the broken rule in `Loaded N rules` so it occupies its slot,
    /// and never matches anything with it.
    NeverMatches,
    /// A value's members, with the attribute's own name beside them: a `%set` reference
    /// for the matcher to resolve against the definitions it holds, or a `dir=` value
    /// listing a keyword beside a literal (#139). Each member is compared the way this
    /// attribute compares one literal, which is the matcher's business and not a token's,
    /// so nothing is expanded here.
    Members(Vec<u8>, Vec<Vec<u8>>),
    /// `pattern=`, `uid=`, `sha256hash=`, a `dir=` keyword on its own, a `%set` written
    /// beside something else: real attributes whose value cannot be decided from a log
    /// record.
    Unevaluable,
}

impl Attr {
    /// One token of a rule's subject or object side. Which side it was written on is the
    /// caller's business: `perm=` on the object side is a real attribute in the wrong
    /// place, and only the matcher knows which side it is reading.
    pub(crate) fn new(token: &[u8]) -> Attr {
        let Some(at) = token.iter().position(|&b| b == b'=') else {
            return if token == b"all" {
                Attr::All
            } else {
                Attr::NeverMatches
            };
        };
        // Two shapes hold several members: a `%set` reference, which names a list -- 24
        // media types for `%languages` -- and a `dir=` value, where S1 (#137) measured a
        // literal matching beside a keyword on 8, 9 and 10. A `%set` written beside
        // anything else is a shape nothing measured, and the arms below would compare the
        // whole value as one literal and call every member of it a mismatch, so it stays
        // undecidable.
        let (name, value) = (&token[..at], &token[at + 1..]);
        let (set, list) = (value.starts_with(b"%"), value.contains(&b','));
        if (set && !list) || (name == b"dir" && list) {
            return Attr::Members(
                name.to_vec(),
                value.split(|&b| b == b',').map(<[u8]>::to_vec).collect(),
            );
        }
        if set {
            return Attr::Unevaluable;
        }
        let v = value.to_vec();
        match name {
            b"perm" => Attr::Perm(v),
            b"exe" => Attr::Exe(v),
            b"path" => Attr::Path(v),
            // `dir=` also takes the keywords `execdirs`, `systemdirs` and `untrusted`,
            // each naming a set of directories this tool cannot enumerate from a record.
            b"dir" if value.starts_with(b"/") => Attr::Dir(v),
            b"ftype" => Attr::Ftype(v),
            b"trust" => Attr::Trust(v),
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
///
/// Which lines are rules is decided by the lossy `str::trim` view, the same test `sets`
/// makes, so the two cannot disagree about a line; what is kept is the line's own bytes.
pub fn parse(file: &[u8]) -> Vec<Rule> {
    let mut rules = Vec::new();
    for line in file.split(|&b| b == b'\n') {
        let trimmed = String::from_utf8_lossy(line);
        let trimmed = trimmed.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        rules.push(Rule::new(line));
    }
    rules
}

/// One `%set` definition. `parse` drops the line because no rule number counts it, which
/// makes an edited set invisible to every comparison of rule text -- and the rules naming
/// it mean something different afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set {
    /// The name as a rule names it, the `%` included: `%languages`.
    pub name: String,
    /// The members, split on `,`. Empty for a line with no `=` at all, which defines
    /// nothing: the caller has to answer for such a reference rather than read it as a
    /// set that matches nothing.
    pub members: Vec<Vec<u8>>,
    /// The whole line as written, trimmed: what one definition is compared against
    /// another by.
    pub text: Vec<u8>,
    /// How many rules of its own file precede it, which is what places the definition in
    /// the merged order against a rule -- S1 (#137) measured that a set used before its
    /// definition fails the reload.
    pub rules_before: usize,
}

/// The `%set` definitions of a file, in the order written, each with the number of its
/// file's rules that precede it.
///
/// Bytes, like a rule: a set holds paths, and §4's byte rule applies to those. Through
/// `from_utf8_lossy` two definitions differing only outside UTF-8 collapse into one U+FFFD
/// and would report agreement that is not there, which is the one direction the caller
/// must never be told (#158).
///
/// The members end at the first space byte. The daemon's `parse_set_line` receives only
/// the line's first space-delimited token, because `strtok` has already cut the line there
/// (research reference, rocky8/9/10, "Attribute sets"), so `%s=/a,/b c` loads `{/a, /b}`
/// and `/b c` is in no set. `text` stays the whole line, because it is what an edit to the
/// definition is detected by.
///
/// Which lines are sets is decided by `parse`'s own test and not by a second one: its
/// `str::trim` takes a vertical tab and U+00A0 that `trim_ascii` leaves, and a line
/// `parse` drops as a set while this skips it would be in neither list, so an edit to it
/// would compare as no edit. The rule count is kept by the same walk for the same reason:
/// two loops over one file's lines could disagree about which of them is a rule. The ASCII
/// trim is only on what is kept, so a CRLF file or a trailing space is not an edit.
pub fn sets(file: &[u8]) -> Vec<Set> {
    let mut sets = Vec::new();
    let mut rules_before = 0usize;
    for line in file.split(|&b| b == b'\n') {
        let trimmed = String::from_utf8_lossy(line);
        let trimmed = trimmed.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with('%') {
            rules_before += 1;
            continue;
        }
        let line = line.trim_ascii();
        let (name, members) = match line.iter().position(|&b| b == b'=') {
            Some(at) => (
                &line[..at],
                line[at + 1..]
                    .split(|&b| b == b' ')
                    .next()
                    .unwrap_or_default()
                    .split(|&b| b == b',')
                    .map(<[u8]>::to_vec)
                    .collect(),
            ),
            None => (line, Vec::new()),
        };
        sets.push(Set {
            name: String::from_utf8_lossy(name).into_owned(),
            members,
            text: line.to_vec(),
            rules_before,
        });
    }
    sets
}

impl Rule {
    /// No unescaping anywhere: the rule language has no escape mechanism and no
    /// quoting, so `%set` references and `pattern=` values are stored literally.
    pub(crate) fn new(line: &[u8]) -> Rule {
        let line = line.trim_ascii();
        let mut tokens = line
            .split(u8::is_ascii_whitespace)
            .filter(|t| !t.is_empty())
            .map(<[u8]>::to_vec);
        let decision = tokens.next().unwrap_or_default();
        let rest: Vec<Vec<u8>> = tokens.collect();
        let (subject, object) = match rest.iter().position(|t| t == b":") {
            Some(i) => (rest[..i].to_vec(), Some(rest[i + 1..].to_vec())),
            None => (rest, None),
        };
        Rule {
            text: line.to_vec(),
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
        fn side(tokens: &[Vec<u8>]) -> Vec<Attr> {
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
        self.decision.starts_with(b"deny")
            && self.object.as_deref().is_some_and(|o| o == [b"all"])
            && self
                .subject
                .iter()
                .any(|t| t != b"all" && !t.starts_with(b"perm="))
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
            r[0].text, b"allow perm=any uid=0 : dir=/var/tmp/",
            "the comment and the %set consume no position"
        );
    }

    #[test]
    fn the_ld_so_deny_is_rule_five_not_six() {
        let r = parse(ROCKY9);
        assert_eq!(r[4].text, b"deny_audit perm=any pattern=ld_so : all");
        assert_eq!(
            r[7].text,
            b"deny_audit perm=open all : ftype=application/x-sharedlib"
        );
        assert_eq!(r[12].text, b"deny_audit perm=execute all : all");
    }

    #[test]
    fn only_the_subject_side_rule_refuses() {
        for (i, r) in parse(ROCKY9).iter().enumerate() {
            assert_eq!(r.refuses(), i == 4, "rule {}: {:?}", i + 1, r.text);
        }
    }

    #[test]
    fn an_original_format_rule_never_refuses() {
        let r = Rule::new(b"deny_audit perm=any pattern=ld_so");
        assert_eq!(r.object, None);
        assert!(
            !r.refuses(),
            "original format has no object side to be `all`"
        );
    }

    #[test]
    fn an_allow_rule_never_refuses() {
        assert!(!Rule::new(b"allow perm=open exe=/usr/bin/rpm : all").refuses());
    }

    #[test]
    fn an_exe_only_deny_refuses() {
        assert!(Rule::new(b"deny perm=execute exe=/usr/bin/foo : all").refuses());
    }

    #[test]
    fn every_d4_attribute_keeps_its_value_and_its_side() {
        let (subject, object) = Rule::new(
            b"allow perm=open exe=/usr/bin/cat dir=/usr/bin : path=/tmp/x dir=/tmp/ \
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
        let (subject, object) = Rule::new(b"allow perm=any all : path=/tmp/sp ace/x").attrs();
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
            Rule::new(b"deny_audit perm=any pattern=ld_so uid=0 : sha256hash=ab dir=execdirs")
                .attrs();
        assert_eq!(
            subject,
            [
                Attr::Perm("any".into()),
                Attr::Unevaluable,
                Attr::Unevaluable
            ]
        );
        assert_eq!(
            object,
            [Attr::Unevaluable, Attr::Unevaluable],
            "a `dir=` keyword on its own is decidable only on a known daemon version (D19)"
        );
    }

    #[test]
    fn a_set_reference_and_a_dir_list_are_members_and_nothing_else_is() {
        let (subject, object) = Rule::new(
            b"allow perm=any exe=%trusted : ftype=%languages dir=execdirs,/opt/ path=%a,%b",
        )
        .attrs();
        assert_eq!(
            subject,
            [
                Attr::Perm("any".into()),
                Attr::Members("exe".into(), vec!["%trusted".into()]),
            ]
        );
        assert_eq!(
            object,
            [
                Attr::Members("ftype".into(), vec!["%languages".into()]),
                Attr::Members("dir".into(), vec!["execdirs".into(), "/opt/".into()]),
                // A set beside anything else on an attribute that is not `dir=`: nothing
                // measured it, and the value is not a literal either.
                Attr::Unevaluable,
            ]
        );
        assert_eq!(
            Rule::new(b"allow perm=any all : dir=/opt/").attrs().1,
            [Attr::Dir("/opt/".into())],
            "one literal directory is still one literal"
        );
    }

    #[test]
    fn a_definition_carries_its_members_and_the_rules_it_sorts_after() {
        let sets = sets(
            b"# a comment\n%a=/one,/two\nallow perm=any all : all\ndeny perm=any all : all\n%b=/three\n%c\n",
        );
        assert_eq!(sets.len(), 3, "{sets:?}");
        assert_eq!(sets[0].name, "%a");
        assert_eq!(sets[0].members, [b"/one".to_vec(), b"/two".to_vec()]);
        assert_eq!(sets[0].text, b"%a=/one,/two");
        assert_eq!(sets[0].rules_before, 0, "the comment is no rule");
        assert_eq!(sets[1].name, "%b");
        assert_eq!(sets[1].members, [b"/three".to_vec()]);
        assert_eq!(sets[1].rules_before, 2, "%b sorts after both rules");
        assert_eq!(
            sets[2].members,
            Vec::<Vec<u8>>::new(),
            "a line with no `=` defines nothing"
        );
        assert_eq!(sets[2].rules_before, 2);
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
    fn a_vertical_tab_or_a_no_break_space_inside_a_value_stays_in_its_token() {
        // `next_rule_token` breaks on the space byte only, so the daemon keeps these inside
        // the value; `split_whitespace` cut both of them.
        for path in [&b"path=/app/x\x0by"[..], "path=/app/x\u{a0}y".as_bytes()] {
            let rule = Rule::new(&[&b"allow perm=open all : "[..], path].concat());
            assert_eq!(rule.object, Some(vec![path.to_vec()]), "{path:?}");
        }
    }

    #[test]
    fn a_set_member_ends_at_the_first_space() {
        let s = sets(b"%s=/app/q,/app/\xff y");
        assert_eq!(s[0].members, [b"/app/q".to_vec(), b"/app/\xff".to_vec()]);
        assert_eq!(
            s[0].text, b"%s=/app/q,/app/\xff y",
            "the edit is still detected"
        );
    }

    #[test]
    fn two_rules_differing_only_outside_utf8_are_not_equal() {
        // The same hazard for a rule: the D3 skip compares rule text, and two texts that
        // both decode to U+FFFD would skip a candidate the daemon never walked past (#162).
        assert_ne!(
            parse(b"allow perm=open all : path=/opt/\xff"),
            parse(b"allow perm=open all : path=/opt/\xfe")
        );
        assert_eq!(
            parse(b"allow perm=open all : path=/opt/\xff")[0].object,
            Some(vec![b"path=/opt/\xff".to_vec()]),
            "the token keeps the byte"
        );
    }

    #[test]
    fn every_line_parse_drops_as_a_set_is_a_line_sets_keeps() {
        // `parse` trims with `str::trim`, which takes a vertical tab and U+00A0 that
        // `trim_ascii` leaves. A line led by either is dropped from the rules as a set, so
        // it has to be compared as one, or an edit to it is in neither list (#158).
        for lead in [&b"\x0b"[..], "\u{a0}".as_bytes()] {
            let (a, b) = (
                [lead, b"%s=/opt/a\n"].concat(),
                [lead, b"%s=/opt/b\n"].concat(),
            );
            assert!(parse(&a).is_empty(), "{a:?}");
            assert_eq!(sets(&a).len(), 1, "{a:?}");
            assert_ne!(sets(&a), sets(&b));
        }
    }

    #[test]
    fn an_original_format_rule_has_no_object_side_to_evaluate() {
        let (subject, object) = Rule::new(b"deny_audit perm=any pattern=ld_so").attrs();
        assert_eq!(subject, [Attr::Perm("any".into()), Attr::Unevaluable]);
        assert_eq!(
            object,
            [Attr::Unevaluable],
            "no object side is not the same as `all`"
        );
    }
}
