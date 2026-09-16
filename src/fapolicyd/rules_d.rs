//! `rules.d/` as fagenrules merges it: filename order, rules renumbered end to end.
//! Pure -- the caller does the `read_dir` and hands the (name, bytes) pairs here.
//!
//! This is a reader, not a generator. It answers one question: which component file
//! holds `rule=N`, so the emitted rule can be given a filename that sorts before it.
//! Everything fagenrules does beyond the order -- the fatal `%set` redefinition, the
//! newline gluing -- stays out, because nothing here writes a file.

use super::rules::{self, Rule};
use std::cmp::Ordering;

/// One component file of `rules.d/`, its rules numbered from 1 within the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub rules: Vec<Rule>,
}

/// GNU `filevercmp`, which is the order `ls -1v` gives fagenrules: a port of gnulib's
/// `lib/filevercmp.c`. `order`, `file_prefixlen` and `verrevcmp` keep the names and the
/// semantics of their C originals, and the C is the reference for any question about
/// them. What they do not keep is its pair of integer cursors: each walks a slice that
/// every step shortens instead, so no loop here can be made to stand still. A cursor a
/// mutation stops advancing hangs the suite rather than failing it, and a hang is a
/// timeout, which is a mutant nothing can kill. Comparisons are ASCII-only, as there.
fn filevercmp(a: &[u8], b: &[u8]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        (false, false) => {}
    }
    // `.`, `..` and every other dotfile sort ahead of the rest, in that order.
    if a[0] == b'.' {
        if b[0] != b'.' {
            return Ordering::Less;
        }
        match (a.len() == 1, b.len() == 1) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        match (a[1] == b'.' && a.len() == 2, b[1] == b'.' && b.len() == 2) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
    } else if b[0] == b'.' {
        return Ordering::Greater;
    }
    // First pass over the names without their extensions; only a tie there, and only
    // when at least one name has an extension, re-runs over the whole of both.
    let (aprefix, bprefix) = (file_prefixlen(a), file_prefixlen(b));
    let one_pass_only = aprefix == a.len() && bprefix == b.len();
    let result = verrevcmp(&a[..aprefix], &b[..bprefix]);
    if result != Ordering::Equal || one_pass_only {
        result
    } else {
        verrevcmp(a, b)
    }
}

/// A digit, and the end of the name: the two classes `verrevcmp` steers on.
const DIGIT: (u8, u8) = (2, 0);
const END: (u8, u8) = (1, 0);

/// The sort class of the first byte of `s`, as a rank that compares
/// lexicographically: the C's `-2 < -1 < 0 < letter < letter + 256` with the numbers
/// replaced by classes. An empty `s` is the end of the name, which the C reaches by
/// letting its cursor step one past the last byte.
fn order(s: &[u8]) -> (u8, u8) {
    match s.first() {
        Some(b'~') => (0, 0),
        None => END,
        Some(&c) if c.is_ascii_digit() => DIGIT,
        Some(&c) if c.is_ascii_alphabetic() => (3, c),
        Some(&c) => (4, c),
    }
}

/// The length of the name up to its file extensions -- the trailing `.` groups that
/// start with a letter or `~`, so `.tar.gz` and `.~1~` are cut and `a..a` is not.
fn file_prefixlen(s: &[u8]) -> usize {
    let mut prefixlen = 0;
    let mut skip_to = 0;
    for i in 0..s.len() {
        // Bytes inside an extension run do not extend the prefix. Everything after
        // the last one does, which is why the extensions are skipped and not stopped
        // at: `zz.0` keeps its `.0`, `zz.0.txt` does not keep its `.txt`.
        if i < skip_to {
            continue;
        }
        prefixlen = i + 1;
        skip_to = prefixlen + extensions_len(&s[prefixlen..]);
    }
    prefixlen
}

/// The run of extensions at the front of `s`: each is a `.`, then a letter or `~`,
/// then any run of letters, digits and `~`.
fn extensions_len(s: &[u8]) -> usize {
    let mut rest = s;
    // The pattern consumes the `.` and the byte after it, so every pass shortens
    // `rest` by at least two and the loop cannot be made to stand still.
    while let [b'.', c, tail @ ..] = rest {
        if !(c.is_ascii_alphabetic() || *c == b'~') {
            break;
        }
        let body = tail
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'~')
            .count();
        rest = &tail[body..];
    }
    s.len() - rest.len()
}

/// The version comparison itself: the two names give up a byte at a time while their
/// classes agree, and a digit run on both sides at once compares as a number instead.
fn verrevcmp(mut s1: &[u8], mut s2: &[u8]) -> Ordering {
    loop {
        let (c1, c2) = (order(s1), order(s2));
        // The C's non-digit loop, one pass of it: a run of digits is only a number
        // when the other side is on one too, or has ended. `0x` against `ax` compares
        // its `0` as a digit, and only `a0` against `a` drops the zero.
        if !([DIGIT, END].contains(&c1) && [DIGIT, END].contains(&c2)) {
            if c1 != c2 {
                return c1.cmp(&c2);
            }
            // Equal classes below `DIGIT` mean the same byte on both sides, so
            // neither has ended and both have one to give.
            (s1, s2) = (&s1[1..], &s2[1..]);
            continue;
        }
        let ((d1, r1), (d2, r2)) = (digits(s1), digits(s2));
        // Leading zeros are gone, so the longer run is the larger number, and equal
        // lengths decide on the first digit that differs.
        let by_number = d1.len().cmp(&d2.len()).then_with(|| d1.cmp(d2));
        if by_number != Ordering::Equal {
            return by_number;
        }
        if (r1.len(), r2.len()) == (s1.len(), s2.len()) {
            // Neither side had a digit or a zero to give, so both have ended: the C's
            // outer loop condition, and what makes every pass through this one either
            // return or shorten a name.
            return Ordering::Equal;
        }
        (s1, s2) = (r1, r2);
    }
}

/// The leading digit run of `s` without its leading zeros, and what follows the run.
fn digits(s: &[u8]) -> (&[u8], &[u8]) {
    let s = &s[s.iter().take_while(|c| **c == b'0').count()..];
    s.split_at(s.iter().take_while(|c| c.is_ascii_digit()).count())
}

/// Drops anything not named `*.rules` -- fagenrules' own filter -- then sorts and
/// parses. Rule numbers inside a `File` are per-file; `locate` does the arithmetic
/// that turns them back into the daemon's numbering.
pub fn files(named: Vec<(String, Vec<u8>)>) -> Vec<File> {
    let mut named: Vec<(String, Vec<u8>)> = named
        .into_iter()
        .filter(|(name, _)| name.ends_with(".rules"))
        .collect();
    // The byte-order tie-break is `ls`'s own: coreutils falls back to `strcmp` when
    // filevercmp calls two names equal, which is what keeps `01-a` before `1-a`.
    named.sort_by(|a, b| {
        let (a, b) = (a.0.as_bytes(), b.0.as_bytes());
        filevercmp(a, b).then_with(|| a.cmp(b))
    });
    named
        .into_iter()
        .map(|(name, bytes)| File {
            name,
            rules: rules::parse(&bytes),
        })
        .collect()
}

/// The index in `files` of the component file holding the daemon's `rule=n`, or `None`
/// when `rules.d/` and `compiled.rules` disagree -- the text at that position differs,
/// or `n` is past the merged total. Both mean `rules.d/` changed after fagenrules last
/// ran, and the merged order in hand is not the one that produced the record.
pub fn locate(files: &[File], compiled: &[Rule], n: usize) -> Option<usize> {
    let mut merged = 0usize;
    for (i, file) in files.iter().enumerate() {
        // `parse` renumbers from 1 inside every file, so the daemon's number is an
        // offset into this file's vec and never an index into the merged set.
        if let Some(within) = n.checked_sub(merged + 1).filter(|w| *w < file.rules.len()) {
            let at = n.checked_sub(1).and_then(|j| compiled.get(j))?;
            return (file.rules[within].text == at.text).then_some(i);
        }
        merged += file.rules.len();
    }
    None
}

/// The leading digit run of `name` as a value and its width, or `None` when the name
/// does not start with digits.
fn prefix(name: &str) -> Option<(u64, usize)> {
    let digits = &name[..name
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(name.len())];
    Some((digits.parse().ok()?, digits.len()))
}

/// The filename to suggest so the new file sorts before `files[at]`.
///
/// With a digit prefix: that prefix minus one, zero-padded to the same width. `None`
/// when the prefix is already `0`, because nothing sorts before it. With no prefix the
/// file sorts last of all, so anything numbered sorts before it: one past the largest
/// prefix in `files`, which shadows the fewest existing rules, or `1-` when nothing is
/// numbered.
pub fn recommend(files: &[File], at: usize) -> Option<String> {
    let (before, width) = match prefix(&files.get(at)?.name) {
        Some((n, width)) => (n.checked_sub(1)?, width),
        None => files
            .iter()
            .filter_map(|f| prefix(&f.name))
            .max()
            .map_or((1, 1), |(n, width)| (n.saturating_add(1), width)),
    };
    Some(format!("{before:0width$}-rulesteward.rules"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(names: &[&str]) -> Vec<(String, Vec<u8>)> {
        names
            .iter()
            .map(|n| ((*n).to_string(), Vec::new()))
            .collect()
    }

    fn order(names: &[&str]) -> Vec<String> {
        files(named(names)).into_iter().map(|f| f.name).collect()
    }

    /// The Rocky 9 shipped split, the same 14 rules `rules.rs` pins, cut at the
    /// boundaries of the files fagenrules merged them from.
    fn shipped() -> Vec<File> {
        files(
            [
                ("10-languages.rules", "%languages=text/x-python"),
                (
                    "20-dracut.rules",
                    "allow perm=any uid=0 : dir=/var/tmp/\nallow perm=any uid=0 trust=1 : all",
                ),
                (
                    "21-updaters.rules",
                    "allow perm=open exe=/usr/bin/rpm : all\nallow perm=open exe=/usr/bin/python3.9 comm=dnf : all",
                ),
                ("30-patterns.rules", "deny_audit perm=any pattern=ld_so : all"),
                (
                    "40-bad-elf.rules",
                    "deny_audit perm=any all : ftype=application/x-bad-elf",
                ),
                (
                    "41-shared-obj.rules",
                    "allow perm=open all : ftype=application/x-sharedlib trust=1\ndeny_audit perm=open all : ftype=application/x-sharedlib",
                ),
                ("42-trusted-elf.rules", "allow perm=execute all : trust=1"),
                (
                    "70-trusted-lang.rules",
                    "allow perm=open all : ftype=%languages trust=1\ndeny_audit perm=any all : ftype=%languages",
                ),
                ("72-shell.rules", "allow perm=any all : ftype=text/x-shellscript"),
                ("90-deny-execute.rules", "deny_audit perm=execute all : all"),
                ("95-allow-open.rules", "allow perm=open all : all"),
            ]
            .into_iter()
            .map(|(n, b)| (n.to_string(), format!("{b}\n").into_bytes()))
            .collect(),
        )
    }

    fn compiled() -> Vec<Rule> {
        let merged: String = shipped()
            .iter()
            .flat_map(|f| f.rules.iter().map(|r| format!("{}\n", r.text)))
            .collect();
        rules::parse(merged.as_bytes())
    }

    #[test]
    fn a_digit_run_compares_as_a_number_not_bytewise() {
        assert_eq!(
            order(&["10-b.rules", "2-a.rules", "10-a.rules"]),
            ["2-a.rules", "10-a.rules", "10-b.rules"],
            "`2-` before `10-`, then the same prefix ties on the rest"
        );
    }

    #[test]
    fn an_unprefixed_file_sorts_last() {
        assert_eq!(
            order(&["zz.rules", "99-z.rules", "local.rules"]),
            ["99-z.rules", "local.rules", "zz.rules"]
        );
    }

    #[test]
    fn only_dot_rules_files_are_merged() {
        assert_eq!(
            order(&["30-patterns.rules", "30-patterns.rules.rpmnew", "README"]),
            ["30-patterns.rules"]
        );
    }

    #[test]
    fn every_file_boundary_locates_to_its_own_file() {
        let (files, compiled) = (shipped(), compiled());
        // (rule number, file index) at both ends of every multi-rule file.
        for (n, want) in [
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 4),
            (7, 5),
            (8, 5),
            (9, 6),
            (10, 7),
            (11, 7),
            (12, 8),
            (13, 9),
            (14, 10),
        ] {
            assert_eq!(
                locate(&files, &compiled, n),
                Some(want),
                "rule={n} belongs to {}",
                files[want].name
            );
        }
    }

    #[test]
    fn the_languages_file_holds_no_rule_and_is_never_located_to() {
        let files = shipped();
        assert_eq!(files[0].name, "10-languages.rules");
        assert!(
            files[0].rules.is_empty(),
            "a `%set` consumes no rule number"
        );
    }

    #[test]
    fn a_rule_past_the_merged_total_is_drift() {
        assert_eq!(locate(&shipped(), &compiled(), 15), None);
        assert_eq!(locate(&[], &compiled(), 1), None);
    }

    #[test]
    fn different_text_at_the_same_position_is_drift() {
        let mut compiled = compiled();
        compiled[12].text = "deny_audit perm=execute all : ftype=application/x-bad-elf".into();
        assert_eq!(
            locate(&shipped(), &compiled, 13),
            None,
            "rules.d/ changed since fagenrules last ran"
        );
        assert_eq!(locate(&shipped(), &compiled, 12), Some(8), "and only there");
    }

    #[test]
    fn the_recommended_name_keeps_the_prefix_width() {
        let f = files(named(&[
            "90-deny-execute.rules",
            "010-x.rules",
            "1-x.rules",
        ]));
        assert_eq!(f[2].name, "90-deny-execute.rules");
        assert_eq!(recommend(&f, 2).as_deref(), Some("89-rulesteward.rules"));
        assert_eq!(f[1].name, "010-x.rules");
        assert_eq!(recommend(&f, 1).as_deref(), Some("009-rulesteward.rules"));
        assert_eq!(f[0].name, "1-x.rules");
        assert_eq!(recommend(&f, 0).as_deref(), Some("0-rulesteward.rules"));
    }

    #[test]
    fn a_name_that_is_a_prefix_of_another_sorts_first_and_an_equal_name_ties() {
        // Both exhaust one side of the comparison; the loop must stop there.
        assert_eq!(filevercmp(b"10", b"10-a"), Ordering::Less);
        assert_eq!(filevercmp(b"10-a", b"10"), Ordering::Greater);
        assert_eq!(filevercmp(b"10-a.rules", b"10-a.rules"), Ordering::Equal);
    }

    /// gnulib's `tests/test-filevercmp.c`, its `examples` array verbatim: a list
    /// already in filevercmp order, `\1` and all. The C test's own `filenvercmp`
    /// pass replaces those bytes with NUL, which no filename can hold, so only the
    /// `filevercmp` half is ported.
    const GNULIB_EXAMPLES: &[&[u8]] = &[
        b"",
        b".",
        b"..",
        b".0",
        b".9",
        b".A",
        b".Z",
        b".a~",
        b".a",
        b".b~",
        b".b",
        b".z",
        b".zz~",
        b".zz",
        b".zz.~1~",
        b".zz.0",
        b".\x01",
        b".\x01.txt",
        b".\x01x",
        b".\x01x\x01",
        b".\x01.0",
        b"0",
        b"9",
        b"A",
        b"Z",
        b"a~",
        b"a",
        b"a.b~",
        b"a.b",
        b"a.bc~",
        b"a.bc",
        b"a+",
        b"a.",
        b"a..a",
        b"a.+",
        b"b~",
        b"b",
        b"gcc-c++-10.fc9.tar.gz",
        b"gcc-c++-10.fc9.tar.gz.~1~",
        b"gcc-c++-10.fc9.tar.gz.~2~",
        b"gcc-c++-10.8.12-0.7rc2.fc9.tar.bz2",
        b"gcc-c++-10.8.12-0.7rc2.fc9.tar.bz2.~1~",
        b"glibc-2-0.1.beta1.fc10.rpm",
        b"glibc-common-5-0.2.beta2.fc9.ebuild",
        b"glibc-common-5-0.2b.deb",
        b"glibc-common-11b.ebuild",
        b"glibc-common-11-0.6rc2.ebuild",
        b"libstdc++-0.5.8.11-0.7rc2.fc10.tar.gz",
        b"libstdc++-4a.fc8.tar.gz",
        b"libstdc++-4.10.4.20040204svn.rpm",
        b"libstdc++-devel-3.fc8.ebuild",
        b"libstdc++-devel-3a.fc9.tar.gz",
        b"libstdc++-devel-8.fc8.deb",
        b"libstdc++-devel-8.6.2-0.4b.fc8",
        b"nss_ldap-1-0.2b.fc9.tar.bz2",
        b"nss_ldap-1-0.6rc2.fc8.tar.gz",
        b"nss_ldap-1.0-0.1a.tar.gz",
        b"nss_ldap-10beta1.fc8.tar.gz",
        b"nss_ldap-10.11.8.6.20040204cvs.fc10.ebuild",
        b"z",
        b"zz~",
        b"zz",
        b"zz.~1~",
        b"zz.0",
        b"zz.0.txt",
        b"\x01",
        b"\x01.txt",
        b"\x01x",
        b"\x01x\x01",
        b"\x01.0",
        b"#\x01.b#",
        b"#.b#",
    ];

    /// The same file's `equals` sets: within a set every name compares equal.
    const GNULIB_EQUALS: &[&[&[u8]]] = &[
        &[b"a", b"a0", b"a0000"],
        &[
            b"a\x01c-27.txt",
            b"a\x01c-027.txt",
            b"a\x01c-00000000000000000000000000000000000000000000000000000027.txt",
        ],
        &[
            b".a\x01c-27.txt",
            b".a\x01c-027.txt",
            b".a\x01c-00000000000000000000000000000000000000000000000000000027.txt",
        ],
        &[b"a\x01c-", b"a\x01c-0", b"a\x01c-00"],
        &[b".a\x01c-", b".a\x01c-0", b".a\x01c-00"],
        &[b"a\x01c-0.txt", b"a\x01c-00.txt"],
        &[b".a\x01c-1\x01.txt", b".a\x01c-001\x01.txt"],
    ];

    #[test]
    fn the_gnulib_example_list_is_already_in_order() {
        let mut sorted = GNULIB_EXAMPLES.to_vec();
        sorted.sort_by(|a, b| filevercmp(a, b));
        assert_eq!(sorted, GNULIB_EXAMPLES, "{} vectors", GNULIB_EXAMPLES.len());
        // Every pair, both directions, as the C test's O(n^2) pass is: no two of
        // these compare equal, and a comparator that disagrees with itself one way
        // round is what an adjacent-pairs sweep would miss.
        for (i, a) in GNULIB_EXAMPLES.iter().enumerate() {
            for b in &GNULIB_EXAMPLES[i + 1..] {
                assert_eq!(
                    (filevercmp(a, b), filevercmp(b, a)),
                    (Ordering::Less, Ordering::Greater),
                    "{:?} sorts before {:?}, both ways round",
                    String::from_utf8_lossy(a),
                    String::from_utf8_lossy(b)
                );
            }
        }
    }

    #[test]
    fn every_gnulib_equal_set_compares_equal_both_ways() {
        for set in GNULIB_EQUALS {
            for a in *set {
                for b in *set {
                    assert_eq!(
                        filevercmp(a, b),
                        Ordering::Equal,
                        "{:?} vs {:?}",
                        String::from_utf8_lossy(a),
                        String::from_utf8_lossy(b)
                    );
                }
            }
        }
    }

    #[test]
    fn the_order_is_the_one_ls_1v_gives() {
        // Measured on coreutils 9.5: `touch` these seven names in an empty directory
        // and `ls -1v` prints them in exactly this order.
        assert_eq!(
            order(&[
                "1-a.rules",
                "01-a.rules",
                "010-x.rules",
                "10-x.rules",
                "2-a.rules",
                "local.rules",
                "zz.rules",
            ]),
            [
                "01-a.rules",
                "1-a.rules",
                "2-a.rules",
                "010-x.rules",
                "10-x.rules",
                "local.rules",
                "zz.rules",
            ]
        );
    }

    #[test]
    fn zero_declines_and_an_unprefixed_file_takes_one_past_the_last_number() {
        let zero = files(named(&["00-first.rules", "0-first.rules"]));
        assert_eq!(recommend(&zero, 0), None, "nothing sorts before 0-");
        assert_eq!(recommend(&zero, 1), None);

        // An unprefixed file sorts last, so one past the largest prefix sorts before it
        // and after every numbered file.
        let mixed = files(named(&[
            "90-deny-execute.rules",
            "95-allow-open.rules",
            "local.rules",
        ]));
        assert_eq!(mixed[2].name, "local.rules");
        assert_eq!(
            recommend(&mixed, 2).as_deref(),
            Some("96-rulesteward.rules")
        );

        let none = files(named(&["local.rules", "zz.rules"]));
        assert_eq!(recommend(&none, 0).as_deref(), Some("1-rulesteward.rules"));
    }
}
