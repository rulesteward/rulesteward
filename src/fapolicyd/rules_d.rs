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

/// fagenrules' `ls -1v`: digit runs compare as numbers, so `2-` precedes `10-`, and a
/// digit run sorts before a non-digit one, so an unprefixed file lands last.
///
/// Equal numeric value falls back to the raw run, which orders `010-` after `10-`.
/// That is a guess at `filevercmp`, not a reproduction of it: leading-zero collisions
/// are not a shipped case and emulating the whole of it would buy nothing.
fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() && !b.is_empty() {
        let (ra, rest_a) = run(a);
        let (rb, rest_b) = run(b);
        let ord = match (ra[0].is_ascii_digit(), rb[0].is_ascii_digit()) {
            (true, true) => number(ra).cmp(&number(rb)).then_with(|| ra.cmp(rb)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => ra.cmp(rb),
        };
        if ord != Ordering::Equal {
            return ord;
        }
        (a, b) = (rest_a, rest_b);
    }
    a.len().cmp(&b.len())
}

/// The leading run of digits, or of non-digits, and what follows it.
fn run(s: &[u8]) -> (&[u8], &[u8]) {
    let digit = s[0].is_ascii_digit();
    s.split_at(
        s.iter()
            .position(|c| c.is_ascii_digit() != digit)
            .unwrap_or(s.len()),
    )
}

/// A run too long for a `u64` sorts last among digit runs rather than panicking; no
/// filename has 20 digits of prefix, and a wrong order there beats an abort.
fn number(digits: &[u8]) -> u64 {
    String::from_utf8_lossy(digits).parse().unwrap_or(u64::MAX)
}

/// Drops anything not named `*.rules` -- fagenrules' own filter -- then sorts and
/// parses. Rule numbers inside a `File` are per-file; `locate` does the arithmetic
/// that turns them back into the daemon's numbering.
pub fn files(named: Vec<(String, Vec<u8>)>) -> Vec<File> {
    let mut named: Vec<(String, Vec<u8>)> = named
        .into_iter()
        .filter(|(name, _)| name.ends_with(".rules"))
        .collect();
    named.sort_by(|a, b| natural_cmp(&a.0, &b.0));
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
        // offset into this file's vec and never a `rules::find` on it.
        if let Some(within) = n.checked_sub(merged + 1).filter(|w| *w < file.rules.len()) {
            return (file.rules[within].text == rules::find(compiled, n)?.text).then_some(i);
        }
        merged += file.rules.len();
    }
    None
}

/// The filename to suggest so the new file sorts before `name`: its leading digit run
/// minus one, zero-padded to the same width. `None` when there is no digit prefix, or
/// it is already `0`, because then nothing can be recommended that sorts before it.
pub fn recommend(name: &str) -> Option<String> {
    let digits = &name[..name
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(name.len())];
    let before = digits.parse::<u64>().ok()?.checked_sub(1)?;
    Some(format!(
        "{before:0width$}-rulesteward.rules",
        width = digits.len()
    ))
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
        assert_eq!(
            recommend("90-deny-execute.rules").as_deref(),
            Some("89-rulesteward.rules")
        );
        assert_eq!(
            recommend("010-x.rules").as_deref(),
            Some("009-rulesteward.rules")
        );
        assert_eq!(
            recommend("1-x.rules").as_deref(),
            Some("0-rulesteward.rules")
        );
    }

    #[test]
    fn a_name_that_is_a_prefix_of_another_sorts_first_and_an_equal_name_ties() {
        // Both exhaust one side of the comparison; the loop must stop there.
        assert_eq!(natural_cmp("10", "10-a"), Ordering::Less);
        assert_eq!(natural_cmp("10-a", "10"), Ordering::Greater);
        assert_eq!(natural_cmp("10-a.rules", "10-a.rules"), Ordering::Equal);
    }

    #[test]
    fn nothing_can_be_recommended_before_zero_or_before_no_prefix() {
        assert_eq!(recommend("00-first.rules"), None);
        assert_eq!(recommend("0-first.rules"), None);
        assert_eq!(recommend("local.rules"), None);
    }
}
