//! `fagenrules`-compatible ordering of rules.d entries.
use std::cmp::Ordering;
use std::iter::Peekable;
use std::path::Path;

/// Order two rules.d entries the way `fagenrules` does: GNU `ls -v` style
/// natural (version) sort on the file NAME. Digit runs compare as integers,
/// non-digit runs compare bytewise. A bytewise tiebreak guarantees a total
/// order for distinct-but-numerically-equal names (e.g. `8-a` vs `08-a`).
///
/// Targets the realistic `NN-name.rules` shape; not a bit-exact `strverscmp`
/// port, so exotic filenames could diverge from fagenrules. Acceptable for a
/// Warning-severity ordering heuristic (fapd-W04).
#[must_use]
pub fn fagenrules_cmp(a: &Path, b: &Path) -> Ordering {
    let an = a
        .file_name()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    let bn = b
        .file_name()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    match natural_cmp(&an, &bn) {
        Ordering::Equal => an.cmp(&bn),
        ord => ord,
    }
}

fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.bytes().peekable();
    let mut bi = b.bytes().peekable();
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(ca), Some(cb)) => {
                if ca.is_ascii_digit() && cb.is_ascii_digit() {
                    if let non_eq @ (Ordering::Less | Ordering::Greater) =
                        take_number(&mut ai).cmp(&take_number(&mut bi))
                    {
                        return non_eq;
                    }
                } else {
                    match ca.cmp(&cb) {
                        Ordering::Equal => {
                            ai.next();
                            bi.next();
                        }
                        non_eq => return non_eq,
                    }
                }
            }
        }
    }
}

fn take_number<I: Iterator<Item = u8>>(it: &mut Peekable<I>) -> u64 {
    let mut n: u64 = 0;
    while let Some(&c) = it.peek() {
        if c.is_ascii_digit() {
            n = n.saturating_mul(10).saturating_add(u64::from(c - b'0'));
            it.next();
        } else {
            break;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn nine_sorts_before_ten() {
        let mut v = [PathBuf::from("10-a.rules"), PathBuf::from("9-a.rules")];
        v.sort_by(|a, b| fagenrules_cmp(a, b));
        assert_eq!(v, [PathBuf::from("9-a.rules"), PathBuf::from("10-a.rules")]);
    }
    #[test]
    fn leading_zero_and_multidigit_order() {
        let mut v = [
            PathBuf::from("100-a.rules"),
            PathBuf::from("08-a.rules"),
            PathBuf::from("10-a.rules"),
            PathBuf::from("2-a.rules"),
        ];
        v.sort_by(|a, b| fagenrules_cmp(a, b));
        let names: Vec<_> = v.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert_eq!(
            names,
            ["2-a.rules", "08-a.rules", "10-a.rules", "100-a.rules"]
        );
    }
    #[test]
    fn distinct_but_numerically_equal_names_are_total_order() {
        assert_ne!(
            fagenrules_cmp(Path::new("8-a.rules"), Path::new("08-a.rules")),
            std::cmp::Ordering::Equal
        );
    }
    #[test]
    fn non_numeric_names_compare_bytewise() {
        assert_eq!(
            fagenrules_cmp(Path::new("aaa.rules"), Path::new("bbb.rules")),
            std::cmp::Ordering::Less
        );
    }
}
