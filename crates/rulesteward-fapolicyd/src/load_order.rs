//! `fagenrules`-compatible ordering of rules.d entries.
use std::cmp::Ordering;
use std::iter::Peekable;
use std::path::Path;

/// Order two rules.d entries the way `fagenrules` does: GNU `ls -v` style
/// natural (version) sort on the file NAME. Digit runs compare as
/// arbitrary-precision unsigned integers (overflow-proof for any prefix
/// length), non-digit runs compare bytewise. A bytewise tiebreak guarantees a total
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
                    let ra = take_digit_run(&mut ai);
                    let rb = take_digit_run(&mut bi);
                    if let non_eq @ (Ordering::Less | Ordering::Greater) =
                        cmp_digit_runs(&ra, &rb)
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

/// Consume and return the leading digit-run bytes from `it` (may be empty if
/// the next byte is not a digit).
fn take_digit_run<I: Iterator<Item = u8>>(it: &mut Peekable<I>) -> Vec<u8> {
    let mut run = Vec::new();
    while let Some(&c) = it.peek() {
        if c.is_ascii_digit() {
            run.push(c);
            it.next();
        } else {
            break;
        }
    }
    run
}

/// Compare two ASCII digit-runs as natural numbers, overflow-proof: strip
/// leading zeros, then order by significant-digit count, then bytewise.
/// Replaces the old `take_number -> u64` path that saturated at `u64::MAX` and
/// tied distinct large numbers, breaking fagenrules-compatible load order for
/// 20+ digit prefixes.
fn cmp_digit_runs(a: &[u8], b: &[u8]) -> Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip_leading_zeros(s: &[u8]) -> &[u8] {
    let nz = s.iter().position(|&c| c != b'0').unwrap_or(s.len());
    &s[nz..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn giant_digit_runs_order_by_true_numeric_value() {
        // 2e19 (20 digits) < 1e20 (21 digits); both overflow u64 under the old code and tied wrongly.
        let mut v = [
            PathBuf::from("100000000000000000000-allow.rules"), // 1e20, 21 digits
            PathBuf::from("20000000000000000000-deny.rules"),   // 2e19, 20 digits
        ];
        v.sort_by(|a, b| fagenrules_cmp(a, b));
        assert_eq!(
            v[0], PathBuf::from("20000000000000000000-deny.rules"),
            "the smaller 20-digit number must sort before the larger 21-digit one"
        );
    }
    #[test]
    fn equal_length_giant_runs_compare_bytewise() {
        // same length, both overflow u64; must still distinguish by value (old code tied them).
        let mut v = [
            PathBuf::from("99999999999999999999-b.rules"), // 20 nines
            PathBuf::from("99999999999999999998-a.rules"), // 20 digits, ...998 < ...999
        ];
        v.sort_by(|a, b| fagenrules_cmp(a, b));
        assert_eq!(v[0], PathBuf::from("99999999999999999998-a.rules"));
    }

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
