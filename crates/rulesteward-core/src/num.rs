//! Shared numeric parsing helpers.

/// Parse `s` as a non-negative integer the way C `strtoul(s, NULL, 0)` reads the
/// magnitude: a `0x`/`0X` prefix is hex, a leading `0` (with more digits) is
/// octal, otherwise decimal.
///
/// CONSERVATIVE by construction: the WHOLE string must be a clean number in the
/// detected radix, so this returns `None` on any ambiguity rather than
/// replicating strtoul's parse-a-prefix-then-stop. In particular `08` is `None`
/// (not `0`), a lone sign or an embedded sign is `None`, and an empty string is
/// `None`. There is no sign handling: callers that accept a leading `-` split it
/// off first and negate the magnitude themselves (auditd `exit`, sysctld
/// integers), which is also where each caller's own out-of-range policy lives.
///
/// Grounded in libaudit `audit_rule_fieldpair_data` (lib/libaudit.c @ 3bfa048),
/// which parses every numeric `-F` value with `strtoul`/`strtol` base 0 (#229),
/// and the kernel's `_parse_integer_fixup_radix` used for sysctl values.
///
/// Shared by `rulesteward-auditd` (uid/gid/exit `-F` values) and
/// `rulesteward-sysctld` (STIG baseline integer comparison) so the base-0 radix
/// semantics live in one place.
#[must_use]
pub fn parse_base0_u64(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        let octal = &s[1..];
        if !octal.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        u64::from_str_radix(octal, 8).ok()
    } else if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        s.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_base0_u64;

    #[test]
    fn decimal_values_parse() {
        assert_eq!(parse_base0_u64("0"), Some(0));
        assert_eq!(parse_base0_u64("7"), Some(7));
        assert_eq!(parse_base0_u64("255"), Some(255));
        // A lone leading zero is decimal 0, not an (empty) octal.
        assert_eq!(parse_base0_u64("18446744073709551615"), Some(u64::MAX));
    }

    #[test]
    fn hex_prefix_parses_both_cases() {
        assert_eq!(parse_base0_u64("0x10"), Some(16));
        assert_eq!(parse_base0_u64("0X10"), Some(16));
        assert_eq!(parse_base0_u64("0xff"), Some(255));
        assert_eq!(parse_base0_u64("0xFF"), Some(255));
    }

    #[test]
    fn octal_leading_zero_parses() {
        assert_eq!(parse_base0_u64("010"), Some(8));
        assert_eq!(parse_base0_u64("0777"), Some(511));
        // Two leading zeros still octal (len > 1).
        assert_eq!(parse_base0_u64("00"), Some(0));
    }

    #[test]
    fn invalid_octal_digit_is_none() {
        // `08` / `09` are not valid octal: conservative None, never `0`.
        assert_eq!(parse_base0_u64("08"), None);
        assert_eq!(parse_base0_u64("019"), None);
    }

    #[test]
    fn invalid_hex_is_none() {
        assert_eq!(parse_base0_u64("0x"), None);
        assert_eq!(parse_base0_u64("0xg"), None);
        assert_eq!(parse_base0_u64("0X-1"), None);
    }

    #[test]
    fn empty_and_signs_and_junk_are_none() {
        assert_eq!(parse_base0_u64(""), None);
        assert_eq!(parse_base0_u64("+5"), None);
        assert_eq!(parse_base0_u64("-5"), None);
        assert_eq!(parse_base0_u64("5a"), None);
        assert_eq!(parse_base0_u64("abc"), None);
        // Whitespace is not trimmed here (callers trim first).
        assert_eq!(parse_base0_u64(" 5"), None);
    }
}
