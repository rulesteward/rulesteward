//! Shared `-F` value interpretation for the duplicate/shadow/suppression lints
//! (#219 interval-aware subsumption, #220 value-spelling folding).
//!
//! Both enhancements need to interpret a `-F field op value` literal BY the
//! field's [`crate::lints::field_type::FieldType`]: #220 folds equivalent spellings into one canonical
//! form for [`crate::lints::normalize::canonical_key`]; #219 compares numeric
//! thresholds for [`crate::lints::ordering`]'s au-W02 subsumption and au-W03
//! disjointness. This module is the single place that decides what a value
//! "means", so the two lints can never disagree on value identity.
//!
//! Split (#438, pure move, no behavior change) into submodules by concern:
//! `classify` (the typed [`classify::FieldValue`] interpretation + base-0
//! parsing), `msgtype` (the record-type name<->number table + lookup),
//! `canonical` ([`canonical::canonical_value`], content identity), and
//! `compare` ([`compare::implies`] / [`compare::disjoint`], the interval and
//! bitmask predicate reasoning). This file keeps the module doc, [`LintOptions`],
//! the public re-exports, and the frozen `mod tests` suite.
//!
//! # The uid/gid/sessionid "unset" sentinel
//! libaudit treats uid/gid as `uid_t`/`gid_t`, and sessionid as a session id,
//! all `u32`. The value `-1` is the conventional "unset" sentinel; cast to
//! `u32` it is `4294967295` (`u32::MAX`), and libaudit's symbolic name for it is
//! `unset`. So for `FieldType::Uid`/`FieldType::Gid`/`FieldType::SessionId`
//! the three spellings `-1`, `4294967295`, and `unset` denote the IDENTICAL
//! kernel value and fold to one ([`FieldValue::UidGidUnset`]). This equivalence
//! is those id fields ONLY: a `pid=4294967295` (`FieldType::Numeric`) is a
//! concrete pid and an `exit=4294967295` (`FieldType::NumericSigned`) is a
//! concrete signed value; neither folds. (sessionid takes the sentinel but,
//! unlike uid/gid, has no name resolution; libaudit.c:1966-1984 @ 3bfa048, #270.)
//!
//! # Numeric spellings (base-0, #229)
//! Numeric fields parse their value with C `strtoul`/`strtol` base 0, matching
//! libaudit `audit_rule_fieldpair_data` @ 3bfa048: `0x80` is hex 128, `010` is
//! octal 8, `80` is decimal 80. So equivalent spellings of the same number fold
//! (`a0=0x80` == `a0=128`), and the leading-zero octal case is read correctly
//! (`a0=010` is 8, NOT 10). Parsing is strict: a value that is not a clean
//! base-0 number in its detected radix stays [`FieldValue::Opaque`] rather than
//! taking strtoul's parse-a-prefix-then-stop shortcut (so `08` is opaque, not 0).
//!
//! # Conservative by construction
//! Anything not numerically interpretable (a username, an errno symbol, a hex
//! literal on a string-typed field, or a malformed number) is
//! [`FieldValue::Opaque`]: it only ever compares by exact (trimmed) spelling,
//! never by interval. The numeric relations below return their answer only when
//! they can PROVE it; on any doubt they decline, so #219 never manufactures a
//! false subsumption or a false disjointness.

mod canonical;
mod classify;
mod compare;
mod msgtype;

pub use canonical::canonical_value;
pub use classify::{FieldValue, classify};
pub use compare::{disjoint, implies};

// Only referenced from `mod tests` below (via `super::msgtype_number` /
// `super::eq_values_provably_equal` / `super::MSGTYPE_NAMES` /
// `super::APPARMOR_MSGTYPE_NAMES`), which is itself `#[cfg(test)]`-gated;
// without this gate a non-test build reports these as unused imports. Each
// item is `pub(super)` in its defining submodule for exactly this reason (a
// private helper the frozen test suite still needs direct access to).
#[cfg(test)]
use compare::eq_values_provably_equal;
#[cfg(test)]
use msgtype::{APPARMOR_MSGTYPE_NAMES, MSGTYPE_NAMES, msgtype_number};

/// Options that gate opt-in folding behaviours in [`canonical_value`] and the
/// functions that call it. `Copy + Default` so callers that don't care can pass
/// `LintOptions::default()` (== `AppArmor` OFF, == pre-#230 byte-identical behaviour).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LintOptions {
    /// Also fold `AppArmor` msgtype record names (`APPARMOR_DENIED`, etc.) when
    /// looking up `msgtype` values. Off by default: a non-AppArmor audit daemon
    /// (RHEL/fapolicyd targets) does not compile the `WITH_APPARMOR` block, so
    /// asserting that equivalence by default would be incorrect. Enable when
    /// linting rules for an AppArmor-enabled audit build (Debian/Ubuntu).
    pub include_apparmor: bool,
}

#[cfg(test)]
mod tests {
    // Test bindings use families like ge1000/ge2000 and ne5/ne5b in one scope
    // (clippy::similar_names), and the `ft` helper takes the small `AuditField`
    // enum by value for call-site ergonomics (clippy::needless_pass_by_value).
    #![allow(clippy::similar_names, clippy::needless_pass_by_value)]

    use super::{
        FieldValue, LintOptions, canonical_value, classify, disjoint, eq_values_provably_equal,
        implies, msgtype_number,
    };
    use crate::ast::{AuditField, CompareOp, FieldFilter};
    use crate::lints::field_type::field_type;

    // Convenience shorthands for opts values used in AppArmor tests (#230).
    const OFF: LintOptions = LintOptions {
        include_apparmor: false,
    };
    const ON: LintOptions = LintOptions {
        include_apparmor: true,
    };

    fn ft(field: AuditField) -> crate::lints::field_type::FieldType {
        field_type(&field)
    }

    fn ff(field: AuditField, op: CompareOp, value: &str) -> FieldFilter {
        FieldFilter {
            field,
            op,
            value: value.to_string(),
        }
    }

    // --- classify: uid/gid sentinel -------------------------------------

    #[test]
    fn uid_sentinel_spellings_all_classify_unset() {
        for s in ["-1", "4294967295", "unset", "UNSET", "Unset"] {
            assert_eq!(
                classify(ft(AuditField::Auid), s),
                FieldValue::UidGidUnset,
                "auid value {s:?} must be the unset sentinel"
            );
        }
        assert_eq!(classify(ft(AuditField::Gid), "-1"), FieldValue::UidGidUnset);
        assert_eq!(
            classify(ft(AuditField::Egid), "4294967295"),
            FieldValue::UidGidUnset
        );
    }

    #[test]
    fn uid_concrete_values_classify_unsigned() {
        assert_eq!(classify(ft(AuditField::Auid), "0"), FieldValue::Unsigned(0));
        assert_eq!(
            classify(ft(AuditField::Uid), "1000"),
            FieldValue::Unsigned(1000)
        );
        // u32::MAX-1 is concrete (only u32::MAX itself is the sentinel).
        assert_eq!(
            classify(ft(AuditField::Uid), "4294967294"),
            FieldValue::Unsigned(4_294_967_294)
        );
    }

    #[test]
    fn uid_non_numeric_and_out_of_range_are_opaque() {
        assert_eq!(classify(ft(AuditField::Auid), "root"), FieldValue::Opaque);
        // > u32::MAX is not a valid uid -> opaque, not a wrapped sentinel.
        assert_eq!(
            classify(ft(AuditField::Auid), "4294967296"),
            FieldValue::Opaque
        );
        // A negative other than -1 is not meaningful for uid -> opaque. (#229: we
        // do NOT replicate libaudit's negative-uid wrap; conservative Opaque.)
        assert_eq!(classify(ft(AuditField::Auid), "-2"), FieldValue::Opaque);
    }

    #[test]
    fn uid_parses_hex_octal_base0() {
        // libaudit parses uid with strtoul base 0 (#229): hex/octal accepted.
        assert_eq!(
            classify(ft(AuditField::Auid), "0x10"),
            FieldValue::Unsigned(16)
        );
        assert_eq!(
            classify(ft(AuditField::Auid), "010"),
            FieldValue::Unsigned(8)
        );
        // 0xFFFFFFFF == u32::MAX == the unset sentinel.
        assert_eq!(
            classify(ft(AuditField::Uid), "0xFFFFFFFF"),
            FieldValue::UidGidUnset
        );
    }

    // --- classify: sessionid sentinel (#270 AUD-3) ----------------------

    #[test]
    fn sessionid_sentinel_spellings_all_classify_unset() {
        // libaudit maps sessionid=unset -> 4294967295 (libaudit.c:1983-84 @
        // 3bfa048); -1 and 0xFFFFFFFF denote the same u32 sentinel, exactly like
        // uid/gid (#270 AUD-3, Q2: -1 folds too).
        for s in ["-1", "4294967295", "0xFFFFFFFF", "unset", "UNSET", "Unset"] {
            assert_eq!(
                classify(ft(AuditField::SessionId), s),
                FieldValue::UidGidUnset,
                "sessionid value {s:?} must be the unset sentinel"
            );
        }
    }

    #[test]
    fn sessionid_concrete_values_classify_unsigned() {
        assert_eq!(
            classify(ft(AuditField::SessionId), "0"),
            FieldValue::Unsigned(0)
        );
        assert_eq!(
            classify(ft(AuditField::SessionId), "5"),
            FieldValue::Unsigned(5)
        );
        // u32::MAX-1 is concrete (only u32::MAX itself is the sentinel).
        assert_eq!(
            classify(ft(AuditField::SessionId), "4294967294"),
            FieldValue::Unsigned(4_294_967_294)
        );
    }

    #[test]
    fn sessionid_out_of_range_and_nonnumeric_are_opaque() {
        // sessionid is a u32: above u32::MAX is not valid -> opaque (no wrap), and
        // sessionid has no name resolution, so a name token is opaque too.
        assert_eq!(
            classify(ft(AuditField::SessionId), "4294967296"),
            FieldValue::Opaque
        );
        assert_eq!(
            classify(ft(AuditField::SessionId), "abc"),
            FieldValue::Opaque
        );
    }

    #[test]
    fn sessionid_canonical_folds_sentinel_but_pid_does_not() {
        // All three sessionid sentinel spellings canonicalize to "unset" so
        // au-W01/au-W02 treat them as one value...
        for s in ["-1", "4294967295", "unset"] {
            assert_eq!(
                canonical_value(ft(AuditField::SessionId), s, OFF),
                "unset",
                "sessionid {s:?} must canonicalize to the sentinel"
            );
        }
        // ...while pid (plain Numeric) keeps 4294967295 as a concrete value: the
        // fold is sessionid-specific, not generic Numeric.
        assert_eq!(
            canonical_value(ft(AuditField::Pid), "4294967295", OFF),
            "4294967295"
        );
    }

    // --- classify: the 4294967295 distinctness invariant ----------------

    #[test]
    fn big_value_on_non_uid_numeric_is_concrete_not_sentinel() {
        // pid is Numeric (unsigned): 4294967295 is a concrete pid, NOT unset.
        assert_eq!(
            classify(ft(AuditField::Pid), "4294967295"),
            FieldValue::Unsigned(4_294_967_295)
        );
        // exit is NumericSigned: 4294967295 is a concrete signed value, -1 is a
        // concrete -1, NEITHER is the uid sentinel.
        assert_eq!(
            classify(ft(AuditField::Exit), "4294967295"),
            FieldValue::Signed(4_294_967_295)
        );
        assert_eq!(classify(ft(AuditField::Exit), "-1"), FieldValue::Signed(-1));
    }

    #[test]
    fn exit_i64_min_classifies_signed_not_opaque() {
        // i64::MIN has magnitude 2^63 (one past i64::MAX), so a naive
        // negate-after-try_from drops it to Opaque. It must classify as
        // Signed(i64::MIN) so au-W02 subsumption is not silently skipped (#270).
        assert_eq!(
            classify(ft(AuditField::Exit), "-9223372036854775808"),
            FieldValue::Signed(i64::MIN)
        );
        // The adjacent in-range bounds still classify correctly.
        assert_eq!(
            classify(ft(AuditField::Exit), "-9223372036854775807"),
            FieldValue::Signed(i64::MIN + 1)
        );
        assert_eq!(
            classify(ft(AuditField::Exit), "9223372036854775807"),
            FieldValue::Signed(i64::MAX)
        );
        // One past i64::MIN's magnitude (2^63 + 1) does not fit -> Opaque.
        assert_eq!(
            classify(ft(AuditField::Exit), "-9223372036854775809"),
            FieldValue::Opaque
        );
    }

    #[test]
    fn signed_and_unsigned_numeric_classify_by_type() {
        assert_eq!(
            classify(ft(AuditField::Exit), "-13"),
            FieldValue::Signed(-13)
        );
        assert_eq!(classify(ft(AuditField::Exit), "EPERM"), FieldValue::Opaque);
        assert_eq!(
            classify(ft(AuditField::Pid), "1000"),
            FieldValue::Unsigned(1000)
        );
        // a negative on an unsigned numeric does not parse -> opaque.
        assert_eq!(classify(ft(AuditField::Pid), "-1"), FieldValue::Opaque);
        // inode is NumericEqNe (still unsigned numeric for value purposes).
        assert_eq!(
            classify(ft(AuditField::Inode), "42"),
            FieldValue::Unsigned(42)
        );
    }

    #[test]
    fn string_typed_fields_are_always_opaque() {
        assert_eq!(
            classify(ft(AuditField::Path), "/etc/passwd"),
            FieldValue::Opaque
        );
        assert_eq!(classify(ft(AuditField::Exe), "/bin/sh"), FieldValue::Opaque);
        assert_eq!(classify(ft(AuditField::Arch), "b64"), FieldValue::Opaque);
        assert_eq!(classify(ft(AuditField::Key), "exec"), FieldValue::Opaque);
        // even a numeric-looking string on a string field stays opaque.
        assert_eq!(classify(ft(AuditField::Path), "1000"), FieldValue::Opaque);
    }

    // --- canonical_value: #220 folding ----------------------------------

    #[test]
    fn canonical_folds_uid_sentinel_triple() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "-1", OFF), "unset");
        assert_eq!(canonical_value(u, "4294967295", OFF), "unset");
        assert_eq!(canonical_value(u, "unset", OFF), "unset");
        assert_eq!(canonical_value(u, "UNSET", OFF), "unset");
        assert_eq!(canonical_value(ft(AuditField::Gid), "-1", OFF), "unset");
    }

    #[test]
    fn canonical_keeps_concrete_uid_distinct_from_sentinel() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "0", OFF), "0"); // root is not unset
        assert_eq!(canonical_value(u, "1000", OFF), "1000");
        assert_ne!(
            canonical_value(u, "0", OFF),
            canonical_value(u, "unset", OFF)
        );
    }

    #[test]
    fn canonical_does_not_fold_big_value_on_other_types() {
        // pid 4294967295 stays itself; exit -1 / 4294967295 stay themselves.
        assert_eq!(
            canonical_value(ft(AuditField::Pid), "4294967295", OFF),
            "4294967295"
        );
        assert_eq!(canonical_value(ft(AuditField::Exit), "-1", OFF), "-1");
        assert_eq!(
            canonical_value(ft(AuditField::Exit), "4294967295", OFF),
            "4294967295"
        );
        assert_ne!(
            canonical_value(ft(AuditField::Exit), "-1", OFF),
            canonical_value(ft(AuditField::Exit), "4294967295", OFF)
        );
    }

    #[test]
    fn canonical_opaque_values_keep_spelling_but_hex_octal_fold() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "root", OFF), "root");
        // #229: hex/octal now parse base-0 and fold to decimal (match libaudit).
        assert_eq!(canonical_value(u, "0x10", OFF), "16");
        assert_eq!(
            canonical_value(u, "0x10", OFF),
            canonical_value(u, "16", OFF)
        );
        // A genuinely unparseable value still keeps its trimmed spelling.
        assert_eq!(canonical_value(u, "0xZZ", OFF), "0xZZ");
    }

    // --- classify / canonical: base-0 numeric parsing (#229) ------------

    #[test]
    fn classify_parses_hex_octal_decimal_base0() {
        // Numeric -F values parse base-0 like libaudit strtoul/strtol @ 3bfa048.
        assert_eq!(
            classify(ft(AuditField::A0), "0x80"),
            FieldValue::Unsigned(128)
        );
        // leading-0 is OCTAL, not decimal (the latent-bug case).
        assert_eq!(classify(ft(AuditField::A0), "010"), FieldValue::Unsigned(8));
        assert_eq!(classify(ft(AuditField::A0), "80"), FieldValue::Unsigned(80));
        // signed exit: base-0 magnitude with an optional leading '-'.
        assert_eq!(
            classify(ft(AuditField::Exit), "0x10"),
            FieldValue::Signed(16)
        );
        assert_eq!(
            classify(ft(AuditField::Exit), "-0x10"),
            FieldValue::Signed(-16)
        );
        assert_eq!(classify(ft(AuditField::Exit), "-1"), FieldValue::Signed(-1));
    }

    #[test]
    fn canonical_folds_hex_octal_decimal_same_value() {
        let a = ft(AuditField::A0);
        assert_eq!(canonical_value(a, "0x80", OFF), "128");
        assert_eq!(
            canonical_value(a, "0x80", OFF),
            canonical_value(a, "128", OFF)
        );
        assert_eq!(canonical_value(a, "010", OFF), "8");
    }

    #[test]
    fn octal_distinct_from_decimal() {
        // The latent-bug guard: a0=010 is octal 8, NOT decimal 10.
        let a = ft(AuditField::A0);
        assert_ne!(
            canonical_value(a, "010", OFF),
            canonical_value(a, "10", OFF)
        );
        assert_eq!(canonical_value(a, "010", OFF), canonical_value(a, "8", OFF));
    }

    #[test]
    fn ambiguous_numeric_stays_opaque_conservative() {
        // We do NOT replicate strtoul's parse-prefix-then-stop; anything that is
        // not a clean base-0 number stays Opaque (#229; never a false fold). The
        // leading-'+' cases pin the digit guard specifically: `from_str_radix`
        // and `u64::parse` both accept a leading '+', so without the all-digit
        // guard `0x+1`/`+1`/`0+1` would parse (and falsely fold with `1`).
        let a = ft(AuditField::A0);
        for s in [
            "08", "0x", "0xZZ", "12x", "", " ", "+1", "0x+1", "0+1", "0X+f",
        ] {
            assert_eq!(classify(a, s), FieldValue::Opaque, "{s:?} must be opaque");
        }
    }

    // --- canonical_value: msgtype name<->number folding (#227) ----------

    #[test]
    fn msgtype_anchor_names_fold_to_numbers() {
        let m = ft(AuditField::MsgType);
        // Anchors spanning every msg_typetab.h block @ 3bfa048, with numbers from
        // audit-records.h @ 3bfa048 / linux/audit.h. A transcription slip on any
        // anchor fails here.
        for (name, num) in [
            ("USER", "1005"),
            ("LOGIN", "1006"),
            ("USER_AUTH", "1100"),
            ("USER_END", "1106"),
            ("SOFTWARE_UPDATE", "1138"),
            ("DAEMON_START", "1200"),
            ("DAEMON_ERR", "1209"),
            ("SYSCALL", "1300"),
            ("PATH", "1302"),
            ("CONFIG_CHANGE", "1305"),
            ("CWD", "1307"),
            ("EXECVE", "1309"),
            ("EOE", "1320"),
            ("PROCTITLE", "1327"),
            ("DM_EVENT", "1339"),
            ("AVC", "1400"),
            ("MAC_CALIPSO_DEL", "1419"),
            ("ANOM_PROMISCUOUS", "1700"),
            ("ANOM_CREAT", "1703"),
            ("INTEGRITY_DATA", "1800"),
            ("INTEGRITY_POLICY_RULE", "1807"),
            ("KERNEL", "2000"),
            ("ANOM_LOGIN_FAILURES", "2100"),
            ("ANOM_SESSION", "2121"),
            ("RESP_ANOMALY", "2200"),
            ("RESP_ORIGIN_UNBLOCK_TIMED", "2215"),
            ("USER_ROLE_CHANGE", "2300"),
            ("USER_MAC_STATUS", "2313"),
            ("CRYPTO_TEST_USER", "2400"),
            ("CRYPTO_IPSEC_SA", "2409"),
            ("VIRT_CONTROL", "2500"),
            ("VIRT_MIGRATE_OUT", "2507"),
        ] {
            assert_eq!(
                canonical_value(m, name, OFF),
                num,
                "msgtype {name} -> {num}"
            );
        }
    }

    #[test]
    fn msgtype_name_folding_is_case_insensitive() {
        let m = ft(AuditField::MsgType);
        assert_eq!(canonical_value(m, "syscall", OFF), "1300");
        assert_eq!(canonical_value(m, "SysCall", OFF), "1300");
        assert_eq!(canonical_value(m, "SYSCALL", OFF), "1300");
    }

    #[test]
    fn msgtype_number_and_name_fold_to_same_canonical() {
        let m = ft(AuditField::MsgType);
        assert_eq!(
            canonical_value(m, "1300", OFF),
            canonical_value(m, "SYSCALL", OFF)
        );
        // A base-0 number spelling folds too (#229): 0x514 == 1300.
        assert_eq!(canonical_value(m, "0x514", OFF), "1300");
    }

    #[test]
    fn msgtype_unknown_stays_opaque() {
        let m = ft(AuditField::MsgType);
        assert_eq!(canonical_value(m, "NOT_A_TYPE", OFF), "NOT_A_TYPE");
        // A number with no name folds only with itself (decimal-normalized).
        assert_eq!(canonical_value(m, "99999", OFF), "99999");
        assert_ne!(
            canonical_value(m, "99999", OFF),
            canonical_value(m, "SYSCALL", OFF)
        );
        // A hex value with no clean parse keeps its spelling.
        assert_eq!(canonical_value(m, "0xZZ", OFF), "0xZZ");
    }

    #[test]
    fn msgtype_table_has_expected_entry_count() {
        // The count of uncommented, non-APPARMOR _S entries in msg_typetab.h
        // @ 3bfa048. Guards against an accidental add/drop during transcription.
        assert_eq!(super::MSGTYPE_NAMES.len(), 189);
    }

    #[test]
    fn msgtype_table_names_are_unique_and_well_formed() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for (name, _) in super::MSGTYPE_NAMES {
            assert!(seen.insert(*name), "duplicate msgtype name {name}");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "unexpected msgtype name spelling {name}"
            );
        }
    }

    #[test]
    fn msgtype_classify_stays_opaque_no_intervals() {
        // #227 folds only in canonical_value; classify(MsgType) stays Opaque so
        // msgtype never enters interval reasoning (au-W03 stays conservative).
        assert_eq!(
            classify(ft(AuditField::MsgType), "SYSCALL"),
            FieldValue::Opaque
        );
        assert_eq!(
            classify(ft(AuditField::MsgType), "1300"),
            FieldValue::Opaque
        );
    }

    #[test]
    fn implies_msgtype_name_number_fold_227() {
        // au-W02 I0 path: same op, folded-equal value across name<->number.
        let name = ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL");
        let num = ff(AuditField::MsgType, CompareOp::Eq, "1300");
        assert!(implies(&name, &num, OFF));
        assert!(implies(&num, &name, OFF));
    }

    // --- implies: au-W02 subsumption (#219) -----------------------------
    // implies(pe, pl, OFF): does later pl imply earlier pe (pl's set subset of pe's)?

    #[test]
    fn implies_exact_same_predicate() {
        let pe = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let pl = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(implies(&pe, &pl, OFF));
    }

    #[test]
    fn implies_folds_sentinel_in_exact_case() {
        // auid!=-1 and auid!=4294967295: same op, folded-equal value.
        let pe = ff(AuditField::Auid, CompareOp::Ne, "-1");
        let pl = ff(AuditField::Auid, CompareOp::Ne, "4294967295");
        assert!(implies(&pe, &pl, OFF));
        assert!(implies(&pl, &pe, OFF));
    }

    #[test]
    fn implies_lower_bound_broader_subsumes_narrower() {
        // auid>=1000 (earlier, broad) is implied by auid>=2000 (later, narrow).
        let pe = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let pl = ff(AuditField::Auid, CompareOp::Ge, "2000");
        assert!(implies(&pe, &pl, OFF), "auid>=1000 must subsume auid>=2000");
        // and not the reverse.
        assert!(
            !implies(&pl, &pe, OFF),
            "auid>=2000 must NOT subsume auid>=1000"
        );
    }

    #[test]
    fn implies_gt_ge_boundary() {
        let gt1000 = ff(AuditField::Auid, CompareOp::Gt, "1000");
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let gt1000b = ff(AuditField::Auid, CompareOp::Gt, "1000");
        // >1000 implied by >=2000 (2000 > 1000)
        assert!(implies(&gt1000, &ge2000, OFF));
        // >=1000 implied by >1000  (>1000 == >=1001, subset of >=1000)
        assert!(implies(&ge1000, &gt1000b, OFF));
        // >1000 NOT implied by >=1000 (1000 satisfies pl but not pe)
        assert!(!implies(&gt1000, &ge1000, OFF));
    }

    #[test]
    fn implies_upper_bound_direction() {
        let le2000 = ff(AuditField::Uid, CompareOp::Le, "2000");
        let le1000 = ff(AuditField::Uid, CompareOp::Le, "1000");
        let lt2000 = ff(AuditField::Uid, CompareOp::Lt, "2000");
        assert!(
            implies(&le2000, &le1000, OFF),
            "uid<=2000 subsumes uid<=1000"
        );
        assert!(
            !implies(&le1000, &lt2000, OFF),
            "uid<=1000 does NOT subsume uid<2000"
        );
    }

    #[test]
    fn implies_opposite_direction_never() {
        let ge = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let le = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(!implies(&ge, &le, OFF));
        assert!(!implies(&le, &ge, OFF));
    }

    #[test]
    fn implies_signed_exit() {
        let ge_m13 = ff(AuditField::Exit, CompareOp::Ge, "-13");
        let ge_m5 = ff(AuditField::Exit, CompareOp::Ge, "-5");
        let ge_m20 = ff(AuditField::Exit, CompareOp::Ge, "-20");
        assert!(implies(&ge_m13, &ge_m5, OFF), "exit>=-13 subsumes exit>=-5");
        assert!(
            !implies(&ge_m13, &ge_m20, OFF),
            "exit>=-13 does NOT subsume exit>=-20"
        );
    }

    #[test]
    fn implies_eq_point_inside_relational_i2() {
        // I2: a later Eq whose point lies inside the earlier relational range.
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        let eq500 = ff(AuditField::Auid, CompareOp::Eq, "500");
        assert!(
            implies(&ge1000, &eq1500, OFF),
            "auid>=1000 subsumes auid=1500"
        );
        assert!(
            !implies(&ge1000, &eq500, OFF),
            "auid>=1000 does NOT subsume auid=500"
        );
        let le1000 = ff(AuditField::Auid, CompareOp::Le, "1000");
        let eq500b = ff(AuditField::Auid, CompareOp::Eq, "500");
        assert!(
            implies(&le1000, &eq500b, OFF),
            "auid<=1000 subsumes auid=500"
        );
    }

    #[test]
    fn implies_relational_does_not_imply_eq() {
        // The reverse of I2: a relational later does NOT imply an Eq earlier.
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!implies(&eq1500, &ge1000, OFF));
    }

    #[test]
    fn implies_ne_and_bitmask_only_exact() {
        // Ne never participates in interval implication.
        let ne5 = ff(AuditField::Auid, CompareOp::Ne, "5");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!implies(&ne5, &ge1000, OFF));
        assert!(!implies(&ge1000, &ne5, OFF));
        let ne5b = ff(AuditField::Auid, CompareOp::Ne, "5");
        assert!(implies(&ne5, &ne5b, OFF), "exact Ne==Ne implies");
        // bitmask: exact only.
        let band4 = ff(AuditField::A0, CompareOp::BitAnd, "4");
        let band4b = ff(AuditField::A0, CompareOp::BitAnd, "4");
        let band6 = ff(AuditField::A0, CompareOp::BitAnd, "6");
        assert!(implies(&band4, &band4b, OFF));
        assert!(!implies(&band4, &band6, OFF));
    }

    #[test]
    fn implies_sentinel_in_relational_is_conservative() {
        // auid>=0 (concrete 0) vs auid>=4294967295 (sentinel): no interval math
        // on the sentinel -> conservative false.
        let ge0 = ff(AuditField::Auid, CompareOp::Ge, "0");
        let ge_sentinel = ff(AuditField::Auid, CompareOp::Ge, "4294967295");
        assert!(!implies(&ge0, &ge_sentinel, OFF));
        assert!(!implies(&ge_sentinel, &ge0, OFF));
        // but >=-1 and >=4294967295 are the SAME predicate (folded) -> implies.
        let ge_m1 = ff(AuditField::Auid, CompareOp::Ge, "-1");
        assert!(implies(&ge_m1, &ge_sentinel, OFF));
    }

    #[test]
    fn implies_requires_same_field_and_numeric_type() {
        // Different fields never imply.
        let a = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let b = ff(AuditField::Uid, CompareOp::Ge, "2000");
        assert!(!implies(&a, &b, OFF));
        // String field with relational op: opaque, never interval.
        let pa = ff(AuditField::Path, CompareOp::Ge, "/a");
        let pb = ff(AuditField::Path, CompareOp::Ge, "/b");
        assert!(!implies(&pa, &pb, OFF));
        // generic Numeric (pid) intervals work too.
        let p1 = ff(AuditField::Pid, CompareOp::Ge, "1000");
        let p2 = ff(AuditField::Pid, CompareOp::Ge, "2000");
        assert!(implies(&p1, &p2, OFF));
    }

    // --- disjoint: au-W03 suppression (#219) ----------------------------

    #[test]
    fn disjoint_eq_eq_different_values() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "0");
        let b = ff(AuditField::Auid, CompareOp::Eq, "1000");
        assert!(disjoint(&a, &b, OFF));
    }

    #[test]
    fn disjoint_eq_eq_folded_sentinel_is_not_disjoint() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "-1");
        let b = ff(AuditField::Auid, CompareOp::Eq, "4294967295");
        assert!(
            !disjoint(&a, &b, OFF),
            "auid=-1 and auid=4294967295 are the same value"
        );
    }

    #[test]
    fn disjoint_eq_eq_string_fields() {
        // A single event has one path; path=/a and path=/b cannot co-match.
        let a = ff(AuditField::Path, CompareOp::Eq, "/a");
        let b = ff(AuditField::Path, CompareOp::Eq, "/b");
        assert!(disjoint(&a, &b, OFF));
        let c = ff(AuditField::Path, CompareOp::Eq, "/a");
        assert!(!disjoint(&a, &c, OFF));
    }

    #[test]
    fn disjoint_opposite_relational_non_meeting() {
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let lt1000 = ff(AuditField::Auid, CompareOp::Lt, "1000");
        assert!(
            disjoint(&ge2000, &lt1000, OFF),
            ">=2000 and <1000 cannot co-match"
        );
        // touching at the boundary is NOT disjoint.
        let ge2000b = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let le2000 = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(
            !disjoint(&ge2000b, &le2000, OFF),
            ">=2000 and <=2000 meet at 2000"
        );
        // overlapping ranges are not disjoint.
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let lt2000 = ff(AuditField::Auid, CompareOp::Lt, "2000");
        assert!(!disjoint(&ge1000, &lt2000, OFF));
    }

    #[test]
    fn disjoint_eq_outside_relational() {
        let eq0 = ff(AuditField::Auid, CompareOp::Eq, "0");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(disjoint(&eq0, &ge1000, OFF), "auid=0 is outside auid>=1000");
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        assert!(
            !disjoint(&eq1500, &ge1000, OFF),
            "auid=1500 is inside auid>=1000"
        );
    }

    #[test]
    fn disjoint_same_direction_is_not_disjoint() {
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        assert!(!disjoint(&ge1000, &ge2000, OFF));
    }

    #[test]
    fn disjoint_conservative_on_sentinel_and_relational() {
        // A sentinel Eq vs a relational cannot be proven disjoint -> overlap (the
        // sentinel has no interval position).
        let eq_unset = ff(AuditField::Auid, CompareOp::Eq, "unset");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!disjoint(&eq_unset, &ge1000, OFF));
    }

    #[test]
    fn disjoint_requires_same_field() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "0");
        let b = ff(AuditField::Uid, CompareOp::Eq, "1000");
        assert!(
            !disjoint(&a, &b, OFF),
            "different fields are independent, not disjoint"
        );
    }

    #[test]
    fn disjoint_signed_exit_ranges() {
        let ge0 = ff(AuditField::Exit, CompareOp::Ge, "0");
        let lt_m5 = ff(AuditField::Exit, CompareOp::Lt, "-5");
        assert!(
            disjoint(&ge0, &lt_m5, OFF),
            "exit>=0 and exit<-5 cannot co-match"
        );
    }

    #[test]
    fn disjoint_touching_boundary_is_not_disjoint() {
        // >=2000 and <=2000 share exactly the value 2000 -> NOT disjoint. Pins
        // the strict `<` (not `<=`) in the overlap check, both operand orders.
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let le2000 = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(
            !disjoint(&ge2000, &le2000, OFF),
            ">=2000 and <=2000 meet at 2000"
        );
        assert!(!disjoint(&le2000, &ge2000, OFF), "symmetric: meet at 2000");
    }

    #[test]
    fn disjoint_tight_lt_boundary() {
        // >=1000 and <1000 are adjacent with NO shared value -> disjoint. The
        // tight seam pins the `c - 1` upper bound of `<` (a wrong offset would
        // include 1000 in `<1000` and make the pair wrongly overlap).
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let lt1000 = ff(AuditField::Auid, CompareOp::Lt, "1000");
        assert!(
            disjoint(&ge1000, &lt1000, OFF),
            ">=1000 and <1000 are disjoint at the 999/1000 seam"
        );
        // The overlapping neighbor <=1000 shares 1000, so NOT disjoint.
        let le1000 = ff(AuditField::Auid, CompareOp::Le, "1000");
        assert!(
            !disjoint(&ge1000, &le1000, OFF),
            ">=1000 and <=1000 share 1000"
        );
    }

    #[test]
    fn disjoint_alias_bearing_eq_pairs_are_not_disjoint() {
        // Different spellings of the SAME kernel value on alias-bearing fields
        // must NOT be called disjoint, or au-W03 drops a real suppression warning.
        // msgtype=SYSCALL == 1300 (the codebase relies on this at ordering.rs).
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1300"),
            OFF,
        ));
        // uid=root resolves to uid 0; a static linter has no passwd db to disprove it.
        assert!(!disjoint(
            &ff(AuditField::Uid, CompareOp::Eq, "root"),
            &ff(AuditField::Uid, CompareOp::Eq, "0"),
            OFF,
        ));
        // arch=b64 selects the same syscall table as x86_64 on an x86 host.
        assert!(!disjoint(
            &ff(AuditField::Arch, CompareOp::Eq, "b64"),
            &ff(AuditField::Arch, CompareOp::Eq, "x86_64"),
            OFF,
        ));
    }

    // --- eq_values_provably_equal: direct (#228) ------------------------

    #[test]
    fn eq_values_provably_equal_cases() {
        let auid = ft(AuditField::Auid);
        assert!(eq_values_provably_equal(auid, "5", "5", OFF));
        assert!(eq_values_provably_equal(auid, "-1", "4294967295", OFF)); // folded sentinel
        assert!(!eq_values_provably_equal(auid, "5", "6", OFF));
        // free-form string: exact match.
        assert!(eq_values_provably_equal(
            ft(AuditField::Key),
            "foo",
            "foo",
            OFF
        ));
        assert!(!eq_values_provably_equal(
            ft(AuditField::Path),
            "/a",
            "/b",
            OFF
        ));
        // alias-bearing / unresolvable -> conservative false (even if equal).
        assert!(!eq_values_provably_equal(auid, "root", "root", OFF));
        assert!(!eq_values_provably_equal(
            ft(AuditField::Arch),
            "b64",
            "b64",
            OFF,
        ));
    }

    // --- disjoint: sound bitmask/Ne cases (#228) ------------------------

    #[test]
    fn disjoint_eq_ne_same_value_is_disjoint() {
        // `auid=5` and `auid!=5` are a contradiction; both operand orders.
        let eq5 = ff(AuditField::Auid, CompareOp::Eq, "5");
        let ne5 = ff(AuditField::Auid, CompareOp::Ne, "5");
        assert!(
            disjoint(&eq5, &ne5, OFF),
            "auid=5 and auid!=5 cannot co-match"
        );
        assert!(disjoint(&ne5, &eq5, OFF), "symmetric");
        // folded spellings of the same value count as same (#220/#229).
        let eq_unset = ff(AuditField::Auid, CompareOp::Eq, "unset");
        let ne_m1 = ff(AuditField::Auid, CompareOp::Ne, "-1");
        assert!(
            disjoint(&eq_unset, &ne_m1, OFF),
            "auid=unset and auid!=-1 contradict"
        );
    }

    #[test]
    fn disjoint_eq_ne_different_value_not_disjoint() {
        // `auid=5` and `auid!=6`: the value 5 satisfies both -> overlap.
        let eq5 = ff(AuditField::Auid, CompareOp::Eq, "5");
        let ne6 = ff(AuditField::Auid, CompareOp::Ne, "6");
        assert!(!disjoint(&eq5, &ne6, OFF));
        assert!(!disjoint(&ne6, &eq5, OFF));
    }

    #[test]
    fn disjoint_eq_ne_freeform_string() {
        // Free-form string fields prove same/different by exact spelling.
        let key_eq = ff(AuditField::Key, CompareOp::Eq, "foo");
        let key_ne = ff(AuditField::Key, CompareOp::Ne, "foo");
        assert!(
            disjoint(&key_eq, &key_ne, OFF),
            "key=foo and key!=foo contradict"
        );
        let path_eq = ff(AuditField::Path, CompareOp::Eq, "/a");
        let path_ne = ff(AuditField::Path, CompareOp::Ne, "/b");
        assert!(
            !disjoint(&path_eq, &path_ne, OFF),
            "path=/a satisfies path!=/b"
        );
    }

    #[test]
    fn disjoint_eq_ne_alias_bearing_stays_conservative() {
        // Alias-bearing fields where the linter cannot resolve a name to a value
        // stay conservative (not disjoint), so au-W03 keeps the warning.
        assert!(!disjoint(
            &ff(AuditField::Uid, CompareOp::Eq, "root"),
            &ff(AuditField::Uid, CompareOp::Ne, "0"),
            OFF,
        ));
        assert!(!disjoint(
            &ff(AuditField::Arch, CompareOp::Eq, "b64"),
            &ff(AuditField::Arch, CompareOp::Ne, "x86_64"),
            OFF,
        ));
    }

    #[test]
    fn disjoint_eq_bitand_no_common_bits() {
        // `a0=4` and `a0&2`: 4 & 2 == 0, so the value 4 never matches the mask.
        let eq4 = ff(AuditField::A0, CompareOp::Eq, "4");
        let band2 = ff(AuditField::A0, CompareOp::BitAnd, "2");
        assert!(disjoint(&eq4, &band2, OFF), "4 & 2 == 0 -> disjoint");
        assert!(disjoint(&band2, &eq4, OFF), "symmetric");
    }

    #[test]
    fn disjoint_eq_bitand_shared_bit_not_disjoint() {
        // `a0=6` and `a0&2`: 6 & 2 == 2 != 0, so 6 matches the mask -> overlap.
        let eq6 = ff(AuditField::A0, CompareOp::Eq, "6");
        let band2 = ff(AuditField::A0, CompareOp::BitAnd, "2");
        assert!(!disjoint(&eq6, &band2, OFF));
    }

    #[test]
    fn disjoint_eq_bitand_hex_mask() {
        // The mask is usually hex; commit-1 base-0 parsing makes it concrete.
        let eq4 = ff(AuditField::A0, CompareOp::Eq, "4");
        let band_hex2 = ff(AuditField::A0, CompareOp::BitAnd, "0x2");
        assert!(disjoint(&eq4, &band_hex2, OFF), "4 & 0x2 == 0 -> disjoint");
    }

    #[test]
    fn disjoint_eq_bitandeq_missing_bits() {
        // `a0=4` and `a0&=2`: 4 & 2 == 0 != 2, so 4 lacks the required bits.
        let eq4 = ff(AuditField::A0, CompareOp::Eq, "4");
        let bandeq2 = ff(AuditField::A0, CompareOp::BitAndEq, "2");
        assert!(disjoint(&eq4, &bandeq2, OFF), "(4 & 2) != 2 -> disjoint");
        assert!(disjoint(&bandeq2, &eq4, OFF), "symmetric");
    }

    #[test]
    fn disjoint_eq_bitandeq_all_bits_present_not_disjoint() {
        // `a0=6` and `a0&=2`: 6 & 2 == 2 == mask, so 6 satisfies the bit test.
        let eq6 = ff(AuditField::A0, CompareOp::Eq, "6");
        let bandeq2 = ff(AuditField::A0, CompareOp::BitAndEq, "2");
        assert!(!disjoint(&eq6, &bandeq2, OFF));
    }

    #[test]
    fn disjoint_eq_bitandeq_exact_not_disjoint() {
        // `a0=2` and `a0&=2`: 2 & 2 == 2 -> the exact value passes the bit test.
        let eq2 = ff(AuditField::A0, CompareOp::Eq, "2");
        let bandeq2 = ff(AuditField::A0, CompareOp::BitAndEq, "2");
        assert!(!disjoint(&eq2, &bandeq2, OFF));
    }

    #[test]
    fn disjoint_bitmask_vs_bitmask_never_disjoint() {
        // Theorem: two bitmask predicates are always co-satisfiable (by m1|m2),
        // so they are never provably disjoint (conservative -> overlap).
        let bandeq1 = ff(AuditField::A0, CompareOp::BitAndEq, "1");
        let bandeq2 = ff(AuditField::A0, CompareOp::BitAndEq, "2");
        assert!(!disjoint(&bandeq1, &bandeq2, OFF), "co-satisfied by 3");
        let band1 = ff(AuditField::A0, CompareOp::BitAnd, "1");
        let bandeq2b = ff(AuditField::A0, CompareOp::BitAndEq, "2");
        assert!(!disjoint(&band1, &bandeq2b, OFF));
    }

    #[test]
    fn disjoint_ne_vs_ne_never_disjoint() {
        // Theorem: two not-equals exclude only one point each -> always intersect.
        let ne5 = ff(AuditField::Auid, CompareOp::Ne, "5");
        let ne6 = ff(AuditField::Auid, CompareOp::Ne, "6");
        assert!(!disjoint(&ne5, &ne6, OFF));
    }

    #[test]
    fn disjoint_freeform_string_eq_pairs_are_disjoint() {
        // Free-form string fields (String / StringEqNe / Key) are exact kernel
        // matches with no symbolic aliases, so different spellings ARE provably
        // different. Pins each variant in the free-form set.
        assert!(disjoint(
            &ff(AuditField::Path, CompareOp::Eq, "/a"),
            &ff(AuditField::Path, CompareOp::Eq, "/b"),
            OFF,
        ));
        assert!(disjoint(
            &ff(AuditField::Exe, CompareOp::Eq, "/bin/sh"),
            &ff(AuditField::Exe, CompareOp::Eq, "/bin/bash"),
            OFF,
        ));
        assert!(disjoint(
            &ff(AuditField::Key, CompareOp::Eq, "a"),
            &ff(AuditField::Key, CompareOp::Eq, "b"),
            OFF,
        ));
    }

    // --- AppArmor msgtype opt-in folding (#230) ----------------------------
    //
    // Ground truth: audit-userspace lib/msg_typetab.h @ 3bfa048.
    // AUDIT_AA is the C macro; the string is "APPARMOR" (not "AA").
    // Numbers 1500-1507 are the AppArmor range.

    #[test]
    fn t1_apparmor_name_folds_to_number_with_on() {
        // Each AppArmor symbolic name canonicalizes to its number when ON.
        let mt = ft(AuditField::MsgType);
        assert_eq!(canonical_value(mt, "APPARMOR", ON), "1500");
        assert_eq!(canonical_value(mt, "APPARMOR_AUDIT", ON), "1501");
        assert_eq!(canonical_value(mt, "APPARMOR_ALLOWED", ON), "1502");
        assert_eq!(canonical_value(mt, "APPARMOR_DENIED", ON), "1503");
        assert_eq!(canonical_value(mt, "APPARMOR_HINT", ON), "1504");
        assert_eq!(canonical_value(mt, "APPARMOR_STATUS", ON), "1505");
        assert_eq!(canonical_value(mt, "APPARMOR_ERROR", ON), "1506");
        assert_eq!(canonical_value(mt, "APPARMOR_KILL", ON), "1507");
    }

    #[test]
    fn t2_apparmor_name_unchanged_with_off() {
        // Without --apparmor the symbolic names are NOT in the fold table; they
        // pass through unchanged (the daemon on RHEL does not know these names).
        let mt = ft(AuditField::MsgType);
        assert_eq!(canonical_value(mt, "APPARMOR", OFF), "APPARMOR");
        assert_eq!(
            canonical_value(mt, "APPARMOR_DENIED", OFF),
            "APPARMOR_DENIED"
        );
    }

    #[test]
    fn t3_msgtype_number_none_for_apparmor_with_off() {
        assert_eq!(msgtype_number("APPARMOR", OFF), None);
        assert_eq!(msgtype_number("APPARMOR_DENIED", OFF), None);
        assert_eq!(msgtype_number("APPARMOR_KILL", OFF), None);
    }

    #[test]
    fn t4_msgtype_number_some_for_apparmor_with_on() {
        assert_eq!(msgtype_number("APPARMOR", ON), Some(1500));
        assert_eq!(msgtype_number("APPARMOR_AUDIT", ON), Some(1501));
        assert_eq!(msgtype_number("APPARMOR_ALLOWED", ON), Some(1502));
        assert_eq!(msgtype_number("APPARMOR_DENIED", ON), Some(1503));
        assert_eq!(msgtype_number("APPARMOR_HINT", ON), Some(1504));
        assert_eq!(msgtype_number("APPARMOR_STATUS", ON), Some(1505));
        assert_eq!(msgtype_number("APPARMOR_ERROR", ON), Some(1506));
        assert_eq!(msgtype_number("APPARMOR_KILL", ON), Some(1507));
    }

    #[test]
    fn t5_apparmor_number_and_name_fold_together_with_on() {
        // With ON: msgtype=APPARMOR and msgtype=1500 are the same canonical value.
        let mt = ft(AuditField::MsgType);
        assert_eq!(
            canonical_value(mt, "APPARMOR", ON),
            canonical_value(mt, "1500", ON),
            "APPARMOR == 1500 when ON"
        );
        assert_eq!(
            canonical_value(mt, "APPARMOR_DENIED", ON),
            canonical_value(mt, "1503", ON),
            "APPARMOR_DENIED == 1503 when ON"
        );
    }

    #[test]
    fn t6_default_opts_is_apparmor_off() {
        // LintOptions::default() must restore pre-#230 behaviour exactly:
        // AppArmor names are NOT folded.
        let mt = ft(AuditField::MsgType);
        let default_opts = LintOptions::default();
        assert!(!default_opts.include_apparmor);
        assert_eq!(
            canonical_value(mt, "APPARMOR_DENIED", default_opts),
            "APPARMOR_DENIED",
            "default opts must not fold AppArmor names"
        );
        // The 189-entry baseline table is unaffected.
        assert_eq!(canonical_value(mt, "SYSCALL", default_opts), "1300");
    }

    #[test]
    fn t7_implies_apparmor_name_vs_number_with_on() {
        // implies(pe, pl, ON): msgtype=1503 (earlier, number) implies
        // msgtype=APPARMOR_DENIED (later, name) -- same canonical value.
        // Used by au-W02 subsumption when --apparmor is active.
        let pe = ff(AuditField::MsgType, CompareOp::Eq, "1503");
        let pl = ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED");
        assert!(
            implies(&pe, &pl, ON),
            "1503 == APPARMOR_DENIED with ON -> implies"
        );
        assert!(
            implies(&pl, &pe, ON),
            "symmetric: APPARMOR_DENIED == 1503 with ON"
        );
        // With OFF: not the same canonical value.
        assert!(!implies(&pe, &pl, OFF), "1503 != APPARMOR_DENIED with OFF");
    }

    #[test]
    fn t10_lint_options_default_and_off_eq() {
        assert_eq!(
            LintOptions::default(),
            OFF,
            "LintOptions::default() must equal the OFF constant"
        );
    }

    #[test]
    fn t11_apparmor_name_folding_is_case_insensitive() {
        // libaudit folds msgtype names case-insensitively; the apparmor branch
        // must use the SAME eq_ignore_ascii_case as the base table. A mutant that
        // changes the apparmor branch to `==` survives without this test.
        let mt = ft(AuditField::MsgType);
        assert_eq!(canonical_value(mt, "apparmor_denied", ON), "1503");
        assert_eq!(canonical_value(mt, "ApParMor_Denied", ON), "1503");
        assert_eq!(msgtype_number("apparmor_kill", ON), Some(1507));
    }

    #[test]
    fn t12_apparmor_table_has_expected_entry_count() {
        // The `#ifdef WITH_APPARMOR` block of msg_typetab.h @ 3bfa048 has exactly
        // 8 `_S` entries (APPARMOR + APPARMOR_{AUDIT,ALLOWED,DENIED,HINT,STATUS,
        // ERROR,KILL}, 1500-1507). Guards against an accidental add/drop.
        assert_eq!(super::APPARMOR_MSGTYPE_NAMES.len(), 8);
    }

    #[test]
    fn t13_apparmor_names_disjoint_from_base_and_well_formed() {
        use std::collections::HashSet;
        let base_names: HashSet<&str> = super::MSGTYPE_NAMES.iter().map(|&(n, _)| n).collect();
        let base_nums: HashSet<u32> = super::MSGTYPE_NAMES.iter().map(|&(_, n)| n).collect();
        let mut seen = HashSet::new();
        for (name, num) in super::APPARMOR_MSGTYPE_NAMES {
            assert!(seen.insert(*name), "duplicate apparmor name {name}");
            assert!(
                !base_names.contains(name),
                "apparmor name {name} must not also be in MSGTYPE_NAMES"
            );
            assert!(
                !base_nums.contains(num),
                "apparmor number {num} collides with a base MSGTYPE_NAMES number"
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "unexpected apparmor name spelling {name}"
            );
        }
    }

    #[test]
    fn t14_apparmor_does_not_change_w03_disjoint() {
        // msgtype is excluded from canonical_decides_value_identity, so apparmor
        // folding must NEVER perturb au-W03 disjointness. An apparmor-name vs
        // number msgtype Eq/Eq pair is conservatively NOT disjoint either way.
        let name = ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED");
        let num = ff(AuditField::MsgType, CompareOp::Eq, "1503");
        assert_eq!(
            disjoint(&name, &num, ON),
            disjoint(&name, &num, OFF),
            "apparmor opts must not perturb au-W03 disjoint() for msgtype"
        );
        assert!(
            !disjoint(&name, &num, ON),
            "msgtype Eq/Eq stays conservative (not decidable from spelling)"
        );
    }

    // --- disjoint: msgtype record-type-number folding (#475, class 1) ---
    //
    // Promotes msgtype Eq/Eq (and Eq/Ne) disjointness: two msgtype predicates
    // are provably disjoint/contradictory ONLY when BOTH sides independently
    // resolve to a concrete record-type NUMBER under the SAME `opts` (name
    // lookup via MSGTYPE_NAMES/APPARMOR_MSGTYPE_NAMES, or the base-0 numeric
    // fallback -- mirrors canonical_value's MsgType branch exactly) and those
    // numbers differ (or match, for the Eq/Ne contradiction direction).
    // Ground truth: kernel auditfilter.c:1205-1227 `audit_comparator` (a plain
    // u32 `==`/`!=` compare) and libaudit.c:1783-1797 `AUDIT_MSGTYPE` value
    // resolution, both @ audit-userspace/kernel 3bfa048/v6.6 (session 7c #475
    // P3 grounding doc). An unresolved side (an unknown name, or an AppArmor
    // name with `include_apparmor` off) MUST stay conservative.
    //
    // PRESERVED, NOT FLIPPED: `disjoint_alias_bearing_eq_pairs_are_not_disjoint`'s
    // msgtype case (above, SYSCALL==1300) and `t14_apparmor_does_not_change_w03_disjoint`
    // (above, APPARMOR_DENIED==1503) both test SAME-VALUE pairs under different
    // spellings; a sound promotion keeps both asserting `!disjoint(...)`
    // exactly as written. Flipping either would encode a false-positive au-W03
    // regression (claiming two spellings of the SAME record type are
    // "provably different", silently dropping a real suppression warning).

    #[test]
    fn msgtype_eq_eq_different_names_are_disjoint_475() {
        // SYSCALL=1300, LOGIN=1006 (msgtype.rs MSGTYPE_NAMES): both resolve,
        // genuinely different record types -> disjoint.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Eq, "LOGIN"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_eq_eq_name_vs_number_different_are_disjoint_475() {
        // SYSCALL=1300 vs the literal number 1309 (EXECVE): mixed resolution
        // paths (name lookup vs numeric fallback), genuinely different.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1309"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_eq_eq_number_vs_number_different_are_disjoint_475() {
        // Pure numeric spellings, no name lookup involved at all.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "1300"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1309"),
            OFF,
        ));
        // A base-0 spelling of the SAME number as one side (0x514 == 1300,
        // confirmed by msgtype_number_and_name_fold_to_same_canonical above)
        // must resolve identically through the numeric fallback.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "0x514"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1309"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_eq_ne_same_value_cross_spelling_is_disjoint_475() {
        // #475's design threads the new msgtype-resolution gate through
        // canonical_decides_value_identity, which is shared by
        // eq_values_provably_differ AND eq_values_provably_equal -- so the
        // Eq/Ne contradiction direction folds too. SYSCALL and 1300 are the
        // SAME record type under DIFFERENT spellings: `msgtype=SYSCALL` and
        // `msgtype!=1300` contradict (a SYSCALL event always fails `!=1300`).
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Ne, "1300"),
            OFF,
        ));
        // Same-spelling contradiction (extends #228's existing Eq/Ne pattern
        // to msgtype): `msgtype=SYSCALL` and `msgtype!=SYSCALL` contradict.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Ne, "SYSCALL"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_eq_ne_different_value_still_overlaps_475() {
        // Regression guard: `msgtype=SYSCALL` and `msgtype!=CONFIG_CHANGE`
        // (1300 vs 1305, different) do NOT contradict -- a SYSCALL event
        // satisfies `!=CONFIG_CHANGE` too, so the predicates overlap. Pins the
        // Eq/Ne direction against a mutant that inverts the newly-reachable
        // msgtype equality gate.
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Ne, "CONFIG_CHANGE"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_apparmor_on_different_numbers_are_disjoint_475() {
        // With include_apparmor ON, AppArmor names resolve too (1500-1507).
        // APPARMOR_DENIED=1503 vs APPARMOR=1500: different -> disjoint.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1500"),
            ON,
        ));
        // APPARMOR_DENIED=1503 vs APPARMOR_ALLOWED=1502: both names, different.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED"),
            &ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_ALLOWED"),
            ON,
        ));
        // Mixed base-table vs AppArmor: SYSCALL=1300 vs APPARMOR_DENIED=1503.
        assert!(disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED"),
            ON,
        ));
    }

    #[test]
    fn msgtype_apparmor_off_unresolved_name_stays_conservative_475() {
        // Same pair as the first assertion above, but OFF: APPARMOR_DENIED
        // does not resolve (the AppArmor table is opt-in), so even though
        // 1500 != 1503 IF resolved, the pair must stay conservative (not
        // disjoint) -- one side unresolved is enough to decline, regardless
        // of the other side's value (grounding doc section 4's per-case
        // table: "AppArmor NAME, include_apparmor=false: does NOT resolve ->
        // stays unfoldable -> conservative, never provably disjoint from
        // anything").
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "APPARMOR_DENIED"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1500"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_unknown_name_never_disjoint_either_opts_475() {
        // An unrecognized name never resolves, ON or OFF (it is in neither
        // MSGTYPE_NAMES nor APPARMOR_MSGTYPE_NAMES) -- must stay conservative
        // even against a known, different number.
        for opts in [OFF, ON] {
            assert!(!disjoint(
                &ff(AuditField::MsgType, CompareOp::Eq, "NOT_A_RECORD"),
                &ff(AuditField::MsgType, CompareOp::Eq, "1300"),
                opts,
            ));
        }
    }

    #[test]
    fn msgtype_relational_pairs_stay_conservative_475() {
        // Interval/relational reasoning for msgtype is explicitly OUT of scope
        // for #475 (a documented non-goal, not a soundness gap:
        // classify(MsgType) stays Opaque BY DESIGN per canonical.rs, so
        // msgtype never enters interval position -- see
        // msgtype_classify_stays_opaque_no_intervals above). Two disjoint-
        // looking relational ranges must NOT be claimed disjoint; this pins
        // the boundary so a future interval extension is a deliberate,
        // separately-tested change, not an accidental side effect of #475.
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Ge, "2000"),
            &ff(AuditField::MsgType, CompareOp::Le, "1500"),
            OFF,
        ));
    }

    #[test]
    fn msgtype_bitmask_pairs_stay_conservative_475() {
        // Bitmask ops reach disjoint() via eq_bitand_disjoint /
        // eq_bitandeq_disjoint (as_u64 -> classify(), still Opaque for
        // msgtype), a path #475 does not touch. Also matches reality: the
        // kernel rejects `&`/`&=` on AUDIT_MSGTYPE at rule-insert time
        // (auditfilter.c:366-393 @ v6.6), so no legally-loadable ruleset
        // could present this case either way.
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "1300"),
            &ff(AuditField::MsgType, CompareOp::BitAnd, "2"),
            OFF,
        ));
    }
}
