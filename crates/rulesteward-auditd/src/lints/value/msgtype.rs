//! The audit record-type `msgtype` name<->number table (#227) and lookup, plus
//! the opt-in `AppArmor` extension (#230). Split out of `value.rs` (#438); see
//! the parent `value` module doc for the overall design.

use rulesteward_core::parse_base0_u64 as parse_u64_base0;

use super::LintOptions;

/// The audit record-type `msgtype` name -> number table (#227), so au-W01 and
/// au-W02 fold `msgtype=SYSCALL` and `msgtype=1300` to one value.
///
/// Names are the UNCOMMENTED `_S(AUDIT_<NAME>, "<NAME>")` entries of
/// audit-userspace `lib/msg_typetab.h` @ commit 3bfa048 (the crate's pinned
/// citation commit); numbers are the `AUDIT_*` constants in `lib/audit-records.h`
/// @ 3bfa048 and the kernel `include/uapi/linux/audit.h`. The `#ifdef
/// WITH_APPARMOR` block (`APPARMOR_*`, 1500-1599) is EXCLUDED from this base
/// table and folded only OPT-IN: it is compiled into libaudit only on `AppArmor`
/// builds, so folding those names by DEFAULT would claim an equivalence a
/// non-`AppArmor` daemon does not make. #230 added them as the separate
/// [`APPARMOR_MSGTYPE_NAMES`] table, consulted only when the caller passes
/// `--apparmor` (see [`LintOptions`]). Commented-out `_S` entries
/// (deprecated/daemon-filtered commands such as
/// `GET`/`SET`/`LIST`/`ADD`/`DEL`/`DAEMON_RECONFIG`) are also excluded.
///
/// Lookup is case-insensitive (libaudit `audit_name_to_msg_type` -> `msg_type_s2i`
/// is generated `--uppercase`). The pinned length is asserted by
/// `msgtype_table_has_expected_entry_count`.
///
/// ## `AppArmor` folding (#230, implemented)
///
/// The `APPARMOR_*` names are folded additively (not a rewrite of this table).
/// The fold is reached through exactly two functions -- [`msgtype_number`] (the
/// name -> number lookup) and [`super::canonical_value`] (its only msgtype caller). #230
/// added the separate, identically-cited [`APPARMOR_MSGTYPE_NAMES`] const (the
/// `#ifdef WITH_APPARMOR` block, 1500-1507, from `msg_typetab.h` @ 3bfa048), and
/// [`msgtype_number`] consults it only when `opts.include_apparmor` is set.
///
/// [`super::canonical_value`] is called from `duplicate.rs` (au-W01), `ordering.rs`
/// (au-W02) and `normalize.rs` (`canonical_key`); the auditd lint entry
/// `lints::lint(rules, opts)` now threads a [`LintOptions`] value (not a bare
/// bool) from the `--apparmor` CLI flag down to [`super::canonical_value`], so this gate
/// and any later one share a single signature. The name<->number map is universal
/// kernel ABI; only WHEN to assert the `AppArmor` equivalence is a policy choice,
/// which is why the gate, not the table, was the real work.
///
/// `pub(super)`: consulted by `msgtype_number` below (same module -- would be
/// private were it not also read directly by `mod tests` in the parent
/// `value::mod` via a `#[cfg(test)]` import).
pub(super) const MSGTYPE_NAMES: &[(&str, u32)] = &[
    // 1000-1099 commanding the audit system (only the two non-deprecated names).
    ("USER", 1005),
    ("LOGIN", 1006),
    // 1100-1199 user space trusted application messages (audit-records.h).
    ("USER_AUTH", 1100),
    ("USER_ACCT", 1101),
    ("USER_MGMT", 1102),
    ("CRED_ACQ", 1103),
    ("CRED_DISP", 1104),
    ("USER_START", 1105),
    ("USER_END", 1106),
    ("USER_AVC", 1107),
    ("USER_CHAUTHTOK", 1108),
    ("USER_ERR", 1109),
    ("CRED_REFR", 1110),
    ("USYS_CONFIG", 1111),
    ("USER_LOGIN", 1112),
    ("USER_LOGOUT", 1113),
    ("ADD_USER", 1114),
    ("DEL_USER", 1115),
    ("ADD_GROUP", 1116),
    ("DEL_GROUP", 1117),
    ("DAC_CHECK", 1118),
    ("CHGRP_ID", 1119),
    ("TEST", 1120),
    ("TRUSTED_APP", 1121),
    ("USER_SELINUX_ERR", 1122),
    ("USER_CMD", 1123),
    ("USER_TTY", 1124),
    ("CHUSER_ID", 1125),
    ("GRP_AUTH", 1126),
    ("SYSTEM_BOOT", 1127),
    ("SYSTEM_SHUTDOWN", 1128),
    ("SYSTEM_RUNLEVEL", 1129),
    ("SERVICE_START", 1130),
    ("SERVICE_STOP", 1131),
    ("GRP_MGMT", 1132),
    ("GRP_CHAUTHTOK", 1133),
    ("MAC_CHECK", 1134),
    ("ACCT_LOCK", 1135),
    ("ACCT_UNLOCK", 1136),
    ("USER_DEVICE", 1137),
    ("SOFTWARE_UPDATE", 1138),
    // 1200-1299 daemon-internal (DAEMON_RECONFIG 1204 is commented out in the tab).
    ("DAEMON_START", 1200),
    ("DAEMON_END", 1201),
    ("DAEMON_ABORT", 1202),
    ("DAEMON_CONFIG", 1203),
    ("DAEMON_ROTATE", 1205),
    ("DAEMON_RESUME", 1206),
    ("DAEMON_ACCEPT", 1207),
    ("DAEMON_CLOSE", 1208),
    ("DAEMON_ERR", 1209),
    // 1300-1399 audit event messages (linux/audit.h; gaps 1301/1308/1310/1329
    // are deprecated/absent/not-in-tab).
    ("SYSCALL", 1300),
    ("PATH", 1302),
    ("IPC", 1303),
    ("SOCKETCALL", 1304),
    ("CONFIG_CHANGE", 1305),
    ("SOCKADDR", 1306),
    ("CWD", 1307),
    ("EXECVE", 1309),
    ("IPC_SET_PERM", 1311),
    ("MQ_OPEN", 1312),
    ("MQ_SENDRECV", 1313),
    ("MQ_NOTIFY", 1314),
    ("MQ_GETSETATTR", 1315),
    ("KERNEL_OTHER", 1316),
    ("FD_PAIR", 1317),
    ("OBJ_PID", 1318),
    ("TTY", 1319),
    ("EOE", 1320),
    ("BPRM_FCAPS", 1321),
    ("CAPSET", 1322),
    ("MMAP", 1323),
    ("NETFILTER_PKT", 1324),
    ("NETFILTER_CFG", 1325),
    ("SECCOMP", 1326),
    ("PROCTITLE", 1327),
    ("FEATURE_CHANGE", 1328),
    ("KERN_MODULE", 1330),
    ("FANOTIFY", 1331),
    ("TIME_INJOFFSET", 1332),
    ("TIME_ADJNTPVAL", 1333),
    ("BPF", 1334),
    ("EVENT_LISTENER", 1335),
    ("URINGOP", 1336),
    ("OPENAT2", 1337),
    ("DM_CTRL", 1338),
    ("DM_EVENT", 1339),
    // 1400-1499 kernel SELinux use.
    ("AVC", 1400),
    ("SELINUX_ERR", 1401),
    ("AVC_PATH", 1402),
    ("MAC_POLICY_LOAD", 1403),
    ("MAC_STATUS", 1404),
    ("MAC_CONFIG_CHANGE", 1405),
    ("MAC_UNLBL_ALLOW", 1406),
    ("MAC_CIPSOV4_ADD", 1407),
    ("MAC_CIPSOV4_DEL", 1408),
    ("MAC_MAP_ADD", 1409),
    ("MAC_MAP_DEL", 1410),
    ("MAC_IPSEC_ADDSA", 1411),
    ("MAC_IPSEC_DELSA", 1412),
    ("MAC_IPSEC_ADDSPD", 1413),
    ("MAC_IPSEC_DELSPD", 1414),
    ("MAC_IPSEC_EVENT", 1415),
    ("MAC_UNLBL_STCADD", 1416),
    ("MAC_UNLBL_STCDEL", 1417),
    ("MAC_CALIPSO_ADD", 1418),
    ("MAC_CALIPSO_DEL", 1419),
    // 1700-1799 kernel anomaly records.
    ("ANOM_PROMISCUOUS", 1700),
    ("ANOM_ABEND", 1701),
    ("ANOM_LINK", 1702),
    ("ANOM_CREAT", 1703),
    // 1800-1899 kernel integrity labels.
    ("INTEGRITY_DATA", 1800),
    ("INTEGRITY_METADATA", 1801),
    ("INTEGRITY_STATUS", 1802),
    ("INTEGRITY_HASH", 1803),
    ("INTEGRITY_PCR", 1804),
    ("INTEGRITY_RULE", 1805),
    ("INTEGRITY_EVM_XATTR", 1806),
    ("INTEGRITY_POLICY_RULE", 1807),
    // 2000 unclassified kernel audit (the lone post-APPARMOR-block tab entry).
    ("KERNEL", 2000),
    // 2100-2199 user space anomaly records.
    ("ANOM_LOGIN_FAILURES", 2100),
    ("ANOM_LOGIN_TIME", 2101),
    ("ANOM_LOGIN_SESSIONS", 2102),
    ("ANOM_LOGIN_ACCT", 2103),
    ("ANOM_LOGIN_LOCATION", 2104),
    ("ANOM_MAX_DAC", 2105),
    ("ANOM_MAX_MAC", 2106),
    ("ANOM_AMTU_FAIL", 2107),
    ("ANOM_RBAC_FAIL", 2108),
    ("ANOM_RBAC_INTEGRITY_FAIL", 2109),
    ("ANOM_CRYPTO_FAIL", 2110),
    ("ANOM_ACCESS_FS", 2111),
    ("ANOM_EXEC", 2112),
    ("ANOM_MK_EXEC", 2113),
    ("ANOM_ADD_ACCT", 2114),
    ("ANOM_DEL_ACCT", 2115),
    ("ANOM_MOD_ACCT", 2116),
    ("ANOM_ROOT_TRANS", 2117),
    ("ANOM_LOGIN_SERVICE", 2118),
    ("ANOM_LOGIN_ROOT", 2119),
    ("ANOM_ORIGIN_FAILURES", 2120),
    ("ANOM_SESSION", 2121),
    // 2200-2299 user space responses to anomalies.
    ("RESP_ANOMALY", 2200),
    ("RESP_ALERT", 2201),
    ("RESP_KILL_PROC", 2202),
    ("RESP_TERM_ACCESS", 2203),
    ("RESP_ACCT_REMOTE", 2204),
    ("RESP_ACCT_LOCK_TIMED", 2205),
    ("RESP_ACCT_UNLOCK_TIMED", 2206),
    ("RESP_ACCT_LOCK", 2207),
    ("RESP_TERM_LOCK", 2208),
    ("RESP_SEBOOL", 2209),
    ("RESP_EXEC", 2210),
    ("RESP_SINGLE", 2211),
    ("RESP_HALT", 2212),
    ("RESP_ORIGIN_BLOCK", 2213),
    ("RESP_ORIGIN_BLOCK_TIMED", 2214),
    ("RESP_ORIGIN_UNBLOCK_TIMED", 2215),
    // 2300-2399 user space generated LSPP events.
    ("USER_ROLE_CHANGE", 2300),
    ("ROLE_ASSIGN", 2301),
    ("ROLE_REMOVE", 2302),
    ("LABEL_OVERRIDE", 2303),
    ("LABEL_LEVEL_CHANGE", 2304),
    ("USER_LABELED_EXPORT", 2305),
    ("USER_UNLABELED_EXPORT", 2306),
    ("DEV_ALLOC", 2307),
    ("DEV_DEALLOC", 2308),
    ("FS_RELABEL", 2309),
    ("USER_MAC_POLICY_LOAD", 2310),
    ("ROLE_MODIFY", 2311),
    ("USER_MAC_CONFIG_CHANGE", 2312),
    ("USER_MAC_STATUS", 2313),
    // 2400-2499 user space crypto events.
    ("CRYPTO_TEST_USER", 2400),
    ("CRYPTO_PARAM_CHANGE_USER", 2401),
    ("CRYPTO_LOGIN", 2402),
    ("CRYPTO_LOGOUT", 2403),
    ("CRYPTO_KEY_USER", 2404),
    ("CRYPTO_FAILURE_USER", 2405),
    ("CRYPTO_REPLAY_USER", 2406),
    ("CRYPTO_SESSION", 2407),
    ("CRYPTO_IKE_SA", 2408),
    ("CRYPTO_IPSEC_SA", 2409),
    // 2500-2599 user space virtualization management events.
    ("VIRT_CONTROL", 2500),
    ("VIRT_RESOURCE", 2501),
    ("VIRT_MACHINE_ID", 2502),
    ("VIRT_INTEGRITY_CHECK", 2503),
    ("VIRT_CREATE", 2504),
    ("VIRT_DESTROY", 2505),
    ("VIRT_MIGRATE_IN", 2506),
    ("VIRT_MIGRATE_OUT", 2507),
];

/// The `#ifdef WITH_APPARMOR` record-type name<->number block, excluded from
/// [`MSGTYPE_NAMES`] by default (#230). Names and numbers from
/// `audit-userspace lib/msg_typetab.h` (the `_S(AUDIT_<NAME>, "<NAME>")` lines
/// inside the `#ifdef WITH_APPARMOR` block) and `lib/audit-records.h`
/// (the `AUDIT_*` constants), both @ commit 3bfa048 -- the same pinned citation
/// commit as [`MSGTYPE_NAMES`].
///
/// Special note on the first entry: the C macro is `AUDIT_AA` but the name
/// string in `msg_typetab.h` is `"APPARMOR"` (not `"AA"`). The comment in
/// `audit-records.h` reads "Not upstream yet". All 8 entries are here (#230).
///
/// This table is SEPARATE and OPT-IN: consult it only when
/// [`LintOptions::include_apparmor`] is true, so default behaviour is
/// byte-identical to pre-#230.
///
/// `pub(super)`: same reason as [`MSGTYPE_NAMES`] (read directly by `mod tests`
/// in the parent `value::mod` via a `#[cfg(test)]` import).
pub(super) const APPARMOR_MSGTYPE_NAMES: &[(&str, u32)] = &[
    // audit-records.h: AUDIT_AA 1500 // "Not upstream yet"; msg_typetab.h: "APPARMOR"
    ("APPARMOR", 1500),
    ("APPARMOR_AUDIT", 1501),
    ("APPARMOR_ALLOWED", 1502),
    ("APPARMOR_DENIED", 1503),
    ("APPARMOR_HINT", 1504),
    ("APPARMOR_STATUS", 1505),
    ("APPARMOR_ERROR", 1506),
    ("APPARMOR_KILL", 1507),
];

/// The shipped base msgtype table ([`MSGTYPE_NAMES`]), publicly projected.
///
/// `pub` (re-exported from `lints::value`) so the out-of-workspace
/// `tools/auditd-msgtype-update` derive tool can drift-check the shipped
/// table against the upstream audit-userspace / kernel-uapi headers without
/// duplicating it (#476) - the same consumer-driven visibility precedent as
/// rulesteward-fapolicyd's `accepted_pattern_values` (#478). Pure visibility
/// change; the table and lookup logic are unchanged.
#[must_use]
pub fn base_msgtype_names() -> &'static [(&'static str, u32)] {
    MSGTYPE_NAMES
}

/// The shipped `#ifdef WITH_APPARMOR` msgtype table
/// ([`APPARMOR_MSGTYPE_NAMES`]), publicly projected - same rationale as
/// [`base_msgtype_names`] (#476). Pure visibility change.
#[must_use]
pub fn apparmor_msgtype_names() -> &'static [(&'static str, u32)] {
    APPARMOR_MSGTYPE_NAMES
}

/// The numeric audit record type for a msgtype NAME (case-insensitive per
/// libaudit `audit_name_to_msg_type`), or `None` if `name` is not a known
/// record-type name. Consults [`MSGTYPE_NAMES`] always; when
/// `opts.include_apparmor` is true also consults [`APPARMOR_MSGTYPE_NAMES`].
///
/// `pub(super)`: called by `canonical_value` in the sibling `canonical` module,
/// and read directly by `mod tests` in the parent `value::mod` via a
/// `#[cfg(test)]` import.
pub(super) fn msgtype_number(name: &str, opts: LintOptions) -> Option<u32> {
    MSGTYPE_NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|&(_, num)| num)
        .or_else(|| {
            if opts.include_apparmor {
                APPARMOR_MSGTYPE_NAMES
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|&(_, num)| num)
            } else {
                None
            }
        })
}

/// The resolved record-type NUMBER for a msgtype value under `opts`, or `None`
/// if `raw` does not resolve to a concrete number: an unknown name, an
/// `AppArmor` name with `opts.include_apparmor` off, or an unparseable
/// spelling (#475). Mirrors [`super::canonical_value`]'s `MsgType` branch
/// exactly -- name lookup via [`msgtype_number`] first, then the base-0
/// numeric fallback (#229) -- so the two can never disagree on whether a
/// msgtype value denotes a concrete kernel record type.
///
/// This is the resolution gate the disjointness prover
/// (`compare::canonical_decides_value_identity`) uses: msgtype disjointness is
/// provable only when BOTH sides of a pair independently resolve here (see the
/// module doc's "central correctness hazard": a naive canonical-STRING
/// inequality is unsound for an alias-bearing field like msgtype, since an
/// unresolved spelling and a resolved one can denote the identical kernel
/// value, e.g. `APPARMOR_DENIED` with the flag off vs `1503`).
///
/// `pub(super)`: called by `compare::canonical_decides_value_identity` and
/// `canonical::canonical_value` (sibling modules in `value`); the frozen
/// `mod tests` suite exercises it indirectly through [`super::disjoint`], not
/// via a direct import.
pub(super) fn msgtype_resolved_number(raw: &str, opts: LintOptions) -> Option<u64> {
    let t = raw.trim();
    // The name table already yields in-range record numbers. A NUMERIC spelling
    // is a __u32 on the wire (`struct audit_rule_data`'s `__u32 values[]`, uapi
    // audit.h:516; the kernel compares with `audit_comparator(u32, ...)`,
    // auditfilter.c:1205-1227 @ v6.6). DECLINE any spelling that does not fit in
    // u32 rather than trying to model the daemon's exact out-of-range behaviour:
    // libaudit parses with SIGNED `strtol` (libaudit.c:1788-1790 @ 3bfa048), which
    // clamps a positive overflow to LONG_MAX BEFORE the truncation, so e.g. 2^63
    // loads as 0xFFFF_FFFF, NOT 0 -- an unsigned `& 0xFFFF_FFFF` mask would
    // mis-model that and prove a false disjointness (dropping an au-W03 warning).
    // Declining above u32::MAX is the conservative, sound choice and mirrors the
    // classify.rs uid/gid/sessionid precedent (`u32::try_from`, decline above): a
    // >u32 spelling never participates in an identity disjointness/equality proof.
    // Below 2^32 this is a no-op, so every in-range value (and the name path) is
    // unchanged. No real audit rule carries a msgtype above u32::MAX.
    msgtype_number(t, opts).map(u64::from).or_else(|| {
        parse_u64_base0(t)
            .and_then(|n| u32::try_from(n).ok())
            .map(u64::from)
    })
}
