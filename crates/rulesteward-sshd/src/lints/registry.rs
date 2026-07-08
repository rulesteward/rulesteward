//! Per-OpenSSH-version valid `sshd_config` keyword registry for sshd-E01.
//!
//! E01 fires when a directive's keyword is not recognized by the target's sshd.
//! "Recognized" means the daemon does NOT answer "Bad configuration option" for
//! it; that deliberately INCLUDES deprecated-but-accepted keywords (sshd-W04's
//! concern, #243), the RHEL out-of-tree GSSAPI key-exchange patch keywords, and
//! the pre-8.5 `*KeyTypes` rename aliases - none of which are E01.
//!
//! # Provenance (generated; do not hand-edit - regenerate from the VMs)
//! Every entry was classified by the live daemon via `sshd -t -o "KW=yes"` on
//! Rocky 8.10 / 9.8 / 10.2 (OpenSSH 8.0p1 / 9.9p1 / 9.9p1) on 2026-06-15: a
//! keyword is valid iff sshd's reply was anything OTHER than "Bad configuration
//! option" (so "Deprecated option", "Unsupported option", a value error, and a
//! platform-unsupported error all count as recognized). The measured sets nest
//! cleanly with no removals: RHEL8 (119) is a subset of RHEL9 (= RHEL8 + 19),
//! a subset of RHEL10 (= RHEL9 + 1), so the table is a base plus per-version
//! additions and the no-`--target` union equals the RHEL10 superset. See
//! `rulesteward-docs/sshd-stig-version-grounding.md` for the full grounding.

use crate::lints::TargetVersion;

/// RHEL 8 / OpenSSH 8.0p1 recognized keyword set, lowercased and sorted for
/// `binary_search`.
const RHEL8_BASE: &[&str] = &[
    "acceptenv",
    "addressfamily",
    "afstokenpassing",
    "allowagentforwarding",
    "allowgroups",
    "allowstreamlocalforwarding",
    "allowtcpforwarding",
    "allowusers",
    "authenticationmethods",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "authorizedkeysfile",
    "authorizedkeysfile2",
    "authorizedprincipalscommand",
    "authorizedprincipalscommanduser",
    "authorizedprincipalsfile",
    "banner",
    "casignaturealgorithms",
    "challengeresponseauthentication",
    "checkmail",
    "chrootdirectory",
    "ciphers",
    "clientalivecountmax",
    "clientaliveinterval",
    "compression",
    "denygroups",
    "denyusers",
    "disableforwarding",
    "dsaauthentication",
    "exposeauthinfo",
    "fingerprinthash",
    "forcecommand",
    "gatewayports",
    "gssapiauthentication",
    "gssapicleanupcredentials",
    "gssapicleanupcreds",
    "gssapienablek5users",
    "gssapikexalgorithms",
    "gssapikeyexchange",
    "gssapistorecredentialsonrekey",
    "gssapistrictacceptorcheck",
    "gssapiusesessioncredcache",
    "gssusesessionccache",
    "hostbasedacceptedkeytypes",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "hostcertificate",
    "hostdsakey",
    "hostkey",
    "hostkeyagent",
    "hostkeyalgorithms",
    "ignorerhosts",
    "ignoreuserknownhosts",
    "include",
    "ipqos",
    "kbdinteractiveauthentication",
    "keepalive",
    "kerberosauthentication",
    "kerberosgetafstoken",
    "kerberosorlocalpasswd",
    "kerberostgtpassing",
    "kerberosticketcleanup",
    "kerberosuniqueccache",
    "kerberosusekuserok",
    "kexalgorithms",
    "keyregenerationinterval",
    "listenaddress",
    "logingracetime",
    "loglevel",
    "macs",
    "match",
    "maxauthtries",
    "maxsessions",
    "maxstartups",
    "pamauthenticationviakbdint",
    "passwordauthentication",
    "permitemptypasswords",
    "permitlisten",
    "permitopen",
    "permitrootlogin",
    "permittty",
    "permittunnel",
    "permituserenvironment",
    "permituserrc",
    "pidfile",
    "port",
    "printlastlog",
    "printmotd",
    "protocol",
    "pubkeyacceptedkeytypes",
    "pubkeyauthentication",
    "rdomain",
    "rekeylimit",
    "reversemappingcheck",
    "revokedkeys",
    "rhostsauthentication",
    "rhostsrsaauthentication",
    "rsaauthentication",
    "serverkeybits",
    "setenv",
    "skeyauthentication",
    "streamlocalbindmask",
    "streamlocalbindunlink",
    "strictmodes",
    "subsystem",
    "syslogfacility",
    "tcpkeepalive",
    "trustedusercakeys",
    "usedns",
    "uselogin",
    "usepam",
    "useprivilegeseparation",
    "verifyreversemapping",
    "versionaddendum",
    "x11displayoffset",
    "x11forwarding",
    "x11maxdisplays",
    "x11uselocalhost",
    "xauthlocation",
];

/// Keywords RHEL 9 / OpenSSH 9.9p1 recognizes beyond the 8.0p1 base, sorted.
const ADDED_RHEL9: &[&str] = &[
    "canonicalmatchuser",
    "channeltimeout",
    "gssapiindicators",
    "hostbasedacceptedalgorithms",
    "logverbose",
    "modulifile",
    "pamservicename",
    "persourcemaxstartups",
    "persourcenetblocksize",
    "persourcepenalties",
    "persourcepenaltyexemptlist",
    "pubkeyacceptedalgorithms",
    "pubkeyauthoptions",
    "refuseconnection",
    "requiredrsasize",
    "rsaminsize",
    "securitykeyprovider",
    "sshdsessionpath",
    "unusedconnectiontimeout",
];

/// Keywords the RHEL 10 build recognizes beyond RHEL 9 (its OpenSSH is also
/// 9.9p1, but el10 enables one more), sorted.
const ADDED_RHEL10: &[&str] = &["gssapidelegatecredentials"];

/// Whether `keyword_lower` (already ASCII-lowercased by the caller) is a
/// recognized `sshd_config` directive for `target`. The per-version sets nest, so
/// each tier ORs in the additions of the tiers below it.
#[must_use]
pub fn is_known(keyword_lower: &str, target: TargetVersion) -> bool {
    let in_base = RHEL8_BASE.binary_search(&keyword_lower).is_ok();
    match target {
        TargetVersion::Rhel8 => in_base,
        TargetVersion::Rhel9 => in_base || ADDED_RHEL9.binary_search(&keyword_lower).is_ok(),
        TargetVersion::Rhel10 => {
            in_base
                || ADDED_RHEL9.binary_search(&keyword_lower).is_ok()
                || ADDED_RHEL10.binary_search(&keyword_lower).is_ok()
        }
    }
}

/// Whether `keyword_lower` is recognized by ANY supported target - the union used
/// when no `--target` is given. Because the sets nest with no removals, the union
/// is exactly the RHEL 10 set.
#[must_use]
pub fn is_known_any(keyword_lower: &str) -> bool {
    is_known(keyword_lower, TargetVersion::Rhel10)
}

/// The full set of recognized `sshd_config` keywords for `target`, enumerated
/// rather than membership-tested. Backs the out-of-tree `sshd-probe-update` drift
/// tool, which diffs this shipped registry against a live daemon probe. The
/// per-version sets nest, so this unions each tier's additions into the ones below
/// it (119 / 138 / 139 for RHEL 8 / 9 / 10). Order is unspecified.
#[must_use]
pub fn known_keywords(target: TargetVersion) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = RHEL8_BASE.to_vec();
    if matches!(target, TargetVersion::Rhel9 | TargetVersion::Rhel10) {
        out.extend_from_slice(ADDED_RHEL9);
    }
    if matches!(target, TargetVersion::Rhel10) {
        out.extend_from_slice(ADDED_RHEL10);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{ADDED_RHEL9, ADDED_RHEL10, RHEL8_BASE, is_known, is_known_any};
    use crate::lints::TargetVersion;

    fn sorted_unique(xs: &[&str]) -> bool {
        xs.windows(2).all(|w| w[0] < w[1])
    }

    #[test]
    fn arrays_are_sorted_lowercase_and_unique() {
        for (name, arr) in [
            ("RHEL8_BASE", RHEL8_BASE),
            ("ADDED_RHEL9", ADDED_RHEL9),
            ("ADDED_RHEL10", ADDED_RHEL10),
        ] {
            assert!(
                sorted_unique(arr),
                "{name} must be sorted + unique for binary_search"
            );
            assert!(
                arr.iter()
                    .all(|k| !k.is_empty() && !k.contains(|c: char| c.is_ascii_uppercase())),
                "{name} entries must be non-empty and lowercase"
            );
        }
    }

    #[test]
    fn measured_set_sizes() {
        // The live `sshd -t` classification (2026-06-15) measured these exact
        // sizes; a change here means the registry must be re-grounded on the VMs.
        assert_eq!(RHEL8_BASE.len(), 119);
        assert_eq!(ADDED_RHEL9.len(), 19);
        assert_eq!(ADDED_RHEL10.len(), 1);
    }

    #[test]
    fn additions_are_disjoint_from_lower_tiers() {
        for k in ADDED_RHEL9 {
            assert!(!RHEL8_BASE.contains(k), "{k} double-listed in RHEL8_BASE");
        }
        for k in ADDED_RHEL10 {
            assert!(!RHEL8_BASE.contains(k), "{k} double-listed in RHEL8_BASE");
            assert!(!ADDED_RHEL9.contains(k), "{k} double-listed in ADDED_RHEL9");
        }
    }

    #[test]
    fn sets_nest_and_union_is_rhel10() {
        for k in RHEL8_BASE {
            assert!(is_known(k, TargetVersion::Rhel8), "{k} known on rhel8");
            assert!(
                is_known(k, TargetVersion::Rhel9),
                "{k} stays known on rhel9"
            );
            assert!(
                is_known(k, TargetVersion::Rhel10),
                "{k} stays known on rhel10"
            );
            assert!(is_known_any(k), "{k} in the union");
        }
        for k in ADDED_RHEL9 {
            assert!(!is_known(k, TargetVersion::Rhel8), "{k} is a 9+ keyword");
            assert!(is_known(k, TargetVersion::Rhel9), "{k} known on rhel9");
            assert!(
                is_known(k, TargetVersion::Rhel10),
                "{k} stays known on rhel10"
            );
            assert!(is_known_any(k), "{k} in the union");
        }
        for k in ADDED_RHEL10 {
            assert!(!is_known(k, TargetVersion::Rhel8), "{k} is rhel10-only");
            assert!(!is_known(k, TargetVersion::Rhel9), "{k} is rhel10-only");
            assert!(is_known(k, TargetVersion::Rhel10), "{k} known on rhel10");
            assert!(is_known_any(k), "{k} in the union");
        }
    }

    #[test]
    fn unknown_keyword_is_unknown_on_every_tier() {
        for t in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            assert!(!is_known("zzbogusdirective", t));
        }
        assert!(!is_known_any("zzbogusdirective"));
    }

    #[test]
    fn grounded_membership_spot_checks() {
        // The cases an upstream-only or man-page-only registry would get wrong.
        assert!(
            is_known("gssapikeyexchange", TargetVersion::Rhel8),
            "RHEL GSSAPI key-exchange patch keyword"
        );
        assert!(
            is_known("pubkeyacceptedkeytypes", TargetVersion::Rhel8),
            "pre-8.5 rename alias stays valid"
        );
        assert!(
            is_known("uselogin", TargetVersion::Rhel8),
            "deprecated-but-recognized -> W04, not E01"
        );
        assert!(
            ADDED_RHEL9.contains(&"requiredrsasize"),
            "9.9p1 boundary keyword"
        );
        assert!(
            ADDED_RHEL9.contains(&"pubkeyacceptedalgorithms"),
            "post-8.5 rename present from 9.9p1"
        );
        assert!(
            is_known("gssapiusesessioncredcache", TargetVersion::Rhel8),
            "RHEL GSSAPI session-cred patch keyword (in the binary, not the man page)"
        );
        assert!(
            ADDED_RHEL9.contains(&"rsaminsize"),
            "RHEL 9+ RSAMinSize (binary-only keyword)"
        );
        assert_eq!(ADDED_RHEL10, &["gssapidelegatecredentials"]);
    }
}

#[cfg(test)]
mod projection_tests {
    use super::{is_known, known_keywords};
    use crate::lints::TargetVersion;

    #[test]
    fn known_keywords_sizes_match_measured_sets() {
        assert_eq!(known_keywords(TargetVersion::Rhel8).len(), 119);
        assert_eq!(known_keywords(TargetVersion::Rhel9).len(), 138);
        assert_eq!(known_keywords(TargetVersion::Rhel10).len(), 139);
    }

    #[test]
    fn every_enumerated_keyword_is_known_on_its_tier() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            for kw in known_keywords(target) {
                assert!(
                    is_known(kw, target),
                    "{kw} enumerated but is_known=false at {target:?}"
                );
            }
        }
    }

    #[test]
    fn known_keyword_sets_nest_across_versions() {
        let r8 = known_keywords(TargetVersion::Rhel8);
        let r9 = known_keywords(TargetVersion::Rhel9);
        let r10 = known_keywords(TargetVersion::Rhel10);
        assert!(r8.iter().all(|k| r9.contains(k)), "rhel8 subset of rhel9");
        assert!(r9.iter().all(|k| r10.contains(k)), "rhel9 subset of rhel10");
    }
}
