//! Host target auto-detection for `--target auto` (epic #251).
//!
//! Resolves the RHEL-keyed lint baseline (rhel8/9/10) from the host's
//! `/etc/os-release`, behind a DI trait so the real filesystem read is excluded
//! from the mutation gate while the pure parse/map logic stays unit-tested and in
//! scope. Mirrors doctor's `SystemProbe`/`LiveProbe` pattern (PR #133/#173) and
//! container-check's `ContainerProbe` (PR #176). Per epic #251, target resolution
//! happens HERE in the CLI command layer; lint passes never probe the system.
//!
//! `--target` selects a RHEL RELEASE, not a tool version, so the authoritative
//! signal is `/etc/os-release` (the same for every backend). The probed major
//! comes from `PLATFORM_ID` ("platform:elN", no minor to confuse) when present,
//! falling back to the integer prefix of `VERSION_ID` ("8.10" -> 8). On RHEL 9 vs
//! 10 the OpenSSH version collides (both ship 9.9p1), which is exactly why a
//! tool-version probe is insufficient and os-release is the right signal.

use crate::cli::{TargetSelector, TargetVersionArg};

/// Detects the host's RHEL-keyed target baseline from `/etc/os-release`.
pub(crate) trait HostTargetProbe {
    /// `Ok(Some(t))` when the host maps to a supported target; `Ok(None)` when the
    /// host is readable but not a recognized RHEL family/major; `Err` when the host
    /// identity could not be read at all.
    fn detect(&self) -> Result<Option<TargetVersionArg>, String>;
}

/// Live probe: reads `/etc/os-release`. EXCLUDED from the mutation gate by name
/// (real I/O, no unit-test seam; covered by the live VM smoke); the pure helpers
/// it delegates to are in scope and unit-tested.
pub(crate) struct LiveTargetProbe;

impl HostTargetProbe for LiveTargetProbe {
    fn detect(&self) -> Result<Option<TargetVersionArg>, String> {
        let text = std::fs::read_to_string("/etc/os-release")
            .map_err(|e| format!("cannot read /etc/os-release: {e}"))?;
        Ok(map_to_target(&parse_os_release(&text)))
    }
}

/// The `/etc/os-release` identity fields used for target mapping (shell quotes
/// stripped). Absent keys are `None`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct OsRelease {
    pub id: Option<String>,
    pub id_like: Option<String>,
    pub version_id: Option<String>,
    pub platform_id: Option<String>,
}

/// Parse the identity fields out of `/etc/os-release` text, stripping the shell
/// quotes os-release wraps values in. Reuses the comment-aware, whitespace-tolerant
/// `conf_value` reader (os-release is a `key=value` file).
pub(crate) fn parse_os_release(text: &str) -> OsRelease {
    let field = |key: &str| {
        super::conf::conf_value(text, key)
            .map(strip_quotes)
            .map(str::to_owned)
    };
    OsRelease {
        id: field("ID"),
        id_like: field("ID_LIKE"),
        version_id: field("VERSION_ID"),
        platform_id: field("PLATFORM_ID"),
    }
}

/// Strip one matching pair of surrounding ASCII quotes (the shell quoting
/// os-release uses around multi-word / dotted values), if present.
fn strip_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Map parsed os-release identity to a target baseline, or `None` when the host is
/// not a recognized RHEL-family release at a supported major (8/9/10).
pub(crate) fn map_to_target(os: &OsRelease) -> Option<TargetVersionArg> {
    if !is_rhel_family(os) {
        return None;
    }
    match major(os)? {
        8 => Some(TargetVersionArg::Rhel8),
        9 => Some(TargetVersionArg::Rhel9),
        10 => Some(TargetVersionArg::Rhel10),
        _ => None,
    }
}

/// True when os-release identifies a RHEL-family (EL) distro: RHEL itself, a
/// downstream with a known family `ID` (Rocky/Alma/CentOS), a distro whose
/// `ID_LIKE` includes the `rhel` token, OR any host that sets
/// `PLATFORM_ID="platform:elN"`. The `PLATFORM_ID` signal is what catches EL
/// rebuilds like Oracle Linux (`ID="ol"`, `ID_LIKE="fedora"`) that ship the same
/// OpenSSH/STIG baseline; only EL distros set it, and `major()` already trusts it
/// for the release number, so accepting it here keeps the two signals consistent.
/// Matching the family (not just `ID=rhel`) is required because `ID=rocky` on the
/// Rocky hosts would otherwise miss.
fn is_rhel_family(os: &OsRelease) -> bool {
    const FAMILY_IDS: &[&str] = &["rhel", "rocky", "almalinux", "centos"];
    let id_match = os.id.as_deref().is_some_and(|id| FAMILY_IDS.contains(&id));
    let id_like_match = os
        .id_like
        .as_deref()
        .is_some_and(|like| like.split_whitespace().any(|token| token == "rhel"));
    let platform_match = os
        .platform_id
        .as_deref()
        .is_some_and(|p| p.starts_with("platform:el"));
    id_match || id_like_match || platform_match
}

/// The major release number, preferring `PLATFORM_ID` ("platform:elN", which has
/// no minor to confuse) and falling back to the integer prefix of `VERSION_ID`
/// ("8.10" -> 8, NOT 8.1). Returns `None` when neither yields a parseable major.
fn major(os: &OsRelease) -> Option<u32> {
    if let Some(platform) = os.platform_id.as_deref()
        && let Some(rest) = platform.strip_prefix("platform:el")
        && let Ok(n) = rest.parse::<u32>()
    {
        return Some(n);
    }
    os.version_id
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|maj| maj.parse::<u32>().ok())
}

/// Outcome of resolving `--target`: the concrete baseline to lint against (or
/// `None` for the version-agnostic dialect) plus an optional operator warning to
/// print to stderr (set only when `auto` could not resolve).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResolvedTarget {
    pub target: Option<TargetVersionArg>,
    pub warning: Option<String>,
}

/// Resolve the `--target` selector in the CLI command layer (epic #251): an
/// explicit value is used as-is; `auto` consults the probe and degrades to the
/// version-agnostic dialect (with a warning) when detection fails; an omitted
/// `--target` stays version-agnostic (the unchanged pre-auto behavior). Only the
/// `auto` arm consults the probe.
pub(crate) fn resolve_target(
    sel: Option<TargetSelector>,
    probe: &dyn HostTargetProbe,
) -> ResolvedTarget {
    let explicit = match sel {
        None => {
            return ResolvedTarget {
                target: None,
                warning: None,
            };
        }
        Some(TargetSelector::Rhel8) => Some(TargetVersionArg::Rhel8),
        Some(TargetSelector::Rhel9) => Some(TargetVersionArg::Rhel9),
        Some(TargetSelector::Rhel10) => Some(TargetVersionArg::Rhel10),
        Some(TargetSelector::Auto) => {
            return match probe.detect() {
                Ok(Some(target)) => ResolvedTarget {
                    target: Some(target),
                    warning: None,
                },
                Ok(None) => ResolvedTarget {
                    target: None,
                    warning: Some(
                        "--target auto: could not map this host to a known target \
                         (rhel8/rhel9/rhel10) from /etc/os-release; linting version-agnostic"
                            .to_string(),
                    ),
                },
                Err(e) => ResolvedTarget {
                    target: None,
                    warning: Some(format!("--target auto: {e}; linting version-agnostic")),
                },
            };
        }
    };
    ResolvedTarget {
        target: explicit,
        warning: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_os_release -------------------------------------------------

    #[test]
    fn parses_quoted_and_unquoted_fields() {
        // Rocky 9 shape: ID unquoted, ID_LIKE/VERSION_ID/PLATFORM_ID double-quoted.
        let text = "NAME=\"Rocky Linux\"\n\
                    ID=rocky\n\
                    ID_LIKE=\"rhel centos fedora\"\n\
                    VERSION_ID=\"9.8\"\n\
                    PLATFORM_ID=\"platform:el9\"\n";
        let os = parse_os_release(text);
        assert_eq!(
            os,
            OsRelease {
                id: Some("rocky".into()),
                id_like: Some("rhel centos fedora".into()),
                version_id: Some("9.8".into()),
                platform_id: Some("platform:el9".into()),
            }
        );
    }

    #[test]
    fn strips_single_quotes_too() {
        let os = parse_os_release("VERSION_ID='8.10'\n");
        assert_eq!(os.version_id.as_deref(), Some("8.10"));
    }

    #[test]
    fn absent_fields_are_none() {
        // Fedora-ish: ID present, no ID_LIKE / PLATFORM_ID.
        let os = parse_os_release("ID=fedora\nVERSION_ID=44\n");
        assert_eq!(os.id.as_deref(), Some("fedora"));
        assert_eq!(os.version_id.as_deref(), Some("44"));
        assert_eq!(os.id_like, None);
        assert_eq!(os.platform_id, None);
    }

    #[test]
    fn ignores_comment_and_blank_lines() {
        let os = parse_os_release("# a comment\n\nID=rhel\n");
        assert_eq!(os.id.as_deref(), Some("rhel"));
    }

    // --- map_to_target: the three Rocky VMs (ground truth) ----------------

    fn os(id: &str, id_like: &str, version_id: &str, platform_id: &str) -> OsRelease {
        OsRelease {
            id: Some(id.into()),
            id_like: Some(id_like.into()),
            version_id: Some(version_id.into()),
            platform_id: Some(platform_id.into()),
        }
    }

    #[test]
    fn rocky8_maps_to_rhel8() {
        assert_eq!(
            map_to_target(&os("rocky", "rhel centos fedora", "8.10", "platform:el8")),
            Some(TargetVersionArg::Rhel8)
        );
    }

    #[test]
    fn rocky9_maps_to_rhel9() {
        assert_eq!(
            map_to_target(&os("rocky", "rhel centos fedora", "9.8", "platform:el9")),
            Some(TargetVersionArg::Rhel9)
        );
    }

    #[test]
    fn rocky10_maps_to_rhel10() {
        // The "10 not 1.0" trap: VERSION_ID 10.2 / platform:el10 -> major 10.
        assert_eq!(
            map_to_target(&os("rocky", "rhel centos fedora", "10.2", "platform:el10")),
            Some(TargetVersionArg::Rhel10)
        );
    }

    #[test]
    fn rhel_proper_maps() {
        assert_eq!(
            map_to_target(&os("rhel", "fedora", "9.4", "platform:el9")),
            Some(TargetVersionArg::Rhel9)
        );
    }

    #[test]
    fn almalinux_maps() {
        assert_eq!(
            map_to_target(&os(
                "almalinux",
                "rhel centos fedora",
                "8.9",
                "platform:el8"
            )),
            Some(TargetVersionArg::Rhel8)
        );
    }

    #[test]
    fn family_matched_via_id_like_when_id_is_unknown() {
        // A downstream whose ID is not in the allowlist but whose ID_LIKE names rhel.
        let mut o = os("somederiv", "centos rhel fedora", "9.3", "platform:el9");
        o.id = Some("someotherderiv".into());
        assert_eq!(map_to_target(&o), Some(TargetVersionArg::Rhel9));
    }

    #[test]
    fn oracle_linux_resolves_via_platform_id() {
        // Oracle Linux is an EL rebuild shipping the same OpenSSH, but ID="ol" is
        // not in the family allowlist and ID_LIKE="fedora" lacks the rhel token.
        // PLATFORM_ID="platform:elN" - which major() already trusts as the
        // authoritative major - is the family signal that resolves it, keeping the
        // two signals consistent. Verified os-release (ID=ol, ID_LIKE=fedora).
        assert_eq!(
            map_to_target(&os("ol", "fedora", "8.7", "platform:el8")),
            Some(TargetVersionArg::Rhel8)
        );
        assert_eq!(
            map_to_target(&os("ol", "fedora", "9.4", "platform:el9")),
            Some(TargetVersionArg::Rhel9)
        );
    }

    #[test]
    fn platform_id_alone_is_a_family_signal() {
        // Even with an unknown ID and no ID_LIKE, platform:elN identifies the EL
        // family (only EL distros set it). Pins the platform_id family branch.
        let o = OsRelease {
            id: Some("mystery".into()),
            id_like: None,
            version_id: None,
            platform_id: Some("platform:el10".into()),
        };
        assert_eq!(map_to_target(&o), Some(TargetVersionArg::Rhel10));
    }

    #[test]
    fn debian_10_is_none_family_gate_not_major_gate() {
        // The family gate (not the major gate) is what rejects a non-EL host. Real
        // Debian 10 has ID=debian, no ID_LIKE, no PLATFORM_ID, and VERSION_ID="10" -
        // a SUPPORTED major. Without is_rhel_family it would map to Rhel10; it must
        // be None. Pins is_rhel_family against a `-> true` bypass that a non-EL host
        // at an UNSUPPORTED major (e.g. ubuntu 22.04) cannot catch.
        let o = OsRelease {
            id: Some("debian".into()),
            id_like: None,
            version_id: Some("10".into()),
            platform_id: None,
        };
        assert_eq!(map_to_target(&o), None);
    }

    #[test]
    fn id_like_rhel_token_alone_is_a_family_signal() {
        // A derivative whose ONLY family signal is a single-token ID_LIKE="rhel" (no
        // allowlist ID, no PLATFORM_ID) must still resolve. Pins the exact
        // `token == "rhel"` match: a `== -> !=` flip drops this host to None, and
        // every other positive id_like fixture also carries a PLATFORM_ID that would
        // mask the flip.
        let o = OsRelease {
            id: Some("someoldrebuild".into()),
            id_like: Some("rhel".into()),
            version_id: Some("9".into()),
            platform_id: None,
        };
        assert_eq!(map_to_target(&o), Some(TargetVersionArg::Rhel9));
    }

    // --- map_to_target: the major-vs-minor and precedence traps -----------

    #[test]
    fn version_id_minor_is_not_read_as_major() {
        // "8.10" must yield major 8, NOT 8.1/10. No PLATFORM_ID, so VERSION_ID is used.
        let mut o = os("rocky", "rhel", "8.10", "");
        o.platform_id = None;
        assert_eq!(map_to_target(&o), Some(TargetVersionArg::Rhel8));
    }

    #[test]
    fn platform_id_takes_precedence_over_version_id() {
        // Contrived mismatch pins the precedence: PLATFORM_ID wins.
        assert_eq!(
            map_to_target(&os("rhel", "fedora", "8.10", "platform:el9")),
            Some(TargetVersionArg::Rhel9)
        );
    }

    #[test]
    fn version_id_used_when_no_platform_id() {
        let mut o = os("rhel", "fedora", "10.0", "");
        o.platform_id = None;
        assert_eq!(map_to_target(&o), Some(TargetVersionArg::Rhel10));
    }

    // --- map_to_target: the None cases ------------------------------------

    #[test]
    fn non_rhel_family_is_none() {
        assert_eq!(map_to_target(&os("ubuntu", "debian", "22.04", "")), None);
    }

    #[test]
    fn fedora_is_none() {
        // Fedora is not RHEL family (no rhel in ID_LIKE) and its major is unsupported.
        let mut o = os("fedora", "", "44", "");
        o.id_like = None;
        o.platform_id = None;
        assert_eq!(map_to_target(&o), None);
    }

    #[test]
    fn unsupported_major_is_none() {
        // RHEL family but an out-of-range major.
        assert_eq!(
            map_to_target(&os("rhel", "fedora", "7.9", "platform:el7")),
            None
        );
    }

    #[test]
    fn empty_os_release_is_none() {
        assert_eq!(map_to_target(&OsRelease::default()), None);
    }

    // --- resolve_target ---------------------------------------------------

    /// A probe whose `detect` must never be consulted (used to prove the non-`auto`
    /// arms short-circuit before any probing).
    struct PanicProbe;
    impl HostTargetProbe for PanicProbe {
        fn detect(&self) -> Result<Option<TargetVersionArg>, String> {
            panic!("probe must not be consulted unless --target auto");
        }
    }

    /// A probe returning a canned result, for the `auto` arms.
    struct FakeProbe(Result<Option<TargetVersionArg>, String>);
    impl HostTargetProbe for FakeProbe {
        fn detect(&self) -> Result<Option<TargetVersionArg>, String> {
            self.0.clone()
        }
    }

    #[test]
    fn omitted_target_is_version_agnostic_and_does_not_probe() {
        let r = resolve_target(None, &PanicProbe);
        assert_eq!(
            r,
            ResolvedTarget {
                target: None,
                warning: None
            }
        );
    }

    #[test]
    fn explicit_target_is_used_and_does_not_probe() {
        let r = resolve_target(Some(TargetSelector::Rhel9), &PanicProbe);
        assert_eq!(
            r,
            ResolvedTarget {
                target: Some(TargetVersionArg::Rhel9),
                warning: None
            }
        );
    }

    #[test]
    fn auto_uses_the_probe_result() {
        let r = resolve_target(
            Some(TargetSelector::Auto),
            &FakeProbe(Ok(Some(TargetVersionArg::Rhel10))),
        );
        assert_eq!(
            r,
            ResolvedTarget {
                target: Some(TargetVersionArg::Rhel10),
                warning: None
            }
        );
    }

    #[test]
    fn auto_unmappable_host_warns_and_is_version_agnostic() {
        let r = resolve_target(Some(TargetSelector::Auto), &FakeProbe(Ok(None)));
        assert_eq!(r.target, None);
        let w = r.warning.expect("auto that resolves to nothing must warn");
        assert!(
            w.contains("version-agnostic"),
            "warning should explain the fallback, got: {w:?}"
        );
    }

    #[test]
    fn auto_probe_error_warns_and_is_version_agnostic() {
        let r = resolve_target(
            Some(TargetSelector::Auto),
            &FakeProbe(Err("cannot read /etc/os-release: nope".into())),
        );
        assert_eq!(r.target, None);
        let w = r.warning.expect("auto with a probe error must warn");
        assert!(
            w.contains("version-agnostic"),
            "warning should explain the fallback, got: {w:?}"
        );
        assert!(
            w.contains("os-release"),
            "warning should surface the probe error context, got: {w:?}"
        );
    }
}
