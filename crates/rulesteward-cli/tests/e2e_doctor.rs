//! End-to-end graceful-degradation tests for `rulesteward fapolicyd doctor`.
//!
//! This host has no fapolicyd installed.  The binary must:
//!   (a) not panic or crash,
//!   (b) emit a valid JSON envelope with `kind: "doctor-report"` and `schemaVersion`,
//!   (c) exit with a defined code (0, 1, or 2 -- never 3 "tool failure").
//!
//! The checks will return `Unknown` / `Skip` / `Fail` (no fapolicyd daemon,
//! no auditctl, no fapolicyd-cli), but the binary must handle those gracefully.
//!
//! Mirrors the `assert_cmd` pattern used in `e2e_selinux.rs` and `e2e_trustdb.rs`.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

/// `fapolicyd doctor --format json` on this bare host must:
///   - Not panic (exit code != 101).
///   - Emit stdout that parses as a JSON object (not an error message).
///   - Carry `kind: "doctor-report"` and `schemaVersion: 1` in the envelope.
///   - Carry a `checks` array with exactly 14 entries (#519 adds `fapolicyd-package`).
///   - Carry a `summary` object.
///   - End with a trailing newline (machine-readable output contract).
///   - Exit with 0, 1, or 2 (never 3, which would indicate a tool-level crash).
#[test]
fn doctor_json_graceful_degradation_on_bare_host() {
    let output = bin()
        .args(["fapolicyd", "doctor", "--format", "json"])
        .output()
        .expect("binary ran");

    // Must not panic (exit 101 is Rust's panic exit code).
    assert_ne!(
        output.status.code(),
        Some(101),
        "doctor must not panic; got exit 101"
    );

    // Exit code must be a known value (0/1/2); never 3 (tool failure).
    let code = output.status.code().expect("process exited normally");
    assert!(
        code == 0 || code == 1 || code == 2,
        "exit code must be 0, 1, or 2 on a bare host; got {code}"
    );

    // Stdout must be valid JSON.
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");

    // Envelope contract.
    assert_eq!(
        v["kind"].as_str(),
        Some("doctor-report"),
        "kind must be doctor-report; got: {stdout}"
    );
    assert_eq!(
        v["schemaVersion"].as_u64(),
        Some(1),
        "schemaVersion must be 1; got: {stdout}"
    );

    // Checks array must have exactly 14 entries (#519 adds fapolicyd-package).
    let checks = v["checks"].as_array().expect("checks must be a JSON array");
    assert_eq!(
        checks.len(),
        14,
        "doctor must produce exactly 14 checks; got {}",
        checks.len()
    );

    // Summary object must be present.
    assert!(
        v["summary"].is_object(),
        "summary must be a JSON object; got: {stdout}"
    );

    // Trailing newline.
    assert!(
        stdout.ends_with('\n'),
        "JSON output must end with a trailing newline"
    );

    // No debug/placeholder leakage.
    for bad in &[
        "<source>",
        "<unknown>",
        "<placeholder>",
        "TODO",
        "panic",
        "dbg!",
    ] {
        assert!(
            !stdout.contains(bad),
            "stdout must not contain debug token {bad:?}; got: {stdout}"
        );
    }
}

/// `fapolicyd doctor` (human format, the default) must not panic and must
/// emit a non-empty human-readable scorecard to stdout.
#[test]
fn doctor_human_format_does_not_panic() {
    bin()
        .args(["fapolicyd", "doctor"])
        .assert()
        .code(predicate::in_iter([0i32, 1, 2]))
        .stdout(predicate::str::contains("fapolicyd doctor report"))
        .stdout(predicate::str::contains("Summary:"));
}

/// `fapolicyd doctor --format json` must include the container-check entry and
/// it must now be wired to the real classifier (#134/#175), NOT the old stub.
///
/// The exact status varies by host (Ok on a bare CI host with no runtime, up to
/// Fail on a host with an active runtime + enforcing fapolicyd + tmpfs/mark), so
/// we assert the rewire happened rather than a fixed verdict: a valid non-skip
/// status, and no "not yet implemented" placeholder.
#[test]
fn doctor_json_container_check_is_wired() {
    let output = bin()
        .args(["fapolicyd", "doctor", "--format", "json"])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let checks = v["checks"].as_array().expect("checks array");

    let cc = checks
        .iter()
        .find(|c| c["name"].as_str() == Some("container-check"))
        .expect("container-check entry must be present in the checks array");

    let status = cc["status"].as_str().unwrap_or("");
    assert_ne!(status, "skip", "container-check is no longer a Skip stub");
    assert!(
        ["ok", "warn", "fail", "unknown"].contains(&status),
        "container-check status must be a real verdict, got {status:?}"
    );
    assert!(
        !cc["detail"]
            .as_str()
            .unwrap_or("")
            .contains("not yet implemented"),
        "container-check detail must not carry the old stub text"
    );
}

/// `fapolicyd doctor --help` must render and include key flags.
#[test]
fn doctor_help_renders_expected_flags() {
    bin()
        .args(["fapolicyd", "doctor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"));
}

/// `fapolicyd doctor --help` must additionally advertise the new `--target`
/// flag (#519).
#[test]
fn doctor_help_renders_target_flag() {
    bin()
        .args(["fapolicyd", "doctor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--target"));
}

/// The RHEL-family major (8/9/10) the live probe would resolve for this host's
/// `/etc/os-release` under the default `--target auto`, or `None` when auto
/// degrades. Mirrors the family + major signals of `commands::target_probe`
/// (family `ID`, an `ID_LIKE` containing `rhel`, or `PLATFORM_ID=platform:elN`;
/// major from `PLATFORM_ID` first, then the integer prefix of `VERSION_ID`) -
/// the same accepted mirror trade-off as `e2e_selinux_lint.rs`'s host guard.
/// Used to branch the omitted-target assertions: the distro-CI containers
/// (Rocky/Alma/Oracle 8/9/10) resolve; ubuntu CI runners and dev sandboxes
/// degrade.
fn host_resolvable_el_major() -> Option<u32> {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |key: &str| {
        text.lines().map(str::trim).find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k == key).then(|| v.trim_matches(|c| c == '"' || c == '\'').to_owned())
        })
    };
    let (id, id_like) = (field("ID"), field("ID_LIKE"));
    let (platform_id, version_id) = (field("PLATFORM_ID"), field("VERSION_ID"));
    let family = id
        .as_deref()
        .is_some_and(|id| matches!(id, "rhel" | "rocky" | "almalinux" | "centos"))
        || id_like
            .as_deref()
            .is_some_and(|like| like.split_whitespace().any(|t| t == "rhel"))
        || platform_id
            .as_deref()
            .is_some_and(|p| p.starts_with("platform:el"));
    if !family {
        return None;
    }
    let major = platform_id
        .as_deref()
        .and_then(|p| p.strip_prefix("platform:el"))
        .and_then(|n| n.parse::<u32>().ok())
        .or_else(|| {
            version_id
                .as_deref()
                .and_then(|v| v.split('.').next())
                .and_then(|maj| maj.parse::<u32>().ok())
        })?;
    matches!(major, 8..=10).then_some(major)
}

/// #519: `--target rhel9` must attach exact STIG `ControlRef`s to the
/// `service-status`, `fapolicyd-package`, and `misconfiguration` checks.
/// Omitting `--target` (the default `auto`) is HOST-DEPENDENT and both arms
/// are asserted: on a resolvable EL host (the distro-CI containers) the three
/// STIG-family checks must auto-attach controls keyed to the host's major and
/// every other check must still carry none; on any other host auto degrades
/// and NO check may carry a `controls` key at all. Combined into one test
/// (the target-explicit assertions run first) so a not-yet-wired
/// implementation fails immediately rather than passing vacuously on the
/// omitted-target half alone.
#[test]
fn doctor_target_rhel9_attaches_exact_stig_controls_and_omitted_target_follows_host() {
    let with_target = bin()
        .args([
            "fapolicyd",
            "doctor",
            "--target",
            "rhel9",
            "--format",
            "json",
        ])
        .output()
        .expect("binary ran");
    let stdout = String::from_utf8(with_target.stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let checks = v["checks"].as_array().expect("checks array");

    let find = |name: &str| -> &serde_json::Value {
        checks
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing check {name:?} in {stdout}"))
    };

    let service = find("service-status");
    assert_eq!(
        service["controls"][0]["id"].as_str(),
        Some("RHEL-09-433015"),
        "service-status must carry the Enabled STIG control under --target rhel9; \
         full output: {stdout}"
    );
    assert_eq!(service["controls"][0]["alias"].as_str(), Some("V-258090"));

    let package = find("fapolicyd-package");
    assert_eq!(
        package["controls"][0]["id"].as_str(),
        Some("RHEL-09-433010"),
        "fapolicyd-package must carry the Installed STIG control under --target rhel9; \
         full output: {stdout}"
    );

    let misconfig = find("misconfiguration");
    assert_eq!(
        misconfig["controls"][0]["id"].as_str(),
        Some("RHEL-09-433016"),
        "misconfiguration must carry the DenyAll STIG control under --target rhel9; \
         full output: {stdout}"
    );

    // Without --target the default `auto` consults this host's
    // /etc/os-release (#519: doctor auto-detects). Host-dependent, so assert
    // both arms honestly instead of assuming a non-EL host (the assumption
    // that broke on the distro-CI containers, where auto RESOLVES).
    let without_target = bin()
        .args(["fapolicyd", "doctor", "--format", "json"])
        .output()
        .expect("binary ran");
    let stdout2 = String::from_utf8(without_target.stdout).expect("utf8");
    let v2: serde_json::Value = serde_json::from_str(&stdout2).expect("valid JSON");
    let checks2 = v2["checks"].as_array().expect("checks array");
    let stig_checks = ["service-status", "fapolicyd-package", "misconfiguration"];
    match host_resolvable_el_major() {
        Some(major) => {
            let prefix = format!("RHEL-{major:02}-");
            for c in checks2 {
                let name = c["name"].as_str().expect("check name");
                if stig_checks.contains(&name) {
                    let id = c["controls"][0]["id"].as_str().unwrap_or_else(|| {
                        panic!(
                            "on a resolvable EL{major} host, omitted --target must \
                             auto-attach a STIG control to {name}; got {c} in {stdout2}"
                        )
                    });
                    assert!(
                        id.starts_with(&prefix),
                        "auto-detected controls on {name} must be keyed to this \
                         host's major ({prefix}*), got {id} in {stdout2}"
                    );
                } else {
                    assert!(
                        c.get("controls").is_none(),
                        "non-STIG check {name} must carry no controls even when \
                         auto resolves, got {c} in {stdout2}"
                    );
                }
            }
        }
        None => {
            for c in checks2 {
                assert!(
                    c.get("controls").is_none(),
                    "omitted --target must carry no controls key on any check \
                     when auto degrades, got {c} in {stdout2}"
                );
            }
        }
    }
}
