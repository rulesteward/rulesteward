//! End-to-end CLI tests: exercise the built binary fully offline (via
//! `check` / `derive` with `--fixtures DIR`) and assert the exit-code
//! contract - 0 in sync, 1 on drift, 2 on error - mirroring
//! `tools/fapolicyd-attr-update/tests/cli.rs`.
//!
//! `--fixtures DIR` expects the committed `tests/fixtures/` shape (see
//! `src/main.rs`'s module doc): `DIR/3bfa048/{msg_typetab.h,audit-records.h}`
//! + `DIR/linux-v6.6/audit.h` at today's pins.
//!
//! PROVENANCE CONTRACT: the offline `--fixtures` path must verify each
//! file's bytes against the config's sha256 pins, exactly like the network
//! path - the PR gate runs `check --fixtures` on the committed fixtures, so
//! an unverified offline read is a fail-OPEN (silently corrupted/stale
//! fixtures would pass the gate). Consequently every test that feeds
//! DOCTORED bytes writes its own pin-matching `refs.toml` (hashes computed
//! test-locally, independent of the impl's own hex encoder) and passes it
//! via `--config`; tests exercising the REAL committed bytes use the default
//! committed `msgtype-refs.toml`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

const MSG_TYPETAB: &str = include_str!("fixtures/3bfa048/msg_typetab.h");
const AUDIT_RECORDS: &str = include_str!("fixtures/3bfa048/audit-records.h");
const KERNEL_AUDIT_H: &str = include_str!("fixtures/linux-v6.6/audit.h");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_auditd-msgtype-update")
}

/// Test-local sha256 hex - computed DIRECTLY via the sha2 crate, deliberately
/// NOT routed through the crate's own `source::verify_sha256`/hex helpers, so
/// a broken impl-side hex encoder cannot make a test's pins
/// self-consistently wrong (both sides agreeing on garbage).
fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Write a `tests/fixtures/`-shaped root
/// (`<root>/3bfa048/{msg_typetab.h,audit-records.h}` +
/// `<root>/linux-v6.6/audit.h`) to a fresh temp directory, using the REAL
/// committed fixture content for every file except the `(dir, filename)`
/// pairs present in `overrides`. Also writes `<root>/refs.toml`: a
/// `msgtype-refs.toml`-shaped config whose sha256 pins are computed
/// (test-locally) from the bytes actually written, so a test feeding
/// doctored fixture content can pass `--config <root>/refs.toml` and keep
/// the provenance gate green while exercising a downstream behavior (drift /
/// conflict / parse failure). Returns the root.
fn write_fixtures_root(tag: &str, overrides: &HashMap<(&str, &str), String>) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("auditd-msgtype-cli-{}-{tag}", std::process::id()));
    let real: [(&str, &str, &str); 3] = [
        ("3bfa048", "msg_typetab.h", MSG_TYPETAB),
        ("3bfa048", "audit-records.h", AUDIT_RECORDS),
        ("linux-v6.6", "audit.h", KERNEL_AUDIT_H),
    ];
    let mut hashes: HashMap<(&str, &str), String> = HashMap::new();
    for (dir, file, content) in real {
        let d = root.join(dir);
        std::fs::create_dir_all(&d).expect("create fixture dir");
        let body = overrides
            .get(&(dir, file))
            .map(String::as_str)
            .unwrap_or(content);
        std::fs::write(d.join(file), body).expect("write fixture file");
        hashes.insert((dir, file), sha256_hex(body));
    }

    // Mirror the committed msgtype-refs.toml's shape (real commit + tag; only
    // the hashes track the possibly-overridden bytes written above).
    let refs = format!(
        "[audit-userspace]\n\
         commit = \"3bfa048\"\n\
         msg_typetab_sha256 = \"{}\"\n\
         audit_records_sha256 = \"{}\"\n\
         \n\
         [kernel]\n\
         tag = \"v6.6\"\n\
         audit_h_sha256 = \"{}\"\n",
        hashes[&("3bfa048", "msg_typetab.h")],
        hashes[&("3bfa048", "audit-records.h")],
        hashes[&("linux-v6.6", "audit.h")],
    );
    std::fs::write(root.join("refs.toml"), refs).expect("write refs.toml");
    root
}

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// GREEN baseline: the real, unmutated committed fixtures must check clean
/// end-to-end through the full CLI (arg parsing + the DEFAULT committed
/// `msgtype-refs.toml` + file read + provenance pins + parse + resolve +
/// drift compare) - a superset of what the library-level `registry` tests
/// cover (those call the derivation functions directly and skip `main.rs`'s
/// own glue entirely).
#[test]
fn check_real_fixtures_report_no_drift() {
    let root = write_fixtures_root("insync", &HashMap::new());
    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(0),
        "in-sync fixtures must exit 0; stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("OK (0 drift"), "stdout={stdout}");
}

/// Drift RED-case (the frozen contract test): rename ONE `_S` row's name
/// (`"SYSCALL"` -> `"SYSCALLX"`, a single quoted occurrence in the fixture)
/// in `msg_typetab.h` only. The derived base table then carries `SYSCALLX`
/// where the shipped table carries `SYSCALL` - name-level drift in the base
/// table. `check` must report DRIFT, exit 1, and the report must name the
/// offending entry. The test's own pin-matching `--config` keeps the
/// provenance gate green so the DRIFT path (not the hash-mismatch path) is
/// what is exercised.
#[test]
fn check_doctored_entry_reports_drift_and_exits_1() {
    let mut overrides = HashMap::new();
    let doctored = MSG_TYPETAB.replace("\"SYSCALL\"", "\"SYSCALLX\"");
    assert_ne!(
        doctored, MSG_TYPETAB,
        "sanity: the rename must actually change the fixture content"
    );
    overrides.insert(("3bfa048", "msg_typetab.h"), doctored);
    let root = write_fixtures_root("doctored-syscall", &overrides);
    let config = root.join("refs.toml");

    let (code, stdout, stderr) = run(&[
        "check",
        "--fixtures",
        &root.to_string_lossy(),
        "--config",
        &config.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "a renamed table row must exit 1; stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("SYSCALL"),
        "the drift report must name the offending entry (SYSCALL/SYSCALLX): stdout={stdout}"
    );
}

/// PROVENANCE fail-closed, audit-userspace half: fixture bytes that PARSE
/// identically to the committed ones (the tamper is a trailing `//` comment
/// line, which the typetab scan ignores - the derived tables are identical)
/// but do NOT match the default `msgtype-refs.toml` sha256 pins must fail
/// CLOSED with exit 2 and a message naming the hash mismatch. Without
/// offline verification this is a fail-OPEN: `check --fixtures` (the PR
/// gate's invocation) would report "OK (0 drift)" on corrupted/stale
/// fixture bytes.
#[test]
fn check_tampered_typetab_bytes_fail_closed_exits_2() {
    let mut overrides = HashMap::new();
    let tampered = format!("{MSG_TYPETAB}// locally tampered: not the pinned upstream bytes\n");
    overrides.insert(("3bfa048", "msg_typetab.h"), tampered);
    let root = write_fixtures_root("tampered-typetab", &overrides);
    // Deliberately NO --config: the DEFAULT committed msgtype-refs.toml pins
    // the real upstream bytes, which the tampered file no longer matches.

    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "typetab bytes that mismatch the committed sha256 pins must fail \
         closed (exit 2), even though they parse to the identical tables; \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("sha256"),
        "the error must name the hash mismatch: stderr={stderr}"
    );
}

/// PROVENANCE fail-closed, kernel half (the NEW surface the third fixture
/// adds): tampered `linux-v6.6/audit.h` bytes against the committed pins
/// must fail closed with exit 2 exactly like the audit-userspace files - the
/// kernel header resolves 60 of the 197 constants, so an unverified kernel
/// fixture is the same fail-open with a different file name.
#[test]
fn check_tampered_kernel_header_bytes_fail_closed_exits_2() {
    let mut overrides = HashMap::new();
    let tampered = format!("{KERNEL_AUDIT_H}/* locally tampered: not the pinned tag bytes */\n");
    overrides.insert(("linux-v6.6", "audit.h"), tampered);
    let root = write_fixtures_root("tampered-kernel", &overrides);
    // Deliberately NO --config, as above.

    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "kernel-header bytes that mismatch the committed sha256 pin must \
         fail closed (exit 2); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("sha256"),
        "the error must name the hash mismatch: stderr={stderr}"
    );
}

/// CROSS-SOURCE CONFLICT hard error: doctor `audit-records.h`'s
/// `#define AUDIT_BPF 1334` to `1399` while the kernel header still says
/// `1334`. AUDIT_BPF is referenced by the typetab (`_S(AUDIT_BPF, "BPF")`),
/// so resolution now sees the same constant with two different numbers -
/// `check` must exit 2 (a hard error naming the constant), NOT exit 0 or 1:
/// the tool must never silently prefer one source on a conflict. The
/// test-local pin-matching `--config` keeps the sha gate green so the
/// CONFLICT path is what is exercised.
#[test]
fn check_conflicting_number_across_sources_exits_2() {
    let mut overrides = HashMap::new();
    let doctored = AUDIT_RECORDS.replace(
        "#define AUDIT_BPF               1334",
        "#define AUDIT_BPF               1399",
    );
    assert_ne!(
        doctored, AUDIT_RECORDS,
        "sanity: the AUDIT_BPF renumber must actually change the fixture"
    );
    overrides.insert(("3bfa048", "audit-records.h"), doctored);
    let root = write_fixtures_root("conflict-bpf", &overrides);
    let config = root.join("refs.toml");

    let (code, stdout, stderr) = run(&[
        "check",
        "--fixtures",
        &root.to_string_lossy(),
        "--config",
        &config.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(2),
        "a cross-source number conflict on a referenced constant must be a \
         hard error (exit 2), never a silent single-source preference; \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("AUDIT_BPF"),
        "the error must name the conflicting constant: stderr={stderr}"
    );
}

/// A `--fixtures` root missing a pinned source entirely (the kernel
/// directory absent) must also fail closed (exit 2), not silently derive
/// from the two files that do exist and report a partial result.
#[test]
fn check_missing_fixture_path_fails_closed_exits_2() {
    let root = std::env::temp_dir().join(format!(
        "auditd-msgtype-cli-{}-missing-kernel",
        std::process::id()
    ));
    let d = root.join("3bfa048");
    std::fs::create_dir_all(&d).expect("create dir");
    std::fs::write(d.join("msg_typetab.h"), MSG_TYPETAB).expect("write");
    std::fs::write(d.join("audit-records.h"), AUDIT_RECORDS).expect("write");
    // linux-v6.6/ deliberately absent.

    let (code, stdout, stderr) = run(&["check", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "a missing pinned-source fixture path must fail closed (exit 2); \
         stdout={stdout} stderr={stderr}"
    );
}

/// `derive` must print the ACTUAL derived tables for review: both counts
/// (189 base / 8 AppArmor) and real entry content from both tables,
/// including a kernel-header-resolved number (2507 for VIRT_MIGRATE_OUT
/// comes from resolution, not from the typetab file, so a derive that skips
/// resolution cannot print it).
#[test]
fn derive_prints_both_derived_tables() {
    let root = write_fixtures_root("derive-content", &HashMap::new());
    let (code, stdout, stderr) = run(&["derive", "--fixtures", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains("189"),
        "derive output must carry the base-table count: stdout={stdout}"
    );
    for token in ["VIRT_MIGRATE_OUT", "2507", "APPARMOR_KILL", "1507"] {
        assert!(
            stdout.contains(token),
            "derive output must carry {token:?}: stdout={stdout}"
        );
    }
}

/// Help exits 0 with usage on stderr naming both subcommands and both flags
/// (mirrors tools/fapolicyd-attr-update/tests/cli.rs's help pin).
#[test]
fn help_exits_0_and_names_the_contract() {
    let (code, _stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0; stderr={stderr}");
    for token in ["check", "derive", "--fixtures", "--config"] {
        assert!(
            stderr.contains(token),
            "help output must mention {token:?}: stderr={stderr}"
        );
    }
}

/// An unknown subcommand is a user error: exit 2 with a message naming it.
#[test]
fn unknown_subcommand_exits_2() {
    let (code, _stdout, stderr) = run(&["frobnicate"]);
    assert_eq!(code, Some(2), "unknown subcommand must exit 2");
    assert!(
        stderr.contains("frobnicate"),
        "the error must name the unknown subcommand: stderr={stderr}"
    );
}
