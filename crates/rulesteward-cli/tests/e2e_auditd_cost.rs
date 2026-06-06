//! End-to-end CLI tests for `rulesteward auditd cost --format csv` (#64).
//!
//! Drives the whole pipeline: argv -> clap parse -> `cost()` -> auditd rules
//! parse -> per-rule cost -> CSV render -> exit code. The locked CSV policy
//! (#64) is per-rule rows ONLY: the aggregate totals / band / confidence stay
//! in the JSON and human surfaces, never in the CSV.

use assert_cmd::Command;
use std::io::Write as _;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

/// `auditd cost --rules F --format csv` over a 2-rule file exits 0 and emits a
/// flat per-rule CSV: the stable header plus exactly one row per rule, with no
/// totals / confidence summary leaking into the CSV surface.
#[test]
fn auditd_cost_csv_is_per_rule_table_no_totals_exit_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut f = std::fs::File::create(&rules).expect("create rules file");
    writeln!(f, "-w /etc/passwd -p wa -k identity").expect("write rule 1");
    writeln!(f, "-w /etc/shadow -p wa -k identity").expect("write rule 2");
    f.flush().expect("flush");

    let assert = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--format", "csv"])
        .assert()
        .success();
    let out = assert.get_output();
    assert_eq!(out.status.code(), Some(0), "cost --format csv must exit 0");

    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert!(
        stdout.ends_with('\n'),
        "csv output must end with a trailing newline"
    );

    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some(
            "rule,key,tier,direction,eventsPerDayLow,eventsPerDayTypical,eventsPerDayHigh,gbPerDay"
        ),
        "first line must be the stable CSV header"
    );
    let rows: Vec<&str> = lines.collect();
    assert_eq!(
        rows.len(),
        2,
        "two rules must produce exactly two CSV rows (no totals row)"
    );

    // Per-column value check on a data row (defense-in-depth at the e2e layer:
    // a column swap would otherwise be caught only by the inline unit test).
    // Both fixture rules are additive watches keyed `identity`.
    let cols: Vec<&str> = rows[0].split(',').collect();
    assert_eq!(
        cols.len(),
        8,
        "each data row must have 8 columns: {}",
        rows[0]
    );
    assert_eq!(cols[1], "identity", "column 2 must be the rule key");
    assert_eq!(cols[3], "additive", "column 4 must be the direction");
    assert!(
        cols[7].parse::<f64>().is_ok(),
        "gbPerDay column must parse as a number: {}",
        cols[7]
    );

    // The aggregate/confidence surface must NOT appear in the CSV.
    assert!(
        !stdout.contains("CONFIDENCE"),
        "CSV must not carry the human CONFIDENCE line"
    );
    assert!(
        !stdout.contains("Estimated"),
        "CSV must not carry the human Estimated totals lines"
    );
}
