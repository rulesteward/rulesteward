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

/// #112 (non-breaking byte band): the ASSUMED-rate JSON total folds the per-event
/// byte-size band (ENRICHED low 760 / typical 1200 / high 2300) into its low/high
/// edges, while the v1 schema surface stays stable. For a single additive rule the
/// totals equal that rule's band, so we can pin the exact byte edge applied to each
/// edge: total.gbPerDay{Low,Typical,High} == eventsPerDay.{low,typical,high} *
/// {760,1200,2300} / 1e9. `bytesPerEvent` stays the scalar 1200 and `schemaVersion`
/// stays 1 (the non-breaking contract).
#[test]
fn auditd_cost_json_assumed_total_folds_byte_band_schema_stable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut f = std::fs::File::create(&rules).expect("create rules file");
    writeln!(f, "-a always,exit -F arch=b64 -S execve -k exec").expect("write rule");
    f.flush().expect("flush");

    let assert = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // v1 schema surface unchanged.
    assert_eq!(
        v["schemaVersion"], 1,
        "schemaVersion must stay 1 (non-breaking)"
    );
    assert_eq!(
        v["assumptions"]["bytesPerEvent"], 1200,
        "bytesPerEvent must stay the scalar typical 1200"
    );

    let ev = &v["rules"][0]["eventsPerDay"];
    let ev_low = ev["low"].as_f64().expect("ev low");
    let ev_typ = ev["typical"].as_f64().expect("ev typical");
    let ev_high = ev["high"].as_f64().expect("ev high");

    let totals = &v["totals"];
    let g_low = totals["gbPerDayLow"].as_f64().expect("gb low");
    let g_typ = totals["gbPerDayTypical"].as_f64().expect("gb typical");
    let g_high = totals["gbPerDayHigh"].as_f64().expect("gb high");

    // Exact byte edge applied per edge (single rule -> totals == this rule's band).
    assert!(
        (g_low - ev_low * 760.0 / 1e9).abs() < 1e-12,
        "gbPerDayLow must apply byte low 760; ev_low={ev_low} got={g_low}"
    );
    assert!(
        (g_typ - ev_typ * 1200.0 / 1e9).abs() < 1e-12,
        "gbPerDayTypical must apply byte typical 1200; ev_typ={ev_typ} got={g_typ}"
    );
    assert!(
        (g_high - ev_high * 2300.0 / 1e9).abs() < 1e-12,
        "gbPerDayHigh must apply byte high 2300; ev_high={ev_high} got={g_high}"
    );
    // And the band is genuinely wider than a flat-1200 band would be.
    assert!(
        g_high > ev_high * 1200.0 / 1e9,
        "high edge must exceed the old flat-1200 high (byte spread widened it)"
    );
}

/// #112 measured-mode default: the MEASURED --from-log JSON total keeps a single
/// typical byte (no byte-band widening), so an exact measured count yields a
/// COLLAPSED band (gbPerDayLow == gbPerDayTypical == gbPerDayHigh). Guards the
/// `match rate_source` wiring so a future refactor cannot silently route the
/// measured total through the banded path.
#[test]
fn auditd_cost_json_measured_total_stays_collapsed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut rf = std::fs::File::create(&rules).expect("create rules file");
    writeln!(rf, "-a always,exit -F arch=b64 -S execve -k exec").expect("write rule");
    rf.flush().expect("flush");

    // Synthetic audit.log: three SYSCALL records tagged key="exec" -> measured rate 3.
    let log = dir.path().join("audit.log");
    let mut lf = std::fs::File::create(&log).expect("create log");
    for i in 0..3 {
        writeln!(
            lf,
            "type=SYSCALL msg=audit(178045344{i}.000:42{i}): arch=c000003e syscall=59 \
             success=yes exit=0 comm=\"true\" exe=\"/usr/bin/true\" key=\"exec\""
        )
        .expect("write log line");
    }
    lf.flush().expect("flush");

    let assert = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--from-log"])
        .arg(&log)
        .args(["--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(
        v["assumptions"]["rateSource"], "measured",
        "rateSource must be measured under --from-log"
    );
    assert_eq!(v["schemaVersion"], 1, "schemaVersion must stay 1");
    assert_eq!(v["assumptions"]["bytesPerEvent"], 1200);

    let totals = &v["totals"];
    let g_low = totals["gbPerDayLow"].as_f64().expect("gb low");
    let g_typ = totals["gbPerDayTypical"].as_f64().expect("gb typical");
    let g_high = totals["gbPerDayHigh"].as_f64().expect("gb high");

    // Measured count is exact (3 events) -> band must stay collapsed, NOT widened.
    assert!(
        (g_low - g_high).abs() < 1e-12 && (g_low - g_typ).abs() < 1e-12,
        "measured total band must be collapsed; low={g_low} typ={g_typ} high={g_high}"
    );
    // Concrete value: 3 events * 1200 B / 1e9 = 3.6e-6 GB/day.
    assert!(
        (g_typ - 3.0 * 1200.0 / 1e9).abs() < 1e-12,
        "measured gbPerDayTypical = 3 * 1200 / 1e9; got {g_typ}"
    );
}

/// #112 functional-smoke: the ASSUMED-mode HUMAN renderer surfaces the WIDENED band
/// edges, and they are the SAME values as the JSON total (cross-surface consistency).
/// The human band suffix is the user-visible face of the #112 change, so pin it
/// directly rather than only via the JSON total.
#[test]
fn auditd_cost_human_assumed_band_suffix_matches_json_widened() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut f = std::fs::File::create(&rules).expect("create rules file");
    writeln!(f, "-a always,exit -F arch=b64 -S execve -k exec").expect("write rule");
    f.flush().expect("flush");

    // JSON total (the machine surface) for the same ruleset.
    let json = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--format", "json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(json.get_output().stdout.clone()).expect("utf8"))
            .expect("valid JSON");
    let g_low = v["totals"]["gbPerDayLow"].as_f64().expect("gb low");
    let g_high = v["totals"]["gbPerDayHigh"].as_f64().expect("gb high");

    // HUMAN surface for the same ruleset.
    let human = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--format", "human"])
        .assert()
        .success();
    let out = String::from_utf8(human.get_output().stdout.clone()).expect("utf8");

    // The human GB/day band suffix prints the same low/high as the JSON total,
    // formatted to 4 decimals (render_human's "(band {:.4} - {:.4} GB/day)").
    let expected = format!("(band {g_low:.4} - {g_high:.4} GB/day)");
    assert!(
        out.contains(&expected),
        "human band suffix must match the JSON total edges: expected {expected:?} in:\n{out}"
    );
    // And the band is genuinely widened (high strictly above low) in assumed mode.
    assert!(
        g_high > g_low,
        "assumed-mode band must be non-collapsed (widened): low={g_low} high={g_high}"
    );
    // The header names the byte BAND in assumed mode (not just the typical), so a
    // reader is not surprised the GB/day band is wider than ~1200 alone implies.
    assert!(
        out.contains("760-2300 B/event band"),
        "assumed-mode header must name the byte band; got:\n{out}"
    );
}

/// #112: in MEASURED mode the total uses a single typical byte, so the header names
/// only the typical (~1200 B/event) and must NOT advertise the assumed byte band.
#[test]
fn auditd_cost_human_measured_header_names_only_typical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut rf = std::fs::File::create(&rules).expect("create rules file");
    writeln!(rf, "-a always,exit -F arch=b64 -S execve -k exec").expect("write rule");
    rf.flush().expect("flush");
    let log = dir.path().join("audit.log");
    let mut lf = std::fs::File::create(&log).expect("create log");
    writeln!(
        lf,
        "type=SYSCALL msg=audit(1780453442.924:4213): syscall=59 success=yes key=\"exec\""
    )
    .expect("write log line");
    lf.flush().expect("flush");

    let assert = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--from-log"])
        .arg(&log)
        .args(["--format", "human"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    assert!(
        out.contains("~1200 B/event"),
        "measured header must name the typical byte; got:\n{out}"
    );
    assert!(
        !out.contains("B/event band"),
        "measured header must NOT advertise the assumed byte band; got:\n{out}"
    );
    // #271-B: the CONFIDENCE line must say the per-event SIZE is still assumed,
    // so an operator knows the measured RATE does not make the byte size measured.
    assert!(
        out.contains("SIZE still assumed"),
        "measured CONFIDENCE must note the per-event size is still assumed; got:\n{out}"
    );
}
