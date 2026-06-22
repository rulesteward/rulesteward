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

/// #307 measured-mode sizing: the MEASURED --from-log JSON total is sized by the
/// log's REAL average bytes/event (not the flat 1200), and because the event count
/// is exact the band stays COLLAPSED (gbPerDayLow == gbPerDayTypical == gbPerDayHigh).
/// Guards both the #307 byte sizing AND the #112 collapse property (a future refactor
/// must not route the measured total through the banded/widening path).
#[test]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
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

    // #307: the per-event SIZE is now MEASURED from the log, not the flat 1200.
    // The fixture's 3 events are short single-record SYSCALLs (no companions), so
    // bytes["exec"] == the whole file (every line is a key-bearing distinct serial,
    // and on-disk bytes = sum of line.len()+1 = file size for a clean log). The
    // reported bytesPerEvent is round(total_bytes / events), well below the old 1200.
    let total_bytes = std::fs::metadata(&log).expect("stat log").len() as f64;
    let expected_bpe = (total_bytes / 3.0).round() as u64;
    assert_eq!(
        v["assumptions"]["bytesPerEvent"], expected_bpe,
        "bytesPerEvent must be the measured average (total_bytes/events), not 1200"
    );
    assert!(
        expected_bpe < 1200,
        "sanity: these short synthetic events average well under the old flat 1200 \
         (proves the size is measured, not hardcoded); got {expected_bpe}"
    );

    let totals = &v["totals"];
    let g_low = totals["gbPerDayLow"].as_f64().expect("gb low");
    let g_typ = totals["gbPerDayTypical"].as_f64().expect("gb typical");
    let g_high = totals["gbPerDayHigh"].as_f64().expect("gb high");

    // Measured count is exact (3 events) -> band must stay collapsed, NOT widened.
    assert!(
        (g_low - g_high).abs() < 1e-12 && (g_low - g_typ).abs() < 1e-12,
        "measured total band must be collapsed; low={g_low} typ={g_typ} high={g_high}"
    );
    // Concrete value: measured total gb/day = total on-disk bytes / 1e9.
    assert!(
        (g_typ - total_bytes / 1e9).abs() < 1e-12,
        "measured gbPerDayTypical = total_bytes / 1e9; got {g_typ}, total_bytes={total_bytes}"
    );
    // And it genuinely moved off the old flat-1200 total.
    assert!(
        (g_typ - 3.0 * 1200.0 / 1e9).abs() > 1e-12,
        "measured total must no longer equal the flat 3*1200/1e9 figure; got {g_typ}"
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

/// #307: in MEASURED mode the header names the log's REAL average bytes/event
/// (measured, not the flat ~1200) and must NOT advertise the assumed byte band; the
/// CONFIDENCE line states the per-event size is MEASURED, not still assumed.
#[test]
fn auditd_cost_human_measured_header_names_measured_size() {
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

    // #307: the header now names the MEASURED average byte size (the real event
    // size), not the flat ~1200 assumption. The single short synthetic event is one
    // key-bearing serial, so bytes["exec"] == the file size and the average == that.
    let file_size = std::fs::metadata(&log).expect("stat log").len();
    let expected_note = format!("~{file_size} B/event measured");
    assert!(
        out.contains(&expected_note),
        "measured header must name the measured average byte size ({expected_note}); got:\n{out}"
    );
    assert!(
        file_size < 1200,
        "sanity: the synthetic event is smaller than the old flat 1200, proving the \
         size is measured; file_size={file_size}"
    );
    assert!(
        !out.contains("B/event band"),
        "measured header must NOT advertise the assumed byte band; got:\n{out}"
    );
    // #307: the CONFIDENCE line must now state the per-event SIZE is MEASURED from
    // the log, and must NOT keep the old "still assumed" caveat (#271-B).
    assert!(
        out.contains("SIZE measured"),
        "measured CONFIDENCE must note the per-event size is measured; got:\n{out}"
    );
    assert!(
        !out.contains("SIZE still assumed"),
        "measured CONFIDENCE must no longer claim the per-event size is assumed; got:\n{out}"
    );
}

/// #307 strengthening (post-GREEN adversarial loop): when the ruleset's key matches
/// NO measured events, the additive event total is 0, so the measured average
/// bytes/event is undefined and falls back to the locked 1200 scalar; the cost is 0
/// regardless. Guards the `total_additive_events > 0.0` fallback branch.
#[test]
fn auditd_cost_json_measured_zero_event_key_falls_back_to_scalar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("audit.rules");
    let mut rf = std::fs::File::create(&rules).expect("create rules file");
    writeln!(rf, "-a always,exit -F arch=b64 -S execve -k exec").expect("write rule");
    rf.flush().expect("flush");

    // The log has an event, but under a DIFFERENT key -> the "exec" rule sees 0.
    let log = dir.path().join("audit.log");
    let mut lf = std::fs::File::create(&log).expect("create log");
    writeln!(
        lf,
        "type=SYSCALL msg=audit(1780453442.924:9001): syscall=59 success=yes key=\"other\""
    )
    .expect("write log line");
    lf.flush().expect("flush");

    let assert = bin()
        .args(["auditd", "cost", "--rules"])
        .arg(&rules)
        .args(["--from-log"])
        .arg(&log)
        .args(["--format", "json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(assert.get_output().stdout.clone()).expect("utf8"))
            .expect("valid JSON");

    assert_eq!(v["assumptions"]["rateSource"], "measured");
    // No additive events matched -> fall back to the locked 1200 scalar.
    assert_eq!(
        v["assumptions"]["bytesPerEvent"], 1200,
        "zero matched events must fall back to the locked scalar, not 0/NaN"
    );
    // And the volume is genuinely zero (the rule matched nothing).
    assert!(
        v["totals"]["gbPerDayTypical"]
            .as_f64()
            .expect("gb typ")
            .abs()
            < 1e-15,
        "no matched events => zero volume"
    );
}

/// #307 strengthening (post-GREEN adversarial loop): a SUPPRESSIVE rule (never /
/// exclude) must contribute ZERO bytes to the measured total, even when its key
/// matches events in the log. Guards the `Direction::Additive` filter on the summed
/// measured bytes -- without it, a never rule's key bytes would inflate the dollar
/// figure. Differential: adding a never rule whose key HAS log events must leave the
/// total (and the per-event average) unchanged.
#[test]
fn auditd_cost_json_measured_suppressive_rule_adds_zero_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");

    let additive_only = dir.path().join("a.rules");
    let mut fa = std::fs::File::create(&additive_only).expect("create rules file");
    writeln!(fa, "-a always,exit -F arch=b64 -S execve -k exec").expect("rule");
    fa.flush().expect("flush");

    let with_never = dir.path().join("b.rules");
    let mut fb = std::fs::File::create(&with_never).expect("create rules file");
    writeln!(fb, "-a always,exit -F arch=b64 -S execve -k exec").expect("rule 1");
    writeln!(fb, "-a never,exit -F arch=b64 -S execve -k noise").expect("rule 2 (suppressive)");
    fb.flush().expect("flush");

    // Log carries BOTH "exec" events and (more) "noise" events.
    let log = dir.path().join("audit.log");
    let mut lf = std::fs::File::create(&log).expect("create log");
    writeln!(
        lf,
        "type=SYSCALL msg=audit(1780453442.000:8001): syscall=59 success=yes key=\"exec\""
    )
    .expect("w");
    writeln!(
        lf,
        "type=SYSCALL msg=audit(1780453442.001:8002): syscall=59 success=yes key=\"noise\""
    )
    .expect("w");
    writeln!(
        lf,
        "type=SYSCALL msg=audit(1780453442.002:8003): syscall=59 success=yes key=\"noise\""
    )
    .expect("w");
    lf.flush().expect("flush");

    let run = |rules: &std::path::Path| -> serde_json::Value {
        let assert = bin()
            .args(["auditd", "cost", "--rules"])
            .arg(rules)
            .args(["--from-log"])
            .arg(&log)
            .args(["--format", "json"])
            .assert()
            .success();
        serde_json::from_str(&String::from_utf8(assert.get_output().stdout.clone()).expect("utf8"))
            .expect("valid JSON")
    };

    let a = run(&additive_only);
    let b = run(&with_never);

    let ga = a["totals"]["gbPerDayTypical"].as_f64().expect("ga");
    let gb = b["totals"]["gbPerDayTypical"].as_f64().expect("gb");
    assert!(
        (ga - gb).abs() < 1e-15,
        "a suppressive rule whose key has log events must not inflate the total; ga={ga} gb={gb}"
    );
    // The reported average is unchanged too (noise excluded from numerator + denom).
    assert_eq!(
        a["assumptions"]["bytesPerEvent"], b["assumptions"]["bytesPerEvent"],
        "suppressive noise events must not move the measured per-event average"
    );
}

/// #307 strengthening (post-GREEN adversarial loop): two ADDITIVE rules sharing one
/// key both look up that key's measured bytes, so the byte total SUMS the bucket
/// once per rule -- the locked per-key-sums model, identical to how the event count
/// already double-counts a shared key. The per-event average is unchanged; the
/// totals scale by the number of sharing rules. Guards that the byte total tracks
/// the count total under shared keys (total == sum of per-rule).
#[test]
fn auditd_cost_json_measured_shared_key_sums_per_rule() {
    let dir = tempfile::tempdir().expect("tempdir");

    let one = dir.path().join("one.rules");
    let mut f1 = std::fs::File::create(&one).expect("create rules file");
    writeln!(f1, "-a always,exit -F arch=b64 -S execve -k exec").expect("rule 1");
    f1.flush().expect("flush");

    let two = dir.path().join("two.rules");
    let mut f2 = std::fs::File::create(&two).expect("create rules file");
    writeln!(f2, "-a always,exit -F arch=b64 -S execve -k exec").expect("rule 1");
    writeln!(f2, "-a always,exit -F arch=b64 -S execveat -k exec").expect("rule 2 (shares key)");
    f2.flush().expect("flush");

    let log = dir.path().join("audit.log");
    let mut lf = std::fs::File::create(&log).expect("create log");
    for i in 0..3 {
        writeln!(
            lf,
            "type=SYSCALL msg=audit(178045344{i}.000:70{i}): syscall=59 success=yes key=\"exec\""
        )
        .expect("write log line");
    }
    lf.flush().expect("flush");

    let run = |rules: &std::path::Path| -> serde_json::Value {
        let assert = bin()
            .args(["auditd", "cost", "--rules"])
            .arg(rules)
            .args(["--from-log"])
            .arg(&log)
            .args(["--format", "json"])
            .assert()
            .success();
        serde_json::from_str(&String::from_utf8(assert.get_output().stdout.clone()).expect("utf8"))
            .expect("valid JSON")
    };

    let v1 = run(&one);
    let v2 = run(&two);

    // Same key, same events -> the per-event average must NOT change.
    assert_eq!(
        v1["assumptions"]["bytesPerEvent"], v2["assumptions"]["bytesPerEvent"],
        "a second rule sharing the key must not change the measured per-event average"
    );
    // But the TOTAL volume doubles: each additive rule contributes the bucket once.
    let g1 = v1["totals"]["gbPerDayTypical"].as_f64().expect("gb1");
    let g2 = v2["totals"]["gbPerDayTypical"].as_f64().expect("gb2");
    assert!(
        (g2 - 2.0 * g1).abs() < 1e-15,
        "two rules sharing a key must sum the bucket 2x (per-key-sums); g1={g1} g2={g2}"
    );
}
