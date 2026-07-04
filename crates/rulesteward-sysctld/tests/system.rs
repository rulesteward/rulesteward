//! Crate-level tests for `sysctl lint --system` cross-directory precedence
//! (issue #420), authored at the test-author barrier BEFORE the impl. These call
//! the frozen public entry `system::lint_system(root, target)` directly and are
//! RED against the Phase-0 stub (which always returns `(vec![], BTreeMap::new())`):
//! only a correct enumerate/mask/merge + `sysctld-W03` pass turns them green.
//!
//! # Ground truth (design doc, re-verified 2026-07-04)
//! `rulesteward-docs/2026-07-04-sysctld-cross-directory-precedence-420-design.md`,
//! grounded by a differential experiment in a Rocky Linux 9.7 container
//! (procps-ng 3.3.17), cross-checked against sysctl.d(5) and systemd 259
//! (`src/basic/conf-files.c`, `src/sysctl/sysctl.c`):
//!
//! 1. **Same-basename directory masking** (design section 2 point 1): search
//!    order highest to lowest precedence is `/etc/sysctl.d` > `/run/sysctl.d` >
//!    `/usr/local/lib/sysctl.d` > `/usr/lib/sysctl.d`. The FIRST directory to
//!    contain a given basename provides that file; the same basename in a lower
//!    directory is silently ignored (proven: `/usr/lib/sysctl.d/50-mask.conf`
//!    never appeared, masked by `/etc/.../50-mask.conf`).
//! 2. **Global lexicographic merge** (design section 2 point 2): every
//!    surviving file is merged and applied in LEXICOGRAPHIC (bytewise) basename
//!    order, REGARDLESS of directory. Proven: `/usr/lib/sysctl.d/90-late.conf`
//!    overrode `/etc/sysctl.d/10-early.conf` (a lower-precedence directory won
//!    on a later filename), and `9-sort.conf` beat `10-sort.conf` bytewise
//!    (`"10" < "9"`), which is lexicographic, NOT natural sort (section 2.1: the
//!    pre-decided `fagenrules_cmp` natural-sort plan was grounded-WRONG for
//!    sysctl and must NOT be used here).
//! 3. **`/etc/sysctl.conf` applier divergence** (design section 2 point 3):
//!    procps `sysctl --system` reads it DEAD LAST (always wins); systemd-sysctl
//!    does not read it natively - it participates only via the distro symlink
//!    `/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf`. If that symlink is
//!    absent, systemd does not apply `/etc/sysctl.conf` at all.
//!
//! `sysctld-W03` (design section 5) has three sub-cases: W03-a
//! (lower-precedence-directory override, suppressing the redundant W01 on the
//! dead line per section 3 point 4), W03-b (procps/systemd applier divergence),
//! and W03-c (a masked same-basename drop-in that sets a key no surviving file
//! applies, silently dropped).

use std::path::Path;

use rulesteward_core::Diagnostic;
use tempfile::tempdir;

/// Write `body` into `<root>/<rel>`, creating parent directories as needed.
fn write_at(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir -p");
    std::fs::write(&path, body).expect("write fixture file");
}

/// All `sysctld-W01` diagnostics.
fn w01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags.iter().filter(|d| d.code == "sysctld-W01").collect()
}

/// All `sysctld-W03` diagnostics.
fn w03s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags.iter().filter(|d| d.code == "sysctld-W03").collect()
}

// ---------------------------------------------------------------------------
// 1. Lexicographic sort proof (design section 2 items 2 & 4, section 2.1
//    decision): the merge order is BYTEWISE by basename, not natural sort.
// ---------------------------------------------------------------------------

#[test]
fn lexicographic_sort_beats_natural_sort_within_one_directory() {
    // Grounded fixture names/values from the container experiment: both files
    // live in the SAME directory (/usr/lib/sysctl.d) so directory precedence
    // cannot be the explanation for the winner - only the basename sort order
    // can. Bytewise, "10-sort.conf" < "9-sort.conf" (b'1' < b'9'), so
    // "9-sort.conf" is the LEXICOGRAPHICALLY LATEST basename and wins. A wrong
    // impl using natural/numeric sort (the pre-decided, grounded-wrong
    // `fagenrules_cmp` plan) would instead treat 10 > 9 and make "10-sort.conf"
    // win - the OPPOSITE result - which this test catches.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/10-sort.conf",
        "kernel.sysrq = 1\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/9-sort.conf",
        "kernel.sysrq = 0\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hits = w01s(&diags);
    let hit = hits
        .iter()
        .find(|d| d.message.contains("kernel.sysrq") || d.message.contains("kernel/sysrq"))
        .unwrap_or_else(|| {
            panic!(
                "expected a sysctld-W01 last-wins conflict for kernel.sysrq \
                 (9-sort.conf lexicographically beats 10-sort.conf); diags: {diags:?}"
            )
        });
    // The DEAD (overridden) assignment is the one anchored: 10-sort.conf's,
    // since 9-sort.conf sorts later and wins.
    assert!(
        hit.file.display().to_string().ends_with("10-sort.conf"),
        "the dead assignment must be 10-sort.conf (9-sort.conf wins \
         lexicographically, NOT numerically); got {:?}",
        hit.file
    );
    // The system pass REUSES `w01_last_wins` unchanged for a plain within-set
    // conflict (design section 4), whose exact message format
    // ("... (= {dead}) is overridden by the later assignment (= {win}) at
    // {file}:{line}") is read directly from parser.rs: dead value 1, winning
    // value 0, winner file 9-sort.conf line 1.
    assert!(
        hit.message.contains("(= 1)"),
        "the dead value (1, from 10-sort.conf) must appear: {}",
        hit.message
    );
    assert!(
        hit.message.contains("(= 0)"),
        "the winning value (0, from 9-sort.conf) must appear: {}",
        hit.message
    );
    assert!(
        hit.message.contains("9-sort.conf:1"),
        "the winning file+line (9-sort.conf:1) must appear: {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// 2. Same-basename directory masking (design section 2 point 1): the masked
//    file must be entirely invisible - never a source of any diagnostic.
// ---------------------------------------------------------------------------

#[test]
fn same_basename_directory_masking_hides_the_lower_precedence_file() {
    // Grounded fixture names from the container experiment: /etc/sysctl.d/
    // (highest precedence) and /usr/lib/sysctl.d/ (lowest precedence) both ship
    // a "50-mask.conf" that sets net.ipv4.ip_forward to DIFFERENT values. Per
    // the masking rule the /usr/lib copy must never be read into the merged
    // set at all - not even as a losing/dead assignment.
    //
    // A third file (/run/sysctl.d/05-early.conf) sets the SAME key to a THIRD
    // value, at a basename that sorts lexicographically BEFORE "50-mask.conf"
    // ('0' < '5'), so among the SURVIVING files {05-early.conf, 50-mask.conf}
    // the /etc copy of 50-mask.conf applies last and wins. Since /etc is also
    // the highest-precedence directory, this is a plain sysctld-W01 (design
    // section 5: "conflicts where the highest-precedence directory legitimately
    // wins remain plain W01"), letting this test PROVE (via the winning value
    // named in that W01) that the /etc copy - not the masked /usr/lib copy -
    // is the one that took effect.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/50-mask.conf",
        "net.ipv4.ip_forward = 1\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-mask.conf",
        "net.ipv4.ip_forward = 0\n",
    );
    write_at(
        root.path(),
        "run/sysctl.d/05-early.conf",
        "net.ipv4.ip_forward = 2\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    // The masked /usr/lib/sysctl.d/50-mask.conf must NEVER be referenced by any
    // diagnostic (of any code): it is silently masked, not merely "loses".
    for d in &diags {
        assert!(
            !d.file
                .display()
                .to_string()
                .contains("usr/lib/sysctl.d/50-mask.conf"),
            "the masked usr/lib/sysctl.d/50-mask.conf must be entirely invisible \
             (never appear as a diagnostic anchor); got: {d:?}"
        );
    }

    // Exactly one conflict for this key, between the surviving 05-early.conf
    // (dead) and the /etc copy of 50-mask.conf (winner, value 1 - NOT the
    // masked /usr/lib copy's value 0).
    let hits: Vec<&Diagnostic> = diags
        .iter()
        .filter(|d| d.message.contains("ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "exactly one diagnostic should reference ip_forward (the masked file \
         contributes none); got: {diags:?}"
    );
    let hit = hits[0];
    assert_eq!(
        hit.code, "sysctld-W01",
        "same-highest-dir win stays plain W01"
    );
    assert!(
        hit.file.display().to_string().ends_with("05-early.conf"),
        "the dead assignment is 05-early.conf's (sorts before 50-mask.conf); got {:?}",
        hit.file
    );
    // Same reused `w01_last_wins` message format as the lexicographic-sort test
    // above: dead value 2 (05-early.conf), winning value 1 (the /etc copy of
    // 50-mask.conf, NOT the masked /usr/lib copy's value 0), winner anchored at
    // the /etc path specifically.
    assert!(
        hit.message.contains("(= 2)"),
        "the dead value (2, from 05-early.conf) must appear: {}",
        hit.message
    );
    assert!(
        hit.message.contains("(= 1)"),
        "the winning value (1, from the /etc copy) must appear - NOT 0, the \
         masked /usr/lib copy's value: {}",
        hit.message
    );
    assert!(
        hit.message.contains("etc/sysctl.d/50-mask.conf:1"),
        "the winner must be anchored at the /etc copy specifically: {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// 3. W03-a: lower-precedence-directory override (design section 5, section 2
//    grounded proof).
// ---------------------------------------------------------------------------

#[test]
fn w03a_fires_when_a_lower_precedence_directory_wins_on_a_later_basename() {
    // Grounded fixture names/values straight from the container experiment:
    // /etc/sysctl.d/10-early.conf (HIGHEST-precedence dir, EARLIER basename) vs
    // /usr/lib/sysctl.d/90-late.conf (LOWEST-precedence dir, LATER basename).
    // "90-late.conf" > "10-early.conf" bytewise, so it applies last and wins -
    // despite sitting in the lowest-precedence search directory. This is
    // EXACTLY the surprise sysctld-W03-a exists to flag, and per design section
    // 3 point 4 the redundant plain W01 for this same dead line must be
    // SUPPRESSED (W03 fires instead, not both).
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-early.conf",
        "kernel.sysrq = 1\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/90-late.conf",
        "kernel.sysrq = 0\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let key_diags: Vec<&Diagnostic> = diags
        .iter()
        .filter(|d| d.message.contains("kernel.sysrq") || d.message.contains("kernel/sysrq"))
        .collect();
    assert_eq!(
        key_diags.len(),
        1,
        "the dead 10-early.conf line must fire W03-a ONLY - the redundant W01 \
         for the same line is suppressed (design section 3 point 4); got: {diags:?}"
    );
    let hit = key_diags[0];
    assert_eq!(
        hit.code, "sysctld-W03",
        "a lower-precedence directory winning on a later basename is W03-a, \
         not plain W01"
    );
    assert!(
        hit.file.display().to_string().ends_with("10-early.conf"),
        "W03-a anchors at the DEAD higher-precedence-directory assignment \
         (10-early.conf); got {:?}",
        hit.file
    );
    assert!(
        hit.message.contains("90-late.conf"),
        "the message must name the winning lower-precedence-directory file \
         (90-late.conf): {}",
        hit.message
    );
    assert!(
        hit.message.contains('0') && hit.message.contains('1'),
        "the message must state both the dead value (1) and the winning \
         value (0): {}",
        hit.message
    );

    // No other pass double-reports this same conflict under sysctld-W01.
    assert!(
        w01s(&diags).iter().all(|d| !d.message.contains("sysrq")),
        "W03-a must SUPPRESS the redundant plain W01 for the same dead line"
    );
}

// ---------------------------------------------------------------------------
// 4. W03-b: procps/systemd applier divergence via a missing 99-sysctl.conf
//    symlink (design section 2 point 3, section 5).
// ---------------------------------------------------------------------------

#[test]
fn w03b_fires_when_the_missing_symlink_makes_systemd_skip_sysctl_conf() {
    // Grounded in design section 2 point 3: procps `sysctl --system` reads
    // /etc/sysctl.conf DEAD LAST unconditionally, so it always wins (here:
    // net.ipv4.tcp_syncookies = 1). systemd-sysctl does NOT read
    // /etc/sysctl.conf natively; it participates ONLY via the distro symlink
    // /etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf. With NO such symlink and
    // no other file touching this key, systemd simply never applies this
    // setting at all - a real, observable procps/systemd divergence (one
    // applier sets the key, the other doesn't touch it).
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.ipv4.tcp_syncookies = 1\n",
    );
    // Deliberately NO /etc/sysctl.d/99-sysctl.conf symlink.

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = diags
        .iter()
        .find(|d| d.code == "sysctld-W03" && d.message.contains("tcp_syncookies"))
        .unwrap_or_else(|| {
            panic!(
                "expected a sysctld-W03 applier-divergence finding for \
                 tcp_syncookies (procps applies /etc/sysctl.conf dead-last; \
                 systemd never applies it without the 99-sysctl.conf symlink); \
                 diags: {diags:?}"
            )
        });
    assert!(
        hit.file.display().to_string().ends_with("sysctl.conf"),
        "W03-b anchors at the /etc/sysctl.conf assignment; got {:?}",
        hit.file
    );
    assert!(
        hit.message.to_lowercase().contains("systemd"),
        "the message must name systemd as the diverging applier: {}",
        hit.message
    );
    assert!(
        hit.message.contains('1'),
        "the message must state the procps-resolved value (1): {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// 5. W03-c: a masked same-basename drop-in sets a key no surviving file
//    applies, so it is silently dropped (design section 5).
// ---------------------------------------------------------------------------

#[test]
fn w03c_fires_when_a_masked_dropin_sets_a_key_nothing_else_applies() {
    // /etc/sysctl.d/50-mask.conf (survives) sets ONLY kernel.sysrq.
    // /usr/lib/sysctl.d/50-mask.conf (masked - same basename, lower dir) sets
    // kernel.sysrq (covered elsewhere, so masking it is not itself a "dropped
    // key") AND fs.protected_hardlinks, which NO surviving file sets anywhere.
    // Per design section 5, W03-c fires ONLY for fs.protected_hardlinks (its
    // canonical form is absent from the whole merged set), anchored at its real
    // line (line 2) in the masked file B - NOT for kernel.sysrq, whose key
    // identity IS present in the merged set (via the surviving /etc copy).
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/50-mask.conf",
        "kernel.sysrq = 1\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-mask.conf",
        "kernel.sysrq = 0\nfs.protected_hardlinks = 1\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let w03_hits: Vec<&Diagnostic> = w03s(&diags);
    let dropped = w03_hits
        .iter()
        .find(|d| d.message.contains("protected_hardlinks"))
        .unwrap_or_else(|| {
            panic!(
                "expected a sysctld-W03 for the silently-dropped \
                 fs.protected_hardlinks (set only in the masked B file, which no \
                 surviving file applies); diags: {diags:?}"
            )
        });
    assert!(
        dropped
            .file
            .display()
            .to_string()
            .ends_with("usr/lib/sysctl.d/50-mask.conf"),
        "W03-c anchors at the MASKED file B's real line, not the surviving A; \
         got {:?}",
        dropped.file
    );
    assert_eq!(
        dropped.line, 2,
        "fs.protected_hardlinks is on line 2 of the masked file; got line {}",
        dropped.line
    );

    // kernel.sysrq's key identity IS present in the merged set (via the
    // surviving /etc copy), so masking it does NOT itself trigger W03-c.
    assert!(
        w03_hits.iter().all(|d| !d.message.contains("sysrq")),
        "kernel.sysrq must NOT fire W03-c: its canonical key is present in the \
         effective merged set (via the surviving /etc/sysctl.d/50-mask.conf), \
         even though B's specific value for it never applies"
    );
}
