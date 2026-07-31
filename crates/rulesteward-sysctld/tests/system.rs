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

/// Create the real distro symlink `<root>/etc/sysctl.d/99-sysctl.conf ->
/// ../sysctl.conf` (a RELATIVE target, exactly as shipped: it resolves to
/// `<root>/etc/sysctl.conf`). This is the only path by which systemd-sysctl
/// applies `/etc/sysctl.conf` content (design section 2 point 3), so its
/// presence/absence and slot position are what drive the W03-b divergence.
fn symlink_99_sysctl_conf(root: &Path) {
    let link = root.join("etc/sysctl.d/99-sysctl.conf");
    std::fs::create_dir_all(link.parent().expect("has parent")).expect("mkdir -p");
    std::os::unix::fs::symlink("../sysctl.conf", &link).expect("create 99-sysctl.conf symlink");
}

/// Create an ARBITRARY-target symlink at `<root>/<link_rel>` (parent dirs made as
/// needed). Used to build the "wrong symlink target" fixture: the distro slot only
/// counts when it resolves to `<root>/etc/sysctl.conf` (design section 8), so a
/// symlink pointing elsewhere must be treated as absent.
fn symlink_at(root: &Path, link_rel: &str, target: &str) {
    let link = root.join(link_rel);
    std::fs::create_dir_all(link.parent().expect("has parent")).expect("mkdir -p");
    std::os::unix::fs::symlink(target, &link).expect("create symlink");
}

/// Create a real `.conf`-NAMED DIRECTORY at `<root>/<rel>` (a direct non-regular,
/// non-symlink entry). This is the type-agnostic basename masker case: a directory
/// entry in a higher-precedence search dir must still claim its basename and mask a
/// lower same-basename regular file (man sysctl.d(5) precedence; design section 2
/// point 1). Uses `create_dir` (not `create_dir_all`) for the leaf so the entry is
/// unambiguously a directory.
fn mkdir_conf_named(root: &Path, rel: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir -p parent");
    std::fs::create_dir(&path).expect("mkdir .conf-named directory");
}

/// All `sysctld-F01` diagnostics.
fn f01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags.iter().filter(|d| d.code == "sysctld-F01").collect()
}

/// All `sysctld-W01` diagnostics.
fn w01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags.iter().filter(|d| d.code == "sysctld-W01").collect()
}

/// All `sysctld-W03` diagnostics.
fn w03s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags.iter().filter(|d| d.code == "sysctld-W03").collect()
}

/// Build the "genuinely absent" comparison baseline for the W03-b
/// reason-clause discrimination tests (round 2 Finding 2, src/system.rs:355-361):
/// ONLY `/etc/sysctl.conf` setting `net.core.somaxconn = 777`, with NOTHING at
/// all at the `/etc/sysctl.d/99-sysctl.conf` slot - no symlink, dangling or
/// otherwise, truly nothing there. Returns that root's single W03-b message for
/// `somaxconn`, so a present-but-broken-slot fixture's message can be compared
/// against it: the two situations call for different operator remedies
/// (repoint/fix the existing symlink vs create a brand-new one, which fails
/// with EEXIST if one is already there), so their reason clauses must differ.
fn w03b_message_for_genuinely_absent_99_slot() -> String {
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 777\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for somaxconn in the \
                 genuinely-absent baseline (no 99-slot at all); \
                 diags: {diags:?}"
            )
        })
        .message
        .clone()
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
    // Values are distinctive MULTI-digit numbers whose digit strings appear in
    // NO fixture filename ("10-early.conf" / "90-late.conf"), directory path, or
    // 1-based line number, so a `contains` on them is non-vacuous (CONCERN A: a
    // plain `contains('0') && contains('1')` was satisfied by the FILENAMES
    // alone and could not tell a value-swapped message apart). kernel.sysrq is a
    // bitmask so 438/176 are valid values.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-early.conf",
        "kernel.sysrq = 438\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/90-late.conf",
        "kernel.sysrq = 176\n",
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
    // Direction is pinned STRUCTURALLY, not by a value-symmetric `contains`:
    // (1) the finding is ANCHORED at the dead high-precedence file (10-early.conf),
    // (2) the message NAMES the winning low-precedence file (90-late.conf), and
    // (3) the message states the DEAD value (438) - design section 5 W03-a: the
    // message "names the dead key/value/file and the winning file". A value/role
    // swap that put 176 in the dead slot would drop "438" from the message and
    // fail here; a wrong anchor (winner file) fails the ends_with. (The winning
    // VALUE is deliberately NOT asserted: design section 5 mandates only the
    // winning FILE, so pinning the winning value would over-constrain a correct
    // impl.)
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
        hit.message.contains("438"),
        "the message must state the DEAD value (438) - not the winning value - \
         so a value/role swap is caught: {}",
        hit.message
    );

    // No other pass double-reports this same conflict under sysctld-W01.
    assert!(
        w01s(&diags).iter().all(|d| !d.message.contains("sysrq")),
        "W03-a must SUPPRESS the redundant plain W01 for the same dead line"
    );
}

// ---------------------------------------------------------------------------
// 4. W03-b: procps/systemd applier divergence (design section 2 point 3,
//    section 5 case b). Three fixtures pin the two grounded triggers PLUS the
//    suppression path the two triggers share:
//    (4a) missing symlink -> systemd never applies /etc/sysctl.conf (RED);
//    (4b) symlink present + a drop-in sorting AFTER 99-sysctl.conf -> the two
//         appliers resolve DIFFERENT values (RED, the central oracle scenario);
//    (4c) symlink present + NO later drop-in -> both appliers agree, NO W03-b
//         fires (GREEN regression guard against an impl that fires for every
//         key in /etc/sysctl.conf, ignoring the symlink slot).
// ---------------------------------------------------------------------------

#[test]
fn w03b_fires_when_the_missing_symlink_makes_systemd_skip_sysctl_conf() {
    // Trigger 1 (design section 5 case b, "...or absent [symlink]"). procps
    // `sysctl --system` reads /etc/sysctl.conf DEAD LAST unconditionally, so it
    // always wins (here: net.core.somaxconn = 512). systemd-sysctl does NOT read
    // /etc/sysctl.conf natively; it participates ONLY via the distro symlink
    // /etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf. With NO such symlink and no
    // other file touching this key, systemd never applies this setting at all - a
    // real, observable procps/systemd divergence (one applier sets 512, the other
    // leaves the key unset). 512 is a distinctive value present in no filename,
    // path, or line number, so `contains("512")` is non-vacuous (CONCERN B: the
    // prior `contains('1')` collided with the line-1 anchor).
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 512\n");
    // Deliberately NO /etc/sysctl.d/99-sysctl.conf symlink.

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = diags
        .iter()
        .find(|d| d.code == "sysctld-W03" && d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a sysctld-W03 applier-divergence finding for \
                 net.core.somaxconn (procps applies /etc/sysctl.conf dead-last; \
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
        hit.message.contains("512"),
        "the message must state the procps-resolved value (512): {}",
        hit.message
    );
}

#[test]
fn w03b_fires_when_symlink_present_but_a_later_dropin_diverges_the_appliers() {
    // Trigger 2 (design section 5 case b, the CENTRAL scenario the container
    // oracle proved in section 2 point 3): the symlink /etc/sysctl.d/
    // 99-sysctl.conf -> ../sysctl.conf IS present, /etc/sysctl.conf sets
    // net.core.somaxconn = 4096, and a drop-in whose basename sorts AFTER
    // "99-sysctl.conf" ("zz-last.conf": 'z'=0x7a > '9'=0x39, matching the
    // container experiment's zz-last.conf appearing dead-last among drop-ins)
    // sets the SAME key = 8192. The two appliers now diverge:
    //   * procps: /etc/sysctl.conf is read DEAD LAST -> 4096 wins.
    //   * systemd: /etc/sysctl.conf participates only at the 99-sysctl.conf slot,
    //     and zz-last.conf sorts AFTER that slot -> 8192 wins.
    // W03-b fires anchored at /etc/sysctl.conf, naming BOTH resolved values
    // (4096 and 8192, distinctive multi-digit values in no filename/path/line)
    // and the cause file (zz-last.conf). RED against the empty stub.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 4096\n",
    );
    symlink_99_sysctl_conf(root.path());
    write_at(
        root.path(),
        "etc/sysctl.d/zz-last.conf",
        "net.core.somaxconn = 8192\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = diags
        .iter()
        .find(|d| d.code == "sysctld-W03" && d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a sysctld-W03 applier-divergence finding for \
                 net.core.somaxconn (symlink present + zz-last.conf sorts after \
                 the 99-sysctl.conf slot: procps resolves 4096, systemd resolves \
                 8192); diags: {diags:?}"
            )
        });
    assert!(
        hit.file.display().to_string().ends_with("sysctl.conf")
            && !hit.file.display().to_string().ends_with("99-sysctl.conf"),
        "W03-b anchors at the real /etc/sysctl.conf assignment (not the \
         99-sysctl.conf symlink); got {:?}",
        hit.file
    );
    // Pin BOTH resolved values precisely (not a weak single-char contains): the
    // procps winner 4096 AND the systemd winner 8192 must both be stated.
    assert!(
        hit.message.contains("4096"),
        "the message must state the procps-resolved value (4096, /etc/sysctl.conf \
         dead-last): {}",
        hit.message
    );
    assert!(
        hit.message.contains("8192"),
        "the message must state the systemd-resolved value (8192, zz-last.conf \
         after the 99-slot): {}",
        hit.message
    );
    assert!(
        hit.message.to_lowercase().contains("systemd"),
        "the message must name systemd as the diverging applier: {}",
        hit.message
    );
    assert!(
        hit.message.contains("zz-last.conf"),
        "the message must name the cause (the drop-in sorting after the \
         99-sysctl.conf slot): {}",
        hit.message
    );
}

#[test]
fn w03b_suppressed_when_symlink_present_and_no_later_dropin() {
    // The suppression path both triggers above share (design section 2 point 3 +
    // section 5 case b, read as an IFF): with the symlink PRESENT and NO drop-in
    // sorting after "99-sysctl.conf", the two appliers AGREE on the key -
    //   * procps: reads /etc/sysctl.d/99-sysctl.conf (= the symlinked
    //     /etc/sysctl.conf, value 1) then /etc/sysctl.conf dead-last (value 1);
    //   * systemd: applies /etc/sysctl.conf at the 99-slot (value 1), with
    //     nothing after it to override;
    // both resolve 1, so NO W03-b divergence exists for this key. This stays
    // GREEN against the empty stub and is the regression guard the barrier
    // reviewer flagged: it EXCLUDES an over-firing impl that fires W03-b for
    // every key set in /etc/sysctl.conf while ignoring the 99-sysctl.conf slot.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.ipv4.tcp_syncookies = 1\n",
    );
    symlink_99_sysctl_conf(root.path());
    // Deliberately NO drop-in whose basename sorts after "99-sysctl.conf".

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    assert!(
        w03s(&diags)
            .iter()
            .all(|d| !d.message.contains("tcp_syncookies")),
        "no W03-b may fire for a key whose /etc/sysctl.conf value is applied \
         identically by both appliers (symlink present at the 99-slot, nothing \
         sorts after it); got: {diags:?}"
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

// ---------------------------------------------------------------------------
// 6. BUG 1 (impl-aware review): the /etc/sysctl.d/99-sysctl.conf symlink must
//    take part in same-basename directory MASKING like any drop-in entry
//    (design section 2 point 1 + section 5 W03-c). The symlink OWNS the basename
//    "99-sysctl.conf" at the highest-precedence directory, so a real same-basename
//    file in a LOWER directory is masked - its keys never apply.
// ---------------------------------------------------------------------------

#[test]
fn the_99_slot_symlink_masks_a_same_basename_file_in_a_lower_dir() {
    // /etc/sysctl.d/99-sysctl.conf is the distro symlink -> ../sysctl.conf, so it
    // OWNS the basename "99-sysctl.conf" at rank 0 (highest). A real
    // /usr/lib/sysctl.d/99-sysctl.conf (rank 3, same basename) is therefore MASKED
    // exactly like any lower same-basename drop-in (design section 2 point 1): its
    // unique key kernel.sysrq = 999 never reaches the effective merged set, so it
    // is silently dropped -> exactly one W03-c anchored at that masked file (design
    // section 5 W03-c). The symlinked /etc/sysctl.conf sets an unrelated key so
    // nothing else touches kernel.sysrq. 999 is distinctive (in no filename/path/
    // line).
    let root = tempdir().expect("temp root");
    symlink_99_sysctl_conf(root.path());
    write_at(
        root.path(),
        "usr/lib/sysctl.d/99-sysctl.conf",
        "kernel.sysrq = 999\n",
    );
    write_at(root.path(), "etc/sysctl.conf", "net.ipv4.ip_forward = 0\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    // (a) Guard: the masked lower file must be invisible to the last-wins pass -
    // NO W01 anchored in it.
    assert!(
        w01s(&diags).iter().all(|d| {
            !d.file
                .display()
                .to_string()
                .contains("usr/lib/sysctl.d/99-sysctl.conf")
        }),
        "the masked usr/lib 99-sysctl.conf must not anchor any W01; got: {diags:?}"
    );
    // (b) RED driver: kernel.sysrq is set ONLY in the masked lower file, so a
    // correct masking impl drops it -> exactly one W03-c, anchored at the masked
    // file. The current buggy impl skips the etc symlink WITHOUT registering its
    // basename, so the lower 99-conf wrongly SURVIVES, kernel.sysrq IS in the
    // merged set, and NO W03-c fires -> RED.
    let sysrq_w03: Vec<&Diagnostic> = w03s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("kernel.sysrq") || d.message.contains("kernel/sysrq"))
        .collect();
    assert_eq!(
        sysrq_w03.len(),
        1,
        "the masked lower 99-sysctl.conf's unique key kernel.sysrq must be \
         silently dropped -> exactly one W03-c; got: {diags:?}"
    );
    assert!(
        sysrq_w03[0]
            .file
            .display()
            .to_string()
            .ends_with("usr/lib/sysctl.d/99-sysctl.conf"),
        "the W03-c must anchor at the MASKED lower file; got {:?}",
        sysrq_w03[0].file
    );
    assert!(
        sysrq_w03[0].message.contains("999"),
        "the W03-c message must state the dropped value (999): {}",
        sysrq_w03[0].message
    );
}

// ---------------------------------------------------------------------------
// 7. BUG 2 (impl-aware review): the 99-sysctl.conf slot counts ONLY when the
//    symlink resolves to <prefix>/etc/sysctl.conf ("not the expected symlink ->
//    treat as absent", design section 8). A symlink to any OTHER resolvable
//    target must NOT be treated as the slot.
// ---------------------------------------------------------------------------

#[test]
fn w03b_fires_when_the_99_symlink_targets_something_other_than_sysctl_conf() {
    // /etc/sysctl.d/99-sysctl.conf is a symlink to a RESOLVABLE decoy
    // (../../other/decoy.conf, which exists) - NOT to ../sysctl.conf. Per design
    // section 8 the slot is "the expected symlink" only when it resolves to
    // <prefix>/etc/sysctl.conf, so this decoy link is treated as ABSENT: systemd
    // never applies /etc/sysctl.conf. procps still reads /etc/sysctl.conf
    // dead-last, so net.core.somaxconn = 777 (touched by no drop-in) diverges ->
    // W03-b "systemd does not apply /etc/sysctl.conf" fires anchored at
    // /etc/sysctl.conf. The current impl treats ANY resolvable symlink as the slot
    // (is_symlink && exists), so it splices /etc/sysctl.conf at the 99-slot, the
    // appliers agree, and NO W03-b fires -> RED. 777 is distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "other/decoy.conf",
        "# unrelated decoy target\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/decoy.conf",
    );
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 777\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for net.core.somaxconn: the \
                 99-sysctl.conf symlink targets a decoy (not ../sysctl.conf), so \
                 per design section 8 systemd does not apply /etc/sysctl.conf while \
                 procps applies 777 dead-last; diags: {diags:?}"
            )
        });
    assert!(
        hit.file.display().to_string().ends_with("sysctl.conf")
            && !hit.file.display().to_string().ends_with("99-sysctl.conf"),
        "W03-b anchors at the real /etc/sysctl.conf; got {:?}",
        hit.file
    );
    assert!(
        hit.message.contains("777"),
        "the message must state the procps-resolved value (777): {}",
        hit.message
    );
    assert!(
        hit.message.to_lowercase().contains("systemd"),
        "the message must name systemd as the diverging applier: {}",
        hit.message
    );

    // STRENGTHEN (Adversarial Testing Loop round 2, Finding 2): the round-2 fix
    // (src/system.rs:362-370) only patched the `Some(sw)` arm's self-contradiction
    // (see `w03b_reason_does_not_deny_the_misdirected_symlink_it_names_as_applier`
    // below); the `None` arm (src/system.rs:355-361) is UNCONDITIONALLY hardcoded
    // to "no /etc/sysctl.d/99-sysctl.conf symlink" regardless of `slot_is_symlink`
    // (computed at src/system.rs:311-312 but never consulted in that arm). This
    // fixture's decoy target sets no keys at all, so `systemd_win` is `None` here
    // and the `None` arm fires - even though a symlink genuinely EXISTS at that
    // path (just misdirected to a resolvable decoy). This is the MORE COMMON real
    // shape of #593 (a misdirected slot usually does not set the same keys as
    // /etc/sysctl.conf, so the winner is `None`, not `Some`).
    assert!(
        !hit.message
            .contains("no /etc/sysctl.d/99-sysctl.conf symlink"),
        "a 99-sysctl.conf symlink genuinely exists here (misdirected to a \
         resolvable decoy, but present) - the reason clause must not claim \
         there is no symlink at all: {}",
        hit.message
    );
    // Non-vacuity: a bare `!contains("no ... symlink")` could pass by
    // accident if the message text changed shape for an unrelated reason.
    // Compare against a root with NOTHING at the 99-slot at all (not
    // misdirected - genuinely absent) using the SAME key/value (777): under
    // the current bug both fixtures hit the identical hardcoded `None` arm
    // and produce the BYTE-IDENTICAL message, even though a misdirected slot
    // and a genuinely absent one call for different operator remedies
    // (repoint the existing symlink vs create a new one, which fails with
    // EEXIST if a - misdirected - one is already there).
    let hit_message = hit.message.clone();
    let absent_message = w03b_message_for_genuinely_absent_99_slot();
    assert_ne!(
        hit_message, absent_message,
        "a present (misdirected) 99-sysctl.conf symlink and a genuinely \
         ABSENT one must not produce the byte-identical W03-b reason clause \
         (the None arm's hardcoded message makes them indistinguishable \
         today): {hit_message:?} == {absent_message:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. Enumerate robustness (design section 8): a MISSING search directory is
//    skipped silently (a system need not have all of them) - no F01.
// ---------------------------------------------------------------------------

#[test]
fn missing_search_directories_are_skipped_silently_with_no_f01() {
    // A root with NONE of the five search directories (only a comment-only
    // /etc/sysctl.conf, which sets no key -> no W03-b). Every read_dir hits
    // NotFound and is skipped; design section 8 says a missing dir is not an error.
    // Pins the NotFound guard: a mutation routing NotFound to the generic error arm
    // would emit a spurious F01 per missing dir.
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "# no keys here\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    assert!(
        f01s(&diags).is_empty(),
        "missing search directories must not emit any sysctld-F01; got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 9. Enumerate robustness (design section 8): an UNREADABLE search directory
//    yields a dir-level sysctld-F01, never a panic; the rest of the scan
//    proceeds. mode 0o000 is only unreadable to a process WITHOUT DAC-override;
//    the test probes that precondition and skips under root (RHEL-family distro
//    CI runs as root and bypasses DAC), asserting fully on every non-root run.
// ---------------------------------------------------------------------------

#[test]
fn unreadable_search_directory_emits_a_file_level_f01() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().expect("temp root");
    let blocked = root.path().join("etc/sysctl.d");
    std::fs::create_dir_all(&blocked).expect("mkdir etc/sysctl.d");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

    // Precondition: mode 0o000 only blocks reads for a process without DAC-override.
    // The RHEL-family distro CI runs the suite as ROOT, which bypasses DAC, so
    // `read_dir` still succeeds there and the F01 branch is structurally unreachable.
    // Probe the actual precondition and skip (rather than false-fail) when this
    // environment cannot produce an unreadable directory. The F01 path stays fully
    // asserted on every non-root run (local dev, the ubuntu llvm-cov gate, mutation CI).
    if std::fs::read_dir(&blocked).is_ok() {
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755))
            .expect("restore perms");
        eprintln!(
            "SKIP unreadable_search_directory_emits_a_file_level_f01: mode 0o000 is \
             readable here (running as root / with CAP_DAC_OVERRIDE); cannot exercise \
             the unreadable-dir F01 path"
        );
        return;
    }

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    // Restore perms BEFORE any assertion so the tempdir cleans up even on failure.
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755))
        .expect("restore perms");

    let dir_f01: Vec<&Diagnostic> = f01s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("cannot read sysctl.d directory"))
        .collect();
    assert_eq!(
        dir_f01.len(),
        1,
        "an unreadable /etc/sysctl.d must emit exactly one dir-level sysctld-F01 \
         (design section 8: unreadable dir -> F01, not a panic); got: {diags:?}"
    );
    assert!(
        dir_f01[0]
            .file
            .display()
            .to_string()
            .ends_with("etc/sysctl.d"),
        "the F01 must name the unreadable directory; got {:?}",
        dir_f01[0].file
    );
}

// ---------------------------------------------------------------------------
// 10. A non-.conf entry (README) and a .conf-NAMED subdirectory in a search dir
//     produce no F01 and no diagnostic. README is filtered out by NAME (no `.conf`
//     extension). The subdir claims its basename type-agnostically (a directory is
//     a valid basename masker, design section 2 point 1) but, with NO lower
//     same-basename file beneath it, masks nothing and contributes no content - so
//     no F01, no diagnostic references it.
// ---------------------------------------------------------------------------

#[test]
fn non_conf_files_and_conf_named_subdirs_in_a_search_dir_are_ignored() {
    // etc/sysctl.d holds: a valid drop-in (10-real.conf), a non-.conf file (README
    // whose body would be a malformed F01 line if parsed), and a .conf-NAMED
    // SUBDIRECTORY. README lacks a `.conf` extension so it is filtered out by name
    // (never read). The subdir.conf directory claims its basename but is not a
    // readable regular file, so it contributes no assignments and - having nothing
    // same-basename beneath it - masks nothing: no F01, no diagnostic names it.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-real.conf",
        "kernel.sysrq = 1\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/README",
        "this line is not a sysctl assignment\n",
    );
    std::fs::create_dir_all(root.path().join("etc/sysctl.d/subdir.conf"))
        .expect("mkdir subdir.conf");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    assert!(
        f01s(&diags).is_empty(),
        "a README and a .conf-named subdirectory must be ignored, not parsed into \
         an F01; got: {diags:?}"
    );
    assert!(
        !diags.iter().any(|d| {
            let f = d.file.display().to_string();
            f.contains("README") || f.contains("subdir.conf")
        }),
        "no diagnostic may reference the ignored README or subdir.conf; got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. W03-b value-equality branch (impl: `sw.value != procps_val`): symlink
//     present AND a later drop-in sets the SAME value as /etc/sysctl.conf -> both
//     appliers resolve the same value -> NO W03-b. Pins the equal-value branch (a
//     `!=`->`==` mutation would wrongly fire here).
// ---------------------------------------------------------------------------

#[test]
fn w03b_suppressed_when_a_later_dropin_sets_the_same_value_as_sysctl_conf() {
    // Symlink present. /etc/sysctl.conf sets net.core.somaxconn = 1234, and
    // etc/sysctl.d/zz-last.conf (sorts after the 99-slot) sets the SAME value 1234.
    //   * procps: /etc/sysctl.conf dead-last = 1234.
    //   * systemd: zz-last after the 99-slot = 1234.
    // Both resolve 1234, so no divergence -> NO W03-b. Reaches the value-equality
    // check with procps == systemd; a `!=`->`==` mutation would (wrongly) fire.
    // 1234 is distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 1234\n",
    );
    symlink_99_sysctl_conf(root.path());
    write_at(
        root.path(),
        "etc/sysctl.d/zz-last.conf",
        "net.core.somaxconn = 1234\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    assert!(
        w03s(&diags)
            .iter()
            .all(|d| !d.message.contains("somaxconn")),
        "both appliers resolve 1234, so no W03-b divergence may fire for \
         net.core.somaxconn; got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 12. W03-b dedup + dead-last procps value (impl: the earlier-duplicate skip):
//     /etc/sysctl.conf sets the SAME key twice -> procps applies the LAST
//     assignment (dead-last within the file) and W03-b fires exactly ONCE.
// ---------------------------------------------------------------------------

#[test]
fn w03b_fires_once_per_key_using_the_dead_last_value_when_sysctl_conf_repeats_it() {
    // No 99 symlink -> systemd never applies /etc/sysctl.conf, so a key it sets
    // diverges (procps applies it, systemd does not). /etc/sysctl.conf sets
    // net.core.somaxconn twice: = 4444 (line 1) then = 5555 (line 2). procps reads
    // the file top-to-bottom and the LAST assignment wins, so the resolved value is
    // 5555 and exactly ONE W03-b fires, anchored at the last assignment (line 2). A
    // mutation of the earlier-duplicate skip would emit two W03-b (or pick 4444).
    // 4444/5555 are distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 4444\nnet.core.somaxconn = 5555\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hits: Vec<&Diagnostic> = w03s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("somaxconn"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "a key set twice in /etc/sysctl.conf must fire W03-b exactly once; \
         got: {diags:?}"
    );
    assert_eq!(
        hits[0].line, 2,
        "the single W03-b must anchor at the LAST (dead-last, procps-winning) \
         assignment on line 2; got line {}",
        hits[0].line
    );
    assert!(
        hits[0].message.contains("5555") && !hits[0].message.contains("4444"),
        "procps applies the dead-last value 5555 (not the earlier 4444): {}",
        hits[0].message
    );
}

// ---------------------------------------------------------------------------
// 13. A REAL (non-symlink) 99-sysctl.conf in /etc/sysctl.d is a NORMAL
//     highest-precedence drop-in - only the distro SYMLINK is special (impl:
//     `path == link_99 && is_symlink(path)`). It masks a same-basename lower file
//     and provides the key at rank 0.
// ---------------------------------------------------------------------------

#[test]
fn a_real_non_symlink_99_conf_is_a_normal_highest_precedence_dropin() {
    // etc/sysctl.d/99-sysctl.conf is a REAL FILE (not the distro symlink) setting
    // kernel.sysrq = 111. usr/lib/sysctl.d/99-sysctl.conf (same basename, lower
    // dir) sets kernel.sysrq = 222 -> masked. usr/lib/sysctl.d/50-other.conf (a
    // DIFFERENT basename, rank 3) sets kernel.sysrq = 333 and survives. In merge
    // order "50-other.conf" < "99-sysctl.conf", so the real etc 99 (rank 0, value
    // 111) applies last and wins over 50-other (333): a plain W01 anchored at
    // 50-other naming the winning value 111 from the etc 99 file. A `&&`->`||`
    // mutation at the symlink-skip would wrongly SKIP the real etc 99 (path ==
    // link_99), letting the lower usr/lib 99 (222) survive and win instead - the
    // W01 winner would then be 222 from the usr/lib path. 111/222/333 distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "kernel.sysrq = 111\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/99-sysctl.conf",
        "kernel.sysrq = 222\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-other.conf",
        "kernel.sysrq = 333\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let sysrq_w01: Vec<&Diagnostic> = w01s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("kernel.sysrq") || d.message.contains("kernel/sysrq"))
        .collect();
    assert_eq!(
        sysrq_w01.len(),
        1,
        "exactly one W01 for kernel.sysrq (50-other dead, etc 99 wins); got: {diags:?}"
    );
    assert!(
        sysrq_w01[0]
            .file
            .display()
            .to_string()
            .ends_with("50-other.conf"),
        "the dead assignment is 50-other.conf's; got {:?}",
        sysrq_w01[0].file
    );
    assert!(
        sysrq_w01[0].message.contains("= 111)")
            && sysrq_w01[0].message.contains("etc/sysctl.d/99-sysctl.conf"),
        "the winner must be the REAL etc 99-sysctl.conf (value 111), proving a \
         non-symlink 99 file is a normal highest-precedence drop-in (not skipped); \
         got: {}",
        sysrq_w01[0].message
    );
}

// ---------------------------------------------------------------------------
// 14. BUG (impl-aware review): the /dev/null disable idiom. man sysctl.d(5)
//     ("CONFIGURATION DIRECTORIES AND PRECEDENCE"): the recommended way to disable
//     a vendor file is a symlink /etc/sysctl.d/<name> -> /dev/null with the SAME
//     basename. That symlink is a directory entry that CLAIMS its basename at rank
//     0 and MASKS the same-basename vendor file in a lower directory (design
//     section 2 point 1: first dir to hold a basename provides it; the lower
//     same-basename file is masked). The impl's is_file() filter FOLLOWS the
//     /dev/null symlink to a char device -> false -> the entry is dropped before it
//     can claim its basename, so the disabled vendor file wrongly SURVIVES.
// ---------------------------------------------------------------------------

#[test]
fn dev_null_disabled_vendor_file_does_not_apply_reopening_the_stig_gap() {
    // /etc/sysctl.d/50-foo.conf -> /dev/null disables the same-basename vendor file
    // /usr/lib/sysctl.d/50-foo.conf, which hardens kernel.dmesg_restrict = 1
    // (STIG-required, compliant). Disabling it must MASK the vendor file so the key
    // no longer applies -> under --target rhel9 the W02 baseline flags
    // kernel.dmesg_restrict as UNSET (the reopened STIG gap is the direct grounded
    // consequence that the disabled value does not apply). The current impl drops
    // the /dev/null symlink at the is_file() filter, so the vendor file survives,
    // dmesg_restrict = 1 stays compliant, and NO W02 fires -> RED.
    let root = tempdir().expect("temp root");
    symlink_at(root.path(), "etc/sysctl.d/50-foo.conf", "/dev/null");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-foo.conf",
        "kernel.dmesg_restrict = 1\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        diags.iter().any(|d| {
            d.code == "sysctld-W02"
                && d.message.contains("kernel.dmesg_restrict")
                && d.message.contains("unset")
        }),
        "a /dev/null-disabled vendor file must be masked, so its STIG key becomes \
         UNSET and W02 flags it; got: {diags:?}"
    );
}

#[test]
fn dev_null_disabled_vendor_file_never_wins_a_cross_directory_surprise() {
    // Sharper variant (man sysctl.d(5) /dev/null disable + design section 2 point 1
    // + section 5 W03-a): /etc/sysctl.d/50-foo.conf -> /dev/null disables the vendor
    // file /usr/lib/sysctl.d/50-foo.conf (net.core.somaxconn = 999). A separate
    // /run/sysctl.d/10-base.conf sets the SAME key = 111. Correct: the disabled
    // vendor file is masked and invisible, so only 111 survives - NO cross-directory
    // surprise. The current impl drops the /dev/null symlink at is_file(), so the
    // vendor file wrongly survives at rank 3 and, sorting after 10-base.conf, WINS -
    // emitting a spurious W03-a that names 999 overriding 111. 999/111 distinctive.
    let root = tempdir().expect("temp root");
    symlink_at(root.path(), "etc/sysctl.d/50-foo.conf", "/dev/null");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-foo.conf",
        "net.core.somaxconn = 999\n",
    );
    write_at(
        root.path(),
        "run/sysctl.d/10-base.conf",
        "net.core.somaxconn = 111\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    // The disabled value 999 must never apply/win: not named in any W01, and not in
    // any W03-a (cross-directory precedence surprise). W03-c (masked-key-drop) is
    // EXCLUDED from this check - whether a /dev/null-disabled key fires W03-c is the
    // implementer's design call (do not assert either way).
    for d in &diags {
        let is_w01 = d.code == "sysctld-W01";
        let is_w03a =
            d.code == "sysctld-W03" && d.message.contains("cross-directory precedence surprise");
        if is_w01 || is_w03a {
            assert!(
                !d.message.contains("999"),
                "the /dev/null-disabled vendor value 999 must never win/apply or be \
                 named in a W01 or W03-a (only the surviving 111 applies): {}",
                d.message
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 15. A symlinked NON-99 drop-in pointing at a regular .conf file is a NORMAL
//     drop-in and IS parsed (man sysctl.d(5): drop-ins may be symlinks; only the
//     distro 99-sysctl.conf symlink is special). Pins the 99-slot guard
//     `path == link_99`: a `==`->`!=` mutation would treat every OTHER symlink as
//     the special slot and skip it.
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_non_99_dropin_pointing_at_a_regular_file_is_parsed_normally() {
    // /etc/sysctl.d/50-link.conf -> ../../other/hardening.conf (a real regular file
    // that hardens kernel.dmesg_restrict = 1, STIG-compliant). Under --target rhel9
    // the key is satisfied -> NO W02 for kernel.dmesg_restrict. A `path == link_99`
    // -> `!=` mutation would wrongly treat this non-99 symlink as the special slot
    // and skip it, dropping the key -> W02 "unset" -> caught. GREEN now.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "other/hardening.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/50-link.conf",
        "../../other/hardening.conf",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        !diags
            .iter()
            .any(|d| d.code == "sysctld-W02" && d.message.contains("kernel.dmesg_restrict")),
        "a symlinked non-99 drop-in to a regular file must be parsed, so its \
         compliant kernel.dmesg_restrict = 1 satisfies the baseline (no W02); \
         got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 16. The distro 99-sysctl.conf symlink is RECOGNIZED as the systemd 99-slot
//     (design section 2 pt3 / section 5 case b), not treated as absent. Pins the
//     `is_symlink` helper: an `is_symlink -> false` mutation would make the real
//     symlink look absent and report the wrong divergence cause.
// ---------------------------------------------------------------------------

#[test]
fn the_99_slot_symlink_is_recognized_as_the_systemd_slot() {
    // /etc/sysctl.conf sets net.core.somaxconn = 2048; the distro
    // /etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf symlink is present;
    // /etc/sysctl.d/zz-after.conf (sorts after "99-sysctl.conf") sets it = 4096. The
    // resulting W03-b must state the cause as "the 99-sysctl.conf slot" - per design
    // section 5 the two causes are "a drop-in after 99-sysctl.conf" (this case, the
    // symlink IS recognized) vs "a missing symlink". A mutation making is_symlink
    // always return false would treat the real symlink as absent and (wrongly)
    // report the missing-symlink cause -> caught. 2048/4096 distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 2048\n",
    );
    symlink_99_sysctl_conf(root.path());
    write_at(
        root.path(),
        "etc/sysctl.d/zz-after.conf",
        "net.core.somaxconn = 4096\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for net.core.somaxconn (symlink present \
                 + zz-after sorts past the 99-slot); got: {diags:?}"
            )
        });
    assert!(
        hit.message.contains("99-sysctl.conf slot"),
        "the divergence cause must be the recognized 99-sysctl.conf slot (the \
         symlink is present), not a missing symlink; got: {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// 17. BUG (convergence impl-aware review): masking is TYPE-AGNOSTIC by basename.
//     A DIRECT non-regular entry (a `.conf`-named DIRECTORY, or a fifo/socket/
//     device - same code path) in a higher-precedence search dir must still CLAIM
//     its basename and MASK a lower same-basename regular file. Grounded: both
//     procps-ng 3.3.17 `sysctl --dry-run --system` AND systemd-sysctl 259
//     `systemd-sysctl --cat-config` resolve to the LOWER file being masked
//     (type-agnostic basename precedence); man sysctl.d(5) "CONFIGURATION
//     DIRECTORIES AND PRECEDENCE" + design section 2 point 1. The impl's
//     `if !ftype.is_file() && !ftype.is_symlink() { continue; }` guard drops the
//     direct non-regular entry BEFORE it can claim its basename, so the lower
//     vendor file wrongly SURVIVES and WINS (the OPPOSITE of both appliers).
// ---------------------------------------------------------------------------

#[test]
fn a_conf_named_directory_masks_a_lower_same_basename_vendor_file() {
    // /etc/sysctl.d/50-foo.conf is a real DIRECTORY (rank 0). It claims the basename
    // "50-foo.conf" and must MASK the lower vendor file /usr/lib/sysctl.d/50-foo.conf
    // (net.core.somaxconn = 999). A separate /run/sysctl.d/10-base.conf sets the SAME
    // key = 111 and survives. Correct (both real appliers agree): the vendor file is
    // masked and invisible, only 111 applies - NO cross-directory surprise. The
    // current impl drops the directory at the file-type guard, so the vendor file
    // wrongly survives at rank 3 and, sorting after 10-base.conf, WINS - emitting a
    // spurious W03-a that names 999 overriding 111. 999/111 distinctive.
    let root = tempdir().expect("temp root");
    mkdir_conf_named(root.path(), "etc/sysctl.d/50-foo.conf");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-foo.conf",
        "net.core.somaxconn = 999\n",
    );
    write_at(
        root.path(),
        "run/sysctl.d/10-base.conf",
        "net.core.somaxconn = 111\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    // The directory-masked vendor value 999 must never win/apply: it may appear in
    // NO sysctld-W01 and NO sysctld-W03 message (only the surviving 111 applies).
    // Here somaxconn is covered by 10-base's 111, so a correct impl fires no W03-c
    // for the masked file either - hence the broad "no W03 names 999" holds.
    for d in &diags {
        if d.code == "sysctld-W01" || d.code == "sysctld-W03" {
            assert!(
                !d.message.contains("999"),
                "a directory-masked vendor value 999 must never win/apply or be named \
                 in a W01/W03 (only the surviving 111 applies): {}",
                d.message
            );
        }
    }
}

#[test]
fn a_conf_named_directory_masks_a_vendor_hardening_file_reopening_the_stig_gap() {
    // Sharper STIG variant (parallel to tests #14/#16): /etc/sysctl.d/50-foo.conf is
    // a DIRECTORY (rank 0) that must mask the lower vendor hardening file
    // /usr/lib/sysctl.d/50-foo.conf (kernel.dmesg_restrict = 1, STIG-compliant).
    // Masking it drops the key from the effective set -> under --target rhel9 the W02
    // baseline flags kernel.dmesg_restrict as UNSET (the reopened STIG gap is the
    // direct grounded consequence that the masked value does not apply). The current
    // impl drops the directory at the file-type guard, so the vendor file survives,
    // dmesg_restrict = 1 stays compliant, and NO W02 fires -> RED.
    let root = tempdir().expect("temp root");
    mkdir_conf_named(root.path(), "etc/sysctl.d/50-foo.conf");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-foo.conf",
        "kernel.dmesg_restrict = 1\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        diags.iter().any(|d| {
            d.code == "sysctld-W02"
                && d.message.contains("kernel.dmesg_restrict")
                && d.message.contains("unset")
        }),
        "a .conf-named directory must mask the lower vendor hardening file, so its \
         STIG key becomes UNSET and W02 flags it; got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 18. #593 RED driver + regression guard: the 99-slot symlink must be
//     followed and parsed like any ordinary drop-in when it does NOT resolve
//     to <prefix>/etc/sysctl.conf (design section 8: "not the expected
//     symlink -> treat as absent" applies to the APPLIER-SLOT decision only,
//     not to whether the entry is content at all - a misdirected symlink is
//     just a symlink pointing somewhere real). The buggy impl's
//     `ftype.is_symlink() && path == link_99` guard is unconditional on the
//     TARGET, so it silently drops a compliant host's assignment and reports
//     a false "unset" (#593). Test A pins the fix's OWN behavior at the
//     `lint_system` entry point; Test B pins that the basename-masking
//     ordering guard (FORBIDDEN item 3 / `seen.insert` before the content
//     decision) still holds for a misdirected symlink specifically - the
//     existing `the_99_slot_symlink_masks_a_same_basename_file_in_a_lower_dir`
//     (line 596) covers only the CORRECT distro symlink, where the
//     content-skip `continue` still fires.
// ---------------------------------------------------------------------------

#[test]
fn misdirected_99_symlink_is_followed_and_parsed_as_an_ordinary_dropin() {
    // /etc/sysctl.d/99-sysctl.conf is a MISDIRECTED symlink (-> ../../other/
    // hidden.conf, NOT ../sysctl.conf), so slot_symlink_ok is false. The real
    // systemd-sysctl oracle never special-cases this filename: it just
    // follows the symlink and parses it like any other drop-in (#593 ground
    // truth: the recorded oracle transcript shows "Parsing /etc/sysctl.d/
    // 99-sysctl.conf"). etc/sysctl.d/10-first.conf sets the SAME key
    // kernel.sysrq = 123 at rank 0. In basename merge order "10-first.conf" <
    // "99-sysctl.conf" (bytewise), so the followed symlink's assignment (987)
    // applies LAST and wins -> exactly one W01 anchored at 10-first.conf
    // naming the winning value 987. The current buggy impl skips ANY symlink
    // at the 99 slot unconditionally (path equality only, ignoring the
    // target), so the symlink's content is never parsed, only one assignment
    // exists, and NO W01 fires -> RED. 987/123 are distinctive (in no path,
    // filename or line number in this fixture).
    let root = tempdir().expect("temp root");
    write_at(root.path(), "other/hidden.conf", "kernel.sysrq = 987\n");
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/hidden.conf",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/10-first.conf",
        "kernel.sysrq = 123\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let sysrq_w01: Vec<&Diagnostic> = w01s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("kernel.sysrq") || d.message.contains("kernel/sysrq"))
        .collect();
    assert_eq!(
        sysrq_w01.len(),
        1,
        "the misdirected symlink must be followed and parsed, so its \
         assignment (987) conflicts with and beats 10-first.conf's (123) in \
         basename merge order -> exactly one W01; got: {diags:?}"
    );
    assert!(
        sysrq_w01[0]
            .file
            .display()
            .to_string()
            .ends_with("10-first.conf"),
        "the dead assignment is 10-first.conf's; got {:?}",
        sysrq_w01[0].file
    );
    assert!(
        sysrq_w01[0].message.contains("= 987)")
            && sysrq_w01[0].message.contains("etc/sysctl.d/99-sysctl.conf"),
        "the winner must be the followed 99-sysctl.conf symlink's content \
         (987), proving the misdirected symlink is parsed as an ordinary \
         drop-in instead of being silently skipped; got: {}",
        sysrq_w01[0].message
    );
}

#[test]
fn a_misdirected_99_symlink_still_masks_a_same_basename_file_in_a_lower_dir() {
    // /etc/sysctl.d/99-sysctl.conf is a MISDIRECTED symlink (-> a real,
    // comment-only file that is NOT ../sysctl.conf), so slot_symlink_ok is
    // false and its content is parsed as an ordinary (empty) drop-in after
    // the fix. But the basename CLAIM (seen.insert) must happen for EVERY
    // .conf-named entry regardless of the content decision (system.rs:191-192's
    // own comment: "Content contribution, decided AFTER the basename claim
    // above"), so a real /usr/lib/sysctl.d/99-sysctl.conf (same basename,
    // lower dir) must still be MASKED: its unique key fs.protected_hardlinks
    // never reaches the effective merged set -> exactly one W03-c anchored at
    // the masked file, and no W01 anchored there.
    //
    // A wrong impl that ties the basename CLAIM itself to the symlink's
    // target - e.g. skipping `seen.insert` for ANY symlink at the 99-slot
    // path regardless of `symlink_ok` - would let the masked lower file
    // wrongly survive instead. (The specific `&& symlink_ok`-gated reorder
    // that positive-control 2 exercises is a no-op for THIS misdirected
    // fixture: its condition is false regardless of block position, so it
    // cannot redden this test - verified empirically, see the lane report.
    // This guard instead directly observes that the type-agnostic
    // basename-claim invariant holds for the misdirected case too, which the
    // pre-existing correct-symlink guard at line 596 does not exercise.)
    //
    // The masked file ALSO sets net.core.somaxconn = 999, a key a surviving
    // drop-in (run/sysctl.d/zz-after.conf) ALSO sets, = 111 - "zz-after.conf"
    // sorts AFTER "99-sysctl.conf" bytewise, so IF the masked file wrongly
    // survived, its 999 would apply before 111 wins, producing a W01
    // anchored AT the masked path. This gives the "no W01 anchored there"
    // assertion below something to range over (without it, no key in this
    // fixture could EVER produce a W01 under any implementation, making that
    // assertion vacuously true - a real gap the reviewer caught). Under the
    // correct impl the masked file never survives, so no such conflict
    // exists and the assertion holds trivially, as intended. 555/999/111 are
    // distinctive.
    let root = tempdir().expect("temp root");
    write_at(root.path(), "other/decoy.conf", "# misdirected target\n");
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/decoy.conf",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/99-sysctl.conf",
        "fs.protected_hardlinks = 555\nnet.core.somaxconn = 999\n",
    );
    write_at(
        root.path(),
        "run/sysctl.d/zz-after.conf",
        "net.core.somaxconn = 111\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    assert!(
        w01s(&diags).iter().all(|d| {
            !d.file
                .display()
                .to_string()
                .contains("usr/lib/sysctl.d/99-sysctl.conf")
        }),
        "the masked usr/lib 99-sysctl.conf must not anchor any W01; got: {diags:?}"
    );
    let hits: Vec<&Diagnostic> = w03s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("protected_hardlinks"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the masked lower 99-sysctl.conf's unique key must be silently \
         dropped -> exactly one W03-c; got: {diags:?}"
    );
    assert!(
        hits[0]
            .file
            .display()
            .to_string()
            .ends_with("usr/lib/sysctl.d/99-sysctl.conf"),
        "the W03-c must anchor at the MASKED lower file; got {:?}",
        hits[0].file
    );
    assert!(
        hits[0].message.contains("555"),
        "the W03-c message must state the dropped value (555): {}",
        hits[0].message
    );
}

// ---------------------------------------------------------------------------
// 19. Over-fix guard (rework, impl-blind adversarial review): the LAZIEST
//     wrong "fix" for #593 is to DELETE the whole 99-slot content-skip block
//     (system.rs:193-198) instead of adding the `&& symlink_ok` conjunct -
//     six lines removed, no hoist, no signature change. That greens the two
//     tests above (it happens to follow a MISDIRECTED symlink correctly),
//     but it is wrong on the MOST COMMON real layout: the CORRECT distro
//     symlink `99-sysctl.conf -> ../sysctl.conf` alongside a real
//     `/etc/sysctl.conf`. With the block gone, the symlink is parsed as an
//     ordinary drop-in via `parse_surviving` AND `parse_etc_conf` ALSO
//     parses the same physical file directly - the two share no dedup, so
//     every key in `/etc/sysctl.conf` is read TWICE, fabricating a
//     duplicate finding. `net.core.somaxconn` is set twice in
//     `/etc/sysctl.conf` (4444 then 5555, a genuine within-file conflict,
//     not just duplication) with the CORRECT symlink present.
// ---------------------------------------------------------------------------

#[test]
fn a_correct_99_symlink_does_not_double_parse_etc_sysctl_conf() {
    // Correct impl: content flows via the /etc/sysctl.conf applier model
    // ONCE (the 99-slot continue fires, symlink_ok is true), so merged is
    // exactly [etcconf:4444(line 1), etcconf:5555(line 2)] -> exactly one
    // W01, anchored at etc/sysctl.conf line 1, naming the winner 5555. The
    // symlink path itself is never independently parsed, so NO diagnostic of
    // any code anchors at etc/sysctl.d/99-sysctl.conf.
    //
    // The block-deleted over-fix instead ALSO parses the symlink as a
    // surviving drop-in, producing a SECOND copy of both assignments
    // (anchored at the symlink path). Merged becomes
    // [99:4444(l1), 99:5555(l2), etcconf:4444(l1), etcconf:5555(l2)];
    // last-wins picks etcconf:5555 as the winner, and BOTH earlier
    // DIFFERENT-valued assignments (99:4444 and etcconf:4444) are now dead
    // -> TWO W01s, one anchored at EACH path - failing both assertions
    // below. 4444/5555 are distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 4444\nnet.core.somaxconn = 5555\n",
    );
    symlink_99_sysctl_conf(root.path());

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let somaxconn_w01: Vec<&Diagnostic> = w01s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("somaxconn"))
        .collect();
    assert_eq!(
        somaxconn_w01.len(),
        1,
        "the correct distro symlink's content must flow via the \
         /etc/sysctl.conf applier model ONCE, not be double-parsed through \
         the symlink path too -> exactly one W01; got: {diags:?}"
    );
    let anchor = somaxconn_w01[0].file.display().to_string();
    assert!(
        anchor.ends_with("etc/sysctl.conf") && !anchor.ends_with("99-sysctl.conf"),
        "the single W01 must anchor at the real etc/sysctl.conf, not the \
         99-sysctl.conf symlink path; got {anchor:?}"
    );
    assert_eq!(
        somaxconn_w01[0].line, 1,
        "the dead assignment is etc/sysctl.conf's line 1 (4444); got line {}",
        somaxconn_w01[0].line
    );
    assert!(
        diags
            .iter()
            .all(|d| !d.file.display().to_string().ends_with("99-sysctl.conf")),
        "no diagnostic of any code must anchor at the 99-sysctl.conf symlink \
         path itself - its content must never be independently parsed when \
         the symlink correctly resolves to /etc/sysctl.conf; got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 20. Over-fix guard (second rework round, impl-blind adversarial review): the
//     PARTIAL over-fix `if ftype.is_symlink() && symlink_ok { continue; }` -
//     dropping only the `path == link_99` conjunct, keeping `symlink_ok` -
//     passes the ENTIRE suite as it stood before this test (all 22 corpus rows,
//     all 24 unit tests). It is a tempting simplification once `symlink_ok` is
//     hoisted to a per-`lint_system`-call value: "`slot_symlink_ok` already
//     looks at the 99 path, so `path == link_99` is redundant" reads plausibly
//     at the call site, but `slot_symlink_ok` is a whole-PREFIX property (is
//     THIS prefix's distro slot wired correctly at all?), not a per-ENTRY one
//     (is THIS specific directory entry the 99 slot?) - the two are
//     independent questions and the guard needs both.
//
//     Blast radius wider than #593: on a host with the standard distro slot
//     (symlink_ok == true, the ordinary RHEL default), the partial over-fix
//     drops EVERY symlinked drop-in in the whole search path, not just the 99
//     slot - the common config-management pattern
//     `60-hardening.conf -> /opt/cm/hardening.conf` would report its keys
//     UNSET and fabricate W02/W04 findings on a compliant host, the same
//     defect class #593 fixes, on a bigger surface.
//
//     Why no existing test catches it: `a_symlinked_non_99_dropin_pointing_at_
//     a_regular_file_is_parsed_normally` (line 1105) is the test that LOOKS
//     like it should - its own comment says it exists to catch a
//     `path == link_99` -> `!=` mutation, and today (with only `path ==
//     link_99` in the guard) it does: deleting that conjunct alone leaves
//     `is_symlink` and reddens it. But :1105's fixture has NO 99 slot and NO
//     `/etc/sysctl.conf`, so `symlink_ok` is FALSE there - under the partial
//     over-fix `is_symlink && symlink_ok` is `true && false` = false, the
//     `continue` never fires, and :1105 stays GREEN by COINCIDENCE, not
//     because it exercises the conjunct that was actually deleted. The guard
//     survives in name only once `&& symlink_ok` lands. The mutation gate does
//     not cover this either: conjunct DELETION is not a cargo-mutants
//     operator, and the `&&`->`||` mutants ARE killed by :1105
//     (`is_symlink || (path == link_99 && symlink_ok)` reddens it), so the
//     gate reports clean while this hole is open.
//
//     This test is :1105's fixture PLUS a resolving 99 slot (symlink_99_
//     sysctl_conf + a present /etc/sysctl.conf), so symlink_ok is TRUE here -
//     the one condition :1105 cannot provide. Today and post-fix: the
//     50-link.conf symlink's path is not link_99, so `path == link_99` is
//     false regardless of symlink_ok, the drop-in is parsed normally, and its
//     compliant kernel.dmesg_restrict = 1 satisfies the baseline -> no W02
//     (GREEN). Under the partial over-fix: is_symlink && symlink_ok is
//     `true && true` = true, so 50-link.conf is wrongly swallowed by the
//     content-skip, kernel.dmesg_restrict becomes unset -> W02 "unset" fires
//     (RED).
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_non_99_dropin_is_still_parsed_when_the_distro_slot_also_resolves() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "other/hardening.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/50-link.conf",
        "../../other/hardening.conf",
    );
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "# present so the distro slot resolves\n",
    );
    symlink_99_sysctl_conf(root.path());

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        !diags
            .iter()
            .any(|d| d.code == "sysctld-W02" && d.message.contains("kernel.dmesg_restrict")),
        "a symlinked non-99 drop-in must still be parsed even when the distro \
         99-slot ALSO resolves (symlink_ok true) - only path == link_99 may \
         gate the content-skip, not symlink_ok alone - so the compliant \
         kernel.dmesg_restrict = 1 must still satisfy the baseline (no W02); \
         got: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 21. STRENGTHEN (Adversarial Testing Loop, round 2 - impl-aware review):
//     Finding 1 - the fix follows a 99-sysctl.conf slot symlink OUT of --root
//     and reads HOST files when the target is an ABSOLUTE path. The corpus
//     materializers mechanically FORBID an absolute symlink target other than
//     /dev/null (PROVENANCE.md's "Symlink target schema rule"), so this exact
//     shape can only be constructed directly here, driving the real
//     `lint_system` entry point against a materialized tempdir tree.
//
//     Orchestrator ruling (2026-07-31), "RE-ROOT, THEN CONTAIN": an absolute
//     symlink target under --root resolves as <root>/<target> (what a real
//     chroot/image would do, and what makes the ordinary admin repair
//     `ln -s /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf` correctly
//     recognized as the distro slot). THEN, any result that still escapes the
//     prefix is treated as unresolvable: it claims its basename but
//     contributes NO content. With no --root prefix (a live scan), behavior is
//     UNCHANGED: absolute targets resolve normally against the real
//     filesystem, exactly as today.
//
//     Scope ruling: 99 SLOT ONLY. The same escape class pre-exists for
//     ordinary (non-99) drop-ins - filed as a separate issue - and is
//     deliberately NOT pinned by these tests.
// ---------------------------------------------------------------------------

#[test]
fn absolute_99_symlink_target_outside_root_is_not_followed_onto_the_host_fs() {
    // <root>/etc/sysctl.d/99-sysctl.conf -> <outside>/593-hostside.conf, an
    // ABSOLUTE target that lives entirely OUTSIDE root (a second, independent
    // tempdir, never nested under root). <root> itself sets
    // kernel.dmesg_restrict nowhere. The outside file sets it compliantly
    // (= 1). Per re-root-then-contain, the absolute target re-roots to
    // <root>/<outside-tempdir-name>/593-hostside.conf, which does not exist
    // UNDER root, so the entry must contribute NOTHING (fail-closed): W02
    // still fires "unset". The impl at 65dba2f instead resolves the absolute
    // target literally against the real filesystem, finds the real outside
    // file, and reads its compliant value straight through - no W02 - RED.
    let root = tempdir().expect("temp root");
    let outside = tempdir().expect("temp dir OUTSIDE root - never nested under it");
    write_at(
        outside.path(),
        "593-hostside.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    let target = outside
        .path()
        .join("593-hostside.conf")
        .to_str()
        .expect("outside path is valid UTF-8")
        .to_string();
    symlink_at(root.path(), "etc/sysctl.d/99-sysctl.conf", &target);

    let (diags, sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        diags.iter().any(|d| {
            d.code == "sysctld-W02"
                && d.message.contains("kernel.dmesg_restrict")
                && d.message.contains("unset")
        }),
        "an absolute 99-sysctl.conf symlink target OUTSIDE --root must not be \
         followed onto the real host filesystem - re-root-then-contain finds \
         no such path under root, so kernel.dmesg_restrict must be reported \
         UNSET (fail-closed); got: {diags:?}"
    );
    assert!(
        sources
            .keys()
            .all(|k| Path::new(k).starts_with(root.path())),
        "no staged source may lie outside --root, even when the symlink \
         target is an absolute host path; got sources keyed at: {:?}",
        sources.keys().collect::<Vec<_>>()
    );
}

#[test]
fn absolute_99_symlink_target_resolving_inside_root_is_recognized_as_the_distro_slot() {
    // Positive counterpart to the test above: etc/sysctl.conf sets a marker
    // key = 2048 (procps's dead-last value). etc/sysctl.d/99-sysctl.conf ->
    // the ABSOLUTE literal "/etc/sysctl.conf" (re-roots to
    // <root>/etc/sysctl.conf, matching - exactly the shape
    // `ln -s /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf` produces).
    // etc/sysctl.d/zz-after.conf sorts after "99-sysctl.conf" bytewise and sets
    // the SAME marker key = 4096, so systemd's view (drop-ins plus
    // /etc/sysctl.conf spliced at the recognized 99-slot) has zz-after.conf
    // win = 4096, diverging from procps's 2048 -> W03-b fires, and per design
    // section 5 the cause must be the RECOGNIZED "99-sysctl.conf slot" wording,
    // not "no symlink" - mirrors the_99_slot_symlink_is_recognized_as_the_
    // systemd_slot (line 1146), which pins the shipped RELATIVE target; this
    // pins the same recognition for an ABSOLUTE target requiring re-rooting.
    //
    // This fixture necessarily also exercises the impl's literal
    // (non-re-rooted) canonicalize of the real host /etc/sysctl.conf as a side
    // effect of reproducing the admin-repair shape exactly; the assertions are
    // keyed to a fictitious canonical key ("rs9m.f1.marker") that cannot appear
    // in any real system's /etc/sysctl.conf, so PASS/FAIL does not depend on
    // the real host file's actual content.
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "rs9m.f1.marker = 2048\n");
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "/etc/sysctl.conf",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/zz-after.conf",
        "rs9m.f1.marker = 4096\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("rs9m.f1.marker"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for rs9m.f1.marker (2048 procps \
                 vs 4096 systemd); diags: {diags:?}"
            )
        });
    assert!(
        hit.message.contains("2048") && hit.message.contains("4096"),
        "the message must state both the procps value (2048) and the systemd \
         value (4096): {}",
        hit.message
    );
    assert!(
        hit.message.contains("99-sysctl.conf slot"),
        "an absolute target that re-roots to <root>/etc/sysctl.conf must be \
         RECOGNIZED as the distro slot (the same cause the shipped relative \
         target gets), not treated as a missing symlink; got: {}",
        hit.message
    );
}

#[test]
fn ninety_nine_symlink_dotdot_escape_out_of_root_contributes_no_content() {
    // "RE-ROOT, THEN CONTAIN" also means containing a resolution that walks
    // back OUT of --root via `..` navigation, whether the target string was
    // absolute or (as here) relative. <root>/etc/sysctl.d/99-sysctl.conf ->
    // ../../../<outside-name>/593-escape-marker.conf, a RELATIVE target that
    // walks up out of --root entirely (three levels from etc/sysctl.d/ reaches
    // root's own parent - the shared OS temp directory - then into a second,
    // independent tempdir that is never nested under root). <root> itself sets
    // kernel.dmesg_restrict nowhere; the outside file sets it compliantly
    // (= 1). The resolved target genuinely exists and is readable, so a fix
    // that only re-roots ABSOLUTE targets without also containing an escaping
    // RELATIVE (or re-rooted) result would still leak this content - per the
    // ruling, ANY resolution leaving the prefix claims the basename but
    // contributes NO content, so W02 must still fire "unset" (fail-closed).
    // The impl at 65dba2f (no containment check of any kind) follows the
    // escape and reads the outside file's compliant value straight through -
    // no W02 - RED.
    //
    // Scope: 99 SLOT ONLY, per the orchestrator ruling - the same escape class
    // pre-exists for ordinary (non-99) drop-ins and is filed separately.
    let root = tempdir().expect("temp root");
    let outside = tempdir().expect("temp dir OUTSIDE root - never nested under it");
    let outside_name = outside
        .path()
        .file_name()
        .expect("tempdir has a basename")
        .to_string_lossy()
        .into_owned();
    write_at(
        outside.path(),
        "593-escape-marker.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    let target = format!("../../../{outside_name}/593-escape-marker.conf");
    symlink_at(root.path(), "etc/sysctl.d/99-sysctl.conf", &target);

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        diags.iter().any(|d| {
            d.code == "sysctld-W02"
                && d.message.contains("kernel.dmesg_restrict")
                && d.message.contains("unset")
        }),
        "a 99-sysctl.conf symlink whose resolution walks OUT of --root via \
         `..` must contribute no content (contained, not followed) - \
         kernel.dmesg_restrict must be reported UNSET (fail-closed); got: \
         {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 22. STRENGTHEN (Adversarial Testing Loop, round 2 - impl-aware review):
//     Finding 2 - the W03-b reason clause is self-contradictory for a
//     misdirected IN-ROOT 99-sysctl.conf symlink (#593 shape) that happens to
//     set the SAME key as /etc/sysctl.conf. Once the fix follows the symlink,
//     that symlink becomes the winning "dropin" for the key, and the impl
//     names it as the file that "applies instead" in the SAME sentence that
//     claims there is "no 99-sysctl.conf symlink" - asserting there is no such
//     symlink while pointing straight at it. The correct remedy for a
//     misdirected slot is to REPOINT it; "no symlink" implies the (no-op)
//     remedy of creating one.
//
//     misdirected_99_symlink_is_followed_and_parsed_as_an_ordinary_dropin
//     (line 1294) never observes this: its fixture uses a DIFFERENT key
//     (kernel.sysrq) than /etc/sysctl.conf's (nothing set there at all in that
//     fixture), so the misdirected symlink's assignment never becomes the
//     systemd-side WINNER for a key /etc/sysctl.conf also sets, and no W03-b
//     reason clause is asserted on there at all.
// ---------------------------------------------------------------------------

#[test]
fn w03b_reason_does_not_deny_the_misdirected_symlink_it_names_as_applier() {
    // <root>/etc/sysctl.d/99-sysctl.conf -> ../../other/hidden.conf (in-root,
    // misdirected; #593 shape). hidden.conf sets net.core.somaxconn = 987 (the
    // sole drop-in once the symlink is followed); etc/sysctl.conf sets
    // net.core.somaxconn = 777 (procps's dead-last value). These diverge -> one
    // W03-b, anchored at etc/sysctl.conf. 777/987 distinctive.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "other/hidden.conf",
        "net.core.somaxconn = 987\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/hidden.conf",
    );
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 777\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for net.core.somaxconn (777 \
                 procps vs 987 systemd, via the followed misdirected symlink); \
                 diags: {diags:?}"
            )
        });
    assert!(
        hit.message.contains("777") && hit.message.contains("987"),
        "the message must state both the procps value (777) and the systemd \
         value (987): {}",
        hit.message
    );
    assert!(
        !(hit.message.contains("no 99-sysctl.conf symlink")
            && hit.message.contains("99-sysctl.conf applies instead")),
        "the reason must not claim there is no 99-sysctl.conf symlink while, \
         in the same breath, naming that exact 99-sysctl.conf symlink as the \
         file that applies instead - self-contradictory; the correct remedy \
         for a misdirected slot is to REPOINT it, not create one that already \
         exists: {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// 23. STRENGTHEN (Adversarial Testing Loop, round 2 - impl-aware review):
//     Finding 1 - containment is checked on the RE-ROOTED path
//     (`resolve_reroot_contained`, src/system.rs:79-95) and used ONLY as a
//     boolean in `enumerate` (src/system.rs:254); the resolved path is
//     DISCARDED and `SurvivingFile { path, .. }` keeps the ORIGINAL LINK path.
//     `parse_surviving` (src/system.rs:420) then does
//     `std::fs::read_to_string(&sf.path)` directly on that link, and the
//     kernel resolves an ABSOLUTE symlink target against the REAL filesystem
//     root, not `prefix`. So the CONTAINMENT DECISION is made on the
//     re-rooted path while the READ silently follows the real root - the
//     locked `--root` semantics ("re-root, then contain": a target that
//     escapes contributes NOTHING and is NEVER read from the host filesystem)
//     and the module's own doc comments (src/system.rs:68-72, :249-251) are
//     both falsified for a resolvable in-root target reached via an absolute
//     link whose real-root counterpart differs from (or is absent from) its
//     re-rooted one.
// ---------------------------------------------------------------------------

#[test]
fn absolute_99_symlink_read_follows_the_real_root_not_the_rerooted_path_when_host_counterpart_absent()
 {
    // <root>/etc/rs9m-dropin.conf is the RE-ROOTED counterpart of the
    // absolute target "/etc/rs9m-dropin.conf": `resolve_reroot_contained`
    // finds it, canonicalizes to a path under `prefix`, and `enumerate`'s
    // boolean gate `is_some_and(|p| p.is_file())` is satisfied, so the entry
    // is ADMITTED as a surviving drop-in. But nothing exists at the REAL,
    // literal "/etc/rs9m-dropin.conf" on the host (a synthetic session-scoped
    // name chosen so it cannot collide with any real host path, matching this
    // file's existing "593-..." / "rs9m.f1..." naming convention - confirmed
    // absent on the lane host before authoring this fixture), so
    // `parse_surviving`'s `read_to_string(&sf.path)` - which dereferences the
    // symlink against the REAL filesystem root, not `prefix` - fails with
    // ENOENT: a spurious sysctld-F01, and since no assignment is contributed
    // for kernel.dmesg_restrict and nothing else sets it, a FALSE "unset" W02
    // even though the correctly re-rooted in-root file DOES set it.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/rs9m-dropin.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "/etc/rs9m-dropin.conf",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        !diags.iter().any(|d| d.code == "sysctld-F01"),
        "the re-rooted counterpart <root>/etc/rs9m-dropin.conf exists and is \
         a file, so the containment decision admits this entry; the READ \
         must use that SAME re-rooted path, not the real filesystem root - a \
         spurious sysctld-F01 (\"cannot read ... No such file or \
         directory\") proves the read instead followed the absolute target \
         onto the real host root; got: {diags:?}"
    );
    assert!(
        !diags
            .iter()
            .any(|d| d.code == "sysctld-W02" && d.message.contains("kernel.dmesg_restrict")),
        "kernel.dmesg_restrict = 1 in the re-rooted in-root counterpart must \
         apply (re-root, then contain), so no sysctld-W02 may fire for it; \
         got: {diags:?}"
    );
}

#[test]
fn absolute_99_symlink_read_returns_host_bytes_not_reroot_bytes_when_host_counterpart_diverges() {
    // A REAL host directory (a second, independent tempdir - `hostdir`, never
    // nested under `root`) and an IN-ROOT counterpart at the SAME relative
    // path (derived from `hostdir`'s own path, exactly how
    // `resolve_reroot_contained` computes it: strip the target's leading "/"
    // and join onto `prefix`) both exist, with DIFFERENT values for the same
    // key. The boolean containment gate is satisfied by the IN-ROOT
    // counterpart (so the entry is admitted), but `parse_surviving`'s
    // `read_to_string(&sf.path)` dereferences the absolute-target symlink
    // against the REAL root, so it returns the HOST file's bytes - the
    // in-root file's content, which "re-root, then contain" requires, is
    // never read at all.
    let hostdir = tempdir().expect("temp host dir OUTSIDE root - never nested under it");
    write_at(
        hostdir.path(),
        "hostfile.conf",
        "kernel.dmesg_restrict = 0\n",
    );
    let target = hostdir
        .path()
        .join("hostfile.conf")
        .to_str()
        .expect("host path is valid UTF-8")
        .to_string();
    // The in-root counterpart lives at the RE-ROOTED relative path: strip the
    // leading "/" from the absolute target, exactly as
    // `resolve_reroot_contained` does (`target.strip_prefix("/")`).
    let reroot_rel = target.trim_start_matches('/').to_string();

    let root = tempdir().expect("temp root");
    write_at(root.path(), &reroot_rel, "kernel.dmesg_restrict = 1\n");
    symlink_at(root.path(), "etc/sysctl.d/99-sysctl.conf", &target);

    let (diags, sources) = rulesteward_sysctld::system::lint_system(
        Some(root.path()),
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    );

    assert!(
        !diags
            .iter()
            .any(|d| d.code == "sysctld-W02" && d.message.contains("kernel.dmesg_restrict")),
        "the applied value must be the IN-ROOT counterpart's (1, compliant), \
         not the host's (0, insecure); got: {diags:?}"
    );
    assert!(
        sources.values().any(|v| v.contains("dmesg_restrict = 1")),
        "the in-root file's content must be staged in `sources`; got: {:?}",
        sources.values().collect::<Vec<_>>()
    );
    // The decisive assertion (impl-aware review): the pre-existing
    // `absolute_99_symlink_target_outside_root_is_not_followed_onto_the_host_fs`
    // test above only checks `sources.keys()` - which is ALWAYS the in-root
    // link path regardless of which bytes actually got staged there - so it
    // cannot see this bug. Only a CONTENT check can: no staged source may
    // carry the HOST value.
    assert!(
        sources.values().all(|v| !v.contains("dmesg_restrict = 0")),
        "no staged source may contain the HOST file's bytes (dmesg_restrict \
         = 0) - the read must follow the re-rooted in-root path, not the \
         real absolute target; got sources: {:?}",
        sources.values().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 24. STRENGTHEN (Adversarial Testing Loop, round 2 - impl-aware review):
//     Finding 2, continued - the same None-arm discrimination gap
//     (src/system.rs:355-361) exercised for the DANGLING and ESCAPING 99-slot
//     shapes (the strengthened test above at "7." covers the misdirected
//     shape). In every one of these three shapes a symlink GENUINELY EXISTS
//     at `/etc/sysctl.d/99-sysctl.conf` (`slot_is_symlink` is true), yet the
//     hardcoded `None`-arm message claims there is none - byte-identical to a
//     root with truly nothing at that path.
// ---------------------------------------------------------------------------

#[test]
fn w03b_dangling_99_symlink_reason_differs_from_genuinely_absent() {
    // A DANGLING 99-sysctl.conf symlink (its target is never created) is a
    // REAL symlink: `std::fs::symlink_metadata` succeeds and reports
    // `is_symlink() == true` regardless of whether the target exists (it
    // never follows the link). `resolve_reroot_contained` fails to
    // canonicalize the missing target (`None`), so the entry contributes no
    // content, and `slot_is_symlink` (src/system.rs:311-312) is `true` while
    // `systemd_win` for the /etc/sysctl.conf key is `None` (no drop-in
    // provides it) - hitting the hardcoded `None` arm, which claims "no
    // 99-sysctl.conf symlink" exactly as it would for a root with nothing
    // there at all.
    let root = tempdir().expect("temp root");
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/never-created.conf",
    );
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 777\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for somaxconn (dangling 99-slot \
                 symlink); diags: {diags:?}"
            )
        });
    assert!(
        !hit.message
            .contains("no /etc/sysctl.d/99-sysctl.conf symlink"),
        "a symlink genuinely exists at the 99 slot here (dangling, but \
         present) - the reason clause must not claim there is none: {}",
        hit.message
    );
    let hit_message = hit.message.clone();
    let absent_message = w03b_message_for_genuinely_absent_99_slot();
    assert_ne!(
        hit_message, absent_message,
        "a DANGLING 99-sysctl.conf symlink and a genuinely absent one are \
         different operator situations (fix the dangling target vs create a \
         symlink from scratch) and must not produce the byte-identical W03-b \
         reason clause: {hit_message:?} == {absent_message:?}"
    );
}

#[test]
fn w03b_escaping_99_symlink_reason_differs_from_genuinely_absent() {
    // An ESCAPING 99-sysctl.conf symlink (a relative `..` walkout to a file
    // that genuinely EXISTS outside --root, mirroring the grounded
    // `ninety_nine_symlink_dotdot_escape_out_of_root_contributes_no_content`
    // fixture above) is likewise a real, present symlink: `slot_is_symlink`
    // is true, but `resolve_reroot_contained`'s containment check
    // (src/system.rs:92-94) rejects the resolved path (canonicalizes fine,
    // but does not `starts_with` the canonical prefix), so the entry
    // contributes no content and `systemd_win` is `None` - the SAME hardcoded
    // "no symlink" `None`-arm message as the dangling and genuinely-absent
    // cases, even though "a symlink pointing outside the scanned root" is
    // again a distinct, differently-remedied situation. (Relative target, so
    // this is independent of Finding 1's absolute-reroot bug above: containment
    // for a relative target is decided and read identically either way.)
    let root = tempdir().expect("temp root");
    let outside = tempdir().expect("temp dir OUTSIDE root - never nested under it");
    let outside_name = outside
        .path()
        .file_name()
        .expect("tempdir has a basename")
        .to_string_lossy()
        .into_owned();
    write_at(
        outside.path(),
        "593-w03b-escape.conf",
        "# unrelated, outside root\n",
    );
    let target = format!("../../../{outside_name}/593-w03b-escape.conf");
    symlink_at(root.path(), "etc/sysctl.d/99-sysctl.conf", &target);
    write_at(root.path(), "etc/sysctl.conf", "net.core.somaxconn = 777\n");

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for somaxconn (escaping 99-slot \
                 symlink); diags: {diags:?}"
            )
        });
    assert!(
        !hit.message
            .contains("no /etc/sysctl.d/99-sysctl.conf symlink"),
        "a symlink genuinely exists at the 99 slot here (it escapes --root, \
         but is present) - the reason clause must not claim there is none: {}",
        hit.message
    );
    let hit_message = hit.message.clone();
    let absent_message = w03b_message_for_genuinely_absent_99_slot();
    assert_ne!(
        hit_message, absent_message,
        "an ESCAPING 99-sysctl.conf symlink and a genuinely absent one are \
         different operator situations and must not produce the \
         byte-identical W03-b reason clause: {hit_message:?} == \
         {absent_message:?}"
    );
}

// ---------------------------------------------------------------------------
// 25. STRENGTHEN (Adversarial Testing Loop, round 2 - mutation-adequacy gap):
//     Finding 3 - `src/system.rs:370`'s `slot_is_symlink && sw.file == link_99`
//     survives being flipped to `||` (confirmed via a local, uncommitted
//     `&&`->`||` edit + revert: both tests below went RED against the mutant
//     and are GREEN against the real `&&` code - not an equivalent mutant).
//     Two reachable real configurations exercise each direction:
// ---------------------------------------------------------------------------

#[test]
fn w03b_reason_names_the_actual_winning_dropin_not_the_misdirected_symlink_itself() {
    // `slot_is_symlink == true`, `sw.file != link_99`: a misdirected 99
    // symlink (-> a resolvable decoy that sets NO keys) coexists with a
    // SEPARATE later drop-in (zz-other.conf, sorts after "99-sysctl.conf")
    // that wins the /etc/sysctl.conf key. Under the real `&&` (false, since
    // `sw.file` is zz-other.conf's path, not `link_99`), the `else` branch
    // fires and correctly NAMES the real winner ("{sw.file} applies
    // instead"). Under the `||` mutant, `slot_is_symlink` (true) alone would
    // make the condition true, wrongly taking the "misdirected" branch, which
    // never names any specific winning drop-in file - blaming the symlink
    // for behavior a completely different file caused.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "other/decoy.conf",
        "# resolvable decoy, sets no keys\n",
    );
    symlink_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "../../other/decoy.conf",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/zz-other.conf",
        "net.core.somaxconn = 2222\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 1111\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for somaxconn (1111 procps vs \
                 2222 systemd via zz-other.conf); diags: {diags:?}"
            )
        });
    assert!(
        hit.message.contains("zz-other.conf") && hit.message.contains("applies instead"),
        "the reason must name the ACTUAL winning drop-in (zz-other.conf), \
         not blame the unrelated misdirected symlink for its win: {}",
        hit.message
    );
    assert!(
        !hit.message.contains("misdirected"),
        "this key's winner is zz-other.conf, NOT the misdirected symlink's \
         own (empty) content - the reason must not use the \"misdirected \
         symlink\" phrasing here (that phrasing names no specific dropin, \
         which the `||` mutant reaches for this case): {}",
        hit.message
    );
}

#[test]
fn w03b_reason_does_not_call_a_regular_file_at_the_99_path_a_misdirected_symlink() {
    // `slot_is_symlink == false`, `sw.file == link_99`: admins do sometimes
    // replace the distro symlink with a REGULAR FILE at the same path. This
    // is a normal highest-precedence drop-in (per
    // `a_real_non_symlink_99_conf_is_a_normal_highest_precedence_dropin`
    // above), which here also wins a key /etc/sysctl.conf sets. Under the
    // real `&&` (false, since `slot_is_symlink` is false - there is no
    // symlink at all), the `else` branch correctly says "no
    // 99-sysctl.conf symlink; <path> applies instead" - true, since it
    // really is a regular file. Under the `||` mutant, `sw.file == link_99`
    // (true) alone would make the condition true, wrongly taking the
    // "misdirected symlink" branch and asserting a symlink "does not
    // resolve" when there is no symlink whatsoever at that path.
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/99-sysctl.conf",
        "net.core.somaxconn = 3333\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.core.somaxconn = 4444\n",
    );

    let (diags, _sources) = rulesteward_sysctld::system::lint_system(Some(root.path()), None);

    let hit = w03s(&diags)
        .into_iter()
        .find(|d| d.message.contains("somaxconn"))
        .unwrap_or_else(|| {
            panic!(
                "expected a W03-b divergence for somaxconn (4444 procps vs \
                 3333 systemd via the real-file 99-sysctl.conf); \
                 diags: {diags:?}"
            )
        });
    assert!(
        !hit.message.contains("misdirected"),
        "there is NO symlink at all here (a regular file replaced it) - the \
         reason must not call it a misdirected symlink that \"does not \
         resolve\": {}",
        hit.message
    );
    assert!(
        hit.message.contains("applies instead"),
        "the reason must use the accurate \"no symlink ... applies instead\" \
         wording, naming the real file that won: {}",
        hit.message
    );
}
