//! `sysctl lint --system`: cross-directory precedence scan (issue #420).
//!
//! Real systems apply `sysctl.d` drop-ins across a search path of four-plus
//! directories plus `/etc/sysctl.conf`; the effective value of a key can be
//! silently decided by a file the operator would not expect to win. [`lint_system`]
//! enumerates that search path (optionally rooted at a `--root` prefix for hermetic
//! testing / chroot-linting), applies the grounded same-basename directory masking
//! and global lexicographic merge, and runs the existing
//! `sysctld-F01`/`sysctld-W01`/`sysctld-W02` passes over the merged,
//! precedence-ordered assignment list plus the new cross-directory `sysctld-W03`
//! pass. See the design doc
//! `rulesteward-docs/2026-07-04-sysctld-cross-directory-precedence-420-design.md`
//! for the full grounded model (verified against a Rocky Linux 9.7 container,
//! sysctl.d(5), and systemd 259).
//!
//! # Grounded precedence model
//! 1. **Same-basename directory masking.** Search order highest to lowest
//!    precedence: `/etc/sysctl.d` > `/run/sysctl.d` > `/usr/local/lib/sysctl.d` >
//!    `/usr/lib/sysctl.d` (with `/lib/sysctl.d` a merged-usr alias of `/usr/lib`).
//!    The FIRST directory to contain a basename provides that file; the same
//!    basename in a lower directory is masked.
//! 2. **Global lexicographic merge.** Every surviving file is merged in bytewise
//!    basename order REGARDLESS of directory (`9-` beats `10-`), last-wins per key.
//! 3. **`/etc/sysctl.conf` applier divergence.** procps `sysctl --system` reads it
//!    dead-last (always wins); systemd-sysctl applies it only at the
//!    `99-sysctl.conf` symlink slot (or not at all if the symlink is absent).
//!
//! # `sysctld-W03` (system-only)
//! * **W03-a** lower-precedence-directory override: the winner sits in a
//!   lower-precedence directory than a dead assignment (won on a later basename).
//!   Suppresses the redundant plain W01 for that dead line.
//! * **W03-b** procps/systemd applier divergence for a `/etc/sysctl.conf` key.
//! * **W03-c** a masked same-basename drop-in sets a key no surviving file applies.
//!
//! The single-file [`crate::parser::lint_str`] and single-directory
//! [`crate::parser::lint_dir`] entry points are UNCHANGED and never emit
//! `sysctld-W03`; W03 is inherently a system-scan finding.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity, anchored};

use crate::lints::baseline::{TargetVersion, w02_baseline};
use crate::parser::{ParsedAssignment, effective_values, parse_file, w01_last_wins};

/// The standard `sysctl.d` search directories, highest precedence first. `/lib` is
/// the merged-usr alias of `/usr/lib`, so it shares rank 3. Each is joined under the
/// `--root` prefix (or `/` for a live scan).
fn search_dirs(prefix: &Path) -> [(PathBuf, usize); 5] {
    [
        (prefix.join("etc/sysctl.d"), 0),
        (prefix.join("run/sysctl.d"), 1),
        (prefix.join("usr/local/lib/sysctl.d"), 2),
        (prefix.join("usr/lib/sysctl.d"), 3),
        (prefix.join("lib/sysctl.d"), 3),
    ]
}

/// Whether `path` is itself a symlink (does NOT follow it). Used to recognise the
/// Whether the `/etc/sysctl.d/99-sysctl.conf` slot under `prefix` is the EXPECTED
/// distro symlink - a symlink that resolves to `<prefix>/etc/sysctl.conf`.
///
/// This is the ONLY path by which systemd-sysctl applies `/etc/sysctl.conf` (design
/// section 2 point 3). Per design section 8, anything that is "not the expected
/// symlink" is treated as ABSENT (systemd does not apply `/etc/sysctl.conf`, so
/// W03-b fires): a non-symlink, a dangling link (`canonicalize` fails, and a
/// dangling link is never followed), or a symlink to any OTHER target.
///
/// The canonicalize-equality below IS the "expected distro symlink" check: only a
/// symlink (chain) can make `99-sysctl.conf` resolve to `etc/sysctl.conf`'s real
/// path (a regular file / hardlink at that name canonicalizes to itself, `!=`
/// `etc/sysctl.conf`; a missing / dangling link yields `Err -> false`), so no
/// separate `is_symlink` guard is needed. Both sides are canonicalized so the
/// shipped relative `../sysctl.conf` target and any prefix-level symlinks resolve
/// identically.
fn slot_symlink_ok(prefix: &Path) -> bool {
    let link_99 = prefix.join("etc/sysctl.d/99-sysctl.conf");
    match (
        std::fs::canonicalize(&link_99),
        std::fs::canonicalize(prefix.join("etc/sysctl.conf")),
    ) {
        (Ok(target), Ok(etc_conf)) => target == etc_conf,
        _ => false,
    }
}

/// A drop-in that survived same-basename directory masking, tagged with its
/// search-directory precedence rank (0 = `/etc/sysctl.d`, highest).
struct SurvivingFile {
    path: PathBuf,
    basename: OsString,
    rank: usize,
}

/// A drop-in masked by a same-basename file in a higher-precedence directory. Kept
/// only for the W03-c "masked drop-in drops a key" check; it contributes no
/// assignment to the merged set and no F01.
struct MaskedFile {
    path: PathBuf,
    masked_by: PathBuf,
}

/// Build a file-level `sysctld-F01` for a search-path file that exists but cannot be
/// read (unanchored: no source line), mirroring `lint_dir`'s tolerance.
fn unreadable_file_f01(path: &Path, err: &std::io::Error) -> Diagnostic {
    Diagnostic::new(
        Severity::Fatal,
        "sysctld-F01",
        0..0,
        format!("cannot read {}: {err}", path.display()),
        path.to_path_buf(),
        0,
        0,
    )
}

/// Enumerate the search path under `prefix`, applying same-basename directory
/// masking. Returns the surviving drop-ins (one per basename, highest-precedence
/// directory wins), the masked drop-ins (for W03-c), and a file-level F01 for any
/// directory that exists but cannot be read. A MISSING directory is skipped
/// silently (a system need not have all of them).
///
/// Masking is by directory ENTRY NAME (design section 2 point 1, man sysctl.d(5)),
/// separate from the content decision. EVERY `.conf`-named regular file or symlink
/// claims its basename at its directory's rank; a same-basename entry in a lower
/// directory is masked. Content is then contributed only by an entry that resolves
/// to a readable regular file. Two entries claim a basename WITHOUT contributing
/// content: the distro `99-sysctl.conf -> ../sysctl.conf` slot (its content flows
/// via the `/etc/sysctl.conf` applier model) and the man sysctl.d(5) `-> /dev/null`
/// disable idiom (which masks a vendor file without applying anything).
fn enumerate(prefix: &Path) -> (Vec<SurvivingFile>, Vec<MaskedFile>, Vec<Diagnostic>) {
    let link_99 = prefix.join("etc/sysctl.d/99-sysctl.conf");
    let mut surviving = Vec::new();
    let mut masked = Vec::new();
    let mut f01 = Vec::new();
    // basename -> the surviving (highest-precedence) file that provides it.
    let mut seen: HashMap<OsString, PathBuf> = HashMap::new();

    for (dir, rank) in search_dirs(prefix) {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                f01.push(Diagnostic::new(
                    Severity::Fatal,
                    "sysctld-F01",
                    0..0,
                    format!("cannot read sysctl.d directory {}: {e}", dir.display()),
                    dir.clone(),
                    0,
                    0,
                ));
                continue;
            }
        };
        // Collect every `.conf`-NAMED entry (by name only - do NOT pre-filter by
        // `is_file()`, which would FOLLOW a `-> /dev/null` disable symlink to a char
        // device and drop it before it can claim/mask its basename). Sorted for
        // deterministic masking within a directory.
        let mut conf: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "conf"))
            .collect();
        conf.sort();
        for path in conf {
            // Masking is TYPE-AGNOSTIC by basename: EVERY `.conf`-named directory
            // entry claims its basename - a regular file, a symlink (to anything), OR
            // a direct non-regular entry (a `.conf`-named subdirectory, fifo, socket,
            // or device). Both procps-ng 3.3.17 and systemd-sysctl 259 mask this way.
            // Classify WITHOUT following the link (symlink_metadata) so the 99-slot
            // symlink is recognised below; the content decision follows the link.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let ftype = meta.file_type();
            let Some(basename) = path.file_name().map(OsStr::to_os_string) else {
                continue;
            };
            // First directory to hold a basename provides it; a same-basename entry in
            // a lower directory is masked (recorded for the W03-c masked-key-drop check).
            if let Some(masker) = seen.get(&basename) {
                masked.push(MaskedFile {
                    path,
                    masked_by: masker.clone(),
                });
                continue;
            }
            seen.insert(basename.clone(), path.clone());
            // Content contribution, decided AFTER the basename claim above.
            if ftype.is_symlink() && path == link_99 {
                // The distro `99-sysctl.conf -> ../sysctl.conf` slot: claims its
                // basename, but its content flows via the `/etc/sysctl.conf` applier
                // model (W03-b), not as a parsed drop-in.
                continue;
            }
            if path.is_file() {
                // A regular file, or a symlink to a readable regular file: a real
                // drop-in whose assignments contribute to the merged set.
                surviving.push(SurvivingFile {
                    path,
                    basename,
                    rank,
                });
            }
            // Otherwise (a `-> /dev/null` disable symlink, a dangling symlink, a
            // symlink to a non-regular target, or a direct non-regular entry such as
            // a `.conf`-named directory / fifo / device): the entry has CLAIMED
            // (masks) its basename above but contributes NO assignments and is never
            // parsed or recursed into (sysctl.d does not descend into subdirectories,
            // so no F01). This is the man sysctl.d(5) `-> /dev/null` disable idiom and
            // the type-agnostic-masking behavior of both real appliers.
        }
    }
    (surviving, masked, f01)
}

/// The procps/systemd applier-divergence pass (`sysctld-W03-b`).
///
/// procps `sysctl --system` reads `/etc/sysctl.conf` dead-last (always winning);
/// systemd-sysctl applies it only at the `99-sysctl.conf` symlink slot (or not at
/// all if the symlink is absent/dangling). For each key set in `/etc/sysctl.conf`,
/// if the two appliers resolve DIFFERENT effective values, one W03 is emitted
/// anchored at the `/etc/sysctl.conf` assignment, stating both values and the cause.
/// When both appliers agree the key is suppressed.
fn w03b_divergence(
    dropins: &[ParsedAssignment],
    etc_conf: &[ParsedAssignment],
    symlink_ok: bool,
) -> Vec<Diagnostic> {
    if etc_conf.is_empty() {
        return Vec::new();
    }

    // The systemd effective value of each key: drop-ins at their own basenames, plus
    // `/etc/sysctl.conf` spliced at the `99-sysctl.conf` slot when the symlink
    // resolves, merged in lexicographic basename order, last-wins.
    let ninety_nine = OsString::from("99-sysctl.conf");
    let mut entries: Vec<(OsString, &ParsedAssignment)> = dropins
        .iter()
        .map(|a| {
            let basename = a
                .file
                .file_name()
                .map_or_else(OsString::new, OsStr::to_os_string);
            (basename, a)
        })
        .collect();
    if symlink_ok {
        entries.extend(etc_conf.iter().map(|a| (ninety_nine.clone(), a)));
    }
    entries.sort_by(|x, y| x.0.cmp(&y.0));
    let mut systemd: HashMap<&str, &ParsedAssignment> = HashMap::new();
    for (_, a) in &entries {
        systemd.insert(a.canonical.as_str(), a);
    }

    let mut out = Vec::new();
    for (i, a) in etc_conf.iter().enumerate() {
        // procps applies `/etc/sysctl.conf` dead-last, so this key's procps value is
        // its LAST assignment in the file; skip earlier duplicates so each key fires
        // at most once.
        if etc_conf[i + 1..].iter().any(|b| b.canonical == a.canonical) {
            continue;
        }
        let procps_val = &a.value;
        let systemd_win = systemd.get(a.canonical.as_str()).copied();
        let diverges = match systemd_win {
            None => true,
            Some(sw) => &sw.value != procps_val,
        };
        if !diverges {
            continue;
        }
        let (systemd_verb, systemd_reason) = match systemd_win {
            None => (
                format!("leaves `{}` unset", a.display),
                "systemd-sysctl does not apply /etc/sysctl.conf (no \
                 /etc/sysctl.d/99-sysctl.conf symlink)"
                    .to_string(),
            ),
            Some(sw) => {
                let verb = format!("applies `{}`", sw.value);
                let reason = if symlink_ok {
                    format!(
                        "systemd-sysctl applies /etc/sysctl.conf at the 99-sysctl.conf \
                         slot, but {} sorts after it and wins",
                        sw.file.display()
                    )
                } else {
                    format!(
                        "systemd-sysctl does not apply /etc/sysctl.conf (no \
                         99-sysctl.conf symlink); {} applies instead",
                        sw.file.display()
                    )
                };
                (verb, reason)
            }
        };
        let message = format!(
            "cross-directory applier divergence for `{}`: procps `sysctl --system` \
             applies `{}` (/etc/sysctl.conf read dead-last), but systemd-sysctl {} - {}",
            a.display, procps_val, systemd_verb, systemd_reason,
        );
        out.push(anchored(
            Severity::Warning,
            "sysctld-W03",
            a.span.clone(),
            message,
            a.file.clone(),
            a.line,
        ));
    }
    out
}

/// Scan the standard `sysctl.d` search-path directories (`/etc/sysctl.d`,
/// `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, plus the
/// `/lib/sysctl.d` alias) and `/etc/sysctl.conf`, optionally rooted at `root` (the
/// `--root PREFIX` hermetic-testing / chroot surface), and run the full `sysctld-`
/// pass set over the precedence-merged result: `sysctld-F01`/`sysctld-W01`, the
/// version-aware `sysctld-W02` when `target` is `Some`, and the cross-directory
/// `sysctld-W03` (a/b/c).
///
/// Returns the diagnostics plus every read file's staged source (keyed by display
/// path, the `source_id` convention `anchored` sets), so the human renderer can show
/// an ariadne snippet (issue #337), matching
/// [`crate::parser::lint_dir_with_target`]'s return shape. A nonexistent `--root`
/// (no directories enumerate, no `/etc/sysctl.conf`) yields an empty result, not an
/// error (read-only tolerance).
/// Parse each surviving drop-in in merge order, returning its assignments and a
/// parallel per-assignment search-directory rank vector, extending `diags` with any
/// F01 and staging every read source under its display path.
fn parse_surviving(
    surviving: &[SurvivingFile],
    diags: &mut Vec<Diagnostic>,
    sources: &mut BTreeMap<String, String>,
) -> (Vec<ParsedAssignment>, Vec<usize>) {
    let mut asgns: Vec<ParsedAssignment> = Vec::new();
    let mut ranks: Vec<usize> = Vec::new();
    for sf in surviving {
        match std::fs::read_to_string(&sf.path) {
            Ok(src) => {
                let (parsed, f01) = parse_file(&src, &sf.path);
                diags.extend(f01);
                asgns.extend(parsed);
                // Pad the parallel rank vector for every assignment just added.
                ranks.resize(asgns.len(), sf.rank);
                sources.insert(sf.path.display().to_string(), src);
            }
            Err(e) => diags.push(unreadable_file_f01(&sf.path, &e)),
        }
    }
    (asgns, ranks)
}

/// Parse `/etc/sysctl.conf` under `prefix` (read dead-last by procps). A missing
/// file yields no assignments; an unreadable one yields a file-level F01.
fn parse_etc_conf(
    prefix: &Path,
    diags: &mut Vec<Diagnostic>,
    sources: &mut BTreeMap<String, String>,
) -> Vec<ParsedAssignment> {
    let etc_conf = prefix.join("etc/sysctl.conf");
    if !etc_conf.is_file() {
        return Vec::new();
    }
    match std::fs::read_to_string(&etc_conf) {
        Ok(src) => {
            let (asgns, f01) = parse_file(&src, &etc_conf);
            diags.extend(f01);
            sources.insert(etc_conf.display().to_string(), src);
            asgns
        }
        Err(e) => {
            diags.push(unreadable_file_f01(&etc_conf, &e));
            Vec::new()
        }
    }
}

/// The W03-a lower-precedence-directory-override pass, together with the reused W01
/// last-wins pass minus the dead lines W03-a claims (design section 3 point 4).
///
/// `ranks[i]` is `merged[i]`'s search-directory rank (0 highest), or `None` for the
/// dead-last `/etc/sysctl.conf` (not a directory tier: its winning is the applier
/// question W03-b handles, never a directory-precedence surprise).
fn w03a_and_w01(merged: &[ParsedAssignment], ranks: &[Option<usize>]) -> Vec<Diagnostic> {
    let effective = effective_values(merged);
    let mut w03a = Vec::new();
    let mut suppressed: HashSet<(PathBuf, usize)> = HashSet::new();
    for (idx, a) in merged.iter().enumerate() {
        let win_idx = effective[a.canonical.as_str()];
        if win_idx == idx {
            continue;
        }
        let win = &merged[win_idx];
        if win.value == a.value {
            continue;
        }
        // Both must be drop-ins; the winner must sit in a LOWER-precedence directory
        // (a strictly higher rank) than this dead assignment.
        let (Some(dead_rank), Some(win_rank)) = (ranks[idx], ranks[win_idx]) else {
            continue;
        };
        if win_rank > dead_rank {
            let message = format!(
                "cross-directory precedence surprise: `{}` (= {}) here in a \
                 higher-precedence directory is overridden by the assignment (= {}) \
                 at {}:{}, which sits in a lower-precedence search directory but has \
                 a lexicographically-later filename",
                a.display,
                a.value,
                win.value,
                win.file.display(),
                win.line,
            );
            w03a.push(anchored(
                Severity::Warning,
                "sysctld-W03",
                a.span.clone(),
                message,
                a.file.clone(),
                a.line,
            ));
            suppressed.insert((a.file.clone(), a.line));
        }
    }

    let mut out: Vec<Diagnostic> = w01_last_wins(merged)
        .into_iter()
        .filter(|d| !suppressed.contains(&(d.file.clone(), d.line)))
        .collect();
    out.extend(w03a);
    out
}

/// The W03-c pass: a masked drop-in sets a key whose canonical form is absent from
/// the effective merged set (no surviving file applies it), so it is silently
/// dropped relative to that file's intent. Masked files are otherwise invisible -
/// their F01s are discarded - and each read source is staged for the ariadne
/// snippet at the dropped key's line.
fn w03c_masked_key_drops(
    masked: &[MaskedFile],
    merged: &[ParsedAssignment],
    sources: &mut BTreeMap<String, String>,
) -> Vec<Diagnostic> {
    let effective = effective_values(merged);
    let mut out = Vec::new();
    let mut emitted: HashSet<(PathBuf, String)> = HashSet::new();
    for mf in masked {
        let Ok(src) = std::fs::read_to_string(&mf.path) else {
            continue;
        };
        let (asgns, _f01) = parse_file(&src, &mf.path);
        for a in &asgns {
            if effective.contains_key(a.canonical.as_str()) {
                continue;
            }
            if !emitted.insert((mf.path.clone(), a.canonical.clone())) {
                continue;
            }
            let message = format!(
                "masked drop-in drops a key: `{}` (= {}) set here is silently \
                 unapplied - a same-basename file in a higher-precedence directory \
                 ({}) masks this file, and no surviving file sets `{}`",
                a.display,
                a.value,
                mf.masked_by.display(),
                a.display,
            );
            out.push(anchored(
                Severity::Warning,
                "sysctld-W03",
                a.span.clone(),
                message,
                a.file.clone(),
                a.line,
            ));
        }
        sources.insert(mf.path.display().to_string(), src);
    }
    out
}

#[must_use]
pub fn lint_system(
    root: Option<&Path>,
    target: Option<TargetVersion>,
) -> (Vec<Diagnostic>, BTreeMap<String, String>) {
    let prefix = root.unwrap_or_else(|| Path::new("/"));

    let (mut surviving, mut masked, mut diags) = enumerate(prefix);
    // Global merge order is BYTEWISE by basename across all directories.
    surviving.sort_by(|a, b| a.basename.cmp(&b.basename));
    masked.sort_by(|a, b| a.path.cmp(&b.path));

    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let (surviving_asgns, surviving_ranks) = parse_surviving(&surviving, &mut diags, &mut sources);
    let etc_conf_asgns = parse_etc_conf(prefix, &mut diags, &mut sources);

    let symlink_ok = slot_symlink_ok(prefix);
    // W03-b needs the pre-merge handles, so compute it before the two are moved.
    let applier = w03b_divergence(&surviving_asgns, &etc_conf_asgns, symlink_ok);

    // The procps merged, precedence-ordered assignment list: drop-ins in basename
    // order, then /etc/sysctl.conf dead-last. Ranks run parallel (None = the
    // dead-last /etc/sysctl.conf, which is not a search-directory tier).
    let mut merged = surviving_asgns;
    let mut ranks: Vec<Option<usize>> = surviving_ranks.into_iter().map(Some).collect();
    merged.extend(etc_conf_asgns);
    ranks.resize(merged.len(), None);

    diags.extend(w03a_and_w01(&merged, &ranks));
    if let Some(t) = target {
        diags.extend(w02_baseline(&merged, t, &prefix.join("etc/sysctl.d")));
    }
    diags.extend(w03c_masked_key_drops(&masked, &merged, &mut sources));
    diags.extend(applier);
    (diags, sources)
}
