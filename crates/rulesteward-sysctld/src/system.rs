//! `sysctl lint --system`: cross-directory precedence scan (issue #420).
//!
//! Real systems apply `sysctl.d` drop-ins across a search path of four-plus
//! directories plus `/etc/sysctl.conf`; the effective value of a key can be
//! silently decided by a file the operator would not expect to win. [`lint_system`]
//! enumerates that search path (optionally rooted at a `--root` prefix for hermetic
//! testing / chroot-linting), applies the grounded same-basename directory masking
//! and global lexicographic merge, and runs the existing
//! `sysctld-F01`/`sysctld-W01`/`sysctld-W02`/`sysctld-W04` passes over the merged,
//! precedence-ordered assignment list plus the cross-directory `sysctld-W03`
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
use crate::lints::cis::w04_baseline;
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

/// Resolve a symlink's on-disk target using RE-ROOT-THEN-CONTAIN semantics
/// (orchestrator ruling 2026-07-31, round 2 of issue #593): an ABSOLUTE target
/// resolves as `<prefix>/<target>` - what a real chroot/image applier would do,
/// and what makes an admin's `ln -s /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf`
/// repair correctly recognized as the distro slot - while a RELATIVE target
/// resolves against `link`'s own parent directory, exactly like an ordinary
/// symlink. Either way, the fully-resolved result is then required to still sit
/// under `prefix`: anything that escapes (a `..`-relative walkout, or an absolute
/// target with no re-rooted counterpart under `prefix`) is UNRESOLVABLE (`None`)
/// rather than being followed onto the real filesystem outside the scanned root.
/// Also `None` when `link` is not a symlink at all, or is dangling.
///
/// This `Some` result is not just a boolean admission gate: for the 99-slot
/// caller in [`enumerate`] it is also the exact path that gets READ
/// (`SurvivingFile::read_path`, round 3, #593 Finding 1). Using it for the read
/// too - not merely to decide whether to admit the entry - is what makes the
/// "never followed onto the real filesystem outside the scanned root" guarantee
/// above actually hold end to end: a contained, re-rooted absolute target must
/// be read from that re-rooted path, or the bytes would still come from
/// wherever the literal (non-rerooted) link happens to dereference to on the
/// real host filesystem.
///
/// Written GENERICALLY in terms of `prefix`, never branching on "do we have a
/// `--root`": a live scan passes `prefix == "/"`, where re-rooting an absolute
/// target is the IDENTITY (`/x` re-roots to `/x`) and containment trivially
/// holds (every canonical path already starts with `/`). Real-system linting is
/// simply the `prefix == "/"` case of this same function.
fn resolve_reroot_contained(prefix: &Path, link: &Path) -> Option<PathBuf> {
    let target = std::fs::read_link(link).ok()?;
    let candidate = if target.is_absolute() {
        // RE-ROOT: join onto `prefix`, not the real filesystem root. A
        // genuinely absolute Unix path always strips "/" successfully; the
        // empty-path fallback is unreachable in practice and simply re-joins
        // `prefix` itself.
        prefix.join(target.strip_prefix("/").unwrap_or_else(|_| Path::new("")))
    } else {
        link.parent()?.join(&target)
    };
    let resolved = std::fs::canonicalize(&candidate).ok()?;
    let canonical_prefix = std::fs::canonicalize(prefix).ok()?;
    // CONTAIN: a resolution that lands outside `prefix` (via re-rooted-absolute
    // miss or a `..` walkout) is treated as unresolvable, never followed.
    resolved.starts_with(&canonical_prefix).then_some(resolved)
}

/// Whether the `/etc/sysctl.d/99-sysctl.conf` slot under `prefix` is the EXPECTED
/// distro symlink - a symlink that resolves (re-root-then-contain) to
/// `<prefix>/etc/sysctl.conf`.
///
/// This is the ONLY path by which systemd-sysctl applies `/etc/sysctl.conf` (design
/// section 2 point 3). Per design section 8, anything that is "not the expected
/// symlink" is treated as ABSENT (systemd does not apply `/etc/sysctl.conf`, so
/// W03-b fires): a non-symlink, a dangling link, a symlink to any OTHER target, or
/// (round 2, #593) a symlink whose resolution escapes `prefix` entirely.
///
/// [`resolve_reroot_contained`] already requires `link` to be an actual, resolvable
/// symlink (`read_link` fails on a non-symlink or a dangling one), so no separate
/// `is_symlink` guard is needed here; comparing its `Some` result against
/// `etc/sysctl.conf`'s own canonical path is the "expected distro symlink" check.
fn slot_symlink_ok(prefix: &Path) -> bool {
    let link_99 = prefix.join("etc/sysctl.d/99-sysctl.conf");
    let Some(resolved) = resolve_reroot_contained(prefix, &link_99) else {
        return false;
    };
    std::fs::canonicalize(prefix.join("etc/sysctl.conf")).is_ok_and(|etc_conf| resolved == etc_conf)
}

/// A drop-in that survived same-basename directory masking, tagged with its
/// search-directory precedence rank (0 = `/etc/sysctl.d`, highest).
///
/// `path` and `read_path` split the DISPLAY identity from the READ target
/// (round 3, #593 Finding 1): `path` is the directory entry itself (what
/// keys `sources`, what every diagnostic/provenance message names - the file
/// the operator has to fix), while `read_path` is where the bytes actually
/// come from. For every ordinary entry they are the same path (reading it
/// directly follows the real filesystem, exactly as before). Only the 99-slot
/// symlink entry (misdirected/dangling/escaping, followed as an ordinary
/// drop-in) ever sets `read_path` to something else: the RE-ROOT-THEN-CONTAIN
/// resolved path computed by [`resolve_reroot_contained`], so the containment
/// decision and the read agree - re-rooted content is what gets read, never
/// the real host file the literal link would otherwise dereference to.
struct SurvivingFile {
    path: PathBuf,
    read_path: PathBuf,
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
/// `symlink_ok` is [`slot_symlink_ok`]'s whole-prefix verdict for THIS `prefix`:
/// whether `<prefix>/etc/sysctl.d/99-sysctl.conf` actually resolves to
/// `<prefix>/etc/sysctl.conf`. It gates whether an entry AT that exact path is
/// recognised as the distro applier slot (see the content-decision comment below);
/// when it is `false` (no slot, a dangling link, or a symlink to anything else),
/// that entry is no longer special-cased and is enumerated like any other
/// `.conf`-named entry.
///
/// Masking is by directory ENTRY NAME (design section 2 point 1, man sysctl.d(5)),
/// separate from the content decision. EVERY `.conf`-named regular file or symlink
/// claims its basename at its directory's rank; a same-basename entry in a lower
/// directory is masked. Content is then contributed only by an entry that resolves
/// to a readable regular file. Two entries claim a basename WITHOUT contributing
/// content: the distro `99-sysctl.conf -> ../sysctl.conf` slot (its content flows
/// via the `/etc/sysctl.conf` applier model) and the man sysctl.d(5) `-> /dev/null`
/// disable idiom (which masks a vendor file without applying anything).
fn enumerate(
    prefix: &Path,
    symlink_ok: bool,
) -> (Vec<SurvivingFile>, Vec<MaskedFile>, Vec<Diagnostic>) {
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
                if symlink_ok {
                    // The distro `99-sysctl.conf -> ../sysctl.conf` slot, recognized
                    // ONLY when the symlink actually resolves (re-root-then-contain)
                    // to `<prefix>/etc/sysctl.conf` (`symlink_ok`): claims its
                    // basename, but its content flows via the `/etc/sysctl.conf`
                    // applier model (W03-b), not as a parsed drop-in.
                    continue;
                }
                // A symlink at this exact path that is NOT the recognized distro
                // slot (misdirected, dangling, or escaping `prefix`) is followed
                // like any other drop-in (#593) - but ONLY under RE-ROOT-THEN-
                // CONTAIN (round 2, read path fixed round 3): an absolute target
                // re-roots under `prefix` rather than the real filesystem, and any
                // resolution that still escapes `prefix` (dangling, an absolute
                // target with no re-rooted counterpart, or a `..` walkout) claims
                // the basename above but contributes NO content - it is never
                // followed onto a real path outside the scanned root. The
                // resolved path is what gets READ (`read_path`); `path` (the link
                // itself) stays the display/provenance key - see the
                // `SurvivingFile` doc comment. 99-slot only: the identical escape
                // for ORDINARY (non-99) drop-in symlinks pre-exists and is out of
                // scope here, filed separately as #610.
                if let Some(resolved) =
                    resolve_reroot_contained(prefix, &path).filter(|p| p.is_file())
                {
                    surviving.push(SurvivingFile {
                        path,
                        read_path: resolved,
                        basename,
                        rank,
                    });
                }
                continue;
            }
            if path.is_file() {
                // A regular file, or a symlink to a readable regular file: a real
                // drop-in whose assignments contribute to the merged set. (Not the
                // 99-slot path handled above, so this follows the real filesystem
                // directly - #610.) `read_path` equals `path`: an ordinary entry's
                // display path and read target are the same file.
                surviving.push(SurvivingFile {
                    path: path.clone(),
                    read_path: path,
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
///
/// `prefix` is used only to work out whether `/etc/sysctl.d/99-sysctl.conf` is
/// itself a symlink at all (round 2, #593 Finding 2): once a MISDIRECTED 99-slot
/// symlink is followed as an ordinary drop-in ([`enumerate`]), it can become the
/// winning `systemd_win` for a key `/etc/sysctl.conf` also sets, and the reason
/// clause must not claim "no symlink" while naming that exact symlink as the file
/// that applies instead.
/// Compute the systemd-sysctl verb + reason clause for one diverging key inside
/// [`w03b_divergence`]. Split out of that function only to stay under the
/// workspace `clippy::too_many_lines` budget; no behavior change from the
/// inline version.
///
/// The four `Some(sw)` branches below are meant to be exhaustive and mutually
/// exclusive over every reachable shape of the 99 slot: (1) the slot resolves
/// correctly (`symlink_ok`) but a later drop-in still wins, (2) the slot is a
/// symlink and IS itself the winner (misdirected, followed as an ordinary
/// drop-in), (3) the slot is a symlink but some OTHER drop-in wins (dangling,
/// escaping `--root`, or misdirected to a target that sets no keys), and (4)
/// there is genuinely no symlink at the slot at all (absent, or replaced by a
/// regular file). Cases (2)-(4) all fall through `symlink_ok == false`; the
/// `slot_is_symlink` check and the `sw.file == link_99` check are independent
/// questions - a symlink EXISTING at the slot says nothing about whether it
/// resolves to `/etc/sysctl.conf` or about which file wins a given key - and
/// conflating them is exactly what previously made the final `else` claim "no
/// symlink" for a slot where a symlink was genuinely present, just broken.
fn w03b_verb_and_reason(
    a: &ParsedAssignment,
    systemd_win: Option<&ParsedAssignment>,
    symlink_ok: bool,
    slot_is_symlink: bool,
    link_99: &Path,
) -> (String, String) {
    match systemd_win {
        None => {
            // (round 3, #593 Finding 2) A hardcoded "no symlink" reason is
            // only true when `slot_is_symlink` is false. When a symlink
            // genuinely EXISTS at the 99-slot but resolves to nothing that
            // sets this key (dangling, escaping `--root`, or misdirected to
            // a target that sets no keys at all), `systemd_win` is `None`
            // too, but claiming "no symlink" is false and points the
            // operator at the wrong remedy (create one, which fails with
            // EEXIST) instead of the right one (repoint/fix the existing
            // one).
            let reason = if slot_is_symlink {
                "the /etc/sysctl.d/99-sysctl.conf symlink exists but does \
                 not resolve to /etc/sysctl.conf (it is dangling, escapes \
                 --root, or points elsewhere), so systemd-sysctl does not \
                 apply /etc/sysctl.conf there"
                    .to_string()
            } else {
                "systemd-sysctl does not apply /etc/sysctl.conf (no \
                 /etc/sysctl.d/99-sysctl.conf symlink)"
                    .to_string()
            };
            (format!("leaves `{}` unset", a.display), reason)
        }
        Some(sw) => {
            let verb = format!("applies `{}`", sw.value);
            let reason = if symlink_ok {
                format!(
                    "systemd-sysctl applies /etc/sysctl.conf at the 99-sysctl.conf \
                     slot, but {} sorts after it and wins",
                    sw.file.display()
                )
            } else if slot_is_symlink && sw.file == link_99 {
                // The winner IS the 99-sysctl.conf entry itself, followed as an
                // ordinary drop-in because it is a symlink that does not resolve
                // to /etc/sysctl.conf (misdirected or escaping --root, #593 round
                // 2). Naming it while also asserting "no symlink" would be
                // self-contradictory; the correct remedy is to REPOINT the
                // symlink, not create one that already exists.
                "the /etc/sysctl.d/99-sysctl.conf symlink does not resolve to \
                 /etc/sysctl.conf (misdirected); systemd-sysctl does not apply \
                 /etc/sysctl.conf there - it reads the symlink's own target as \
                 an ordinary drop-in instead"
                    .to_string()
            } else if slot_is_symlink {
                // (round 4, #593 Finding - Adversarial Testing Loop) A symlink
                // genuinely EXISTS at the 99 slot (dangling, escaping --root, or
                // misdirected to a target that sets no keys of its own) but some
                // OTHER drop-in - not the symlink itself - wins this key. This is
                // the identical false "no symlink" claim the `None` arm above and
                // the `sw.file == link_99` arm just above both already guard
                // against, reached here because `sw.file != link_99`: the symlink
                // is present, just broken, and a separate file happens to win.
                // The remedy is still to REPOINT the existing symlink, not create
                // one that already exists.
                format!(
                    "the /etc/sysctl.d/99-sysctl.conf symlink exists but does \
                     not resolve to /etc/sysctl.conf (it is dangling, escapes \
                     --root, or points elsewhere), so systemd-sysctl does not \
                     apply /etc/sysctl.conf there; {} applies instead",
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
    }
}

fn w03b_divergence(
    dropins: &[ParsedAssignment],
    etc_conf: &[ParsedAssignment],
    symlink_ok: bool,
    prefix: &Path,
) -> Vec<Diagnostic> {
    if etc_conf.is_empty() {
        return Vec::new();
    }
    let link_99 = prefix.join("etc/sysctl.d/99-sysctl.conf");
    let slot_is_symlink =
        std::fs::symlink_metadata(&link_99).is_ok_and(|m| m.file_type().is_symlink());

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
    for &(_, a) in &entries {
        systemd.insert(a.canonical.as_str(), a);
    }

    // procps applies `/etc/sysctl.conf` dead-last, so each key's procps value is its
    // LAST assignment in the file. `effective_values` already maps each canonical key
    // to that last index; gating on `== i` fires each key exactly once at its winner.
    let procps_last = effective_values(etc_conf);
    let mut out = Vec::new();
    for (i, a) in etc_conf.iter().enumerate() {
        if procps_last[a.canonical.as_str()] != i {
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
        let (systemd_verb, systemd_reason) =
            w03b_verb_and_reason(a, systemd_win, symlink_ok, slot_is_symlink, &link_99);
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

/// Parse each surviving drop-in in merge order, returning its assignments and a
/// parallel per-assignment search-directory rank vector, extending `diags` with any
/// F01 and staging every read source under its display path.
///
/// Reads `sf.read_path` (the containment-checked, re-rooted target for a followed
/// 99-slot symlink; identical to `sf.path` for every ordinary entry - see the
/// `SurvivingFile` doc comment), never `sf.path` directly: the containment
/// decision and the read must agree, or an escaping/absolute symlink target could
/// be admitted on the re-rooted path yet silently read from the real host
/// filesystem instead (round 3, #593 Finding 1). Every diagnostic, provenance
/// error, and `sources` key still names `sf.path` (the link/file the operator
/// actually has to fix), never `read_path`.
fn parse_surviving(
    surviving: &[SurvivingFile],
    diags: &mut Vec<Diagnostic>,
    sources: &mut BTreeMap<String, String>,
) -> (Vec<ParsedAssignment>, Vec<usize>) {
    let mut asgns: Vec<ParsedAssignment> = Vec::new();
    let mut ranks: Vec<usize> = Vec::new();
    for sf in surviving {
        match std::fs::read_to_string(&sf.read_path) {
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
        // Routed through `rulesteward_core::fsread` (#560, closeout round 3): a
        // masked entry is collected without an `is_file()` filter (unlike the
        // surviving-file push above, gated by `path.is_file()`), so it can be a
        // FIFO/socket/device. A raw `std::fs::read_to_string` here blocks forever
        // on a masked FIFO with no writer; `fsread::read_to_string` fails fast
        // instead, and the pre-existing `else { continue }` already skips any read
        // error (a masked file's own read failure is deliberately invisible - see
        // the module doc above), so a skipped masked FIFO is correct: it has no
        // assignments to drop.
        let Ok(src) = rulesteward_core::fsread::read_to_string(&mf.path) else {
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

/// Scan the standard `sysctl.d` search-path directories (`/etc/sysctl.d`,
/// `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, plus the
/// `/lib/sysctl.d` alias) and `/etc/sysctl.conf`, optionally rooted at `root` (the
/// `--root PREFIX` hermetic-testing / chroot surface), and run the full `sysctld-`
/// pass set over the precedence-merged result: `sysctld-F01`/`sysctld-W01`, the
/// version-aware `sysctld-W02` (STIG) and `sysctld-W04` (CIS) when `target` is
/// `Some`, and the cross-directory `sysctld-W03` (a/b/c).
///
/// Returns the diagnostics plus every read file's staged source (keyed by display
/// path, the `source_id` convention `anchored` sets), so the human renderer can show
/// an ariadne snippet (issue #337), matching
/// [`crate::parser::lint_dir_with_target`]'s return shape. A nonexistent `--root`
/// (no directories enumerate, no `/etc/sysctl.conf`) yields an empty result, not an
/// error (read-only tolerance).
#[must_use]
pub fn lint_system(
    root: Option<&Path>,
    target: Option<TargetVersion>,
) -> (Vec<Diagnostic>, BTreeMap<String, String>) {
    let prefix = root.unwrap_or_else(|| Path::new("/"));

    // Computed once per call (rather than once per directory entry inside
    // `enumerate`) since it is a whole-prefix property, not a per-entry one.
    let symlink_ok = slot_symlink_ok(prefix);
    let (mut surviving, mut masked, mut diags) = enumerate(prefix, symlink_ok);
    // Global merge order is BYTEWISE by basename across all directories.
    surviving.sort_by(|a, b| a.basename.cmp(&b.basename));
    masked.sort_by(|a, b| a.path.cmp(&b.path));

    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let (surviving_asgns, surviving_ranks) = parse_surviving(&surviving, &mut diags, &mut sources);
    let etc_conf_asgns = parse_etc_conf(prefix, &mut diags, &mut sources);

    // W03-b needs the pre-merge handles, so compute it before the two are moved.
    let applier = w03b_divergence(&surviving_asgns, &etc_conf_asgns, symlink_ok, prefix);

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
        diags.extend(w04_baseline(&merged, t, &prefix.join("etc/sysctl.d")));
    }
    diags.extend(w03c_masked_key_drops(&masked, &merged, &mut sources));
    diags.extend(applier);
    (diags, sources)
}
