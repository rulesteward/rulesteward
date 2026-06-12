//! `SELinux` AVC denial log parser.
//!
//! Phase-0 shared foundation (issue #95): the tolerant `type=AVC` parser +
//! `AvcDenial` model that the triage / te-emit / libsepol pipelines all consume.
//!
//! The kernel emits `type=AVC` records in two callbacks (`avc_audit_pre_callback` +
//! `avc_audit_post_callback` in `security/selinux/avc.c`). This module parses one
//! AVC line OR an `ausearch`-grouped multi-line block, producing one [`AvcDenial`]
//! per `type=AVC` record found.
//!
//! # Design decisions
//!
//! - **Tolerant by default**: unknown `k=v` fields are silently ignored; double
//!   spaces in the verdict/perm-brace area are accepted (they are what the kernel
//!   emits, per `Linux v6.12 security/selinux/avc.c:659`).
//! - **Hex residual perm tokens preserved**: when the kernel encounters unknown
//!   permission bits it emits `0x%x` inside the braces (`Linux v6.12 security/selinux/avc.c:677`). These are
//!   stored verbatim in [`AvcDenial::perms`].
//! - **`ssid=`/`tsid=` fallback**: when a SID cannot be resolved to a context
//!   string the kernel emits `ssid=NNN`/`tsid=NNN` (`Linux v6.12 security/selinux/avc.c:709,714`). We store
//!   the raw token (e.g. `"ssid=42"`) in both `*_raw` and `source_type`/`target_type`
//!   so callers can detect and handle the numeric form. This is the most informative
//!   representation that does not require fabricating a fake context string.
//! - **No regex**: parsed with `std` string operations only (no new heavy deps).
//! - **ausearch grouping**: companion `SYSCALL`/`PATH` records sharing the same
//!   `audit(TS:SERIAL)` token enrich `exe=` and `path=` in the [`AvcDenial`].

use std::collections::HashMap;

use rulesteward_core::extract_audit_field;
use serde::Serialize;

/// Verdict from a `type=AVC` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// A real or permissive-mode denial (`avc:  denied`).
    Denied,
    /// An audited-allow grant (`avc:  granted`).
    Granted,
}

/// One parsed `type=AVC` denial (or audited-allow grant).
///
/// Built from the four kernel-guaranteed `SELinux` fields (`scontext`, `tcontext`,
/// `tclass`, and on a denial `permissive`) plus optional context fields that vary
/// by LSM hook type (see f4 section 1.1). Companion facts (`exe=`, `path=`) are
/// enriched when an `ausearch`-grouped block is supplied (f4 section 1.3).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AvcDenial {
    /// `Denied` or `Granted` (audited allow).
    pub verdict: Verdict,
    /// Permission tokens from the `{ ... }` brace list. May contain a raw
    /// `0x%x` hex token for unknown kernel permission bits (`Linux v6.12 security/selinux/avc.c:677`).
    pub perms: Vec<String>,
    /// The TYPE component of `scontext` (`user:role:TYPE[:level]`). This is
    /// the source domain used in a TE allow rule.
    pub source_type: String,
    /// The TYPE component of `tcontext`. This is the target type used in a
    /// TE allow rule.
    pub target_type: String,
    /// Object class name (e.g. `"file"`, `"dir"`, `"process"`).
    pub tclass: String,
    /// `Some(false)` = enforcing denial (real block), `Some(true)` = permissive
    /// denial (did NOT actually block), `None` = granted record (no `permissive=`
    /// field emitted by kernel for grants, per `Linux v6.12 security/selinux/avc.c:721`).
    pub permissive: Option<bool>,
    /// Full raw source context string (`user:role:type[:level]`).
    pub scontext_raw: String,
    /// Full raw target context string (`user:role:type[:level]`).
    pub tcontext_raw: String,
    /// Process ID from `pid=` on the AVC line (optional).
    pub pid: Option<u32>,
    /// Process comm from `comm="..."` on the AVC line (optional).
    pub comm: Option<String>,
    /// Executable path enriched from a companion `SYSCALL` record's `exe=` (optional).
    pub exe: Option<String>,
    /// Path enriched from a companion `PATH` record's `name=` (optional).
    pub path: Option<String>,
    /// Object name from `name="..."` on the AVC line (optional).
    pub name: Option<String>,
    /// Audit serial number from `audit(EPOCH:SERIAL)`.
    pub serial: Option<u64>,
    /// Audit timestamp (epoch seconds with fractional ms) from `audit(EPOCH:SERIAL)`.
    pub timestamp: Option<f64>,
}

/// Error returned by [`parse_avc`].
#[derive(Debug, thiserror::Error)]
pub enum AvcParseError {
    /// Input contained no `type=AVC` line.
    #[error("no type=AVC record found in input")]
    NoAvcRecord,
    /// The `avc:` verdict token was present but unrecognizable.
    #[error("unrecognized AVC verdict token: {0:?}")]
    UnknownVerdict(String),
    /// A required `SELinux` field (`scontext`, `tcontext`, or `tclass`) was absent.
    #[error("missing required SELinux field: {0}")]
    MissingField(&'static str),
}

/// Parse one AVC line OR an `ausearch`-grouped multi-line event block.
///
/// Returns one [`AvcDenial`] per `type=AVC` record found. Companion `SYSCALL`
/// and `PATH` records in the same block are correlated by shared
/// `audit(TS:SERIAL)` and used to enrich `exe=` / `path=`.
///
/// # Errors
///
/// Returns [`AvcParseError::NoAvcRecord`] when no `type=AVC` line is found.
/// Returns [`AvcParseError::MissingField`] when a required `SELinux` field is absent.
pub fn parse_avc(input: &str) -> Result<Vec<AvcDenial>, AvcParseError> {
    let lines: Vec<&str> = input.lines().collect();

    // Companion map: audit serial string -> enrichment facts from SYSCALL/PATH records.
    let mut companion: HashMap<String, CompanionFacts> = HashMap::new();
    let mut avc_lines: Vec<(String, &str)> = Vec::new(); // (serial, line)

    for line in &lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Correlation key: the numeric serial from `audit(EPOCH:SERIAL)`. Keying
        // on the SAME parsed serial that fills `AvcDenial.serial` (rather than a
        // second, string-returning parser) means the anchor test's serial +
        // timestamp assertions also pin this correlation key - no internal-only
        // helper whose output is never surfaced.
        let (_timestamp, serial) = parse_audit_timestamp_serial(line);
        let serial_str = serial.map(|serial| serial.to_string()).unwrap_or_default();

        if line.starts_with("type=AVC ") || line.contains(" type=AVC ") {
            avc_lines.push((serial_str, line));
        } else if (line.starts_with("type=SYSCALL ") || line.contains(" type=SYSCALL "))
            && let Some(exe) = avc_field(line, "exe")
        {
            companion.entry(serial_str).or_default().exe = Some(exe);
        } else if (line.starts_with("type=PATH ") || line.contains(" type=PATH "))
            && let Some(name) = avc_field(line, "name")
        {
            companion.entry(serial_str).or_default().path = Some(name);
        }
    }

    if avc_lines.is_empty() {
        return Err(AvcParseError::NoAvcRecord);
    }

    let mut results = Vec::with_capacity(avc_lines.len());
    for (serial_str, line) in avc_lines {
        let comp = companion.get(&serial_str).cloned().unwrap_or_default();
        results.push(parse_single_avc_line(line, comp)?);
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Companion facts enriched from non-AVC records in the same audit event.
#[derive(Debug, Default, Clone)]
struct CompanionFacts {
    exe: Option<String>,
    path: Option<String>,
}

/// Parse timestamp and serial from `audit(EPOCH:SERIAL)`.
fn parse_audit_timestamp_serial(line: &str) -> (Option<f64>, Option<u64>) {
    let Some(after_open) = line.find("audit(").map(|i| &line[i + 6..]) else {
        return (None, None);
    };
    let Some(colon) = after_open.find(':') else {
        return (None, None);
    };
    let ts_str = &after_open[..colon];
    let after_colon = &after_open[colon + 1..];
    let Some(close) = after_colon.find(')') else {
        return (None, None);
    };
    let serial_str = &after_colon[..close];
    (ts_str.parse::<f64>().ok(), serial_str.parse::<u64>().ok())
}

/// Extract an audit `key=value` from an AVC line as an owned `String`.
///
/// Thin wrapper over [`rulesteward_core::extract_audit_field`], which carries the
/// word-boundary guard (so a search for `pid` does NOT match inside `ppid=`) plus
/// the quoted/unquoted value handling. This replaces the two former hand-rolled
/// extractors (`extract_quoted_or_plain` / `extract_plain_value`), which used a
/// bare `line.find(key)` with no boundary guard (issue #192, D1). Every field this
/// parser reads (`scontext`/`tclass`/`pid`/`ssid`/...) is unquoted in kernel
/// output, so the quoted-aware core extractor returns the identical value for the
/// plain ones. `key` is passed WITHOUT the trailing `=`.
fn avc_field(line: &str, key: &str) -> Option<String> {
    extract_audit_field(line, key).map(str::to_string)
}

/// Extract the TYPE component (third colon-delimited field) from a full `SELinux`
/// context `user:role:type[:level]`.
///
/// Tolerant-by-default fallback: a malformed context with fewer than three
/// colon-delimited fields returns the WHOLE context string unchanged (e.g.
/// `user:role` -> `user:role`). Real kernel AVC records always carry full
/// contexts, so this path only fires on hand-mangled input; returning the
/// full string keeps the malformation visible downstream instead of hiding
/// it behind an empty type.
fn extract_type_from_context(ctx: &str) -> String {
    let mut parts = ctx.splitn(4, ':');
    parts.next(); // user
    parts.next(); // role
    parts.next().unwrap_or(ctx).to_string() // type
}

/// Parse one `type=AVC` line into an [`AvcDenial`].
fn parse_single_avc_line(
    line: &str,
    companion: CompanionFacts,
) -> Result<AvcDenial, AvcParseError> {
    let (timestamp, serial) = parse_audit_timestamp_serial(line);

    // Locate "avc: " and parse verdict + perm brace.
    // Kernel emits: "avc:  denied  { ... } for  " (two spaces each, `Linux v6.12 security/selinux/avc.c:659`).
    let avc_pos = line
        .find("avc: ")
        .ok_or(AvcParseError::MissingField("avc: marker"))?;
    // Skip "avc: " then trim leading spaces (the second space in "avc:  denied").
    let after_avc = line[avc_pos + 5..].trim_start();

    let (verdict, after_verdict);
    if let Some(rest) = after_avc.strip_prefix("denied") {
        verdict = Verdict::Denied;
        after_verdict = rest;
    } else if let Some(rest) = after_avc.strip_prefix("granted") {
        verdict = Verdict::Granted;
        after_verdict = rest;
    } else {
        let token = after_avc
            .split_ascii_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        return Err(AvcParseError::UnknownVerdict(token));
    }

    // Trim spaces before "{", then parse brace list.
    let after_verdict_trimmed = after_verdict.trim_start();
    let Some(brace_start) = after_verdict_trimmed.strip_prefix('{') else {
        return Err(AvcParseError::MissingField("perm brace {"));
    };
    let close = brace_start
        .find('}')
        .ok_or(AvcParseError::MissingField("closing brace }"))?;
    let perms: Vec<String> = brace_start[..close]
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    let after_brace = &brace_start[close + 1..];

    // Skip "for " (with possible leading spaces - kernel emits "} for  ").
    let for_rest = after_brace.trim_start();
    let after_for = for_rest
        .strip_prefix("for")
        .map(str::trim_start)
        .ok_or(AvcParseError::MissingField("'for' keyword"))?;

    // -- scontext= or ssid= fallback (`Linux v6.12 security/selinux/avc.c:711,709`) --
    let (scontext_raw, source_type) = if let Some(sctx) = avc_field(after_for, "scontext") {
        let stype = extract_type_from_context(&sctx);
        (sctx, stype)
    } else if let Some(ssid) = avc_field(after_for, "ssid") {
        let raw = format!("ssid={ssid}");
        (raw.clone(), raw)
    } else {
        return Err(AvcParseError::MissingField("scontext= or ssid="));
    };

    // -- tcontext= or tsid= fallback (`Linux v6.12 security/selinux/avc.c:716,714`) --
    let (tcontext_raw, target_type) = if let Some(tctx) = avc_field(after_for, "tcontext") {
        let ttype = extract_type_from_context(&tctx);
        (tctx, ttype)
    } else if let Some(tsid) = avc_field(after_for, "tsid") {
        let raw = format!("tsid={tsid}");
        (raw.clone(), raw)
    } else {
        return Err(AvcParseError::MissingField("tcontext= or tsid="));
    };

    // -- tclass= (`Linux v6.12 security/selinux/avc.c:719`) --
    let tclass = avc_field(after_for, "tclass").ok_or(AvcParseError::MissingField("tclass="))?;

    // -- permissive= only on denial records (`Linux v6.12 security/selinux/avc.c:721-722`) --
    let permissive = if verdict == Verdict::Denied {
        avc_field(after_for, "permissive").map(|v| v == "1")
    } else {
        None
    };

    // -- Optional AVC-line context fields --
    let pid = avc_field(after_for, "pid").and_then(|v| v.parse::<u32>().ok());
    let comm = avc_field(after_for, "comm");
    let name = avc_field(after_for, "name");

    // exe: prefer AVC line, fall back to companion SYSCALL record.
    let exe = avc_field(after_for, "exe").or(companion.exe);
    let path = companion.path;

    Ok(AvcDenial {
        verdict,
        perms,
        source_type,
        target_type,
        tclass,
        permissive,
        scontext_raw,
        tcontext_raw,
        pid,
        comm,
        exe,
        path,
        name,
        serial,
        timestamp,
    })
}
