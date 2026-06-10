//! Workload parsing: terse-line and JSON formats into `Query`.

use anyhow::Context as _;
use rulesteward_fapolicyd::{Perm, Trust};

/// A single parsed access query from the workload.
pub(super) struct Query {
    pub(super) perm: Perm,
    pub(super) exe: Option<String>,
    pub(super) path: Option<String>,
    pub(super) comm: Option<String>,
    pub(super) device: Option<String>,
    pub(super) uids: Vec<u32>,
    pub(super) gids: Vec<u32>,
    pub(super) ftype: Option<String>,
    pub(super) sha256: Option<String>,
    /// Subject-side trust status.
    ///
    /// Set from `subjTrust` (per-side override) if present, else from
    /// `trust` (symmetric shorthand) if present, else `Trust::Unknown`.
    pub(super) subj_trust: Trust,
    /// Object-side trust status.
    ///
    /// Set from `objTrust` (per-side override) if present, else from
    /// `trust` (symmetric shorthand) if present, else `Trust::Unknown`.
    pub(super) obj_trust: Trust,
}

/// Parse a single JSON object `{exe, path, perm, ...}` into a `Query`.
fn parse_json_object(obj: &serde_json::Map<String, serde_json::Value>) -> anyhow::Result<Query> {
    let perm_str = obj.get("perm").and_then(|v| v.as_str()).unwrap_or("open");
    let perm = match perm_str {
        "open" => Perm::Open,
        "execute" => Perm::Execute,
        "any" => Perm::Any,
        other => anyhow::bail!("unknown perm value in workload: {other:?}"),
    };

    // Use `resolved_exe` when present (multicall binaries on RHEL 8/9/10 resolve
    // to a different path than the symlink), falling back to `exe`.
    let exe = obj
        .get("resolved_exe")
        .or_else(|| obj.get("exe"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let path = obj.get("path").and_then(|v| v.as_str()).map(str::to_owned);
    let comm = obj.get("comm").and_then(|v| v.as_str()).map(str::to_owned);
    let device = obj
        .get("device")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let ftype = obj.get("ftype").and_then(|v| v.as_str()).map(str::to_owned);
    let sha256 = obj
        .get("sha256")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // uid / gid: accept a single integer, an array of integers, or null (= absent).
    let uids = parse_int_field(obj, "uid")?;
    let gids = parse_int_field(obj, "gid")?;

    // trust: bool, null, or absent. null and absent both map to Trust::Unknown.
    // This is the symmetric shorthand: when subjTrust / objTrust are absent,
    // both sides inherit this value.
    let trust_sym = parse_trust_field(obj, "trust")?;

    // subjTrust / objTrust: per-side overrides. When present they take priority
    // over the symmetric `trust` shorthand for their respective side.
    let subj_trust =
        parse_trust_field(obj, "subjTrust")?.unwrap_or(trust_sym.unwrap_or(Trust::Unknown));
    let obj_trust =
        parse_trust_field(obj, "objTrust")?.unwrap_or(trust_sym.unwrap_or(Trust::Unknown));

    Ok(Query {
        perm,
        exe,
        path,
        comm,
        device,
        uids,
        gids,
        ftype,
        sha256,
        subj_trust,
        obj_trust,
    })
}

/// Parse a trust field by key: bool, null, or absent.
///
/// Returns `Ok(Some(Trust::Yes/No))` when the value is a boolean,
/// `Ok(None)` when the key is absent or `null` (caller decides the default),
/// and an error when the value has an unexpected type.
fn parse_trust_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<Option<Trust>> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(true)) => Ok(Some(Trust::Yes)),
        Some(serde_json::Value::Bool(false)) => Ok(Some(Trust::No)),
        Some(other) => anyhow::bail!("unexpected {key} value in workload: {other}"),
    }
}

/// Parse a uid or gid field: single integer, array, null, or absent.
/// `null` and absent both produce an empty Vec (absent fact - widens the match).
fn parse_int_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<Vec<u32>> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{key} must be a non-negative integer"))?;
            Ok(vec![
                u32::try_from(v).context(format!("{key} value {v} overflows u32"))?,
            ])
        }
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| {
                        anyhow::anyhow!("{key} array element must be a non-negative integer")
                    })
                    .and_then(|n| {
                        u32::try_from(n).context(format!("{key} value {n} overflows u32"))
                    })
            })
            .collect(),
        Some(other) => anyhow::bail!("unexpected {key} value: {other}"),
    }
}

/// Parse a terse line `perm exe -> path` into a `Query`.
///
/// Grammar: `<perm> <exe> -> <path>`
/// Examples:
///   `execute /usr/bin/curl -> /tmp/payload`
///   `open /usr/bin/cat -> /etc/hostname`
fn parse_terse_line(line: &str) -> anyhow::Result<Query> {
    let line = line.trim();
    // Split on " -> "
    let (left, path_part) = line
        .split_once(" -> ")
        .ok_or_else(|| anyhow::anyhow!("terse line missing ' -> ': {line:?}"))?;

    let mut parts = left.splitn(2, ' ');
    let perm_str = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("terse line missing perm: {line:?}"))?;
    let exe_str = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("terse line missing exe: {line:?}"))?;

    let perm = match perm_str {
        "open" => Perm::Open,
        "execute" => Perm::Execute,
        "any" => Perm::Any,
        other => anyhow::bail!("unknown perm in terse line: {other:?}"),
    };

    Ok(Query {
        perm,
        exe: Some(exe_str.trim().to_owned()),
        path: Some(path_part.trim().to_owned()),
        comm: None,
        device: None,
        uids: Vec::new(),
        gids: Vec::new(),
        ftype: None,
        sha256: None,
        subj_trust: Trust::Unknown,
        obj_trust: Trust::Unknown,
    })
}

/// Parse the workload string into a `Vec<Query>`.
///
/// Detects JSON (`{` or `[` prefix) vs terse line format.
pub(super) fn parse_workload(raw: &str) -> anyhow::Result<Vec<Query>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // JSON path
        let value: serde_json::Value =
            serde_json::from_str(trimmed).context("parsing workload JSON")?;
        match value {
            serde_json::Value::Object(obj) => Ok(vec![parse_json_object(&obj)?]),
            serde_json::Value::Array(arr) => arr
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    item.as_object()
                        .ok_or_else(|| {
                            anyhow::anyhow!("workload array element {i} is not an object")
                        })
                        .and_then(parse_json_object)
                })
                .collect(),
            other => anyhow::bail!("workload JSON must be an object or array, got: {other}"),
        }
    } else {
        // Terse line format
        raw.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(parse_terse_line)
            .collect()
    }
}
