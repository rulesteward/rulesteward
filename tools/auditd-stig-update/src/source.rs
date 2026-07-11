//! The live fetch seam: download a DISA STIG zip, unzip it, and read out the
//! `*Manual-xccdf.xml`. Isolated here (a `curl` + `unzip` shell-out) so the
//! derivation core ([`crate::xccdf`]) stays offline-testable with fixtures; this
//! module is exercised only by the live `check` / `derive` runs. Byte-identical
//! logic to `tools/sshd-stig-update/src/source.rs` (generic zip-fetch, not
//! sshd-specific); kept as a separate copy so this tool has no dependency on the
//! sshd crate/tool.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Download the DISA STIG zip at `url`, unzip it, and return the contents of the
/// single `*Manual-xccdf.xml` inside. Uses a per-process temp dir under the system
/// temp directory.
pub fn fetch_xccdf(url: &str) -> Result<String, String> {
    let stem: String = url
        .rsplit('/')
        .next()
        .unwrap_or("stig")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let work =
        std::env::temp_dir().join(format!("auditd-stig-update-{}-{stem}", std::process::id()));
    // Fresh working dir.
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("create {}: {e}", work.display()))?;

    let zip = work.join("stig.zip");
    run(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "180",
            "-o",
            &zip.to_string_lossy(),
            url,
        ],
    )?;
    run(
        "unzip",
        &["-oq", &zip.to_string_lossy(), "-d", &work.to_string_lossy()],
    )?;

    let xccdf = find_xccdf(&work).ok_or_else(|| {
        format!("no *Manual-xccdf.xml found after unzipping {url} (is the pinned zip correct?)")
    })?;
    let body =
        std::fs::read_to_string(&xccdf).map_err(|e| format!("read {}: {e}", xccdf.display()))?;
    let _ = std::fs::remove_dir_all(&work);
    Ok(body)
}

/// Read a local XCCDF xml file (the offline `derive --file <path>` path).
pub fn read_local(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Recursively find the first `*Manual-xccdf.xml` under `dir`.
fn find_xccdf(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("Manual-xccdf.xml"))
        {
            return Some(path);
        }
    }
    subdirs.iter().find_map(|d| find_xccdf(d))
}

/// Run a command, mapping a spawn failure or non-zero exit to a readable error.
fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {cmd} (is it installed?): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
