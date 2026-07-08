//! The docker seam: run the embedded in-container probe script against a real
//! `sshd` binary in a Rocky Linux image and collect the transcript. Isolated here
//! (all `Command` use lives in this file) so the classify/derive core stays
//! offline-testable with fixtures; this module is exercised only by the live
//! `check` / `derive` runs and is excluded from the mutation gate (`.cargo/mutants.toml`).

use std::io::Write;
use std::process::{Command, Stdio};

use crate::transcript::{Transcript, parse_tsv};

/// The in-container probe script (Loop B `sshd -t -o KW=yes` + Loop C
/// non-activating `Match` + `sshd -t -f`). Embedded so the tool is a single
/// self-contained binary with no external script dependency.
const REMOTE_PROBE_SH: &str = include_str!("remote_probe.sh");

// TODO(#372-followup): a best-effort `man sshd_config` keyword-discovery pass is
// a LIVE-only advisory (it needs man-db in the container) that would widen the
// candidate universe beyond `known_keywords ∪ bogus` to catch a keyword the
// registry entirely missed. It is deferred: the current candidate universe is
// VERIFY-ONLY (option C), which still catches every drift within the shipped
// registry's own keywords plus the guaranteed-bogus sentinel.

/// Probe a live `sshd` in the docker `image` for each of `candidates`, returning
/// the parsed transcript. Feeds the embedded probe script + the candidate list to
/// `docker run --rm -i <image> sh -s` on stdin, then parses the TSV stdout.
///
/// # Errors
/// Returns a readable error string if docker cannot be spawned, the container
/// exits non-zero, or its stdout is not parseable as the probe TSV.
pub fn probe_live(image: &str, candidates: &[&str]) -> Result<Transcript, String> {
    let mut child = Command::new("docker")
        .args(["run", "--rm", "-i", image, "sh", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn docker (is it installed and running?): {e}"))?;

    // The stdin script: write the candidate list to a file, write the embedded
    // probe script to a file, then run it with the candidate file as arg 1. Both
    // heredocs are single-quoted so nothing inside expands.
    let mut stdin_script = String::new();
    stdin_script.push_str("set -e\n");
    stdin_script.push_str("cat > /tmp/rs_probe_cands.txt <<'RS_CANDS_EOF'\n");
    for kw in candidates {
        stdin_script.push_str(kw);
        stdin_script.push('\n');
    }
    stdin_script.push_str("RS_CANDS_EOF\n");
    stdin_script.push_str("cat > /tmp/rs_probe.sh <<'RS_PROBE_EOF'\n");
    stdin_script.push_str(REMOTE_PROBE_SH);
    stdin_script.push_str("\nRS_PROBE_EOF\n");
    stdin_script.push_str("sh /tmp/rs_probe.sh /tmp/rs_probe_cands.txt\n");

    child
        .stdin
        .take()
        .ok_or("docker stdin unavailable")?
        .write_all(stdin_script.as_bytes())
        .map_err(|e| format!("write probe script to docker stdin: {e}"))?;

    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait for docker: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker run {image} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_tsv(&stdout).map_err(|e| format!("parsing probe output from {image}: {e}"))
}
