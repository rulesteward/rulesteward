//! The docker seam: run a probe against a real `fapolicyd` in one of the prebuilt
//! `fapolicyd8` / `fapolicyd9` / `fapolicyd10` images and collect a transcript.
//! Isolated here (all `Command` use lives in this file) so the
//! [`crate::transcript`] / [`crate::derive`] core stays offline-testable with the
//! committed fixtures. This module is exercised only by the live `check` / `derive`
//! runs and is excluded from the mutation gate (`.cargo/mutants.toml`), matching
//! `tools/sshd-probe-update/src/probe.rs`.
//!
//! Unlike `tools/sshd-probe-update`, which BUILDS its own `sshd-probe{8,9,10}` images
//! (openssh-server is absent from the base fapolicyd differential images), this tool
//! probes the EXISTING prebuilt `fapolicyd8` / `fapolicyd9` / `fapolicyd10` images
//! directly - fapolicyd already ships on them (see this repo's CLAUDE.md
//! "Differential verification (fapolicyd, dev-only)" section) - so no `dockerfiles/`
//! directory is needed here.
//!
//! Live probe mode: the embedded [`PROBE_SCRIPT`] (`src/probe_fapd.sh`, adapted from
//! the grounding-session reference `/var/tmp/7b-grounding/p2/probe_fapd.sh` +
//! `probe_fapd_objectside_fix.sh`) is piped to `docker run --rm -i <image> sh -s --
//! <dataset>` and its TSV stdout is parsed. Notably: object-side E07 probes (path=,
//! mode=) use a concrete subject attribute (`exe=/usr/bin/probe`), NEVER bare `all`
//! on the subject side - bare `all` on the subject side is itself a real-daemon
//! SYNTAX error, independent of any macro; see
//! `/var/tmp/7b-grounding/p2/drift-findings.md` "probe-methodology correction".

use std::io::Write;
use std::process::{Command, Stdio};

use crate::transcript::{Transcript, parse_tsv};

/// The in-container probe script, embedded so the tool is a single self-contained
/// binary with no external script dependency (mirrors
/// `tools/sshd-probe-update/src/probe.rs`'s `REMOTE_PROBE_SH`).
const PROBE_SCRIPT: &str = include_str!("probe_fapd.sh");

/// Probe a live `fapolicyd` in the docker `image` (`"fapolicyd8"` | `"fapolicyd9"` |
/// `"fapolicyd10"`) for `dataset` (`"version"` | `"pattern"` | `"e07"`), returning the
/// parsed transcript.
///
/// # Errors
/// Returns a readable error string if `dataset` is not one of the three known
/// datasets, docker cannot be spawned, the container exits non-zero, or its stdout
/// is not parseable via [`crate::transcript::parse_tsv`].
pub fn probe_live(image: &str, dataset: &str) -> Result<Transcript, String> {
    if !matches!(dataset, "version" | "pattern" | "e07") {
        return Err(format!(
            "unknown dataset {dataset:?} (expected version|pattern|e07)"
        ));
    }

    let mut child = Command::new("docker")
        .args(["run", "--rm", "-i", image, "sh", "-s", "--", dataset])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn docker (is it installed and running?): {e}"))?;

    child
        .stdin
        .take()
        .ok_or("docker stdin unavailable")?
        .write_all(PROBE_SCRIPT.as_bytes())
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
    parse_tsv(&stdout).map_err(|e| format!("parsing probe output from {image} ({dataset}): {e}"))
}
