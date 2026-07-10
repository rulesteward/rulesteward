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
//! Live probe mode is explicitly OUT of scope for the RED-test-authoring pass that
//! wrote this stub (issue #478's frozen tests are fully offline, per the pipeline
//! brief's PRE-ANSWERED decision #1); a separate implementer session fills in the
//! docker invocation (see `/var/tmp/7b-grounding/p2/probe_fapd.sh` and
//! `probe_fapd_objectside_fix.sh` for the grounding-session reference methodology,
//! notably: object-side E07 probes - path=, mode= - must use a concrete subject
//! attribute like `exe=/usr/bin/probe`, NEVER bare `all`, on the subject side; see
//! `/var/tmp/7b-grounding/p2/drift-findings.md` "probe-methodology correction").

use crate::transcript::Transcript;

/// Probe a live `fapolicyd` in the docker `image` (`"fapolicyd8"` | `"fapolicyd9"` |
/// `"fapolicyd10"`) for `dataset` (`"version"` | `"pattern"` | `"e07"`), returning the
/// parsed transcript.
///
/// # Errors
/// Returns a readable error string if docker cannot be spawned, the container exits
/// non-zero, or its stdout is not parseable via [`crate::transcript::parse_tsv`].
pub fn probe_live(image: &str, dataset: &str) -> Result<Transcript, String> {
    let _ = (image, dataset);
    todo!(
        "spawn `docker run --rm -i {{image}} sh -s`, feed it a probe script that \
         exercises `dataset`'s candidates against the real fapolicyd daemon (see the \
         grounding-session reference scripts cited in this module's doc comment), \
         and parse its TSV stdout via crate::transcript::parse_tsv"
    )
}
