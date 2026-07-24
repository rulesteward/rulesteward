# stig-update

Derives / drift-checks the sysctld-W02 STIG kernel-hardening baseline tables
(`crates/rulesteward-sysctld/src/lints/baseline.rs`) against the official DISA
XCCDF (issue #335, #512). See the tool's `--help` and `stig-refs.toml` for the
pinned DISA zip filenames.

## Workflow cross-reference (#580)

The two CI workflow names read inverted at a glance ("check" sounds like the
live probe, "drift" sounds like the offline gate -- it is the other way
around). This table is the disambiguation:

| Workflow                          | What it runs                                            | `just` recipe equivalent |
|------------------------------------|-----------------------------------------------------------|---------------------------|
| `.github/workflows/stig-check.yml` | OFFLINE: PR-time gate against the committed DISA fixtures | `just stig-check-offline` |
| `.github/workflows/stig-drift.yml` | LIVE: weekly fetch of the pinned DISA zips, opens an issue on drift | `just stig-check` |

`just stig-derive <product>` (product = `rhel8`/`rhel9`/`rhel10`/`all`) prints
the derived table + diff + paste-ready `k(...)`/`k_exact(...)` lines for
updating `baseline.rs` by hand; it is not run by either workflow.
