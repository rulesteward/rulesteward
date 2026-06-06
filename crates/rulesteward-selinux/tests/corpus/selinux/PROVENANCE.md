# SELinux denial-corpus provenance (#101, epic #139 Lane B)

This directory vendors a curated copy of the SELinux denial corpus used by the
data-driven oracle in `crates/rulesteward-selinux/tests/selinux_corpus_oracle.rs`.

## Source

- **NFS run root:** `/mnt/side-projects/selinux-corpus/20260603T004238Z/`
- **Corpus RS_COMMIT (recorded in the corpus INDEX.md/ORACLES.md):** `fe89260`
- **Vendoring against RuleSteward commit:** `d5999cc`
- **Scenarios vendored:** all 69 (45 grammar + 21 cross-version + 3 vm-live).
  The corpus run dir also contains underscore-prefixed support dirs
  (`_policies/`, `_anchors/`, `_tools/`) and the synthetic bounds/cons policies
  under `_policies/`; those are NOT scenario dirs and are skipped by the oracle's
  enumeration (`!name.starts_with('_')`).

## What is vendored per scenario

- `manifest.json` (always) -- the oracle reads only `id`,
  `authoritative_category`, `floor_label`, `policyvers`, and
  `xver_baseline.buckets_match`.
- `denials.txt` (when present) -- the raw `type=AVC` records.
- `denials.el8.txt` + `denials.el10.txt` (the dual-format scenario
  `rocky8-vs-rocky10-format` only) -- replayed per-variant against policy.31 and
  policy.35 respectively.
- `rocky10-live-avc-capture/oracle/avc-summary.json` (that ONE scenario only) --
  it ships no `denials.txt`, only this aggregated per-domain summary; it is
  excluded from the floor parse loop but counted toward the `>= 69` guard.

## What is deliberately NOT vendored

- The per-scenario `oracle/` subdirs (`expected.te`/`.pp`/`.mod`,
  `audit2why.txt`, `audit2allow-*.te`, logs) -- those are te-emit / triage
  oracles (~19 MB of compiled `.pp`), irrelevant to #101's parse + categorize
  scope. (The single `avc-summary.json` exception above is the only `oracle/`
  file kept.)
- The synthetic bounds/cons policies (`_policies/policy.bounds`,
  `_policies/policy.cons`). The seven synthetic-type scenarios that need them
  (`rsbnd_child_t`/`rsbnd_parent_t` typebounds and `rscons_src_t`/`rscons_tgt_t`
  constraints) are scoped OUT of the authoritative layer here (they return
  `ContextInvalid` against the STOCK policy, which the oracle confirms) and stay
  covered by `tests/known_answer_categorize.rs`, which ships its own bounds
  policy fixture.

## Binary policies (`_policies/policies.tar.zst`)

A solid zstd archive of the three STOCK binary SELinux policies, placed by the
orchestrator (extracted + drift-verified, NOT via docker in this session):

| File        | Policy version | selinux-policy package                    | Source image |
|-------------|----------------|-------------------------------------------|--------------|
| `policy.31` | 31 (el8)       | `selinux-policy-3.14.3-139.el8_10.2`      | `fapolicyd8` |
| `policy.33` | 33 (el9)       | `selinux-policy-38.1.75-2.el9`            | `fapolicyd9` |
| `policy.35` | 35 (el10)      | `selinux-policy-42.1.18-4.el10`           | `fapolicyd10`|

- **Archive sha256:** `c2a58484a349bd5b8952b841cfc54289344b1d8deaf6816a3d9fd02cf9c97b62`
- The orchestrator verified `categorize()` vs the corpus oracle for BADSCON +
  TeAllowable per version (all matched) before placing the archive.
- The oracle decodes this archive IN-PROCESS (`tar` + `zstd` dev-deps), unpacks
  it once into a `tempfile::TempDir`, and loads each `policy.NN` once. No
  shell-out, no docker at test time.

## Stale-doc warning (load-bearing)

The corpus `ORACLES.md` states that `categorize()` shells out to `audit2why`.
That mechanism is STALE: the real `rulesteward-selinux` impl categorizes via the
libsepol FFI (`sepol_compute_av_reason_buffer`, behind the
`authoritative-categorizer` feature), NOT by invoking `audit2why`. The oracle
asserts ONLY against `manifest.json` fields and the real `categorize` return
value; it never depends on the audit2why mechanism. The manifest
`authoritative_category` values themselves remain valid ground truth (they were
captured from the same libsepol classification audit2why also wraps).
