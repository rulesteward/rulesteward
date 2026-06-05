# Simulate Oracle Corpus - Provenance

**NFS source:** `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/`

**Timestamp:** 20260603T065853Z (corpus finalization; 2026-06-04 vendoring)

**Oracle method:** Real fapolicyd `--debug --permissive` `dec=` line capture.
Images: `fapolicyd8` (Rocky Linux 8, fapolicyd 1.3.2), `fapolicyd9` (Rocky Linux 9, fapolicyd 1.4.5), `fapolicyd10` (Rocky Linux 10, fapolicyd 1.4.5).

**Vendored files per scenario:** `rules.d/` (ruleset), `workload.json` (access facts), `expected.json` (trimmed ground truth: decision, full_decision_keyword, rule_number, source, confidence).

**Not vendored:** `README.md`, `validation.log`, `manifest.json` (provenance on NFS).

**Scenario counts:** 77 total - 36 happy-path, 38 adversarial, 3 neutral (2 exe=untrusted scenarios dropped; see below + #126).

**CI portability:** Tests use `env!("CARGO_MANIFEST_DIR")` to locate this vendored corpus; no NFS dependency at test time.

## Dropped scenarios (session 5a, 2026-06-04)

Two adversarial scenarios were dropped from this vendored corpus (79 -> 77) because
they assert the macro-aware behavior the frozen `evaluate()` does not yet implement
(`exe=trusted`/`exe=untrusted` is a trust macro in real fapolicyd, but `evaluate()`
treats it as a literal exe path). Tracked for re-add in issue #126; still on NFS:

- `adversarial/exe-untrusted-macro-match`
- `adversarial/exe-untrusted-macro-trusted-no-match`
