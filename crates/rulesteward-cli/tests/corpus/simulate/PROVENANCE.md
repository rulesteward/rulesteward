# Simulate Oracle Corpus - Provenance

**NFS source:** `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/`

**Timestamp:** 20260603T065853Z (corpus finalization; 2026-06-04 vendoring)

**Oracle method:** Real fapolicyd `--debug --permissive` `dec=` line capture.
Images: `fapolicyd8` (Rocky Linux 8, fapolicyd 1.3.2), `fapolicyd9` (Rocky Linux 9, fapolicyd 1.4.5), `fapolicyd10` (Rocky Linux 10, fapolicyd 1.4.5).

**Vendored files per scenario:** `rules.d/` (ruleset), `workload.json` (access facts), `expected.json` (trimmed ground truth: decision, full_decision_keyword, rule_number, source, confidence).

**Not vendored:** `README.md`, `validation.log`, `manifest.json` (provenance on NFS).

**Scenario counts:** 79 total - 36 happy-path, 40 adversarial, 3 neutral.

**CI portability:** Tests use `env!("CARGO_MANIFEST_DIR")` to locate this vendored corpus; no NFS dependency at test time.
