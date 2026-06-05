# Simulate Oracle Corpus - Provenance

**NFS source:** `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/`

**Timestamp:** 20260603T065853Z (corpus finalization; 2026-06-04 vendoring)

**Oracle method:** Real fapolicyd `--debug --permissive` `dec=` line capture.
Images: `fapolicyd8` (Rocky Linux 8, fapolicyd 1.3.2), `fapolicyd9` (Rocky Linux 9, fapolicyd 1.4.5), `fapolicyd10` (Rocky Linux 10, fapolicyd 1.4.5).

**Vendored files per scenario:** `rules.d/` (ruleset), `workload.json` (access facts), `expected.json` (trimmed ground truth: decision, full_decision_keyword, rule_number, source, confidence).

**Not vendored:** `README.md`, `validation.log`, `manifest.json` (provenance on NFS).

**Scenario counts:** 79 total - 36 happy-path, 40 adversarial, 3 neutral (2 exe=untrusted scenarios dropped; see below + #126).

**CI portability:** Tests use `env!("CARGO_MANIFEST_DIR")` to locate this vendored corpus; no NFS dependency at test time.

## Added scenarios (session 5a follow-up, impl-aware adversarial review)

Two adversarial scenarios added (77 -> 79) from the impl-aware adversarial review
finding a bug in `simulate.rs` (single `trust` field collapsed onto both sides):

- `adversarial/trust-subject-vs-object-distinct`: workload uses `subjTrust: true,
  objTrust: false`; tests that `deny_audit trust=1 : trust=0` fires correctly when
  the subject is trusted and the object is untrusted. Expected derived from the
  frozen `evaluate()` with `subj_trust=Yes, obj_trust=No`. RED against the current
  impl (which reads only `trust`, so `subjTrust`/`objTrust` are unknown -> Possible).
  The fix requires `simulate.rs` to parse `subjTrust`/`objTrust` as per-side overrides.
- `adversarial/exe-resolved-distinct`: workload uses both `exe` and `resolved_exe`;
  tests that the deny rule matching `/usr/bin/coreutils` (the resolved exe) fires
  even when `exe` is `/usr/bin/cat`. Pins the `resolved_exe`-over-`exe` preference
  that was already implemented but not covered by any corpus scenario. GREEN against
  the current impl (which already handles `resolved_exe`); serves as a regression pin.

**Workload schema extended:** `subjTrust` and `objTrust` (boolean, optional) added as
per-side trust overrides for the new scenarios. The implementer must update
`parse_json_object` in `simulate.rs` to read these fields.

## Dropped scenarios (session 5a, 2026-06-04)

Two adversarial scenarios were dropped from this vendored corpus (original 79 -> 77) because
they assert the macro-aware behavior the frozen `evaluate()` does not yet implement
(`exe=trusted`/`exe=untrusted` is a trust macro in real fapolicyd, but `evaluate()`
treats it as a literal exe path). Tracked for re-add in issue #126; still on NFS:

- `adversarial/exe-untrusted-macro-match`
- `adversarial/exe-untrusted-macro-trusted-no-match`
