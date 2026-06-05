# Simulate Oracle Corpus - Provenance

**NFS source:** `/mnt/side-projects/fapolicyd-simulate-corpus/canonical/`

**Timestamp:** 20260603T065853Z (corpus finalization; 2026-06-04 vendoring)

**Oracle method:** Real fapolicyd `--debug --permissive` `dec=` line capture.
Images: `fapolicyd8` (Rocky Linux 8, fapolicyd 1.3.2), `fapolicyd9` (Rocky Linux 9, fapolicyd 1.4.5), `fapolicyd10` (Rocky Linux 10, fapolicyd 1.4.5).

**Vendored files per scenario:** `rules.d/` (ruleset), `workload.json` (access facts), `expected.json` (trimmed ground truth: decision, full_decision_keyword, rule_number, source, confidence).

**Not vendored:** `README.md`, `validation.log`, `manifest.json` (provenance on NFS).

**Scenario counts:** 81 total - 36 happy-path, 42 adversarial, 3 neutral (the 2 exe=untrusted scenarios were re-vendored for #126; see below).

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

## Re-vendored for #126 (session 5b follow-up, 2026-06-05)

The two `exe=untrusted` trust-macro scenarios were re-vendored from NFS (79 -> 81)
now that #126 makes `evaluate()` treat `exe=untrusted` as a TRUST MACRO instead of
a literal exe path. (Grounded correction: `exe=untrusted` is the ONLY exe trust
macro; `exe=trusted` is a LITERAL exe-path compare - real fapolicyd has no
`trusted` macro, f1 §1.4 line ~164 / `rules.c:1443-1463`.) Oracle: real fapolicyd
1.4.5 (el9/el10) `dec=` capture (each scenario's NFS `manifest.json`/`validation.log`).

- `adversarial/exe-untrusted-macro-match`: subject `/tmp/payload` is untrusted
  (`trust: false`); `deny_audit exe=untrusted : all` fires -> `deny`, rule 1.
  RED against the pre-#126 `evaluate()` (which compares `untrusted` as a literal
  exe path -> `NoMatch` -> fallthrough to rule 2 `allow`).
- `adversarial/exe-untrusted-macro-trusted-no-match`: subject `/usr/bin/cat` is
  trusted (`trust: true`); the macro is inverted so rule 1 does NOT fire ->
  fallthrough to rule 2 `allow`, rule 2. (This scenario coincidentally passes
  the pre-#126 impl for the WRONG reason - literal `NoMatch` also reaches rule 2;
  the focused unit tests pin the macro semantics so a wrong impl cannot satisfy
  both this and the match scenario.)

**fapolicyd version note:** the macro is functional only on fapolicyd >= 1.4.x;
on 1.3.2 (el8) it is INERT (the el8 oracle shows rule 1 NOT firing even for an
untrusted exe, falling through to allow). The vendored `expected.json` pins the
modern (>= 1.4) behavior, which is what `evaluate()` implements; the impl should
document the 1.3.2-inert caveat in `simulate --help` (#126).
