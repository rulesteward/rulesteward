# Test fixtures: trimmed DISA XCCDF fapolicyd-control extracts

Each `<product>_fapolicyd_controls.xml` is a trimmed slice of the real,
official, publicly-releasable DISA STIG XCCDF benchmark for that product,
containing exactly the 3 fapolicyd Groups the #519 tool cares about
(Installed/Enabled/DenyAll), plus 2 decoy Groups per file (real DISA Groups
that are NOT fapolicyd controls, so the selector-exclusion tests have real,
non-synthetic negative fixtures - one SELinux-enforcement-style check and one
SELinux-policy/package-style check). `check-content` and `fixtext` text is
copied VERBATIM from the source benchmark (byte-for-byte after entity
decoding); `ident`/`reference` elements are retained as-is (mirrors the source
exactly - the parser is not expected to read them, matching
`tools/auditd-stig-update`'s precedent). No non-ASCII typographic characters
appear in any of the three source benchmarks' fapolicyd/decoy prose, so no
transliteration was needed here (unlike the auditd fixtures, which required
it in a few unrelated Groups).

DEV-ONLY: these fixtures exist to make `tools/fapolicyd-stig-update`'s tests
and its CI drift gate run OFFLINE, without depending on the DISA CDN being
reachable during a PR. They are not shipped in the `rulesteward` release
binary or its distribution artifacts.

## Provenance

| Product | Source benchmark | Selected requirements | Decoys |
|---|---|---:|---:|
| rhel8  | RHEL 8 STIG V2R4 (02 Jul 2025), `U_RHEL_8_V2R4_STIG.zip`   | 3 | 2 |
| rhel9  | RHEL 9 STIG V2R7 (05 Jan 2026), `U_RHEL_9_V2R7_STIG.zip`   | 3 | 2 |
| rhel10 | RHEL 10 STIG V1R1 (26 Feb 2026), `U_RHEL_10_V1R1_STIG.zip` | 3 | 2 |

These are the SAME three DISA zip filenames `tools/{sshd,auditd}-stig-update`
already pin (the fapolicyd, sshd, and auditd baselines are all drawn from the
same three benchmark documents); see `../../stig-refs.toml` in this tool for
the pinned CDN URL. Extracted 2026-07-16 into
`/mnt/side-projects/9d-v0_8-wave2b/grounding/g7-g8-xccdf-vnumbers.md` (section
2) from freshly-downloaded copies of the pinned zips; SHA-256 hashes recorded
there.

## Selector (which Groups are included)

A `<Group>`/`<Rule>` pair is a "selected" (fapolicyd-control) fixture entry
IFF its Rule `<title>` names the `fapolicyd`/`fapolicy` module's
installed/enabled/deny-all-policy state (the three #519 `ControlFamily`
variants: `Installed`, `Enabled`, `DenyAll`). Exactly 3 such Groups exist per
product in the full benchmark - the #518 exhaustive sweep found no other
fapolicyd-mapped STIG control on any pinned release.

The 2 decoys per file are real DISA Groups that were NOT selected: one that
checks SELinux enforcement mode (`getenforce`/`/etc/selinux/config`
`SELINUX=`) and one that checks a SELinux policy-type or policycoreutils
package state. Their presence proves the selector's exclusion logic actually
filters something, rather than passing every Group through (mirrors
`tools/auditd-stig-update`'s decoy rationale).

## Regenerating

These files were extracted from the raw `<Group>` XML slices already captured
under `/mnt/side-projects/9d-v0_8-wave2b/grounding/xccdf/RHEL-0{8,9,10}-*.xml`
(one file per control, produced by the G7/G8 grounding pass) and wrapped in a
minimal `<Benchmark>` root that declares the XCCDF 1.1 default namespace plus
the `dc:` prefix the `<reference>` children use (a raw `<Group>` fixture is
NOT independently namespace-parseable without this wrapper - see the G7/G8
grounding doc's fixture caveat). If the pinned DISA revision bumps,
regenerate by re-running the same selector over the new benchmark and
reviewing the diff before committing - do not hand-edit these files.
