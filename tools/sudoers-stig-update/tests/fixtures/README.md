# Test fixtures: trimmed DISA XCCDF sudo-W04 extracts

Each `<product>_sudoers_controls.xml` is a trimmed slice of the real, official,
publicly-releasable DISA STIG XCCDF benchmark for that product, containing
only the four `<Group>`/`<Rule>` elements relevant to sudo-W04's scope: the
three DISA control families (`!authenticate`, the `targetpw`/`rootpw`/
`runaspw` pw-family, `timestamp_timeout`) plus one decoy (the sudo-W01/W05
`NOPASSWD` control -- real sudoers-related DISA content, but a DIFFERENT lint,
proving the eventual selector is family-specific and not "any control that
mentions /etc/sudoers"). `check-content`, `fixtext`, and the Rule's own
`<title>` are copied VERBATIM from the source benchmark; the `<Group>`-level
`<title>` (the SRG requirement id, not a human title), `<description>`
(`GroupDescription` / `VulnDiscussion`), `<reference>`, `<ident>`, `<fix id=.../>`,
and `<check-content-ref/>` elements are stripped (parser-irrelevant, matching
the `tools/sshd-stig-update` / `tools/auditd-stig-update` fixture convention).
No non-ASCII transliteration was needed -- all nine selected Groups (plus the
three decoys) are already pure ASCII in the source documents.

DEV-ONLY: these fixtures exist to make `tools/sudoers-stig-update`'s tests run
OFFLINE, without depending on the DISA CDN being reachable during a PR. They
are not shipped in the `rulesteward` release binary or its distribution
artifacts.

## Provenance

| Product | Source benchmark | Families selected | Decoy |
|---|---|---:|---:|
| rhel8  | RHEL 8 STIG V2R4 (02 Jul 2025), `U_RHEL_8_V2R4_STIG.zip`   | 3 | 1 (NOPASSWD, RHEL-08-010380) |
| rhel9  | RHEL 9 STIG V2R7 (05 Jan 2026), `U_RHEL_9_V2R7_STIG.zip`   | 3 | 1 (NOPASSWD, RHEL-09-611085) |
| rhel10 | RHEL 10 STIG V1R1 (26 Feb 2026), `U_RHEL_10_V1R1_STIG.zip` | 3 | 1 (NOPASSWD, RHEL-10-600560) |

These are the SAME three DISA zip filenames pinned in this tool's own
`../../stig-refs.toml` (see that file's CURRENCY NOTE: `tools/sshd-stig-update`
and `tools/auditd-stig-update` have SINCE bumped their own live pins forward to
V2R8/V2R9/V1R2; whether the nine sudo-W04 ids extracted here are unchanged in
those newer revisions is an explicit, undone follow-up -- no network fetch was
performed to build these fixtures).

### Extracted STIG Rule ids (the nine ids these fixtures ground)

| Product | `!authenticate` | pw-family (targetpw/rootpw/runaspw) | timestamp_timeout |
|---|---|---|---|
| rhel8  | RHEL-08-010381 (V-230272) | RHEL-08-010383 (V-237642) | RHEL-08-010384 (V-237643) |
| rhel9  | RHEL-09-432025 (V-258086) | RHEL-09-432020 (V-258085) | RHEL-09-432015 (V-258084) |
| rhel10 | RHEL-10-600530 (V-281208) | RHEL-10-600550 (V-281210) | RHEL-10-600540 (V-281209) |

These are EXACTLY the ids `crates/rulesteward-sudoers/src/lints/stig.rs`'s
`AUTHENTICATE_CONTROLS` / `PW_FAMILY_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS`
already cite (RHEL-10's three grounded explicitly against this same V1R1
XCCDF per issue #563 / 9i lane-7's citations table; RHEL-08/09's presence in
these exact cached documents was verified mechanically by `grep` at authoring
time, 2026-07-24).

## Regenerating

These files were extracted from the real DISA XCCDF benchmarks cached locally
at `/home/runner/rulesteward-docs/grounding/auditd-stig/stig_research/`
(gitignored docs tree; not part of this repo; the SAME cache
`tools/auditd-stig-update`'s own fixtures README points at). If the pinned
DISA revision bumps, regenerate by re-extracting the same nine
`<Group>`/`<Rule>` blocks (by their `<version>` STIG ids, or by re-deriving
the family selector once it exists) from the new benchmark and reviewing the
diff before committing -- do not hand-edit these files.
