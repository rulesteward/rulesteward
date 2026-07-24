# Test fixtures: trimmed DISA XCCDF sudo-W04 extracts

Each `<product>_sudoers_controls.xml` is a trimmed slice of the real, official,
publicly-releasable DISA STIG XCCDF benchmark for that product, in TRUE
DOCUMENT ORDER (never reordered), containing the `<Group>`/`<Rule>` elements
relevant to sudo-W04's scope: the three DISA control families
(`!authenticate`, the `targetpw`/`rootpw`/`runaspw` pw-family,
`timestamp_timeout`), one decoy in every product (the sudo-W01/W05
`NOPASSWD` control -- real sudoers-related DISA content, but a DIFFERENT
lint, proving the eventual selector is family-specific and not "any control
that mentions /etc/sudoers"), and -- rhel8 ONLY -- 3 further Groups with NO
bearing on sudo at all, preceding even the NOPASSWD decoy (adversarial
round: a positional/ordinal selector that assigns the first N Groups to the
3 families, or skips only sudo-flavored decoys, must fail against this
fixture; see `../src/xccdf.rs`'s `selector_is_content_based_not_positional`
test).

`check-content`, `fixtext`, the Rule's OWN `<title>`, AND the `<Group>`-level
`<title>` (the SRG requirement id, e.g. `SRG-OS-000373-GPOS-00156` -- kept
DELIBERATELY, not stripped: it is real DISA content and is exactly the
same-tag-different-meaning trap a selector reading "the first `<title>` in
the Group" falls into; see `../src/xccdf.rs`'s
`group_level_title_is_never_used_as_the_control_title` test) are copied
VERBATIM from the source benchmark. Only the empty `GroupDescription` /
`VulnDiscussion` `<description>` wrapper, `<reference>`, `<ident>`,
`<fix id=.../>`, and `<check-content-ref/>` elements are stripped
(parser-irrelevant, matching the `tools/sshd-stig-update` /
`tools/auditd-stig-update` fixture convention). No non-ASCII transliteration
was needed -- every selected Group is already pure ASCII in the source
documents.

DEV-ONLY: these fixtures exist to make `tools/sudoers-stig-update`'s tests run
OFFLINE, without depending on the DISA CDN being reachable during a PR. They
are not shipped in the `rulesteward` release binary or its distribution
artifacts.

## Provenance

| Product | Groups extracted | Document order | Decoys |
|---|---:|---|---|
| rhel8  | 7 | 3 unrelated, NOPASSWD, auth, pw, ts | 3 unrelated (RHEL-08-010000/010010/010020) + 1 NOPASSWD (RHEL-08-010380) |
| rhel9  | 4 | ts, pw, auth, NOPASSWD | 1 NOPASSWD (RHEL-09-611085) |
| rhel10 | 4 | auth, ts, pw, NOPASSWD | 1 NOPASSWD (RHEL-10-600560) |

These fixtures were originally extracted (2026-07-24) from the DISA XCCDF
benchmarks cached locally at
`/home/runner/rulesteward-docs/grounding/auditd-stig/stig_research/` (RHEL 8
V2R4, RHEL 9 V2R7, RHEL 10 V1R1 -- gitignored docs tree; not part of this
repo; the SAME cache `tools/auditd-stig-update`'s own fixtures README points
at). An independent adversarial-test-review pass subsequently fetched the
CURRENT pinned revisions (RHEL 8 V2R8, RHEL 9 V2R9, RHEL 10 V1R2 -- see
`../stig-refs.toml`) and byte-verified every Group used by these fixtures is
IDENTICAL across both revisions, so `../stig-refs.toml`'s live pin was bumped
to match sshd/auditd's current pin with no fixture changes required. These
fixtures remain accurate, verbatim extracts of the CURRENTLY pinned
revisions, not stale copies of a superseded one.

### Extracted STIG Rule ids (the nine ids these fixtures ground)

| Product | `!authenticate` | pw-family (targetpw/rootpw/runaspw) | timestamp_timeout |
|---|---|---|---|
| rhel8  | RHEL-08-010381 (V-230272) | RHEL-08-010383 (V-237642) | RHEL-08-010384 (V-237643) |
| rhel9  | RHEL-09-432025 (V-258086) | RHEL-09-432020 (V-258085) | RHEL-09-432015 (V-258084) |
| rhel10 | RHEL-10-600530 (V-281208) | RHEL-10-600550 (V-281210) | RHEL-10-600540 (V-281209) |

These are EXACTLY the ids `crates/rulesteward-sudoers/src/lints/stig.rs`'s
`AUTHENTICATE_CONTROLS` / `PW_FAMILY_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS`
already cite (RHEL-10's three grounded explicitly against this same XCCDF
family per issue #563 / 9i lane-7's citations table; RHEL-08/09's presence
verified mechanically by `grep` at authoring time, 2026-07-24, and
cross-checked live against source at every test run by
`../src/derive.rs`'s `code_table_matches_stig_rs_source_for_all_targets`
test).

## Regenerating

If the pinned DISA revision bumps again in the future, regenerate by
re-extracting the same `<Group>`/`<Rule>` blocks (by their `<version>` STIG
ids) from the new benchmark, PRESERVING true document order and the
Group-level `<title>` elements (do not reorder or re-strip), and reviewing
the diff before committing -- do not hand-edit these files.
