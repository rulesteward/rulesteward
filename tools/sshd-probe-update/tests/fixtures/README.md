# Fixture provenance

## `rhel{8,9,10}_probe.jsonl`

Committed offline probe transcripts used by the `check`/`derive --transcript`
CLI tests and the `derive::tests` unit tests. See the individual test doc
comments for how each was captured (`sshd -t -o KW=yes` / non-activating
`Match` block probes via `remote_probe.sh`).

## `rhel{8,9,10}_sshd_config.5.roff` (#471, man-page keyword discovery)

UNMODIFIED `gunzip -c` output of `/usr/share/man/man5/sshd_config.5.gz` from a
fresh `rockylinux/rockylinux:<N>` container with `openssh-server` installed via
`dnf -y --setopt=tsflags= install openssh-server` (the container's default
`tsflags=nodocs` would otherwise skip man pages, hence the override). Captured
2026-07-10.

Package NVR (`rpm -q openssh-server`) and sha256 of each committed fixture:

| Product | Package NVR | sha256 (`rhel<N>_sshd_config.5.roff`) |
|---|---|---|
| rhel8  | `openssh-server-8.0p1-29.el8_10.x86_64`         | `b1733f5ba5c79809c462e3ca49d15d79ce5ac22cb17bf432b046f1508b6aaaf0` |
| rhel9  | `openssh-server-9.9p1-7.el9_8.rocky.0.1.x86_64` | `5bb8c67b29455ed5312bf3d6539df04a64bebff7a91edd2f6eba76bef81092f0` |
| rhel10 | `openssh-server-9.9p1-23.el10_2.rocky.0.1.x86_64` | `28207d673bc98eb7e0dee6571889246321e1b0cc1b020a02af39832c116825f3` |

Capture command (per product, `<N>` = 8, 9, or 10):

```sh
docker run --rm rockylinux/rockylinux:<N> bash -lc '
  dnf -y --setopt=tsflags= install openssh-server >/dev/null 2>&1
  gunzip -c /usr/share/man/man5/sshd_config.5.gz
' > rhel<N>_sshd_config.5.roff
```

- Each file retains the original OpenBSD/Red&nbsp;Hat copyright header verbatim
  (BSD-style license, see the file's own `.\"` comment block).
- These files are DEV-ONLY test fixtures for the out-of-workspace
  `sshd-probe-update` drift tool (`publish = false`, its own empty
  `[workspace]`). They are not compiled into, linked against, or distributed
  with any RuleSteward artifact; the shipped engine remains Apache-2.0.
- Line-count sanity at capture time (`wc -l`): rhel8 = 1876, rhel9 = 2303,
  rhel10 = 2306. A byte-for-byte re-capture should reproduce the same sha256;
  if the upstream `openssh-server` package is bumped, re-run the capture
  command and update this table (no automated pin/enforcement test exists for
  these fixtures, unlike `fapolicyd-attr-update`'s `attr-refs.toml` - the
  keyword-discovery pass is advisory-only, so a stale fixture degrades
  gracefully rather than failing closed).
