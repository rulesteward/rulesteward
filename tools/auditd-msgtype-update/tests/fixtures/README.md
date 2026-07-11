# Fixture provenance

Three UNMODIFIED upstream header copies, from TWO distinct upstreams (kept in
separate directories so the provenances are never blurred):

- `3bfa048/msg_typetab.h` and `3bfa048/audit-records.h` are unmodified copies
  of `lib/msg_typetab.h` and `lib/audit-records.h` from the upstream
  audit-userspace project (<https://github.com/linux-audit/audit-userspace>)
  at commit `3bfa048` - the same pinned citation commit
  `crates/rulesteward-auditd` uses throughout. Each file retains its original
  Red Hat copyright and GNU Lesser General Public License v2.1-or-later
  (LGPL-2.1-or-later) header verbatim.
- `linux-v6.6/audit.h` is an unmodified copy of `include/uapi/linux/audit.h`
  from the Linux kernel (<https://github.com/torvalds/linux>) at tag `v6.6`
  (LTS). It retains its original SPDX header verbatim:
  `GPL-2.0+ WITH Linux-syscall-note`. It is needed because `audit-records.h`
  resolves 60 of the 197 `_S`-referenced `AUDIT_*` constants only via
  `#include <linux/audit.h>`.
- The sha256 of every fixture is pinned in `../../msgtype-refs.toml` and
  enforced by the test suite (`tests/provenance.rs`) and by the tool's
  offline `check --fixtures` path; any byte change fails closed.
- These files are DEV-ONLY test fixtures for the out-of-workspace
  `auditd-msgtype-update` drift tool (`publish = false`). They are not
  compiled into, linked against, or distributed with any RuleSteward
  artifact; the shipped engine remains Apache-2.0.
