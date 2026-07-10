# Fixture provenance

The C sources under `1.3.2/` and `1.4.5/` are UNMODIFIED copies of
`src/library/{subject,object}-attr.c` from the upstream fapolicyd project
(<https://github.com/linux-application-whitelisting/fapolicyd>) at tags
`v1.3.2` and `v1.4.5`, matching the RHEL-major daemon versions this repo's
`--target` machinery models (RHEL8 = 1.3.2; RHEL9/RHEL10 = 1.4.5).

- Each file retains its original Red Hat copyright and GNU GPL v2-or-later
  license header verbatim.
- The sha256 of every fixture is pinned in `../../attr-refs.toml` and
  enforced by the test suite (`tests/provenance.rs`) and by the tool's
  offline `check` path; any byte change fails closed.
- These files are DEV-ONLY test fixtures for the out-of-workspace
  `fapolicyd-attr-update` drift tool (`publish = false`). They are not
  compiled into, linked against, or distributed with any RuleSteward
  artifact; the shipped engine remains Apache-2.0.
