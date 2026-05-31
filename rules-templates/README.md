# rules-templates

Sample fapolicyd rule files for use with RuleSteward.

## License

The files in this directory are licensed under the **BSD-3-Clause** license
(see `LICENSE`). This is separate from the RuleSteward engine itself, which
is licensed under Apache-2.0.

The BSD-3-Clause license was chosen for these templates so that administrators
can copy, adapt, and redistribute them without restriction, including in
proprietary deployments.

## What is in this directory

| File | Purpose |
|---|---|
| `10-trusted-interpreters.rules` | Allow carve-outs for known language runtimes and shared libraries in the trust database |
| `50-deny-untrusted-exec.rules` | Deny execution of ELF content not present in the trust database |
| `90-deny-all-fallback.rules` | Terminal fallback: deny everything not matched by an earlier allow |

## How to use these templates

1. Copy the files you want into your system's `rules.d/` directory (typically
   `/etc/fapolicyd/rules.d/`).

2. Adapt the rules to match your deployment. For example, add or remove
   interpreter paths in `10-trusted-interpreters.rules` based on which language
   runtimes are installed.

3. Run `rulesteward fapolicyd lint rules.d/` to verify your customized rules
   are clean before deploying them.

4. After deploying, reload fapolicyd: `systemctl reload fapolicyd`.

## File naming convention

Every file in `rules.d/` must begin with a two-digit numeric prefix followed
by a hyphen (e.g. `10-`, `50-`, `90-`). This controls the load order: lower
numbers are evaluated first by `fagenrules`. Files without this prefix will
trigger the `fapd-C01` lint code.

## Rule authoring notes

- Use modern syntax (`decision perm=... subj : obj`) consistently within each
  file. Mixing modern and legacy syntax in one file triggers `fapd-F03`.
- Comments must be on their own lines starting with `#`. Inline trailing
  comments after a rule line are silently dropped by fapolicyd and trigger
  `fapd-W03`.
- `dir=` values must end with a trailing slash (e.g. `dir=/var/tmp/`).
  Without it fapolicyd matches by byte-prefix and can over-match sibling
  directory names, which triggers `fapd-W08`.
- Avoid broad `allow perm=execute all : all`. This allows every binary on the
  system to execute and triggers `fapd-W02`.
- Place allow rules in lower-numbered files (10-xx, 20-xx) and deny rules in
  higher-numbered files (50-xx, 90-xx). An allow rule that appears after a
  deny-all that subsumes it is unreachable and triggers `fapd-W04`.
