# rulesteward

audit2why/audit2allow for host policy systems. Read fapolicyd denial records on
stdin, write the rules that would allow them on stdout.

Two verbs share that input. `rules` answers denials a rule fixes and `trust`
answers denials of an untrusted file that a trust entry fixes. Each one's output
says when the other verb is the right answer for part of the input.

## Install

Download from <https://github.com/rulesteward/rulesteward/releases>. The RPM is
GPG-signed and both assets carry a GitHub build-provenance attestation.
`SHA256SUMS` sits beside them, and catches a corrupted download and nothing
else: whoever can replace an asset can replace the sums next to it.

The signing key is a release asset beside the RPM. Its primary fingerprint, from
`gpg --show-keys --fingerprint RPM-GPG-KEY-rulesteward`:

```
1D3D D934 70C4 ECAE B3F5  77F7 D13B D5DA 6F14 575A
```

Import it, then check the package:

```
rpm --import RPM-GPG-KEY-rulesteward
rpm -K rulesteward-0.6.0.rc2-1.x86_64.rpm
```

```
rulesteward-0.6.0.rc2-1.x86_64.rpm: digests signatures OK
```

Without the import the same command says `digests SIGNATURES NOT OK` and exits 1.
A STIG host sets `localpkg_gpgcheck=1`, so dnf repeats that check on a local
file and an unimported key fails the transaction, which is why the import comes
first:

```
dnf install ./rulesteward-0.6.0.rc2-1.x86_64.rpm
```

```
...
Installed:
  rulesteward-0.6.0~rc2-1.x86_64                                                

Complete!
```

installs `/usr/bin/rulesteward`. The tarball holds the same static binary and
nothing else:

```
tar -xzf rulesteward-v0.6.0-rc2-x86_64-unknown-linux-musl.tar.gz
```

The attestation ties either file to the workflow run that built it:

```
gh attestation verify rulesteward-v0.6.0-rc2-x86_64-unknown-linux-musl.tar.gz --repo rulesteward/rulesteward
```

```
Loaded digest sha256:cfcef0440c0af2382947da318be5b300ae2aa826ecdf6972455b096f45bfb88a for file://rulesteward-v0.6.0-rc2-x86_64-unknown-linux-musl.tar.gz
Loaded 1 attestation from GitHub API

The following policy criteria will be enforced:
- Predicate type must match:................ https://slsa.dev/provenance/v1
- Source Repository Owner URI must match:... https://github.com/rulesteward
- Source Repository URI must match:......... https://github.com/rulesteward/rulesteward
- Subject Alternative Name must match regex: (?i)^https://github\.com/rulesteward/rulesteward/
- OIDC Issuer must match:................... https://token.actions.githubusercontent.com

✓ Verification succeeded!

The following 1 attestation matched the policy criteria

- Attestation #1
  - Build repo:..... rulesteward/rulesteward
  - Build workflow:. .github/workflows/ci.yml@refs/tags/v0.6.0-rc2
  - Signer repo:.... rulesteward/rulesteward
  - Signer workflow: .github/workflows/ci.yml@refs/tags/v0.6.0-rc2
```

```
gh attestation verify rulesteward-0.6.0.rc2-1.x86_64.rpm --repo rulesteward/rulesteward
```

```
Loaded digest sha256:1775d088f8265f9be4f13d02693b27b0c529477189c475a4c3498f1e5f574bb0 for file://rulesteward-0.6.0.rc2-1.x86_64.rpm
Loaded 1 attestation from GitHub API
...
✓ Verification succeeded!

The following 1 attestation matched the policy criteria

- Attestation #1
  - Build repo:..... rulesteward/rulesteward
  - Build workflow:. .github/workflows/ci.yml@refs/tags/v0.6.0-rc2
  - Signer repo:.... rulesteward/rulesteward
  - Signer workflow: .github/workflows/ci.yml@refs/tags/v0.6.0-rc2
```

`gh` writes that report only to a terminal. In a script the exit status is the
answer.

## Getting denials

The daemon writes denial records to stderr under `--debug-deny`, and
`rulesteward` reads stdin to end of file before it writes anything. With the
systemd unit stopped:

```
timeout 60 fapolicyd --debug-deny --permissive 2>&1 | rulesteward fapolicyd rules
```

`--permissive` still logs every denial and only changes the kernel's answer.
`timeout` ends the daemon so the pipe reaches end of file, whereas Ctrl-C on the
pipeline kills both sides with nothing written. To keep the capture, pipe through
`tee denials.log` instead and run both verbs against the file. When the daemon
runs under systemd with a `--debug-deny` drop-in, the journal carries the same
bytes:

```
journalctl -u fapolicyd -o cat | rulesteward fapolicyd rules
```

When the unit runs as shipped, with no `--debug-deny`, a `deny_audit` denial goes
to auditd and nowhere else, so the audit log already carries every denial the
host has seen. `--raw` is the mode the reader takes, and `--input-logs` is
needed in a script because `ausearch` reads stdin whenever stdin is not a tty:

```
ausearch -m FANOTIFY --raw --input-logs | rulesteward fapolicyd why --conf /etc/fapolicyd/fapolicyd.conf
```

A real run against a vendored Rocky 9 `ausearch --raw` capture, with `--conf`
pointing at the vendored Rocky 9 conf and `rules.d` fixture:

```
# rulesteward: 1 audit event(s) carry no PATH record for the object, so nothing to act on: load an exit rule with `auditctl -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM` or use the journal route
# rulesteward: 2 untrusted path(s) need a trust entry, not a rule: run rulesteward fapolicyd trust on the same input
rule=5   30-patterns.rules      22 denials  subject-side, nothing to emit  deny_audit perm=any pattern=ld_so : all
rule=8   41-shared-obj.rules     1 denials  trust: 1                       deny_audit perm=open all : ftype=application/x-sharedlib
rule=13  90-deny-execute.rules   1 denials  trust: 1                       deny_audit perm=execute all : all
```

`why` needs only the rule number the FANOTIFY record carries. `rules` and
`trust` also need the object's PATH record, which the kernel writes only while
an exit rule is loaded, so without one they emit nothing and say so: load an
exit rule with `auditctl -a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM` or use
the journal route above.

A log captured on another host needs `--no-conf`, because the default reads
this host's `fapolicyd.conf` and rules files and would validate against the
wrong machine.

## rules

```
rulesteward fapolicyd rules < denials.log
```

The sample below is a real run against a vendored Rocky 9 journal capture,
off-host with `--no-conf`:

```
# rulesteward: line 53: exe= is stale: pid 75414 was denied perm=execute of /usr/lib64/ld-linux-x86-64.so.2, and the daemon keeps the pre-exec image until that exec is permitted; the emitted rule is scoped to exe=/usr/lib64/ld-linux-x86-64.so.2 and not to the logged exe=/usr/sbin/runuser (x16)
# rulesteward: new file: none recommended (rules.d/ not read: --no-conf, legacy fapolicyd.rules, or unreadable)
# rulesteward: 6 untrusted path(s) need a trust entry, not a rule: run rulesteward fapolicyd trust on the same input
allow perm=execute exe=/usr/sbin/runuser : path=/usr/lib64/ld-linux-x86-64.so.2
allow perm=open exe=/usr/sbin/runuser : path=/usr/lib64/ld-linux-x86-64.so.2
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/bin/grep
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libpcre.so.1.2.12
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libsigsegv.so.2.0.6
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libc.so.6
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_MEASUREMENT
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_TELEPHONE
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_ADDRESS
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_NAME
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_PAPER
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_MONETARY
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_COLLATE
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_TIME
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_NUMERIC
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/C.utf8/LC_CTYPE
```

`--dir-min <N>` replaces N or more rules that share `exe=`, `perm=` and parent
directory with one `dir=` rule, and a bare `--dir-min` means 5. It is opt-in
because a `dir=` rule allows every path under that directory, which is more
than the log showed, and the comment ahead of the rule names what it replaced.
The same capture with `--dir-min 2`:

```
# rulesteward: line 53: exe= is stale: pid 75414 was denied perm=execute of /usr/lib64/ld-linux-x86-64.so.2, and the daemon keeps the pre-exec image until that exec is permitted; the emitted rule is scoped to exe=/usr/lib64/ld-linux-x86-64.so.2 and not to the logged exe=/usr/sbin/runuser (x16)
# rulesteward: dir=/usr/lib/locale/en_US.utf8/ replaces 10 rules and allows every path under that directory, which is more than this log showed: /usr/lib/locale/en_US.utf8/LC_IDENTIFICATION /usr/lib/locale/en_US.utf8/LC_MEASUREMENT /usr/lib/locale/en_US.utf8/LC_TELEPHONE /usr/lib/locale/en_US.utf8/LC_ADDRESS /usr/lib/locale/en_US.utf8/LC_NAME /usr/lib/locale/en_US.utf8/LC_PAPER /usr/lib/locale/en_US.utf8/LC_MONETARY /usr/lib/locale/en_US.utf8/LC_COLLATE /usr/lib/locale/en_US.utf8/LC_TIME /usr/lib/locale/en_US.utf8/LC_NUMERIC
# rulesteward: new file: none recommended (rules.d/ not read: --no-conf, legacy fapolicyd.rules, or unreadable)
# rulesteward: 6 untrusted path(s) need a trust entry, not a rule: run rulesteward fapolicyd trust on the same input
allow perm=execute exe=/usr/sbin/runuser : path=/usr/lib64/ld-linux-x86-64.so.2
allow perm=open exe=/usr/sbin/runuser : path=/usr/lib64/ld-linux-x86-64.so.2
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/bin/grep
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libpcre.so.1.2.12
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libsigsegv.so.2.0.6
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib64/libc.so.6
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : dir=/usr/lib/locale/en_US.utf8/
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES
allow perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 : path=/usr/lib/locale/C.utf8/LC_CTYPE
```

The three `/usr/lib64` libraries stay as `path=` rules. A parent the FHS names
(`/usr/lib64`, `/usr/bin`, `/opt`, `/home` and the rest) and anything under
`/tmp/`, `/var/tmp/` or `/dev/shm/` is grouped only with `--dir-system` as
well, which on this capture adds `dir=/usr/lib64/`. `dir=/` is never written,
and neither is a `dir=` rule for a suggestion with no usable `exe=`.

## why

```
rulesteward fapolicyd why --conf /etc/fapolicyd/fapolicyd.conf < denials.log
```

One line per denying rule: its number, the `rules.d` file it lives in, how
many denials it produced, and whether `rules` or `trust` has anything for it.
Under `--no-conf` there is no rules file to read, so each line is the number
and the count only. Same capture as under rules, run with `--conf` pointing at
the vendored Rocky 9 conf and `rules.d` fixture:

```
# rulesteward: 2 untrusted path(s) need a trust entry, not a rule: run rulesteward fapolicyd trust on the same input
rule=5   30-patterns.rules      22 denials  subject-side, nothing to emit  deny_audit perm=any pattern=ld_so : all
rule=8   41-shared-obj.rules     1 denials  trust: 1                       deny_audit perm=open all : ftype=application/x-sharedlib
rule=13  90-deny-execute.rules   1 denials  trust: 1                       deny_audit perm=execute all : all
```

## check

```
rulesteward fapolicyd check 50-mine.rules --conf /etc/fapolicyd/fapolicyd.conf < denials.log
```

One line per denial: the verdict, the record, and the rule behind it. `<PATH>`
is a rules file, sorted into the host's `rules.d/` under its own name, or a
directory read as a whole proposed `rules.d/` in place of the host's. The name
is what decides placement, so a candidate merged after the rule that denied
cannot allow anything.

`allowed` names the candidate that matches the record and merges ahead of the
rule that denied it. `denied` means no candidate before that rule matches, so
the same rule denies the access again. `unknown` means the tool did not guess:
the candidate turns on something the record cannot decide (`pattern=`, `uid=`,
`sha256hash=`, a `dir=` keyword such as `execdirs`), the record carries no
`rule=`, the placement cannot be resolved, or `exe=` is the stale pre-exec
image described under rules. A `%set` reference is resolved by membership
against its definition. A set that is undefined, defined twice, or defined
after the rule that names it fails the daemon's reload, so every line of that
run answers `unknown` and says why.

Same capture as under rules, with `--conf` pointing at the vendored Rocky 9
conf and `rules.d` fixture, and a candidate file that allows the denied execute
of `/tmp/live/probe-grep`:

```
allowed perm=execute exe=/usr/sbin/runuser path=/tmp/live/probe-grep rule=13 (1 denials)  00-cand.rules: allow perm=execute all : path=/tmp/live/probe-grep
denied  perm=open exe=/usr/bin/cat path=/tmp/live/probe-lib.so rule=8 (1 denials)  no candidate before rule=8 matches; deny_audit perm=open all : ftype=application/x-sharedlib denies it again
denied  perm=execute exe=/usr/sbin/runuser path=/usr/lib64/ld-linux-x86-64.so.2 rule=5 (1 denials)  no candidate before rule=5 matches; deny_audit perm=any pattern=ld_so : all denies it again
denied  perm=open exe=/usr/sbin/runuser path=/usr/lib64/ld-linux-x86-64.so.2 rule=5 (1 denials)  no candidate before rule=5 matches; deny_audit perm=any pattern=ld_so : all denies it again
unknown perm=open exe=/usr/sbin/runuser path=/usr/bin/grep rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/etc/ld.so.cache rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib64/libpcre.so.1.2.12 rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib64/libsigsegv.so.2.0.6 rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib64/libc.so.6 rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/share/locale/locale.alias rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib64/gconv/gconv-modules.cache rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_MEASUREMENT rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_TELEPHONE rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_ADDRESS rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_NAME rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_PAPER rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_MONETARY rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_COLLATE rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_TIME rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/en_US.utf8/LC_NUMERIC rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/usr/lib/locale/C.utf8/LC_CTYPE rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
unknown perm=open exe=/usr/sbin/runuser path=/etc/hostname rule=5 (1 denials)  exe= is stale (§6): a rule for this record has to name /usr/lib64/ld-linux-x86-64.so.2, not the logged exe=, and no candidate can be matched against a value the log does not carry
```

A directory replaces the host's `rules.d/` whole. The vendored Rocky 9
`rules.d` fixture, proposed as itself against a vendored `ausearch --raw`
capture, allows nothing new:

```
# rulesteward: 23 audit event(s) carry no PATH record for the object, so nothing to act on: load an exit rule with `auditctl -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM` or use the journal route
# rulesteward: line 3: record carries no path=; nothing to act on (this is a syslog_format configuration, not a malformed record) (x2)
denied  perm=execute exe=/tmp/live/probe-grep rule=13 (1 denials)  no candidate before rule=13 matches; deny_audit perm=execute all : all denies it again
denied  perm=open exe=/usr/bin/cat rule=8 (1 denials)  no candidate before rule=8 matches; deny_audit perm=open all : ftype=application/x-sharedlib denies it again
denied  perm=execute exe=/usr/lib64/ld-linux-x86-64.so.2 rule=5 (2 denials)  no candidate before rule=5 matches; deny_audit perm=any pattern=ld_so : all denies it again
denied  perm=open exe=/usr/lib64/ld-linux-x86-64.so.2 rule=5 (20 denials)  no candidate before rule=5 matches; deny_audit perm=any pattern=ld_so : all denies it again
```

With no `<PATH>`, `check` reads the `rules.d/` beside `--conf` as the proposal
and `compiled.rules` as what the daemon loaded, which answers "would what is
on disk now allow these denials?" after an in-place edit and before a reload.
`--no-conf` with no `<PATH>` is a usage error. The three runs below read one
record:

```
rule=13 dec=deny_audit perm=execute auid=1000 pid=1 exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls ftype=application/x-executable trust=1
```

`--conf tests/fixtures/conf/edited/fapolicyd.conf`, where `00-new.rules` was
added to `rules.d/` and `fagenrules` has not run:

```
allowed perm=execute exe=/usr/bin/bash path=/tmp/gaps/trusted-ls rule=13 (1 denials)  00-new.rules: allow perm=execute all : path=/tmp/gaps/trusted-ls
```

`--conf tests/fixtures/conf/default.conf`, where nothing was edited:

```
# rulesteward: tests/fixtures/conf/rules.d merges to the rules the daemon loaded; nothing is proposed and every denial is denied again
denied  perm=execute exe=/usr/bin/bash path=/tmp/gaps/trusted-ls rule=13 (1 denials)  no candidate before rule=13 matches; deny_audit perm=execute all : all denies it again
```

`--conf tests/fixtures/conf/edited-set-and-rule/fapolicyd.conf`, where the edit
added `application/x-executable` to `%languages` and wrote an allow for the
path after the deny that names the set. The set is resolved against the
proposed definition, the record's `ftype=` is now a member, and the deny is
reached first:

```
denied  perm=execute exe=/usr/bin/bash path=/tmp/gaps/trusted-ls rule=13 (1 denials)  50-shipped.rules: deny_audit perm=any all : ftype=%languages
```

Denials left in place are still exit 0. Exit 0 says the input parsed and every
denial got a verdict, not that the candidate rules allow them all.

## trust

```
rulesteward fapolicyd trust < denials.log
```

`fapolicyd-cli --file add` writes the trust file and `--update` is what makes
the running daemon see it, hence the pair. Same capture as under rules:

```
# rulesteward: 18 denial(s) need a rule, not a trust entry: run rulesteward fapolicyd rules on the same input
fapolicyd-cli --file add '/tmp/live/probe-grep'
fapolicyd-cli --update
fapolicyd-cli --file add '/tmp/live/probe-lib.so'
fapolicyd-cli --update
fapolicyd-cli --file add '/etc/ld.so.cache'
fapolicyd-cli --update
fapolicyd-cli --file add '/usr/share/locale/locale.alias'
fapolicyd-cli --update
fapolicyd-cli --file add '/usr/lib64/gconv/gconv-modules.cache'
fapolicyd-cli --update
fapolicyd-cli --file add '/etc/hostname'
fapolicyd-cli --update
```

## Exit codes

- `0`: the input parsed. That includes a log with nothing to suggest.
- `1`: usage or I/O error.
- `2`: input arrived and no line yielded a single `name=value` field.
