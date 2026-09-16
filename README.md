# rulesteward

audit2why/audit2allow for host policy systems. Read fapolicyd denial records on
stdin, write the rules that would allow them on stdout.

Two verbs share that input. `rules` answers denials a rule fixes and `trust`
answers denials of an untrusted file that a trust entry fixes. Each one's output
says when the other verb is the right answer for part of the input.

## Install

Download from <https://github.com/rulesteward/rulesteward/releases>. `SHA256SUMS`
sits beside both assets.

```
dnf install ./rulesteward-0.3.0-1.x86_64.rpm
```

installs `/usr/bin/rulesteward`. The tarball holds the same static binary and
nothing else:

```
tar -xzf rulesteward-v0.3.0-x86_64-unknown-linux-musl.tar.gz
```

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
