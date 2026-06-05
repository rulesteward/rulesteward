# report golden scenario: hash-filehash-sha1-40

- class: hash-origin-alg
- edge_case_axis: hash-origin-alg

## Intent

A 40-hex inline filehash yields hashAlgorithm SHA1 (length 40).

## Input

rules.d/ contains the fapolicyd rule file(s) below. The register is the
static exception-register JSON computed by mapping the allow-family grants
per f2 sections 2.2/3.2 (no daemon, no trust DB join: against_trustdb=false).

### rules.d/61-sha1.rules

```
allow perm=open all : filehash=0123456789abcdef0123456789abcdef01234567
```

## Edge case axis

`hash-origin-alg`: this scenario exercises the hashOrigin x
hashAlgorithm mapping. hashAlgorithm is inferred BY HEX LENGTH
(32=MD5, 40=SHA1, 64=SHA256, 128=SHA512); hashOrigin is rule-filehash when
the rule embeds filehash=/sha256hash=, else none. Without --against-trustdb a
type/pattern/trust-scoped grant has no hash to attach (honest none).

## Golden output

`golden-register.json` is the canonical exception-register envelope. It is
valid JSON and ends with a trailing newline.
