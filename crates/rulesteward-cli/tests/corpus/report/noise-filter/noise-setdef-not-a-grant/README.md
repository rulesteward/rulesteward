# noise-setdef-not-a-grant

- **class:** noise-filter
- **edge_case_axis:** noise-filter

## Intent

A rules file containing a `%macro` set DEFINITION line plus a comment line and a
blank line. The register correctly emits ONLY the actual allow-grant, proving that
set-definition lines (and comments and blanks) are NOT grants and do not produce
register rows. The set definition still resolves into the grant's `setExpansions`,
but the definition line itself is never a grant.

## Input

One file `B2-setdef.rules`:

```
# scripts allowlist
%scripts=text/x-perl,text/x-python

allow perm=open all : ftype=%scripts
```

- Line 1: a comment (`Entry::Comment`) - not a grant.
- Line 2: a set definition (`Entry::SetDefinition`) - not a grant; not
  load-indexed.
- Line 3: a blank (`Entry::Blank`) - not a grant.
- Line 4: the single allow-grant.

No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- The register enumerates only allow-family `Entry::Rule` entries (f2 section
  2.1). The comment, the set definition, and the blank are non-`Rule` entries and
  are skipped, so there is exactly ONE register row.
- That row is on line 4: `source.line:4`, `loadIndex:1` (the set definition is
  not a grant and is not load-indexed - same rule as `set-defined-but-unused` and
  `set-expansion-single-member`).
- `perm=open` renders `perm:"open"`. Subject `all`; object `ftype=%scripts`
  (the SetRef renders verbatim as `%scripts`).
- `ftype=` is a type predicate: `scope:"ftype"`, `subjectPaths:[]`,
  `objectPaths:[]`, `hash:null`, `hashOrigin:"none"`, `hashAlgorithm:null`.
- The grant references `%scripts`, so `setExpansions` carries
  `"%scripts" -> ["text/x-perl", "text/x-python"]` (already sorted; f2 section
  2.2). This confirms the set DEFINITION feeds the expansion WITHOUT itself being
  a grant row.
