# combo-trust-and-ftype

- **class:** scope
- **edge_case_axis:** scope

## Intent

One grant whose OBJECT side combines `trust=` and `ftype=` (both are `Either`-side
attributes per `attrs.rs:57` `BOTH_SIDES = ["all", "dir", "ftype", "trust"]`, so
both legally appear on the object side of a single modern rule). This exercises the
`scope` precedence decision when two scope-keying predicates co-occur on one side.

## Input

One file `C4-trustftype.rules`:

```
allow perm=open all : trust=1 ftype=application/x-executable
```

No `--against-trustdb`, no `--diff-against`.

## Scope precedence decision (justified per f2)

f2 does not state a verbatim precedence table, but a precedence is FORCED by two
grounded facts and is applied consistently across the `combo-*` scenarios:

1. f2 section 2.3 (line 100) calls an inline `filehash=` pin "the STRONGEST static
   pin", and the task's `combo-exe-and-filehash` scenario resolves to `scope:"hash"`
   even though `exe=` (path) is also present. So the operative ordering is by
   SPECIFICITY / strength of the keying predicate, NOT by the enum list order in
   f2 section 3.2 (where `hash` is listed AFTER `path` yet wins).
2. The resulting specificity order is:
   `hash` (a single file pin) > `path`/`dir` (a concrete path) >
   `ftype`/`pattern` (a MIME/loader TYPE class) > `trust` (the ENTIRE trust DB) >
   `all` (everything).

Under that order, `ftype=application/x-executable` (a single MIME-type class) is
MORE SPECIFIC than `trust=1` (which grants over every trusted file in the DB, the
broadest enumerable set, f2 section 2.4). So the grant's `scope` is `ftype`. This
is also the only choice that keeps `combo-uid-gid-no-path` (-> `all`, the broadest
when nothing narrows) and `combo-exe-and-filehash` (-> `hash`, the strongest)
mutually consistent.

## Why the rest of the golden output is correct (f2 sections 2.2 / 3.2)

- One allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`. Subject `all`; object renders both attrs in
  source order: `trust=1 ftype=application/x-executable` (lossless `Display for
  Rule`, `format.rs:56-74`).
- Neither `trust=` nor `ftype=` is a path attribute, so `subjectPaths:[]` and
  `objectPaths:[]` (f2 section 2.4: trust/ftype carry no path).
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef: `setExpansions:{}`.
