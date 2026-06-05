# set-no-expansion

## Intent

A grant with no SetRef anywhere in its predicates, confirming `setExpansions` is
an empty object `{}` (not null, not omitted) when nothing is expanded.

The single grant `allow perm=open all : ftype=text/x-shellscript` keys on a
literal MIME type, not a `%set`. So `setExpansions: {}`. Scope is `ftype`.
`hashOrigin: none`, `hash: null`, `hashAlgorithm: null` (type-scoped). Both path
arrays empty. The grant is on line 1, `loadIndex` 1.

This is the negative control for the set-expansion axis: it pins the empty-object
shape so the single/multi-member cases can be distinguished from "no set used."

## edge_case_axis

`set-expansion` - the absent-SetRef control, fixing `setExpansions` to `{}`.
