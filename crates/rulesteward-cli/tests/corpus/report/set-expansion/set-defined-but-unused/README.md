# set-defined-but-unused

## Intent

A `%set` is DEFINED in the file but referenced by NO grant. The definition is
noise from the register's point of view: `setExpansions` stays `{}` on every
grant, because only sets actually referenced by a rule are expanded (a bare
definition is not, per f2 section 2.2 - setExpansions carries SetRefs used IN the
rule).

`%unused=text/x-perl,text/x-python` is on line 1 but the only grant
(`allow perm=open all : ftype=text/x-shellscript`, line 2) keys on a literal MIME
type and references no set. So `setExpansions: {}`, scope `ftype`,
`hashOrigin: none`. The grant's `source.line` is 2; `loadIndex` is 1 (the setdef
is an `Entry::SetDefinition`, not a grant, and is not enumerated).

This proves the emitter does NOT walk every `Entry::SetDefinition` into
`setExpansions` - only the sets a grant references.

## edge_case_axis

`set-expansion` - the defined-but-unused control, proving a bare set definition
is not expanded into any grant's setExpansions.
