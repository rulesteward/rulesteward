#!/bin/sh
# In-container probe script for RuleSteward issue #478 (fapolicyd-probe-update).
# Runs INSIDE a fapolicyd8/9/10 docker image via `docker run --rm -i <image> sh -s
# -- <dataset>` (see src/probe.rs). Mirrors the ground-truth parse gate documented
# in fapolicyd-corpus/.../tools/validate.sh and this repo's CLAUDE.md "Differential
# verification" section: `fapolicyd-cli --check-rules` does NOT exist on any
# shipping RHEL image, so the real gate is:
#   1. write a candidate rules.d/*.rules file
#   2. fagenrules --load   (regenerates /etc/fapolicyd/compiled.rules)
#   3. timeout 5 fapolicyd --debug --permissive
#   ACCEPT iff a "Loaded N rules" line appears AND no "ERROR" line precedes it
#          (a post-Loaded "Cannot change to uid" is expected unprivileged
#           teardown, not a parse error).
#   REJECT otherwise.
#
# $1 selects which dataset to emit: version | pattern | e07 (see
# transcript.rs's module doc for the TSV row shape each emits).
#
# CRITICAL grounded methodology (issue #478 grounding recon,
# /var/tmp/7b-grounding/p2/drift-findings.md "probe-methodology correction"):
# object-side E07 probes (path=, mode=) must use a CONCRETE subject attribute
# (`exe=/usr/bin/probe`), never bare `all` on the subject side - bare `all` on
# the subject side is itself a real-daemon SYNTAX error
# ("'=' is missing for field :,"), independent of any macro, so a naive
# `allow all : path=%t` probe never reaches the type-check it is meant to
# exercise.
set -u

run_case() {
    dataset="$1"
    id="$2"
    ruletext="$3"
    rm -f /etc/fapolicyd/rules.d/*.rules 2>/dev/null
    printf '%s\n' "$ruletext" >/etc/fapolicyd/rules.d/90-probe.rules
    out=$(fagenrules --load 2>&1; timeout 5 fapolicyd --debug --permissive 2>&1)
    loaded=$(printf '%s\n' "$out" | grep -oE 'Loaded [0-9]+ rules' | grep -oE '[0-9]+' | head -1)
    flat=$(printf '%s\n' "$out" | tr '\t' ' ' | tr '\r\n' '  ' | sed -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//')
    if [ -n "$loaded" ]; then
        pre=$(printf '%s\n' "$out" | sed '/Loaded [0-9]* rules/q' | grep -c ERROR)
        if [ "$pre" -eq 0 ]; then verdict=accept; else verdict=reject; fi
    else
        verdict=reject
        loaded=0
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$dataset" "$id" "$verdict" "$loaded" "$flat"
}

dataset="${1:?usage: probe_fapd.sh <version|pattern|e07>}"

# A leading '#'-prefixed documentation line, always emitted first (regardless of
# dataset): transcript::parse_tsv fails CLOSED on a body with no comment line at all
# (a plausible symptom of a truncated fixture), so LIVE output - which otherwise has
# no header - must carry one too, exactly like the committed tests/fixtures/*.tsv do.
printf '# fapolicyd probe transcript - dataset: %s (live probe via probe_fapd.sh)\n' "$dataset"

case "$dataset" in
version)
    # --- dataset (a): exact fapolicyd version ---------------------------------
    v=$(rpm -q fapolicyd 2>&1)
    printf 'version\trpm_q\tok\t\t%s\n' "$v"
    ;;
pattern)
    # --- dataset (b): pattern= accepted value set ------------------------------
    # Candidate universe = union of the shipped RHEL8/RHEL9+ tables
    # (crates/rulesteward-fapolicyd/src/lints/version_target.rs) plus a
    # guaranteed-bogus sentinel.
    for val in normal ld_so ld_preload static zzzz_rulesteward_probe_bogus; do
        run_case pattern "$val" "allow perm=any pattern=$val : all"
    done
    ;;
e07)
    # --- dataset (c): fapd-E07 attribute type categories -----------------------
    # Representative probes per crates/rulesteward-fapolicyd/src/attrs.rs
    # AttrTypeCategory: Unsigned (uid/auid/sessionid always; pid/ppid on rhel8;
    # gid on rhel9+), Signed (pid/ppid on rhel9+), Str (exe subject; path/mode
    # object, via the object-side fix above), Permissive (gid on rhel8), NoSet
    # (pattern/trust).
    run_case e07 uid_int "%t=1,2,3
allow uid=%t : all"
    run_case e07 uid_str "%t=abc,def
allow uid=%t : all"
    run_case e07 auid_int "%t=1,2,3
allow auid=%t : all"
    run_case e07 auid_str "%t=abc,def
allow auid=%t : all"
    run_case e07 sessionid_int "%t=1,2,3
allow sessionid=%t : all"
    run_case e07 sessionid_str "%t=abc,def
allow sessionid=%t : all"

    run_case e07 pid_int "%t=1,2,3
allow pid=%t : all"
    run_case e07 pid_signed_negfirst "%t=-1,-2
allow pid=%t : all"
    run_case e07 pid_str "%t=abc,def
allow pid=%t : all"

    run_case e07 ppid_int "%t=1,2,3
allow ppid=%t : all"
    run_case e07 ppid_signed_negfirst "%t=-1,-2
allow ppid=%t : all"
    run_case e07 ppid_str "%t=abc,def
allow ppid=%t : all"

    run_case e07 gid_str "%t=abc,def
allow gid=%t : all"
    run_case e07 gid_int "%t=1,2,3
allow gid=%t : all"
    run_case e07 gid_mixed "%t=1,abc
allow gid=%t : all"

    run_case e07 exe_str "%t=abc,def
allow exe=%t : all"
    run_case e07 exe_int "%t=1,2,3
allow exe=%t : all"

    # Object-side (path/mode): concrete subject attr, per the methodology note
    # above - NOT bare `all` on the subject side.
    run_case e07 path_str "%t=abc,def
allow exe=/usr/bin/probe : path=%t"
    run_case e07 path_int "%t=1,2,3
allow exe=/usr/bin/probe : path=%t"
    run_case e07 mode_str "%t=abc,def
allow exe=/usr/bin/probe : mode=%t"
    run_case e07 mode_int "%t=1,2,3
allow exe=/usr/bin/probe : mode=%t"

    run_case e07 pattern_set "%t=1,2,3
allow pattern=%t : all"
    run_case e07 trust_set "%t=1,2,3
allow trust=%t : all"
    ;;
*)
    echo "probe_fapd.sh: unknown dataset $dataset (expected version|pattern|e07)" >&2
    exit 1
    ;;
esac
