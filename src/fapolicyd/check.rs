//! `check`: would a proposed `rules.d/` have allowed these denials? DESIGN.md §7, #121.
//!
//! Pure like the rest of `fapolicyd/`: `main.rs` reads the candidate path and hands the
//! merged listing here. Every branch below is measured. The 48-row table in #120 is this
//! module's unit test, and that issue's corrections K1, K2 and K3 are cited where they
//! changed the code.
//!
//! One rule governs the whole module: **a wrong `allowed` is worse than an `unknown`**.
//! What the daemon evaluates and a log record cannot answer -- `pattern=`, a `%set`, a
//! `uid=`, a rule the operator moved -- returns `Unknown` naming the reason. Closing
//! those cases means evaluating the whole ruleset against a reconstructed event, which is
//! parked (DESIGN.md §11).

use super::model::Record;
use super::rules::{Attr, Rule};
use super::rules_d;
use std::io::Write;

/// What the candidates would do with one denial. Each arm carries the line's last
/// column: the candidate as `file: rule text`, or the reason there is no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An `allow*` candidate matches before the rule that denied.
    Allowed(String),
    /// A `deny*` candidate matches first, or nothing the operator added matches and the
    /// rule that denied denies again.
    Denied(String),
    Unknown(String),
}

/// The denial a report line is about (D-d). Two records agreeing on these six values are
/// one line with a count, however many times the log repeats them.
///
/// `ftype` and `trust` are in the key and not in the line: two records for one path can
/// differ in them and reach different rules, so collapsing them would hide a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    perm: Option<Vec<u8>>,
    exe: Option<Vec<u8>>,
    path: Option<Vec<u8>>,
    ftype: Option<Vec<u8>>,
    trust: Option<Vec<u8>>,
    rule: Option<usize>,
}

pub fn key(record: &Record, n: Option<usize>) -> Key {
    Key {
        perm: record.subject_get(b"perm"),
        exe: record.subject_get(b"exe"),
        path: record.object_get(b"path"),
        ftype: record.object_get(b"ftype"),
        trust: record.object_get(b"trust"),
        rule: n,
    }
}

/// What `check` was asked to check (#158). Both arms carry the same merged listing to
/// `verdict`; what differs is what rule `N` is placed against.
#[derive(Clone, Copy)]
pub enum Proposal<'a> {
    /// `check <PATH>`: the host's `rules.d/` with the candidates merged in, placed
    /// against that same directory as fagenrules last left it.
    Merged(&'a [rules_d::File]),
    /// `check` with no `PATH`: the host's `rules.d/` as it is on disk now, placed against
    /// `compiled.rules`. The two disagreeing is the edit being asked about and not drift,
    /// so there is no host listing to locate rule `N` in.
    OnDisk,
}

/// The verdict for one denial: `n` is its `rule=`, `stale` what §6's rewrite would scope
/// a rule to, `compiled` the host's own rules, `host` the `rules.d/` they were generated
/// from -- `None` in `Proposal::OnDisk`, where the proposal is that directory itself --
/// and `proposed` the merged listing to walk.
///
/// The walk is candidates-only, which is D3: the daemon reached rule N, so every rule the
/// host already had before N is proved not to match this record and is skipped rather
/// than re-evaluated. Only what the operator added has to be decided, and everything the
/// matcher cannot decide stops the walk.
pub fn verdict(
    record: &Record,
    n: Option<usize>,
    stale: Option<&[u8]>,
    compiled: Option<&[Rule]>,
    host: Option<&[rules_d::File]>,
    proposed: &[rules_d::File],
) -> Verdict {
    // K3: #120 measured the daemon comparing a candidate's `exe=` against the value the
    // record logs, verbatim, on all three releases -- so the one case the comparison
    // cannot be trusted is where this tool's own §6 rewrite fires, because there the
    // logged value and the value a rule would have to name are different images.
    if let Some(execed) = stale {
        return Verdict::Unknown(format!(
            "exe= is stale (§6): a rule for this record has to name {}, not the logged \
             exe=, and no candidate can be matched against a value the log does not carry",
            shown(execed)
        ));
    }
    let Some(n) = n else {
        return Verdict::Unknown(
            "the record carries no rule= (or rule=0): there is no position to merge the \
             candidates against"
                .into(),
        );
    };
    let Some(compiled) = compiled else {
        return Verdict::Unknown(
            "no rules file was read (--no-conf, a legacy fapolicyd.rules, or unreadable): \
             rule= resolves to nothing and the candidates cannot be placed"
                .into(),
        );
    };
    let Some(target) = n.checked_sub(1).and_then(|i| compiled.get(i)) else {
        return Verdict::Unknown(format!(
            "rule={n} is past the end of the rules file: it is not this log's"
        ));
    };
    // Drift: `rules.d/` no longer agrees with `compiled.rules`, so the merged order in
    // hand is not the one that produced this `rule=` and nothing can be placed against it.
    // `Proposal::OnDisk` has no host listing, because there that disagreement is the
    // proposal itself (#158) and rule N is found by its text below.
    let from = match host {
        Some(host) => match rules_d::locate(host, compiled, n).and_then(|i| host.get(i)) {
            Some(from) => Some(from),
            None => {
                return Verdict::Unknown(format!(
                    "rule={n} is not in the host rules.d/ (not read, or changed since \
                     fagenrules ran); run fagenrules, recapture, rerun"
                ));
            }
        },
        None => None,
    };
    // K1: `perm=` is not optional. `allow all : path=...` fails the reload with `'=' is
    // missing for field :` on 8, 9 and 10, the daemon discards the WHOLE ruleset and goes
    // on answering `rule=0 dec=no-opinion`, so one such rule decides every denial in the
    // run and not just the ones it was written for.
    if let Some((file, text)) = missing_perm(proposed, compiled) {
        return Verdict::Unknown(format!(
            "{file}: {text} has no perm=, which fails the reload and discards the whole \
             ruleset (#120 K1); nothing can be checked against these candidates"
        ));
    }
    // Rule N has to still be where it was, in the file it came from. An operator who
    // moved or deleted it changed which rules precede it, and deciding that needs the
    // full-ruleset evaluation §11 parks. With no host listing there is no file it came
    // from, so its text decides wherever the edit left it: a duplicate earlier in the
    // merge only shortens the walk, which can turn an `allowed` into a `denied` and
    // never the other way.
    let limit = match from {
        Some(from) => position(proposed, &from.name, &target.text),
        None => flat(proposed).position(|(_, rule)| rule.text == target.text),
    };
    let Some(limit) = limit else {
        return Verdict::Unknown(format!(
            "rule={n} ({}) is no longer in {}: which rules now precede it cannot be \
             decided from this record alone",
            target.text,
            from.map_or("the rules.d/ on disk", |f| f.name.as_str())
        ));
    };

    for (file, rule) in flat(proposed).take(limit) {
        // D3 again: this rule is one of the host's own, from before N, and the daemon
        // walked past it to reach N.
        if compiled
            .iter()
            .take(n - 1)
            .any(|before| before.text == rule.text)
        {
            continue;
        }
        let named = format!("{}: {}", file.name, rule.text);
        match matches(rule, record) {
            Some(false) => {}
            // Whatever a later candidate would say, the daemon might never reach it.
            None => {
                return Verdict::Unknown(format!(
                    "{named} cannot be decided from this record, and it is reached before \
                     rule={n}"
                ));
            }
            Some(true) if rule.decision.starts_with("allow") => return Verdict::Allowed(named),
            Some(true) if rule.decision.starts_with("deny") => return Verdict::Denied(named),
            // Neither word: fagenrules would merge it and the daemon would refuse it.
            Some(true) => {
                return Verdict::Unknown(format!("{named} is neither an allow nor a deny"));
            }
        }
    }
    Verdict::Denied(format!(
        "no candidate before rule={n} matches; {} denies it again",
        target.text
    ))
}

/// D-d's report, in first-seen order: one line per denial, the verdict first so the file
/// is greppable by it, then the record's own fields, the count, and the candidate or the
/// reason.
pub fn report(rows: &[(Key, usize, Verdict)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, count, verdict) in rows {
        let (word, detail) = rendered(verdict);
        let mut fields = String::new();
        for (name, value) in [("perm", &k.perm), ("exe", &k.exe), ("path", &k.path)] {
            if let Some(v) = value {
                fields.push_str(&format!("{name}={} ", shown(v)));
            }
        }
        if let Some(n) = k.rule {
            fields.push_str(&format!("rule={n} "));
        }
        // Writing into a Vec cannot fail; the one write that can is in main.rs.
        let _ = writeln!(out, "{word:<7} {fields}({count} denials)  {detail}");
    }
    out
}

/// A record's value as the daemon spelled it: every control byte back in the escaper's
/// octal form, the rest lossily as text.
///
/// §9 promises bare lines on stdout, and the values here come back from `model::get`
/// UNESCAPED -- so a path holding a newline would write two lines and a second denial
/// would appear out of nowhere. `rocky8-base-edge-paths.log` has exactly that path, which
/// is how this was found. The emitter refuses such a record outright (§7); a report has to
/// name it instead, so it names it the way the record did.
fn shown(value: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(value).chars() {
        if c.is_control() {
            out.push_str(&format!("\\{:03o}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The verdict word and its detail. One place, so the report and the tests cannot drift.
fn rendered(verdict: &Verdict) -> (&'static str, &str) {
    match verdict {
        Verdict::Allowed(d) => ("allowed", d),
        Verdict::Denied(d) => ("denied", d),
        Verdict::Unknown(d) => ("unknown", d),
    }
}

/// Every rule of a merged `rules.d/` in the order the daemon reads it, with the file it
/// came from.
fn flat(files: &[rules_d::File]) -> impl Iterator<Item = (&rules_d::File, &Rule)> {
    files
        .iter()
        .flat_map(|f| f.rules.iter().map(move |r| (f, r)))
}

/// The merged index of the rule whose text is `text` in the file called `name`.
fn position(files: &[rules_d::File], name: &str, text: &str) -> Option<usize> {
    let mut merged = 0usize;
    for file in files {
        if file.name == name {
            return file
                .rules
                .iter()
                .position(|r| r.text == text)
                .map(|i| merged + i);
        }
        merged += file.rules.len();
    }
    None
}

/// The first proposed rule the host did not already have and that carries no `perm=` (K1).
fn missing_perm<'a>(
    proposed: &'a [rules_d::File],
    compiled: &[Rule],
) -> Option<(&'a str, &'a str)> {
    flat(proposed)
        .filter(|(_, r)| !compiled.iter().any(|host| host.text == r.text))
        .find(|(_, r)| !r.attrs().0.iter().any(|a| matches!(a, Attr::Perm(_))))
        .map(|(f, r)| (f.name.as_str(), r.text.as_str()))
}

/// Does this rule fire on this record? `Some(true)` yes, `Some(false)` no, `None` no
/// answer this tool may give.
///
/// A rule is a conjunction of its attributes, so one that does not match settles the rule
/// whatever the others are -- which is why `Some(false)` wins over `None` here, and why a
/// rule broken by K2's missing `=` matches nothing while still occupying its slot.
fn matches(rule: &Rule, record: &Record) -> Option<bool> {
    let (subject, object) = rule.attrs();
    let mut undecided = false;
    for attr in subject
        .iter()
        .map(|a| subject_matches(a, record))
        .chain(object.iter().map(|a| object_matches(a, record)))
    {
        match attr {
            Some(false) => return Some(false),
            Some(true) => {}
            None => undecided = true,
        }
    }
    (!undecided).then_some(true)
}

fn subject_matches(attr: &Attr, record: &Record) -> Option<bool> {
    let exe = || field(record.subject_get(b"exe"));
    match attr {
        Attr::All => Some(true),
        Attr::Perm(p) => perm_matches(p, record),
        // K3: verbatim against the value the record logs.
        Attr::Exe(e) => Some(exe()? == e.as_bytes()),
        // #120 Q4: a plain byte prefix with no slash logic, `strncmp` and nothing more --
        // subject `dir=/usr/sbi` matched `exe=/usr/sbin/runuser`.
        Attr::Dir(d) => prefix(exe()?, d),
        Attr::NeverMatches => Some(false),
        // Subject `trust=` is #120's H3, not measured. `uid=`, `pattern=`, `comm=` and an
        // object attribute written on this side are outside D4 altogether.
        _ => None,
    }
}

fn object_matches(attr: &Attr, record: &Record) -> Option<bool> {
    let get = |name: &[u8]| field(record.object_get(name));
    match attr {
        Attr::All => Some(true),
        Attr::Path(p) => Some(get(b"path")? == p.as_bytes()),
        // #120 Q4 again: `dir=/tmp/live` allowed `/tmp/live2/probe-grep`.
        Attr::Dir(d) => prefix(get(b"path")?, d),
        Attr::Ftype(f) => Some(get(b"ftype")? == f.as_bytes()),
        // #120 Q5: object `trust=` compares against the logged value. Subject trust takes
        // a different path with no sentinel (DESIGN.md §7) and is never evaluated.
        Attr::Trust(t) => Some(get(b"trust")? == t.as_bytes()),
        Attr::NeverMatches => Some(false),
        _ => None,
    }
}

/// #120 Q2. `any` matches both perms and `open`/`execute` match the equal value; any
/// other value on either side is outside the measured set.
fn perm_matches(rule_perm: &str, record: &Record) -> Option<bool> {
    let logged = field(record.subject_get(b"perm"))?;
    if !matches!(logged.as_slice(), b"open" | b"execute") {
        return None;
    }
    match rule_perm {
        "any" => Some(true),
        "open" | "execute" => Some(logged == rule_perm.as_bytes()),
        _ => None,
    }
}

/// A `dir=` prefix test, refused on a value the daemon had to escape.
///
/// The rule language has no escape mechanism and no quoting (`rules.rs`), so what the
/// daemon wrote and what a rule would have to spell are not the same bytes, and #120
/// measured neither: a space made the rule unloadable (K2) and nothing measured the
/// prefix. `sh_set` plus the control bytes is the escaper's whole table
/// (`parse::unescape`), and `<= b' '` is `sh_set`'s own space plus every one of those
/// control bytes -- which is why the literal below does not repeat the space.
fn prefix(value: Vec<u8>, dir: &str) -> Option<bool> {
    let escaped = value
        .iter()
        .any(|b| *b <= b' ' || b"\"'`$\\!()|".contains(b));
    (!escaped).then(|| value.starts_with(dir.as_bytes()))
}

/// The record's value for a field, or `None` when it carries nothing a rule can be
/// compared against: the daemon writes `?` for an image it could not read and `??` for a
/// path it could not encode (DESIGN.md §4), and neither names a file.
fn field(value: Option<Vec<u8>>) -> Option<Vec<u8>> {
    value.filter(|v| !matches!(v.as_slice(), b"?" | b"??"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fapolicyd::{parse, rules};

    /// The shipped Rocky `rules.d/`, verbatim, in the eleven files fagenrules merges it
    /// from: #120's host ruleset, identical on 8, 9 and 10. Inlined rather than read out
    /// of `tests/fixtures/conf/`, because these are the rules the measurement ran against
    /// and they have to stay fixed whatever a golden fixture needs later.
    ///
    /// Merged, it is `compiled.rules`: fourteen rules, `pattern=ld_so` at 5, the
    /// `%languages` deny at 11, the execute deny at 13 and `allow perm=open all : all`
    /// at 14. Those four numbers are the ones every row below turns on.
    const HOST: &[(&str, &str)] = &[
        (
            "10-languages.rules",
            "%languages=application/x-bytecode.ocaml,application/x-bytecode.python,application/java-archive,text/x-java,application/x-java-applet,application/javascript,text/javascript,text/x-awk,text/x-gawk,text/x-lisp,application/x-elc,text/x-lua,text/x-m4,text/x-nftables,text/x-perl,text/x-php,text/x-script.python,text/x-python,text/x-R,text/x-ruby,text/x-script.guile,text/x-tcl,text/x-luatex,text/x-systemtap\n",
        ),
        (
            "20-dracut.rules",
            "allow perm=any uid=0 : dir=/var/tmp/\nallow perm=any uid=0 trust=1 : all\n",
        ),
        (
            "21-updaters.rules",
            "allow perm=open exe=/usr/bin/rpm : all\nallow perm=open exe=/usr/bin/python3.9 comm=dnf : all\n",
        ),
        (
            "30-patterns.rules",
            "deny_audit perm=any pattern=ld_so : all\n",
        ),
        (
            "40-bad-elf.rules",
            "deny_audit perm=any all : ftype=application/x-bad-elf\n",
        ),
        (
            "41-shared-obj.rules",
            "allow perm=open all : ftype=application/x-sharedlib trust=1\ndeny_audit perm=open all : ftype=application/x-sharedlib\n",
        ),
        ("42-trusted-elf.rules", "allow perm=execute all : trust=1\n"),
        (
            "70-trusted-lang.rules",
            "allow perm=open all : ftype=%languages trust=1\ndeny_audit perm=any all : ftype=%languages\n",
        ),
        (
            "72-shell.rules",
            "allow perm=any all : ftype=text/x-shellscript\n",
        ),
        (
            "90-deny-execute.rules",
            "deny_audit perm=execute all : all\n",
        ),
        ("95-allow-open.rules", "allow perm=open all : all\n"),
    ];

    /// The probes' own records, as the daemon logged them under the install-default
    /// `syslog_format` (#120). Each `rule=` is the one the control row measured with no
    /// candidate present.
    const EXEC: &str = "rule=13 dec=deny_audit perm=execute auid=1000 pid=1100 \
exe=/usr/sbin/runuser : path=/tmp/live/probe-grep ftype=application/x-executable trust=0";
    const LIB: &str = "rule=8 dec=deny_audit perm=open auid=1000 pid=1101 exe=/usr/bin/cat \
: path=/tmp/live/probe-lib.so ftype=application/x-sharedlib trust=0";
    const PY: &str = "rule=11 dec=deny_audit perm=open auid=1000 pid=1102 exe=/usr/bin/cat \
: path=/tmp/live/probe.py ftype=text/x-python trust=0";
    /// The trusted `grep` reached through `ld-linux`: rule 5 is subject-side, which is the
    /// shape D3 was least obviously true for.
    const LDSO: &str = "rule=5 dec=deny_audit perm=open auid=1000 pid=1103 \
exe=/usr/sbin/runuser : path=/usr/bin/grep ftype=application/x-executable trust=1";
    /// The sibling directory the `dir=` rows turn on: `/tmp/live2`, not `/tmp/live`.
    const SIBLING: &str = "rule=13 dec=deny_audit perm=execute auid=1000 pid=1104 \
exe=/usr/sbin/runuser : path=/tmp/live2/probe-grep ftype=application/x-executable trust=0";
    /// K2's path, escaped the way the daemon writes it.
    const SPACE: &str = "rule=13 dec=deny_audit perm=execute auid=1000 pid=1105 \
exe=/usr/sbin/runuser : path=/tmp/live/sp\\ ace/probe-grep \
ftype=application/x-executable trust=0";
    /// Q7's stale window: the lib open by the process that already exec'd `probe-grep`.
    /// K3 measured that this record logs the exec'd image and not `runuser`, which is why
    /// a candidate naming `runuser` did not fire on it.
    const LIB_BY_PROBE: &str = "rule=8 dec=deny_audit perm=open auid=1000 pid=1106 \
exe=/tmp/live/probe-grep : path=/tmp/live/probe-lib.so ftype=application/x-sharedlib \
trust=0";

    /// One row of #120's table: the case name, the candidate file and its rules (`None`
    /// for a control row), the record, and fapolicyd's MEASURED verdict.
    type Row = (
        &'static str,
        Option<(&'static str, &'static str)>,
        &'static str,
        &'static str,
    );

    /// #120's table, one row each, the expectation being fapolicyd's MEASURED verdict and
    /// never the predicted one. A candidate in `00-cand.rules` merges as rule 1 and one in
    /// `99-cand.rules` as rule 15, which is the whole of the before/after split.
    ///
    /// Three rows of the 48 are not here. `window-control` is an **allow** record --
    /// `allow (rule=14)`, the shipped `allow perm=open all : all` -- so it is not a denial
    /// and this tool never sees it; `window-deny-names-logged` and
    /// `window-deny-names-executed` are candidates against that same allowed open, so they
    /// measure which `exe=` a candidate must name rather than a verdict. They are
    /// `the_window_rows_pin_which_exe_a_candidate_must_name` below.
    const TABLE: &[Row] = &[
        ("exec-control", None, EXEC, "denied"),
        ("lib-control", None, LIB, "denied"),
        ("py-control", None, PY, "denied"),
        ("ldso-control", None, LDSO, "denied"),
        (
            "exec-before-N",
            Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "exec-after-N",
            Some((
                "99-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "denied",
        ),
        (
            "subjectside-before-N",
            Some(("00-cand.rules", "allow perm=any all : path=/usr/bin/grep")),
            LDSO,
            "allowed",
        ),
        (
            "subjectside-after-N",
            Some(("99-cand.rules", "allow perm=any all : path=/usr/bin/grep")),
            LDSO,
            "denied",
        ),
        (
            "set-ruleN-before",
            Some((
                "00-cand.rules",
                "allow perm=open all : path=/tmp/live/probe.py",
            )),
            PY,
            "allowed",
        ),
        (
            "set-ruleN-after",
            Some((
                "99-cand.rules",
                "allow perm=open all : path=/tmp/live/probe.py",
            )),
            PY,
            "denied",
        ),
        (
            "cand-perm=open-vs-open",
            Some((
                "00-cand.rules",
                "allow perm=open all : path=/tmp/live/probe-lib.so",
            )),
            LIB,
            "allowed",
        ),
        (
            "cand-perm=open-vs-execute",
            Some((
                "00-cand.rules",
                "allow perm=open all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "denied",
        ),
        (
            "cand-perm=execute-vs-open",
            Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-lib.so",
            )),
            LIB,
            "denied",
        ),
        (
            "cand-perm=execute-vs-execute",
            Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "cand-perm=any-vs-open",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-lib.so",
            )),
            LIB,
            "allowed",
        ),
        (
            "cand-perm=any-vs-execute",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        // K1: the reload failed on all three releases, so there is no verdict to have.
        (
            "cand-no-perm-vs-open",
            Some(("00-cand.rules", "allow all : path=/tmp/live/probe-lib.so")),
            LIB,
            "unknown",
        ),
        (
            "cand-no-perm-vs-execute",
            Some(("00-cand.rules", "allow all : path=/tmp/live/probe-grep")),
            EXEC,
            "unknown",
        ),
        (
            "exe-exact",
            Some((
                "00-cand.rules",
                "allow perm=any exe=/usr/sbin/runuser : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "exe-other",
            Some((
                "00-cand.rules",
                "allow perm=any exe=/usr/bin/bash : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "denied",
        ),
        (
            "path-other",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-gre",
            )),
            EXEC,
            "denied",
        ),
        (
            "obj-dir-slash",
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live/")),
            EXEC,
            "allowed",
        ),
        (
            "obj-dir-noslash",
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live")),
            EXEC,
            "allowed",
        ),
        (
            "obj-dir-slash-sibling",
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live/")),
            SIBLING,
            "denied",
        ),
        // The prefix is bytes and not path components: `/tmp/live` covers `/tmp/live2`.
        (
            "obj-dir-noslash-sibling",
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live")),
            SIBLING,
            "allowed",
        ),
        (
            "subj-dir-slash",
            Some((
                "00-cand.rules",
                "allow perm=any dir=/usr/sbin/ : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "subj-dir-noslash",
            Some((
                "00-cand.rules",
                "allow perm=any dir=/usr/sbin : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "subj-dir-partial",
            Some((
                "00-cand.rules",
                "allow perm=any dir=/usr/sbi : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        (
            "subj-dir-other",
            Some((
                "00-cand.rules",
                "allow perm=any dir=/usr/bin/ : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "denied",
        ),
        (
            "ftype-match",
            Some((
                "00-cand.rules",
                "allow perm=any all : ftype=application/x-executable",
            )),
            EXEC,
            "allowed",
        ),
        (
            "ftype-other",
            Some((
                "00-cand.rules",
                "allow perm=any all : ftype=application/x-sharedlib",
            )),
            EXEC,
            "denied",
        ),
        (
            "trust0-match",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-grep trust=0",
            )),
            EXEC,
            "allowed",
        ),
        (
            "trust1-vs-0",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-grep trust=1",
            )),
            EXEC,
            "denied",
        ),
        (
            "trust1-match",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/usr/bin/grep trust=1",
            )),
            LDSO,
            "allowed",
        ),
        (
            "trust0-vs-1",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/usr/bin/grep trust=0",
            )),
            LDSO,
            "denied",
        ),
        // Q6: first match wins, in both orders.
        (
            "deny-then-allow",
            Some((
                "00-cand.rules",
                "deny_audit perm=any all : path=/tmp/live/probe-grep\n\
                 allow perm=any all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "denied",
        ),
        (
            "allow-then-deny",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/probe-grep\n\
                 deny_audit perm=any all : path=/tmp/live/probe-grep",
            )),
            EXEC,
            "allowed",
        ),
        ("stale-control", None, LIB_BY_PROBE, "denied"),
        (
            "cand-names-logged-exe",
            Some((
                "00-cand.rules",
                "allow perm=open exe=/usr/sbin/runuser : path=/tmp/live/probe-lib.so",
            )),
            LIB_BY_PROBE,
            "denied",
        ),
        (
            "cand-names-executed-path",
            Some((
                "00-cand.rules",
                "allow perm=open exe=/tmp/live/probe-grep : path=/tmp/live/probe-lib.so",
            )),
            LIB_BY_PROBE,
            "allowed",
        ),
        (
            "exec-allowed+executed-path",
            Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep\n\
                 allow perm=open exe=/tmp/live/probe-grep : path=/tmp/live/probe-lib.so",
            )),
            LIB_BY_PROBE,
            "allowed",
        ),
        (
            "exec-allowed+logged-exe",
            Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep\n\
                 allow perm=open exe=/usr/sbin/runuser : path=/tmp/live/probe-lib.so",
            )),
            LIB_BY_PROBE,
            "denied",
        ),
        ("space-control", None, SPACE, "denied"),
        // K2: both spellings draw `'=' is missing for field ace/probe-grep`, load anyway,
        // occupy rule 1 and match nothing.
        (
            "space-cand-literal",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/sp ace/probe-grep",
            )),
            SPACE,
            "denied",
        ),
        (
            "space-cand-escaped",
            Some((
                "00-cand.rules",
                "allow perm=any all : path=/tmp/live/sp\\ ace/probe-grep",
            )),
            SPACE,
            "denied",
        ),
    ];

    /// `rules.d/` as the daemon's host has it, plus the candidate file when there is one.
    fn listing(candidate: Option<(&str, &str)>) -> Vec<(String, Vec<u8>)> {
        HOST.iter()
            .map(|(name, body)| ((*name).to_string(), body.as_bytes().to_vec()))
            .chain(
                candidate.map(|(name, body)| (name.to_string(), format!("{body}\n").into_bytes())),
            )
            .collect()
    }

    fn host() -> Vec<rules_d::File> {
        rules_d::files(listing(None))
    }

    /// What fagenrules would have written: the same files, concatenated in merge order.
    fn compiled() -> Vec<Rule> {
        rules::parse(
            HOST.iter()
                .map(|(_, body)| *body)
                .collect::<String>()
                .as_bytes(),
        )
    }

    /// One record and its `rule=`, read exactly as `analyze` reads them.
    fn parsed(line: &str) -> (Record, Option<usize>) {
        let record = parse::parse(line.as_bytes());
        let n = record
            .subject_get(b"rule")
            .and_then(|v| std::str::from_utf8(&v).ok()?.parse::<usize>().ok())
            .filter(|n| *n != 0);
        (record, n)
    }

    /// The verdict for one row: no stale window, the shipped host, the candidate merged.
    fn check(candidate: Option<(&str, &str)>, line: &str) -> Verdict {
        let (record, n) = parsed(line);
        let compiled = compiled();
        verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &rules_d::files(listing(candidate)),
        )
    }

    #[test]
    fn the_host_ruleset_is_the_shipped_fourteen_rules() {
        let compiled = compiled();
        assert_eq!(compiled.len(), 14, "the daemon logged `Loaded 14 rules`");
        assert_eq!(compiled[4].text, "deny_audit perm=any pattern=ld_so : all");
        assert_eq!(
            compiled[10].text,
            "deny_audit perm=any all : ftype=%languages"
        );
        assert_eq!(compiled[12].text, "deny_audit perm=execute all : all");
        assert_eq!(compiled[13].text, "allow perm=open all : all");
        // Every host rule has to `locate`, or the walk below would stop at a drift that
        // is really a typo in the constant above.
        for n in 1..=14 {
            assert!(
                rules_d::locate(&host(), &compiled, n).is_some(),
                "rule={n} does not locate to a file"
            );
        }
    }

    #[test]
    fn a_candidate_file_merges_first_or_last_by_its_name() {
        let names = |candidate| {
            rules_d::files(listing(Some(candidate)))
                .iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
        };
        let rule = "allow perm=any all : all";
        assert_eq!(names(("00-cand.rules", rule))[0], "00-cand.rules");
        assert_eq!(
            names(("99-cand.rules", rule)).last().unwrap(),
            "99-cand.rules",
            "after 95-allow-open.rules, which is what makes it rule 15"
        );
    }

    #[test]
    fn the_measured_table_decides_every_row_as_fapolicyd_did() {
        let mut wrong = Vec::new();
        for (case, candidate, line, want) in TABLE {
            let got = check(*candidate, line);
            let (word, detail) = rendered(&got);
            if word != *want {
                wrong.push(format!("{case}: measured {want}, got {word} ({detail})"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} rows disagree with the daemon:\n{}",
            wrong.len(),
            TABLE.len(),
            wrong.join("\n")
        );
    }

    /// #120's window rows. The record is the open of `probe-grep` by the process that
    /// exec'd it, which the shipped ruleset ALLOWS at rule 14 -- so there is no denial and
    /// no verdict, and what the two rows measured is which `exe=` the daemon compared: the
    /// candidate naming `runuser` fired (`deny (rule=1)`) and the one naming the exec'd
    /// path did not (`allow (rule=15)`). That is K3 stated from the other side.
    #[test]
    fn the_window_rows_pin_which_exe_a_candidate_must_name() {
        let (open, _) = parsed(
            "rule=14 dec=allow perm=open auid=1000 pid=1107 exe=/usr/sbin/runuser \
             : path=/tmp/live/probe-grep ftype=application/x-executable trust=0",
        );
        let names_logged =
            Rule::new("deny_audit perm=open exe=/usr/sbin/runuser : path=/tmp/live/probe-grep");
        let names_executed =
            Rule::new("deny_audit perm=open exe=/tmp/live/probe-grep : path=/tmp/live/probe-grep");
        assert_eq!(matches(&names_logged, &open), Some(true));
        assert_eq!(matches(&names_executed, &open), Some(false));
    }

    #[test]
    fn a_stale_exe_window_is_unknown_and_never_a_guess() {
        // K3: where §6's rewrite fires, a rule has to name the exec'd image and the record
        // logs the pre-exec one, so no candidate can be matched against it.
        let (record, n) = parsed(EXEC);
        let compiled = compiled();
        let got = verdict(
            &record,
            n,
            Some(b"/tmp/live/probe-other"),
            Some(&compiled),
            Some(&host()),
            &rules_d::files(listing(Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep\n",
            )))),
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(rendered(&got).1.contains("probe-other"), "{got:?}");
    }

    #[test]
    fn a_record_with_no_rule_number_has_nothing_to_place_candidates_against() {
        for line in [
            "dec=deny_audit perm=execute : path=/tmp/live/probe-grep",
            "rule=0 dec=deny_audit perm=execute : path=/tmp/live/probe-grep",
        ] {
            let got = check(
                Some((
                    "00-cand.rules",
                    "allow perm=any all : path=/tmp/live/probe-grep",
                )),
                line,
            );
            assert_eq!(rendered(&got).0, "unknown", "{line}: {got:?}");
        }
    }

    #[test]
    fn no_rules_file_and_a_number_it_does_not_have_are_both_unknown() {
        let (record, n) = parsed(EXEC);
        let compiled = compiled();
        let proposed = rules_d::files(listing(None));
        let got = verdict(&record, n, None, None, Some(&host()), &proposed);
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        let (short, short_n) = parsed(
            "rule=99 dec=deny_audit perm=execute auid=1000 pid=1 exe=/usr/sbin/runuser \
             : path=/tmp/live/probe-grep ftype=application/x-executable trust=0",
        );
        let got = verdict(
            &short,
            short_n,
            None,
            Some(&compiled),
            Some(&host()),
            &proposed,
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
    }

    #[test]
    fn a_rules_d_that_no_longer_agrees_with_the_rules_file_is_unknown() {
        // The merged order in hand is not the one that produced this `rule=`, so nothing
        // can be placed against it -- the same drift `placement_note` refuses on.
        let (record, n) = parsed(EXEC);
        let compiled = compiled();
        let drifted = rules_d::files(vec![(
            "90-deny-execute.rules".to_string(),
            b"deny_audit perm=execute all : all\n".to_vec(),
        )]);
        let got = verdict(&record, n, None, Some(&compiled), Some(&drifted), &drifted);
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(rendered(&got).1.contains("fagenrules"), "{got:?}");
    }

    #[test]
    fn a_rule_the_proposal_removed_needs_the_whole_ruleset_evaluated() {
        // rule=13's own file is still there and no longer holds it: what now precedes it
        // is a question this record cannot answer (DESIGN.md §11).
        let (record, n) = parsed(EXEC);
        let compiled = compiled();
        let mut proposed = listing(None);
        for entry in &mut proposed {
            if entry.0 == "90-deny-execute.rules" {
                entry.1 = b"deny_audit perm=execute all : ftype=application/x-bad-elf\n".to_vec();
            }
        }
        let got = verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &rules_d::files(proposed),
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(rendered(&got).1.contains("no longer in"), "{got:?}");
    }

    #[test]
    fn a_candidate_this_tool_cannot_decide_stops_the_walk() {
        // `uid=` is real and unevaluable: the record carries no uid, and a later candidate
        // would only be reached if this one did not match.
        let got = check(
            Some((
                "00-cand.rules",
                "allow perm=any uid=0 : path=/tmp/live/probe-grep\n\
                 allow perm=any all : path=/tmp/live/probe-grep",
            )),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(rendered(&got).1.contains("uid=0"), "{got:?}");
    }

    #[test]
    fn a_broken_token_makes_its_rule_match_nothing_and_the_walk_go_on() {
        // K2 alone: every other attribute of this candidate matches the record, and the
        // rule still matches nothing because the daemon could not parse that token.
        let got = check(
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live/ ace/x")),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
    }

    #[test]
    fn a_record_missing_the_field_a_candidate_tests_is_unknown() {
        // A host `syslog_format` that names no `ftype` is not a truncated record; it is a
        // record that cannot answer the question this candidate asks.
        let got = check(
            Some((
                "00-cand.rules",
                "allow perm=execute all : ftype=application/x-executable",
            )),
            "rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/sbin/runuser \
             : path=/tmp/live/probe-grep",
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
    }

    #[test]
    fn a_value_the_daemon_could_not_supply_decides_nothing() {
        // §7's `path=??` and an `exe=?` the tool already renders as `all`.
        let (record, _) = parsed(
            "rule=13 dec=deny_audit perm=execute pid=1 exe=? : path=?? \
             ftype=application/x-executable trust=0",
        );
        assert_eq!(
            matches(
                &Rule::new("allow perm=execute exe=/usr/sbin/runuser : path=/tmp/live/probe-grep"),
                &record
            ),
            None
        );
    }

    #[test]
    fn an_escaped_path_is_unknown_against_a_dir_candidate() {
        // K2 measured the space in a rule and nothing measured the prefix test, so the one
        // shape where the record's bytes and a rule's bytes cannot be the same is refused.
        let got = check(
            Some(("00-cand.rules", "allow perm=any all : dir=/tmp/live/")),
            SPACE,
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
    }

    #[test]
    fn a_decision_that_is_neither_allow_nor_deny_is_unknown() {
        let got = check(
            Some((
                "00-cand.rules",
                "permit perm=any all : path=/tmp/live/probe-grep",
            )),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
    }

    #[test]
    fn a_perm_outside_the_measured_pair_is_unknown_on_either_side() {
        let (record, _) = parsed(EXEC);
        assert_eq!(perm_matches("any", &record), Some(true));
        assert_eq!(perm_matches("execute", &record), Some(true));
        assert_eq!(perm_matches("open", &record), Some(false));
        assert_eq!(perm_matches("all", &record), None, "not a perm value");
        let (odd, _) = parsed("rule=1 dec=deny_audit perm=whatever : path=/tmp/x");
        assert_eq!(perm_matches("any", &odd), None, "not a logged perm value");
    }

    #[test]
    fn the_report_is_one_line_per_denial_with_its_count() {
        let (exec, n) = parsed(EXEC);
        let rows = [
            (
                key(&exec, n),
                3,
                Verdict::Allowed("00-cand.rules: allow perm=execute all : path=x".into()),
            ),
            // A record with no `rule=` still names itself; the reason says the rest.
            (key(&exec, None), 1, Verdict::Unknown("no rule=".into())),
        ];
        let out = String::from_utf8(report(&rows)).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "allowed perm=execute exe=/usr/sbin/runuser path=/tmp/live/probe-grep rule=13 (3 denials)  00-cand.rules: allow perm=execute all : path=x"
        );
        assert_eq!(
            lines[1],
            "unknown perm=execute exe=/usr/sbin/runuser path=/tmp/live/probe-grep (1 denials)  no rule="
        );
        assert_eq!(lines.len(), 2);
    }

    /// The proposed `rules.d/` with one file's contents replaced: a candidate written
    /// into a file the host already has, rather than a new file of its own.
    fn replacing(name: &str, body: &str) -> Vec<rules_d::File> {
        let mut listing = listing(None);
        for entry in &mut listing {
            if entry.0 == name {
                entry.1 = body.as_bytes().to_vec();
            }
        }
        rules_d::files(listing)
    }

    #[test]
    fn a_candidate_inside_an_existing_file_is_placed_by_its_position_in_that_file() {
        // rule=8 is the SECOND rule of 41-shared-obj.rules, so where the candidate lands
        // in the merged order is that file's own offset plus its index inside it. The
        // candidate here is written between the two shipped rules.
        let (record, n) = parsed(LIB);
        let compiled = compiled();
        let got = verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &replacing(
                "41-shared-obj.rules",
                "allow perm=open all : ftype=application/x-sharedlib trust=1\n\
                 allow perm=open all : path=/tmp/live/probe-lib.so\n\
                 deny_audit perm=open all : ftype=application/x-sharedlib\n",
            ),
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
        assert!(rendered(&got).1.contains("41-shared-obj.rules"), "{got:?}");
    }

    #[test]
    fn a_candidate_repeating_rule_n_verbatim_is_still_a_candidate_before_it() {
        // D3 skips the host's rules 1..N-1 and NOT rule N itself: a copy of the rule that
        // denied, merged ahead of it, is a rule the daemon would reach first.
        let got = check(
            Some(("00-cand.rules", "deny_audit perm=execute all : all")),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
        assert!(
            rendered(&got).1.starts_with("00-cand.rules:"),
            "the candidate decides, not the shipped rule 13: {got:?}"
        );
    }

    #[test]
    fn a_broken_token_on_the_subject_side_matches_nothing_either() {
        // K2 again, on the other side of the colon: everything else about this candidate
        // matches the record.
        let got = check(
            Some((
                "00-cand.rules",
                "allow perm=execute all ace/x : path=/tmp/live/probe-grep",
            )),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
    }

    #[test]
    fn an_object_side_all_places_no_constraint_on_the_file() {
        let got = check(
            Some(("00-cand.rules", "allow perm=execute all : all")),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
    }

    #[test]
    fn a_control_byte_in_the_path_is_unknown_against_a_dir_candidate() {
        // `rocky8-base-edge-paths.log`'s `\012` path. The escaped byte is not a space, so
        // it is the control-byte half of the refusal that has to catch it.
        let got = check(
            Some(("00-cand.rules", "allow perm=execute all : dir=/tmp/edge/")),
            "rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
             : path=/tmp/edge/nl\\012line ftype=application/x-executable trust=0",
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
    }

    #[test]
    fn a_path_with_a_newline_in_it_is_still_one_line() {
        // From `rocky8-base-edge-paths.log`, where the daemon writes `\012`. One denial is
        // one line, or the next reader counts denials that never happened.
        let (record, n) = parsed(
            "rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
             : path=/tmp/edge/nl\\012line ftype=application/x-executable trust=0",
        );
        let rows = [(
            key(&record, n),
            1,
            Verdict::Denied("nothing matches".into()),
        )];
        let out = String::from_utf8(report(&rows)).unwrap();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("path=/tmp/edge/nl\\012line"), "{out}");
    }
}
