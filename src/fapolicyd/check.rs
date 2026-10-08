//! `check`: would a proposed `rules.d/` have allowed these denials? DESIGN.md §7, #121.
//!
//! Pure like the rest of `fapolicyd/`: `main.rs` reads the candidate path and hands the
//! merged listing here. Every branch below is measured. The 48-row table in #120 is this
//! module's unit test, and that issue's corrections K1, K2 and K3 are cited where they
//! changed the code.
//!
//! One rule governs the whole module: **a wrong `allowed` is worse than an `unknown`**.
//! What the daemon evaluates and a log record cannot answer -- `pattern=`, a `uid=`, a
//! `dir=` keyword, a rule the operator moved -- returns `Unknown` naming the reason. A
//! `%set` reference is the one of those #139 closed, by membership against the definitions
//! the merged listing carries. Closing the rest means evaluating the whole ruleset against
//! a reconstructed event, which is parked (DESIGN.md §11).

use super::json;
use super::model::Record;
use super::rules::{Attr, Rule, Set};
use super::rules_d;
use serde::Serialize;
use std::io::Write;

/// What the candidates would do with one denial. Each arm carries the line's last
/// column: the candidate as `file: rule text`, or the reason there is no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An `allow*` candidate matches before the rule that denied.
    Allowed(Vec<u8>),
    /// A `deny*` candidate matches first, or nothing the operator added matches and the
    /// rule that denied denies again.
    Denied(Vec<u8>),
    /// Bytes like the other two, because a reason can quote a rule's text (`rules.rs`).
    Unknown(Vec<u8>),
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
///
/// `changed` is `changed_sets`' answer for both of them: the names whose proposed `%set`
/// definition is not the one the daemon loaded, decided in `main` where the two files are
/// read. A `%set` is in no rule's text and in no rule number, so an edited one is invisible
/// to every comparison of rule text here and changes what the rules naming it match.
#[derive(Clone, Copy)]
pub enum Proposal<'a> {
    /// `check <PATH>`: the host's `rules.d/` with the candidates merged in, placed
    /// against that same directory as fagenrules last left it.
    Merged {
        files: &'a [rules_d::File],
        changed: &'a [String],
    },
    /// `check` with no `PATH`: the host's `rules.d/` as it is on disk now, placed against
    /// `compiled.rules`. The two disagreeing is the edit being asked about and not drift,
    /// so there is no host listing to locate rule `N` in.
    OnDisk { changed: &'a [String] },
}

/// The names whose proposed `%set` definition is not the one the daemon loaded (#139).
/// `main` calls it where the two files are read, because nothing under `fapolicyd/` reads
/// one.
///
/// Per name, and not one bool for the whole directory: a candidate file that only defines a
/// new set of its own changes nothing about the rules naming `%languages`, and turning
/// every one of those into an `unknown` would throw away the verdicts D3 proves. A name
/// defined on one side only is changed too -- adding or removing a definition changes what
/// the rules naming it match -- and the definitions are compared as bytes, because a set
/// holds paths (§4, #158).
pub fn changed_sets(proposed: &[rules_d::File], loaded: &[Set]) -> Vec<String> {
    let mine: Vec<&Set> = proposed.iter().flat_map(|f| &f.sets).collect();
    let theirs: Vec<&Set> = loaded.iter().collect();
    // Every definition of that name on that side, in order: a name defined twice is a
    // ruleset the daemon refuses (`refused`), and two definitions of it are still not one.
    let defined = |sets: &[&Set], name: &str| -> Vec<Vec<u8>> {
        sets.iter()
            .filter(|s| s.name == name)
            .map(|s| s.text.clone())
            .collect()
    };
    let mut changed: Vec<String> = Vec::new();
    for set in mine.iter().chain(&theirs) {
        if !changed.contains(&set.name) && defined(&mine, &set.name) != defined(&theirs, &set.name)
        {
            changed.push(set.name.clone());
        }
    }
    changed
}

/// Why the daemon will refuse to load this merged listing, or `None` for one it will load.
///
/// S1 (#137) measured all three cases on 8, 9 and 10: a `%set` used before its definition,
/// a name defined twice, and an undefined set each fail the reload, and the daemon then
/// discards the WHOLE ruleset and goes on enforcing the one it has. `fagenrules` exits 0
/// and `--reload-rules` exits 0, so neither warns. There is no "what that rule then
/// matches" to report, which is why D20 answers `unknown` on every row naming this reason
/// rather than adding a verdict or an exit code.
///
/// A name defined in the candidates and again in the host `rules.d/` is one of the three:
/// the merged listing holds both definitions, so it is a duplicate and not a fallback.
///
/// Scoped to what the reload refuses and no further: a name defined twice refuses whether
/// or not a rule names it, while an undefined or a late definition is only reachable
/// through a rule that names it -- so a set defined once and never used is not a refusal
/// and is not reported.
pub fn refused(files: &[rules_d::File]) -> Option<String> {
    let refuses = "; the daemon fails the reload and keeps the ruleset it has (#137), so \
                   nothing here can be checked against this one";
    // Every definition with its place in the merged order: the rules of the files before
    // it, plus the rules of its own file written above it.
    let mut defined: Vec<(&Set, &str, usize)> = Vec::new();
    let mut merged = 0usize;
    for file in files {
        for set in &file.sets {
            defined.push((set, file.name.as_str(), merged + set.rules_before));
        }
        merged += file.rules.len();
    }
    for (i, (set, file, _)) in defined.iter().enumerate() {
        if let Some((_, first, _)) = defined[..i].iter().find(|(d, _, _)| d.name == set.name) {
            return Some(format!(
                "{first} and {file} both define {}{refuses}",
                set.name
            ));
        }
    }
    for (at, (file, rule)) in flat(files).enumerate() {
        for name in references(rule) {
            let Some((_, defines, position)) =
                defined.iter().find(|(d, _, _)| d.name.as_bytes() == name)
            else {
                return Some(format!(
                    "{}: {} names {}, which no file defines{refuses}",
                    file.name,
                    String::from_utf8_lossy(&rule.text),
                    String::from_utf8_lossy(name)
                ));
            };
            // The definition has to sort before the rule: `position` counts the rules
            // ahead of it and `at` the rules ahead of this one, so equal is the definition
            // written immediately above the rule that uses it.
            if *position > at {
                return Some(format!(
                    "{}: {} names {} before its definition in {defines}{refuses}",
                    file.name,
                    String::from_utf8_lossy(&rule.text),
                    String::from_utf8_lossy(name)
                ));
            }
        }
    }
    None
}

/// Every `%set` a rule names, on either side and whatever the attribute. Over the tokens
/// and not over `attrs()`, which keeps only the shapes the matcher can use: the daemon
/// resolves a reference wherever it is written, so `uid=%who` is a use too.
fn references(rule: &Rule) -> impl Iterator<Item = &[u8]> {
    rule.subject
        .iter()
        .chain(rule.object.iter().flatten())
        .filter_map(|token| {
            let at = token.iter().position(|&b| b == b'=')?;
            Some(&token[at + 1..])
        })
        .flat_map(|value| value.split(|&b| b == b','))
        .filter(|member| member.starts_with(b"%"))
}

/// The verdict for one denial: `n` is its `rule=`, `stale` what §6's rewrite would scope
/// a rule to, `compiled` the host's own rules, `host` the `rules.d/` they were generated
/// from -- `None` in `Proposal::OnDisk`, where the proposal is that directory itself --
/// `changed` the `%set` names whose proposed definition is not the loaded one, and
/// `proposed` the merged listing to walk.
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
    changed: &[String],
    proposed: &[rules_d::File],
) -> Verdict {
    // D20, ahead of every arm below including the ones about the record: a ruleset the
    // daemon refuses to load is not one any record can be placed against, and the merge
    // those arms reason about never happens. `analyze` says the same thing once for the run.
    if let Some(why) = refused(proposed) {
        return Verdict::Unknown(why.into());
    }
    // K3: #120 measured the daemon comparing a candidate's `exe=` against the value the
    // record logs, verbatim, on all three releases -- so the one case the comparison
    // cannot be trusted is where this tool's own §6 rewrite fires, because there the
    // logged value and the value a rule would have to name are different images.
    if let Some(execed) = stale {
        return Verdict::Unknown(
            format!(
                "exe= is stale (§6): a rule for this record has to name {}, not the logged \
                 exe=, and no candidate can be matched against a value the log does not carry",
                shown(execed)
            )
            .into(),
        );
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
        return Verdict::Unknown(
            format!("rule={n} is past the end of the rules file: it is not this log's").into(),
        );
    };
    // Drift: `rules.d/` no longer agrees with `compiled.rules`, so the merged order in
    // hand is not the one that produced this `rule=` and nothing can be placed against it.
    // `Proposal::OnDisk` has no host listing, because there that disagreement is the
    // proposal itself (#158) and rule N is found by its text below.
    let from = match host {
        Some(host) => match rules_d::locate(host, compiled, n).and_then(|i| host.get(i)) {
            Some(from) => Some(from),
            None => {
                return Verdict::Unknown(
                    format!(
                        "rule={n} is not in the host rules.d/ (not read, or changed since \
                         fagenrules ran); run fagenrules, recapture, rerun"
                    )
                    .into(),
                );
            }
        },
        None => None,
    };
    // K1: `perm=` is not optional. `allow all : path=...` fails the reload with `'=' is
    // missing for field :` on 8, 9 and 10, the daemon discards the WHOLE ruleset and goes
    // on answering `rule=0 dec=no-opinion`, so one such rule decides every denial in the
    // run and not just the ones it was written for.
    if let Some((file, text)) = missing_perm(proposed, compiled) {
        return Verdict::Unknown(quote(
            &format!("{file}: "),
            text,
            " has no perm=, which fails the reload and discards the whole ruleset (#120 K1); \
             nothing can be checked against these candidates",
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
        return Verdict::Unknown(quote(
            &format!("rule={n} ("),
            &target.text,
            &format!(
                ") is no longer in {}: which rules now precede it cannot be decided from \
                 this record alone",
                from.map_or("the rules.d/ on disk", |f| f.name.as_str())
            ),
        ));
    };

    let defined: Vec<&Set> = proposed.iter().flat_map(|f| &f.sets).collect();
    for (file, rule) in flat(proposed).take(limit) {
        // D3 again: this rule is one of the host's own, from before N, and the daemon
        // walked past it to reach N. That proof is about the rule's text and holds only
        // while the sets its text names hold: an edited `%languages` makes an untouched
        // `ftype=%languages` deny a different rule, reached before N and matching what it
        // did not match when the record was written. So a rule naming a set whose
        // definition changed is evaluated against the PROPOSED definition rather than
        // skipped, and a rule naming only unchanged sets keeps its skip (#139).
        if !names_changed_set(rule, changed)
            && compiled
                .iter()
                .take(n - 1)
                .any(|before| before.text == rule.text)
        {
            continue;
        }
        let named = quote(&format!("{}: ", file.name), &rule.text, "");
        match matches(rule, record, &defined) {
            Some(false) => {}
            // Whatever a later candidate would say, the daemon might never reach it.
            None => {
                return Verdict::Unknown(quote(
                    "",
                    &named,
                    &format!(
                        " cannot be decided from this record, and it is reached before rule={n}"
                    ),
                ));
            }
            Some(true) if rule.decision.starts_with(b"allow") => return Verdict::Allowed(named),
            Some(true) if rule.decision.starts_with(b"deny") => return Verdict::Denied(named),
            // Neither word: fagenrules would merge it and the daemon would refuse it.
            Some(true) => {
                return Verdict::Unknown(quote("", &named, " is neither an allow nor a deny"));
            }
        }
    }
    // "Denies it again" is D3's proof read the other way: the daemon matched rule N when
    // the record was written. It holds only while the sets N names hold, like the skip
    // above, so an N naming a changed set is asked again against the proposed definition.
    // When it no longer matches, the walk would go on past N, which is §11's parked work.
    if names_changed_set(target, changed) && matches(target, record, &defined) != Some(true) {
        return Verdict::Unknown(quote(
            &format!("rule={n} ("),
            &target.text,
            ") names a %set whose definition changed and is no longer known to match this \
             record: what the rules after it decide cannot be said from this record alone",
        ));
    }
    Verdict::Denied(quote(
        &format!("no candidate before rule={n} matches; "),
        &target.text,
        " denies it again",
    ))
}

/// A verdict's detail around a rule's text, which stays bytes so a document can carry it
/// with its `detail_hex` (§9.1) and the report decodes it once, at the edge.
fn quote(before: &str, text: &[u8], after: &str) -> Vec<u8> {
    [before.as_bytes(), text, after.as_bytes()].concat()
}

/// D-d's report, in first-seen order: one line per denial, the verdict first so the file
/// is greppable by it, then the record's own fields, the count, and the candidate or the
/// reason.
pub fn report(rows: &[(Key, usize, Verdict)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, count, verdict) in rows {
        line(&mut out, k, Some(*count), verdict);
    }
    out
}

/// `report`'s lines as `--follow` writes them, one per key when it is first seen: the
/// count is not known yet, so its column is dropped and the end of the run has it.
pub fn live(rows: &[(Key, Verdict)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, verdict) in rows {
        line(&mut out, k, None, verdict);
    }
    out
}

fn line(out: &mut Vec<u8>, k: &Key, count: Option<usize>, verdict: &Verdict) {
    let (word, detail) = rendered(verdict);
    let detail = lossy(detail);
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
    let _ = match count {
        Some(count) => writeln!(out, "{word:<7} {fields}({count} denials)  {detail}"),
        None => writeln!(out, "{word:<7} {fields} {detail}"),
    };
}

/// One report line as a document carries it (#146, DESIGN.md §9.1). Built here rather than in
/// `json.rs` because `Key`'s fields are this module's, and the verdict is split into the
/// word the text report greps by and the detail it ends with, so a reader filtering on
/// `verdict` never parses the line.
///
/// `ftype` and `trust` are in because two entries can differ only in them -- the same
/// reason they are in the key. A `*_hex` sibling is the one conditional field in the
/// document (§9.1): it appears only when the value was not UTF-8.
#[derive(Serialize)]
pub struct Entry {
    verdict: &'static str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail_hex: Option<String>,
    denials: usize,
    perm: Option<String>,
    exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_hex: Option<String>,
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_hex: Option<String>,
    ftype: Option<String>,
    trust: Option<String>,
    rule: Option<usize>,
}

/// `report`'s rows as entries, same rows and same order.
pub fn entries(rows: &[(Key, usize, Verdict)]) -> Vec<Entry> {
    rows.iter()
        .map(|(k, count, verdict)| {
            let (word, detail) = rendered(verdict);
            // The detail can quote a rule's text, which is bytes like a record's value.
            let (detail, detail_hex) = json::lossy_hex(detail);
            let (exe, exe_hex) = with_hex(&k.exe);
            let (path, path_hex) = with_hex(&k.path);
            Entry {
                verdict: word,
                detail,
                detail_hex,
                denials: *count,
                // `perm` and `trust` are the daemon's own vocabulary and `ftype` is a
                // MIME type. A byte that is not UTF-8 in one of them is corruption and
                // not a name anyone has to recover, so none of them earns a hex sibling.
                perm: k.perm.as_deref().map(lossy),
                exe,
                exe_hex,
                path,
                path_hex,
                ftype: k.ftype.as_deref().map(lossy),
                trust: k.trust.as_deref().map(lossy),
                rule: k.rule,
            }
        })
        .collect()
}

/// A field the record may not have carried, as text plus §9.1's hex sibling.
fn with_hex(value: &Option<Vec<u8>>) -> (Option<String>, Option<String>) {
    match value {
        Some(v) => {
            let (text, hex) = json::lossy_hex(v);
            (Some(text), hex)
        }
        None => (None, None),
    }
}

fn lossy(value: &[u8]) -> String {
    json::lossy_hex(value).0
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
fn rendered(verdict: &Verdict) -> (&'static str, &[u8]) {
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
fn position(files: &[rules_d::File], name: &str, text: &[u8]) -> Option<usize> {
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
) -> Option<(&'a str, &'a [u8])> {
    flat(proposed)
        .filter(|(_, r)| !compiled.iter().any(|host| host.text == r.text))
        .find(|(_, r)| !r.attrs().0.iter().any(|a| matches!(a, Attr::Perm(_))))
        .map(|(f, r)| (f.name.as_str(), r.text.as_slice()))
}

/// Does this rule name a `%set` whose proposed definition is not the one the daemon loaded?
/// Then D3's proof -- the daemon walked past this rule -- was about a different definition.
fn names_changed_set(rule: &Rule, changed: &[String]) -> bool {
    references(rule).any(|name| changed.iter().any(|c| c.as_bytes() == name))
}

/// Does this rule fire on this record? `Some(true)` yes, `Some(false)` no, `None` no
/// answer this tool may give. `defined` is every `%set` definition of the merged listing,
/// which `refused` has already proved each reference resolves into.
///
/// A rule is a conjunction of its attributes, so one that does not match settles the rule
/// whatever the others are -- which is why `Some(false)` wins over `None` here, and why a
/// rule broken by K2's missing `=` matches nothing while still occupying its slot.
fn matches(rule: &Rule, record: &Record, defined: &[&Set]) -> Option<bool> {
    let (subject, object) = rule.attrs();
    let mut undecided = false;
    for attr in subject
        .iter()
        .map(|a| subject_matches(a, record, defined))
        .chain(object.iter().map(|a| object_matches(a, record, defined)))
    {
        match attr {
            Some(false) => return Some(false),
            Some(true) => {}
            None => undecided = true,
        }
    }
    (!undecided).then_some(true)
}

fn subject_matches(attr: &Attr, record: &Record, defined: &[&Set]) -> Option<bool> {
    let exe = || field(record.subject_get(b"exe"));
    match attr {
        Attr::All => Some(true),
        Attr::Perm(p) => perm_matches(p, record),
        // K3: verbatim against the value the record logs.
        Attr::Exe(e) => Some(exe()? == *e),
        // #120 Q4: a plain byte prefix with no slash logic, `strncmp` and nothing more --
        // subject `dir=/usr/sbi` matched `exe=/usr/sbin/runuser`.
        Attr::Dir(d) => prefix(exe()?, d),
        Attr::Members(field, members) => {
            any_member(field, members, record, defined, subject_matches)
        }
        Attr::NeverMatches => Some(false),
        // Subject `trust=` is #120's H3, not measured. `uid=`, `pattern=`, `comm=` and an
        // object attribute written on this side are outside D4 altogether.
        _ => None,
    }
}

fn object_matches(attr: &Attr, record: &Record, defined: &[&Set]) -> Option<bool> {
    let get = |name: &[u8]| field(record.object_get(name));
    match attr {
        Attr::All => Some(true),
        Attr::Path(p) => Some(get(b"path")? == *p),
        // #120 Q4 again: `dir=/tmp/live` allowed `/tmp/live2/probe-grep`.
        Attr::Dir(d) => prefix(get(b"path")?, d),
        Attr::Ftype(f) => Some(get(b"ftype")? == *f),
        // #120 Q5: object `trust=` compares against the logged value. Subject trust takes
        // a different path with no sentinel (DESIGN.md §7) and is never evaluated.
        Attr::Trust(t) => Some(get(b"trust")? == *t),
        Attr::Members(field, members) => {
            any_member(field, members, record, defined, object_matches)
        }
        Attr::NeverMatches => Some(false),
        _ => None,
    }
}

/// A value's members, any one of which matching settles the attribute (#139): that is what
/// `ftype=%languages` means for its 24 media types, and what S1 measured for a literal
/// beside a `dir=` keyword.
///
/// Each member is compared by reading it as this attribute's own value and handing it back
/// to `eval`, so `dir=` stays a prefix and `ftype=` an equality in the one place each is
/// written. A member this tool cannot decide makes the whole value `None` and NEVER a miss:
/// `dir=execdirs` matches the compiled list on 1.4.5 and nothing on 1.3.2 and a log carries
/// no daemon version (D19), so beside a literal a hit is a match and a miss is still an
/// `unknown`. A member that is itself a set reference is a nesting nothing measured, and
/// re-reading it here would be the second expansion this function does not do.
fn any_member(
    field: &[u8],
    members: &[Vec<u8>],
    record: &Record,
    defined: &[&Set],
    eval: fn(&Attr, &Record, &[&Set]) -> Option<bool>,
) -> Option<bool> {
    let mut undecided = false;
    for member in members.iter().flat_map(|m| expand(m, defined)) {
        let decided = member.and_then(|m| {
            let attr = Attr::new(&[field, &b"="[..], &m].concat());
            (!matches!(attr, Attr::Members(..))).then(|| eval(&attr, record, defined))?
        });
        match decided {
            Some(true) => return Some(true),
            Some(false) => {}
            None => undecided = true,
        }
    }
    (!undecided).then_some(false)
}

/// One member of a value, with a `%set` reference replaced by the definition's own members.
///
/// `None` is a member this tool cannot compare at all: a definition that is a bare `%name`
/// with no `=`, which defines nothing. A member is bytes like the rest of a rule (§4), so
/// one outside UTF-8 is compared with the record's bytes like any other. An unresolved
/// name cannot arrive here behind `refused`, which answers for the whole run first.
fn expand(member: &[u8], defined: &[&Set]) -> Vec<Option<Vec<u8>>> {
    if !member.starts_with(b"%") {
        return vec![Some(member.to_vec())];
    }
    let Some(set) = defined.iter().find(|s| s.name.as_bytes() == member) else {
        return vec![None];
    };
    if set.members.is_empty() {
        return vec![None];
    }
    set.members.iter().cloned().map(Some).collect()
}

/// #120 Q2. `any` matches both perms and `open`/`execute` match the equal value; any
/// other value on either side is outside the measured set.
fn perm_matches(rule_perm: &[u8], record: &Record) -> Option<bool> {
    let logged = field(record.subject_get(b"perm"))?;
    if !matches!(logged.as_slice(), b"open" | b"execute") {
        return None;
    }
    match rule_perm {
        b"any" => Some(true),
        b"open" | b"execute" => Some(logged == rule_perm),
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
fn prefix(value: Vec<u8>, dir: &[u8]) -> Option<bool> {
    let escaped = value
        .iter()
        .any(|b| *b <= b' ' || b"\"'`$\\!()|".contains(b));
    (!escaped).then(|| value.starts_with(dir))
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
    fn parsed(line: impl AsRef<[u8]>) -> (Record, Option<usize>) {
        let record = parse::parse(line.as_ref());
        let n = record
            .subject_get(b"rule")
            .and_then(|v| std::str::from_utf8(&v).ok()?.parse::<usize>().ok())
            .filter(|n| *n != 0);
        (record, n)
    }

    /// What the daemon loaded beside its rules: the `%set` definitions of the same bytes
    /// `compiled` parses, so every row below goes through the real per-set gate.
    fn loaded_sets() -> Vec<Set> {
        rules::sets(
            HOST.iter()
                .map(|(_, body)| *body)
                .collect::<String>()
                .as_bytes(),
        )
    }

    /// A verdict's detail as the report writes it.
    fn detail(verdict: &Verdict) -> String {
        lossy(rendered(verdict).1)
    }

    /// The verdict for one row: no stale window, the shipped host, the candidate merged.
    fn check(candidate: Option<(&str, &str)>, line: &str) -> Verdict {
        let (record, n) = parsed(line);
        let compiled = compiled();
        let proposed = rules_d::files(listing(candidate));
        verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &changed_sets(&proposed, &loaded_sets()),
            &proposed,
        )
    }

    #[test]
    fn the_host_ruleset_is_the_shipped_fourteen_rules() {
        let compiled = compiled();
        assert_eq!(compiled.len(), 14, "the daemon logged `Loaded 14 rules`");
        assert_eq!(compiled[4].text, b"deny_audit perm=any pattern=ld_so : all");
        assert_eq!(
            compiled[10].text,
            b"deny_audit perm=any all : ftype=%languages"
        );
        assert_eq!(compiled[12].text, b"deny_audit perm=execute all : all");
        assert_eq!(compiled[13].text, b"allow perm=open all : all");
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
            let (word, detail) = (rendered(&got).0, detail(&got));
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
            Rule::new(b"deny_audit perm=open exe=/usr/sbin/runuser : path=/tmp/live/probe-grep");
        let names_executed =
            Rule::new(b"deny_audit perm=open exe=/tmp/live/probe-grep : path=/tmp/live/probe-grep");
        assert_eq!(matches(&names_logged, &open, &[]), Some(true));
        assert_eq!(matches(&names_executed, &open, &[]), Some(false));
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
            &[],
            &rules_d::files(listing(Some((
                "00-cand.rules",
                "allow perm=execute all : path=/tmp/live/probe-grep\n",
            )))),
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(detail(&got).contains("probe-other"), "{got:?}");
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
        let got = verdict(&record, n, None, None, Some(&host()), &[], &proposed);
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
            &[],
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
        let got = verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&drifted),
            &[],
            &drifted,
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(detail(&got).contains("fagenrules"), "{got:?}");
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
            &[],
            &rules_d::files(proposed),
        );
        assert_eq!(rendered(&got).0, "unknown", "{got:?}");
        assert!(detail(&got).contains("no longer in"), "{got:?}");
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
        assert!(detail(&got).contains("uid=0"), "{got:?}");
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
                &Rule::new(b"allow perm=execute exe=/usr/sbin/runuser : path=/tmp/live/probe-grep"),
                &record,
                &[]
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
        assert_eq!(perm_matches(b"any", &record), Some(true));
        assert_eq!(perm_matches(b"execute", &record), Some(true));
        assert_eq!(perm_matches(b"open", &record), Some(false));
        assert_eq!(perm_matches(b"all", &record), None, "not a perm value");
        let (odd, _) = parsed("rule=1 dec=deny_audit perm=whatever : path=/tmp/x");
        assert_eq!(perm_matches(b"any", &odd), None, "not a logged perm value");
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

    #[test]
    fn a_live_line_is_the_report_line_without_its_count() {
        let (exec, n) = parsed(EXEC);
        let rows = [
            (
                key(&exec, n),
                Verdict::Allowed("00-cand.rules: allow perm=execute all : path=x".into()),
            ),
            (key(&exec, None), Verdict::Unknown("no rule=".into())),
        ];
        let out = String::from_utf8(live(&rows)).unwrap();
        assert_eq!(
            out,
            "allowed perm=execute exe=/usr/sbin/runuser path=/tmp/live/probe-grep rule=13  00-cand.rules: allow perm=execute all : path=x\n\
             unknown perm=execute exe=/usr/sbin/runuser path=/tmp/live/probe-grep  no rule=\n"
        );
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
            &[],
            &replacing(
                "41-shared-obj.rules",
                "allow perm=open all : ftype=application/x-sharedlib trust=1\n\
                 allow perm=open all : path=/tmp/live/probe-lib.so\n\
                 deny_audit perm=open all : ftype=application/x-sharedlib\n",
            ),
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
        assert!(detail(&got).contains("41-shared-obj.rules"), "{got:?}");
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
            detail(&got).starts_with("00-cand.rules:"),
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

    /// A path whose parent shares a prefix with a second directory: `dir=/opt/app/` must
    /// not cover it, which is what keeps a `%set` member on `dir=` a prefix test and not a
    /// path-component one (#120 Q4).
    const UNDER_APP2: &str = "rule=13 dec=deny_audit perm=execute auid=1000 pid=1108 \
exe=/usr/sbin/runuser : path=/opt/app2/x ftype=application/x-executable trust=0";
    /// The #139 comment's own record: the execute of a trusted file that rule 13 denied.
    const TRUSTED_LS: &str = "rule=13 dec=deny_audit perm=execute auid=1000 pid=1109 \
exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls ftype=application/x-executable trust=1";

    /// The shipped `%languages` with `application/x-executable` prepended: the one edit both
    /// #139 reproductions turn on, and the one the daemon's own walk never saw.
    fn edited_languages() -> String {
        HOST[0]
            .1
            .replace("%languages=", "%languages=application/x-executable,")
    }

    /// #139: a `%set` on each of the five attributes the matcher can compare, resolved by
    /// membership -- any member matching settles it, and each member is compared the way
    /// that attribute compares one literal. The definition is the candidate file's first
    /// line, so it sorts before the rule naming it.
    #[test]
    fn a_set_on_each_measured_attribute_is_matched_by_membership() {
        for (attr, members, record, want) in [
            ("exe=%s", "/usr/sbin/runuser,/usr/bin/cat", EXEC, "allowed"),
            ("exe=%s", "/usr/bin/cat", EXEC, "denied"),
            ("path=%s", "/tmp/live/probe-grep", EXEC, "allowed"),
            ("path=%s", "/tmp/live/probe-other", EXEC, "denied"),
            ("dir=%s", "/tmp/live/", EXEC, "allowed"),
            ("dir=%s", "/tmp/live2/", EXEC, "denied"),
            ("dir=%s", "/opt/app2/", UNDER_APP2, "allowed"),
            ("dir=%s", "/opt/app/", UNDER_APP2, "denied"),
            ("ftype=%s", "application/x-executable", EXEC, "allowed"),
            ("ftype=%s", "text/x-python", EXEC, "denied"),
            ("trust=%s", "0", EXEC, "allowed"),
            ("trust=%s", "1", EXEC, "denied"),
        ] {
            // `exe=` is the subject's; the other four are the object's, and the side is
            // what decides which comparison the member goes through.
            let rule = match attr.starts_with("exe=") {
                true => format!("allow perm=execute {attr} : all"),
                false => format!("allow perm=execute all : {attr}"),
            };
            let body = format!("%s={members}\n{rule}");
            let got = check(Some(("00-cand.rules", &body)), record);
            assert_eq!(rendered(&got).0, want, "{attr} = {members}: {got:?}");
        }
    }

    /// D19: a `dir=` keyword is decidable only on a known daemon version -- S1 measured
    /// `execdirs` and `systemdirs` matching the compiled list on 1.4.5 and nothing on
    /// 1.3.2, and a log carries no version. Beside a literal, a literal hit is a match and
    /// a literal miss is still `unknown`, never a miss, because the keyword might have
    /// matched. A set whose members include one reads the same way.
    #[test]
    fn a_dir_keyword_stays_unknown_and_a_literal_beside_it_is_resolved() {
        for (body, want) in [
            ("allow perm=execute all : dir=execdirs", "unknown"),
            ("allow perm=execute all : dir=systemdirs", "unknown"),
            ("allow perm=execute all : dir=untrusted", "unknown"),
            (
                "allow perm=execute all : dir=execdirs,/tmp/live/",
                "allowed",
            ),
            ("allow perm=execute all : dir=execdirs,/opt/", "unknown"),
            (
                "%d=execdirs,/tmp/live/\nallow perm=execute all : dir=%d",
                "allowed",
            ),
            (
                "%d=execdirs,/opt/\nallow perm=execute all : dir=%d",
                "unknown",
            ),
        ] {
            let got = check(Some(("00-cand.rules", body)), EXEC);
            assert_eq!(rendered(&got).0, want, "{body}: {got:?}");
        }
    }

    /// D20: S1 measured that a set used before its definition, a name defined twice and an
    /// undefined set each fail the reload on 8, 9 and 10, and the daemon then keeps the
    /// ruleset it has. A name defined once in the candidates and once in the host
    /// `rules.d/` is a duplicate and not a fallback. Every row says so, naming the set and
    /// the case; `analyze` says it once more for the run.
    #[test]
    fn a_ruleset_the_daemon_refuses_is_unknown_on_every_row_with_the_reason() {
        for (case, body, reason) in [
            (
                "undefined",
                "allow perm=execute all : ftype=%nosuch",
                "%nosuch, which no file defines",
            ),
            (
                "used before its definition",
                "allow perm=execute all : ftype=%mine\n%mine=application/x-executable",
                "names %mine before its definition in 00-cand.rules",
            ),
            (
                "defined twice in the candidates",
                "%mine=a\n%mine=b",
                "00-cand.rules and 00-cand.rules both define %mine",
            ),
            (
                "defined again over the host's",
                "%languages=application/x-executable",
                "00-cand.rules and 10-languages.rules both define %languages",
            ),
        ] {
            let got = check(Some(("00-cand.rules", body)), EXEC);
            assert_eq!(rendered(&got).0, "unknown", "{case}: {got:?}");
            assert!(detail(&got).contains(reason), "{case}: {got:?}");
            assert!(detail(&got).contains("reload"), "{case}: {got:?}");
        }
    }

    /// The third of those cases is the only one that does not need a rule naming the set:
    /// a duplicate fails the reload on its own, while an undefined name and a late
    /// definition are reachable only through a rule. So a set defined once and never used
    /// is not a refusal, and the verdicts around it stand.
    #[test]
    fn a_set_defined_once_and_never_used_is_not_a_refusal() {
        let got = check(
            Some((
                "00-cand.rules",
                "%mine=/tmp/live/\nallow perm=execute all : path=/tmp/live/probe-grep",
            )),
            EXEC,
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
    }

    /// The definition has to sort before the rule that names it, in the merged order and
    /// not only within one file. One line above it is enough; one line below it is the
    /// reload S1 measured failing.
    #[test]
    fn a_definition_sorts_before_the_rule_naming_it_or_the_reload_fails() {
        let one = |body: &str| {
            rules_d::files(vec![(
                "00-cand.rules".to_string(),
                body.as_bytes().to_vec(),
            )])
        };
        assert!(refused(&one("%d=/tmp/\nallow perm=any all : dir=%d\n")).is_none());
        assert!(
            refused(&one("allow perm=any all : dir=%d\n%d=/tmp/\n"))
                .is_some_and(|why| why.contains("before its definition")),
            "the line below it is not before it"
        );
        let two = |first: &[u8], second: &[u8]| {
            rules_d::files(vec![
                ("00-cand.rules".to_string(), first.to_vec()),
                ("01-cand.rules".to_string(), second.to_vec()),
            ])
        };
        assert!(refused(&two(b"%d=/tmp/\n", b"allow perm=any all : dir=%d\n")).is_none());
        assert!(refused(&two(b"allow perm=any all : dir=%d\n", b"%d=/tmp/\n")).is_some());
        assert!(
            refused(&host()).is_none(),
            "the shipped ruleset is one the daemon loads"
        );
    }

    /// The host's own `10-languages.rules` sorts first, so a candidate written after it
    /// has the definition in hand and is decided by membership like any other value.
    #[test]
    fn a_set_the_host_alone_defines_resolves_for_a_candidate_sorted_after_it() {
        let cand = Some(("11-cand.rules", "allow perm=open all : ftype=%languages"));
        let got = check(cand, PY);
        assert_eq!(
            rendered(&got).0,
            "allowed",
            "text/x-python is a member: {got:?}"
        );
        let got = check(cand, LIB);
        assert_eq!(
            rendered(&got).0,
            "denied",
            "application/x-sharedlib is not: {got:?}"
        );
    }

    /// A set inside a set, and a bare `%name` line, which defines no members at all:
    /// neither is measured and neither is a miss.
    #[test]
    fn a_member_this_tool_cannot_read_is_undecided_and_never_a_miss() {
        for body in [
            &b"%d=%other\n%other=/tmp/live/\nallow perm=execute all : dir=%d\n"[..],
            b"%d\nallow perm=execute all : dir=%d\n",
        ] {
            let mut named = listing(None);
            named.push(("00-cand.rules".to_string(), body.to_vec()));
            let proposed = rules_d::files(named);
            let (record, n) = parsed(EXEC);
            let compiled = compiled();
            let got = verdict(
                &record,
                n,
                None,
                Some(&compiled),
                Some(&host()),
                &changed_sets(&proposed, &loaded_sets()),
                &proposed,
            );
            assert_eq!(rendered(&got).0, "unknown", "{body:?}: {got:?}");
        }
    }

    /// The candidate file `00-cand.rules`, holding bytes no `&str` can, merged into the
    /// shipped host and checked against one record.
    fn check_bytes(candidate: &[u8], line: &[u8]) -> Verdict {
        let mut named = listing(None);
        named.push(("00-cand.rules".to_string(), candidate.to_vec()));
        let proposed = rules_d::files(named);
        let (record, n) = parsed(line);
        let compiled = compiled();
        verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &changed_sets(&proposed, &loaded_sets()),
            &proposed,
        )
    }

    /// D9 (#174): a set's members are bytes like the rest of a rule, so a member outside
    /// UTF-8 is compared with the record's bytes, and the same bytes match.
    #[test]
    fn a_member_outside_utf8_matches_a_record_carrying_the_same_bytes() {
        let set = b"%d=/tmp/live/\xff\nallow perm=execute all : dir=%d\n";
        let got = check_bytes(
            set,
            b"rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
              : path=/tmp/live/\xff/x ftype=application/x-executable trust=0",
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
        let got = check_bytes(
            set,
            b"rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
              : path=/tmp/live/\xfe/x ftype=application/x-executable trust=0",
        );
        assert_eq!(
            rendered(&got).0,
            "denied",
            "one byte apart is a miss: {got:?}"
        );
    }

    /// The daemon loads a set's members only up to the first space (`rules::sets`), so a
    /// member written `/app/\xff y` is `/app/\xff`, and the record holding `/app/\xff y`
    /// is in no set: the rule does not match and rule 13 denies again. Without the space
    /// the same member matches.
    #[test]
    fn a_set_member_past_the_first_space_is_not_in_the_set() {
        let got = check_bytes(
            b"%s=/app/q,/app/\xff y\nallow perm=execute all : path=%s\n",
            b"rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
              : path=/app/\xff\\ y ftype=application/x-executable trust=0",
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
        let got = check_bytes(
            b"%s=/app/q,/app/\xff\nallow perm=execute all : path=%s\n",
            b"rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
              : path=/app/\xff ftype=application/x-executable trust=0",
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
    }

    /// A vertical tab or U+00A0 inside a candidate's value is part of the value, as it is
    /// for the daemon (`rules.rs`), so the record carrying the same bytes is allowed. The
    /// daemon logs the tab as `\013`.
    #[test]
    fn a_vertical_tab_or_a_no_break_space_in_a_candidate_value_still_matches() {
        for (candidate, path) in [
            (
                &b"allow perm=execute all : path=/app/x\x0by"[..],
                &b"/app/x\\013y"[..],
            ),
            (
                "allow perm=execute all : path=/app/x\u{a0}y".as_bytes(),
                "/app/x\u{a0}y".as_bytes(),
            ),
        ] {
            let line = [
                &b"rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : path="[..],
                path,
                b" ftype=application/x-executable trust=0",
            ]
            .concat();
            let got = check_bytes(candidate, &line);
            assert_eq!(rendered(&got).0, "allowed", "{got:?}");
        }
    }

    /// #174 F1: a candidate's `path=`, `exe=` and `dir=` are compared with the record's raw
    /// bytes. Through `from_utf8_lossy` the rule held `ef bf bd` where the record held
    /// `ff`, and a file the daemon allows read `denied`. The UTF-8 twin of each is the
    /// control: it allowed before and still does.
    #[test]
    fn a_candidate_outside_utf8_matches_a_record_carrying_the_same_bytes() {
        for (candidate, exe, path) in [
            (
                &b"allow perm=execute exe=/usr/bin/bash : path=/app/d\xffr"[..],
                &b"/usr/bin/bash"[..],
                &b"/app/d\xffr"[..],
            ),
            (
                b"allow perm=execute exe=/usr/bin/bash : path=/app/ok",
                b"/usr/bin/bash",
                b"/app/ok",
            ),
            (
                b"allow perm=execute exe=/opt/b\xffsh : all",
                b"/opt/b\xffsh",
                b"/app/ok",
            ),
            (
                b"allow perm=execute exe=/opt/bash : all",
                b"/opt/bash",
                b"/app/ok",
            ),
            (
                b"allow perm=execute all : dir=/app/d\xff/",
                b"/usr/bin/bash",
                b"/app/d\xff/x",
            ),
            (
                b"allow perm=execute all : dir=/app/d/",
                b"/usr/bin/bash",
                b"/app/d/x",
            ),
        ] {
            let line = [
                &b"rule=13 dec=deny_audit perm=execute pid=1 exe="[..],
                exe,
                b" : path=",
                path,
                b" ftype=application/x-executable trust=0",
            ]
            .concat();
            let got = check_bytes(candidate, &line);
            assert_eq!(
                rendered(&got),
                ("allowed", &[b"00-cand.rules: ", candidate].concat()[..]),
                "{:?}",
                String::from_utf8_lossy(&line)
            );
        }
    }

    /// #162: the D3 skip compares rule text. A candidate differing from the host's own rule
    /// before N only in one byte outside UTF-8 is a rule the daemon never walked past, so it
    /// is evaluated -- and here it allows. Through `from_utf8_lossy` both texts were one
    /// U+FFFD, the candidate was skipped as the host's rule and N denied again.
    #[test]
    fn a_candidate_differing_from_a_host_rule_only_outside_utf8_is_not_skipped() {
        let deny = b"deny_audit perm=execute all : all\n";
        let host_body = [&b"allow perm=execute all : path=/app/d\xfer\n"[..], deny].concat();
        let host = rules_d::files(vec![("10-host.rules".to_string(), host_body.clone())]);
        let compiled = rules::parse(&host_body);
        let proposed = rules_d::files(vec![(
            "10-host.rules".to_string(),
            [&b"allow perm=execute all : path=/app/d\xffr\n"[..], deny].concat(),
        )]);
        let (record, n) = parsed(
            &b"rule=2 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
               : path=/app/d\xffr ftype=application/x-executable trust=0"[..],
        );
        let got = verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host),
            &[],
            &proposed,
        );
        assert_eq!(rendered(&got).0, "allowed", "{got:?}");
    }

    /// The reproduction from the #139 comment, which answered `allowed` before
    /// `Proposal::Merged` carried the gate. The proposed directory prepends the record's own
    /// ftype to `%languages`, so the shipped `deny_audit perm=any all : ftype=%languages` --
    /// a rule the daemon walked past, with the definition it had then -- is reached before
    /// the new allow and, resolved against the proposed definition, matches. `allowed` is
    /// the wrong answer the hazard forbids; the answer is that deny.
    #[test]
    fn the_reproduction_from_139_is_denied_by_the_deny_the_edit_reaches() {
        let (record, n) = parsed(TRUSTED_LS);
        let compiled = compiled();
        let proposed = rules_d::files(vec![
            (
                "10-languages.rules".to_string(),
                edited_languages().into_bytes(),
            ),
            (
                "70-trusted-lang.rules".to_string(),
                HOST[7].1.as_bytes().to_vec(),
            ),
            (
                "71-new.rules".to_string(),
                b"allow perm=execute all : path=/tmp/gaps/trusted-ls\n".to_vec(),
            ),
            (
                "90-deny-execute.rules".to_string(),
                b"deny_audit perm=execute all : all\n".to_vec(),
            ),
        ]);
        let changed = changed_sets(&proposed, &loaded_sets());
        assert_eq!(changed, ["%languages"], "the edit is the only one");
        let got = verdict(
            &record,
            n,
            None,
            Some(&compiled),
            Some(&host()),
            &changed,
            &proposed,
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
        assert!(
            detail(&got).ends_with("deny_audit perm=any all : ftype=%languages"),
            "{got:?}"
        );
    }

    /// `Proposal::OnDisk`, the same hazard through the directory itself: the rules naming
    /// the changed set are evaluated and the rest keep the D3 skip. This record carries no
    /// `ftype=`, so the two answers differ visibly -- evaluating the `%languages` deny
    /// cannot be decided, skipping it leaves rule 13 to deny again -- and rule 1's `uid=`
    /// would make the whole walk `unknown` if the skip were dropped for every rule.
    #[test]
    fn on_disk_evaluates_the_rules_naming_a_changed_set_and_skips_the_others() {
        let (record, n) = parsed(
            "rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash \
             : path=/tmp/gaps/trusted-ls trust=1",
        );
        let compiled = compiled();
        let proposed = replacing("10-languages.rules", &edited_languages());
        let answer = |changed: &[String]| {
            let got = verdict(&record, n, None, Some(&compiled), None, changed, &proposed);
            rendered(&got).0
        };
        assert_eq!(answer(&changed_sets(&proposed, &loaded_sets())), "unknown");
        assert_eq!(
            answer(&[]),
            "denied",
            "a rule naming only unchanged sets is one the daemon walked past"
        );
    }

    /// Rule N is proved to match only under the definition the daemon had. Take the
    /// record's type out of `%languages` and rule 11 stops matching it, so "denies it
    /// again" would be a verdict nothing proves; leave the set alone, or edit it without
    /// touching that member, and rule 11 still denies.
    #[test]
    fn a_rule_n_naming_a_changed_set_is_asked_again_before_it_denies_again() {
        let (record, n) = parsed(PY);
        let compiled = compiled();
        let answer = |body: &str| {
            let proposed = replacing("10-languages.rules", body);
            let changed = changed_sets(&proposed, &loaded_sets());
            let got = verdict(&record, n, None, Some(&compiled), None, &changed, &proposed);
            (rendered(&got).0, changed.len())
        };
        assert_eq!(answer(HOST[0].1), ("denied", 0));
        // Unchanged sets keep the proof even where the record cannot re-answer it: this one
        // carries no `ftype=`, and the daemon matched rule 11 all the same.
        let (bare, bare_n) = parsed(PY.replace(" ftype=text/x-python", ""));
        let proposed = rules_d::files(listing(None));
        let got = verdict(&bare, bare_n, None, Some(&compiled), None, &[], &proposed);
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
        assert_eq!(
            answer(&HOST[0].1.replace("text/x-python,", "")),
            ("unknown", 1),
            "rule 11 no longer matches text/x-python"
        );
        assert_eq!(
            answer(&edited_languages()),
            ("denied", 1),
            "the set changed and rule 11 still matches"
        );
    }

    /// The all-or-nothing regression the #139 comment describes: a candidate file defining a
    /// new set of its own says nothing about `%languages`, so the host's rules naming that
    /// set are still rules the daemon walked past. The record carries no `ftype=`, so
    /// evaluating one of them instead would throw the verdict away.
    #[test]
    fn a_candidate_defining_a_set_of_its_own_leaves_the_other_sets_skipped() {
        let got = check(
            Some((
                "99-cand.rules",
                "%mine=/tmp/live/\nallow perm=any all : dir=%mine",
            )),
            "rule=13 dec=deny_audit perm=execute pid=1 exe=/usr/sbin/runuser \
             : path=/tmp/live/probe-grep trust=0",
        );
        assert_eq!(rendered(&got).0, "denied", "{got:?}");
    }

    #[test]
    fn changed_sets_names_every_definition_that_is_not_the_loaded_one_once() {
        let loaded = loaded_sets();
        assert_eq!(
            changed_sets(&host(), &loaded),
            Vec::<String>::new(),
            "the directory the daemon loaded from changed nothing"
        );
        assert_eq!(
            changed_sets(
                &replacing("10-languages.rules", &edited_languages()),
                &loaded
            ),
            ["%languages"]
        );
        // Defined on one side only, either side: adding or dropping a definition changes
        // what the rules naming it match.
        let mine = rules_d::files(vec![(
            "00-cand.rules".to_string(),
            b"%mine=/tmp/live/\n".to_vec(),
        )]);
        assert_eq!(changed_sets(&mine, &loaded), ["%mine", "%languages"]);
        assert_eq!(changed_sets(&mine, &[]), ["%mine"]);
        let twice = rules_d::files(vec![(
            "00-cand.rules".to_string(),
            b"%mine=a\n%mine=b\n".to_vec(),
        )]);
        assert_eq!(changed_sets(&twice, &[]), ["%mine"], "one name, one entry");
    }

    #[test]
    fn only_a_rule_naming_a_changed_set_loses_its_skip() {
        let deny = Rule::new(b"deny_audit perm=any all : ftype=%languages");
        assert!(names_changed_set(&deny, &["%languages".to_string()]));
        assert!(!names_changed_set(&deny, &["%other".to_string()]));
        assert!(!names_changed_set(
            &Rule::new(b"deny_audit perm=execute all : all"),
            &["%languages".to_string()]
        ));
        // Wherever it is written and whatever the attribute: the daemon resolves a
        // reference on `uid=` and one beside a literal too.
        assert!(names_changed_set(
            &Rule::new(b"allow perm=open uid=%who : all"),
            &["%who".to_string()]
        ));
        assert!(names_changed_set(
            &Rule::new(b"allow perm=open all : dir=execdirs,%d"),
            &["%d".to_string()]
        ));
    }
}
