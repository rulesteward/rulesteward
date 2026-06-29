//! Alias-reference lint passes (#331): sudo-E01 (reference to an undefined alias)
//! and sudo-W03 (alias defined but never referenced - a dead alias).
//!
//! # Algorithm
//!
//! Both passes share a single walk over all [`SudoersFile`]s that builds four
//! per-kind symbol tables and a per-kind reference set, then diffs them.
//!
//! ## Symbol table (defined set)
//! Every [`LineKind::Alias`](crate::ast::LineKind::Alias) contributes to its
//! kind's defined set: `{ (AliasKind, NAME) -> (file, line, span) }`.
//!
//! ## Reference set
//! References to alias NAMEs arise in six positions (verified against
//! `visudo -c` on sudo 1.9.17p2; see the project grounding doc):
//!
//! - `UserSpec.users`: tokens matching `[A-Z][A-Z0-9_]*` (not `ALL`) ->
//!   `User_Alias` reference.
//! - `UserSpec.hosts`: same pattern -> `Host_Alias` reference.
//! - `CmndSpec.runas.users` / `CmndSpec.runas.groups`: same pattern ->
//!   `Runas_Alias` reference.
//! - `CmndSpec.cmnd` (`CmndItem::Cmnd`): token (after stripping `!`) matching
//!   the pattern -> `Cmnd_Alias` reference.
//! - `AliasDef.members`: token (after stripping `!`) matching the pattern ->
//!   same-kind alias reference (an alias referencing another alias).
//!
//! The built-in `ALL` is NEVER flagged. `CmndItem::All` is excluded directly;
//! `ALL` in other raw token lists is excluded by the pattern check.
//!
//! Tag keywords (`NOPASSWD`, `SETENV`, ...) are uppercase but are consumed by the
//! parser before the command token; they never appear as raw tokens in the fields
//! we walk.
//!
//! ## W03: dead aliases
//! visudo (1.9.17p2) reports an alias as "unused" when it is NOT referenced from a
//! user-spec (directly or transitively). An alias referenced only from ANOTHER alias
//! that is itself dead is ALSO reported unused (confirmed: `visudo -c` reports BOTH
//! in a dead chain). We mirror this: W03 fires for every defined alias NAME not
//! present in the reference set built by the user-spec walk alone (NOT the
//! alias-members walk).
//!
//! ## E01: undefined references
//! E01 fires for each alias reference (from either user-specs or alias members) that
//! has no entry in the defined set for that kind. Anchored at the reference site's
//! line/span.

use std::collections::{HashMap, HashSet, VecDeque};

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{AliasKind, CmndItem, LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

/// Human-readable name of an alias kind, for diagnostic messages.
fn kind_name(kind: AliasKind) -> &'static str {
    match kind {
        AliasKind::User => "User_Alias",
        AliasKind::Runas => "Runas_Alias",
        AliasKind::Host => "Host_Alias",
        AliasKind::Cmnd => "Cmnd_Alias",
    }
}

/// Returns `true` when `token` (after stripping ALL leading `!`) matches the
/// sudoers alias-name pattern `[A-Z][A-Z0-9_]*` AND is not the built-in `ALL`.
///
/// The sudoers grammar allows zero or more `!` before an alias name (`'!'* Cmnd_Alias`
/// per sudoers(5)); we must strip ALL of them, not just one, before testing the NAME
/// pattern. A single `strip_prefix('!')` would leave `!NAME` and silently mis-classify
/// a `!!NAME` token as a non-alias, causing W03 false-positives and E01 false-negatives.
///
/// Used to decide whether a raw token in a user-spec or alias-member list is an
/// alias reference (vs a path, a username, a group, etc.).
fn is_alias_ref(token: &str) -> bool {
    let t = token.trim_start_matches('!');
    if t == "ALL" {
        return false;
    }
    let mut chars = t.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Returns `true` when `token` is a POSITIVE reference (no leading `!`) to the
/// reserved built-in `ALL`.
///
/// A leading `!` makes the token a NEGATION (`!ALL` = "deny everything"), the
/// OPPOSITE of the run-anything grant, so it must NOT count as expanding-to-ALL.
/// Grounded against `visudo -x` (sudo 1.9.17p2): `!ALL` exports with
/// `"negated": true`, a subtraction rather than a grant.
fn is_positive_all(token: &str) -> bool {
    token == "ALL"
}

/// Build the set of `Cmnd_Alias` NAMEs that TRANSITIVELY expand to the reserved
/// `ALL`, for the sudo-W02 walk (#332).
///
/// A `Cmnd_Alias` expands-to-ALL when its member list contains the POSITIVE
/// literal `ALL`, OR contains a POSITIVE `Cmnd_Alias` reference that itself
/// expands-to-ALL. A leading `!` on a member (a negation / subtraction, not a
/// grant) does NOT contribute - so we test members with [`is_positive_all`] for
/// the literal-ALL case and require a non-`!`-prefixed token for the alias-ref
/// case.
///
/// Reuses the #331 alias-table construction shape: one pass builds a REVERSE-edge
/// map (`member-name -> the aliases that reference it as a positive member`,
/// covering the `Cmd_Alias` synonym, since both map to [`AliasKind::Cmnd`]) and
/// records the SEED set (aliases whose own member list directly contains a positive
/// literal `ALL`). A backward worklist/BFS then propagates "expands-to-ALL" from the
/// seeds along the reverse edges: each defined alias is enqueued at most once and
/// each reverse edge is relaxed at most once, so the walk is O(V+E) (LINEAR) rather
/// than the previous re-scan-every-pass O(V^2) fixpoint. The result SET is identical:
/// a name is marked iff it directly contains positive `ALL`, or some positive
/// `Cmnd_Alias` member it references is marked (transitively). It is cycle-safe: a
/// self- or mutual reference (`X = Y`, `Y = X`) that never reaches `ALL` has no seed
/// in its component, so the worklist never enters it and it is never marked; a cycle
/// member that DOES reach `ALL` is reached from that seed exactly once (the
/// "already marked" guard prevents re-enqueue, so a cycle cannot loop forever).
///
/// This is the alias-expansion case the #330 / sudo-W01 pass deliberately leaves
/// as a documented false-negative: W01 keys off the LITERAL [`CmndItem::All`] only.
#[must_use]
pub(crate) fn cmnd_aliases_expanding_to_all(files: &[SudoersFile]) -> HashSet<String> {
    // Reverse adjacency: member-name -> the alias NAMEs that reference it via a
    // POSITIVE same-kind (Cmnd) member edge. To propagate "X expands-to-ALL"
    // BACKWARD (X marked => everyone that references X is marked), we index edges
    // by the referenced member, not by the referencing alias. We only record
    // positive alias refs; a literal ALL member is recorded separately as a seed.
    let mut rev_edges: HashMap<String, Vec<String>> = HashMap::new();
    // Seed: aliases whose OWN member list directly contains a positive literal ALL.
    let mut seeds: Vec<String> = Vec::new();

    for file in files {
        for ll in &file.lines {
            if let LineKind::Alias(def) = &ll.kind
                && def.kind == AliasKind::Cmnd
            {
                for tok in &def.members {
                    if is_positive_all(tok) {
                        seeds.push(def.name.clone());
                    } else if !tok.starts_with('!') && is_alias_ref(tok) {
                        // A POSITIVE same-kind (Cmnd) alias reference: an expansion
                        // edge `def.name -> member`. We store it REVERSED
                        // (`member -> def.name`) keyed by the bare member NAME, so
                        // that marking `member` lets us reach `def.name` in O(1) per
                        // edge. `!`-prefixed refs are subtractions (deny), excluded by
                        // the `!starts_with('!')` guard above - WITHOUT that guard a
                        // `!A` edge would strip to `A` and wrongly propagate A's
                        // expand-to-ALL into the negating alias.
                        let member = tok.trim_start_matches('!').to_string();
                        rev_edges.entry(member).or_default().push(def.name.clone());
                    }
                }
            }
        }
    }

    // Backward worklist/BFS from the seeds along the reverse edges. `expands` is the
    // result set AND the visited set: a name is pushed onto the queue exactly when it
    // is first inserted, so every defined alias is dequeued at most once and every
    // reverse edge is relaxed at most once -> O(V+E). Cycle-safe: the `insert`
    // returning `false` (already present) prevents re-enqueue, so a cycle that is
    // reachable from a seed is traversed once and a cycle with no seed in its
    // component is never entered.
    let mut expands: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for s in seeds {
        if expands.insert(s.clone()) {
            queue.push_back(s);
        }
    }
    while let Some(name) = queue.pop_front() {
        if let Some(preds) = rev_edges.get(&name) {
            for pred in preds {
                if expands.insert(pred.clone()) {
                    queue.push_back(pred.clone());
                }
            }
        }
    }

    expands
}

/// A single alias definition site (where the name is defined, for W03 anchoring).
#[derive(Debug)]
struct DefSite {
    file_idx: usize,
    line: usize,
    span: std::ops::Range<usize>,
}

/// A reference to an alias name (where it is used, for E01 anchoring).
#[derive(Debug)]
struct RefSite {
    kind: AliasKind,
    name: String,
    file_idx: usize,
    line: usize,
    span: std::ops::Range<usize>,
}

/// Four per-kind symbol tables keyed by alias NAME (all caps).
///
/// `AliasKind` does not implement `Hash` (it is a frozen AST type), so we cannot
/// use `(AliasKind, String)` as a `HashMap` key. Instead we keep one map per
/// kind - a simple, zero-overhead alternative that also makes per-kind lookups
/// direct.
struct Tables {
    /// `User_Alias` definitions: name -> `DefSite`.
    user: HashMap<String, DefSite>,
    /// `Runas_Alias` definitions.
    runas: HashMap<String, DefSite>,
    /// `Host_Alias` definitions.
    host: HashMap<String, DefSite>,
    /// `Cmnd_Alias` definitions (covers `Cmd_Alias` synonym too).
    cmnd: HashMap<String, DefSite>,
    /// Names referenced from USER-SPECS (for W03 dead-alias check), four sets.
    user_spec_refs: Vec<String>,
    runas_spec_refs: Vec<String>,
    host_spec_refs: Vec<String>,
    cmnd_spec_refs: Vec<String>,
    /// All reference sites (spec + alias-member) for E01 undefined check.
    all_refs: Vec<RefSite>,
}

impl Tables {
    fn def_map(&self, kind: AliasKind) -> &HashMap<String, DefSite> {
        match kind {
            AliasKind::User => &self.user,
            AliasKind::Runas => &self.runas,
            AliasKind::Host => &self.host,
            AliasKind::Cmnd => &self.cmnd,
        }
    }

    fn def_map_mut(&mut self, kind: AliasKind) -> &mut HashMap<String, DefSite> {
        match kind {
            AliasKind::User => &mut self.user,
            AliasKind::Runas => &mut self.runas,
            AliasKind::Host => &mut self.host,
            AliasKind::Cmnd => &mut self.cmnd,
        }
    }

    fn push_spec_ref(&mut self, kind: AliasKind, name: String) {
        let v = match kind {
            AliasKind::User => &mut self.user_spec_refs,
            AliasKind::Runas => &mut self.runas_spec_refs,
            AliasKind::Host => &mut self.host_spec_refs,
            AliasKind::Cmnd => &mut self.cmnd_spec_refs,
        };
        if !v.contains(&name) {
            v.push(name);
        }
    }
}

/// Push a reference to `tables` for each alias-ref token in `tokens` of the
/// given `kind`, recording both the spec-level reference (for W03) and the
/// all-refs list (for E01). `fi` / `line` / `span` are the source location of
/// the containing line.
fn push_token_refs(
    tables: &mut Tables,
    tokens: &[String],
    kind: AliasKind,
    fi: usize,
    line: usize,
    span: &std::ops::Range<usize>,
) {
    for tok in tokens {
        if is_alias_ref(tok) {
            let name = tok.trim_start_matches('!').to_string();
            tables.push_spec_ref(kind, name.clone());
            tables.all_refs.push(RefSite {
                kind,
                name,
                file_idx: fi,
                line,
                span: span.clone(),
            });
        }
    }
}

/// Build the four per-kind symbol tables and both reference sets from all files.
fn build_tables(files: &[SudoersFile]) -> Tables {
    let mut t = Tables {
        user: HashMap::new(),
        runas: HashMap::new(),
        host: HashMap::new(),
        cmnd: HashMap::new(),
        user_spec_refs: Vec::new(),
        runas_spec_refs: Vec::new(),
        host_spec_refs: Vec::new(),
        cmnd_spec_refs: Vec::new(),
        all_refs: Vec::new(),
    };

    // Pass 1: collect definitions.
    for (fi, file) in files.iter().enumerate() {
        for ll in &file.lines {
            if let LineKind::Alias(def) = &ll.kind {
                t.def_map_mut(def.kind).insert(
                    def.name.clone(),
                    DefSite {
                        file_idx: fi,
                        line: ll.line,
                        span: ll.span.clone(),
                    },
                );
            }
        }
    }

    // Pass 2: collect references.
    for (fi, file) in files.iter().enumerate() {
        for ll in &file.lines {
            match &ll.kind {
                LineKind::UserSpec(spec) => {
                    push_token_refs(&mut t, &spec.users, AliasKind::User, fi, ll.line, &ll.span);
                    push_token_refs(&mut t, &spec.hosts, AliasKind::Host, fi, ll.line, &ll.span);
                    for cs in &spec.cmnd_specs {
                        if let Some(runas) = &cs.runas {
                            let all_runas: Vec<String> = runas
                                .users
                                .iter()
                                .chain(runas.groups.iter())
                                .cloned()
                                .collect();
                            push_token_refs(
                                &mut t,
                                &all_runas,
                                AliasKind::Runas,
                                fi,
                                ll.line,
                                &ll.span,
                            );
                        }
                        // CmndItem::All is the built-in ALL - never a Cmnd_Alias ref.
                        if let CmndItem::Cmnd(tok) = &cs.cmnd
                            && is_alias_ref(tok)
                        {
                            let name = tok.trim_start_matches('!').to_string();
                            t.push_spec_ref(AliasKind::Cmnd, name.clone());
                            t.all_refs.push(RefSite {
                                kind: AliasKind::Cmnd,
                                name,
                                file_idx: fi,
                                line: ll.line,
                                span: ll.span.clone(),
                            });
                        }
                    }
                }
                LineKind::Alias(def) => {
                    // Alias members -> same-kind refs.
                    // These go into all_refs (E01) but NOT into spec_refs (W03): an alias
                    // only referenced from another dead alias is still W03-dead (visudo
                    // 1.9.17p2 "dead chain" behavior). W03 uses a transitive reachability
                    // expansion from spec_refs, so members are processed there separately.
                    for tok in &def.members {
                        if is_alias_ref(tok) {
                            let name = tok.trim_start_matches('!').to_string();
                            t.all_refs.push(RefSite {
                                kind: def.kind,
                                name,
                                file_idx: fi,
                                line: ll.line,
                                span: ll.span.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    t
}

/// sudo-E01: a user-spec (or another alias) references an alias name that is never
/// defined. Anchored at the reference site.
///
/// Grounded against `visudo -c` (sudo 1.9.17p2): visudo reports
/// `<Kind>_Alias "NAME" referenced but not defined` for every undefined alias
/// reference in user-spec or alias-member position. ALL is built-in and excluded.
#[must_use]
pub fn e01(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let tables = build_tables(files);
    let mut diags = Vec::new();
    for r in &tables.all_refs {
        if !tables.def_map(r.kind).contains_key(&r.name) {
            let file = &files[r.file_idx];
            diags.push(anchored(
                Severity::Error,
                "sudo-E01",
                r.span.clone(),
                format!(
                    "{} \"{}\" referenced but not defined",
                    kind_name(r.kind),
                    r.name
                ),
                &file.path,
                r.line,
            ));
        }
    }
    diags
}

/// sudo-W03: an alias is defined but never referenced anywhere (dead alias).
/// Anchored at the definition site.
///
/// Grounded against `visudo -c` (sudo 1.9.17p2): visudo reports
/// `Warning: ... unused <Kind>_Alias "NAME"` for every alias that is not
/// reachable from a user-spec.
///
/// Reachability is TRANSITIVE: if a user-spec references alias B, and B's member
/// list references alias A, then A is also reachable and NOT W03-dead.
/// Conversely, in a dead chain where neither A nor B is referenced from any spec,
/// BOTH are W03-dead (confirmed by visudo).
///
/// Algorithm: seed the reachable set with every alias name appearing directly in
/// a user-spec, then expand transitively via alias-member lists until a fixpoint.
#[must_use]
pub fn w03(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let tables = build_tables(files);

    // Build a "members of alias X" lookup for alias-kind cross-referencing.
    // Key: (AliasKind discriminant, name) -> member alias names of the same kind.
    // We store the member alias names separately per kind since alias-member refs
    // are same-kind only. We use a Vec<(kind, name, member_refs)> approach.
    //
    // For reachability we need: given a (kind, name) that is reachable, which
    // other (kind, name') does it pull in transitively?
    // Answer: any member of that alias definition that itself looks like an alias ref.
    //
    // We build per-kind maps: kind -> name -> Vec<member_alias_names>.
    let mut member_alias_refs: [HashMap<String, Vec<String>>; 4] = [
        HashMap::new(), // User
        HashMap::new(), // Runas
        HashMap::new(), // Host
        HashMap::new(), // Cmnd
    ];
    for file in files {
        for ll in &file.lines {
            if let LineKind::Alias(def) = &ll.kind {
                let idx = kind_to_idx(def.kind);
                let entry = member_alias_refs[idx].entry(def.name.clone()).or_default();
                for tok in &def.members {
                    if is_alias_ref(tok) {
                        let name = tok.trim_start_matches('!').to_string();
                        entry.push(name);
                    }
                }
            }
        }
    }

    // Seed: all alias names referenced directly from user-specs.
    // Reachability is a FORWARD worklist/BFS per kind along the alias-member edges:
    // each kind's `reachable` set is both the result and the visited set, so every
    // alias name is enqueued at most once and every member edge is relaxed at most
    // once -> O(V+E) (LINEAR), replacing the previous re-scan-every-pass O(V^2)
    // fixpoint. We use a HashSet for O(1) membership (the prior Vec + `contains`
    // linear scan was the other quadratic factor) plus a per-kind work queue.
    // The reachable SET is identical to the fixpoint: a name is reachable iff it is
    // referenced directly from a user-spec, or it is a member of an already-reachable
    // alias (transitively). Cycle-safe: a name inserted once is never re-enqueued, so
    // a cyclic member chain (`A` members include `B`, `B` members include `A`) is
    // traversed once instead of looping.
    let mut reachable: [HashSet<String>; 4] = [
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    ];
    let seed_refs = [
        &tables.user_spec_refs,
        &tables.runas_spec_refs,
        &tables.host_spec_refs,
        &tables.cmnd_spec_refs,
    ];
    for ki in 0..4 {
        let mut queue: VecDeque<String> = VecDeque::new();
        for name in seed_refs[ki] {
            if reachable[ki].insert(name.clone()) {
                queue.push_back(name.clone());
            }
        }
        while let Some(name) = queue.pop_front() {
            if let Some(members) = member_alias_refs[ki].get(&name) {
                for m in members {
                    if reachable[ki].insert(m.clone()) {
                        queue.push_back(m.clone());
                    }
                }
            }
        }
    }

    // Now emit W03 for every defined alias that is not reachable.
    let all_kinds = [
        AliasKind::User,
        AliasKind::Runas,
        AliasKind::Host,
        AliasKind::Cmnd,
    ];
    let mut defs: Vec<(AliasKind, &String, &DefSite)> = all_kinds
        .iter()
        .flat_map(|&k| {
            tables
                .def_map(k)
                .iter()
                .map(move |(name, site)| (k, name, site))
        })
        .collect();
    defs.sort_by_key(|(_, _, site)| (site.file_idx, site.line));

    let mut diags = Vec::new();
    for (kind, name, site) in defs {
        let ki = kind_to_idx(kind);
        if !reachable[ki].contains(name) {
            let file = &files[site.file_idx];
            diags.push(anchored(
                Severity::Warning,
                "sudo-W03",
                site.span.clone(),
                format!(
                    "{} \"{}\" is defined but never referenced (dead alias)",
                    kind_name(kind),
                    name
                ),
                &file.path,
                site.line,
            ));
        }
    }
    diags
}

/// Map an [`AliasKind`] to a 0-based index into the four-element per-kind arrays.
fn kind_to_idx(kind: AliasKind) -> usize {
    match kind {
        AliasKind::User => 0,
        AliasKind::Runas => 1,
        AliasKind::Host => 2,
        AliasKind::Cmnd => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::{e01, w03};
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use rulesteward_core::Severity;
    use std::path::Path;

    fn parse_one(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    // ---- E01: undefined alias references ----

    /// Grounded: `User_Alias ADMINS = alice, bob` + `ADMINS ALL = ALL`
    /// visudo -c: parsed OK (defined and referenced -> no E01, no W03).
    #[test]
    fn e01_no_diag_when_user_alias_defined_and_referenced() {
        let files = parse_one("User_Alias ADMINS = alice, bob\nADMINS ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ADMINS is defined and referenced: no E01; got {diags:?}"
        );
    }

    /// Grounded: `admins ALL = OPS` where `OPS` (`Cmnd_Alias`) is never defined.
    /// visudo -c: `Cmnd_Alias "OPS" referenced but not defined`.
    #[test]
    fn e01_fires_for_undefined_cmnd_alias_in_user_spec() {
        // `admins` is lowercase - not an alias ref. `OPS` is uppercase and not defined.
        let files = parse_one("admins ALL = OPS\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one undefined Cmnd_Alias OPS; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(
            diags[0].message.contains("OPS"),
            "message names the undefined alias"
        );
        assert!(
            diags[0].message.contains("Cmnd_Alias"),
            "message names the kind"
        );
    }

    /// Grounded: `SYSADMINS ALL = ALL` where `SYSADMINS` (`User_Alias`) is never defined.
    /// visudo -c: `User_Alias "SYSADMINS" referenced but not defined`.
    #[test]
    fn e01_fires_for_undefined_user_alias_in_user_spec() {
        let files = parse_one("SYSADMINS ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one undefined User_Alias SYSADMINS; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert!(diags[0].message.contains("SYSADMINS"));
        assert!(diags[0].message.contains("User_Alias"));
    }

    /// Grounded: `alice WEBSERVERS = ALL` where `WEBSERVERS` (`Host_Alias`) is never defined.
    /// visudo -c: `Host_Alias "WEBSERVERS" referenced but not defined`.
    #[test]
    fn e01_fires_for_undefined_host_alias_in_user_spec() {
        let files = parse_one("alice WEBSERVERS = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one undefined Host_Alias WEBSERVERS; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert!(diags[0].message.contains("WEBSERVERS"));
        assert!(diags[0].message.contains("Host_Alias"));
    }

    /// Grounded: `alice ALL = (DBOPS) ALL` where `DBOPS` (`Runas_Alias`) is never defined.
    /// visudo -c: `Runas_Alias "DBOPS" referenced but not defined`.
    #[test]
    fn e01_fires_for_undefined_runas_alias_in_user_spec() {
        let files = parse_one("alice ALL = (DBOPS) ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one undefined Runas_Alias DBOPS; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert!(diags[0].message.contains("DBOPS"));
        assert!(diags[0].message.contains("Runas_Alias"));
    }

    /// Grounded: `Cmnd_Alias A = MISSING, /bin/cat` + `alice ALL = A`
    /// visudo -c: `Cmnd_Alias "MISSING" referenced but not defined` (alias-in-alias).
    #[test]
    fn e01_fires_for_undefined_alias_inside_alias_member_list() {
        let files = parse_one("Cmnd_Alias A = MISSING, /bin/cat\nalice ALL = A\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "MISSING is undefined inside A's members; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert!(diags[0].message.contains("MISSING"));
        assert!(diags[0].message.contains("Cmnd_Alias"));
    }

    /// Grounded: `ALL` in user/host/runas/cmnd position -> built-in, never E01.
    /// visudo -c: parsed OK.
    #[test]
    fn e01_all_builtin_never_fires() {
        let files = parse_one("root ALL = ALL\nalice ALL = (ALL) ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ALL is built-in and never E01; got {diags:?}"
        );
    }

    /// Grounded: `!DANGEROUS` negated alias ref - strip `!` before checking.
    /// visudo -c (fixture 15): `DANGEROUS` is defined and referenced -> no E01.
    #[test]
    fn e01_negated_alias_ref_is_recognised() {
        let files = parse_one("Cmnd_Alias DANGEROUS = /bin/rm\nalice ALL = ALL, !DANGEROUS\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "!DANGEROUS strips to DANGEROUS which is defined -> no E01; got {diags:?}"
        );
    }

    /// Cross-alias: `Cmnd_Alias A = /bin/ls` + `Cmnd_Alias B = A, /bin/cat` + `alice ALL = B`.
    /// A is referenced by B (alias-member), B is referenced by the user-spec.
    /// No E01 for either (both defined). visudo: parsed OK.
    #[test]
    fn e01_no_diag_for_cross_alias_reference() {
        let files =
            parse_one("Cmnd_Alias A = /bin/ls\nCmnd_Alias B = A, /bin/cat\nalice ALL = B\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "A and B are both defined -> no E01; got {diags:?}"
        );
    }

    /// Diagnostic has the correct meta: code, severity, `source_id` set.
    #[test]
    fn e01_diagnostic_is_anchored_with_source_id() {
        let files = parse_one("BOGUS ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sudo-E01");
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].source_id.is_some(),
            "anchored diagnostics carry a source_id for ariadne"
        );
    }

    // ---- W03: dead aliases ----

    /// Grounded: `Cmnd_Alias UNUSED = /bin/ls` + `root ALL = ALL`.
    /// visudo -c: `Warning: ... unused Cmnd_Alias "UNUSED"`.
    #[test]
    fn w03_fires_for_dead_cmnd_alias() {
        let files = parse_one("Cmnd_Alias UNUSED = /bin/ls\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(diags.len(), 1, "UNUSED is dead -> one W03; got {diags:?}");
        assert_eq!(diags[0].code, "sudo-W03");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(diags[0].message.contains("UNUSED"));
        assert!(diags[0].message.contains("Cmnd_Alias"));
    }

    /// Grounded: `User_Alias DEADGUYS = charlie, dave` + `root ALL = ALL`.
    /// visudo -c: `Warning: ... unused User_Alias "DEADGUYS"`.
    #[test]
    fn w03_fires_for_dead_user_alias() {
        let files = parse_one("User_Alias DEADGUYS = charlie, dave\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(diags.len(), 1, "DEADGUYS is dead -> one W03; got {diags:?}");
        assert_eq!(diags[0].code, "sudo-W03");
        assert!(diags[0].message.contains("DEADGUYS"));
        assert!(diags[0].message.contains("User_Alias"));
    }

    /// Grounded: `Host_Alias WEBSERVERS = web1, web2` + `root ALL = ALL`.
    /// visudo -c: `Warning: ... unused Host_Alias "WEBSERVERS"`.
    #[test]
    fn w03_fires_for_dead_host_alias() {
        let files = parse_one("Host_Alias WEBSERVERS = web1, web2\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "WEBSERVERS is dead -> one W03; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-W03");
        assert!(diags[0].message.contains("WEBSERVERS"));
        assert!(diags[0].message.contains("Host_Alias"));
    }

    /// Grounded: `Runas_Alias DBOPS = postgres, mysql` + `root ALL = ALL`.
    /// visudo -c: `Warning: ... unused Runas_Alias "DBOPS"`.
    #[test]
    fn w03_fires_for_dead_runas_alias() {
        let files = parse_one("Runas_Alias DBOPS = postgres, mysql\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(diags.len(), 1, "DBOPS is dead -> one W03; got {diags:?}");
        assert_eq!(diags[0].code, "sudo-W03");
        assert!(diags[0].message.contains("DBOPS"));
        assert!(diags[0].message.contains("Runas_Alias"));
    }

    /// Grounded: `User_Alias ADMINS = alice, bob` + `ADMINS ALL = ALL`.
    /// visudo -c: parsed OK (no W03 - defined and referenced).
    #[test]
    fn w03_no_diag_when_alias_is_referenced() {
        let files = parse_one("User_Alias ADMINS = alice, bob\nADMINS ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ADMINS is referenced from user-spec -> no W03; got {diags:?}"
        );
    }

    /// Grounded: cross-alias (`Cmnd_Alias A = /bin/ls`, `Cmnd_Alias B = A, /bin/cat`,
    /// `alice ALL = B`). A referenced by B, B referenced by spec.
    /// visudo -c: parsed OK (no W03 for either).
    #[test]
    fn w03_no_diag_for_cross_alias_when_both_referenced() {
        let files =
            parse_one("Cmnd_Alias A = /bin/ls\nCmnd_Alias B = A, /bin/cat\nalice ALL = B\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "B is referenced from spec, A from B -> no W03; got {diags:?}"
        );
    }

    /// Grounded: dead chain - `Cmnd_Alias A = /bin/ls` + `Cmnd_Alias B = A` + `root ALL = ALL`.
    /// Neither A nor B is referenced from a user-spec.
    /// visudo -c: WARNING for BOTH A and B (unused).
    #[test]
    fn w03_fires_for_both_aliases_in_dead_chain() {
        let files = parse_one("Cmnd_Alias A = /bin/ls\nCmnd_Alias B = A\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(
            diags.len(),
            2,
            "A and B are both unreferenced from specs -> two W03; got {diags:?}"
        );
        let names: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
        assert!(
            diags.iter().any(|d| d.message.contains("\"A\"")),
            "W03 for A; diags: {names:?}"
        );
        assert!(
            diags.iter().any(|d| d.message.contains("\"B\"")),
            "W03 for B; diags: {names:?}"
        );
    }

    /// W03 diagnostic is anchored: carries `source_id`, line, correct code/severity.
    #[test]
    fn w03_diagnostic_is_anchored_with_source_id() {
        let files = parse_one("Cmnd_Alias DEAD = /bin/ls\nroot ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sudo-W03");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1, "W03 anchored at the definition line");
        assert!(
            diags[0].source_id.is_some(),
            "anchored diagnostics carry a source_id"
        );
    }

    /// No aliases defined at all -> no W03 (nothing dead).
    #[test]
    fn w03_no_diag_when_no_aliases_defined() {
        let files = parse_one("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "no aliases defined -> no W03; got {diags:?}"
        );
    }

    // ---- Bug 1: multi-`!` negation (!! / !!!  ...) ----
    //
    // The sudoers grammar allows `'!'*` (zero OR MORE `!`) before an alias name.
    // Grounded: `visudo -c -f` rc 0 on all three cases below (sudo 1.9.17p2).

    /// Grounded: `Cmnd_Alias DANGEROUS = /bin/rm` + `alice ALL = !!DANGEROUS`
    /// visudo -c: parsed OK (DANGEROUS is referenced via double-negation -> NOT dead).
    /// Bug: single `strip_prefix('!')` leaves `!DANGEROUS`; `is_alias_ref` fails ->
    /// `push_spec_ref` never fires -> DANGEROUS is falsely emitted as W03-dead.
    #[test]
    fn w03_double_negation_in_cmnd_not_dead() {
        let files = parse_one("Cmnd_Alias DANGEROUS = /bin/rm\nalice ALL = !!DANGEROUS\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "DANGEROUS is referenced via !!DANGEROUS -> not dead, no W03; got {diags:?}"
        );
    }

    /// Grounded: `User_Alias ADMINS = alice` + `!!ADMINS ALL = ALL`
    /// visudo -c: parsed OK (ADMINS referenced in subject position via !!).
    /// Bug: single `strip_prefix('!')` leaves `!ADMINS` in the token; not matched as
    /// alias ref -> ADMINS falsely appears dead.
    #[test]
    fn w03_double_negation_in_user_subject_not_dead() {
        let files = parse_one("User_Alias ADMINS = alice\n!!ADMINS ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ADMINS is referenced via !!ADMINS in subject position -> not dead, no W03; got {diags:?}"
        );
    }

    /// Grounded: `alice ALL = !!MISSING` where MISSING (`Cmnd_Alias`) is never defined.
    /// visudo -c: `Cmnd_Alias "MISSING" referenced but not defined`.
    /// Bug: single `strip_prefix('!')` leaves `!MISSING`; `is_alias_ref` never fires
    /// -> the undefined reference goes unreported (E01 false-negative).
    #[test]
    fn e01_double_negation_undefined_alias_fires() {
        let files = parse_one("alice ALL = !!MISSING\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert_eq!(
            diags.len(),
            1,
            "!!MISSING strips to MISSING which is undefined -> one sudo-E01; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sudo-E01");
        assert!(
            diags[0].message.contains("MISSING"),
            "message names the undefined alias name"
        );
        assert!(
            diags[0].message.contains("Cmnd_Alias"),
            "message names the alias kind"
        );
    }

    // ---- Bug 2 (mutation survivors): is_alias_ref predicate pinning ----
    //
    // Three survivors from the mutation gate, all in `is_alias_ref`:
    //   guard: `c.is_ascii_uppercase()` replaced with `true`
    //   second ||: `||` replaced with `&&` (between is_ascii_digit() and c == '_')
    //   equality: `== '_'` replaced with `!= '_'`
    // Grounded: visudo treats `[A-Z][A-Z0-9_]*` as an alias NAME; anything else
    // (non-uppercase first char, lowercase tail char, digit-first, etc.) is a
    // username, path, UID spec, or group spec - not an alias reference.
    //
    // The KEY DISTINGUISHING CASES (beyond what the simple lowercase tests cover):
    //
    // Survivor 1 (guard -> true):
    //   `admin` has lowercase 'a' -> lowercase tail 'dmin' fails all() anyway -> mutant can't be
    //   distinguished by `admin` alone. Need a non-uppercase first char with an all-uppercase/
    //   digit/_ tail. `#1000` (UID spec in user position): '#' is non-uppercase, "1000" is all-
    //   digits -> under guard-true mutant, chars.all passes -> is_alias_ref returns true -> E01
    //   fires spuriously. visudo -c: parsed OK (UID spec, no User_Alias error).
    //
    // Survivor 2 (|| -> &&, effectively only uppercase chars pass the tail predicate):
    //   The mutation makes `c == '_'` unreachable (the && makes it impossible to satisfy).
    //   An alias name containing `_` or a digit fails recognition under this mutant:
    //   `SAFE_CMD` -> tail char `_` -> under && mutant, `_`.is_ascii_uppercase()=false -> all()
    //   returns false -> alias ref not recognized -> W03 fires when alias IS referenced (false
    //   positive), or E01 fires when it's NOT defined (expected, but key is: referencing it doesn't
    //   suppress the false-positive dead-alias warning). Test: W03 must NOT fire for a referenced
    //   alias whose name contains `_`.
    //
    // Survivor 3 (== -> !=, i.e. '_' FAILS the equality):
    //   Same shape as survivor 2: `_` in an alias name is no longer recognized as valid -> same
    //   test kills it.

    /// Grounded: `admin ALL = ALL` -> visudo treats `admin` as a username (no alias
    /// lookup, no "referenced but not defined" error). `is_alias_ref("admin")` must
    /// return false (lowercase first char).
    /// visudo -c: parsed OK (no `User_Alias` error for `admin`).
    #[test]
    fn e01_lowercase_first_char_is_not_alias_ref() {
        // `admin` has a lowercase first char -> username, NOT a User_Alias ref.
        // visudo -c on `admin ALL = ALL` -> parsed OK (no alias error).
        let files = parse_one("admin ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "admin (lowercase first char) is a username, not an alias ref -> no E01; got {diags:?}"
        );
    }

    /// Grounded: `Admin ALL = ALL` -> visudo treats `Admin` as a username (mixed-case
    /// names are usernames; the alias NAME grammar requires ALL uppercase).
    /// `is_alias_ref("Admin")` must return false (lowercase `d` in tail).
    /// visudo -c: parsed OK (no alias error for `Admin`).
    #[test]
    fn e01_mixed_case_name_is_not_alias_ref() {
        // `Admin` starts uppercase but has lowercase tail char 'd' -> NOT a valid alias NAME.
        let files = parse_one("Admin ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "Admin (mixed case) is a username, not an alias ref -> no E01; got {diags:?}"
        );
    }

    /// Grounded: `ADMINs ALL = ALL` -> visudo treats `ADMINs` as a username (lowercase
    /// tail char `s`). `is_alias_ref("ADMINs")` must return false.
    /// visudo -c: parsed OK (no alias error for `ADMINs`).
    #[test]
    fn e01_uppercase_with_lowercase_tail_is_not_alias_ref() {
        // `ADMINs` has lowercase tail char 's' -> NOT a valid alias NAME.
        let files = parse_one("ADMINs ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ADMINs (lowercase tail) is a username, not an alias ref -> no E01; got {diags:?}"
        );
    }

    /// Grounded: `#1000 ALL = ALL` -> visudo treats `#1000` as a UID spec, NOT a
    /// `User_Alias` reference. No "`User_Alias` referenced but not defined" error.
    /// visudo -c: parsed OK.
    ///
    /// Kills survivor: guard `c.is_ascii_uppercase()` -> `true`. Under that mutant,
    /// `#` passes the guard; "1000" is all-digits so `chars.all` passes; `is_alias_ref`
    /// returns true (wrong) and E01 fires spuriously. The real code: `#` is not
    /// `ascii_uppercase` -> guard fails -> returns false -> no E01.
    #[test]
    fn e01_uid_spec_token_is_not_alias_ref() {
        // `#1000` in user-spec position is a UID reference, not a User_Alias ref.
        // visudo -c on `#1000 ALL = ALL` -> parsed OK (no User_Alias error).
        let files = parse_one("#1000 ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = e01(&files, &ctx);
        assert!(
            diags.is_empty(),
            "#1000 is a UID spec, not a User_Alias ref -> no E01; got {diags:?}"
        );
    }

    /// Grounded: `Cmnd_Alias SAFE_CMD = /bin/ls` + `alice ALL = SAFE_CMD` (alias name
    /// contains `_`). visudo -c: parsed OK (`SAFE_CMD` is defined and referenced -> no W03).
    ///
    /// Kills survivor: second `||` -> `&&` (between `is_ascii_digit()` and `c == '_'`).
    /// Under that mutant, `_` is no longer a valid tail char: `_`.`is_ascii_uppercase()`=false,
    /// the `&&` makes `c == '_'` unreachable. So `is_alias_ref("SAFE_CMD")` returns false ->
    /// `SAFE_CMD` is not recognized as referenced -> W03 fires spuriously.
    /// Also kills `== '_'` -> `!= '_'`: `_` would fail the inverted predicate -> same result.
    #[test]
    fn w03_alias_name_with_underscore_not_dead_when_referenced() {
        // SAFE_CMD contains '_' in its name: tests that '_' is accepted as a valid alias char.
        // visudo -c on this fixture: parsed OK (no W03).
        let files = parse_one("Cmnd_Alias SAFE_CMD = /bin/ls\nalice ALL = SAFE_CMD\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "SAFE_CMD is referenced -> not dead, no W03; got {diags:?}"
        );
    }

    /// Grounded: `User_Alias ADMIN_2 = alice` + `ADMIN_2 ALL = ALL`.
    /// visudo -c: parsed OK. `ADMIN_2` contains both `_` and a digit.
    /// `is_alias_ref("ADMIN_2")` must return true (first char uppercase, all tail
    /// chars are uppercase/digit/underscore).
    /// Kills survivor: second `||` -> `&&` and `== '_'` -> `!= '_'`: `_` and digit
    /// chars would fail recognition, causing W03 to fire spuriously for `ADMIN_2`.
    #[test]
    fn w03_alias_name_with_underscore_and_digit_not_dead_when_referenced() {
        // visudo -c: parsed OK (ADMIN_2 defined and referenced -> no W03).
        let files = parse_one("User_Alias ADMIN_2 = alice\nADMIN_2 ALL = ALL\n");
        let ctx = SudoersLintContext::default();
        let diags = w03(&files, &ctx);
        assert!(
            diags.is_empty(),
            "ADMIN_2 is referenced -> not dead, no W03; got {diags:?}"
        );
    }

    // ---- bounded-time: linear alias-graph walks on a long valid chain ----
    //
    // This test exists to PIN the LINEAR-time behavior of the two alias-graph walks:
    //   - `cmnd_aliases_expanding_to_all` (W02's backward expands-to-ALL worklist), and
    //   - `w03`'s forward reachability worklist.
    // Both were originally `while changed { for ..all-edges }` fixpoints that re-scan
    // the WHOLE edge map every pass -> O(V^2). On an adversarial-but-VALID chained
    // `Cmnd_Alias` file (`A0 = A1`, ..., `A_{n-1} = ALL`, head referenced under
    // NOPASSWD) the quadratic versions took seconds-to-minutes (N~4000 ~ 43s release)
    // while `visudo -c` parses it in ~20ms - a CPU-DoS on valid input. The linear
    // rewrites finish in milliseconds.
    //
    // There is deliberately NO `Instant`/timeout assertion (wall-clock asserts are
    // flaky in CI). The pin is structural: a quadratic impl at N=5000 would take
    // minutes and effectively hang the suite, so the test merely COMPLETING in the
    // normal run is the linear-time evidence. We also assert the OUTPUT is exactly
    // correct (one W02; zero W03 - every link is referenced down the chain, so none
    // is a dead alias), guarding against a "fast but wrong" regression.
    #[test]
    fn large_valid_alias_chain_lints_correctly_and_in_linear_time() {
        const N: usize = 5000;
        // Build `Cmnd_Alias A0 = A1`, `Cmnd_Alias A1 = A2`, ..., `A_{N-1} = ALL`,
        // then a user-spec granting NOPASSWD on the head alias A0. The whole chain
        // is VALID sudoers (each fixture shape is `visudo -c -f` rc 0, sudo 1.9.17p2):
        // A0 transitively expands to ALL via A1 -> A2 -> ... -> ALL.
        use std::fmt::Write as _;
        let mut src = String::new();
        for i in 0..N - 1 {
            writeln!(src, "Cmnd_Alias A{i} = A{}", i + 1).unwrap();
        }
        writeln!(src, "Cmnd_Alias A{} = ALL", N - 1).unwrap();
        src.push_str("bob ALL = NOPASSWD: A0\n");

        let files = parse_one(&src);
        let ctx = SudoersLintContext::default();

        // W02: exactly one finding - A0 (the only NOPASSWD-granted command) expands
        // to ALL through the whole chain.
        let w02_diags = crate::lints::tags::w02(&files, &ctx);
        let w02_count = w02_diags.iter().filter(|d| d.code == "sudo-W02").count();
        assert_eq!(
            w02_count, 1,
            "the head alias A0 expands to ALL via the chain -> exactly one W02; got {w02_diags:?}"
        );

        // W03: zero dead aliases - A0 is referenced from the user-spec and each Ai is
        // referenced as the member of A_{i-1}, so the whole chain is reachable.
        let w03_diags = w03(&files, &ctx);
        let w03_count = w03_diags.iter().filter(|d| d.code == "sudo-W03").count();
        assert_eq!(
            w03_count, 0,
            "every link in the chain is referenced -> no dead alias (no W03); got {w03_count} W03"
        );

        // E01 sanity: every referenced alias is defined -> no undefined-reference error.
        let e01_diags = e01(&files, &ctx);
        assert!(
            e01_diags.is_empty(),
            "all chain links are defined -> no E01; got {e01_diags:?}"
        );
    }

    // ---- joint: clean file produces neither E01 nor W03 ----

    #[test]
    fn clean_file_produces_no_e01_or_w03() {
        // All four alias kinds defined and referenced.
        let src = "\
User_Alias ADMINS = alice, bob\n\
Host_Alias WEBSERVERS = web1, web2\n\
Runas_Alias DBOPS = postgres\n\
Cmnd_Alias SAFETOOLS = /bin/ls, /bin/cat\n\
ADMINS WEBSERVERS = (DBOPS) SAFETOOLS\n";
        let files = parse_one(src);
        let ctx = SudoersLintContext::default();
        assert!(
            e01(&files, &ctx).is_empty(),
            "all aliases defined -> no E01"
        );
        assert!(
            w03(&files, &ctx).is_empty(),
            "all aliases referenced -> no W03"
        );
    }
}
