//! Pure trust-DB diff/stale computations, separated from the I/O orchestration in
//! [`super::fapolicyd`] so they can be unit-tested against exact expected output and
//! brought under the cargo-mutants net. Nothing here touches the filesystem or LMDB;
//! every function is a deterministic transform over already-read [`TrustEntry`] /
//! [`CheckRow`] values.

use std::collections::BTreeMap;

use rulesteward_fapolicyd::{TrustEntry, TrustSource};

use crate::output::trustdb::{CheckRow, DbDiffKind, DbDiffRow};

/// Stable total-order rank for [`TrustSource`], which is not `Ord` (it is a frozen
/// foundation type). Used only to give the per-path value multiset a deterministic
/// sort so an equal multiset compares equal regardless of insertion order.
pub(crate) fn source_rank(source: TrustSource) -> u8 {
    match source {
        TrustSource::Unknown => 0,
        TrustSource::RpmDb => 1,
        TrustSource::FileDb => 2,
        TrustSource::Deb => 3,
    }
}

/// Group trust-DB entries by path into a sorted multiset of `(source, size, digest)`
/// value-tuples per path, so a value difference on a shared path is detected without
/// spurious only-in-X rows.
pub(crate) fn group_by_path(
    entries: &[TrustEntry],
) -> BTreeMap<String, Vec<(TrustSource, u64, String)>> {
    let mut m: BTreeMap<String, Vec<(TrustSource, u64, String)>> = BTreeMap::new();
    for e in entries {
        m.entry(e.path.clone())
            .or_default()
            .push((e.source, e.size, e.digest.clone()));
    }
    for v in m.values_mut() {
        v.sort_by(|x, y| (source_rank(x.0), x.1, &x.2).cmp(&(source_rank(y.0), y.1, &y.2)));
    }
    m
}

/// Classify a DB-vs-DB diff. Union the paths of both grouped DBs (sorted, deduped);
/// for each path emit one [`DbDiffRow`]: only in `a` -> `OnlyInDb`, only in `b` ->
/// `OnlyInAgainst`, present in both but with a differing value-multiset ->
/// `ValueDiffers`. A path present in both with an equal multiset emits nothing.
pub(crate) fn compute_db_diff(a: &[TrustEntry], b: &[TrustEntry]) -> Vec<DbDiffRow> {
    let ga = group_by_path(a);
    let gb = group_by_path(b);

    let mut rows: Vec<DbDiffRow> = Vec::new();
    let mut paths: Vec<&String> = ga.keys().chain(gb.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        match (ga.get(path), gb.get(path)) {
            (Some(_), None) => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::OnlyInDb,
            }),
            (None, Some(_)) => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::OnlyInAgainst,
            }),
            (Some(va), Some(vb)) if va != vb => rows.push(DbDiffRow {
                path: path.clone(),
                kind: DbDiffKind::ValueDiffers,
            }),
            _ => {}
        }
    }
    rows
}

/// The stale rows of a verified check report: the rows whose verdict is a divergence
/// (anything other than `Match`). Order-preserving.
pub(crate) fn stale_rows(rows: Vec<CheckRow>) -> Vec<CheckRow> {
    rows.into_iter()
        .filter(|r| r.verdict.is_divergence())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::trustdb::CheckVerdict;

    fn entry(path: &str, source: TrustSource, size: u64, digest: &str) -> TrustEntry {
        TrustEntry {
            path: path.into(),
            source,
            size,
            digest: digest.into(),
        }
    }

    // ---- source_rank ---------------------------------------------------------

    #[test]
    fn source_rank_is_a_distinct_total_order() {
        // Each variant ranks distinctly so the per-path sort is a real total order;
        // a mutant collapsing two ranks would let an unequal multiset compare equal.
        let ranks = [
            source_rank(TrustSource::Unknown),
            source_rank(TrustSource::RpmDb),
            source_rank(TrustSource::FileDb),
            source_rank(TrustSource::Deb),
        ];
        assert_eq!(ranks, [0, 1, 2, 3], "each TrustSource must rank distinctly");
    }

    // ---- group_by_path -------------------------------------------------------

    #[test]
    fn group_by_path_collects_values_per_path_sorted_stably() {
        // Two entries on the same path, pushed in reverse rank order, must come back
        // sorted by (rank, size, digest) so multiset equality is insertion-order-free.
        let entries = vec![
            entry("/bin/ls", TrustSource::FileDb, 10, "bb"),
            entry("/bin/ls", TrustSource::RpmDb, 10, "aa"),
            entry("/bin/cat", TrustSource::RpmDb, 5, "cc"),
        ];
        let g = group_by_path(&entries);
        assert_eq!(g.len(), 2, "two distinct paths");
        assert_eq!(
            g["/bin/ls"],
            vec![
                (TrustSource::RpmDb, 10, "aa".to_string()),
                (TrustSource::FileDb, 10, "bb".to_string()),
            ],
            "values sorted by source_rank then size then digest"
        );
        assert_eq!(
            g["/bin/cat"],
            vec![(TrustSource::RpmDb, 5, "cc".to_string())]
        );
    }

    #[test]
    fn group_by_path_equal_multiset_regardless_of_insertion_order() {
        let a = vec![
            entry("/p", TrustSource::RpmDb, 1, "x"),
            entry("/p", TrustSource::FileDb, 2, "y"),
        ];
        let b = vec![
            entry("/p", TrustSource::FileDb, 2, "y"),
            entry("/p", TrustSource::RpmDb, 1, "x"),
        ];
        assert_eq!(
            group_by_path(&a)["/p"],
            group_by_path(&b)["/p"],
            "the same value-set in different insertion order must compare equal"
        );
    }

    // ---- compute_db_diff -----------------------------------------------------

    #[test]
    fn diff_only_in_db_when_path_absent_from_against() {
        let a = vec![entry("/only-a", TrustSource::RpmDb, 1, "h")];
        let b = vec![];
        assert_eq!(
            compute_db_diff(&a, &b),
            vec![DbDiffRow {
                path: "/only-a".into(),
                kind: DbDiffKind::OnlyInDb
            }]
        );
    }

    #[test]
    fn diff_only_in_against_when_path_absent_from_db() {
        let a = vec![];
        let b = vec![entry("/only-b", TrustSource::RpmDb, 1, "h")];
        assert_eq!(
            compute_db_diff(&a, &b),
            vec![DbDiffRow {
                path: "/only-b".into(),
                kind: DbDiffKind::OnlyInAgainst
            }]
        );
    }

    #[test]
    fn diff_value_differs_on_shared_path_with_different_digest() {
        let a = vec![entry("/p", TrustSource::RpmDb, 10, "aaa")];
        let b = vec![entry("/p", TrustSource::RpmDb, 10, "bbb")];
        assert_eq!(
            compute_db_diff(&a, &b),
            vec![DbDiffRow {
                path: "/p".into(),
                kind: DbDiffKind::ValueDiffers
            }]
        );
    }

    #[test]
    fn diff_value_differs_on_shared_path_with_different_size() {
        let a = vec![entry("/p", TrustSource::RpmDb, 10, "h")];
        let b = vec![entry("/p", TrustSource::RpmDb, 20, "h")];
        assert_eq!(
            compute_db_diff(&a, &b)[0].kind,
            DbDiffKind::ValueDiffers,
            "a size-only difference is still a value divergence"
        );
    }

    #[test]
    fn diff_identical_value_multiset_emits_no_row() {
        let a = vec![
            entry("/p", TrustSource::RpmDb, 1, "x"),
            entry("/p", TrustSource::FileDb, 2, "y"),
        ];
        // Same path, same two values, reversed insertion order -> equal -> no row.
        let b = vec![
            entry("/p", TrustSource::FileDb, 2, "y"),
            entry("/p", TrustSource::RpmDb, 1, "x"),
        ];
        assert_eq!(
            compute_db_diff(&a, &b),
            vec![],
            "an equal value multiset (any order) must not be reported as a diff"
        );
    }

    #[test]
    fn diff_unions_paths_sorted_and_deduped() {
        // /a only in db, /b shared+equal (no row), /c only in against, /d value-differs.
        let a = vec![
            entry("/a", TrustSource::RpmDb, 1, "h"),
            entry("/b", TrustSource::RpmDb, 2, "h"),
            entry("/d", TrustSource::RpmDb, 4, "old"),
        ];
        let b = vec![
            entry("/b", TrustSource::RpmDb, 2, "h"),
            entry("/c", TrustSource::RpmDb, 3, "h"),
            entry("/d", TrustSource::RpmDb, 4, "new"),
        ];
        assert_eq!(
            compute_db_diff(&a, &b),
            vec![
                DbDiffRow {
                    path: "/a".into(),
                    kind: DbDiffKind::OnlyInDb
                },
                DbDiffRow {
                    path: "/c".into(),
                    kind: DbDiffKind::OnlyInAgainst
                },
                DbDiffRow {
                    path: "/d".into(),
                    kind: DbDiffKind::ValueDiffers
                },
            ],
            "rows are path-sorted, /b (equal) is omitted, each path appears once"
        );
    }

    #[test]
    fn diff_two_dbs_equal_yields_empty() {
        let a = vec![entry("/p", TrustSource::RpmDb, 1, "h")];
        assert_eq!(compute_db_diff(&a, &a.clone()), vec![]);
    }

    // ---- stale_rows ----------------------------------------------------------

    #[test]
    fn stale_rows_keeps_divergences_drops_matches_preserving_order() {
        let rows = vec![
            CheckRow {
                path: "/clean".into(),
                verdict: CheckVerdict::Match,
            },
            CheckRow {
                path: "/gone".into(),
                verdict: CheckVerdict::Missing,
            },
            CheckRow {
                path: "/also-clean".into(),
                verdict: CheckVerdict::Match,
            },
            CheckRow {
                path: "/size".into(),
                verdict: CheckVerdict::SizeMismatch {
                    recorded: 1,
                    actual: 2,
                },
            },
        ];
        let stale = stale_rows(rows);
        assert_eq!(
            stale,
            vec![
                CheckRow {
                    path: "/gone".into(),
                    verdict: CheckVerdict::Missing
                },
                CheckRow {
                    path: "/size".into(),
                    verdict: CheckVerdict::SizeMismatch {
                        recorded: 1,
                        actual: 2
                    }
                },
            ],
            "only non-Match rows survive, in their original order"
        );
    }

    #[test]
    fn stale_rows_all_clean_yields_empty() {
        let rows = vec![CheckRow {
            path: "/a".into(),
            verdict: CheckVerdict::Match,
        }];
        assert!(stale_rows(rows).is_empty());
    }
}
