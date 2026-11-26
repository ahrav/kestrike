//! Window names distinguish boundaries and repeated occurrences of a site.
//! Fabricated ledgers isolate the effect of missing, failed or mismeasured cuts.

use super::census::rows;
use super::{Row, Status, census};
use crate::sim::cut::{Boundary, Class, Cut, Site, plan};
use crate::sim::ledger::{Activation, Checked, Entry, Evidence, event, rebuild};
use crate::sim::ledger_tests::{activation, complete, entries};
use crate::sim::recovery::Recovery;

fn row(rows: &[Row], name: &str) -> (Status, usize) {
    let row = rows.iter().find(|r| r.name == name).unwrap();
    (row.status, row.count)
}

fn only_submission_cut(table: &[Cut], boundary: Boundary) -> u32 {
    let mut matching = table.iter().enumerate().filter(|(_, c)| {
        (c.operation, c.site, c.occurrence, c.boundary, c.class)
            == (0, Site::Submission as u16, 0, boundary, Class::ProcessDeath)
    });
    let at = matching.next().unwrap().0;
    assert!(
        matching.next().is_none(),
        "one cut for {boundary:?}.ProcessDeath"
    );
    at as u32
}

#[test]
fn every_cut_has_one_named_row_and_absent_sites_follow_in_registry_order() {
    for (profile, cuts) in [
        (Recovery::Kib16, 4),
        (Recovery::Sector, 4),
        (Recovery::Torn, 20),
    ] {
        let table = profile.table();
        assert_eq!(table.len(), cuts, "{profile:?}");
        let ledger = rebuild(&complete(&table), cuts as u32).unwrap();
        let mut descriptor = profile.descriptor();
        descriptor.points.reverse();
        descriptor.classes.reverse();
        let actual = rows(&descriptor, &table, &ledger);
        let mut expected = Vec::new();
        let mut points = vec![
            (0, "accepted-submission"),
            (0, "qualified-persistence"),
            (0, "root-or-admission-publication"),
            (0, "recovery-mutation"),
        ];
        if profile != Recovery::Torn {
            points.push((1, "accepted-submission"));
        }
        for (op, site) in points {
            for side in ["before", "after"] {
                for class in ["ProcessDeath", "ControllerReset"] {
                    if class == "ControllerReset" && profile != Recovery::Torn {
                        continue;
                    }
                    let (status, count) = if site != "accepted-submission" {
                        (Status::NotRequired, 0)
                    } else {
                        (
                            Status::Covered,
                            if class == "ControllerReset" && side == "after" {
                                17
                            } else {
                                1
                            },
                        )
                    };
                    expected.push(Row {
                        name: format!("{op}.{site}.0.{side}.{class}"),
                        status,
                        count,
                    });
                }
            }
        }
        for (name, status) in [
            ("permitted-media-effect", Status::Unreached),
            ("completion-posting-and-delivery", Status::Unreached),
            ("protected-exclusion", Status::Undecided),
            ("first-successor-visibility", Status::Undecided),
            ("external-response-observation", Status::Unreached),
            ("reuse", Status::Unreached),
        ] {
            expected.push(Row {
                name: name.to_owned(),
                status,
                count: 0,
            });
        }
        assert_eq!(actual, expected, "{profile:?}");
        assert_eq!(census(profile, &ledger), expected, "{profile:?}");
        assert_eq!(
            actual.iter().map(|r| r.count).sum::<usize>(),
            cuts,
            "{profile:?}"
        );
    }
}

#[test]
fn only_checked_pass_with_the_planned_measurement_counts() {
    let profile = Recovery::Kib16;
    let table = profile.table();
    let at = only_submission_cut(&table, Boundary::After);
    let descriptor = profile.descriptor();
    let a = activation(&table[at as usize]);
    let pass = Some(Checked::Pass);
    let status = |events: &[crate::sim::trace::Event]| {
        let ledger = rebuild(events, table.len() as u32).unwrap();
        row(
            &rows(&descriptor, &table, &ledger),
            "0.accepted-submission.0.after.ProcessDeath",
        )
    };
    assert_eq!(status(&entries(at, a.clone(), pass)), (Status::Covered, 1));
    let cases = [
        ("missing Checked", a.clone(), None),
        ("Fail", a.clone(), Some(Checked::Fail)),
        (
            "Ambiguous",
            Activation {
                evidence: Evidence::Ambiguous,
                ..a.clone()
            },
            pass,
        ),
        (
            "Unmatched",
            Activation {
                evidence: Evidence::Unmatched,
                ..a.clone()
            },
            pass,
        ),
        (
            "wrong landing",
            Activation {
                landing: vec![0],
                ..a.clone()
            },
            pass,
        ),
        (
            "wrong class",
            Activation {
                class: Class::ControllerReset,
                ..a.clone()
            },
            pass,
        ),
        (
            "undrained",
            Activation {
                drained: false,
                ..a
            },
            pass,
        ),
    ];
    for (label, events) in cases
        .into_iter()
        .map(|(label, a, checked)| (label, entries(at, a, checked)))
        .chain([(
            "skipped",
            vec![event(at, &Entry::Planned), event(at, &Entry::Skipped)],
        )])
    {
        assert_eq!(status(&events), (Status::Gap, 0), "{label}");
    }
}

#[test]
fn a_required_window_without_a_cut_is_a_gap_and_one_landing_covers_a_multi_cut_row() {
    let profile = Recovery::Torn;
    let mut table = profile.table();
    let before = "0.accepted-submission.0.before.ProcessDeath";
    let descriptor = profile.descriptor();
    let all_pass = |table: &[Cut]| {
        rows(
            &descriptor,
            table,
            &rebuild(&complete(table), table.len() as u32).unwrap(),
        )
    };
    assert_eq!(row(&all_pass(&table), before), (Status::Covered, 1));
    let removed = only_submission_cut(&table, Boundary::Before);
    table.remove(removed as usize);
    assert_eq!(row(&all_pass(&table), before), (Status::Gap, 0));
    let in_row = |c: &Cut| {
        (c.operation, c.site, c.occurrence, c.class, c.boundary)
            == (
                0,
                Site::Submission as u16,
                0,
                Class::ControllerReset,
                Boundary::After,
            )
    };
    let first = table.iter().position(in_row).unwrap();
    let last = table.iter().rposition(in_row).unwrap();
    assert!(first < last);
    for at in [first, last] {
        let ledger = rebuild(
            &entries(at as u32, activation(&table[at]), Some(Checked::Pass)),
            table.len() as u32,
        )
        .unwrap();
        assert_eq!(
            row(
                &rows(&descriptor, &table, &ledger),
                "0.accepted-submission.0.after.ControllerReset"
            ),
            (Status::Covered, 1),
            "cut {at}"
        );
    }
}

#[test]
fn only_the_checked_occurrence_counts_at_a_repeated_site() {
    let profile = Recovery::Kib16;
    let mut descriptor = profile.descriptor();
    let table = profile.table();
    let base = table[only_submission_cut(&table, Boundary::Before) as usize].clone();
    let mut repeated = descriptor
        .points
        .iter()
        .find(|p| p.identity() == (base.operation, base.site, 0))
        .unwrap()
        .clone();
    repeated.occurrence = 1;
    descriptor.points.insert(0, repeated);
    let table = plan(
        &descriptor,
        &[
            Cut {
                occurrence: 1,
                ..base.clone()
            },
            base,
        ],
    )
    .unwrap();
    let at = table.iter().position(|c| c.occurrence == 1).unwrap();
    let ledger = rebuild(
        &entries(at as u32, activation(&table[at]), Some(Checked::Pass)),
        table.len() as u32,
    )
    .unwrap();
    let listed = rows(&descriptor, &table, &ledger);
    let before: Vec<_> = listed
        .iter()
        .filter(|r| {
            r.name.starts_with("0.accepted-submission.") && r.name.ends_with(".before.ProcessDeath")
        })
        .map(|r| (r.name.as_str(), r.status, r.count))
        .collect();
    assert_eq!(
        before,
        [
            (
                "0.accepted-submission.0.before.ProcessDeath",
                Status::Gap,
                0
            ),
            (
                "0.accepted-submission.1.before.ProcessDeath",
                Status::Covered,
                1
            )
        ]
    );
}
