//! The stage ledger: entries round-trip through `LEDGER` events, stage
//! order is enforced, and a campaign credits only when every required cut
//! is checked Pass and the Restart obligation fired.

use crate::oracle::Obligation;

use super::cut::{Child, Class, Cut, Descriptor, Point, Reach, Site, State, Unit, enumerate};
use super::ledger::{
    Activation, Checked, Entry, Evidence, Gap, LEDGER, LedgerError, Stage, credit, event, rebuild,
};
use super::trace::Event;

/// A descriptor with one submission-site point, plus an exclusion-site
/// point when `undecided`, under process death.
fn descriptor(undecided: bool) -> Descriptor {
    let child = Child {
        lba: 0,
        blocks: 1,
        state: State::Outstanding,
    };
    let point = |operation, site: Site, after: &[Child]| Point {
        operation,
        site: site as u16,
        occurrence: 0,
        before: Vec::new(),
        after: after.to_vec(),
    };
    let mut reach = vec![Reach {
        site: Site::Submission as u16,
        required: true,
    }];
    let mut points = vec![point(0, Site::Submission, &[child])];
    if undecided {
        reach.push(Reach {
            site: Site::Exclusion as u16,
            required: true,
        });
        points.push(point(1, Site::Exclusion, &[]));
    }
    Descriptor {
        unit: Unit::Sector,
        classes: vec![Class::ProcessDeath],
        reach,
        points,
        bound: 16,
    }
}

pub(super) fn activation(cut: &Cut) -> Activation {
    Activation {
        landing: cut.mask.clone(),
        drained: true,
        held: 1,
        class: cut.class,
        queue: 2,
        evidence: Evidence::Attributed,
    }
}

pub(super) fn entries(at: u32, activation: Activation, checked: Option<Checked>) -> Vec<Event> {
    [
        Entry::Planned,
        Entry::Reached {
            queue: activation.queue,
        },
        Entry::Activated(activation),
        Entry::Recovered,
    ]
    .into_iter()
    .chain(checked.map(Entry::Checked))
    .map(|entry| event(at, &entry))
    .collect()
}

/// Every stage of every cut of `table`, in order, each check passing.
pub(super) fn complete(table: &[Cut]) -> Vec<Event> {
    table
        .iter()
        .enumerate()
        .flat_map(|(at, cut)| entries(at as u32, activation(cut), Some(Checked::Pass)))
        .collect()
}

#[test]
fn entries_round_trip_through_ledger_events() {
    let table = enumerate(&descriptor(false)).unwrap();
    let events = complete(&table);
    assert!(events.iter().all(|event| event.kind == LEDGER));
    let ledger = rebuild(&events, table.len() as u32).unwrap();
    assert_eq!(ledger.cuts.len(), table.len());
    for (at, cut) in table.iter().enumerate() {
        let progress = &ledger.cuts[&(at as u32)];
        assert_eq!(
            progress.stages,
            [
                Stage::Planned,
                Stage::Reached,
                Stage::Activated,
                Stage::Recovered,
                Stage::Checked
            ]
        );
        assert_eq!(progress.checked, Some(Checked::Pass));
        let activation = progress.activation.as_ref().unwrap();
        assert_eq!(
            (activation.landing.clone(), activation.class),
            (cut.mask.clone(), cut.class)
        );
        assert_eq!((activation.held, activation.queue), (1, 2));
        assert_eq!(
            (activation.drained, activation.evidence),
            (true, Evidence::Attributed)
        );
    }
    for (drained, evidence) in [
        (false, Evidence::Attributed),
        (true, Evidence::Ambiguous),
        (false, Evidence::Unmatched),
    ] {
        let entry = Entry::Activated(Activation {
            landing: vec![0, u64::MAX],
            drained,
            held: 3,
            class: Class::ControllerReset,
            queue: 4,
            evidence,
        });
        let events = [
            event(0, &Entry::Planned),
            event(0, &Entry::Reached { queue: 4 }),
            event(0, &entry),
        ];
        let rebuilt = rebuild(&events, table.len() as u32).unwrap();
        assert_eq!(
            Entry::Activated(rebuilt.cuts[&0].activation.clone().unwrap()),
            entry
        );
    }
}

/// A stage before its predecessor, a repeated stage, a stage after a
/// skip, a skip after a check, a check without an activation, an unknown
/// cut, an unknown stage or class code and a landing longer than the
/// payload each refuse the rebuild.
#[test]
fn the_ledger_refuses_out_of_order_and_unknown_entries() {
    let table = enumerate(&descriptor(false)).unwrap();
    let cuts = table.len() as u32;
    let order = |stage| Err(LedgerError::Order { cut: 0, stage });
    let at = |entries: &[Entry]| {
        let events: Vec<Event> = entries.iter().map(|entry| event(0, entry)).collect();
        rebuild(&events, cuts)
    };
    assert_eq!(at(&[Entry::Reached { queue: 2 }]), order(Stage::Reached));
    assert_eq!(at(&[Entry::Planned, Entry::Planned]), order(Stage::Planned));
    assert_eq!(
        at(&[
            Entry::Planned,
            Entry::Reached { queue: 2 },
            Entry::Checked(Checked::Pass)
        ]),
        order(Stage::Checked)
    );
    assert_eq!(
        at(&[Entry::Planned, Entry::Skipped, Entry::Reached { queue: 2 }]),
        order(Stage::Reached)
    );
    assert_eq!(
        at(&[
            Entry::Planned,
            Entry::Reached { queue: 2 },
            Entry::Activated(activation(&table[0])),
            Entry::Recovered,
            Entry::Checked(Checked::Pass),
            Entry::Skipped
        ]),
        order(Stage::Skipped)
    );
    assert!(at(&[Entry::Planned, Entry::Reached { queue: 2 }, Entry::Skipped]).is_ok());
    assert_eq!(
        rebuild(&[event(cuts, &Entry::Planned)], cuts),
        Err(LedgerError::Unknown { cut: cuts })
    );
    let malformed = |edit: fn(&mut Event)| {
        let mut events: Vec<Event> = [Entry::Planned, Entry::Reached { queue: 2 }]
            .iter()
            .map(|entry| event(0, entry))
            .collect();
        events.push(event(0, &Entry::Activated(activation(&table[0]))));
        events.push(event(0, &Entry::Recovered));
        events.push(event(0, &Entry::Checked(Checked::Pass)));
        edit(&mut events[2]);
        edit(&mut events[4]);
        rebuild(&events, cuts)
    };
    let unknown_stage: fn(&mut Event) = |event| event.payload[0] = 7;
    let unknown_code: fn(&mut Event) = |event| event.payload[5] = 9;
    let unknown_evidence: fn(&mut Event) = |event| {
        if event.payload[0] == Stage::Activated as u8 {
            event.payload[11] = 3 << 1;
        }
    };
    let long_landing: fn(&mut Event) = |event| {
        if event.payload[0] == Stage::Activated as u8 {
            event.payload[10] = u8::MAX;
        }
    };
    assert_eq!(
        malformed(unknown_stage),
        Err(LedgerError::Malformed { at: 2 })
    );
    assert_eq!(
        malformed(unknown_code),
        Err(LedgerError::Malformed { at: 2 })
    );
    assert_eq!(
        malformed(long_landing),
        Err(LedgerError::Malformed { at: 2 })
    );
    assert_eq!(
        malformed(unknown_evidence),
        Err(LedgerError::Malformed { at: 2 })
    );
}

/// A ledger whose activations record an inverted landing, the class
/// `ControllerReset` against a prescribed `ProcessDeath`, an undrained
/// queue, or an ambiguous or unmatched comparison withholds credit through
/// each one's gap, naming the first required cut it affects.
#[test]
fn a_measurement_other_than_the_plan_withholds_credit() {
    let descriptor = descriptor(false);
    let table = enumerate(&descriptor).unwrap();
    let cuts = table.len() as u32;
    let judged = |edit: &dyn Fn(&mut Activation)| {
        let mut events = Vec::new();
        for (at, cut) in table.iter().enumerate() {
            let mut activation = activation(cut);
            edit(&mut activation);
            events.extend(entries(at as u32, activation, Some(Checked::Pass)));
        }
        credit(&rebuild(&events, cuts).unwrap(), &table, &descriptor, true)
    };
    assert_eq!(judged(&|_| {}), Ok(()));
    let inverted = |a: &mut Activation| a.landing.iter_mut().for_each(|word| *word = !*word);
    let first = |gap: fn(u32) -> Gap| Err(gap(0));
    // Cut 0 holds no child, so its landing inverts to itself; cut 1 lands one.
    assert!(table[0].mask.is_empty() && !table[1].mask.is_empty());
    assert_eq!(judged(&inverted), Err(Gap::Landing { cut: 1 }));
    assert_eq!(
        judged(&|a| a.class = Class::ControllerReset),
        first(|cut| Gap::Class { cut })
    );
    assert_eq!(
        judged(&|a| a.drained = false),
        first(|cut| Gap::Undrained { cut })
    );
    assert_eq!(
        judged(&|a| a.evidence = Evidence::Ambiguous),
        first(|cut| Gap::Ambiguous { cut })
    );
    assert_eq!(
        judged(&|a| a.evidence = Evidence::Unmatched),
        first(|cut| Gap::Unmatched { cut })
    );
    assert_eq!(
        judged(&|a| {
            inverted(a);
            a.class = Class::ControllerReset;
            a.drained = false;
        }),
        Err(Gap::Class { cut: 0 })
    );
}

/// A complete ledger with the Restart obligation fired credits; each
/// missing piece withholds credit by its own gap, naming the cut.
#[test]
fn a_campaign_credits_only_every_required_cut_checked_pass_with_restart() {
    let descriptor = descriptor(false);
    let table = enumerate(&descriptor).unwrap();
    let cuts = table.len() as u32;
    let events = complete(&table);
    let judged = |events: &[Event], restart| {
        credit(
            &rebuild(events, cuts).unwrap(),
            &table,
            &descriptor,
            restart,
        )
    };
    assert_eq!(judged(&events, true), Ok(()));
    assert_eq!(judged(&events, false), Err(Gap::NoRestart));
    let without = |stage: Stage| -> Vec<Event> {
        let at = events
            .iter()
            .position(|event| event.payload[0] == stage as u8 && event.payload[1] == 1)
            .unwrap();
        events[..at]
            .iter()
            .chain(events[at..].iter().filter(|event| event.payload[1] != 1))
            .cloned()
            .collect()
    };
    assert_eq!(
        judged(&without(Stage::Planned), true),
        Err(Gap::Omitted { cut: 1 })
    );
    assert_eq!(
        judged(&without(Stage::Reached), true),
        Err(Gap::Unreached { cut: 1 })
    );
    assert_eq!(
        judged(&without(Stage::Recovered), true),
        Err(Gap::Unchecked { cut: 1 })
    );
    let mut failed = events.clone();
    let last = failed.len() - 1;
    failed[last] = event(1, &Entry::Checked(Checked::Fail));
    assert_eq!(judged(&failed, true), Err(Gap::Failed { cut: 1 }));
    let mut skipped = without(Stage::Reached);
    skipped.push(event(1, &Entry::Skipped));
    assert_eq!(judged(&skipped, true), Err(Gap::Bound { cut: 1 }));
}

/// A required cut at an undecided site stays Inconclusive by name even
/// when checked Pass, and the obligation masks
/// keep eight bits with no stage among them.
#[test]
fn an_undecided_site_cut_is_inconclusive_and_the_masks_keep_eight_bits() {
    let descriptor = descriptor(true);
    let table = enumerate(&descriptor).unwrap();
    let ledger = rebuild(&complete(&table), table.len() as u32).unwrap();
    let undecided = table
        .iter()
        .position(|cut| cut.site == Site::Exclusion as u16)
        .unwrap() as u32;
    assert_eq!(
        credit(&ledger, &table, &descriptor, true),
        Err(Gap::Undecided { cut: undecided })
    );
    assert_eq!(Obligation::ALL.len(), 8);
}

/// A second cut reached while another reached cut has not ended refuses
/// the ledger.
#[test]
fn cuts_run_one_at_a_time() {
    let descriptor = descriptor(false);
    let table = enumerate(&descriptor).unwrap();
    let cuts = table.len() as u32;
    let interleaved = [
        event(0, &Entry::Planned),
        event(1, &Entry::Planned),
        event(0, &Entry::Reached { queue: 0 }),
        event(1, &Entry::Reached { queue: 0 }),
    ];
    assert_eq!(
        rebuild(&interleaved, cuts),
        Err(LedgerError::Order {
            cut: 1,
            stage: Stage::Reached
        })
    );
}
