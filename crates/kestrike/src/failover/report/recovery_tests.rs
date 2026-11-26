//! The report tests cover refusals returned by `Restart::run` and `Takeover::run` and refusals constructed from check
//! variants.

use super::*;
use crate::failover::admission::AdmissionError;
use crate::failover::report::tests::bare;
use crate::failover::report::{RecordedRole, VolumeEntry};
use crate::failover::restart::tests::{self as restart_tests, Card, sample, shard_record};
use crate::failover::restart::{Driver, Failed, Local};
use crate::failover::retire::{Target, Trigger};
use crate::failover::takeover::tests::{
    self as takeover_tests, a_holds_c_registered, c_host, c_pair, stored_c, takeover_of, with_c,
};
use crate::net::ownership::session_of;
use crate::storage::SessionRefusal;
use crate::storage::store::Refusal;
use crate::storage::store::sim::Arm;
use crate::storage::store_tests::client;

/// The entry `recovery` fills encodes and decodes to itself, so the field rules accept it.
#[track_caller]
fn round_trips(recovery: Recovery) {
    let entry = VolumeEntry {
        recovery,
        ..bare("vol-0123456789abcdef0", RecordedRole::Owner)
    };
    assert_eq!(
        VolumeEntry::decode(&entry.encode().unwrap()),
        Ok(entry),
        "{recovery:?}"
    );
}

fn reported_refusal(kind: RecoveryKind, refusal: RecoveryRefusal) -> Recovery {
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(kind, 100);
    status.refuse(refusal);
    let recovery = status.recovery(150);
    round_trips(recovery);
    recovery
}

/// `name` treats the first word of a check's or label's `Debug` text as the variant name.
fn name(value: &dyn core::fmt::Debug) -> String {
    let text = format!("{value:?}");
    text.split(|c: char| !c.is_alphanumeric())
        .next()
        .unwrap()
        .to_owned()
}

/// A takeover whose compare-and-swap reply is lost, whether or not the write committed, reads the takeover check,
/// the unknown store class and the same-host restart its `Takeover::next` names, and the reply authorized no device
/// command. The acknowledged twin reads a completed takeover with no check, next step or store class.
#[test]
fn a_takeover_write_with_a_lost_reply_shows_unknown_and_restart() {
    let faults = crate::storage::store_tests::UNKNOWN.map(Some);
    for fault in faults.into_iter().chain([None]) {
        let lost = fault.is_some();
        let store = restart_tests::store(takeover_tests::shard_record(), with_c());
        let path = takeover_of(&store, c_host());
        if let Some(fault) = fault {
            for arm in [Arm::Pass, Arm::Pass, fault] {
                store.schedule(arm);
            }
        }
        let mut card = takeover_tests::Card::new(c_pair(), &a_holds_c_registered());
        let mut status = RecoveryStatus::NO_ATTEMPT;
        status.start(RecoveryKind::Takeover, 10);
        match path.run(&mut client(&store), &stored_c(), &mut card) {
            Ok(_) => status.complete(),
            Err(refused) => {
                assert!(matches!(path.next(&refused), takeover::Next::Restart(_)));
                status.refuse(RecoveryRefusal::from(&refused));
            }
        }
        let recovery = status.recovery(25);
        round_trips(recovery);
        let (outcome, check, next, store_class) = if lost {
            assert!(
                card.log.is_empty(),
                "the lost reply authorized {:?}",
                card.log
            );
            (
                RecoveryOutcome::Refused,
                Some(RecoveryCheck::TakeOver),
                Some(RecoveryNext::Restart),
                Some(StoreClass::Unknown),
            )
        } else {
            (RecoveryOutcome::Completed, None, None, None)
        };
        assert_eq!(
            recovery,
            Recovery {
                kind: Some(RecoveryKind::Takeover),
                outcome: Some(outcome),
                check,
                next,
                store: store_class,
                attempts: Some(1),
                age_us: Some(15),
            },
            "{fault:?}"
        );
    }
}

/// A takeover of a stale nomination refuses before its compare-and-swap and stops.
#[test]
fn a_stale_takeover_stops() {
    let store = restart_tests::store(takeover_tests::shard_record(), with_c());
    let stale = Target {
        attempts: takeover_tests::shard_record().attempts - 1,
        ..Target::of(&takeover_tests::shard_record())
    };
    let path = takeover_tests::takeover(stale, c_host());
    let mut card = takeover_tests::Card::new(c_pair(), &a_holds_c_registered());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    let recovery = reported_refusal(RecoveryKind::Takeover, RecoveryRefusal::from(&refused));
    assert_eq!(
        (recovery.check, recovery.next, recovery.store),
        (Some(RecoveryCheck::Stale), Some(RecoveryNext::Stop), None)
    );
}

/// A replay and a refusal naming a recovery tenure read `Restart`, as `Takeover::next` returns the restart for them,
/// and a refusal before the compare-and-swap reads `Stop`.
#[test]
fn takeover_next_steps_follow_the_restart_rule() {
    let target = Target::of(&takeover_tests::shard_record());
    let path = takeover_tests::takeover(target, c_host());
    let rows = [
        (takeover::Check::Restart, None, RecoveryNext::Restart),
        (
            takeover::Check::Records(StoreError::Unavailable),
            None,
            RecoveryNext::Stop,
        ),
        (
            takeover::Check::Records(StoreError::Unavailable),
            Some(target),
            RecoveryNext::Restart,
        ),
        (takeover::Check::Stale, None, RecoveryNext::Stop),
    ];
    for (check, recovery, expected) in rows {
        let refused = takeover::Refused { check, recovery };
        let reported = reported_refusal(RecoveryKind::Takeover, RecoveryRefusal::from(&refused));
        assert_eq!(reported.next, Some(expected), "{refused:?}");
        assert_eq!(
            matches!(path.next(&refused), takeover::Next::Restart(_)),
            expected == RecoveryNext::Restart,
            "{refused:?}"
        );
    }
}

/// Restart refusals read the next step their refusal names: an unavailable record read stops with the unavailable
/// class, exhausted counters request the flip, a failed ready wait holds, and a bump with a lost reply holds with
/// the unknown class.
#[test]
fn restart_refusals_read_their_check_store_class_and_next_step() {
    type Setup = fn(&crate::storage::store::sim::Shared, &mut Card);
    type Row = (
        &'static str,
        u32,
        Setup,
        RecoveryCheck,
        RecoveryNext,
        Option<StoreClass>,
    );
    let rows: [Row; 4] = [
        (
            "unavailable read",
            4,
            |store, _| store.schedule(Arm::Unavailable),
            RecoveryCheck::Records,
            RecoveryNext::Stop,
            Some(StoreClass::Unavailable),
        ),
        (
            "exhausted",
            crate::failover::records::ATTEMPTS_MAX,
            |_, _| {},
            RecoveryCheck::Exhausted,
            RecoveryNext::Flip,
            None,
        ),
        (
            "ready",
            4,
            |_, card| card.stop_at = Some(1),
            RecoveryCheck::Ready,
            RecoveryNext::Hold,
            None,
        ),
        (
            "lost bump reply",
            4,
            |store, _| {
                // The volume read, the shard read and the volume reread after Report #1 precede the bump.
                for arm in [
                    Arm::Pass,
                    Arm::Pass,
                    Arm::Pass,
                    Arm::Timeout { commit: false },
                ] {
                    store.schedule(arm);
                }
            },
            RecoveryCheck::Bump,
            RecoveryNext::Hold,
            Some(StoreClass::Unknown),
        ),
    ];
    for (row, attempts, setup, check, next, store_class) in rows {
        let store = restart_tests::store(shard_record(attempts), restart_tests::volume_record());
        let mut card = Card::new();
        setup(&store, &mut card);
        let refused = restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        let recovery = reported_refusal(RecoveryKind::Restart, RecoveryRefusal::from(&refused));
        assert_eq!(
            (recovery.check, recovery.next, recovery.store),
            (Some(check), Some(next), store_class),
            "{row}: {refused:?}"
        );
    }
    let target = Target::of(&shard_record(4));
    for (local, flip, next) in [
        (Local::Retained, Some(target), RecoveryNext::Flip),
        (Local::Absent, None, RecoveryNext::Stop),
    ] {
        let refused = restart::Refused {
            check: restart::Check::Local(local),
            flip,
            recovery: None,
        };
        let recovery = reported_refusal(RecoveryKind::Restart, RecoveryRefusal::from(&refused));
        assert_eq!(
            (recovery.check, recovery.next),
            (Some(RecoveryCheck::Local), Some(next)),
            "{refused:?}"
        );
    }
    let store = restart_tests::store(shard_record(4), restart_tests::volume_record());
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(RecoveryKind::Restart, 10);
    restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut Card::new())
        .unwrap();
    status.complete();
    let completed = status.recovery(30);
    round_trips(completed);
    assert_eq!(
        completed,
        Recovery {
            kind: Some(RecoveryKind::Restart),
            outcome: Some(RecoveryOutcome::Completed),
            attempts: Some(1),
            age_us: Some(20),
            ..Recovery::UNAVAILABLE
        }
    );
}

/// When a fresh refusal requests a flip, the report names the flip as the next step. Without a flip, a refusal of
/// `Restart` or one after the acknowledged bump names the same-host restart, and each refusal before the bump names
/// a stop. `Superseded` names a stop too, directly and under a failed retention release: its Confirm reread showed
/// the shard record naming another tenure or active volume, so the next start runs no same-host restart of this
/// volume. A coverage page fenced by a later tenure's activated session shows the same and names a stop, while a
/// fence above the own session that no tenure can activate (an exhausted generation, a candidate epoch) is page
/// damage and keeps the restart, as a malformed page does. A retention failure after a lost bump reply reports its
/// own label, its original's unknown class and its flip request.
#[test]
fn fresh_refusals_read_their_check_store_class_and_next_step() {
    let after_bump = [
        "HostId",
        "Register",
        "Acquire",
        "Report",
        "NotSole",
        "Hold",
        "Write",
        "Read",
        "Activation",
        "Confirm",
        "Named",
        "Fencing",
        "Fence",
        "UnresolvedPage",
        "Release",
        "Retention",
    ];
    let target = Target::of(&shard_record(0));
    for (check, _) in fresh_checks(DIRECT[0], TERMINAL[0]) {
        let variant = name(&check);
        let expected = if variant == "Restart" || after_bump.contains(&variant.as_str()) {
            RecoveryNext::Restart
        } else {
            RecoveryNext::Stop
        };
        for (flip, next) in [(None, expected), (Some(target), RecoveryNext::Flip)] {
            let recovery = reported_refusal(
                RecoveryKind::Fresh,
                RecoveryRefusal::from(&fresh::Refused {
                    check: check.clone(),
                    flip,
                }),
            );
            assert_eq!(recovery.next, Some(next), "{check:?} {flip:?}");
            assert_eq!(name(&recovery.check.unwrap()), variant, "{flip:?}");
        }
    }
    let unreleased = |original| fresh::Refused {
        check: fresh::Check::Retention {
            original: Box::new(original),
            error: AdmissionError::Record,
        },
        flip: None,
    };
    let generation = shard_record(0).generation.get() as u32;
    let fenced = |fence| fresh::Check::Fence(Withdraw::NewerFence { page: 0, fence });
    let successor = fenced(session_of(generation, 200));
    let damaged = [
        fenced(u64::MAX),
        fenced(session_of(u32::MAX, 2)),
        fenced(session_of(generation, 3)),
    ];
    let mut rows = vec![
        (fresh::Check::Superseded, RecoveryNext::Stop),
        (successor.clone(), RecoveryNext::Stop),
        (
            fresh::Check::Fence(Withdraw::Malformed { page: 0 }),
            RecoveryNext::Restart,
        ),
    ];
    rows.extend(damaged.map(|check| (check, RecoveryNext::Restart)));
    for (original, next) in rows {
        let label = RecoveryCheck::from(&original);
        let wrapped = unreleased(original.clone());
        let nested = unreleased(wrapped.check.clone());
        let bare = fresh::Refused {
            check: original,
            flip: None,
        };
        for (refused, check) in [
            (bare, label),
            (wrapped, RecoveryCheck::Retention),
            (nested, RecoveryCheck::Retention),
        ] {
            let recovery = reported_refusal(RecoveryKind::Fresh, RecoveryRefusal::from(&refused));
            assert_eq!(
                (recovery.check, recovery.next, recovery.store),
                (Some(check), Some(next), None),
                "{refused:?}"
            );
        }
    }
    let flipped = reported_refusal(
        RecoveryKind::Fresh,
        RecoveryRefusal::from(&fresh::Refused {
            check: successor,
            flip: Some(target),
        }),
    );
    assert_eq!(flipped.next, Some(RecoveryNext::Flip));
    let retained = fresh::Refused {
        check: fresh::Check::Retention {
            original: Box::new(fresh::Check::Bump(StoreError::Unknown)),
            error: AdmissionError::Record,
        },
        flip: Some(target),
    };
    let recovery = reported_refusal(RecoveryKind::Fresh, RecoveryRefusal::from(&retained));
    assert_eq!(
        (recovery.check, recovery.next, recovery.store),
        (
            Some(RecoveryCheck::Retention),
            Some(RecoveryNext::Flip),
            Some(StoreClass::Unknown)
        )
    );
    let constructed = fresh::Refused {
        check: fresh::Check::Retention {
            original: Box::new(fresh::Check::Bump(StoreError::Refused(Refusal::Condition))),
            error: AdmissionError::Record,
        },
        flip: None,
    };
    let recovery = reported_refusal(RecoveryKind::Fresh, RecoveryRefusal::from(&constructed));
    assert_eq!(
        (recovery.check, recovery.next, recovery.store),
        (
            Some(RecoveryCheck::Retention),
            Some(RecoveryNext::Stop),
            Some(StoreClass::Refused)
        )
    );
}

/// The initial status contains only an attempt count of zero. Each `start` increments the count until it reaches
/// `u32::MAX` and replaces the last attempt; `complete` and `refuse` change only a running attempt; and an age read
/// before the start is absent.
#[test]
fn the_status_counts_attempts_and_keeps_the_last_outcome() {
    let target = Target::of(&shard_record(0));
    let bump = RecoveryRefusal::from(&fresh::Refused {
        check: fresh::Check::Bump(StoreError::Unknown),
        flip: Some(target),
    });
    let stale = RecoveryRefusal::from(&takeover::Refused {
        check: takeover::Check::Stale,
        recovery: None,
    });
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.complete();
    status.refuse(bump);
    assert_eq!(status, RecoveryStatus::NO_ATTEMPT);
    let idle = status.recovery(5);
    assert_eq!(
        idle,
        Recovery {
            attempts: Some(0),
            ..Recovery::UNAVAILABLE
        }
    );
    round_trips(idle);
    status.start(RecoveryKind::Restart, 10);
    let running = status.recovery(12);
    let early = status.recovery(9);
    assert_eq!(
        (running.kind, running.outcome, running.age_us),
        (
            Some(RecoveryKind::Restart),
            Some(RecoveryOutcome::Running),
            Some(2)
        )
    );
    assert_eq!(
        early,
        Recovery {
            age_us: None,
            ..running
        }
    );
    round_trips(running);
    round_trips(early);
    status.complete();
    status.refuse(bump);
    let completed = status.recovery(30);
    assert_eq!(
        completed,
        Recovery {
            outcome: Some(RecoveryOutcome::Completed),
            age_us: Some(20),
            ..running
        }
    );
    round_trips(completed);
    status.start(RecoveryKind::Fresh, 40);
    status.refuse(bump);
    let refused = status.recovery(50);
    status.complete();
    status.refuse(stale);
    assert_eq!(status.recovery(50), refused);
    assert_eq!(
        refused,
        Recovery {
            kind: Some(RecoveryKind::Fresh),
            outcome: Some(RecoveryOutcome::Refused),
            check: Some(RecoveryCheck::Bump),
            next: Some(RecoveryNext::Flip),
            store: Some(StoreClass::Unknown),
            attempts: Some(2),
            age_us: Some(10),
        }
    );
    round_trips(refused);
    status.start(RecoveryKind::Takeover, 60);
    status.start(RecoveryKind::Restart, 70);
    let replaced = status.recovery(75);
    assert_eq!(
        replaced,
        Recovery {
            kind: Some(RecoveryKind::Restart),
            outcome: Some(RecoveryOutcome::Running),
            attempts: Some(4),
            age_us: Some(5),
            ..Recovery::UNAVAILABLE
        }
    );
    round_trips(replaced);
    let mut full = RecoveryStatus {
        attempts: u32::MAX,
        last: None,
    };
    full.start(RecoveryKind::Takeover, 0);
    let saturated = full.recovery(0);
    assert_eq!(
        saturated,
        Recovery {
            kind: Some(RecoveryKind::Takeover),
            outcome: Some(RecoveryOutcome::Running),
            attempts: Some(u32::MAX),
            age_us: Some(0),
            ..Recovery::UNAVAILABLE
        }
    );
    round_trips(saturated);
}

#[test]
fn each_check_variant_reads_the_label_of_its_name() {
    let mut labels = Vec::new();
    for (direct, terminal) in DIRECT.into_iter().zip(TERMINAL) {
        let carriers = [
            census(
                restart_checks(direct, terminal),
                |check| {
                    RecoveryRefusal::from(&restart::Refused {
                        check: check.clone(),
                        flip: None,
                        recovery: None,
                    })
                },
                |check| RecoveryCheck::from(check),
                &mut labels,
            ),
            census(
                takeover_checks(direct, terminal),
                |check| {
                    RecoveryRefusal::from(&takeover::Refused {
                        check: check.clone(),
                        recovery: None,
                    })
                },
                |check| RecoveryCheck::from(check),
                &mut labels,
            ),
            census(
                fresh_checks(direct, terminal),
                |check| {
                    RecoveryRefusal::from(&fresh::Refused {
                        check: check.clone(),
                        flip: None,
                    })
                },
                |check| RecoveryCheck::from(check),
                &mut labels,
            ),
        ];
        assert_eq!(carriers, [3, 3, 6], "rows carrying a store error");
    }
    for label in super::super::CHECKS {
        assert!(labels.contains(label), "{label:?} has no producing check");
    }
}

fn census<C: core::fmt::Debug>(
    rows: Vec<(C, Option<StoreClass>)>,
    refusal: impl Fn(&C) -> RecoveryRefusal,
    label: impl Fn(&C) -> RecoveryCheck,
    labels: &mut Vec<RecoveryCheck>,
) -> usize {
    let mut carriers = 0;
    for (check, class) in rows {
        let converted = refusal(&check);
        assert_eq!(name(&converted.check), name(&check), "{check:?}");
        assert_eq!(name(&label(&check)), name(&check), "{check:?}");
        assert_eq!(converted.store, class, "{check:?}");
        carriers += usize::from(class.is_some());
        labels.push(converted.check);
    }
    carriers
}

type Carried = (StoreError, StoreClass);

const DIRECT: [Carried; 2] = [
    (StoreError::Unavailable, StoreClass::Unavailable),
    (StoreError::Unknown, StoreClass::Unknown),
];

const TERMINAL: [Carried; 2] = [
    (
        StoreError::Codec(crate::failover::records::CodecError::Length),
        StoreClass::Codec,
    ),
    (StoreError::Refused(Refusal::Denied), StoreClass::Refused),
];

fn restart_checks(
    (store, class): Carried,
    (fence, fenced): Carried,
) -> Vec<(restart::Check, Option<StoreClass>)> {
    use crate::storage::page_coverage::FencingRefusal;
    let failed = Failed(None);
    vec![
        (restart::Check::Records(store), Some(class)),
        (restart::Check::Deposed, None),
        (restart::Check::RecordedHolder, None),
        (restart::Check::Unheld, None),
        (restart::Check::Fresh, None),
        (restart::Check::Volume(Trigger::Activation), None),
        (
            restart::Check::Exhausted(SessionRefusal::AttemptsExhausted),
            None,
        ),
        (restart::Check::SuffixOnly, None),
        (restart::Check::Local(Local::Absent), None),
        (restart::Check::Driver(Driver::LiveQueues), None),
        (restart::Check::Ready(failed), None),
        (restart::Check::HostId(failed), None),
        (restart::Check::FirstReport(failed), None),
        (
            restart::Check::NotHolding(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (restart::Check::Unobserved, None),
        (restart::Check::Bump(store), Some(class)),
        (restart::Check::Preempt(failed), None),
        (restart::Check::SecondReport(failed), None),
        (
            restart::Check::NotSole(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (
            restart::Check::Coverage(FenceRefused::Fence(Withdraw::Store(fence))),
            Some(fenced),
        ),
        (
            restart::Check::Coverage(FenceRefused::Fence(Withdraw::Malformed { page: 0 })),
            None,
        ),
        (
            restart::Check::Coverage(FenceRefused::Fencing(FencingRefusal::Shard)),
            None,
        ),
        (
            restart::Check::Coverage(FenceRefused::Unresolved { page: 0 }),
            None,
        ),
    ]
}

fn takeover_checks(
    (store, class): Carried,
    (fence, fenced): Carried,
) -> Vec<(takeover::Check, Option<StoreClass>)> {
    let failed = Failed(None);
    vec![
        (takeover::Check::Records(store), Some(class)),
        (takeover::Check::Stale, None),
        (takeover::Check::Restart, None),
        (
            takeover::Check::Exhausted(SessionRefusal::AttemptsExhausted),
            None,
        ),
        (takeover::Check::Volume(Trigger::Activation), None),
        (takeover::Check::Predecessor, None),
        (takeover::Check::Local(Local::Absent), None),
        (takeover::Check::TakeOver(store), Some(class)),
        (takeover::Check::Driver(Driver::LiveQueues), None),
        (takeover::Check::Ready(failed), None),
        (takeover::Check::HostId(failed), None),
        (takeover::Check::FirstReport(failed), None),
        (
            takeover::Check::Unparsed(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (
            takeover::Check::Holder(crate::storage::HolderRefusal::Unresolved),
            None,
        ),
        (takeover::Check::Register(failed), None),
        (takeover::Check::Preempt(failed), None),
        (takeover::Check::SecondReport(failed), None),
        (
            takeover::Check::NotSole(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (
            takeover::Check::SecondUnparsed(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (takeover::Check::Superseded, None),
        (
            takeover::Check::Coverage(FenceRefused::Fence(Withdraw::Store(fence))),
            Some(fenced),
        ),
        (
            takeover::Check::Coverage(FenceRefused::Fence(Withdraw::NewerFence {
                page: 0,
                fence: 9,
            })),
            None,
        ),
        (
            takeover::Check::Coverage(FenceRefused::Unresolved { page: 0 }),
            None,
        ),
        (takeover::Check::SuffixOnly, None),
    ]
}

fn fresh_checks(
    (store, class): Carried,
    (fence, fenced): Carried,
) -> Vec<(fresh::Check, Option<StoreClass>)> {
    let failed = Failed(None);
    let admission = AdmissionError::Record;
    vec![
        (fresh::Check::Records(store), Some(class)),
        (fresh::Check::Unobserved, None),
        (fresh::Check::Deposed, None),
        (fresh::Check::Restart, None),
        (fresh::Check::Volume(Trigger::Activation), None),
        (fresh::Check::Origin, None),
        (
            fresh::Check::Exhausted(SessionRefusal::AttemptsExhausted),
            None,
        ),
        (fresh::Check::Persist(admission), None),
        (fresh::Check::EnrollWrite(store), Some(class)),
        (
            fresh::Check::EnrollRefused(crate::failover::records::Enrollment::Unattached),
            None,
        ),
        (fresh::Check::Bump(store), Some(class)),
        (fresh::Check::Local(Local::Absent), None),
        (fresh::Check::HostId(failed), None),
        (fresh::Check::Register(failed), None),
        (fresh::Check::Acquire(failed), None),
        (fresh::Check::Report(failed), None),
        (
            fresh::Check::NotSole(crate::failover::evidence::NotSole::Excess),
            None,
        ),
        (fresh::Check::Hold(admission), None),
        (fresh::Check::Write(failed), None),
        (fresh::Check::Read(failed), None),
        (
            fresh::Check::Activation(crate::storage::activation::Fault::Damaged(
                crate::storage::activation::Damage::Torn,
            )),
            None,
        ),
        (fresh::Check::Confirm(store), Some(class)),
        (fresh::Check::Superseded, None),
        (fresh::Check::Named, None),
        (
            fresh::Check::Fencing(crate::storage::page_coverage::FencingRefusal::Shard),
            None,
        ),
        (fresh::Check::Fence(Withdraw::Store(fence)), Some(fenced)),
        (fresh::Check::Fence(Withdraw::NoPage { page: 0 }), None),
        (fresh::Check::Fence(Withdraw::Malformed { page: 0 }), None),
        (fresh::Check::Fence(Withdraw::Unpaired), None),
        (fresh::Check::UnresolvedPage { page: 0 }, None),
        (fresh::Check::Release(admission), None),
        (
            fresh::Check::Retention {
                original: Box::new(fresh::Check::Confirm(store)),
                error: admission,
            },
            Some(class),
        ),
    ]
}

/// A restart whose lineage arm completes reads `kind = lineage`, `outcome = completed` for its one attempt, whose
/// start the transition keeps. A restart whose arm fails a step reads `check = recorded-holder`, `next = hold`; the
/// attempt reads `kind = lineage` when the step was one of the arm's device commands, its Register, its preempt or
/// its Report #2, or its refusal of a full registrant table before the bump, and stays a restart for a failed reread, a superseded tenure and an observed Report #2 refusal. `lineage` leaves a takeover attempt and an ended attempt as they were.
#[test]
fn a_restart_through_its_lineage_arm_reads_lineage_and_a_failed_arm_step_reads_recorded_holder() {
    use crate::failover::restart::Lineage;
    let store = restart_tests::store(shard_record(5), restart_tests::with_standby());
    let mut card = Card::new();
    card.entries = vec![restart_tests::holder(restart_tests::standby_pair(), 2)];
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(RecoveryKind::Restart, 100);
    let restarted = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    if restarted.lineage() {
        status.lineage();
    }
    status.complete();
    let recovery = status.recovery(130);
    assert_eq!(
        recovery,
        Recovery {
            kind: Some(RecoveryKind::Lineage),
            outcome: Some(RecoveryOutcome::Completed),
            attempts: Some(1),
            age_us: Some(30),
            ..Recovery::UNAVAILABLE
        }
    );
    round_trips(recovery);

    let unavailable = Some(StoreClass::Unavailable);
    for (step, store) in [
        (Lineage::Register(Failed(None)), None),
        (Lineage::Full, None),
        (Lineage::Superseded, None),
        (Lineage::Reread(StoreError::Unavailable), unavailable),
        (Lineage::Preempt(Failed(None)), None),
        (
            Lineage::Confirm(Box::new(restart::Check::SecondReport(Failed(None)))),
            None,
        ),
        (
            Lineage::Confirm(Box::new(restart::Check::NotSole(
                crate::failover::evidence::NotSole::ForeignHolder,
            ))),
            None,
        ),
        (
            Lineage::Confirm(Box::new(restart::Check::NotSole(
                crate::failover::evidence::NotSole::Unreadable,
            ))),
            None,
        ),
        (
            Lineage::Confirm(Box::new(restart::Check::Records(StoreError::Unavailable))),
            unavailable,
        ),
    ] {
        let refused = restart::Refused {
            check: restart::Check::Lineage(step.clone()),
            flip: None,
            recovery: Some(Target::of(&shard_record(6))),
        };
        let recovery = reported_refusal(RecoveryKind::Restart, RecoveryRefusal::from(&refused));
        // A Report #2 whose bytes fail the parse shows no holder, as a failed Report #2 command does.
        let device = matches!(
            &step,
            Lineage::Register(_) | Lineage::Preempt(_) | Lineage::Full
        ) || matches!(&step, Lineage::Confirm(check) if matches!(
            **check,
            restart::Check::SecondReport(_)
                | restart::Check::NotSole(crate::failover::evidence::NotSole::Unreadable)
        ));
        let kind = match device {
            true => RecoveryKind::Lineage,
            false => RecoveryKind::Restart,
        };
        assert_eq!(
            (
                recovery.kind,
                recovery.outcome,
                recovery.check,
                recovery.next,
                recovery.store
            ),
            (
                Some(kind),
                Some(RecoveryOutcome::Refused),
                Some(RecoveryCheck::RecordedHolder),
                Some(RecoveryNext::Hold),
                store
            ),
            "{step:?}"
        );
    }

    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(RecoveryKind::Takeover, 0);
    status.lineage();
    assert_eq!(status.recovery(0).kind, Some(RecoveryKind::Takeover));
    status.start(RecoveryKind::Restart, 0);
    status.complete();
    status.lineage();
    assert_eq!(status.recovery(0).kind, Some(RecoveryKind::Restart));
}
