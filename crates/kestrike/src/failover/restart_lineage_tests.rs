//! The restart's lineage arm: a host the shard record names owner bumps, registers when unlisted, rereads the
//! record and preempts another host's recorded holder, then reaches its fencing boundary at the bumped tenure.

use super::tests::{
    ARM, Card, Fault, Plant, holder, host, own, restart, sample, shard_now, shard_record,
    standby_host, standby_pair, store as seeded, volume_id, volume_record, with_plant,
    with_standby,
};
use super::*;
use crate::failover::records::RecordedPair;
use crate::failover::takeover::tests::lineage_on;
use crate::storage::store::sim::{Arm, MemLog, Recorder, Request, Shared};
use crate::storage::store_tests::{client, shard};

/// The commands of the arm over a Report #1 that lists no record of the own pair.
const UNLISTED: [&str; 7] = [
    "start", "ready", "host", "report", "register", "lineage", "report",
];

/// A handoff target's volume record: the predecessor, the standby pair's host, attached first and still recorded,
/// and this host attached after it and enrolled under the own pair.
fn handed() -> VolumeRecord {
    lineage_on(
        volume_id(),
        (standby_host(), standby_pair()),
        &[(host(), own())],
    )
}

/// A Report #1 the predecessor's recorded pair holds, with no record of the own pair.
fn predecessor_holds() -> Card {
    let mut card = Card::new();
    card.entries = vec![holder(standby_pair(), 1)];
    card
}

/// Runs the restart over a client that traces `store` and `card`'s commands together: the result and every request
/// and command in issue order.
fn traced(store: &Shared, card: &mut Card) -> (Result<Restarted, Refused>, Vec<Request>) {
    let recorder = Recorder::new(store);
    card.trace = Some(recorder.clone());
    let mut client = Client::open(recorder.clone(), MemLog::default()).unwrap();
    let result = restart().run(&mut client, &sample(), card);
    (result, recorder.take())
}

/// OwnBumpBeforePreempt over a traced run: the shard-record write, the bump, is the run's first write and precedes
/// every Register and lineage preempt of the arm.
fn own_bump_first(trace: &[Request]) -> bool {
    let shard_key = Key::Shard(shard());
    let at = |wanted: &dyn Fn(&Request) -> bool| trace.iter().position(wanted);
    let bump = at(&|request| matches!(request, Request::Write(key, _) if *key == shard_key));
    let first_write = at(&|request| matches!(request, Request::Write(..)));
    let arm = at(&|request| matches!(request, Request::Device("register" | "lineage")));
    match (bump, arm) {
        (Some(bump), Some(arm)) => first_write == Some(bump) && bump < arm,
        _ => false,
    }
}

/// `NoPreemptOfForeignKey` over a traced run: a shard-record read directly precedes each lineage preempt, and the
/// run issued one.
fn reread_before_each_preempt(trace: &[Request]) -> bool {
    let shard_key = Key::Shard(shard());
    let preempts: Vec<usize> = (trace.iter().enumerate())
        .filter(|(_, request)| **request == Request::Device("lineage"))
        .map(|(at, _)| at)
        .collect();
    !preempts.is_empty()
        && preempts.iter().all(|&at| {
            at.checked_sub(1)
                .is_some_and(|before| trace[before] == Request::Read(shard_key))
        })
}

/// The handoff target's activation: the record names this host owner at `n + 1 = 5` after the predecessor's
/// transfer while the predecessor's recorded pair holds and this host holds no registration. The restart's commands
/// run start, ready, host ID, Report #1, Register, the lineage preempt naming the predecessor's key and Report #2,
/// with the acknowledged bump before the Register and a shard read directly before the preempt; the record ends at
/// `n + 2`, the session is that bump's, and `Fenced` comes from Report #2 with the own pair as the one holder.
#[test]
fn a_handoff_target_bumps_registers_rereads_and_preempts_the_recorded_predecessor() {
    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    let (result, trace) = traced(&store, &mut card);
    let restarted = result.unwrap();
    assert!(restarted.lineage());
    assert_eq!(card.log, UNLISTED);
    assert_eq!(card.preempted, [standby_pair().key]);
    assert!(own_bump_first(&trace), "{trace:?}");
    assert!(reread_before_each_preempt(&trace), "{trace:?}");
    assert_eq!(shard_now(&store), shard_record(6));
    assert_eq!(restarted.session().target(), Target::of(&shard_record(6)));
    assert_eq!(restarted.fenced().own(), own());
    let holders: Vec<Pair> = (card.entries.iter())
        .filter(|entry| entry.holder)
        .map(|entry| entry.pair)
        .collect();
    assert_eq!(holders, [own()]);
}

/// A bump refused on its condition and a bump of unknown outcome issue no Register and no preempt and hold with no
/// flip: the refusal names the step-1 target, and the unknown one the same target, since its commit is unproven. A
/// rerun over the record either outcome left takes the arm at the next `E` and reaches FB.
#[test]
fn a_refused_or_unknown_bump_issues_no_register_or_preempt_and_the_rerun_takes_the_arm() {
    use crate::storage::store::Refusal;
    for (arm, error) in [
        (None, StoreError::Refused(Refusal::Condition)),
        (Some(Arm::Timeout { commit: false }), StoreError::Unknown),
        (Some(Arm::Timeout { commit: true }), StoreError::Unknown),
    ] {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        match arm {
            Some(arm) => {
                for scheduled in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Pass, arm] {
                    store.schedule(scheduled);
                }
            }
            // Another incarnation's bump commits before this one's, so this bump fails its version condition.
            None => {
                let racing = store.clone();
                card.before_report = Some(Box::new(move || {
                    let mut writer = client(&racing);
                    let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                    writer.bump(&read).unwrap();
                }));
            }
        }
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: Check::Bump(error),
                flip: None,
                recovery: Some(Target::of(&shard_record(5))),
            },
            "{arm:?}"
        );
        assert_eq!(card.log, UNLISTED[..4], "{arm:?}: no Register, no preempt");
        assert!(card.preempted.is_empty(), "{arm:?}");
        let committed = shard_now(&store).attempts;
        let mut card = predecessor_holds();
        let rerun = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap();
        assert!(rerun.lineage(), "{arm:?}");
        assert_eq!(
            rerun.session().target().attempts,
            committed + 1,
            "{arm:?}: the rerun bumps from the record the bump left"
        );
        assert_eq!(card.preempted, [standby_pair().key], "{arm:?}");
    }
}

/// Moves the shard record as another writer would: a bump by another incarnation of this host, or a takeover by the
/// standby host over the record's current tenure.
type Mover = fn(&Shared);

const MOVERS: [(&str, Mover); 2] = [
    ("another bump", |store| {
        let mut writer = client(store);
        let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        writer.bump(&read).unwrap();
    }),
    ("a takeover", |store| {
        let mut writer = client(store);
        let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let read = writer
            .designate(&read, Target::of(read.value()), standby_host())
            .unwrap();
        writer
            .take_over(&read, Target::of(read.value()), standby_host())
            .unwrap();
    }),
];

/// A record that moves between the bump and the preempt refuses the arm at its reread: a takeover by another host
/// over the bumped tenure, or a bump by another incarnation of this host. The restart issues no preempt, requests no
/// flip and names the bumped target; a failed reread holds the same way as `Lineage::Reread` with the store error.
#[test]
fn a_record_moved_after_the_bump_refuses_at_the_reread_with_no_preempt() {
    for (case, mover) in MOVERS {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        let moved = store.clone();
        card.after_register = Some(Box::new(move |_| mover(&moved)));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: Check::Lineage(Lineage::Superseded),
                flip: None,
                recovery: Some(Target::of(&shard_record(6))),
            },
            "{case}"
        );
        assert_eq!(card.log, UNLISTED[..5], "{case}: no preempt");
        assert!(card.preempted.is_empty(), "{case}");
    }

    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    let failing = store.clone();
    card.after_register = Some(Box::new(move |_| failing.schedule(Arm::Unavailable)));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Lineage(Lineage::Reread(StoreError::Unavailable)),
            flip: None,
            recovery: Some(Target::of(&shard_record(6))),
        }
    );
    assert_eq!(card.log, UNLISTED[..5]);
    assert!(card.preempted.is_empty());
}

/// ENDED-GRANTS-NOTHING at the arm: an end of the own attach that commits after Report #1's volume reread and before
/// the arm's preempt, here right after the Register, refuses `Local::Ended` at the arm's volume read with no preempt,
/// no flip and no recovery hint, after the bump.
#[test]
fn an_end_of_the_own_attach_after_the_register_refuses_the_arm_with_no_preempt() {
    use crate::failover::records::EventKind;
    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    let writer = store.clone();
    card.after_register = Some(Box::new(move |_| {
        let mut writer = client(&writer);
        let read = writer
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let mut next = read.value().clone();
        let own_attach = (next.events.iter_mut())
            .rfind(|event| event.host == host() && event.kind == EventKind::Attach)
            .expect("the target's attach");
        own_attach.kind = EventKind::Ended;
        writer.replace(&read, next).unwrap();
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (Check::Local(Local::Ended), None, None)
    );
    assert_eq!(card.log, UNLISTED[..5], "no preempt");
    assert!(card.preempted.is_empty());
    assert_eq!(shard_now(&store).attempts, 6, "the bump committed");
}

/// A target Report #1 already lists as a registrant takes the arm with no Register, and its reread before the
/// preempt still runs: a record another writer moves after the bump commits, and before its reply reaches the
/// restart, refuses `Lineage::Superseded` at the bumped target with no Register and no preempt.
#[test]
fn a_registered_target_rereads_before_its_preempt() {
    for (case, mover) in MOVERS {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        card.entries.push(Registrant {
            holder: false,
            ..holder(own(), 2)
        });
        let moved = store.clone();
        let hook = crate::storage::store::sim::hooked(
            &store,
            Key::Shard(shard()),
            crate::storage::store::sim::Point::AfterWrite,
            move || mover(&moved),
        );
        let mut client = Client::open(hook, MemLog::default()).unwrap();
        let refused = restart()
            .run(&mut client, &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: Check::Lineage(Lineage::Superseded),
                flip: None,
                recovery: Some(Target::of(&shard_record(6))),
            },
            "{case}"
        );
        assert_eq!(card.log, ["start", "ready", "host", "report"], "{case}");
        assert!(card.preempted.is_empty(), "{case}");
    }
}

/// A takeover that commits over the bumped tenure after the arm's reread, while its preempt runs, refuses the arm
/// at the reread after Report #2: Report #2 shows the own pair holding, and the restart returns no capability,
/// requests no flip, names the bumped target and writes no coverage page. The control with that reread planted away
/// reaches FB on the superseded tenure.
#[test]
fn a_takeover_during_the_preempt_refuses_the_arm_after_report_two() {
    let run = |plant: Option<Plant>| {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        let moved = store.clone();
        card.after_lineage = Some(Box::new(move |_| MOVERS[1].1(&moved)));
        let (result, trace) = match plant {
            Some(plant) => with_plant(plant, || traced(&store, &mut card)),
            None => traced(&store, &mut card),
        };
        (result, trace, card)
    };
    let (result, trace, card) = run(None);
    assert_eq!(
        result.unwrap_err(),
        Refused {
            check: Check::Lineage(Lineage::Superseded),
            flip: None,
            recovery: Some(Target::of(&shard_record(6))),
        }
    );
    assert_eq!(card.log, UNLISTED);
    let holders: Vec<Pair> = (card.entries.iter())
        .filter(|entry| entry.holder)
        .map(|entry| entry.pair)
        .collect();
    assert_eq!(holders, [own()], "Report #2 showed the own pair holding");
    let writes = (trace.iter())
        .filter(|request| matches!(request, Request::Write(..)))
        .count();
    assert_eq!(writes, 1, "the bump alone: no coverage page write");

    let (result, _, _) = run(Some(Plant::NoFinalReread));
    assert!(
        result.is_ok(),
        "control: with no reread after Report #2 the superseded arm reaches FB"
    );
}

/// A Register, a lineage preempt, a Report #2 command or a Report #2 whose bytes fail the parse in the arm holds
/// with no flip, names the bumped target and issues no later command. Each rerun reaches FB from the next `E`: through
/// the arm again while the predecessor holds, and through the self preempt once the failed Report #2 followed a preempt
/// that landed.
#[test]
fn a_failed_step_of_the_arm_holds_and_the_rerun_takes_the_arm_again() {
    let conflict = Failed(Some(DeviceStatus::Nvme(0x83 << 1)));
    type Row = (Option<Fault>, Option<usize>, Check, usize, bool);
    let rows: [Row; 4] = [
        (
            Some(Fault::Register(0x83)),
            None,
            Check::Lineage(Lineage::Register(conflict)),
            5,
            true,
        ),
        (
            Some(Fault::Preempt(0x83)),
            None,
            Check::Lineage(Lineage::Preempt(conflict)),
            6,
            true,
        ),
        (
            None,
            Some(6),
            Check::Lineage(Lineage::Confirm(Box::new(Check::SecondReport(Failed(
                None,
            ))))),
            7,
            false,
        ),
        (
            Some(Fault::ReportTruncated(2)),
            None,
            Check::Lineage(Lineage::Confirm(Box::new(Check::NotSole(
                NotSole::Unreadable,
            )))),
            7,
            false,
        ),
    ];
    for (fault, stop_at, check, issued, again) in rows {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        card.fault = fault;
        card.stop_at = stop_at;
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: check.clone(),
                flip: None,
                recovery: Some(Target::of(&shard_record(6))),
            },
            "{check:?}"
        );
        assert_eq!(card.log, UNLISTED[..issued], "{check:?}");
        assert_eq!(disposition(&check), Disposition::Hold, "{check:?}");
        let entries = card.entries.clone();
        let mut card = Card::new();
        card.entries = entries;
        let rerun = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap();
        assert_eq!(rerun.lineage(), again, "{check:?}");
        assert_eq!(
            rerun.session().target(),
            Target::of(&shard_record(7)),
            "{check:?}"
        );
    }
}

/// The arm preempts only a recorded pair of another host. A holder recorded for this host's own earlier attach, a
/// holder outside the recorded pairs, and a Report with nobody holding keep their refusals with no bump and no
/// preempt: `RecordedHolder` with no flip, the unrecorded-holder refusal with its flip, and `Unheld` with no flip.
#[test]
fn only_a_recorded_holder_of_another_host_takes_the_arm() {
    let earlier = Pair {
        exhid: Exhid::new([0x5e; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((5 << 32) | 5).unwrap(),
    };
    use crate::failover::records::{ERA, EventKind};
    let mut own_earlier = super::tests::volume_record_of(volume_id(), host(), earlier);
    own_earlier.push(EventKind::Detach, host(), ERA);
    let attach = own_earlier.push(EventKind::Attach, host(), ERA).unwrap();
    own_earlier.pairs.push(RecordedPair {
        host: host(),
        pair: own(),
        attach,
    });
    let rows: [(&str, VolumeRecord, Vec<Registrant>, Check, bool); 3] = [
        (
            "this host's earlier pair",
            own_earlier,
            vec![
                Registrant {
                    holder: false,
                    ..holder(own(), 1)
                },
                holder(earlier, 2),
            ],
            Check::RecordedHolder,
            false,
        ),
        (
            "an unrecorded holder",
            volume_record(),
            vec![
                Registrant {
                    holder: false,
                    ..holder(own(), 1)
                },
                holder(standby_pair(), 2),
            ],
            Check::NotHolding(NotSole::ForeignHolder),
            true,
        ),
        (
            "nobody holds",
            with_standby(),
            vec![
                Registrant {
                    holder: false,
                    ..holder(own(), 1)
                },
                Registrant {
                    holder: false,
                    ..holder(standby_pair(), 2)
                },
            ],
            Check::Unheld,
            false,
        ),
    ];
    for (case, volume, entries, check, flips) in rows {
        let store = seeded(shard_record(4), volume);
        let mut card = Card::new();
        card.entries = entries;
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(refused.check, check, "{case}");
        assert_eq!(refused.flip.is_some(), flips, "{case}");
        assert_eq!(card.log, ARM[..4], "{case}: no command after Report #1");
        assert!(card.preempted.is_empty(), "{case}");
        assert_eq!(shard_now(&store), shard_record(4), "{case}: no bump");
    }
}

/// A record that names another owner, or names this host its standby, deposes the restart before any write and any
/// device command, whoever holds the reservation.
#[test]
fn a_record_naming_another_owner_or_this_host_as_standby_deposes_before_any_command() {
    for (case, record) in [
        (
            "another owner",
            ShardRecord {
                owner: standby_host(),
                ..shard_record(5)
            },
        ),
        (
            "this host as standby",
            ShardRecord {
                owner: standby_host(),
                standby: Some(host()),
                ..shard_record(5)
            },
        ),
    ] {
        let store = seeded(record, handed());
        let mut card = predecessor_holds();
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (Check::Deposed, None, None),
            "{case}"
        );
        assert!(card.log.is_empty(), "{case}");
        assert_eq!(shard_now(&store), record, "{case}: no write");
    }
}

/// Control: with the lineage arm planted away, the handoff target's restart refuses `Check::RecordedHolder` at
/// Report #1 and the predecessor keeps the reservation, so the activation the arm passes fails.
#[test]
fn control_a_restart_with_no_lineage_arm_holds_the_handoff_target() {
    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    let refused = with_plant(Plant::NoLineage, || {
        restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err()
    });
    assert_eq!(refused.check, Check::RecordedHolder);
    assert!(card.preempted.is_empty());
    assert_eq!(shard_now(&store), shard_record(5));
}

/// Control: an arm that preempts with no bump, and one that registers and preempts before its bump, each issue the
/// planted commands with a shard read before each preempt, so the reread check passes and only the own-bump order
/// `own_bump_first` rejects them. The unplanted arm passes both checks.
#[test]
fn control_a_preempt_before_or_without_the_bump_fails_the_own_bump_order() {
    let shard_key = Key::Shard(shard());
    for plant in [Plant::NoBump, Plant::PreemptBeforeBump] {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        let (_, trace) = with_plant(plant, || traced(&store, &mut card));
        let first_preempt = trace
            .iter()
            .position(|request| *request == Request::Device("lineage"))
            .expect("the plant issued its lineage preempt");
        let bump = trace
            .iter()
            .position(|request| matches!(request, Request::Write(key, _) if *key == shard_key));
        match plant {
            Plant::NoBump => assert_eq!(bump, None, "{trace:?}"),
            _ => assert!(bump.is_some_and(|bump| first_preempt < bump), "{trace:?}"),
        }
        assert!(reread_before_each_preempt(&trace), "{plant:?}: {trace:?}");
        assert!(!own_bump_first(&trace), "{plant:?}: {trace:?}");
    }
    let store = seeded(shard_record(5), handed());
    let (result, trace) = traced(&store, &mut predecessor_holds());
    assert!(result.is_ok() && own_bump_first(&trace) && reread_before_each_preempt(&trace));
}

/// ENDED-NEVER-RETIRES in the arm: a registrant under an ended attach's key that is no recorded pair, beside the
/// predecessor's recorded holder, stays through the arm as it stays through the self preempt. The target bumps,
/// registers, rereads, preempts the predecessor's key and reaches FB with the ended registrant admitted at Report #2.
#[test]
fn an_ended_key_registrant_beside_the_recorded_holder_takes_the_arm() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::records::{AttachmentEvent, ERA, EventKind, Host};
    let mut volume = handed();
    let seq = volume.next;
    volume.next += 1;
    volume.events.push(AttachmentEvent {
        seq,
        kind: EventKind::Ended,
        host: Host::new(host().get() + 7).unwrap(),
        era: ERA,
        instance: Some(InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap()),
    });
    let ended = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::records::attachment_key(seq).unwrap(),
    };
    let store = seeded(shard_record(5), volume);
    let mut card = predecessor_holds();
    card.entries.push(Registrant {
        cntlid: 3,
        pair: ended,
        holder: false,
    });
    let (result, trace) = traced(&store, &mut card);
    let restarted = result.unwrap();
    assert!(restarted.lineage());
    assert_eq!(card.log, UNLISTED);
    assert_eq!(card.preempted, [standby_pair().key]);
    assert!(own_bump_first(&trace), "{trace:?}");
    let (_, _, (admitted, _), _, _, _) = restarted.into_parts();
    assert!(
        admitted.contains(&ended) && admitted.contains(&own()),
        "{admitted:?}"
    );
}

/// The card's lineage preempt follows the shared reservation table: a registered issuer whose preempt names a key
/// that no longer holds removes that key's registrations and leaves the current holder. A recorded host that takes
/// the reservation after the arm's Register and reread, before its preempt executes, keeps it: Report #2 refuses
/// the arm and the restart holds at the bumped target with no capability.
#[test]
fn a_holder_change_before_the_preempt_executes_refuses_the_arm_at_report_two() {
    let later = Pair {
        exhid: Exhid::new([0x6b; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((6 << 32) | 6).unwrap(),
    };
    let volume = lineage_on(
        volume_id(),
        (standby_host(), standby_pair()),
        &[
            (host(), own()),
            (
                crate::failover::records::Host::new(host().get() + 9).unwrap(),
                later,
            ),
        ],
    );
    let store = seeded(shard_record(5), volume);
    let mut card = predecessor_holds();
    card.after_register = Some(Box::new(move |entries| {
        for entry in entries.iter_mut() {
            entry.holder = false;
        }
        entries.push(holder(later, 4));
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(refused.flip, None);
    assert_eq!(refused.recovery, Some(Target::of(&shard_record(6))));
    assert_eq!(
        refused.check,
        Check::Lineage(Lineage::Confirm(Box::new(Check::RecordedHolder))),
        "Report #2 takes no lineage arm: the recorded holder refuses inside the arm's hold"
    );
    assert_eq!(card.log, UNLISTED);
    assert_eq!(card.preempted, [standby_pair().key]);
    let holders: Vec<Pair> = (card.entries.iter())
        .filter(|entry| entry.holder)
        .map(|entry| entry.pair)
        .collect();
    assert_eq!(holders, [later], "the later holder keeps the reservation");
}

/// A Report #2 of the arm whose observed registrants refuse it, here an unrecorded registrant that joined after the
/// preempt, holds at the bumped target: the arm carries the refusal in `Lineage::Confirm` and requests no flip, and no
/// command follows Report #2; `report::recovery`'s tests read that refusal as `recorded-holder` and `hold`. Outside
/// the arm the same Report #2 refusal requests the flip.
#[test]
fn an_observed_report_two_refusal_of_the_arm_holds_at_the_bumped_target() {
    let stranger = Registrant {
        cntlid: 7,
        pair: crate::storage::gate_fixture::foreign(),
        holder: false,
    };
    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    card.after_lineage = Some(Box::new(move |entries| entries.push(stranger)));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    let observed = Check::NotSole(NotSole::ForeignRegistrant);
    assert_eq!(
        refused,
        Refused {
            check: Check::Lineage(Lineage::Confirm(Box::new(observed.clone()))),
            flip: None,
            recovery: Some(Target::of(&shard_record(6))),
        }
    );
    assert_eq!(card.log, UNLISTED, "no command after Report #2");
    assert_eq!(disposition(&observed), Disposition::Flip, "outside the arm");
}

/// The two ends of the arm after Report #2 that are no hold of an observed Report. A record read that fails after
/// Report #2 holds with the store's error: `admit`'s volume reread of Report #2 refuses `Lineage::Confirm` of
/// `Check::Records`, and the arm's shard reread after it refuses `Lineage::Reread`. Either way the restart returns
/// no capability, requests no flip, names the bumped target and writes no coverage page, where a restart that
/// fenced from its step-1 read would reach FB. A successor's takeover that committed over the bumped tenure and
/// whose enrolled pair holds at Report #2 refuses `Deposed` itself, outside `Lineage::Confirm`, with no flip and no
/// recovery target, so the host ends `Deposed` and holds nothing.
#[test]
fn a_failed_read_after_report_two_holds_and_a_successor_holding_there_deposes_unwrapped() {
    let confirm = Check::Lineage(Lineage::Confirm(Box::new(Check::Records(
        StoreError::Unavailable,
    ))));
    let reread = Check::Lineage(Lineage::Reread(StoreError::Unavailable));
    for (passes, check) in [(0, confirm), (1, reread)] {
        let store = seeded(shard_record(5), handed());
        let mut card = predecessor_holds();
        let failing = store.clone();
        // The first `passes` reads after Report #2 pass, and the next one fails.
        card.after_lineage = Some(Box::new(move |_| {
            for _ in 0..passes {
                failing.schedule(Arm::Pass);
            }
            failing.schedule(Arm::Unavailable);
        }));
        let (result, trace) = traced(&store, &mut card);
        assert_eq!(
            result.unwrap_err(),
            Refused {
                check: check.clone(),
                flip: None,
                recovery: Some(Target::of(&shard_record(6))),
            }
        );
        assert_eq!(card.log, UNLISTED, "{check:?}: no command after Report #2");
        let writes = (trace.iter())
            .filter(|request| matches!(request, Request::Write(..)))
            .count();
        assert_eq!(
            writes, 1,
            "{check:?}: the bump alone, no coverage page write"
        );
    }

    let store = seeded(shard_record(5), handed());
    let mut card = predecessor_holds();
    let moved = store.clone();
    card.after_lineage = Some(Box::new(move |entries| {
        MOVERS[1].1(&moved);
        for entry in entries.iter_mut() {
            entry.holder = entry.pair == standby_pair();
        }
        if !entries.iter().any(|entry| entry.holder) {
            entries.push(holder(standby_pair(), 4));
        }
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Deposed,
            flip: None,
            recovery: None,
        }
    );
    assert_eq!(card.log, UNLISTED, "no command after Report #2");
}

/// The handoff target's record and Report #1 with `ended` registrants under ended attaches' keys beside the
/// predecessor's recorded holder, each an `Ended` entry of a host of its own; `listed` adds the own pair's record.
fn table(ended: u8, listed: bool) -> (Shared, Card) {
    use crate::failover::attachments::InstanceId;
    use crate::failover::records::{AttachmentEvent, ERA, EventKind, Host};
    let mut volume = handed();
    let mut card = predecessor_holds();
    if listed {
        card.entries.push(Registrant {
            cntlid: 2,
            holder: false,
            pair: own(),
        });
    }
    for at in 0..ended {
        let seq = volume.next;
        volume.next += 1;
        volume.events.push(AttachmentEvent {
            seq,
            kind: EventKind::Ended,
            host: Host::new(host().get() + 7 + u64::from(at)).unwrap(),
            era: ERA,
            instance: Some(InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap()),
        });
        card.entries.push(Registrant {
            cntlid: 3 + u16::from(at),
            holder: false,
            pair: Pair {
                exhid: Exhid::new([0x70 + at; 16]).unwrap(),
                key: crate::failover::records::attachment_key(seq).unwrap(),
            },
        });
    }
    (seeded(shard_record(5), volume), card)
}

/// `N_reg` of the restart fixture's bounds.
fn n_reg() -> u8 {
    u8::try_from(restart().bounds.registrant_max()).unwrap()
}

/// REGISTER-ROOM: a Report #1 at `N_reg` registrants that lists no record of the own pair refuses the arm before its
/// bump as `Lineage::Full`: no flip, the step-1 target as the recovery hint, no command after Report #1, no Register,
/// no preempt and `E` unchanged. A rerun over the same table refuses the same way.
#[test]
fn a_full_table_without_the_own_pair_holds_before_the_bump() {
    let (store, mut card) = table(n_reg() - 1, false);
    assert_eq!(card.entries.len(), usize::from(n_reg()));
    for run in 0..2 {
        card.log.clear();
        let (result, trace) = traced(&store, &mut card);
        let refused = result.unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: Check::Lineage(Lineage::Full),
                flip: None,
                recovery: Some(Target::of(&shard_record(5))),
            },
            "run {run}"
        );
        assert_eq!(disposition(&refused.check), Disposition::Hold);
        assert_eq!(
            card.log,
            UNLISTED[..4],
            "run {run}: no command after Report #1"
        );
        assert!(card.preempted.is_empty(), "run {run}");
        assert_eq!(card.entries.len(), usize::from(n_reg()), "run {run}");
        assert!(
            !trace
                .iter()
                .any(|request| matches!(request, Request::Write(..))),
            "run {run}: no write: {trace:?}"
        );
        assert_eq!(shard_now(&store), shard_record(5), "run {run}: no bump");
    }
}

/// A full table that already lists the own pair needs no Register, and a table with room for it takes the Register:
/// both take the arm, preempt the predecessor and reach FB at the bumped tenure.
#[test]
fn a_full_table_listing_the_own_pair_and_a_table_with_room_take_the_arm() {
    let rows: [(&str, u8, bool, &[&str]); 2] = [
        (
            "full, own pair listed",
            n_reg() - 2,
            true,
            &["start", "ready", "host", "report", "lineage", "report"],
        ),
        ("room for the Register", n_reg() - 2, false, &UNLISTED),
    ];
    for (case, ended, listed, log) in rows {
        let (store, mut card) = table(ended, listed);
        let at_bound = card.entries.len() == usize::from(n_reg());
        assert_eq!(at_bound, listed, "{case}");
        let (result, trace) = traced(&store, &mut card);
        let restarted = result.unwrap_or_else(|refused| panic!("{case}: {refused:?}"));
        assert!(restarted.lineage(), "{case}");
        assert_eq!(card.log, log, "{case}");
        assert_eq!(card.preempted, [standby_pair().key], "{case}");
        assert!(own_bump_first(&trace), "{case}: {trace:?}");
        assert!(reread_before_each_preempt(&trace), "{case}: {trace:?}");
        assert_eq!(shard_now(&store), shard_record(6), "{case}");
        assert_eq!(
            card.entries.len(),
            usize::from(n_reg()) - 1,
            "{case}: the preempt removed the predecessor's registration"
        );
    }
}

/// Control: with REGISTER-ROOM planted away, the arm registers into the full table, its reread fails and it holds;
/// the rerun over the same table, now at `N_reg + 1`, refuses Report #1 as `NotHolding(Excess)` and requests the flip
/// of the healthy volume, the outcome the check prevents.
#[test]
fn control_an_arm_that_registers_into_a_full_table_requests_the_flip_on_its_rerun() {
    let (store, mut card) = table(n_reg() - 1, false);
    let failing = store.clone();
    card.after_register = Some(Box::new(move |_| failing.schedule(Arm::Unavailable)));
    let refused = with_plant(Plant::NoRoom, || {
        restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err()
    });
    assert_eq!(
        refused.check,
        Check::Lineage(Lineage::Reread(StoreError::Unavailable))
    );
    assert_eq!(card.entries.len(), usize::from(n_reg()) + 1);
    let entries = card.entries.clone();
    let mut card = Card::new();
    card.entries = entries;
    let rerun = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(rerun.check, Check::NotHolding(NotSole::Excess));
    assert_eq!(rerun.flip, Some(Target::of(&shard_record(6))));
}
