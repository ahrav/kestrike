use crate::failover::records::{CoveragePage, VolumeState};
use crate::failover::retire::Trigger;
use crate::failover::sim::{Attach, Checks, World};
use crate::net::ownership::session_of;
use crate::storage::store::Key;
use crate::storage::store::sim::Arm;
use crate::storage::store_tests::client;

const ORDER: [&str; 9] = [
    "listing", "record", "bump", "host", "register", "acquire", "report", "write", "read",
];

fn attempts(world: &World) -> Vec<Vec<&'static str>> {
    let trace = world.trace.borrow();
    trace
        .split(|command| *command == "start")
        .skip(1)
        .map(<[_]>::to_vec)
        .collect()
}

fn fenced_at(world: &mut World, session: u64) -> bool {
    let record = world.shard_record();
    (0..record.pages.get()).all(|page| {
        client(&world.store)
            .read::<CoveragePage>(Key::Page(record.shard, page))
            .unwrap()
            .value()
            .fence
            == session
    })
}

#[test]
fn fresh_spare_activation_order() {
    for fault in 0..4 {
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1), "fault {fault}");
        assert!(world.flip(), "fault {fault}");
        let target = world.shard_record().active;
        match fault {
            0 => {}
            1 => world.plane.down = 1,
            2 => {
                world.store.schedule(Arm::Pass);
                world.store.schedule(Arm::Unavailable);
            }
            _ => world.attach(target, Attach::Unrecorded, false),
        }
        world.trace.borrow_mut().clear();
        let mut activated = false;
        for _ in 0..3 {
            activated = world.activate(2);
            if activated {
                break;
            }
        }
        assert!(activated, "fault {fault}");
        if matches!(fault, 1 | 2) {
            assert_eq!(
                world.refusals.before_commands, 1,
                "fault {fault}: one unavailable start"
            );
        }
        let runs = attempts(&world);
        for run in &runs {
            assert_eq!(run.as_slice(), &ORDER[..run.len()], "fault {fault}");
        }
        assert_eq!(runs.last().unwrap().as_slice(), ORDER, "fault {fault}");
        assert!(
            runs[..runs.len() - 1].iter().all(|run| run.len() <= 1),
            "fault {fault}: every refusal precedes the first device command"
        );
        let record = world.shard_record();
        assert_eq!(record.attempts, 1, "fault {fault}");
        let session = session_of(record.generation.get() as u32, 2);
        assert!(
            fenced_at(&mut world, session),
            "fault {fault}: every page carries the fence"
        );
        if fault == 3 {
            assert_ne!(record.active, target, "fault {fault}");
            assert_eq!(world.stored_state(target), VolumeState::Retired);
        }
    }
}

#[test]
fn foreign_attachment_refuses_before_commands() {
    for arm in [Attach::Stale, Attach::Unrecorded] {
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1));
        assert!(world.flip());
        let target = world.shard_record().active;
        world.attach(target, arm, false);
        world.trace.borrow_mut().clear();
        assert!(world.activate(2), "{arm:?}");
        let runs = attempts(&world);
        assert_eq!(
            runs[0],
            ["listing"],
            "{arm:?}: no device command reaches the written spare"
        );
        assert_eq!(runs[1].as_slice(), ORDER, "{arm:?}");
        assert_eq!(world.stored_state(target), VolumeState::Retired, "{arm:?}");
        let record = world.shard_record();
        assert_ne!(record.active, target);
        assert_eq!(world.alarms.len(), 1, "{arm:?}");
        assert!(world.activated.iter().all(|(volume, _)| *volume != target));
    }
}

#[test]
fn a_refusal_after_the_bump_retires_the_spare_through_the_reconciler() {
    let mut world = World::new(Checks::Listing);
    assert!(world.activate(1));
    assert!(world.flip());
    let target = world.shard_record().active;
    world.reserve_foreign(target);
    world.trace.borrow_mut().clear();
    assert!(world.activate(2));
    let runs = attempts(&world);
    assert_eq!(runs[0].as_slice(), &ORDER[..6], "the Acquire conflicts");
    assert_eq!(runs[1].as_slice(), ORDER);
    assert_eq!(world.stored_state(target), VolumeState::Retired);
    assert_ne!(world.shard_record().active, target);
    assert_eq!(
        world.alarms.last().map(|alarm| alarm.trigger()),
        Some(&Trigger::Activation)
    );
    assert_eq!(
        (world.refusals.before_fb, world.refusals.flip_requests),
        (1, 1)
    );
}
