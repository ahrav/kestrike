//! The poll's listing detects foreign attachments even when the Report permits continued ownership.

use crate::failover::attachments::Mismatch;
use crate::failover::poll::Verdict;
use crate::failover::records::VolumeState;
use crate::failover::retire::Trigger;
use crate::failover::sim::{Attach, Checks, FOREIGN, HOSTS, World, instance};

fn attached(checks: Checks, arm: Attach, loss: bool) -> World {
    let mut world = World::new(checks);
    assert!(world.activate(1));
    for unit in 0..4 {
        assert!(world.write(unit));
    }
    let volume = world.owner.as_ref().unwrap().holder.volume;
    world.attach(volume, arm, loss);
    assert_eq!(world.foreign_write(volume, 2), loss);
    world
}

#[test]
fn stale_and_unrecorded_attach_retires_at_poll() {
    for arm in [Attach::Stale, Attach::Unrecorded] {
        for loss in [false, true] {
            let mut world = attached(Checks::Listing, arm, loss);
            let volume = world.owner.as_ref().unwrap().holder.volume;
            assert_eq!(world.read(0), Some(true));
            assert_eq!(
                world.read(2),
                Some(!loss),
                "{arm:?} {loss}: a foreign landing reads as a miss"
            );
            let attacher = match arm {
                Attach::Stale => instance(HOSTS[2]).as_str().to_owned(),
                Attach::Unrecorded => FOREIGN.to_owned(),
            };
            let Some(Verdict::Retire(retirement)) = world.poll() else {
                panic!("{arm:?} {loss}: the poll continued");
            };
            assert_eq!(
                retirement.trigger(),
                &Trigger::Attachment(Mismatch::Foreign(attacher))
            );
            assert_eq!(retirement.volume, volume);
            assert_eq!(world.alarms, vec![retirement]);
            assert!(world.owner.as_ref().unwrap().withdrawn);
            assert!(!world.write(5), "a withdrawn owner submits nothing");
            assert_eq!(world.read(0), None);
            assert_eq!(world.poll(), None);
            let record = world.shard_record();
            assert_eq!(record.generation.get(), 2);
            assert_ne!(record.active, volume);
            assert_eq!(world.retired, vec![volume]);
            assert_eq!(world.stored_state(volume), VolumeState::Retired);

            let mut control = attached(Checks::WithoutListing, arm, loss);
            match (arm, loss, control.poll()) {
                (Attach::Unrecorded, false, Some(Verdict::Continue)) => {}
                (Attach::Unrecorded, true, Some(Verdict::Retire(retirement))) => {
                    assert!(matches!(retirement.trigger(), Trigger::Report(_)));
                }
                (Attach::Stale, _, Some(Verdict::Retire(retirement))) => {
                    assert!(
                        matches!(retirement.trigger(), Trigger::Attachment(_)),
                        "the stale attach event names it"
                    );
                }
                (arm, loss, other) => panic!("{arm:?} {loss}: {other:?}"),
            }
        }
    }
}
