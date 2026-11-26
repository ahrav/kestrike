//! `duties` runs an owner's turn with its serving duties, and `reconcile` a reconciler's tick; `owners` holds a host's
//! recovery. Fleet scenarios use these functions as actor entry points.

use crate::failover::records::ShardRecord;
use crate::net::ownership::Shard;
use crate::storage::store::Key;
use crate::storage::store::sim::Shared;
use crate::storage::store_tests::client as store_client;

use super::super::Serving;

/// `duties` steps `serving`'s owner one round and then, when the tenure runs its serving duties and no exit ended
/// them yet, one [`Duties::turn`](crate::host::Duties::turn) at that round's time and, until it is held, the read
/// of the tenure's recovery line (`serve::recovery_line`), the serving loop's turn in its order. As the serving loop does after
/// a turn, it takes the exit the owner's state names ([`serve::ended`](crate::host::serve::ended)) over the duties'
/// own. A turn whose duties withdrew the authority emits the tenure's `Commands` and `Withdrawn` steps at once, so
/// the ownership monitor judges every later round of its device, the teardown's drain included. Returns the exit of
/// this turn, which `serving` keeps.
pub(super) fn duties(serving: &mut Serving<'_>) -> Option<crate::host::Exit> {
    let now = serving.step();
    if serving.duty_exit.is_some() {
        return None;
    }
    let named = serving.duties.as_mut()?.turn(&mut serving.owner, now);
    serving.note_late_withdrawal();
    // The serving loop's one write of the tenure's recovery line, once its first-safe-hit span has closed.
    if serving.recovery_line.is_none() {
        serving.recovery_line = crate::host::serve::recovery_line(&serving.owner);
    }
    let exit = crate::host::serve::ended(&serving.owner).or(named)?;
    serving.duty_exit = Some(exit.clone());
    Some(exit)
}

/// `reconcile` performs a read-only survey and counts the shard records whose `standby` is `None`. The fleet's
/// store carries no fault arm, so a read that fails is a harness defect and panics.
pub(super) fn reconcile(store: &Shared, shards: &[Shard]) -> u32 {
    let mut client = store_client(store);
    let unnamed = |shard: &&Shard| {
        let read = client.read::<ShardRecord>(Key::Shard(**shard));
        let read = read.unwrap_or_else(|error| panic!("shard {}: {error:?}", shard.get()));
        read.value().standby.is_none()
    };
    shards.iter().filter(unnamed).count() as u32
}
