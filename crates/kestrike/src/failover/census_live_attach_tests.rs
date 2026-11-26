//! `Census::released` keeps the entry of a host that still holds a live attach of the active volume.
//!
//! CENSUS-COVERS: `Census::released` drops the census entry of a shard once the shard record names no standby
//! and holds another `(g, owner, E)` than the entry's, and the entry's host is the owner or holds no live
//! attach in the record of the active volume. These tests take the live attach: an entry whose host is not
//! the owner and still holds a live attach of the active volume stays listed, and stays counted against that
//! host's attachment headroom.
//!
//! One history runs in every test: a reconciler reserved shard 1's slot for host 30 at the record's
//! `(g, owner 11, E 2)`; the record then moved to owner 21 at `E 3` and names no standby. The tests differ
//! only in what the volume record of the active volume shows for host 30 and in who the record names its
//! owner. `live` is the predicate `Reconciler::release` passes: the volume record's live attach of the host.

use super::poll_tests::volume;
use super::records::{ERA, EventKind, Host, ShardRecord, VolumeRecord, VolumeState};
use super::retire::Target;
use super::sim::host;
use super::standbys::tests::{listing, roomy};
use super::standbys::{Attach, Census, Entry, Population, Refusal, Zone};
use crate::net::ownership::Shard;
use crate::storage::store_tests::record;

const ZONE: Zone = Zone(1);
const RESERVED: u64 = 30;

fn shard(n: u32) -> Shard {
    Shard::new(n).unwrap()
}

/// Shard 1's record when the slot was reserved: owner 11 at `E = 2`, no standby.
fn reserved() -> ShardRecord {
    ShardRecord {
        shard: shard(1),
        owner: host(11),
        attempts: 2,
        standby: None,
        ..record()
    }
}

/// The same record read after the census: the tenure moved to `owner` at `E = 3`, still with no standby.
fn moved(owner: u64) -> ShardRecord {
    ShardRecord {
        owner: host(owner),
        attempts: reserved().attempts + 1,
        ..reserved()
    }
}

/// The entry the reconciler reserved: shard 1's slot for host 30 at the reserved record's `(g, owner, E)`.
fn entry() -> Entry {
    Entry {
        target: Target::of(&reserved()),
        host: host(RESERVED),
    }
}

/// The census of zone 1 listing that entry alone.
fn census() -> Census {
    listing(ZONE, shard(1), entry())
}

/// The record of the active volume with host 30 attached.
fn attached() -> VolumeRecord {
    let active = volume(VolumeState::Active, host(RESERVED));
    assert_eq!(
        active.volume,
        reserved().active,
        "premise: the volume record is the active volume's"
    );
    assert!(
        active.live(host(RESERVED)).is_some(),
        "premise: host 30 holds a live attach"
    );
    active
}

/// The same volume record after host 30 detached; hosts 11 and 21 hold live attaches, so a call that asked about
/// the owner instead of the entry's host would still see a live attach.
fn detached() -> VolumeRecord {
    let mut active = attached();
    active.push(EventKind::Detach, host(RESERVED), ERA);
    active.push(EventKind::Attach, host(11), ERA);
    active.push(EventKind::Attach, host(21), ERA);
    assert!(
        active.live(host(RESERVED)).is_none(),
        "premise: host 30 holds no live attach"
    );
    assert!(
        active.live(host(21)).is_some(),
        "premise: the owner holds a live attach"
    );
    active
}

/// The predicate `Reconciler::release` builds over the volume record it read after the shard record.
fn live(active: &VolumeRecord) -> impl Fn(Host) -> bool + '_ {
    |asked| active.live(asked).is_some()
}

/// What admitting host 30, a candidate with one free attachment slot, for shard 2 over `census` returns: the
/// reservation of shard 1 counts against that slot while the census lists it (HEADROOM).
fn admit_second(census: &Census) -> Result<Option<Census>, Refusal> {
    let second = ShardRecord {
        shard: shard(2),
        owner: host(12),
        ..reserved()
    };
    Population { cap: 2 }.admit(
        census,
        &second,
        &roomy(host(RESERVED)),
        Attach::Open,
        |_| None,
        |_| false,
    )
}

/// The fault: host 30 is not the owner and still holds a live attach of the active volume. The entry stays: the
/// call returns `None`, the census still lists shard 1's slot for host 30, and that reservation still takes host
/// 30's one free attachment slot, so a second shard's reservation for it refuses `Headroom`.
#[test]
fn an_entry_whose_host_is_not_the_owner_and_is_still_attached_stays_listed_and_counted() {
    let (census, taken, active) = (census(), moved(21), attached());
    assert_eq!(taken.standby, None, "premise: the record names no standby");
    assert_ne!(
        Target::of(&taken),
        entry().target,
        "premise: the record holds another (g, owner, E)"
    );
    assert_ne!(
        taken.owner,
        entry().host,
        "premise: the entry's host is not the owner"
    );

    let released = census.released(&taken, live(&active));

    assert_eq!(
        released, None,
        "CENSUS-COVERS: the entry of a host that still holds a live attach of the active volume was dropped"
    );
    assert_eq!((census.len(), census.slot(shard(1))), (1, Some(entry())));
    assert_eq!(
        admit_second(&census),
        Err(Refusal::Headroom),
        "HEADROOM: the listed reservation counts against host 30's attachment headroom"
    );
}

/// The same census and shard record, and host 30 holds no live attach in the volume record. The call
/// returns the census of the same zone without the entry, and host 30's free attachment slot is free again: the
/// second shard's reservation is admitted over the released census.
#[test]
fn the_same_entry_leaves_once_its_host_holds_no_live_attach() {
    let (census, taken, active) = (census(), moved(21), detached());

    let released = census
        .released(&taken, live(&active))
        .expect("an entry whose host holds no live attach leaves");

    assert_eq!(released, Census::empty(ZONE));
    assert_eq!((released.len(), released.slot(shard(1))), (0, None));
    assert_eq!(released.zone(), ZONE);
    let admitted = admit_second(&released)
        .expect("the released reservation no longer counts")
        .expect("the census takes the second shard's slot");
    assert_eq!(
        admitted.slot(shard(2)).map(|held| held.host),
        Some(host(RESERVED))
    );
    assert_eq!(
        census.slot(shard(1)),
        Some(entry()),
        "the census the call read is unchanged"
    );
}

/// The other way out: the record names host 30 its owner. Its live attach of the active volume is then the
/// owner's, and the entry leaves although `live` shows the attach.
#[test]
fn the_same_entry_leaves_when_the_record_names_its_host_the_owner() {
    let (census, promoted, active) = (census(), moved(RESERVED), attached());
    assert_eq!(
        promoted.owner,
        entry().host,
        "premise: the entry's host is the owner"
    );

    let released = census.released(&promoted, live(&active));

    assert_eq!(released, Some(Census::empty(ZONE)));
}
