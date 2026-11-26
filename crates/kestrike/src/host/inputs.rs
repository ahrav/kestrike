//! [`peers`] computes an owner process's peer bindings from a volume record. The caller shares one slice from
//! [`peers`] among [`restart`], [`takeover`] and [`reads`] for the judges of OWNER-EVENTS over the same volume
//! record, so those judges bind the same hosts.

use crate::failover::attachments::{InstanceId, Peer};
use crate::failover::bounds::Bounds;
use crate::failover::detect::host::Revalidated;
use crate::failover::fresh::Fresh;
use crate::failover::poll::{Holder, Reads};
use crate::failover::records::{Host, ShardRecord, VolumeRecord};
use crate::failover::restart::Restart;
use crate::failover::takeover::Takeover;
use crate::net::ownership::Shard;
use crate::storage::ReservationLimits;

/// [`Inputs::new`] enforces agreement between `limits` and `bounds` on the registrant count and the Report deadline,
/// the two values attach requires equal.
#[derive(Debug, Clone, Copy)]
pub struct Inputs {
    shard: Shard,
    holder: Holder,
    bounds: Bounds,
    limits: ReservationLimits,
    intervals: usize,
}

impl Inputs {
    /// `intervals` is the number of intervals of one key the coverage keeps on a page.
    pub fn new(
        shard: Shard,
        holder: Holder,
        bounds: Bounds,
        limits: ReservationLimits,
        intervals: usize,
    ) -> Option<Self> {
        limits.agrees_with(&bounds).then_some(Self {
            shard,
            holder,
            bounds,
            limits,
            intervals,
        })
    }

    pub fn shard(&self) -> Shard {
        self.shard
    }

    pub fn holder(&self) -> &Holder {
        &self.holder
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }
}

/// The peers of the holder's volume: each host other than the holder's whose newest retained attach, ended or gone
/// entry in `volume` is an attach or ended entry that binds no instance ([`VolumeRecord::bound_by_lookup`]),
/// detached and force-detached format-2 hosts included, once and by first attach, each bound to the instance
/// `instance` returns for it. `None` when `volume` is another volume's record; the caller treats that as a wiring
/// fault and passes no empty slice in its place.
///
/// An entry that binds an instance gives the judges that instance itself (BIND-AT-ATTACH), so `peers` binds only the
/// hosts whose newest entries carry none, as every entry of a format-2 record does. A host whose newest entry is gone
/// binds nothing here, an older entry of it that binds no instance included: two settled listings showed its host
/// detached, and the judges admit no instance of it (ENDED-GRANTS-NOTHING). The owner's poll judges a cached listing
/// beside a later volume read, so the gone mark's settle time must exceed the gap from that listing's request to that
/// read. The owner's periods keep that gap below
/// [`LISTING_HOLD_US`](crate::failover::reconcile::LISTING_HOLD_US); a settle time above that constant is an
/// obligation of the caller of
/// [`Reconciler::release_attach`](crate::failover::reconcile::Reconciler::release_attach), which that step does not check. A host whose newest entry is ended and
/// binds no instance stays bound while the record holds that entry ended, which admits its listed instance and grants
/// it no authority, since the judges of OWNER-EVENTS read only live attaches.
///
/// `instance` returns `Some` only for a standby host the caller expects on this volume: the verified instance that
/// made the host's retained attach. It returns `None` for all other hosts, including those the caller can identify;
/// a caller whose lookup failed skips `peers`. OWNER-EVENTS accepts a bound host's live unenrolled attach, and the
/// owner's poll admits a bound host's listed instance. Binding every identifiable host can therefore admit an
/// unexpected attach. An unbound host's live unenrolled attach that binds no instance fails OWNER-EVENTS. A listed
/// instance that neither a peer nor an entry of the record admits, an enrolled host's included, retires an owner's
/// poll that reaches its listing check, which follows the deposition check.
///
/// The slice binds only hosts the source record holds. An attach recorded after that read that binds no instance,
/// still unenrolled at the judge's read and bound by no caller peer, refuses a restart or a takeover as
/// `Check::Volume(Events)`, and the caller computes the slice again from the volume record its judge reads.
pub fn peers(
    holder: &Holder,
    volume: &VolumeRecord,
    instance: impl Fn(Host) -> Option<InstanceId>,
) -> Option<Vec<Peer>> {
    (volume.volume == holder.volume).then(|| {
        volume
            .hosts_with_attach_event()
            .filter(|&host| host != holder.host && volume.bound_by_lookup(host))
            .filter_map(|host| {
                Some(Peer {
                    host,
                    instance: instance(host)?,
                })
            })
            .collect()
    })
}

/// The fresh activation over the checked inputs, so all three sequences start from one [`Inputs`].
pub fn fresh(inputs: &Inputs) -> Fresh {
    Fresh {
        shard: inputs.shard,
        holder: inputs.holder,
        bounds: inputs.bounds,
        limits: inputs.limits,
        intervals: inputs.intervals,
    }
}

pub fn restart<'a>(inputs: &Inputs, peers: &'a [Peer]) -> Restart<'a> {
    Restart {
        shard: inputs.shard,
        holder: inputs.holder,
        bounds: inputs.bounds,
        limits: inputs.limits,
        peers,
        intervals: inputs.intervals,
    }
}

/// `None` under each refusal of [`Takeover::nominated`]: a witness of another shard, or one that expired.
pub fn takeover<'a>(
    inputs: &Inputs,
    peers: &'a [Peer],
    witness: &Revalidated,
    now: u64,
) -> Option<Takeover<'a>> {
    Takeover::nominated(restart(inputs, peers), witness, now)
}

/// The reads of one check, each `None` when its read returned no value. The caller takes them in READ-ORDER: the
/// owner's poll obtains the Report and the listing before it reads the volume record, then the shard record; the
/// builder checks no order. With `volume` unread the poll admits a listed instance of every host in `peers` and of no
/// entry, and a slice from [`peers`] holds no host whose entry binds its instance. A caller without the volume record
/// therefore passes the binding of its last volume record read: that record's [`peers`] and, with its host, each
/// instance an attach or ended entry of another host binds there ([`VolumeRecord::bound_beside`]), the set that
/// record admitted. The owner's duties pass it for a listing they adopted before the view that read that record
/// (READ-ORDER). For a later listing they pass no peer and a listing reduced to what no binding admits: the
/// holder's records, the malformed records and the records listed more than once.
pub fn reads<'a>(
    shard: Option<&'a ShardRecord>,
    volume: Option<&'a VolumeRecord>,
    listed: Option<&'a [String]>,
    peers: &'a [Peer],
) -> Reads<'a> {
    Reads {
        shard,
        volume,
        listed,
        peers,
    }
}
