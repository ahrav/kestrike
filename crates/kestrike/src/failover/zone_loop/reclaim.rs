//! The loop reclaims attachments for hosts outside the shard record's owner and standby roles: it ends a live attach,
//! requests the detach of an ended attach whose recorded pair is gone, marks the ended entry gone after two settled
//! listings omit its instance, and requests the detach of a gone entry's instance that a listing shows again.
//!
//! - END-NAMED: when the reread of `Reconciler::end_attach` names the host owner or standby, `end` returns
//!   `Wait(Moved)` with `EndedNamed`. The tick's loss evidence takes only the ends that advance, and the shard's later
//!   steps wait for the next survey.
//! - DETACH-LISTED: `detach` requests a detach only with a fresh witness for the surveyed entry, a `Detachable` from
//!   `Reconciler::detachable` for an ended entry or a `Relisted` from `Reconciler::relisted` for a gone one
//!   (DETACH-RELISTED), and a listing, read in the same step, that shows the witness's instance. The loop sends a
//!   repeat request at least `detach_settle_us` after its previous detach request for the same volume and instance,
//!   an unknown reply included. A listing that holds an unreadable identifier and omits the instance gives
//!   `Wait(Unlisted)`.
//! - RELEASE-SETTLED: `release_attach` keeps the first whole survey listing that omits the instance and is taken at
//!   least `detach_settle_us` after this loop's last attach or detach request for the entry returned, and calls
//!   `Reconciler::release_attach` with it and a second such listing at least `detach_settle_us` after the first.
//!   The request's return time is the time of the first survey after the call that made it (REQUEST-RETURNED in
//!   `actuate`), which follows the return however long the call ran. When this loop holds no request time for the
//!   entry, `tick_us` after its first survey serves as the return: a call of an earlier run of the process that
//!   began before that survey has returned or reached its deadline by then, so a restart preserves or postpones
//!   the earliest release time. Each listing uses its survey's time.
//! - SIGHTING-RESETS: [`ZoneLoop::forget_sighted`] drops a kept listing at each survey whose listing row of the volume
//!   shows the entry's instance, and the attach and detach steps drop it when their own listing of the volume shows
//!   the instance; a release later in that call waits `Moved`, and the next qualifying absence starts the pair
//!   again. A failed listing leaves the kept listing in place.
//!
//! The loop keeps request times and listings in process memory. It drops a listing when its shard reads another active
//! volume or leaves the directory.

use std::collections::BTreeMap;

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted};
use crate::failover::reconcile::{Listing, ReconcileError, Settle, StandbyGate};
use crate::failover::records::{EventKind, Host, ShardRecord, VolumeId};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::actuate::{
    Budget, Reason, Reclaim, Tick, Verdict, listing, records, verdict_of,
};
use crate::failover::zone_loop::observe::Observation;
use crate::failover::zone_loop::sources::{Attacher, DetachReply, Witness};
use crate::net::ownership::Shard;
use crate::storage::store::{Key, Store, WatermarkLog};

/// The first qualifying listing that omits an ended entry's bound instance: the entry's shard, the listing's survey
/// time, the bound instance, and every identifier the listing returned.
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    pub(super) shard: Shard,
    at: u64,
    instance: InstanceId,
    ids: Vec<String>,
}

/// Kept listings by volume and entry sequence number.
pub(crate) type Clean = BTreeMap<(VolumeId, u32), Kept>;

/// The loop's last detach request for a volume and instance, whatever the reply: `at_us`, the `now_us` of the call
/// that sent it, which spaces repeat detach requests (DETACH-LISTED), and `returned_us`, the time of the first survey
/// after it (REQUEST-RETURNED), from which RECORD-SETTLED withholds a new attach entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sent {
    pub(super) at_us: u64,
    pub(super) returned_us: Option<u64>,
}

/// The detach requests by volume and instance. [`ZoneLoop::actuate`] drops one once a survey falls
/// `detach_settle_us` after its return, which is later than the last call the repeat spacing withholds.
pub(crate) type Detached = BTreeMap<(VolumeId, InstanceId), Sent>;

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    /// Drops each kept listing whose instance a listing row of its volume in `observation` shows, even a row that also
    /// holds unreadable identifiers.
    pub(super) fn forget_sighted(&mut self, observation: &Observation) {
        let Ok(view) = &observation.zone else {
            return;
        };
        let Ok(rows) = &view.volumes else {
            return;
        };
        self.clean.retain(|(volume, _), kept| {
            let mut rows = rows.iter().filter(|row| row.volume == *volume);
            !rows.any(|row| {
                row.attachments
                    .iter()
                    .any(|id| id == kept.instance.as_str())
            })
        });
    }

    pub(super) fn saw(
        &mut self,
        fresh: &mut BTreeMap<VolumeId, Vec<String>>,
        volume: VolumeId,
        ids: &[String],
    ) {
        self.clean.retain(|(held, _), kept| {
            *held != volume || ids.iter().all(|id| id != kept.instance.as_str())
        });
        fresh.entry(volume).or_default().extend(ids.iter().cloned());
    }

    pub(super) fn end(
        &mut self,
        gate: &StandbyGate,
        tick: &mut Tick<'_>,
        shard: Shard,
        host: Host,
    ) -> (Verdict, Option<Reclaim>) {
        let Some(records) = records(tick.view, shard) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let volume = records.record.active;
        let Some(seq) = records.active.live(host) else {
            return (Verdict::Wait(Reason::Moved), None);
        };
        match self.reconciler.end_attach(gate, shard, volume, host, seq) {
            Ok(ended) if ended.named() => (Verdict::Wait(Reason::Moved), Some(Reclaim::EndedNamed)),
            Ok(_) => {
                tick.ended.insert((shard, host));
                (Verdict::Advance, Some(Reclaim::Ended))
            }
            Err(ReconcileError::Conflict) => {
                let record = match self.reconciler.read::<ShardRecord>(Key::Shard(shard)) {
                    Ok(read) => *read.value(),
                    Err(error) => match verdict_of(error.into()) {
                        Verdict::Alarm(reason) => return (Verdict::Alarm(reason), None),
                        _ => return (Verdict::Wait(Reason::Moved), None),
                    },
                };
                let refusal = if record.owner == host {
                    Some(Reclaim::RefusedOwner)
                } else if record.standby == Some(host) {
                    Some(Reclaim::RefusedStandby)
                } else {
                    None
                };
                (Verdict::Wait(Reason::Moved), refusal)
            }
            Err(error) => (self.failed(error), None),
        }
    }

    pub(super) fn detach(
        &mut self,
        tick: &mut Tick<'_>,
        shard: Shard,
        host: Host,
        budget: &mut Budget,
        effects: &mut (impl Attacher + ControlPlane),
    ) -> (Verdict, Option<Reclaim>) {
        let Some(records) = records(tick.view, shard) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let volume = records.record.active;
        let Some((seq, event)) = records.active.latest(host) else {
            return (Verdict::Wait(Reason::Moved), None);
        };
        let gone = event.kind == EventKind::Gone;
        let settle_us = self.bounds.config().detach_settle_us;
        let last = (event.instance).and_then(|instance| self.detached.get(&(volume, instance)));
        if last.is_some_and(|last| tick.now_us.saturating_sub(last.at_us) < settle_us) {
            return (Verdict::Wait(Reason::Settling), None);
        }
        let (ended, relisted) = if gone {
            match self.reconciler.relisted(volume, host) {
                Ok(witness) if witness.seq() == seq => (None, Some(witness)),
                Ok(_) => return (Verdict::Wait(Reason::Moved), None),
                Err(error) => return (verdict_of(error), None),
            }
        } else {
            match self.reconciler.detachable(volume, host) {
                Ok(witness) if witness.seq() == seq => (Some(witness), None),
                Ok(_) => return (Verdict::Wait(Reason::Moved), None),
                Err(error) => return (verdict_of(error), None),
            }
        };
        let witness = match (&ended, &relisted) {
            (Some(witness), _) => Witness::Ended(witness),
            (_, Some(witness)) => Witness::Relisted(witness),
            (None, None) => return (Verdict::Wait(Reason::Moved), None),
        };
        let instance = witness.instance();
        let listed = effects.attachments(&volume);
        if let Ok(ids) = &listed {
            self.saw(&mut tick.fresh, volume, ids);
        }
        match listed {
            Err(Unlisted) => return (Verdict::Wait(Reason::Unlisted), None),
            Ok(ids) if ids.iter().any(|id| id == instance.as_str()) => {}
            Ok(ids) if ids.iter().any(|id| InstanceId::new(id).is_none()) => {
                return (Verdict::Wait(Reason::Unlisted), None);
            }
            Ok(_) => return (Verdict::Advance, None),
        }
        if !budget.spend_call() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let reply = effects.detach(witness);
        let sent = Sent {
            at_us: tick.now_us,
            returned_us: None,
        };
        self.detached.insert((volume, instance), sent);
        if !gone {
            self.request(volume, seq, shard, tick.now_us);
        }
        match reply {
            DetachReply::Accepted | DetachReply::AlreadyDetached => {
                (Verdict::Advance, Some(Reclaim::DetachRequested))
            }
            DetachReply::Unknown => (Verdict::Wait(Reason::Unknown), Some(Reclaim::DetachUnknown)),
        }
    }

    pub(super) fn release_attach(
        &mut self,
        gate: &StandbyGate,
        tick: &Tick<'_>,
        shard: Shard,
        host: Host,
        budget: &mut Budget,
    ) -> (Verdict, Option<Reclaim>) {
        let Some(records) = records(tick.view, shard) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let volume = records.record.active;
        let latest = records.active.latest(host);
        let bound = latest.and_then(|(seq, event)| Some((seq, event.instance?)));
        let Some((seq, instance)) = bound else {
            return (Verdict::Wait(Reason::Moved), None);
        };
        let Some(ids) = listing(tick.view, volume) else {
            return (Verdict::Wait(Reason::Unlisted), None);
        };
        let fresh = tick.fresh.get(&volume).into_iter().flatten();
        if ids.iter().chain(fresh).any(|id| id == instance.as_str()) {
            return (Verdict::Wait(Reason::Moved), None);
        }
        let config = self.bounds.config();
        let (settle_us, tick_us) = (config.detach_settle_us, config.tick_us);
        let requested = match self.requests.get(&(volume, seq)) {
            Some(sent) => match sent.returned_us {
                Some(returned) => returned,
                None => return (Verdict::Wait(Reason::Settling), None),
            },
            None => tick.started_us.saturating_add(tick_us),
        };
        let at = tick.surveyed_us;
        if at < requested.saturating_add(settle_us) {
            return (Verdict::Wait(Reason::Settling), None);
        }
        let Some(kept) = self.clean.get(&(volume, seq)) else {
            let kept = Kept {
                shard,
                at,
                instance,
                ids: ids.to_vec(),
            };
            self.clean.insert((volume, seq), kept);
            return (Verdict::Wait(Reason::Settling), None);
        };
        if at.saturating_sub(kept.at) < settle_us {
            return (Verdict::Wait(Reason::Settling), None);
        }
        let witness = match self.reconciler.detachable(volume, host) {
            Ok(witness) if witness.seq() == seq && witness.instance() == instance => witness,
            Ok(_) => return (Verdict::Wait(Reason::Moved), None),
            Err(error) => return (verdict_of(error), None),
        };
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let listings = [
            Listing {
                at: kept.at,
                instances: &kept.ids,
            },
            Listing { at, instances: ids },
        ];
        let timing = Settle {
            requested,
            settle: settle_us,
        };
        let released = (self.reconciler).release_attach(gate, &witness, &listings, timing);
        match released {
            Ok(()) => {
                self.clean.remove(&(volume, seq));
                (Verdict::Advance, Some(Reclaim::Gone))
            }
            Err(error) => (self.failed(error), None),
        }
    }
}
