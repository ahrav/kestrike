//! `OwnerView` holds the latest accepted record of the owner's shard, the caller's attachment binding for that record's
//! host, the owner's own volume identity and retirement state, the own volume's last read state and recorded layout,
//! and the time the named checkpoint was first read. Accepted shard reads move forward only: each one
//! carries a store version and a `(g, E)` at or above the last accepted read's.
use crate::failover::identity::Exhid;
use crate::failover::records::{
    Host, Layout, NamedCheckpoint, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::report::RecordedRole;
use crate::failover::serving::{Cause, Token};
use crate::storage::AuthorityReport;
use crate::storage::Session;
use crate::storage::store::{Read, Version};

use super::ownership::{ActivatedEpoch, OwnershipBody, ShardGeneration, Tenure, Validity, Volume};

#[derive(Default)]
pub(super) struct OwnerView {
    shard: Option<ShardRecord>,
    shard_version: Option<Version>,
    /// The caller's binding of `shard`'s owner host to its attachment identifier.
    owner: Option<(Host, Exhid)>,
    /// The session's own host, which names this owner in a shard record.
    local: Option<Host>,
    /// The attached volume, fixed by the first observation.
    own: Option<VolumeId>,
    /// The `(g, attempts, owner)` that the last observation in which both reads returned a value named, when its
    /// accepted shard read names the own volume active; cleared by any returned read that contradicts that, whatever
    /// the other read returned. A read that returned no value, a store outage, is no evidence. The judgment holds
    /// only for the tenure it names: an accepted read alone that names a later tenure leaves it in place, and `body`
    /// grants it to no other tenure.
    fresh: Option<(ShardGeneration, u32, Host)>,
    /// Set once the own volume's record reaches `VolumeState::Retired` or a later shard record names another active
    /// volume; `retired` stays true thereafter.
    retired: bool,
    /// The state of the own volume's last read record, and whether that record lists a pair of the local host.
    own_read: Option<(VolumeState, bool)>,
    /// The recorded layout of the own volume's last read record.
    layout: Option<Layout>,
    /// The live attaches the own volume's last read record lists.
    attaches: Option<usize>,
    /// The checkpoint `shard` names, with the time of the first accepted read that named it.
    named_since: Option<(NamedCheckpoint, u64)>,
}

/// The own volume, the role and volume state that the last accepted shard read and the last own-volume read give
/// the local host, whether that shard record names the local host its standby on the own volume, `None` before an
/// accepted shard record, the last accepted
/// shard record, the layout the last own-volume read recorded, and the checkpoint the shard record names with the
/// time of its first read.
pub(super) struct Recorded<'a> {
    pub(super) volume: VolumeId,
    pub(super) role: Option<RecordedRole>,
    pub(super) named: Option<bool>,
    pub(super) state: Option<VolumeState>,
    pub(super) shard: Option<&'a ShardRecord>,
    pub(super) layout: Option<&'a Layout>,
    pub(super) named_since: Option<(NamedCheckpoint, u64)>,
    pub(super) attaches: Option<usize>,
}

impl OwnerView {
    pub(super) fn observe(
        &mut self,
        session: &Session,
        own: VolumeId,
        shard: Option<&Read<ShardRecord>>,
        volume: Option<&Read<VolumeRecord>>,
        owner: Option<(Host, Exhid)>,
        now_us: u64,
    ) -> Option<Cause> {
        let target = session.target();
        self.local = Some(target.owner);
        let own = &*self.own.get_or_insert(own);
        let serving = (target.generation, target.attempts);
        let mut cause = None;
        let shard_returned = shard.is_some();
        let shard = shard.filter(|read| read.value().shard == session.shard());
        let accepted = shard.filter(|read| {
            let record = read.value();
            (record.generation, record.attempts) >= serving
                && self
                    .shard_version
                    .is_none_or(|version| read.version() >= version)
                && self.shard.as_ref().is_none_or(|old| {
                    (record.generation, record.attempts) >= (old.generation, old.attempts)
                })
        });
        if shard.is_some() && accepted.is_none() {
            cause = Some(Cause::Regression);
        }
        if let Some(read) = accepted {
            let record = read.value();
            let same = self.shard.as_ref().is_some_and(|old| {
                old.generation == record.generation
                    && old.active == record.active
                    && old.owner == record.owner
            });
            self.shard_version = Some(read.version());
            self.shard = Some(*record);
            self.named_since = record.checkpoint.map(|checkpoint| match self.named_since {
                Some((since, at)) if since == checkpoint => (since, at),
                _ => (checkpoint, now_us),
            });
            self.owner = owner
                .filter(|(host, _)| *host == record.owner)
                .or(self.owner.filter(|_| same));
            let named = (record.generation, record.attempts);
            if named > serving
                || (named == serving && (record.owner != target.owner || record.active != *own))
            {
                cause = Some(Cause::Flipped);
            }
        }
        if let Some(record) = &self.shard {
            self.retired |= (record.generation, record.attempts) > serving && record.active != *own;
        }
        let volume_active = match volume.map(Read::value) {
            Some(record) if record.volume == *own => {
                self.retired |= record.state >= VolumeState::Retired;
                let listed = record.records_pair_of(target.owner);
                self.own_read = Some((record.state, listed));
                self.layout = Some(record.layout);
                self.attaches = Some(record.live_hosts().count());
                Some(self.shard.as_ref().is_some_and(|shard| {
                    crate::failover::flip::volume_state(shard, record) == Ok(VolumeState::Active)
                }))
            }
            Some(_) => Some(false),
            None => None,
        };
        // A read that returned no value, a store outage, is no evidence; a read that returned a value contradicting
        // the view clears it, an accepted shard read naming another active volume included.
        match (shard_returned, volume_active) {
            (true, Some(active)) => {
                self.fresh = accepted
                    .filter(|_| active)
                    .map(|read| read.value())
                    .map(|record| (record.generation, record.attempts, record.owner))
            }
            (true, None) if accepted.is_none_or(|read| read.value().active != *own) => {
                self.fresh = None
            }
            (false, Some(false)) => self.fresh = None,
            _ => {}
        }
        // A retired own volume shows a later tenure, which outranks a regressed shard read in the same observation.
        if self.retired {
            cause = Some(Cause::Flipped);
        }
        cause
    }

    /// What the records give the own volume, or `None` before an observation names it. The role follows the last
    /// accepted shard record; `Standby` also needs that record to name the own volume active and the last
    /// own-volume read to list a local pair, and without an own-volume read a role other than `Owner` or
    /// `Replacement` is `None`.
    pub(super) fn recorded(&self) -> Option<Recorded<'_>> {
        let own = self.own?;
        let role = self
            .shard
            .as_ref()
            .zip(self.local)
            .and_then(|(record, local)| {
                if (record.owner, record.active) == (local, own) {
                    Some(RecordedRole::Owner)
                } else if record.spare == Some((own, local)) {
                    Some(RecordedRole::Replacement)
                } else {
                    self.own_read
                        .map(|(_, listed)| match listed && record.active == own {
                            true => RecordedRole::Standby,
                            false => RecordedRole::Unrecorded,
                        })
                }
            });
        let named = self
            .shard
            .as_ref()
            .zip(self.local)
            .map(|(record, local)| (record.standby, record.active) == (Some(local), own));
        Some(Recorded {
            volume: own,
            role,
            named,
            state: self.own_read.map(|(state, _)| state),
            shard: self.shard.as_ref(),
            layout: self.layout.as_ref(),
            named_since: self.named_since,
            attaches: self.attaches,
        })
    }

    pub(super) fn body(
        &self,
        token: Token,
        report: AuthorityReport,
        report_valid: bool,
    ) -> OwnershipBody<'_> {
        let record = (self.shard.as_ref()).filter(|record| record.shard == token.shard);
        let tenure = record.and_then(|record| {
            Some(Tenure {
                generation: record.generation,
                epoch: ActivatedEpoch::new(record.attempts.checked_mul(2)?)?,
                host: if self.local == Some(record.owner) && record.generation == token.generation {
                    token.exhid
                } else {
                    self.owner?.1
                },
            })
        });
        let current = self.fresh.is_some_and(|judged| {
            record.is_some_and(|r| (r.generation, r.attempts, r.owner) == judged)
        }) && !self.retired
            && record.is_some_and(|r| self.own.as_ref() == Some(&r.active))
            && tenure == Some(tenure_of(token));
        let reported = current
            && report.report_age_us.is_some()
            && report_valid
            && report.withdrawal.is_none();
        let serving = reported
            && report.state == crate::failover::serving::State::Serving
            && !report.withheld;
        let flags = if reported { Validity::REPORT } else { 0 }
            | if serving {
                Validity::SERVING | Validity::LIVE
            } else {
                0
            };
        OwnershipBody {
            shard: token.shard,
            volume: self.own.as_ref().map(|v| Volume {
                name: v.as_str(),
                state: if self.retired {
                    super::ownership::VolumeState::Retired
                } else {
                    super::ownership::VolumeState::Active
                },
            }),
            tenure,
            report_age_us: if reported {
                report.report_age_us.unwrap_or(0)
            } else {
                0
            },
            responder: Some(token.exhid),
            validity: Validity::new(flags).expect("ownership flags are listed"),
        }
    }
}

pub(super) fn tenure_of(token: Token) -> Tenure {
    Tenure {
        generation: token.generation,
        epoch: token.epoch,
        host: token.exhid,
    }
}
