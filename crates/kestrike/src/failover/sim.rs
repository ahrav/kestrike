//! A simulation of one shard across hosts over the store double, a control-plane double and per-volume media, with
//! stale and unrecorded attach arms. The owner polls and serves, the standby checks its idle spare, the reconciler
//! admits retirement requests, provisions spares and flips, and a new owner runs the fresh check before its first
//! device command. A unit's media records its writer, and a read hits only when that writer is the session the
//! owner's index names, so a foreign landing reads as a miss. Every check reads the volume record before the shard
//! record, and the store double fails reads only as unavailable.
//!
//! The simulated reconciler is a store client. It serves an admitted request for the active volume with one
//! `Client::flip` write only after the operator's release of that request, an event of its own ([`World::release`]): in
//! the release's step when the spare passes the pre-flip check, and on a later [`World::tick`] otherwise. Under
//! [`Gate::Release`] the request waits in `World::awaiting` until the operator releases it. [`World::unreleased`]
//! compares the store's flip log with the release log and lists each committed flip that displaces a volume before the
//! operator releases a request from the displaced volume's tenure; a correct world yields an empty list. Under the
//! planted [`Gate::WithoutRelease`], the reconciler checks the spare when it admits the request and flips at once if
//! the spare passes. Under [`Operator::Releases`], the default, the operator releases each such request right after its
//! alarm; under [`Operator::Silent`] each request stays pending. A fresh host parks while its request for its volume
//! waits for the release or for a usable spare, and resumes its attempts once a flip moves the shard. The reconciler's
//! one check of the spare before a flip is the attachment listing (LISTED-SPARE). The `compile_fail` doctests on
//! `StandbyGate` and `OperatorRelease` check the gates of `Reconciler::flip` and `Reconciler::flip_for`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted, check};
use crate::failover::evidence::{Pair, Registrant, Report, ReservationType};
use crate::failover::evidence_tests::{bounds, pair};
use crate::failover::poll::{self, Holder, Reads, Verdict};
use crate::failover::records::{
    AttachmentEvent, CreationSource, ERA, EventKind, Host, Layout, Lineage, ShardRecord, VolumeId,
    VolumeRecord, VolumeState,
};
use crate::failover::retire::{Admitted, Retirement, Role, Target, Trigger};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::seeded::SplitMix64;
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Key, Outcome, Read, Store, StoreError, Tracked};
use crate::storage::store_tests::client;

/// The fleet hosts: the first owner, its standby, and the stale attacher.
pub(crate) const HOSTS: [u64; 3] = [1, 2, 3];
/// An instance outside the fleet.
pub(crate) const FOREIGN: &str = "i-0000beef";

/// The instance of `host`: eight hex digits for a host number that fits 32 bits, seventeen above it.
pub(crate) fn instance(host: u64) -> InstanceId {
    if host <= u64::from(u32::MAX) {
        InstanceId::new(&format!("i-{host:08x}")).unwrap()
    } else {
        InstanceId::new(&format!("i-{host:017x}")).unwrap()
    }
}

pub(crate) fn host(value: u64) -> Host {
    Host::new(value).unwrap()
}

/// The instance the tests give `host`: `i-` and the host's number in 17 hexadecimal digits.
pub(crate) fn instance_of_host(host: Host) -> InstanceId {
    InstanceId::new(&format!("i-{:017x}", host.get())).unwrap()
}

/// The test instance of every host numbered 1 to 255, as `Binding::unbound` rows.
fn test_peers() -> &'static [crate::failover::attachments::Peer] {
    static PEERS: std::sync::LazyLock<Vec<crate::failover::attachments::Peer>> =
        std::sync::LazyLock::new(|| {
            (1..=255)
                .map(|number| {
                    let host = host(number);
                    crate::failover::attachments::Peer {
                        host,
                        instance: instance_of_host(host),
                    }
                })
                .collect()
        });
    &PEERS
}

/// A standby attach record's binding for `host` under its test instance, with the test instance of every other
/// numbered host for the live entries that bind none, and no listing.
pub(crate) fn binding(host: Host) -> crate::failover::reconcile::Binding<'static> {
    crate::failover::reconcile::Binding {
        instance: instance_of_host(host),
        unbound: test_peers(),
        listing: None,
    }
}

fn shard() -> Shard {
    Shard::new(5).unwrap()
}

/// How a foreign attachment reaches a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attach {
    /// A fleet host's attach from a desired state computed before the volume was assigned: its event is in the
    /// volume record and the control plane lists it.
    Stale,
    /// An attach by software outside the protocol: only the control plane lists it.
    Unrecorded,
}

/// Who wrote a unit of a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Writer {
    Session(u64),
    Foreign,
}

/// The checks the simulation runs: the production checks, or a control that omits the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Checks {
    Listing,
    /// The poll and the fresh check take the volume record's attach events as their listing.
    WithoutListing,
}

/// The control-plane double: every attachment record of each volume, whatever its state, visible to the next call;
/// the double drops no record, so the harness holds the listing premises of FreshIsEmpty, and a test that empties
/// a listing models an omitted record. A count of calls that return no listing is its one fault.
#[derive(Default)]
pub(crate) struct Plane {
    pub(crate) listed: BTreeMap<VolumeId, Vec<String>>,
    pub(crate) down: u32,
}

impl ControlPlane for Plane {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        if self.down > 0 {
            self.down -= 1;
            return Err(Unlisted);
        }
        Ok(self.listed.get(volume).cloned().unwrap_or_default())
    }
}

/// One volume's reservation records the own pair while registered and a foreign holder.
#[derive(Debug, Default, Clone, Copy)]
struct Reservation {
    own: Option<Pair>,
    foreign: Option<Pair>,
}

/// The serving owner's process.
pub(crate) struct Owner {
    pub(crate) holder: Holder,
    target: Target,
    session: u64,
    pair: Pair,
    client: Client<Shared, MemLog>,
    index: BTreeMap<u32, u64>,
    pub(crate) withdrawn: bool,
    /// POST-WITHDRAWAL-POLL: a withdrawal with no request, a deposing status or a hold, keeps the owner's poll until
    /// a poll retires or deposes.
    polling: bool,
    /// Writes submitted to the device and not yet landed, in submission order.
    in_flight: Vec<u32>,
}

/// The operator's response to a retirement alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operator {
    /// Releases each request for the active volume right after its alarm, an event of its own.
    Releases,
    /// Leaves each request for the active volume pending in `World::awaiting`.
    Silent,
}

/// Whether the simulated reconciler waits for the operator's release of an admitted request for the active volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// The correct reconciler: the request waits in `World::awaiting` until the operator releases it.
    Release,
    /// The planted control: the reconciler checks the spare when it admits the request, flips at once if the spare
    /// passes, and defers the request to [`World::tick`] otherwise. The plant routes a deferred request to
    /// `deferred`, so under [`Operator::Releases`] the eager release returns false and [`World::unreleased`] reports
    /// the later flip.
    WithoutRelease,
}

/// The operator's release of one pending request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Release {
    request: Retirement,
    /// The number of shard flips the store had committed when the operator released the request.
    flips: usize,
}

pub(crate) struct World {
    pub(crate) store: Shared,
    reconciler: Client<Shared, MemLog>,
    pub(crate) plane: Plane,
    pub(crate) media: BTreeMap<VolumeId, BTreeMap<u32, Writer>>,
    reservations: BTreeMap<VolumeId, Reservation>,
    pub(crate) owner: Option<Owner>,
    pub(crate) checks: Checks,
    /// Every retirement a check raised, in order: the alarms.
    pub(crate) alarms: Vec<Retirement>,
    /// Every volume a fresh path activated, with whether a foreign writer had written it.
    pub(crate) activated: Vec<(VolumeId, bool)>,
    /// Every volume the reconciler retired.
    pub(crate) retired: Vec<VolumeId>,
    /// Every admissible active request the reconciler deferred for want of a spare its pre-flip check admits.
    pub(crate) deferred: Vec<Retirement>,
    pub(crate) gate: Gate,
    pub(crate) operator: Operator,
    /// `awaiting` holds each active [`Gate::Release`] request awaiting release exactly once, in arrival order. An
    /// entry may have gone stale since its delivery; a release call removes a stale match and returns false.
    awaiting: Vec<Retirement>,
    /// Every release the operator made, in order.
    releases: Vec<Release>,
    /// The index in the store's flip log of every flip [`World::flip`] committed as a fixture step for a test's
    /// setup.
    fixture_flips: Vec<usize>,
    /// Which of the last owner poll's record reads returned no value.
    pub(crate) unread: Unread,
    volumes: u32,
    pub(crate) trace: Rc<RefCell<Vec<&'static str>>>,
    pub(crate) refusals: crate::failover::fresh::Refusals,
}

/// Which of a poll's record reads returned no value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unread {
    pub(crate) volume: bool,
    pub(crate) shard: bool,
}

impl Unread {
    /// The sweep's coverage marker for the reads that failed.
    fn marker(self) -> Option<&'static str> {
        match (self.volume, self.shard) {
            (true, false) => Some("volume read outage"),
            (false, true) => Some("shard read outage"),
            (true, true) => Some("store outage"),
            (false, false) => None,
        }
    }
}

/// The fixed layout every simulated volume records.
pub(crate) fn layout() -> Layout {
    Layout {
        units: 64,
        slots: 3,
        slot_units: 3,
        entries: 64,
    }
}

/// A check's read: `None` when the store is unavailable. The simulation schedules no other read failure.
fn observed<R: Tracked>(read: Result<Read<R>, StoreError>) -> Option<Read<R>> {
    match read {
        Ok(read) => Some(read),
        Err(StoreError::Unavailable) => None,
        Err(error) => panic!("the simulation schedules only unavailable reads: {error:?}"),
    }
}

impl World {
    /// A shard at `g = 1` whose active volume host 1 attached and whose spare host 2 attached, before any owner
    /// activates.
    pub(crate) fn new(checks: Checks) -> Self {
        let store = Shared::new();
        let mut world = Self {
            reconciler: client(&store),
            store,
            plane: Plane::default(),
            media: BTreeMap::new(),
            reservations: BTreeMap::new(),
            owner: None,
            checks,
            alarms: Vec::new(),
            activated: Vec::new(),
            retired: Vec::new(),
            deferred: Vec::new(),
            gate: Gate::Release,
            operator: Operator::Releases,
            awaiting: Vec::new(),
            releases: Vec::new(),
            fixture_flips: Vec::new(),
            unread: Unread::default(),
            volumes: 0,
            trace: Rc::default(),
            refusals: crate::failover::fresh::Refusals::default(),
        };
        let active = world.provision_volume(HOSTS[0]);
        let spare = world.provision_volume(HOSTS[1]);
        let record = ShardRecord {
            shard: shard(),
            generation: ShardGeneration::new(1).unwrap(),
            active,
            owner: host(HOSTS[0]),
            attempts: 0,
            spare: Some((spare, host(HOSTS[1]))),
            checkpoint: None,
            cut: 0,
            pages: core::num::NonZeroU16::new(1).unwrap(),
            page_cap: core::num::NonZeroU32::new(64).unwrap(),

            namespace: crate::storage::store::sim::NAMESPACE,

            ancestry: Default::default(),
            standby: None,
        };
        world.reconciler.create_shard(record).unwrap();
        world
    }

    /// The reconciler's client checks each shard read against its watermark. A read that returns a version below
    /// the one the client observed is a regression, and the unwrap fails the test that scheduled it.
    fn shard_read(&mut self) -> Read<ShardRecord> {
        self.reconciler
            .read::<ShardRecord>(Key::Shard(shard()))
            .unwrap()
    }

    pub(crate) fn shard_record(&mut self) -> ShardRecord {
        *self.shard_read().value()
    }

    /// The state the store holds for `volume`, read by a client of its own.
    pub(crate) fn stored_state(&self, volume: VolumeId) -> VolumeState {
        client(&self.store)
            .read::<VolumeRecord>(Key::Volume(volume))
            .unwrap()
            .value()
            .state
    }

    /// Creates a volume record with its one attach event, and only then attaches it in the control plane.
    fn provision_volume(&mut self, owner: u64) -> VolumeId {
        self.volumes += 1;
        let volume = VolumeId::new(&format!("vol-{:x}", 0xa0 + self.volumes)).unwrap();
        let record = VolumeRecord {
            volume,
            state: VolumeState::Fresh,
            source: CreationSource::Provisioned,
            lineage: Lineage::None,
            modification: None,
            layout: layout(),
            next: 1,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![AttachmentEvent {
                seq: 0,
                kind: EventKind::Attach,
                host: host(owner),
                era: ERA,
                instance: None,
            }],
        };
        self.reconciler.create(Key::Volume(volume), record).unwrap();
        self.plane
            .listed
            .insert(volume, vec![instance(owner).as_str().to_owned()]);
        volume
    }

    fn volume_record(
        client: &mut Client<Shared, MemLog>,
        volume: VolumeId,
    ) -> Option<Read<VolumeRecord>> {
        observed(client.read::<VolumeRecord>(Key::Volume(volume)))
    }

    /// A check's record reads: the volume record, then the shard record (READ-ORDER).
    fn records(
        client: &mut Client<Shared, MemLog>,
        volume: VolumeId,
    ) -> (Option<Read<VolumeRecord>>, Option<Read<ShardRecord>>) {
        let volume = Self::volume_record(client, volume);
        let shard = observed(client.read::<ShardRecord>(Key::Shard(shard())));
        (volume, shard)
    }

    /// Runs up to `rounds` fresh attempts on the active volume the shard record names and returns true when one
    /// activates. If an active request in `awaiting` or `deferred` still admits the record, the call returns false
    /// before the round's attempt. A refused round that raises a request continues to the next round; a refusal that
    /// raises none returns false, as does a call whose rounds all end in raised requests.
    pub(crate) fn activate(&mut self, rounds: u32) -> bool {
        for _ in 0..rounds {
            let record = self.shard_record();
            if self.parked(&record) {
                return false;
            }
            let owner = record.owner.get();
            let holder = Holder {
                volume: record.active,
                host: record.owner,
                instance: instance(owner),
            };
            let pair = pair(owner as u8, 1, 1);
            let foreign = self
                .media
                .get(&holder.volume)
                .is_some_and(|units| units.values().any(|writer| *writer == Writer::Foreign));
            self.trace.borrow_mut().push("start");
            let log = MemLog::default();
            let mut client = Client::open(
                FreshStore {
                    inner: self.store.clone(),
                    trace: self.trace.clone(),
                    bumped: false,
                },
                log.clone(),
            )
            .unwrap();
            let mut local = SimLocal {
                holder,
                pair,
                refused: false,
                trace: self.trace.clone(),
            };
            let mut listing = Listing {
                checks: self.checks,
                plane: &mut self.plane,
                store: &self.store,
                trace: self.trace.clone(),
            };
            let mut card = FreshCard {
                reservations: &mut self.reservations,
                volume: holder.volume,
                unit0: None,
                trace: self.trace.clone(),
            };
            let result = crate::failover::fresh::tests::fresh_of(shard(), holder).run(
                &mut client,
                &mut listing,
                &mut local,
                &mut card,
                &mut self.refusals,
            );
            let activated = match result {
                Ok(activated) => activated,
                Err(refused) => match refused.retirement(holder.volume) {
                    Some(retirement) => {
                        self.raise(retirement);
                        continue;
                    }
                    None => return false,
                },
            };
            let session = activated.session();
            self.media
                .entry(holder.volume)
                .or_default()
                .insert(0, Writer::Session(session.get()));
            self.activated.push((holder.volume, foreign));
            self.owner = Some(Owner {
                holder,
                target: session.target(),
                session: session.get(),
                pair,
                client: Client::open(self.store.clone(), log).unwrap(),
                index: BTreeMap::new(),
                withdrawn: false,
                polling: false,
                in_flight: Vec::new(),
            });
            return true;
        }
        false
    }

    /// Writes `unit` as the owner. A withdrawn owner submits nothing, and a write without the reservation fails.
    pub(crate) fn write(&mut self, unit: u32) -> bool {
        let Some(owner) = self.owner.as_mut().filter(|owner| !owner.withdrawn) else {
            return false;
        };
        let reservation = self
            .reservations
            .get(&owner.holder.volume)
            .copied()
            .unwrap_or_default();
        if reservation.own != Some(owner.pair) || reservation.foreign.is_some() {
            return false;
        }
        self.media
            .entry(owner.holder.volume)
            .or_default()
            .insert(unit, Writer::Session(owner.session));
        owner.index.insert(unit, owner.session);
        true
    }

    /// Reads `unit` as the owner: `Some(true)` for a hit, `Some(false)` for a miss, `None` when no owner serves or its
    /// index holds no entry for `unit`. A hit requires the unit's writer to be the session the index names for it.
    pub(crate) fn read(&self, unit: u32) -> Option<bool> {
        let owner = self.owner.as_ref().filter(|owner| !owner.withdrawn)?;
        let named = owner.index.get(&unit)?;
        let writer = self.media.get(&owner.holder.volume)?.get(&unit);
        Some(writer == Some(&Writer::Session(*named)))
    }

    /// A foreign attachment of `volume` by `arm`. With `loss` it registers and preempts the reservation, so its
    /// writes land and the owner's fail.
    pub(crate) fn attach(&mut self, volume: VolumeId, arm: Attach, loss: bool) {
        let attacher = match arm {
            Attach::Stale => {
                let stale = HOSTS[2];
                let read = Self::volume_record(&mut self.reconciler, volume).unwrap();
                let mut next = read.value().clone();
                next.push(EventKind::Attach, host(stale), ERA);
                self.reconciler.replace(&read, next).unwrap();
                instance(stale).as_str().to_owned()
            }
            Attach::Unrecorded => FOREIGN.to_owned(),
        };
        self.plane.listed.entry(volume).or_default().push(attacher);
        if loss {
            let reservation = self.reservations.entry(volume).or_default();
            reservation.own = None;
            reservation.foreign = Some(pair(0xff, 7, 1));
        }
    }

    pub(crate) fn reserve_foreign(&mut self, volume: VolumeId) {
        self.reservations.entry(volume).or_default().foreign = Some(pair(0xff, 7, 1));
    }

    /// A foreign write of `unit`: it lands on a volume nobody holds and on one the foreign attachment holds.
    pub(crate) fn foreign_write(&mut self, volume: VolumeId, unit: u32) -> bool {
        let reservation = self.reservations.get(&volume).copied().unwrap_or_default();
        if reservation.own.is_some() && reservation.foreign.is_none() {
            return false;
        }
        self.media
            .entry(volume)
            .or_default()
            .insert(unit, Writer::Foreign);
        true
    }

    /// A command of the serving owner completes with a deposing status (`0x1B` or `0x83`): the owner withdraws with
    /// no request, and its polls judge the holder and the listing (STATUS-REJUDGE, POST-WITHDRAWAL-POLL).
    pub(crate) fn deposing_status(&mut self) {
        let owner = self
            .owner
            .as_mut()
            .filter(|owner| !owner.withdrawn)
            .unwrap();
        (owner.withdrawn, owner.polling) = (true, true);
    }

    /// The owner's poll: its Report, its reads of the volume and shard records, and the listing. A withdrawn owner
    /// polls while its withdrawal made no request.
    pub(crate) fn poll(&mut self) -> Option<Verdict> {
        let owner = self
            .owner
            .as_mut()
            .filter(|owner| !owner.withdrawn || owner.polling)?;
        let mut entries = Vec::new();
        let rtype = report(&self.reservations, owner.holder.volume, &mut entries);
        let report = Report {
            submitted_at: 0,
            rtype,
            regctl: entries.len() as u32,
            entries: &entries,
        };
        let plane = match self.checks {
            Checks::Listing => Some(self.plane.attachments(&owner.holder.volume).ok()),
            Checks::WithoutListing => None,
        };
        let (volume, read) = Self::records(&mut owner.client, owner.holder.volume);
        self.unread = Unread {
            volume: volume.is_none(),
            shard: read.is_none(),
        };
        let listed = plane.unwrap_or_else(|| {
            listing(
                self.checks,
                &mut self.plane,
                owner.holder.volume,
                volume.as_ref(),
            )
        });
        let verdict = poll::poll(
            &owner.holder,
            owner.target,
            owner.pair,
            Ok(&report),
            &Reads {
                shard: read.as_ref().map(Read::value),
                volume: volume.as_ref().map(Read::value),
                listed: listed.as_deref(),
                peers: &[],
            },
            &bounds(),
        );
        owner.withdrawn = owner.polling
            || matches!(
                verdict,
                Verdict::Retire(_) | Verdict::Deposed | Verdict::Withdraw
            );
        owner.polling =
            owner.withdrawn && !matches!(verdict, Verdict::Retire(_) | Verdict::Deposed);
        if let Verdict::Retire(retirement) = &verdict {
            self.raise(retirement.clone());
        }
        Some(verdict)
    }

    /// The standby's check of the shard's spare: it finds the spare in the shard record, then reads the spare's
    /// volume record and the shard record again for the check.
    pub(crate) fn check_spare(&mut self) -> Option<Verdict> {
        let (volume, standby) = self.shard_record().spare?;
        let holder = Holder {
            volume,
            host: standby,
            instance: instance(standby.get()),
        };
        let mut client = client(&self.store);
        let (volume_read, read) = Self::records(&mut client, volume);
        let listed = self.plane.attachments(&volume).ok();
        let verdict = poll::spare(
            &holder,
            &Reads {
                shard: read.as_ref().map(Read::value),
                volume: volume_read.as_ref().map(Read::value),
                listed: listed.as_deref(),
                peers: &[],
            },
        );
        if let Verdict::Retire(retirement) = &verdict {
            self.raise(retirement.clone());
        }
        Some(verdict)
    }

    /// The reconciler handles the alarm's request before the operator under [`Operator::Releases`] answers it, so a
    /// planted reconciler's flip at admission commits before the operator's call to `release`, which then finds no
    /// waiting request, and [`World::unreleased`] reports the flip's source generation.
    fn raise(&mut self, retirement: Retirement) {
        self.alarms.push(retirement.clone());
        self.reconcile(&retirement);
        if retirement.role == Role::Active && self.operator == Operator::Releases {
            self.release(&retirement);
        }
    }

    /// Whether a fresh host on `record`'s active volume parks: an active request for that volume waits for the
    /// operator's release or for a usable spare, and still admits `record`, the recovering allowance at `E + 1`
    /// included.
    fn parked(&self, record: &ShardRecord) -> bool {
        self.awaiting
            .iter()
            .chain(&self.deferred)
            .any(|request| request.role == Role::Active && request.admit(record).is_ok())
    }

    /// The reconciler checks admission against the current shard record before any write and returns on a stale
    /// request. Under [`Gate::Release`] an admissible active request the operator has not released waits in
    /// `awaiting`, once. For an active request with a release, and for every active request under the planted
    /// [`Gate::WithoutRelease`], the reconciler provides a spare the pre-flip check admits; if the check finds no
    /// usable spare, the reconciler keeps the request for [`World::tick`]. It writes the admitted retirement on one
    /// read, and after a spare's retirement it provisions a replacement.
    fn reconcile(&mut self, request: &Retirement) {
        if request.admit(self.shard_read().value()).is_err() {
            return;
        }
        let unreleased = request.role == Role::Active
            && !self
                .releases
                .iter()
                .any(|release| release.request == *request);
        if unreleased && self.gate == Gate::Release {
            if !self.awaiting.contains(request) {
                self.awaiting.push(request.clone());
            }
            return;
        }
        if request.role == Role::Active && !self.provide_spare() {
            if !self.deferred.contains(request) {
                self.deferred.push(request.clone());
            }
            return;
        }
        let read = self.shard_read();
        match request.role {
            Role::Active => request
                .admit(read.value())
                .map_err(StoreError::Stale)
                .and_then(|_| self.reconciler.flip(&read).map(drop)),
            Role::Spare => self.reconciler.retire(&read, request).map(drop),
        }
        .expect("the simulation's admitted retirement commits");
        self.retire_volume(request.volume);
        if request.role == Role::Spare {
            self.provide_spare();
        }
    }

    /// The operator can call `release` as a separate simulation step. `release` removes `request` from `awaiting`
    /// before checking admission. If `request` still admits the current shard record, `release` records the release
    /// with the store's flip count, the reconciler handles `request` in the same step, and `release` returns true.
    /// `release` returns false if the lookup in `awaiting` fails or the admission check rejects `request`.
    pub(crate) fn release(&mut self, request: &Retirement) -> bool {
        let Some(at) = self
            .awaiting
            .iter()
            .position(|awaiting| awaiting == request)
        else {
            return false;
        };
        self.awaiting.remove(at);
        if request.admit(self.shard_read().value()).is_err() {
            return false;
        }
        let flips = self.store.0.borrow().flips.len();
        self.releases.push(Release {
            request: request.clone(),
            flips,
        });
        self.reconcile(request);
        true
    }

    /// The source generation of every committed flip that served a host's request before the operator released it,
    /// judged from the store's flip log and shard-record history, outside the reconciler. A flip from generation
    /// `g` replaced the last shard-record version at `g`. It counts as released when a release recorded before the
    /// flip committed names a flip request matching the replaced record's active volume and tenure `(g, owner, E)`.
    /// A recovering request also matches at `E + 1`. A spare-role request naming the record's spare counts as a
    /// spare-removal request. The oracle reports a flip when it finds releases only for spare-removal requests. The
    /// oracle treats requests in the same tenure that differ only by trigger as sharing a release;
    /// `World::release` binds the exact request.
    /// `fixture_flips` identifies the setup steps of [`World::flip`]; the oracle evaluates the host-request flips of
    /// this single-shard world.
    pub(crate) fn unreleased(&self) -> Vec<u64> {
        let store = self.store.0.borrow();
        let versions = store.versions(&Key::Shard(shard()));
        let records: Vec<ShardRecord> = versions
            .iter()
            .map(|item| {
                <ShardRecord as crate::failover::records::Record>::decode(&item.value).unwrap()
            })
            .collect();
        store
            .flips
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.fixture_flips.contains(index))
            .filter_map(|(index, &source)| {
                let replaced = records
                    .iter()
                    .rev()
                    .find(|record| record.generation.get() == source)
                    .expect("the one shard's history holds the version each logged flip replaced");
                let released = self.releases.iter().any(|release| {
                    release.request.admit(replaced) == Ok(Admitted::Flip) && release.flips <= index
                });
                (!released).then_some(source)
            })
            .collect()
    }

    /// The reconciler's next step: it delivers every deferred request again.
    pub(crate) fn tick(&mut self) {
        for request in core::mem::take(&mut self.deferred) {
            self.reconcile(&request);
        }
    }

    /// Test setup authorizes the reconciler's fixture flip; `fixture_flips` records its index for
    /// [`World::unreleased`]. [`World::flip`] requires every active request in `awaiting` or `deferred` to be stale,
    /// so only test setup authorizes the flip. On success, [`World::flip`] provides a spare the pre-flip check
    /// admits, flips the shard to the admitted spare and returns true. When the pre-flip check admits no spare,
    /// [`World::flip`] returns false and the shard keeps its generation.
    pub(crate) fn flip(&mut self) -> bool {
        let record = self.shard_record();
        assert!(
            !self.parked(&record),
            "a fixture flip over a host's pending request"
        );
        if !self.provide_spare() {
            return false;
        }
        let read = self.shard_read();
        let old = read.value().active;
        let index = self.store.0.borrow().flips.len();
        self.reconciler.flip(&read).unwrap();
        self.fixture_flips.push(index);
        self.retire_volume(old);
        true
    }

    /// Provisions a spare when the shard has none, and retires a spare whose listing shows an attachment outside
    /// the desired state, until the shard names a spare the pre-flip check admits; then it returns true. An
    /// unavailable or empty listing keeps the spare and returns false.
    fn provide_spare(&mut self) -> bool {
        loop {
            let read = self.shard_read();
            let record = *read.value();
            match record.spare {
                Some((volume, standby)) => {
                    let Ok(listed) = self.plane.attachments(&volume) else {
                        return false;
                    };
                    let Err(mismatch) = check(&listed, &instance(standby.get()), &[]) else {
                        return true;
                    };
                    let Some(request) = Retirement::new(
                        volume,
                        Role::Spare,
                        Target::of(&record),
                        Trigger::Attachment(mismatch),
                    ) else {
                        return false;
                    };
                    self.reconciler.retire(&read, &request).unwrap();
                    self.retire_volume(volume);
                }
                None => {
                    let standby = *HOSTS
                        .iter()
                        .find(|&&candidate| candidate != record.owner.get())
                        .unwrap();
                    let volume = self.provision_volume(standby);
                    let next = ShardRecord {
                        spare: Some((volume, host(standby))),
                        ..record
                    };
                    self.reconciler.replace(&read, next).unwrap();
                }
            }
        }
    }

    fn retire_volume(&mut self, volume: VolumeId) {
        let read = Self::volume_record(&mut self.reconciler, volume).unwrap();
        let next = VolumeRecord {
            state: VolumeState::Retired,
            ..read.value().clone()
        };
        self.reconciler.replace(&read, next).unwrap();
        self.retired.push(volume);
    }

    /// The spare the shard record names now.
    pub(crate) fn spare(&mut self) -> VolumeId {
        self.shard_record().spare.unwrap().0
    }

    /// Whether any activated volume held a foreign write when its fresh path activated it.
    pub(crate) fn activated_written(&self) -> bool {
        self.activated.iter().any(|&(_, foreign)| foreign)
    }
}

/// The listing a check reads: the control plane's, or for the control, the volume record's attach events.
fn listing(
    checks: Checks,
    plane: &mut Plane,
    volume: VolumeId,
    record: Option<&Read<VolumeRecord>>,
) -> Option<Vec<String>> {
    match checks {
        Checks::Listing => plane.attachments(&volume).ok(),
        Checks::WithoutListing => Some(record.map_or(Vec::new(), |record| {
            record
                .value()
                .events
                .iter()
                .map(|event| instance(event.host.get()).as_str().to_owned())
                .collect()
        })),
    }
}

struct FreshStore {
    inner: Shared,
    trace: Rc<RefCell<Vec<&'static str>>>,
    bumped: bool,
}

impl Store for FreshStore {
    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }

    fn read(
        &mut self,
        key: &Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }
    fn write(&mut self, key: &Key, write: &crate::storage::store::Write) -> Outcome {
        let outcome = self.inner.write(key, write);
        if !self.bumped && matches!(key, Key::Shard(_)) && matches!(outcome, Outcome::Committed(_))
        {
            self.bumped = true;
            self.trace.borrow_mut().push("bump");
        }
        outcome
    }
}

struct SimLocal {
    holder: Holder,
    pair: Pair,
    refused: bool,
    trace: Rc<RefCell<Vec<&'static str>>>,
}

impl crate::failover::fresh::LocalRecords for SimLocal {
    fn persist(
        &mut self,
        holder: &Holder,
        _: u32,
        key: crate::failover::identity::Key,
    ) -> Result<crate::failover::record::LocalRecord, crate::failover::admission::AdmissionError>
    {
        assert_eq!(holder, &self.holder);
        if self.refused {
            return Err(crate::failover::admission::AdmissionError::Retained);
        }
        if self.pair.key != key {
            return Err(crate::failover::admission::AdmissionError::Key);
        }
        self.trace.borrow_mut().push("record");
        let binding = crate::failover::record::Binding {
            instance: self.holder.instance.as_str().to_owned(),
            volume: self.holder.volume.as_str().to_owned(),
            attachment: "attach-1".to_owned(),
        };
        let exhid = self.pair.exhid.bytes();
        Ok(
            crate::failover::record::LocalRecord::fresh(binding, self.pair.key, || Some(exhid))
                .unwrap(),
        )
    }

    fn retain_refusal(
        &mut self,
        record: &crate::failover::record::LocalRecord,
    ) -> Result<(), crate::failover::admission::AdmissionError> {
        assert_eq!(record.binding().volume, self.holder.volume.as_str());
        assert_eq!(record.pair().key.incarnation(), self.pair.key.incarnation());
        self.refused = true;
        Ok(())
    }

    fn release_refusal(
        &mut self,
        record: &crate::failover::record::LocalRecord,
    ) -> Result<(), crate::failover::admission::AdmissionError> {
        assert_eq!(record.binding().volume, self.holder.volume.as_str());
        self.refused = false;
        Ok(())
    }
}

struct Listing<'w> {
    checks: Checks,
    plane: &'w mut Plane,
    store: &'w Shared,
    trace: Rc<RefCell<Vec<&'static str>>>,
}

impl ControlPlane for Listing<'_> {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        self.trace.borrow_mut().push("listing");
        let record = match self.checks {
            Checks::Listing => None,
            Checks::WithoutListing => World::volume_record(&mut client(self.store), *volume),
        };
        listing(self.checks, self.plane, *volume, record.as_ref()).ok_or(Unlisted)
    }
}

struct FreshCard<'w> {
    reservations: &'w mut BTreeMap<VolumeId, Reservation>,
    volume: VolumeId,
    unit0: Option<Vec<u8>>,
    trace: Rc<RefCell<Vec<&'static str>>>,
}

impl FreshCard<'_> {
    fn command(&mut self, name: &'static str) -> Reservation {
        self.trace.borrow_mut().push(name);
        self.reservations
            .get(&self.volume)
            .copied()
            .unwrap_or_default()
    }
}

impl crate::failover::fresh::Device for FreshCard<'_> {
    fn set_host_id(
        &mut self,
        _: crate::failover::identity::Exhid,
    ) -> Result<(), crate::failover::restart::Failed> {
        self.command("host");
        Ok(())
    }

    fn register(&mut self, own: Pair) -> Result<(), crate::failover::restart::Failed> {
        self.command("register");
        self.reservations.entry(self.volume).or_default().own = Some(own);
        Ok(())
    }

    fn acquire(&mut self, own: Pair) -> Result<(), crate::failover::restart::Failed> {
        let reservation = self.command("acquire");
        if reservation.own != Some(own) || reservation.foreign.is_some() {
            return Err(crate::failover::restart::Failed(None));
        }
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, crate::failover::restart::Failed> {
        self.command("report");
        let mut entries = Vec::new();
        let rtype = report(self.reservations, self.volume, &mut entries);
        Ok(crate::storage::gate_fixture::encode_report(
            u8::from(rtype == ReservationType::ExclusiveAccess) * 2,
            &entries,
        ))
    }

    fn write(
        &mut self,
        fenced: &crate::storage::Fenced,
        _: u64,
        bytes: &[u8; crate::storage::activation::RECORD_LEN],
    ) -> Result<(), crate::failover::restart::Failed> {
        let reservation = self.command("write");
        if reservation.own != Some(fenced.own()) || reservation.foreign.is_some() {
            return Err(crate::failover::restart::Failed(None));
        }
        self.unit0 = Some(bytes.to_vec());
        Ok(())
    }

    fn read(
        &mut self,
        _: &crate::storage::Fenced,
        _: u64,
    ) -> Result<Vec<u8>, crate::failover::restart::Failed> {
        self.command("read");
        self.unit0
            .clone()
            .ok_or(crate::failover::restart::Failed(None))
    }
}

/// The Report `volume` returns now.
fn report(
    reservations: &BTreeMap<VolumeId, Reservation>,
    volume: VolumeId,
    entries: &mut Vec<Registrant>,
) -> ReservationType {
    let reservation = reservations.get(&volume).copied().unwrap_or_default();
    let own = reservation
        .own
        .map(|pair| (pair, reservation.foreign.is_none()));
    let foreign = reservation.foreign.map(|pair| (pair, true));
    entries.extend(
        own.into_iter()
            .chain(foreign)
            .enumerate()
            .map(|(at, (pair, holder))| Registrant {
                cntlid: at as u16,
                pair,
                holder,
            }),
    );
    if entries.iter().any(|entry| entry.holder) {
        ReservationType::ExclusiveAccess
    } else {
        ReservationType::None
    }
}

/// Over seeded schedules of owner writes and reads, polls, store-read and control-plane outages, and one foreign
/// attachment of the active volume by either arm, with or without a reservation loss: no poll before the attach
/// retires; every poll after it retires, by the attachment trigger whenever its listing returned, and otherwise by
/// the Report under a loss and by the attach events for the stale arm, and only an unrecorded attach without a
/// loss is unobserved under a listing outage; the owner submits nothing after the retiring poll; every owner read
/// of a unit the foreign attachment wrote misses; and the reconciler flips the shard once, to a spare that only its
/// standby's instance lists, and the store records the old volume retired. The release gates the flip: under
/// `Operator::Silent` the request waits and the shard stays at its generation until the operator's release, and the
/// reconciler then flips the shard once. Across all seeds, each flip follows the release of the request it serves.
#[test]
fn foreign_attach_retires_at_poll() {
    let mut reached = std::collections::BTreeSet::new();
    for seed in 0..128 {
        let mut rng = SplitMix64::new(seed);
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1), "seed {seed}: the first owner activates");
        if seed % 2 == 1 {
            world.operator = Operator::Silent;
        }
        let volume = world.owner.as_ref().unwrap().holder.volume;
        let arm = [Attach::Stale, Attach::Unrecorded][rng.below(2) as usize];
        let loss = rng.below(2) == 1;
        reached.insert(format!("{arm:?} loss={loss}"));
        let attach_at = 1 + rng.below(8);
        let (mut attached, mut outage, mut store_down) = (false, false, false);
        let mut foreign_units = Vec::new();
        let mut retiring = None;
        for step in 0..24 {
            if step == attach_at {
                world.attach(volume, arm, loss);
                attached = true;
            }
            match rng.below(5) {
                0 => {
                    world.write(rng.below(8) as u32);
                }
                1 => {
                    let hit = world.read(rng.below(8) as u32);
                    if hit == Some(false) {
                        reached.insert("foreign landing missed".to_owned());
                    }
                    assert!(
                        attached || hit != Some(false),
                        "seed {seed}: a miss before any foreign landing"
                    );
                }
                2 if attached => {
                    let unit = rng.below(8) as u32;
                    if world.foreign_write(volume, unit) {
                        assert!(
                            loss,
                            "seed {seed}: a foreign write landed under the owner's reservation"
                        );
                        foreign_units.push(unit);
                    }
                }
                3 if !outage => {
                    outage = true;
                    if rng.below(2) == 0 {
                        world.plane.down = 1;
                    } else {
                        store_down = true;
                    }
                }
                _ => {
                    let listed = world.plane.down == 0;
                    let serving = world.owner.as_ref().is_some_and(|o| !o.withdrawn);
                    if core::mem::take(&mut store_down) && serving {
                        let arms: &[Arm] = match rng.below(3) {
                            0 => &[Arm::Unavailable],
                            1 => &[Arm::Pass, Arm::Unavailable],
                            _ => &[Arm::Unavailable, Arm::Unavailable],
                        };
                        for arm in arms {
                            world.store.schedule(*arm);
                        }
                    }
                    outage = false;
                    let Some(verdict) = world.poll() else {
                        continue;
                    };
                    if let Some(marker) = world.unread.marker().filter(|_| attached) {
                        reached.insert(format!("{marker} after attach"));
                    }
                    match verdict {
                        Verdict::Retire(retirement) => {
                            assert!(
                                attached,
                                "seed {seed}: a retirement without an attach: {retirement:?}"
                            );
                            let trigger = retirement.trigger();
                            let expected = match (listed, loss, arm) {
                                (true, _, _) => matches!(trigger, Trigger::Attachment(_)),
                                (false, true, _) => matches!(trigger, Trigger::Report(_)),
                                (false, false, Attach::Stale) => *trigger == Trigger::Events,
                                (false, false, Attach::Unrecorded) => false,
                            };
                            assert!(expected, "seed {seed}: {retirement:?}");
                            if !listed {
                                reached.insert(format!(
                                    "{arm:?} loss={loss} retired under a listing outage"
                                ));
                            }
                            retiring = Some(retirement);
                        }
                        Verdict::Continue => {
                            assert!(!attached, "seed {seed}: a poll missed the attach")
                        }
                        Verdict::Deposed | Verdict::Withdraw => {
                            panic!("seed {seed}: a deposition without a flip")
                        }
                        Verdict::Unobserved => {
                            assert!(
                                !attached || (!listed && !loss && arm == Attach::Unrecorded),
                                "seed {seed}: an attach a source shows unobserved"
                            );
                            if attached {
                                reached
                                    .insert(format!("{arm:?} loss={loss} unobserved after attach"));
                            }
                        }
                    }
                }
            }
            for unit in &foreign_units {
                let hit = world.read(*unit);
                assert_ne!(hit, Some(true), "seed {seed}: a foreign unit hit");
                if hit == Some(false) {
                    reached.insert("foreign landing missed".to_owned());
                }
            }
        }
        for _ in 0..4 {
            if retiring.is_some() {
                break;
            }
            if let Some(Verdict::Retire(retirement)) = world.poll() {
                retiring = Some(retirement);
            }
        }
        assert!(!world.write(0), "seed {seed}: a withdrawn owner wrote");
        assert_eq!(world.read(0), None, "seed {seed}: a withdrawn owner read");
        if world.operator == Operator::Silent {
            let pending = world.shard_record();
            assert_eq!(
                pending.generation.get(),
                1,
                "seed {seed}: no release, no flip"
            );
            assert_eq!(world.awaiting, world.alarms, "seed {seed}");
            assert!(
                world.release(retiring.as_ref().unwrap()),
                "seed {seed}: the pending request takes the release"
            );
            world.tick();
            assert!(
                world.awaiting.is_empty() && world.deferred.is_empty(),
                "seed {seed}"
            );
        }
        assert_eq!(
            world.unreleased(),
            Vec::<u64>::new(),
            "seed {seed}: a flip with no release"
        );
        let record = world.shard_record();
        assert_eq!(record.generation.get(), 2, "seed {seed}: one flip");
        assert_eq!(world.retired, vec![volume], "seed {seed}");
        assert_eq!(
            world.stored_state(volume),
            VolumeState::Retired,
            "seed {seed}"
        );
        assert_eq!(
            world.plane.listed[&record.active],
            vec![instance(record.owner.get()).as_str().to_owned()],
            "seed {seed}"
        );
        assert_eq!(world.alarms, vec![retiring.unwrap()], "seed {seed}");
    }
    let mut expected = vec![
        "Stale loss=false",
        "Stale loss=false retired under a listing outage",
        "Stale loss=true",
        "Stale loss=true retired under a listing outage",
        "Unrecorded loss=false",
        "Unrecorded loss=false unobserved after attach",
        "Unrecorded loss=true",
        "Unrecorded loss=true retired under a listing outage",
        "foreign landing missed",
        "shard read outage after attach",
        "store outage after attach",
        "volume read outage after attach",
    ];
    expected.sort_unstable();
    assert_eq!(
        reached.iter().map(String::as_str).collect::<Vec<_>>(),
        expected,
        "every arm and outage is reached"
    );
}

/// A foreign attachment of a fresh spare, by either arm, writes unit 0, either right after the flip to it or while
/// it is idle; in the second variant the standby's check replaces the idle spare and the foreign attachment then
/// writes unit 1 of the later spare right after the flip to that one. The standby's check refuses the idle written
/// spare and the fresh check refuses each written spare the shard flipped to, before any device command; the
/// reconciler retires each and flips the shard to a new spare, and only clean spares activate. The control whose
/// fresh check takes the volume record's attach events as the listing activates a written spare only when the
/// attach left no event.
#[test]
fn spare_with_foreign_attachment_never_activated() {
    for arm in [Attach::Stale, Attach::Unrecorded] {
        for later in [false, true] {
            for checks in [Checks::Listing, Checks::WithoutListing] {
                let mut world = World::new(checks);
                if checks == Checks::Listing {
                    world.plane.down = 1;
                    assert!(
                        !world.activate(1),
                        "an unlisted fresh check activates nothing"
                    );
                    assert!(world.activated.is_empty());
                }
                assert!(world.activate(1));
                let mut written = Vec::new();
                if later {
                    let idle = world.spare();
                    world.attach(idle, arm, false);
                    assert!(world.foreign_write(idle, 0));
                    assert!(matches!(
                        world.check_spare(),
                        Some(Verdict::Retire(retirement))
                            if matches!(retirement.trigger(), Trigger::Attachment(_))
                    ));
                    assert_ne!(
                        world.spare(),
                        idle,
                        "the standby's check replaced the spare"
                    );
                    written.push(idle);
                }
                assert!(world.flip());
                let target = world.shard_record().active;
                world.attach(target, arm, false);
                let unit = if later { 1 } else { 0 };
                assert!(
                    world.foreign_write(target, unit),
                    "nobody holds a fresh spare's reservation"
                );
                written.push(target);
                let activated = world.activate(4);
                assert!(activated, "{arm:?} {later} {checks:?}");
                if checks == Checks::WithoutListing && arm == Attach::Unrecorded {
                    assert!(
                        world.activated_written(),
                        "the control activates the written spare"
                    );
                    continue;
                }
                assert!(!world.activated_written(), "{:?}", world.activated);
                for volume in &written {
                    assert!(world.activated.iter().all(|(active, _)| active != volume));
                    assert!(world.retired.contains(volume), "{volume:?} retires");
                    assert_eq!(world.stored_state(*volume), VolumeState::Retired);
                }
                let record = world.shard_record();
                assert_eq!(
                    record.generation.get(),
                    3,
                    "the shard flipped past the written spare"
                );
                assert!(!written.contains(&record.active));
                assert_eq!(
                    world.activated.last().map(|&(volume, _)| volume),
                    Some(record.active)
                );
                assert_eq!(world.unreleased(), Vec::<u64>::new());
            }
        }
    }
}

/// A retirement request computed before a flip, or before the successor's `E` bump, retires nothing when the
/// reconciler receives it after that write, and the deposed owner's poll requests nothing; a reconciler's flip to
/// an idle spare with a foreign attachment retires that spare and flips to a clean one. The reconciler rejects each
/// stale request at admission, preserving the shard record.
#[test]
fn delayed_retirement_never_retires_the_successor() {
    let mut world = World::new(Checks::Listing);
    assert!(world.activate(1));
    let holder = world.owner.as_ref().unwrap().holder;
    let before = world.shard_record();
    world.attach(holder.volume, Attach::Unrecorded, false);
    let listed = world.plane.attachments(&holder.volume).unwrap();
    let own = [crate::failover::evidence_tests::entry(
        1,
        world.owner.as_ref().unwrap().pair,
        true,
    )];
    let Verdict::Retire(request) = poll::poll(
        &holder,
        Target::of(&before),
        own[0].pair,
        Ok(&crate::failover::evidence_tests::report(&own)),
        &Reads {
            shard: Some(&before),
            listed: Some(&listed),
            ..Reads::default()
        },
        &bounds(),
    ) else {
        panic!("the listing requests retirement");
    };
    assert!(world.flip());
    let flipped = world.shard_record();
    let retired = world.retired.clone();
    assert_eq!(world.poll(), Some(Verdict::Deposed));
    assert!(world.owner.as_ref().unwrap().withdrawn);
    assert!(world.alarms.is_empty());
    world.reconcile(&request);
    assert_eq!(
        world.shard_record(),
        flipped,
        "a stale request writes nothing"
    );
    assert!(
        world.awaiting.is_empty() && world.deferred.is_empty(),
        "a stale request waits for nothing"
    );
    assert_eq!(world.retired, retired);
    assert!(world.provide_spare());
    let flipped = world.shard_record();

    let successor = Retirement::new(
        flipped.active,
        Role::Active,
        Target::of(&flipped),
        Trigger::Events,
    )
    .unwrap();
    assert!(world.activate(1));
    let bumped = world.shard_record();
    assert_eq!(bumped.attempts, 1);
    world.reconcile(&successor);
    assert_eq!(world.shard_record(), bumped, "after an E bump");
    assert!(
        world.awaiting.is_empty() && world.deferred.is_empty(),
        "a request stale after an E bump waits for nothing"
    );
    assert_eq!(world.retired, retired);
    assert_eq!(world.poll(), Some(Verdict::Continue));

    let idle = world.spare();
    world.attach(idle, Attach::Unrecorded, false);
    assert!(world.flip());
    let record = world.shard_record();
    assert_ne!(record.active, idle);
    assert!(world.retired.contains(&idle));
    assert_eq!(world.stored_state(idle), VolumeState::Retired);
    assert_eq!(world.unreleased(), Vec::<u64>::new());
}

/// STATUS-REJUDGE and POST-WITHDRAWAL-POLL: the serving owner's command completes with a deposing status while no
/// poll is outstanding, and the owner withdraws with no request. A preempt by a pair outside the volume record,
/// which the listing does not show, retires the volume at the next poll with the alarm. When that poll's Report
/// still shows the own pair holding, the withdrawn owner keeps polling, and a later unrecorded attachment retires
/// the volume through the listing. A withdrawn owner submits nothing, and no poll follows the retirement.
#[test]
fn a_deposing_status_withdraws_and_later_polls_judge_the_holder_and_the_listing() {
    use crate::failover::evidence::NotSole;
    for foreign in [true, false] {
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1));
        let volume = world.owner.as_ref().unwrap().holder.volume;
        if foreign {
            world.reserve_foreign(volume);
        }
        world.deposing_status();
        assert!(!world.write(1), "a withdrawn owner submits nothing");
        assert!(world.alarms.is_empty(), "the status requests nothing");
        if !foreign {
            assert_eq!(world.poll(), Some(Verdict::Continue));
            assert!(!world.write(1), "the owner stays withdrawn");
            world.attach(volume, Attach::Unrecorded, false);
        }
        let Some(Verdict::Retire(retirement)) = world.poll() else {
            panic!("{foreign}: a poll after the status retires the volume");
        };
        assert!(
            if foreign {
                *retirement.trigger() == Trigger::Report(NotSole::ForeignHolder)
            } else {
                matches!(retirement.trigger(), Trigger::Attachment(_))
            },
            "{foreign}: {retirement:?}"
        );
        assert_eq!(world.alarms, vec![retirement]);
        assert_eq!(world.retired, vec![volume]);
        assert_eq!(world.poll(), None);
    }
}

/// The reconciler defers a flip and an active retirement while the spare's listing is unavailable or empty, and a
/// retry under either outage defers again: the shard record and the spare stay unchanged and nothing retires. Once
/// the listing returns, the deferred retirement commits as the one flip on the next reconciler step, and a deferred
/// request that went stale retires nothing.
#[test]
fn reconciler_defers_without_a_usable_spare_listing() {
    let mut world = World::new(Checks::Listing);
    assert!(world.activate(1));
    let before = world.shard_record();
    let spare = before.spare.unwrap().0;
    world.plane.down = 1;
    assert!(!world.flip());
    assert_eq!(world.shard_record(), before);
    let listed = world.plane.listed.insert(spare, Vec::new()).unwrap();
    assert!(!world.flip());
    assert_eq!(world.shard_record(), before);
    let holder = world.owner.as_ref().unwrap().holder;
    world.attach(holder.volume, Attach::Unrecorded, false);
    let Some(Verdict::Retire(request)) = world.poll() else {
        panic!("the listing retires the active volume");
    };
    assert!(world.owner.as_ref().unwrap().withdrawn);
    assert_eq!(world.deferred, vec![request]);
    assert_eq!(
        world.shard_record(),
        before,
        "nothing flips during the outage"
    );
    assert_eq!(world.stored_state(spare), VolumeState::Fresh);
    assert!(world.retired.is_empty());
    let deferred = world.deferred.clone();
    world.tick();
    world.plane.down = 1;
    world.tick();
    assert_eq!(
        world.deferred, deferred,
        "a retry without a usable listing defers again"
    );
    assert_eq!(world.shard_record(), before);
    assert_eq!(world.stored_state(spare), VolumeState::Fresh);
    assert!(world.retired.is_empty());
    world.plane.listed.insert(spare, listed);
    world.tick();
    assert!(world.deferred.is_empty());
    let record = world.shard_record();
    assert_eq!(record.generation.get(), 2);
    assert_eq!(record.active, spare);
    assert_eq!(world.retired, vec![holder.volume]);
    assert_eq!(world.stored_state(holder.volume), VolumeState::Retired);

    let stale = world.alarms[0].clone();
    world.deferred.push(stale);
    world.tick();
    assert_eq!(
        world.shard_record(),
        record,
        "a deferred request that went stale writes nothing"
    );
    assert_eq!(world.retired, vec![holder.volume]);
}

/// With `Operator::Silent` and `Gate::Release`, a host's active-volume retirement request waits for its release.
/// Duplicate delivery, reconciliation of `other`, and idle ticks preserve the shard record, flip log, and volume
/// count. Releasing the first request flips the shard once and leaves `other` pending. The successor's request then
/// waits with `spare == None` and keeps the volume count until its own release. With `Gate::WithoutRelease`, the
/// shard flips at admission, and `World::unreleased` reports that flip.
#[test]
fn a_host_request_flips_only_after_the_operator_release() {
    for (gate, operator) in [
        (Gate::Release, Operator::Silent),
        (Gate::WithoutRelease, Operator::Silent),
        (Gate::WithoutRelease, Operator::Releases),
    ] {
        let mut world = World::new(Checks::Listing);
        world.operator = operator;
        world.gate = gate;
        assert!(world.activate(1));
        let before = world.shard_record();
        let volume = world.owner.as_ref().unwrap().holder.volume;
        let volumes = world.volumes;
        world.attach(volume, Attach::Stale, false);
        let Some(Verdict::Retire(request)) = world.poll() else {
            panic!("the foreign attach retires the active volume");
        };
        if gate == Gate::WithoutRelease {
            assert_eq!(world.shard_record().generation.get(), 2);
            assert_eq!(
                world.unreleased(),
                vec![1],
                "a flip serves a host's request with no operator release"
            );
            assert!(world.releases.is_empty(), "{operator:?}");
            continue;
        }
        let other =
            Retirement::new(volume, Role::Active, Target::of(&before), Trigger::Events).unwrap();
        assert!(
            !world.release(&other),
            "a release of another request of the tenure"
        );
        assert!(world.releases.is_empty());
        assert_eq!(world.awaiting, vec![request.clone()]);
        assert_eq!(world.shard_record(), before);
        assert!(world.store.0.borrow().flips.is_empty());
        world.reconcile(&request);
        world.reconcile(&other);
        world.reconcile(&request);
        for _ in 0..3 {
            world.tick();
        }
        assert_eq!(world.awaiting, [request.clone(), other.clone()]);
        assert!(world.deferred.is_empty());
        assert_eq!(world.shard_record(), before, "no step serves the request");
        assert!(world.store.0.borrow().flips.is_empty());
        assert_eq!(world.volumes, volumes);
        assert!(world.retired.is_empty());
        assert!(world.release(&request));
        assert_eq!(world.awaiting, core::slice::from_ref(&other));
        let flipped = world.shard_record();
        assert_eq!(flipped.generation.get(), 2);
        assert_eq!(flipped.spare, None);
        assert_eq!(world.retired, vec![volume]);

        assert!(
            world.activate(1),
            "the successor activates beside a stale waiting request"
        );
        let successor = world.owner.as_ref().unwrap().holder.volume;
        let bumped = world.shard_record();
        assert_eq!(bumped.spare, None);
        let (volumes, flips) = (world.volumes, world.store.0.borrow().flips.len());
        let commits = world.store.0.borrow().commit_count(&Key::Shard(shard()));
        assert!(!world.release(&other), "a stale request takes no release");
        assert!(world.awaiting.is_empty());
        assert_eq!(world.releases.len(), 1);
        assert_eq!(world.shard_record(), bumped);
        assert_eq!(world.volumes, volumes);
        assert_eq!(world.store.0.borrow().flips.len(), flips);
        assert_eq!(
            world.store.0.borrow().commit_count(&Key::Shard(shard())),
            commits
        );
        world.attach(successor, Attach::Unrecorded, false);
        let Some(Verdict::Retire(second)) = world.poll() else {
            panic!("the foreign attach retires the successor's volume");
        };
        assert_ne!(second, request);
        world.reconcile(&second);
        world.tick();
        assert_eq!(world.awaiting, core::slice::from_ref(&second));
        assert_eq!(
            world.shard_record(),
            bumped,
            "the first release serves no later request"
        );
        assert_eq!(world.store.0.borrow().flips.len(), flips);
        assert_eq!(world.volumes, volumes, "no spare before the release");
        assert!(world.release(&second));
        assert_eq!(world.shard_record().generation.get(), 3);
        assert_eq!(world.retired, vec![volume, successor]);
        assert_eq!(world.unreleased(), Vec::<u64>::new());
    }
}

/// A request must enter `awaiting` before a release can authorize it: a release made before the alarm returns
/// false, and the alarm's request then waits. A repeated release of a deferred request returns false and leaves one
/// deferred copy. The deferred request keeps its release across ticks and flips once the spare's listing returns.
#[test]
fn a_release_acts_only_on_a_pending_request() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    assert!(world.activate(1));
    let before = world.shard_record();
    let volume = before.active;
    let early =
        Retirement::new(volume, Role::Active, Target::of(&before), Trigger::Events).unwrap();
    assert!(!world.release(&early), "a release before the alarm");
    assert_eq!(world.shard_record(), before);
    assert!(world.store.0.borrow().flips.is_empty());
    assert!(world.releases.is_empty());
    world.attach(volume, Attach::Stale, false);
    world.plane.down = 1;
    let Some(Verdict::Retire(request)) = world.poll() else {
        panic!("the stale attach event retires the active volume");
    };
    assert_eq!(
        request, early,
        "the alarm raises the request released before it"
    );
    assert_eq!(world.awaiting, vec![request.clone()]);
    assert_eq!(world.shard_record(), before);
    assert!(world.store.0.borrow().flips.is_empty());

    let spare = before.spare.unwrap().0;
    let listed = world.plane.listed.insert(spare, Vec::new()).unwrap();
    assert!(world.release(&request));
    assert!(!world.release(&request), "a second release");
    world.reconcile(&request);
    assert_eq!(
        world.deferred,
        vec![request.clone()],
        "a redelivery adds no second retry"
    );
    assert_eq!(world.releases.len(), 1);
    assert_eq!(world.shard_record(), before);
    world.plane.listed.insert(spare, listed);
    let tenure = Retirement::new(
        volume,
        Role::Active,
        Target::of(&before),
        Trigger::VolumeState,
    )
    .unwrap();
    world.reconcile(&tenure);
    assert_eq!(
        world.awaiting,
        vec![tenure.clone()],
        "a request of the same tenure waits for its own release"
    );
    assert_eq!(world.deferred, vec![request.clone()]);
    assert_eq!(world.shard_record(), before);
    assert!(world.store.0.borrow().flips.is_empty());
    world.plane.down = 1;
    world.tick();
    assert_eq!(world.deferred, vec![request.clone()]);
    assert_eq!(world.shard_record(), before);
    world.tick();
    assert!(world.deferred.is_empty());
    let record = world.shard_record();
    assert_eq!(record.generation.get(), 2);
    assert_eq!(record.active, spare);
    assert_eq!(world.retired, vec![volume]);
    assert_eq!(world.unreleased(), Vec::<u64>::new());
}

/// When a fresh host's bump times out before commit, the host raises a recovering request for its volume and parks
/// pending the operator's release. While the host waits, the shard record remains unchanged and the trace holds one
/// start and no device command. After the release the flip moves the shard to the spare, and the next activation
/// runs there.
#[test]
fn a_fresh_host_parks_while_its_request_waits_for_the_release() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    let before = world.shard_record();
    for _ in 0..4 {
        world.store.schedule(Arm::Pass);
    }
    world.store.schedule(Arm::Timeout { commit: false });
    assert!(!world.activate(3), "the host parks on its waiting request");
    assert!(!world.activate(2), "a later activation parks as well");
    assert_eq!(
        world
            .trace
            .borrow()
            .iter()
            .filter(|step| **step == "start")
            .count(),
        1
    );
    assert!(!world.trace.borrow().contains(&"host"), "no device command");
    assert_eq!(world.shard_record(), before);
    assert!(world.activated.is_empty());
    assert_eq!(world.alarms.len(), 1);
    assert_eq!(world.alarms[0].trigger(), &Trigger::Activation);
    assert_eq!(world.awaiting, world.alarms);
    let request = world.alarms[0].clone();
    assert!(world.release(&request));
    let record = world.shard_record();
    assert_eq!(record.generation.get(), 2);
    assert_eq!(record.active, before.spare.unwrap().0);
    assert!(world.activate(1), "the host on the spare activates");
    assert_eq!(world.unreleased(), Vec::<u64>::new());
}

/// Under the releasing operator a fresh host's uncommitted bump timeout raises a request that the operator releases
/// at once and the reconciler defers while the spare's listing is empty. The host stays parked across activation
/// rounds and later `activate` calls while the request is deferred. Once the listing returns, one tick applies the
/// deferred release and flips the shard to the spare. The host on the spare then activates.
#[test]
fn a_fresh_host_parks_while_its_released_request_is_deferred() {
    let mut world = World::new(Checks::Listing);
    let before = world.shard_record();
    let spare = before.spare.unwrap().0;
    let listed = world.plane.listed.insert(spare, Vec::new()).unwrap();
    for _ in 0..4 {
        world.store.schedule(Arm::Pass);
    }
    world.store.schedule(Arm::Timeout { commit: false });
    assert!(!world.activate(3));
    assert!(world.awaiting.is_empty());
    assert_eq!(world.deferred, world.alarms);
    assert_eq!(world.releases.len(), 1);
    assert!(!world.activate(2), "a later activation parks as well");
    let starts = world
        .trace
        .borrow()
        .iter()
        .filter(|step| **step == "start")
        .count();
    assert_eq!(starts, 1);
    assert!(!world.trace.borrow().contains(&"host"), "no device command");
    assert_eq!(world.shard_record(), before);
    assert!(world.activated.is_empty());
    world.plane.listed.insert(spare, listed);
    world.tick();
    let record = world.shard_record();
    assert_eq!(record.generation.get(), 2);
    assert_eq!(record.active, spare);
    assert_eq!(world.retired, vec![before.active]);
    assert!(world.activate(1), "the host on the spare activates");
    assert_eq!(world.releases.len(), 1);
    assert_eq!(world.unreleased(), Vec::<u64>::new());
}

/// `World::unreleased` binds each release to the tenure of the record the flip replaced and to the flip log's
/// order. A released request deferred across an acknowledged same-owner bump goes stale; its retry clears the stale
/// request and preserves the bumped shard record. The oracle reports a planted flip of a request at the bumped
/// tenure. The release log at that report holds the earlier tenure's release and two releases that name the spare
/// at the bumped tenure, one per role. A release of the planted request after its flip and a later fixture flip
/// leave the report unchanged.
#[test]
fn the_flip_oracle_binds_each_release_to_the_tenure_it_served() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    assert!(world.activate(1));
    let before = world.shard_record();
    let volume = before.active;
    let spare = before.spare.unwrap().0;
    world.attach(volume, Attach::Stale, false);
    let Some(Verdict::Retire(request)) = world.poll() else {
        panic!("the stale attach retires the active volume");
    };
    let listed = world.plane.listed.insert(spare, Vec::new()).unwrap();
    assert!(world.release(&request));
    assert_eq!(world.deferred, vec![request.clone()]);
    let read = world.shard_read();
    world.reconciler.bump(&read).unwrap();
    let bumped = world.shard_record();
    assert_eq!(bumped.attempts, before.attempts + 1);
    world.plane.listed.insert(spare, listed);
    world.tick();
    assert!(world.deferred.is_empty());
    assert_eq!(
        world.shard_record(),
        bumped,
        "the earlier tenure's retry flips nothing"
    );
    assert!(world.store.0.borrow().flips.is_empty());
    assert!(world.retired.is_empty());

    for role in [Role::Active, Role::Spare] {
        let beside = Retirement::new(spare, role, Target::of(&bumped), Trigger::Events).unwrap();
        world.releases.push(Release {
            request: beside,
            flips: 0,
        });
    }
    world.gate = Gate::WithoutRelease;
    let later =
        Retirement::new(volume, Role::Active, Target::of(&bumped), Trigger::Events).unwrap();
    world.reconcile(&later);
    assert_eq!(world.shard_record().generation.get(), 2);
    assert_eq!(world.unreleased(), vec![1]);
    let flips = world.store.0.borrow().flips.len();
    world.releases.push(Release {
        request: later,
        flips,
    });
    assert_eq!(world.unreleased(), vec![1], "a release after the flip");
    world.gate = Gate::Release;
    assert!(world.flip());
    assert_eq!(world.shard_record().generation.get(), 3);
    assert_eq!(world.unreleased(), vec![1], "the fixture flip");
}

/// `World::flip` panics if a host request awaits operator release.
#[test]
#[should_panic(expected = "a fixture flip over a host's pending request")]
fn a_fixture_flip_over_a_pending_host_request_panics() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    assert!(world.activate(1));
    let volume = world.owner.as_ref().unwrap().holder.volume;
    world.attach(volume, Attach::Stale, false);
    assert!(matches!(world.poll(), Some(Verdict::Retire(_))));
    world.flip();
}

/// A stale read at the fixture flip's guard reaches the reconciler's client below its watermark. The client
/// refuses it as a regression before the guard judges a record.
#[test]
#[should_panic(expected = "Regression(Value(Shard(")]
fn a_stale_read_at_the_fixture_flip_is_a_regression() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    assert!(world.activate(1));
    let volume = world.owner.as_ref().unwrap().holder.volume;
    world.attach(volume, Attach::Stale, false);
    assert!(matches!(world.poll(), Some(Verdict::Retire(_))));
    world.store.schedule(Arm::StaleRead);
    world.flip();
}

/// A stale read at the operator's release reaches the reconciler's client below its watermark. The client refuses
/// it as a regression before the release judges admission.
#[test]
#[should_panic(expected = "Regression(Value(Shard(")]
fn a_stale_read_at_the_release_is_a_regression() {
    let mut world = World::new(Checks::Listing);
    world.operator = Operator::Silent;
    assert!(world.activate(1));
    let volume = world.owner.as_ref().unwrap().holder.volume;
    world.attach(volume, Attach::Stale, false);
    let Some(Verdict::Retire(request)) = world.poll() else {
        panic!("the stale attach event retires the active volume");
    };
    assert_eq!(world.awaiting, vec![request.clone()]);
    world.store.schedule(Arm::StaleRead);
    world.release(&request);
}

/// A shard-read outage with a listing outage leaves the stale attach event, which retires the owner's volume
/// through the target its caller supplied.
#[test]
fn a_shard_read_outage_keeps_the_attach_events() {
    let mut world = World::new(Checks::Listing);
    assert!(world.activate(1));
    let volume = world.owner.as_ref().unwrap().holder.volume;
    world.attach(volume, Attach::Stale, false);
    world.plane.down = 1;
    world.store.schedule(Arm::Pass);
    world.store.schedule(Arm::Unavailable);
    assert!(matches!(
        world.poll(),
        Some(Verdict::Retire(retirement)) if *retirement.trigger() == Trigger::Events
    ));
    assert_eq!(
        world.unread,
        Unread {
            volume: false,
            shard: true
        }
    );
    assert_eq!(world.retired, vec![volume]);
}

/// A flip and the old volume's retirement that commit between a check's two record reads depose the owner when it
/// reads the volume record first, and read in the other order they show a contradiction.
#[test]
fn a_flip_between_the_record_reads_deposes() {
    let mut world = World::new(Checks::Listing);
    assert!(world.activate(1));
    let (holder, target, pair) = {
        let owner = world.owner.as_ref().unwrap();
        (owner.holder, owner.target, owner.pair)
    };
    let own = vec![holder.instance.as_str().to_owned()];
    let held = [crate::failover::evidence_tests::entry(1, pair, true)];
    let held = crate::failover::evidence_tests::report(&held);
    let mut reader = client(&world.store);
    let volume = World::volume_record(&mut reader, holder.volume).unwrap();
    let early = observed(reader.read::<ShardRecord>(Key::Shard(shard()))).unwrap();
    assert!(world.flip());
    let late_volume = World::volume_record(&mut reader, holder.volume).unwrap();
    let late = observed(reader.read::<ShardRecord>(Key::Shard(shard()))).unwrap();
    let verdict = |shard: &Read<ShardRecord>, volume: &Read<VolumeRecord>| {
        poll::poll(
            &holder,
            target,
            pair,
            Ok(&held),
            &Reads {
                shard: Some(shard.value()),
                volume: Some(volume.value()),
                listed: Some(&own),
                peers: &[],
            },
            &bounds(),
        )
    };
    assert_eq!(
        verdict(&late, &volume),
        Verdict::Deposed,
        "volume, flip, shard"
    );
    assert_eq!(
        verdict(&early, &late_volume),
        Verdict::Retire(
            Retirement::new(holder.volume, Role::Active, target, Trigger::VolumeState).unwrap()
        ),
        "shard, flip, volume"
    );
}

/// One event at the card of the owner's volume across an in-place restart, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardEvent {
    /// A write of the session landed on the unit.
    Landed {
        unit: u32,
        session: u64,
    },
    Ready,
    Report,
    Preempt,
}

/// The controller of the owner's volume as a restarted process finds it: the writes the ended incarnation submitted
/// that the card still holds, which the driver's ready wait completes at the card before it reports ready.
struct RestartCard<'w> {
    world: &'w mut World,
    volume: VolumeId,
    held: Vec<(u32, u64)>,
    events: Vec<CardEvent>,
    /// Whether the ready wait completes the held writes before it returns; the negative control reports ready
    /// with them still held, and they land after the sequence.
    drains: bool,
}

/// Issues one restart's commands at the card: the production sequence over the card, or over a device a control
/// places between the sequence and the card.
type Sequence =
    fn(
        &crate::failover::restart::Restart<'static>,
        &mut Client<Shared, MemLog>,
        &crate::failover::restart::tests::Stored,
        &mut RestartCard<'_>,
    ) -> Result<crate::failover::restart::Restarted, crate::failover::restart::Refused>;

impl RestartCard<'_> {
    fn land(&mut self, unit: u32, session: u64) {
        self.world
            .media
            .entry(self.volume)
            .or_default()
            .insert(unit, Writer::Session(session));
        self.events.push(CardEvent::Landed { unit, session });
    }
}

impl crate::failover::restart::Device for RestartCard<'_> {
    fn start(&mut self) -> Result<(), crate::failover::restart::Driver> {
        Ok(())
    }

    /// Ready is blocked while a request of the ended incarnation is card-held: each wait round completes one held
    /// write at the card, and ready returns only once none remains.
    fn ready(&mut self) -> Result<(), crate::failover::restart::Failed> {
        if self.drains {
            while let Some((unit, session)) = self.held.pop() {
                self.land(unit, session);
            }
        }
        self.events.push(CardEvent::Ready);
        Ok(())
    }

    fn set_host_id(
        &mut self,
        _: crate::failover::identity::Exhid,
    ) -> Result<(), crate::failover::restart::Failed> {
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, crate::failover::restart::Failed> {
        self.events.push(CardEvent::Report);
        let mut entries = Vec::new();
        let rtype = report(&self.world.reservations, self.volume, &mut entries);
        Ok(crate::storage::gate_fixture::encode_report(
            u8::from(rtype == ReservationType::ExclusiveAccess) * 2,
            &entries,
        ))
    }

    fn preempt(
        &mut self,
        preempt: crate::storage::SelfPreempt,
    ) -> Result<(), crate::failover::restart::Failed> {
        assert_eq!(
            self.world
                .reservations
                .get(&self.volume)
                .and_then(|r| r.own),
            Some(preempt.pair())
        );
        self.events.push(CardEvent::Preempt);
        Ok(())
    }

    fn register(
        &mut self,
        _: crate::failover::evidence::Pair,
    ) -> Result<(), crate::failover::restart::Failed> {
        unreachable!("this world's reservation holds no other host's recorded pair")
    }

    fn preempt_lineage(
        &mut self,
        _: crate::storage::LineagePreempt,
    ) -> Result<(), crate::failover::restart::Failed> {
        unreachable!("this world's reservation holds no other host's recorded pair")
    }
}

impl World {
    /// Submits a write of `unit` as the owner, which stays in flight until the card lands it. A withdrawn owner
    /// submits nothing.
    fn submit(&mut self, unit: u32) -> bool {
        let Some(owner) = self.owner.as_mut().filter(|owner| !owner.withdrawn) else {
            return false;
        };
        owner.in_flight.push(unit);
        true
    }

    /// The owner's rule on a mid-tenure controller event: it stops submitting, tears down its queues and discards
    /// its index. The card still holds the in-flight writes, which the rule returns for the restart's ready wait to
    /// complete; an Abort or a queue delete ended the last submitted one with its status, so that one lands nowhere.
    fn controller_event(&mut self, event: crate::storage::ControllerEvent) -> Vec<u32> {
        use crate::storage::ControllerEvent;
        let owner = self.owner.as_mut().expect("an owner serves");
        owner.withdrawn = true;
        owner.index.clear();
        let mut in_flight = core::mem::take(&mut owner.in_flight);
        if matches!(event, ControllerEvent::Abort | ControllerEvent::QueueDelete) {
            in_flight.pop();
        }
        in_flight
    }

    /// Ends the owner's incarnation with `held` of its writes still at the card, then runs the restart sequence of
    /// the same host over the store and a card whose ready wait drains them, as the driver's does. On the fencing
    /// boundary the owner serves under the new session with an empty index. Returns the session and the card's
    /// events.
    fn restart_in_place(&mut self, held: &[u32]) -> (u64, Vec<CardEvent>) {
        self.restart_over(held, true)
    }

    /// [`restart_in_place`](Self::restart_in_place) over a card whose ready wait `drains` the held writes or leaves
    /// them to land after the sequence.
    fn restart_over(&mut self, held: &[u32], drains: bool) -> (u64, Vec<CardEvent>) {
        self.restart_through(held, drains, |restart, store, local, card| {
            restart.run(store, local, card)
        })
    }

    /// [`restart_over`](Self::restart_over) with `sequence` issuing the restart's commands at the card.
    fn restart_through(
        &mut self,
        held: &[u32],
        drains: bool,
        sequence: Sequence,
    ) -> (u64, Vec<CardEvent>) {
        let owner = self.owner.take().expect("an owner to restart");
        let volume = owner.holder.volume;
        let local = crate::failover::record::LocalRecord::fresh(
            crate::failover::record::Binding {
                instance: owner.holder.instance.as_str().to_owned(),
                volume: volume.as_str().to_owned(),
                attachment: "attach-1".to_owned(),
            },
            owner.pair.key,
            || Some(owner.pair.exhid.bytes()),
        )
        .unwrap();
        let restart = crate::failover::restart::tests::restart_of(shard(), owner.holder);
        let mut store = client(&self.store);
        let mut card = RestartCard {
            world: self,
            volume,
            held: held.iter().map(|&unit| (unit, owner.session)).collect(),
            events: Vec::new(),
            drains,
        };
        let restarted = sequence(
            &restart,
            &mut store,
            &crate::failover::restart::tests::Stored(Ok(local)),
            &mut card,
        )
        .expect("the restart reaches the fencing boundary");
        while let Some((unit, session)) = card.held.pop() {
            card.land(unit, session);
        }
        let events = card.events;
        let session = restarted.session().get();
        self.owner = Some(Owner {
            target: restarted.session().target(),
            session,
            client: store,
            index: BTreeMap::new(),
            withdrawn: false,
            polling: false,
            in_flight: Vec::new(),
            ..owner
        });
        (session, events)
    }
}

/// The sequence orders the card's events as ready, Report #1, the self Preempt-and-Abort and Report #2, and under a
/// card whose ready wait completes the ended incarnation's held writes, as the driver's does, every such write lands
/// before ready and none after Report #2. A landing of the earlier session reads as a miss under the new session,
/// and the new incarnation's own write hits. The control card reports ready with the writes still held: they land
/// after Report #2, and the read check turns them into misses.
#[test]
fn restart_card_held_copies() {
    card_held_copies(World::restart_over);
}

/// The checks of [`restart_card_held_copies`] over `restart`, which ends the owner's incarnation with the given
/// writes card-held and restarts it over a card whose ready wait drains them or not.
fn card_held_copies(restart: impl Fn(&mut World, &[u32], bool) -> (u64, Vec<CardEvent>)) {
    for drains in [true, false] {
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1));
        assert!(world.write(1));
        let before = world.owner.as_ref().unwrap().session;
        let (session, events) = restart(&mut world, &[1, 2, 3], drains);
        assert_ne!(session, before);
        let ready = events.iter().position(|e| *e == CardEvent::Ready).unwrap();
        let second_report = events
            .iter()
            .rposition(|e| *e == CardEvent::Report)
            .unwrap();
        let sequence = [
            CardEvent::Ready,
            CardEvent::Report,
            CardEvent::Preempt,
            CardEvent::Report,
        ];
        assert_eq!(
            events[ready..=second_report],
            sequence,
            "{drains}: {events:?}"
        );
        let landings: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, CardEvent::Landed { session: s, .. } if *s == before))
            .map(|(at, _)| at)
            .collect();
        assert_eq!(
            landings.len(),
            3,
            "{drains}: every held write landed at the card"
        );
        let before_ready = landings.iter().all(|&at| at < ready);
        let after_fb = landings.iter().all(|&at| at > second_report);
        assert_eq!(
            (before_ready, after_fb),
            (drains, !drains),
            "{drains}: a draining ready wait lands every held write before ready, and only the control lands one after Report #2: {events:?}"
        );
        world.owner.as_mut().unwrap().index.insert(2, session);
        assert_eq!(
            world.read(2),
            Some(false),
            "{drains}: a landing of the earlier session reads as a miss under the new session"
        );
        world.owner.as_mut().unwrap().index.clear();
        assert!(world.write(3));
        assert_eq!(world.read(3), Some(true));
        assert_eq!(
            world.read(1),
            None,
            "the index names nothing it did not write"
        );
    }
}

/// The card behind a restart that takes Report #1 before its ready wait: the ready wait reaches the card once the
/// first Report completed, and every other command passes through unchanged.
struct ReportBeforeReady<'c, 'w> {
    card: &'c mut RestartCard<'w>,
    reported: bool,
}

impl crate::failover::restart::Device for ReportBeforeReady<'_, '_> {
    fn start(&mut self) -> Result<(), crate::failover::restart::Driver> {
        self.card.start()
    }

    fn ready(&mut self) -> Result<(), crate::failover::restart::Failed> {
        Ok(())
    }

    fn set_host_id(
        &mut self,
        exhid: crate::failover::identity::Exhid,
    ) -> Result<(), crate::failover::restart::Failed> {
        self.card.set_host_id(exhid)
    }

    fn report(&mut self) -> Result<Vec<u8>, crate::failover::restart::Failed> {
        let bytes = self.card.report()?;
        if !self.reported {
            self.reported = true;
            self.card.ready()?;
        }
        Ok(bytes)
    }

    fn preempt(
        &mut self,
        preempt: crate::storage::SelfPreempt,
    ) -> Result<(), crate::failover::restart::Failed> {
        self.card.preempt(preempt)
    }

    fn register(
        &mut self,
        _: crate::failover::evidence::Pair,
    ) -> Result<(), crate::failover::restart::Failed> {
        unreachable!("this world's reservation holds no other host's recorded pair")
    }

    fn preempt_lineage(
        &mut self,
        _: crate::storage::LineagePreempt,
    ) -> Result<(), crate::failover::restart::Failed> {
        unreachable!("this world's reservation holds no other host's recorded pair")
    }
}

/// Negative control for the card order: the production sequence runs over [`ReportBeforeReady`], so the card sees
/// the commands of a restart that takes Report #1 before its ready wait, and Report #1 judges the reservation
/// while the ended incarnation's writes are still card-held. The checks of [`restart_card_held_copies`] refuse it
/// at the order of the card's events from ready to Report #2, which then begin at the late ready wait. The
/// production sequence fixes its step order, so the defective order is formed between the sequence and the card.
/// The control covers the card order alone; the mid-tenure rerun and the card's drain keep their own checks.
#[test]
#[should_panic(expected = "true: [Report, Landed")]
fn negative_control_a_first_report_before_the_ready_wait_breaks_the_card_order() {
    card_held_copies(|world, held, drains| {
        world.restart_through(held, drains, |restart, store, local, card| {
            restart.run(
                store,
                local,
                &mut ReportBeforeReady {
                    card,
                    reported: false,
                },
            )
        })
    });
}

/// A mid-tenure controller event ends the incarnation through the owner's rule: it stops submitting, tears down
/// the queues with the in-flight writes of units 6 and 8 still at the card, the last of them ended by an Abort or a
/// queue delete, discards the index, and reruns the sequence from step 1 to a new fencing boundary at the next
/// attempt's activated epoch. Every held write lands before the ready wait returns and reads as a miss under the new
/// session.
#[test]
fn mid_tenure_controller_event_reruns_restart() {
    use crate::storage::ControllerEvent;
    for event in [
        ControllerEvent::Reset,
        ControllerEvent::Abort,
        ControllerEvent::QueueDelete,
    ] {
        let mut world = World::new(Checks::Listing);
        assert!(world.activate(1));
        let (first, _) = world.restart_in_place(&[]);
        let n = world.shard_record().attempts;
        assert_eq!(first & 0xffff_ffff, u64::from(2 * (n - 1) + 2), "{event:?}");
        assert!(world.write(5));
        assert!(world.submit(6));
        assert!(world.submit(8));
        let held = world.controller_event(event);
        assert!(!world.submit(7), "{event:?}: no submission after the event");
        assert!(
            world.owner.as_ref().unwrap().index.is_empty(),
            "{event:?}: the index was discarded"
        );
        let expected_held: &[u32] = match event {
            ControllerEvent::Reset => &[6, 8],
            ControllerEvent::Abort | ControllerEvent::QueueDelete => &[6],
        };
        assert_eq!(
            held, expected_held,
            "{event:?}: the writes the card still holds"
        );
        let (second, events) = world.restart_in_place(&held);
        assert_eq!(
            second & 0xffff_ffff,
            u64::from(2 * n + 2),
            "{event:?}: the next attempt's activated epoch"
        );
        assert_eq!(second >> 32, first >> 32, "{event:?}: one generation");
        let ready = events.iter().position(|e| *e == CardEvent::Ready).unwrap();
        let mut landed: Vec<u32> = events[..ready]
            .iter()
            .map(|e| match e {
                CardEvent::Landed { unit, session } if *session == first => *unit,
                other => panic!("{event:?}: {other:?} before ready"),
            })
            .collect();
        landed.sort_unstable();
        assert_eq!(
            landed, held,
            "{event:?}: every held write lands before ready"
        );
        assert!(
            !events[ready..]
                .iter()
                .any(|e| matches!(e, CardEvent::Landed { .. })),
            "{event:?}: no landing after ready"
        );
        let owner = world.owner.as_mut().unwrap();
        assert!(
            owner.index.is_empty(),
            "{event:?}: the rerun starts with an empty index"
        );
        let volume = owner.holder.volume;
        owner.index.insert(6, second);
        owner.index.insert(8, second);
        assert_eq!(
            world.media[&volume].get(&8).copied(),
            (event == ControllerEvent::Reset).then_some(Writer::Session(first)),
            "{event:?}: only a reset leaves the ended write to land"
        );
        assert_eq!(
            (world.read(6), world.read(8)),
            (Some(false), Some(false)),
            "{event:?}: units 6 and 8 read as misses"
        );
        assert!(world.write(5));
        assert_eq!(world.read(5), Some(true), "{event:?}");
    }
}
