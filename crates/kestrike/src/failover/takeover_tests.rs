use super::*;
use crate::failover::arbiter::{Clock, Partition};
use crate::failover::assignment_tests::record as local_record;
use crate::failover::attachments::InstanceId;
use crate::failover::detect::host::{Nominated, Reading, RepairDemand, Watch};
use crate::failover::detect::tests::clock;
use crate::failover::fresh::tests::registrant;
use crate::failover::poll::Holder;
use crate::failover::record::LocalRecord;
use crate::failover::records::Record;
use crate::failover::records::{ERA, EventKind, Host, NamedCheckpoint, RecordedPair, VolumeRecord};
use crate::failover::restart::tests::{
    self as restart_tests, FULL, Stored, host as owner_host, own as owner_pair, shard_now,
    volume_id,
};
use crate::failover::retire::{Retirement, Role, Stale};
use crate::storage::DeviceStatus;
use crate::storage::gate_fixture::{encode_report, limits};
use crate::storage::store::sim::{Arm, Request, Shared};
use crate::storage::store::{Outcome, Write};
use crate::storage::store_tests::{UNKNOWN, client, committed, shard, stored};
use std::cell::RefCell;
use std::rc::Rc;

/// Hosts A (the owner, the restart fixture's host, with the restart fixture's local record), C (the standby the shard
/// record names) and B (attached and enrolled, unnamed) share the volume; B's and C's local records bind A's volume
/// under each host's own instance, key and host ID.
fn successor_host(offset: u64) -> Host {
    Host::new(owner_host().get() + offset).unwrap()
}

pub(crate) fn b_host() -> Host {
    successor_host(200)
}

pub(crate) fn c_host() -> Host {
    successor_host(100)
}

/// D, a fresh host the reconciler attaches after A and C are lost.
pub(crate) fn d_host() -> Host {
    successor_host(300)
}

/// The offset from A's host number of the hosts a history generates, each with an instance of its own.
pub(crate) const GENERATED: u64 = 1_000;

/// Each host's instance: A's is the restart fixture's, and B, C, D and each generated host have their own.
pub(crate) fn instance_of(host: Host) -> InstanceId {
    let owner = local_record().binding().instance.clone();
    let instance = if host == b_host() {
        "i-0bbbbbbbbbbbbbbb0"
    } else if host == c_host() {
        "i-0ccccccccccccccc0"
    } else if host == d_host() {
        "i-0ddddddddddddddd0"
    } else if host.get() >= owner_host().get() + GENERATED {
        return crate::failover::sim::instance_of_host(host);
    } else {
        &owner
    };
    InstanceId::new(instance).unwrap()
}

pub(crate) fn successor_record(host: Host, key: u64, exhid: u8) -> LocalRecord {
    bound_record(instance_of(host), volume_id(), key, exhid)
}

/// The record keeps the restart fixture's attachment ID.
pub(crate) fn bound_record(
    instance: InstanceId,
    volume: crate::failover::records::VolumeId,
    key: u64,
    exhid: u8,
) -> LocalRecord {
    LocalRecord::fresh(
        crate::failover::record::Binding {
            instance: instance.as_str().to_owned(),
            volume: volume.as_str().to_owned(),
            ..local_record().binding().clone()
        },
        crate::failover::identity::Key::decode(key).unwrap(),
        || Some([exhid; 16]),
    )
    .unwrap()
}

pub(crate) fn c_record() -> LocalRecord {
    successor_record(c_host(), (4 << 32) | 9, 0x5c)
}

pub(crate) fn c_pair() -> Pair {
    c_record().pair()
}

pub(crate) fn b_record() -> LocalRecord {
    successor_record(b_host(), (5 << 32) | 7, 0x5b)
}

pub(crate) fn b_pair() -> Pair {
    b_record().pair()
}

pub(crate) fn holder_of(host: Host) -> Holder {
    holder_on(volume_id(), host, instance_of(host))
}

pub(crate) fn holder_on(
    volume: crate::failover::records::VolumeId,
    host: Host,
    instance: InstanceId,
) -> Holder {
    Holder {
        volume,
        host,
        instance,
    }
}

/// The owner's shard record at `E = 4` naming a checkpoint, its cut, one certified suffix and C as its standby.
pub(crate) fn shard_record() -> ShardRecord {
    let record = restart_tests::shard_record(4);
    let session = crate::net::ownership::session_of(record.generation.get() as u32, 8);
    ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            slot: 1,
            session,
            capture: 2,
            units: 3,
        }),
        cut: 12,
        ancestry: crate::failover::records::Ancestry::new(&[crate::failover::records::Suffix {
            session,
            start: 12,
            certified: 14,
            end: 14,
        }])
        .unwrap(),
        standby: Some(c_host()),
        ..record
    }
}

/// The active volume record with A attached and enrolled first and each of `successors` attached and enrolled after
/// it.
pub(crate) fn lineage(successors: &[(Host, Pair)]) -> VolumeRecord {
    lineage_on(volume_id(), (owner_host(), owner_pair()), successors)
}

/// `owner` attaches and enrolls first on `volume`; each of `successors` follows in order.
pub(crate) fn lineage_on(
    volume: crate::failover::records::VolumeId,
    (owner, pair): (Host, Pair),
    successors: &[(Host, Pair)],
) -> VolumeRecord {
    let mut volume = restart_tests::volume_record_of(volume, owner, pair);
    for (host, pair) in successors {
        let attach = volume.push(EventKind::Attach, *host, ERA).unwrap();
        volume.pairs.push(RecordedPair {
            host: *host,
            pair: *pair,
            attach,
        });
    }
    volume
}

pub(crate) fn with_c() -> VolumeRecord {
    lineage(&[(c_host(), c_pair())])
}

pub(crate) fn with_c_and_b() -> VolumeRecord {
    lineage(&[(c_host(), c_pair()), (b_host(), b_pair())])
}

/// The takeover by `host` for the nomination of the target `store`'s shard record holds.
pub(crate) fn takeover_of(store: &Shared, host: Host) -> Takeover<'static> {
    takeover(Target::of(&shard_now(store)), host)
}

pub(crate) fn takeover(target: Target, host: Host) -> Takeover<'static> {
    Takeover {
        restart: restart_tests::restart_of(shard(), holder_of(host)),
        target,
    }
}

thread_local! {
    /// The planted defect of the open end-race order's control: step 1 reads the volume record before the shard
    /// record.
    static VOLUME_FIRST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn volume_first() -> bool {
    VOLUME_FIRST.with(std::cell::Cell::get)
}

/// Sets [`VOLUME_FIRST`] for its lifetime.
pub(crate) struct VolumeFirst;

impl VolumeFirst {
    pub(crate) fn set() -> Self {
        VOLUME_FIRST.with(|planted| planted.set(true));
        Self
    }
}

impl Drop for VolumeFirst {
    fn drop(&mut self) {
        VOLUME_FIRST.with(|planted| planted.set(false));
    }
}

/// Names `standby` in the stored shard record by a raw exact-version write, the enrollment write of a function
/// outside the cache hosts.
pub(crate) fn designate(store: &Shared, standby: Option<Host>) {
    rewrite(store, |record| ShardRecord { standby, ..record });
}

/// Replaces the stored shard record with `edit` of it by a raw exact-version write, as a writer outside this host
/// makes it.
pub(crate) fn rewrite(store: &Shared, edit: impl FnOnce(ShardRecord) -> ShardRecord) {
    let key = Key::Shard(shard());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let write = Write::Exact {
        expect: item.version,
        value: edit(ShardRecord::decode(&item.value).unwrap()).encode(),
    };
    let mut raw = store.clone();
    assert!(matches!(
        crate::storage::store::Store::write(&mut raw, &key, &write),
        Outcome::Committed(_)
    ));
}

/// A local record source that runs `hook` once at the step-2 read, between the step-1 record reads and the CAS.
pub(crate) struct Hooked(Stored, RefCell<Option<Box<dyn FnOnce()>>>);

impl LocalSource for Hooked {
    fn local(&self) -> Result<LocalRecord, Local> {
        if let Some(hook) = self.1.borrow_mut().take() {
            hook();
        }
        self.0.local()
    }
}

pub(crate) fn hooked(stored: Stored, hook: impl FnOnce() + 'static) -> Hooked {
    Hooked(stored, RefCell::new(Some(Box::new(hook))))
}

/// The reservation state one controller holds across every host's commands: the registry the `Reserving` device
/// doubles of a volume share, so a card and a host's device double read and change one table.
pub(crate) type Reservation = crate::storage::gate_fixture::Registry;

/// A holds the type-2 reservation and C is registered without holding.
pub(crate) fn a_holds_c_registered() -> Rc<RefCell<Reservation>> {
    holds_registered(owner_pair(), &[c_pair()])
}

/// `holder` holds the type-2 reservation; `registered` lists the other registrants in registration order.
pub(crate) fn holds_registered(holder: Pair, registered: &[Pair]) -> Rc<RefCell<Reservation>> {
    let others =
        (registered.iter().zip(2..)).map(|(pair, cntlid)| registrant(*pair, cntlid, false));
    Rc::new(RefCell::new(Reservation {
        entries: std::iter::once(registrant(holder, 1, true))
            .chain(others)
            .collect(),
        rtype: 2,
        ..Reservation::default()
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Preempt,
    Register,
    LeavesHolder,
    AddsUnknown,
    TornFirst,
    TornSecond,
}

/// One host's view of the shared controller: its commands in order, the host ID it set, and one scheduled fault.
pub(crate) struct Card {
    own: Pair,
    reservation: Rc<RefCell<Reservation>>,
    pub(crate) log: Vec<&'static str>,
    exhid: Option<Exhid>,
    fault: Option<Fault>,
    pub(crate) stop_at: Option<usize>,
    /// Runs at Report #1 before its bytes are taken.
    before_report: Option<Box<dyn FnOnce()>>,
    on_report: Option<Box<dyn FnOnce()>>,
    on_second: Option<Box<dyn FnOnce()>>,
    before_preempt: Option<Box<dyn FnOnce()>>,
    on_register: Option<Box<dyn FnOnce()>>,
    /// CAS-BEFORE-DEVICE: the store and host whose committed takeover the first device call must observe.
    after_cas: Option<(Shared, crate::net::ownership::Shard, Host)>,
    /// Traces each command, at its entry, in order with the store requests the recorder holds.
    pub(crate) trace: Option<crate::storage::store::sim::Recorder>,
}

impl Card {
    pub(crate) fn new(own: Pair, reservation: &Rc<RefCell<Reservation>>) -> Self {
        Self {
            own,
            reservation: reservation.clone(),
            log: Vec::new(),
            exhid: None,
            fault: None,
            stop_at: None,
            before_report: None,
            on_report: None,
            on_second: None,
            before_preempt: None,
            on_register: None,
            after_cas: None,
            trace: None,
        }
    }

    fn command(&mut self, name: &'static str) -> Result<(), Failed> {
        if let Some(trace) = &self.trace {
            trace.device(name);
        }
        if let (true, Some((store, shard, host))) = (self.log.is_empty(), &self.after_cas) {
            let record = restart_tests::shard_now_of(store, *shard);
            assert_eq!(
                (record.owner, record.standby),
                (*host, None),
                "the first device call follows the committed takeover"
            );
        }
        self.log.push(name);
        if self.stop_at.is_some_and(|at| self.log.len() > at) {
            return Err(Failed(None));
        }
        Ok(())
    }
}

const CONFLICT: DeviceStatus = DeviceStatus::Nvme(0x83 << 1);

impl Device for Card {
    fn start(&mut self) -> Result<(), Driver> {
        self.command("start").map_err(|_| Driver::LiveQueues)
    }

    fn ready(&mut self) -> Result<(), Failed> {
        self.command("ready")
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        self.command("host")?;
        self.exhid = Some(exhid);
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        self.command("report")?;
        if let Some(hook) = self.before_report.take() {
            hook();
        }
        let bytes = {
            let reservation = self.reservation.borrow();
            encode_report(reservation.rtype, &reservation.entries)
        };
        let second = self.log.iter().filter(|&&c| c == "report").count() == 2;
        if second {
            if let Some(hook) = self.on_second.take() {
                hook();
            }
            if self.fault == Some(Fault::TornSecond) {
                return Ok(vec![]);
            }
        } else {
            if let Some(hook) = self.on_report.take() {
                hook();
            }
            if self.fault == Some(Fault::TornFirst) {
                return Ok(vec![]);
            }
        }
        Ok(bytes)
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.command("register")?;
        assert_eq!(own, self.own);
        if self.fault == Some(Fault::Register) {
            return Err(Failed(Some(CONFLICT)));
        }
        self.reservation
            .borrow_mut()
            .entries
            .push(registrant(own, 9, false));
        if let Some(hook) = self.on_register.take() {
            hook();
        }
        Ok(())
    }

    /// The controller's Preempt-and-Abort: the registration of the preempted key leaves, and the own pair, registered
    /// and identified, becomes the holder only when that key was the holder's.
    fn preempt(&mut self, preempt: LineagePreempt) -> Result<(), Failed> {
        self.command("preempt")?;
        assert_eq!(preempt.pair(), self.own, "the preempt names the own pair");
        assert_eq!(
            self.exhid,
            Some(self.own.exhid),
            "the host ID precedes the preempt"
        );
        if self.fault == Some(Fault::Preempt) {
            return Err(Failed(Some(CONFLICT)));
        }
        if let Some(hook) = self.before_preempt.take() {
            hook();
        }
        if self.fault == Some(Fault::LeavesHolder) {
            return Ok(());
        }
        let mut reservation = self.reservation.borrow_mut();
        // A PRKEY matching a non-holder removes that registration while retaining the reservation holder.
        let transfers = reservation
            .entries
            .iter()
            .any(|e| e.holder && e.pair.key == preempt.preempted());
        assert!(
            reservation
                .entries
                .iter()
                .any(|entry| entry.pair == self.own),
            "the own pair is registered before its preempt"
        );
        reservation
            .entries
            .retain(|entry| entry.pair.key != preempt.preempted());
        if transfers {
            for entry in &mut reservation.entries {
                entry.holder = entry.pair == self.own;
            }
        }
        if self.fault == Some(Fault::AddsUnknown) {
            reservation.entries.push(registrant(
                crate::storage::gate_fixture::foreign(),
                15,
                false,
            ));
        }
        reservation.rtype = 2;
        Ok(())
    }
}

impl crate::failover::restart::Device for Card {
    fn start(&mut self) -> Result<(), Driver> {
        self.command("start").map_err(|_| Driver::LiveQueues)
    }

    fn ready(&mut self) -> Result<(), Failed> {
        self.command("ready")
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        self.command("host")?;
        self.exhid = Some(exhid);
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        self.command("report")?;
        let reservation = self.reservation.borrow();
        Ok(encode_report(reservation.rtype, &reservation.entries))
    }

    fn preempt(&mut self, preempt: crate::storage::SelfPreempt) -> Result<(), Failed> {
        self.command("preempt")?;
        assert_eq!(preempt.pair(), self.own, "the preempt names the own pair");
        assert_eq!(
            self.exhid,
            Some(self.own.exhid),
            "the host ID precedes the preempt"
        );
        Ok(())
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        Device::register(self, own)
    }

    fn preempt_lineage(&mut self, preempt: LineagePreempt) -> Result<(), Failed> {
        Device::preempt(self, preempt)
    }
}

const TO_REPORT: [&str; 4] = ["start", "ready", "host", "report"];
pub(crate) const CONDITION: StoreError =
    StoreError::Refused(crate::storage::store::Refusal::Condition);

pub(crate) fn stored_c() -> Stored {
    Stored(Ok(c_record()))
}

pub(crate) fn stored_b() -> Stored {
    Stored(Ok(b_record()))
}

/// The record a committed takeover of `prior` by `successor` leaves: owner and `E + 1` change, the standby clears,
/// and every manifest field stays.
pub(crate) fn taken(prior: &ShardRecord, successor: Host) -> ShardRecord {
    ShardRecord {
        owner: successor,
        attempts: prior.attempts + 1,
        standby: None,
        ..*prior
    }
}

pub(crate) fn card_after_cas(
    store: &Shared,
    own: Pair,
    host: Host,
    reservation: &Rc<RefCell<Reservation>>,
) -> Card {
    let mut card = Card::new(own, reservation);
    card.after_cas = Some((store.clone(), shard(), host));
    card
}

impl Card {
    /// The card's first device command asserts that `store`'s record of `shard` names `host` owner with no standby,
    /// the committed takeover's record.
    pub(crate) fn after_cas_of(
        mut self,
        store: &Shared,
        shard: crate::net::ownership::Shard,
        host: Host,
    ) -> Self {
        self.after_cas = Some((store.clone(), shard, host));
        self
    }
}

fn own_target() -> Target {
    Target::of(&taken(&shard_record(), c_host()))
}

pub(crate) fn volume_now(store: &Shared) -> VolumeRecord {
    client(store)
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap()
        .into_value()
}

/// C, the record's standby, takes over the retained volume: its CAS commits before its first device call, then the
/// sequence issues start, ready, host ID, Report #1, the preempt of A's key and Report #2; the shard record names C
/// at `E + 1` with no standby and its generation, volume, checkpoint, cut and ancestry kept; the session is
/// `(g, 2E + 2)` naming C; the capability names C's pair. An unregistered C registers before its preempt. The
/// client's tally stays zero.
#[test]
fn the_named_standby_takes_over_the_retained_volume() {
    for registered in [true, false] {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        if !registered {
            reservation.borrow_mut().entries.pop();
        }
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        let mut taking = client(&store);
        let taken_over = takeover_of(&store, c_host())
            .run(&mut taking, &stored_c(), &mut card)
            .unwrap();
        assert_eq!(
            taking.outcomes(),
            crate::storage::store::Tally::default(),
            "registered: {registered}"
        );
        let expected = taken(&shard_record(), c_host());
        assert_eq!(shard_now(&store), expected);
        assert_eq!(taken_over.session().target(), Target::of(&expected));
        assert_eq!(
            taken_over.session().get(),
            crate::net::ownership::session_of(expected.generation.get() as u32, 10)
        );
        let log: Vec<&str> = if registered {
            FULL.to_vec()
        } else {
            vec![
                "start", "ready", "host", "report", "register", "preempt", "report",
            ]
        };
        assert_eq!(card.log, log, "registered: {registered}");
        let (session, fenced, (recorded, _), _, _, _) = taken_over.into_parts();
        assert_eq!(session.target().owner, c_host());
        assert_eq!(fenced.own(), c_pair());
        assert_eq!(recorded, with_c().recorded_pairs());
        assert_eq!(
            reservation.borrow().entries,
            vec![registrant(c_pair(), if registered { 2 } else { 9 }, true)]
        );
        assert_eq!(volume_now(&store), with_c());
    }
}

/// Two attached and enrolled hosts, one named standby: B, which the record does not name, refuses `Stale`, and the
/// owner A refuses `Restart`, both with no write and no device call; the named standby C then takes over. The store client refuses B's
/// CAS before any request too.
#[test]
fn of_two_attached_hosts_only_the_named_standby_takes_over() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(registrant(b_pair(), 3, false));
    let before = reservation.borrow().entries.clone();
    let unwritten = stored(&store);
    let mut card_b = Card::new(b_pair(), &reservation);
    let refused = takeover_of(&store, b_host())
        .run(&mut client(&store), &stored_b(), &mut card_b)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(card_b.log.is_empty());
    let mut b = client(&store);
    let read = b.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    assert_eq!(
        b.take_over(&read, Target::of(read.value()), b_host())
            .map(drop),
        Err(StoreError::Stale(Stale::Target))
    );
    let mut card_a = Card::new(owner_pair(), &reservation);
    let refused = takeover_of(&store, owner_host())
        .run(&mut client(&store), &restart_tests::sample(), &mut card_a)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Restart, None));
    assert!(card_a.log.is_empty());
    assert_eq!(stored(&store), unwritten);
    assert_eq!(reservation.borrow().entries, before);

    let mut card_c = card_after_cas(&store, c_pair(), c_host(), &reservation);
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card_c)
        .unwrap();
    assert_eq!(card_c.log, FULL);
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
}

/// A stale standby designation licenses nothing. A designation replaced between C's record read and its CAS fails
/// the CAS's version condition; a record that names no standby, or B, refuses `Stale` at step 1; a nomination whose
/// target A's bump moved refuses `Stale`. No case writes, issues a device call or names a recovery target.
#[test]
fn a_stale_standby_designation_refuses_without_a_device_command() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let st = store.clone();
    let local = hooked(stored_c(), move || designate(&st, Some(b_host())));
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &local, &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(card.log.is_empty());
    let replaced = ShardRecord {
        standby: Some(b_host()),
        ..shard_record()
    };
    assert_eq!(shard_now(&store), replaced);
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 2);
    let designated = stored(&store);
    let refused = takeover(Target::of(&replaced), c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert_eq!(stored(&store), designated);
    designate(&store, None);
    let cleared = stored(&store);
    let refused = takeover(Target::of(&replaced), c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), cleared);

    let store = restart_tests::store(shard_record(), with_c());
    let nominated = takeover_of(&store, c_host());
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    owner.bump(&read).unwrap();
    let bumped = stored(&store);
    let refused = nominated
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), bumped);
    assert_eq!(
        bumped.1.standby,
        Some(c_host()),
        "the bump keeps the standby"
    );
}

/// Two takeover requests for one nomination, both by C: the second runs between the first's record read and its
/// CAS and takes over; the first's CAS fails its version condition with no device call and mints nothing. One
/// session exists for `(g, E + 1)`, and a flip request naming the nomination's target admits against the taken
/// record as stale.
#[test]
fn two_successor_requests_yield_one_tenure() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let winner = Rc::new(RefCell::new(None));
    let (st, rs, won) = (store.clone(), reservation.clone(), winner.clone());
    let local = hooked(stored_c(), move || {
        let mut card = Card::new(c_pair(), &rs);
        let taken_over = takeover_of(&st, c_host())
            .run(&mut client(&st), &stored_c(), &mut card)
            .unwrap();
        *won.borrow_mut() = Some(taken_over);
    });
    let mut card = Card::new(c_pair(), &reservation);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &local, &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(card.log.is_empty());
    let expected = taken(&shard_record(), c_host());
    assert_eq!(shard_now(&store), expected);
    let winner = winner.borrow_mut().take().unwrap();
    assert_eq!(winner.session().target(), Target::of(&expected));
    assert_eq!(
        reservation.borrow().entries,
        vec![registrant(c_pair(), 2, true)]
    );
    let stale = Retirement::new(
        volume_id(),
        Role::Active,
        Target::of(&shard_record()),
        Trigger::Activation,
    )
    .unwrap();
    assert_eq!(stale.admit(&expected), Err(Stale::Target));
}

/// A's same-host restart and C's takeover condition on one version of the shard record. When C's takeover commits
/// first, the shard-record version condition refuses A's restart bump, which `restart::disposition` classes as a
/// hold. When A's restart reaches its boundary between C's record read and C's CAS, C's takeover ends at the failed
/// shard-record condition check, and the record names A at `E + 1` and C as standby. Both orders preserve one session.
#[test]
fn a_same_host_restart_and_a_takeover_race_the_record_and_the_loser_stops() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let mut card = Card::new(c_pair(), &reservation);
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    let lost = owner.bump(&read).map(drop).unwrap_err();
    assert_eq!(lost, CONDITION);
    assert_eq!(
        crate::failover::restart::disposition(&crate::failover::restart::Check::Bump(lost)),
        crate::failover::restart::Disposition::Hold,
        "the lost bump holds with no flip"
    );
    let expected = taken(&shard_record(), c_host());
    assert_eq!(shard_now(&store), expected);

    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut card = Card::new(c_pair(), &reservation);
    let st = store.clone();
    let local = hooked(stored_c(), move || {
        let mut restarting = restart_tests::Card::new();
        restart_tests::restart()
            .run(&mut client(&st), &restart_tests::sample(), &mut restarting)
            .unwrap();
        assert_eq!(restarting.log, FULL);
    });
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &local, &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(card.log.is_empty());
    assert_eq!(
        shard_now(&store),
        ShardRecord {
            attempts: 5,
            ..shard_record()
        }
    );
}

/// A takeover replayed after its CAS committed reads a record naming C owner and refuses `Restart` with no device
/// call and no write.
#[test]
fn a_replayed_takeover_refuses_restart_before_any_device_command() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let nominated = takeover_of(&store, c_host());
    nominated
        .run(
            &mut client(&store),
            &stored_c(),
            &mut Card::new(c_pair(), &reservation),
        )
        .unwrap();
    let after = stored(&store);
    let mut card = Card::new(c_pair(), &reservation);
    let refused = nominated
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Restart, None));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), after);
}

/// An absent shard or volume record refuses `Records(Absent)`, a missing local record `Local(Absent)`, a record at
/// `E = ATTEMPTS_MAX` or at the last generation `Exhausted`, and a record at `E = 0` `Stale`, each before the CAS with
/// no write and no device call; the store client refuses the `E = 0` CAS before any request too.
/// A nomination whose `E` is `u32::MAX` matches no record and refuses `Stale` before any arithmetic on it.
#[test]
fn absent_records_and_an_exhausted_record_refuse_before_the_cas() {
    let reservation = a_holds_c_registered();
    let store = Shared::new();
    client(&store)
        .create(Key::Volume(volume_id()), with_c())
        .unwrap();
    let mut card = Card::new(c_pair(), &reservation);
    let refused = takeover(Target::of(&shard_record()), c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Records(StoreError::Absent), None)
    );

    let store = Shared::new();
    client(&store).create_shard(shard_record()).unwrap();
    let before = stored(&store);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Records(StoreError::Absent), None)
    );
    assert_eq!(stored(&store), before);

    let store = restart_tests::store(shard_record(), with_c());
    let before = stored(&store);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &Stored(Err(Local::Absent)), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Local(Local::Absent), None)
    );
    assert_eq!(stored(&store), before);

    // The last generation admits no session after this one, so step 1 refuses before the CAS, whose witness the
    // session activation would otherwise refuse after a committed write; at `E = ATTEMPTS_MAX` the store client would
    // refuse the CAS before any request, and step 1 refuses first; at `E = 0` the generation's fresh first
    // acquisition has not run, so no tenure exists to take over.
    let bare = ShardRecord {
        ancestry: Default::default(),
        checkpoint: None,
        cut: 0,
        ..shard_record()
    };
    for (record, check) in [
        (
            ShardRecord {
                attempts: crate::failover::records::ATTEMPTS_MAX,
                ..bare
            },
            Check::Exhausted(crate::storage::SessionRefusal::AttemptsExhausted),
        ),
        (
            ShardRecord {
                generation: crate::net::ownership::ShardGeneration::new(u64::from(u32::MAX))
                    .unwrap(),
                ..bare
            },
            Check::Exhausted(crate::storage::SessionRefusal::GenerationExhausted),
        ),
        (
            ShardRecord {
                attempts: 0,
                ..bare
            },
            Check::Stale,
        ),
    ] {
        let store = restart_tests::store(record, with_c());
        let before = stored(&store);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!((refused.check, refused.recovery), (check, None));
        assert_eq!(stored(&store), before);
        assert!(card.log.is_empty());
    }
    // The store client refuses the `E = 0` CAS before any request.
    let store = restart_tests::store(
        ShardRecord {
            attempts: 0,
            ..bare
        },
        with_c(),
    );
    let before = stored(&store);
    let mut c = client(&store);
    let read = c.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    assert_eq!(
        c.take_over(&read, Target::of(read.value()), c_host())
            .map(drop),
        Err(StoreError::Stale(Stale::Target))
    );
    assert_eq!(stored(&store), before);
    let store = restart_tests::store(shard_record(), with_c());
    let before = stored(&store);
    let overflowing = Target {
        attempts: u32::MAX,
        ..Target::of(&shard_record())
    };
    let refused = takeover(overflowing, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert_eq!(stored(&store), before);
    assert!(card.log.is_empty());
}

/// Step 2 refuses a successor whose identity the volume record or its local record does not confirm: a volume record
/// enrolling no pair for C's live attach refuses `Local(Unenrolled)`, one enrolling another pair `Local(Altered)`,
/// and a local record bound to another instance `Local(Binding)`, each before the CAS with no write, no device call
/// and no recovery hint.
#[test]
fn an_unconfirmed_successor_identity_refuses_before_the_cas() {
    let mut missing = with_c();
    missing.pairs.retain(|entry| entry.host != c_host());
    let mut altered = with_c();
    altered.pairs[1].pair = b_pair();
    for (volume, local, expected) in [
        (missing, stored_c(), Local::Unenrolled),
        (altered, stored_c(), Local::Altered),
        (with_c(), stored_b(), Local::Binding),
    ] {
        let store = restart_tests::store(shard_record(), volume);
        let before = stored(&store);
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &local, &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Local(expected), None)
        );
        assert!(card.log.is_empty());
        assert_eq!(stored(&store), before);
    }
}

/// SUPERSEDED-TENURE-PREEMPT's refusals: after the acknowledged CAS, a Report #1 whose holder is an unrecorded pair,
/// the own pair or no pair, or that lists an unrecorded registrant, refuses at Report #1 with the own tenure as the
/// hint and no preempt; the record names C at `E + 1`, and the volume record and the reservation are as they were.
#[test]
fn a_holder_outside_the_superseded_tenures_refuses_after_the_cas_with_no_preempt() {
    let stranger = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((7 << 32) | 7).unwrap(),
    };
    let cases: [(&str, Vec<Registrant>, Check); 4] = [
        (
            "unrecorded holder",
            vec![
                registrant(stranger, 1, true),
                registrant(c_pair(), 2, false),
            ],
            Check::Holder(HolderRefusal::Unrecorded),
        ),
        (
            "own holder",
            vec![
                registrant(c_pair(), 2, true),
                registrant(owner_pair(), 1, false),
            ],
            Check::Holder(HolderRefusal::Own),
        ),
        (
            "nobody holds",
            vec![
                registrant(owner_pair(), 1, false),
                registrant(c_pair(), 2, false),
            ],
            Check::Holder(HolderRefusal::Unresolved),
        ),
        (
            "unrecorded registrant",
            vec![
                registrant(owner_pair(), 1, true),
                registrant(c_pair(), 2, false),
                registrant(stranger, 3, false),
            ],
            Check::Holder(HolderRefusal::Registrants(NotSole::ForeignRegistrant)),
        ),
    ];
    for (name, entries, check) in cases {
        let store = restart_tests::store(shard_record(), with_c_and_b());
        let reservation = Rc::new(RefCell::new(Reservation {
            entries: entries.clone(),
            rtype: 2,
            ..Reservation::default()
        }));
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (check, Some(own_target())),
            "{name}"
        );
        assert_eq!(card.log, TO_REPORT, "{name}");
        assert_eq!(
            shard_now(&store),
            taken(&shard_record(), c_host()),
            "{name}"
        );
        assert_eq!(volume_now(&store), with_c_and_b(), "{name}");
        assert_eq!(reservation.borrow().entries, entries, "{name}");
    }
}

/// HOST-LOSS-KEEPS-VOLUME after a committed CAS: when A's registration no longer holds, the takeover's Report #1
/// refuses `Holder(Unresolved)` with no preempt, whether A stays registered or its registration is gone, and C's
/// same-host restart then finds nobody holding beside its own pair and recorded pairs, so it refuses `Unheld` at
/// Report #1 with no flip, no bump and C's tenure as the recovery hint (NO-HOLDER-HOLD). The record keeps naming C,
/// the volume record is unchanged and the volume stays active for the fresh-host attach: a registration that ended
/// without a preempt shows no volume loss.
#[test]
fn a_successor_restart_after_a_report_with_nobody_holding_keeps_the_volume() {
    for (name, entries) in [
        (
            "A registered without holding",
            vec![
                registrant(owner_pair(), 1, false),
                registrant(c_pair(), 2, false),
            ],
        ),
        ("A unregistered", vec![registrant(c_pair(), 2, false)]),
    ] {
        let store = restart_tests::store(shard_record(), with_c_and_b());
        let reservation = Rc::new(RefCell::new(Reservation {
            entries: entries.clone(),
            rtype: 2,
            ..Reservation::default()
        }));
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Holder(HolderRefusal::Unresolved), Some(own_target())),
            "{name}"
        );
        assert_eq!(card.log, TO_REPORT, "{name}: no preempt");
        let committed = stored(&store);
        assert_eq!(committed.1, taken(&shard_record(), c_host()), "{name}");
        let mut restarting = restart_tests::Card::new();
        restarting.entries = entries.clone();
        let refused = restart_tests::restart_of(shard(), holder_of(c_host()))
            .run(&mut client(&store), &stored_c(), &mut restarting)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (
                crate::failover::restart::Check::Unheld,
                None,
                Some(own_target())
            ),
            "{name}"
        );
        assert_eq!(restarting.log, TO_REPORT, "{name}: no self preempt");
        assert_eq!(stored(&store), committed, "{name}: no bump");
        assert_eq!(volume_now(&store), with_c_and_b(), "{name}");
    }
}

/// A takeover CAS of unknown outcome refuses `TakeOver(Unknown)` with no device call and no session, under each
/// unknown arm, naming the own tenure as the hint. The host then runs only the same-host restart: when the CAS
/// committed, the restart reads the record naming C, bumps it once and preempts A's recorded registration through
/// its lineage arm, reaching FB with no flip; when it did not, the restart refuses `Deposed` with no device call. A
/// duplicate invocation of
/// the takeover after a committed CAS, outside the restart-only rule, refuses `Restart`. No reread licenses a
/// session. The takeover's client tallies one unknown shard-record write and nothing else.
#[test]
fn an_unknown_cas_outcome_issues_no_device_command_and_continues_only_by_restart() {
    use crate::storage::store::{RecordClass, Tallied};
    for arm in UNKNOWN {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        let path = takeover_of(&store, c_host());
        for scheduled in [Arm::Pass, Arm::Pass, arm] {
            store.schedule(scheduled);
        }
        let mut card = Card::new(c_pair(), &reservation);
        let mut taking = client(&store);
        let refused = path.run(&mut taking, &stored_c(), &mut card).unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::TakeOver(StoreError::Unknown), Some(own_target())),
            "{arm:?}"
        );
        assert!(card.log.is_empty(), "{arm:?}");
        assert_eq!(
            crate::storage::store::tally_tests::nonzero(taking.outcomes()),
            [(RecordClass::Shard, Tallied::Unknown, 1)],
            "{arm:?}"
        );
        let expected = if committed(arm) {
            taken(&shard_record(), c_host())
        } else {
            shard_record()
        };
        let settled = stored(&store);
        assert_eq!(settled.1, expected, "{arm:?}");

        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        let restart = restart_tests::restart_of(shard(), holder_of(c_host())).run(
            &mut client(&store),
            &stored_c(),
            &mut restarting,
        );
        if committed(arm) {
            let restarted = restart.unwrap();
            assert!(restarted.lineage(), "{arm:?}");
            assert_eq!(
                restarted.session().target(),
                Target {
                    attempts: own_target().attempts + 1,
                    ..own_target()
                },
                "{arm:?}"
            );
            assert_eq!(restarting.log, restart_tests::ARM, "{arm:?}");
            assert_eq!(restarting.preempted, [owner_pair().key], "{arm:?}");
            assert_eq!(volume_now(&store), with_c(), "{arm:?}");
            let mut card = Card::new(c_pair(), &reservation);
            let rerun = takeover(Target::of(&shard_record()), c_host())
                .run(&mut client(&store), &stored_c(), &mut card)
                .unwrap_err();
            assert_eq!(
                (rerun.check, rerun.recovery),
                (Check::Restart, None),
                "{arm:?}"
            );
            assert!(card.log.is_empty(), "{arm:?}");
        } else {
            let restart = restart.unwrap_err();
            assert_eq!(
                (restart.check, restart.flip, restart.recovery),
                (crate::failover::restart::Check::Deposed, None, None),
                "{arm:?}"
            );
            assert!(restarting.log.is_empty(), "{arm:?}");
            assert_eq!(stored(&store), settled, "{arm:?}");
        }
    }
}

/// CAS-BEFORE-DEVICE with DEVICE-FAILURE-HOLD: C's takeover CAS commits with an unknown outcome, and C's same-host
/// restart then fails its ready wait, its host ID or its Report #1. Each refusal holds with no flip and C's tenure
/// as the hint, and leaves the shard and volume records as the CAS left them, so a transient fault on the restart
/// that follows an unknown CAS keeps the retained volume. C's clean rerun then preempts A's recorded registration
/// through its lineage arm.
#[test]
fn an_unknown_takeover_cas_then_a_restart_device_failure_keeps_the_volume() {
    for arm in UNKNOWN.into_iter().filter(|arm| committed(*arm)) {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        let path = takeover_of(&store, c_host());
        for scheduled in [Arm::Pass, Arm::Pass, arm] {
            store.schedule(scheduled);
        }
        let mut card = Card::new(c_pair(), &reservation);
        let refused = path
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            refused.check,
            Check::TakeOver(StoreError::Unknown),
            "{arm:?}"
        );
        let settled = stored(&store);
        assert_eq!(settled.1, taken(&shard_record(), c_host()), "{arm:?}");
        for (stop_at, check) in [
            (1, crate::failover::restart::Check::Ready(Failed(None))),
            (2, crate::failover::restart::Check::HostId(Failed(None))),
            (
                3,
                crate::failover::restart::Check::FirstReport(Failed(None)),
            ),
        ] {
            let mut restarting = restart_tests::Card::new();
            restarting.entries = reservation.borrow().entries.clone();
            restarting.stop_at = Some(stop_at);
            let restart = restart_tests::restart_of(shard(), holder_of(c_host()))
                .run(&mut client(&store), &stored_c(), &mut restarting)
                .unwrap_err();
            assert_eq!(
                (restart.check, restart.flip, restart.recovery),
                (check.clone(), None, Some(own_target())),
                "{arm:?} {check:?}"
            );
            assert_eq!(
                stored(&store),
                settled,
                "{arm:?} {check:?}: no record write"
            );
            assert_eq!(volume_now(&store), with_c(), "{arm:?} {check:?}");
        }
        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        let rerun = restart_tests::restart_of(shard(), holder_of(c_host()))
            .run(&mut client(&store), &stored_c(), &mut restarting)
            .unwrap();
        assert!(rerun.lineage(), "{arm:?}");
        assert_eq!(restarting.preempted, [owner_pair().key], "{arm:?}");
        assert_eq!(
            stored(&store).1.attempts,
            own_target().attempts + 1,
            "{arm:?}"
        );
    }
}

/// The named standby's takeover ends a hold. A's restarts each fail at Report #2 after their own bump, so each holds
/// with no flip and moves `E`. A nomination of the record's `E` before those reruns refuses `Stale` with no device
/// call, and a nomination of the record A's last hold left commits and reaches C's admission capability on the
/// retained volume at its generation.
#[test]
fn the_standby_takeover_ends_a_restart_hold_at_the_last_held_epoch() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let nominated = Target::of(&shard_record());
    for rerun in 1..=2 {
        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        restarting.stop_at = Some(5);
        let refused = restart_tests::restart()
            .run(
                &mut client(&store),
                &restart_tests::sample(),
                &mut restarting,
            )
            .unwrap_err();
        let held = Target {
            attempts: nominated.attempts + rerun,
            ..nominated
        };
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (
                crate::failover::restart::Check::SecondReport(Failed(None)),
                None,
                Some(held)
            ),
            "rerun {rerun}"
        );
        assert_eq!(Target::of(&shard_now(&store)), held, "rerun {rerun}");
    }
    let mut card = Card::new(c_pair(), &reservation);
    let stale = takeover(nominated, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((stale.check, stale.recovery), (Check::Stale, None));
    assert!(card.log.is_empty());
    let last = shard_now(&store);
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let taken_over = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    let expected = taken(&last, c_host());
    assert_eq!(shard_now(&store), expected);
    assert_eq!(taken_over.session().target(), Target::of(&expected));
    assert_eq!(
        (expected.generation, expected.active),
        (shard_record().generation, shard_record().active)
    );
    assert_eq!(volume_now(&store), with_c());
}

/// The successor dies after its takeover write and before its preempt, and recovery is the fresh-host path. C's
/// takeover commits and C stops at Report #1 while A holds. The record names C at `E + 1` with no standby, so no host
/// holds takeover authority: A's restart refuses `Deposed` with no flip, and C's restart, over a copy of the store,
/// preempts A's recorded registration through its lineage arm. With C lost as well, the shard needs a fresh host;
/// the reconciler attaches,
/// enrolls and designates D over C's tenure. D's CAS commits, its Report #1 shows A, whose tenure C's write
/// superseded, holding under a pair enrolled for A's live attach, and D preempts A's key and reaches its
/// capability on the retained volume at its generation, checkpoint, cut and ancestry. With an unrecorded pair
/// holding in A's place, D's Report #1 refuses `Holder(Unrecorded)` with no preempt and the reservation unchanged.
#[test]
fn a_fresh_host_recovers_the_volume_after_a_successor_stops_before_its_preempt() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let before = reservation.borrow().entries.clone();
    let mut card_c = Card::new(c_pair(), &reservation);
    card_c.stop_at = Some(3);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card_c)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::FirstReport(Failed(None)), Some(own_target()))
    );
    assert_eq!(card_c.log, TO_REPORT);
    let after_c = taken(&shard_record(), c_host());
    assert_eq!(shard_now(&store), after_c);
    let committed_c = stored(&store);
    assert_eq!(reservation.borrow().entries, before);

    let mut restarting = restart_tests::Card::new();
    restarting.entries = before.clone();
    let refused = restart_tests::restart()
        .run(
            &mut client(&store),
            &restart_tests::sample(),
            &mut restarting,
        )
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (crate::failover::restart::Check::Deposed, None, None)
    );
    assert!(restarting.log.is_empty());
    let copy = crate::storage::store::sim::Shared(Rc::new(RefCell::new(store.0.borrow().clone())));
    let mut restarting = restart_tests::Card::new();
    restarting.entries = before.clone();
    let restarted = restart_tests::restart_of(shard(), holder_of(c_host()))
        .run(&mut client(&copy), &stored_c(), &mut restarting)
        .unwrap();
    assert!(restarted.lineage());
    assert_eq!(restarting.preempted, [owner_pair().key]);
    assert_eq!(
        restarted.session().target(),
        Target {
            attempts: after_c.attempts + 1,
            ..Target::of(&after_c)
        }
    );
    assert_eq!(stored(&store), committed_c);

    let lost = |h: Host| h == owner_host() || h == c_host();
    assert_eq!(
        crate::failover::standbys::need(&after_c, lost),
        Some(crate::failover::standbys::Need::Fresh)
    );
    fence_page_zero(&store);
    let d_record = designate_fresh_host(&store);
    let designated = shard_now(&store);
    assert_eq!(designated.standby, Some(d_host()));
    let enrolled = volume_now(&store);

    let stranger = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((7 << 32) | 7).unwrap(),
    };
    let foreign = Rc::new(RefCell::new(Reservation {
        entries: vec![registrant(stranger, 1, true)],
        rtype: 2,
        ..Reservation::default()
    }));
    let unrelated = restart_tests::store(designated, enrolled.clone());
    let mut card_d = Card::new(d_record.pair(), &foreign);
    let refused = takeover_of(&unrelated, d_host())
        .run(
            &mut client(&unrelated),
            &Stored(Ok(d_record.clone())),
            &mut card_d,
        )
        .unwrap_err();
    assert_eq!(refused.check, Check::Holder(HolderRefusal::Unrecorded));
    assert_eq!(card_d.log, TO_REPORT);
    assert_eq!(foreign.borrow().entries, [registrant(stranger, 1, true)]);

    let mut card_d = card_after_cas(&store, d_record.pair(), d_host(), &reservation);
    let recovered = takeover_of(&store, d_host())
        .run(
            &mut client(&store),
            &Stored(Ok(d_record.clone())),
            &mut card_d,
        )
        .unwrap();
    assert_eq!(
        card_d.log,
        [
            "start", "ready", "host", "report", "register", "preempt", "report"
        ]
    );
    let after_d = taken(&designated, d_host());
    assert_eq!(shard_now(&store), after_d);
    assert_eq!(recovered.session().target(), Target::of(&after_d));
    let manifest = |r: &ShardRecord| (r.generation, r.active, r.checkpoint, r.cut, r.ancestry);
    assert_eq!(manifest(&after_d), manifest(&shard_record()));
    assert_eq!(
        reservation.borrow().entries,
        vec![
            registrant(c_pair(), 2, false),
            registrant(d_record.pair(), 9, true)
        ]
    );
    assert_eq!(volume_now(&store), enrolled);
}

/// Each device refusal after the CAS stops the sequence at its step with the own tenure as the hint, the record
/// taken and C's same-host restart as the one next step: the driver start, the ready wait, the host ID, Report #1, a
/// torn Report #1, Register and Report #2.
#[test]
fn device_refusals_after_the_cas_name_the_own_tenure() {
    type Case = (Option<usize>, Option<Fault>, bool, Check, usize);
    let cases: [Case; 7] = [
        (Some(0), None, true, Check::Driver(Driver::LiveQueues), 1),
        (Some(1), None, true, Check::Ready(Failed(None)), 2),
        (Some(2), None, true, Check::HostId(Failed(None)), 3),
        (Some(3), None, true, Check::FirstReport(Failed(None)), 4),
        (
            None,
            Some(Fault::TornFirst),
            true,
            Check::Unparsed(NotSole::Unreadable),
            4,
        ),
        (
            None,
            Some(Fault::Register),
            false,
            Check::Register(Failed(Some(CONFLICT))),
            5,
        ),
        (Some(5), None, true, Check::SecondReport(Failed(None)), 6),
    ];
    for (stop_at, fault, registered, check, issued) in cases {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        if !registered {
            reservation.borrow_mut().entries.pop();
        }
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        card.stop_at = stop_at;
        card.fault = fault;
        let path = takeover_of(&store, c_host());
        let refused = path
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert!(
            matches!(path.next(&refused), Next::Restart(restart) if restart.holder == holder_of(c_host())),
            "{check:?}: the one next step is C's restart"
        );
        assert_eq!(
            (refused.check, refused.recovery),
            (check.clone(), Some(own_target()))
        );
        assert_eq!(card.log.len(), issued, "{check:?}");
        assert_eq!(
            shard_now(&store),
            taken(&shard_record(), c_host()),
            "{check:?}"
        );
        assert_eq!(volume_now(&store), with_c(), "{check:?}");
    }
}

/// A takeover whose holder is another volume's refuses `Stale` at step 1 with no write and no device call.
#[test]
fn a_takeover_of_another_volume_refuses_stale() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let other = crate::failover::records::VolumeId::new("vol-0c").unwrap();
    client(&store)
        .create(
            Key::Volume(other),
            VolumeRecord {
                volume: other,
                ..with_c_and_b()
            },
        )
        .unwrap();
    let before = stored(&store).0;
    let mut path = takeover_of(&store, c_host());
    path.restart.holder.volume = other;
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store).0, before);
}

/// C's restart after its acknowledged CAS and a failed preempt takes the lineage arm: it bumps C's tenure once,
/// preempts A's recorded registration and reaches FB with no flip; the volume stays active. The unknown-outcome arms are
/// `an_unknown_cas_outcome_issues_no_device_command_and_continues_only_by_restart`'s.
#[test]
fn a_successor_restart_after_its_takeover_cas_keeps_the_volume() {
    {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        let mut card = Card::new(c_pair(), &reservation);
        card.fault = Some(Fault::Preempt);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Preempt(Failed(Some(CONFLICT))), Some(own_target()))
        );
        assert_eq!(card.log, FULL[..5]);
        let expected = taken(&shard_record(), c_host());
        let committed = stored(&store);
        assert_eq!(committed.1, expected);
        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        let restarted = restart_tests::restart_of(shard(), holder_of(c_host()))
            .run(&mut client(&store), &stored_c(), &mut restarting)
            .unwrap();
        assert!(restarted.lineage());
        assert_eq!(restarting.log, restart_tests::ARM);
        assert_eq!(restarting.preempted, [owner_pair().key]);
        assert_eq!(
            stored(&store).1,
            ShardRecord {
                attempts: expected.attempts + 1,
                ..expected
            }
        );
        assert_eq!(
            stored(&store).0,
            committed.0.next().unwrap(),
            "the bump is the restart's one shard-record write"
        );
        assert_eq!(volume_now(&store), with_c());
    }
}

/// A successor superseded after its CAS receives no capability. B, designated over C's tenure, takes the record
/// while C pauses, preempts the holder A, whose tenure B's write superseded through C's, and reaches its capability.
/// When C paused in Register, C's check before the preempt refuses `Superseded` and C issues no preempt; when C
/// paused after that check, C's preempt names A's key, which no registrant holds, so B keeps the reservation and C's
/// Report #2 refuses.
#[test]
fn a_superseded_successor_stops_before_preempt_or_before_admission() {
    for after_check in [false, true] {
        let store = restart_tests::store(shard_record(), with_c_and_b());
        let reservation = a_holds_c_registered();
        reservation
            .borrow_mut()
            .entries
            .push(registrant(b_pair(), 3, false));
        let mut c = Card::new(c_pair(), &reservation);
        let (st, rs) = (store.clone(), reservation.clone());
        let after_b = taken(&taken(&shard_record(), c_host()), b_host());
        let run_b = Box::new(move || {
            designate(&st, Some(b_host()));
            let mut b = card_after_cas(&st, b_pair(), b_host(), &rs);
            let taken_over = takeover_of(&st, b_host())
                .run(&mut client(&st), &stored_b(), &mut b)
                .unwrap();
            assert_eq!(taken_over.session().target(), Target::of(&after_b));
            assert_eq!(b.log, FULL);
        });
        if after_check {
            c.before_preempt = Some(run_b);
        } else {
            reservation
                .borrow_mut()
                .entries
                .retain(|e| e.pair != c_pair());
            c.on_register = Some(run_b);
        }
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut c)
            .unwrap_err();
        let (check, log): (Check, Vec<&str>) = if after_check {
            (Check::NotSole(NotSole::ForeignHolder), FULL.to_vec())
        } else {
            (
                Check::Superseded,
                vec!["start", "ready", "host", "report", "register"],
            )
        };
        assert_eq!(
            (refused.check, refused.recovery),
            (check, Some(own_target())),
            "after_check: {after_check}"
        );
        assert_eq!(c.log, log, "after_check: {after_check}");
        assert_eq!(shard_now(&store), after_b);
        let holders: Vec<Pair> = reservation
            .borrow()
            .entries
            .iter()
            .filter(|e| e.holder)
            .map(|e| e.pair)
            .collect();
        assert_eq!(holders, [b_pair()], "after_check: {after_check}");
        assert_eq!(volume_now(&store), with_c_and_b());
    }
}

/// KEY-REUSE-EXPOSURE: C pauses after its tenure check and before its preempt of A's key. A, designated over C's
/// tenure, takes the record, refuses at Report #1 since its own pair holds, and serves again through its same-host
/// restart under the same attachment key. C's stale preempt then lands over A's later tenure, and C's final check
/// refuses `Superseded` with no capability. A's owner poll withdraws with no retirement, and A's next restart, whose
/// record still names A, preempts C's key through its lineage arm and reaches FB at the next `E`, so the retained
/// volume stays active under one serving tenure.
#[test]
fn a_reused_key_can_be_preempted_after_the_record_check_but_grants_no_capability() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let reservation = a_holds_c_registered();
    let (st, rs) = (store.clone(), reservation.clone());
    let mut c = Card::new(c_pair(), &reservation);
    c.before_preempt = Some(Box::new(move || {
        designate(&st, Some(owner_host()));
        let mut a = Card::new(owner_pair(), &rs);
        let refused = takeover_of(&st, owner_host())
            .run(&mut client(&st), &restart_tests::sample(), &mut a)
            .unwrap_err();
        let a_tenure = Target::of(&taken(&taken(&shard_record(), c_host()), owner_host()));
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Holder(HolderRefusal::Own), Some(a_tenure))
        );
        assert_eq!(a.log, TO_REPORT);
        let mut restarting = restart_tests::Card::new();
        restarting.entries = rs.borrow().entries.clone();
        restart_tests::restart()
            .run(&mut client(&st), &restart_tests::sample(), &mut restarting)
            .unwrap();
    }));
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut c)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Superseded, Some(own_target()))
    );
    assert_eq!(shard_now(&store).owner, owner_host());
    assert!(
        reservation
            .borrow()
            .entries
            .iter()
            .any(|e| e.holder && e.pair == c_pair()),
        "the stale preempt landed over A's later tenure"
    );
    let current = shard_now(&store);
    let unwritten = stored(&store);
    let volume = volume_now(&store);
    let entries = reservation.borrow().entries.clone();
    let report = crate::failover::poll_tests::report_of(&entries);
    let peers = [b_host(), c_host()].map(|host| crate::failover::attachments::Peer {
        host,
        instance: instance_of(host),
    });
    let listed: Vec<String> = [owner_host(), b_host(), c_host()]
        .map(|host| instance_of(host).as_str().to_owned())
        .to_vec();
    let reads = crate::failover::poll::Reads {
        shard: Some(&current),
        volume: Some(&volume),
        listed: Some(&listed),
        peers: &peers,
    };
    let verdict = crate::failover::poll::poll(
        &holder_of(owner_host()),
        Target::of(&current),
        owner_pair(),
        Ok(&report),
        &reads,
        &crate::storage::gate_fixture::bounds_of(limits()),
    );
    assert_eq!(verdict, crate::failover::poll::Verdict::Withdraw);
    let mut restarting = restart_tests::Card::new();
    restarting.entries = entries;
    let restarted = restart_tests::restart()
        .run(
            &mut client(&store),
            &restart_tests::sample(),
            &mut restarting,
        )
        .unwrap();
    assert!(restarted.lineage());
    assert_eq!(restarting.preempted, [c_pair().key]);
    assert_eq!(
        stored(&store).1,
        ShardRecord {
            attempts: current.attempts + 1,
            ..current
        }
    );
    assert_eq!(
        stored(&store).0,
        unwritten.0.next().unwrap(),
        "the bump is the restart's one shard-record write"
    );
    assert_eq!(volume_now(&store), with_c_and_b());
}

/// C pauses in Register after its CAS while A takes the record back through a designation and its takeover CAS, and
/// A refuses at Report #1 since its own pair holds; C's check before the preempt refuses `Superseded`, so C issues no
/// preempt and A keeps holding.
#[test]
fn a_pause_before_the_tenure_check_issues_no_stale_preempt() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    reservation.borrow_mut().entries.pop();
    let (st, rs) = (store.clone(), reservation.clone());
    let mut c = Card::new(c_pair(), &reservation);
    c.on_register = Some(Box::new(move || {
        designate(&st, Some(owner_host()));
        let mut a = Card::new(owner_pair(), &rs);
        let refused = takeover_of(&st, owner_host())
            .run(&mut client(&st), &restart_tests::sample(), &mut a)
            .unwrap_err();
        let a_tenure = Target::of(&taken(&taken(&shard_record(), c_host()), owner_host()));
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Holder(HolderRefusal::Own), Some(a_tenure))
        );
        assert_eq!(a.log, TO_REPORT);
    }));
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut c)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Superseded, Some(own_target()))
    );
    assert_eq!(c.log, ["start", "ready", "host", "report", "register"]);
    assert_eq!(shard_now(&store).owner, owner_host());
    assert!(
        reservation
            .borrow()
            .entries
            .iter()
            .any(|e| e.holder && e.pair == owner_pair()),
        "A keeps the reservation"
    );
}

#[test]
fn report_two_refuses_a_foreign_holder_unknown_registrant_and_torn_bytes() {
    for (fault, expected) in [
        (Fault::LeavesHolder, Check::NotSole(NotSole::ForeignHolder)),
        (
            Fault::AddsUnknown,
            Check::NotSole(NotSole::ForeignRegistrant),
        ),
        (
            Fault::TornSecond,
            Check::SecondUnparsed(NotSole::Unreadable),
        ),
    ] {
        let store = restart_tests::store(shard_record(), with_c());
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        card.fault = Some(fault);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (expected, Some(own_target()))
        );
        assert_eq!(card.log, FULL);
        assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
        assert_eq!(volume_now(&store), with_c());
    }
}

/// READ-ORDER-ADMISSION: each Report is judged against a volume record read after it. A fence raise that drops C's
/// pair refuses `Local(Unenrolled)` at either reread; one that drops A's pair during Report #1 refuses `Holder`, since
/// the predecessor holder is unrecorded, and during Report #2 admits. Both reads follow the CAS.
#[test]
fn a_report_rereads_enrollment_and_volume_checks() {
    for second in [false, true] {
        for own in [false, true] {
            let store = restart_tests::store(shard_record(), with_c());
            let mut card = Card::new(c_pair(), &a_holds_c_registered());
            let st = store.clone();
            let hook = Box::new(move || {
                let mut writer = client(&st);
                let read = writer
                    .read::<VolumeRecord>(Key::Volume(volume_id()))
                    .unwrap();
                let mut next = read.value().clone();
                next.fence = (3 << 32) | 10;
                next.pairs
                    .retain(|p| p.host != if own { c_host() } else { owner_host() });
                writer.replace(&read, next).unwrap();
            });
            if second {
                card.on_second = Some(hook);
            } else {
                card.on_report = Some(hook);
            }
            let mut path = takeover_of(&store, c_host());
            let peers = [crate::failover::attachments::Peer {
                host: owner_host(),
                instance: holder_of(owner_host()).instance,
            }];
            path.restart.peers = &peers;
            let result = path.run(&mut client(&store), &stored_c(), &mut card);
            if second && !own {
                let mut dropped = with_c();
                dropped.pairs.retain(|p| p.host != owner_host());
                assert_eq!(result.unwrap().into_parts().2.0, dropped.recorded_pairs());
                continue;
            }
            let refused = result.unwrap_err();
            let check = if own {
                Check::Local(Local::Unenrolled)
            } else {
                Check::Holder(HolderRefusal::Unrecorded)
            };
            assert_eq!(
                (refused.check, refused.recovery),
                (check, Some(own_target()))
            );
            assert_eq!(
                card.log,
                if second {
                    FULL.to_vec()
                } else {
                    TO_REPORT.to_vec()
                }
            );
        }
    }
}

#[test]
fn a_takeover_value_passes_the_attach_gate_without_a_gate_command() {
    use crate::storage::gate_fixture::{ZeroClock, arena, attach_reserving, ticks};
    let store = restart_tests::store(shard_record(), with_c());
    let path = takeover_of(&store, c_host());
    let taken = path
        .run(
            &mut client(&store),
            &stored_c(),
            &mut Card::new(c_pair(), &a_holds_c_registered()),
        )
        .unwrap();
    let expected = (taken.session().generation(), taken.session().epoch());
    let (mut authority, _) = crate::storage::ServingAuthority::restarted(
        path.restart.bounds,
        Box::new(ZeroClock),
        taken,
    );
    // The gate's pass is the property; the named slot's layout exceeds this fixture's prefix.
    assert!(
        authority.take_warm().is_some(),
        "the record names a checkpoint"
    );
    let arena = arena();
    let storage = crate::storage::owner_fixture::storage(8);
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    {
        let mut r = registry.borrow_mut();
        r.entries.push(registrant(c_pair(), 2, true));
        r.rtype = 2;
    }
    ticks(&mut volume, &control, 4);
    assert_eq!(
        volume.authority_state(),
        crate::failover::serving::State::Recovering
    );
    let token = volume.serving_token().unwrap();
    assert_eq!((token.exhid, token.key), (c_pair().exhid, c_pair().key));
    assert_eq!((token.generation, token.epoch), expected);
    let r = registry.borrow();
    assert!(!r.log.is_empty() && r.log.iter().all(|c| c.is_report()));
}

#[test]
fn a_takeover_between_restart_records_and_report_deposes_the_restart() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let path = takeover_of(&store, c_host());
    let st = store.clone();
    let rs = reservation.clone();
    let mut restarting = restart_tests::Card::new();
    restarting.entries = reservation.borrow().entries.clone();
    let shared = Rc::new(RefCell::new(restarting.entries.clone()));
    let (shared_hook, shared_card) = (shared.clone(), shared.clone());
    restarting.before_report = Some(Box::new(move || {
        path.run(&mut client(&st), &stored_c(), &mut Card::new(c_pair(), &rs))
            .unwrap();
        *shared_hook.borrow_mut() = rs.borrow().entries.clone();
    }));
    restarting.entries_from = Some(shared_card);
    let refused = restart_tests::restart()
        .run(
            &mut client(&store),
            &restart_tests::sample(),
            &mut restarting,
        )
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (crate::failover::restart::Check::Deposed, None, None)
    );
    assert_eq!(restarting.log, TO_REPORT);
    assert_eq!(stored(&store).1, taken(&shard_record(), c_host()));
}

#[test]
fn volume_contradictions_refuse_before_the_cas() {
    use crate::failover::records::{Modification, VolumeState};
    for trigger in [Trigger::VolumeState, Trigger::Events, Trigger::Modification] {
        let store = restart_tests::store(shard_record(), with_c());
        let mut w = client(&store);
        let read = w.read::<VolumeRecord>(Key::Volume(volume_id())).unwrap();
        let mut next = read.value().clone();
        match trigger {
            Trigger::VolumeState => next.state = VolumeState::Retired,
            Trigger::Events => {
                next.push(EventKind::Attach, b_host(), ERA);
            }
            Trigger::Modification => next.modification = Some(Modification::InProgress),
            _ => unreachable!(),
        }
        w.replace(&read, next.clone()).unwrap();
        let before = stored(&store);
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Volume(trigger), None)
        );
        assert!(card.log.is_empty());
        assert_eq!(stored(&store), before);
        assert_eq!(volume_now(&store), next);
    }
}

/// A takeover CAS that committed and then failed its log write or returned a regressed reply refuses with the own
/// tenure as the hint, and C's same-host restart then preempts A's recorded registration through its lineage arm,
/// keeping the volume.
#[test]
fn post_commit_log_and_reply_regressions_retain_the_volume_on_restart() {
    use crate::storage::store::sim::MemLog;
    use crate::storage::store::{Item, Store, Unavailable, Version};
    struct BadReply(Shared);
    impl Store for BadReply {
        fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
            self.0.read(key)
        }
        fn namespace(&self) -> crate::failover::records::Namespace {
            self.0.namespace()
        }
        fn write(&mut self, key: &Key, write: &Write) -> Outcome {
            match self.0.write(key, write) {
                Outcome::Committed(_) => Outcome::Committed(Version::FIRST),
                result => result,
            }
        }
    }
    for log_failure in [false, true] {
        let store = restart_tests::store(shard_record(), with_c());
        let path = takeover_of(&store, c_host());
        let reservation = a_holds_c_registered();
        let mut card = Card::new(c_pair(), &reservation);
        let error = if log_failure {
            let log = MemLog::default();
            let flag = log.fail.clone();
            let local = hooked(stored_c(), move || flag.set(true));
            let mut writer = Client::open(store.clone(), log).unwrap();
            path.run(&mut writer, &local, &mut card).unwrap_err()
        } else {
            let mut writer = Client::open(BadReply(store.clone()), MemLog::default()).unwrap();
            path.run(&mut writer, &stored_c(), &mut card).unwrap_err()
        };
        assert_eq!(error.recovery, Some(own_target()));
        assert!(card.log.is_empty());
        assert!(
            matches!(path.next(&error), Next::Restart(restart) if restart.holder == holder_of(c_host())),
            "{:?}",
            error.check
        );
        if log_failure {
            assert_eq!(error.check, Check::TakeOver(StoreError::Log));
        } else {
            assert!(
                matches!(error.check, Check::TakeOver(StoreError::Regression(_))),
                "{:?}",
                error.check
            );
        }
        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        let restarted = restart_tests::restart_of(shard(), holder_of(c_host()))
            .run(&mut client(&store), &stored_c(), &mut restarting)
            .unwrap();
        assert!(restarted.lineage());
        let taken = taken(&shard_record(), c_host());
        assert_eq!(
            shard_now(&store),
            ShardRecord {
                attempts: taken.attempts + 1,
                ..taken
            }
        );
        assert_eq!(volume_now(&store), with_c());
    }
}

/// A modification recorded during Report #1 or Report #2 refuses at the reread after it, with the own tenure as the
/// hint and no capability, and leaves the volume record as the modification wrote it.
#[test]
fn a_modification_during_either_report_refuses_at_its_reread() {
    use crate::failover::records::Modification;
    for second in [false, true] {
        let store = restart_tests::store(shard_record(), with_c());
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        let st = store.clone();
        let hook = Box::new(move || {
            let mut writer = client(&st);
            let read = writer
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            let next = VolumeRecord {
                modification: Some(Modification::InProgress),
                ..read.value().clone()
            };
            writer.replace(&read, next).unwrap();
        });
        if second {
            card.on_second = Some(hook);
        } else {
            card.on_report = Some(hook);
        }
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Volume(Trigger::Modification), Some(own_target())),
            "second: {second}"
        );
        let log = if second {
            FULL.to_vec()
        } else {
            TO_REPORT.to_vec()
        };
        assert_eq!(card.log, log, "second: {second}");
        assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
        assert_eq!(
            volume_now(&store).modification,
            Some(Modification::InProgress)
        );
    }
}

/// A record read that returns no value refuses `Records(Unavailable)` at each read after the CAS, with the own tenure
/// as the hint and no later device call: the volume reread after Report #1, the tenure check before the preempt, the
/// reread after Report #2 and the final tenure check.
#[test]
fn a_failed_read_at_each_step_refuses_and_names_the_own_tenure() {
    for (passes, issued) in [(3, 4), (4, 4), (5, 6), (6, 6)] {
        let store = restart_tests::store(shard_record(), with_c());
        let path = takeover_of(&store, c_host());
        for _ in 0..passes {
            store.schedule(Arm::Pass);
        }
        store.schedule(Arm::Unavailable);
        let reservation = a_holds_c_registered();
        let mut card = Card::new(c_pair(), &reservation);
        let refused = path
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (Check::Records(StoreError::Unavailable), Some(own_target())),
            "after {passes} requests"
        );
        assert_eq!(card.log, FULL[..issued], "after {passes} requests");
        assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
        let holder = if issued == FULL.len() {
            c_pair()
        } else {
            owner_pair()
        };
        assert!(
            reservation
                .borrow()
                .entries
                .iter()
                .any(|entry| entry.holder && entry.pair == holder),
            "after {passes} requests: the holder is the preempt's"
        );
    }
}

/// A duplicate invocation outside the restart-only rule, a safety check rather than a recovery path: an earlier
/// attempt's held CAS commits after a rerun read the record: the rerun's own CAS fails its condition with
/// no device call, while the record names C at `E + 1` from the earlier attempt, so neither attempt mints a session.
/// When the held CAS is released after the rerun's acknowledged CAS, the late write fails its condition and the
/// rerun's tenure stands.
#[test]
fn a_late_commit_of_an_earlier_takeover_cas_mints_no_session() {
    let store = restart_tests::store(shard_record(), with_c());
    let nominated = takeover_of(&store, c_host());
    for arm in [Arm::Pass, Arm::Pass, Arm::Hold] {
        store.schedule(arm);
    }
    let reservation = a_holds_c_registered();
    let mut card = Card::new(c_pair(), &reservation);
    let first = nominated
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (first.check, first.recovery),
        (Check::TakeOver(StoreError::Unknown), Some(own_target()))
    );
    assert!(card.log.is_empty());
    assert_eq!(shard_now(&store), shard_record());
    let releasing = store.clone();
    let local = hooked(stored_c(), move || {
        releasing.release();
    });
    let rerun = nominated
        .run(&mut client(&store), &local, &mut card)
        .unwrap_err();
    assert_eq!(
        (rerun.check, rerun.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(card.log.is_empty());
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));

    let store = restart_tests::store(shard_record(), with_c());
    for arm in [Arm::Pass, Arm::Pass, Arm::Hold] {
        store.schedule(arm);
    }
    let first = nominated
        .run(
            &mut client(&store),
            &stored_c(),
            &mut Card::new(c_pair(), &reservation),
        )
        .unwrap_err();
    assert_eq!(
        (first.check, first.recovery),
        (Check::TakeOver(StoreError::Unknown), Some(own_target()))
    );
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let taken_over = nominated
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
    assert_eq!(
        store.release(),
        vec![Outcome::NotCommitted(
            crate::storage::store::Refusal::Condition
        )],
        "the late write fails its condition"
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), commits);
    let expected = taken(&shard_record(), c_host());
    assert_eq!(shard_now(&store), expected);
    assert_eq!(taken_over.session().target(), Target::of(&expected));
}

/// A predecessor whose detach the volume record records after step 1, during Report #1: the CAS has committed, the
/// reread still records A's pair on its ended attach, and Report #1 admits A's holding pair, so the preempt names
/// A's key and C reaches its fencing boundary with A's pair still among the recorded pairs.
#[test]
fn a_predecessor_detached_after_step_1_is_preempted_at_report_1() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let st = store.clone();
    card.on_report = Some(Box::new(move || {
        let mut writer = client(&st);
        let read = writer
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let mut next = read.value().clone();
        next.push(EventKind::Detach, owner_host(), ERA);
        writer.replace(&read, next).unwrap();
    }));
    let taken_over = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    assert_eq!(taken_over.session().target(), own_target());
    assert_eq!(
        reservation.borrow().entries,
        vec![registrant(c_pair(), 2, true)],
        "the preempt removed A's registration"
    );
    let (_, fenced, (recorded, _), _, _, _) = taken_over.into_parts();
    assert_eq!(fenced.own(), c_pair());
    assert_eq!(recorded, volume_now(&store).recorded_pairs());
    assert!(volume_now(&store).live(owner_host()).is_none());
}

/// A predecessor whose attach is live, bound as a peer, and whose pair a fence raise dropped has no enrolled pair: no
/// Report can resolve it, so step 1 refuses `Predecessor` before the CAS, with no write, no device call and no
/// recovery hint.
#[test]
fn a_live_predecessor_with_no_enrolled_pair_refuses_before_the_cas() {
    let mut unenrolled = with_c();
    unenrolled.fence = (3 << 32) | 10;
    unenrolled.pairs.retain(|p| p.host != owner_host());
    let store = restart_tests::store(shard_record(), unenrolled.clone());
    let before = stored(&store);
    let peers = [crate::failover::attachments::Peer {
        host: owner_host(),
        instance: holder_of(owner_host()).instance,
    }];
    let mut path = takeover_of(&store, c_host());
    path.restart.peers = &peers;
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Predecessor, None)
    );
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), before);
    assert_eq!(volume_now(&store), unenrolled);
}

/// A predecessor whose attach the volume record ended still holds the reservation: its pair stays recorded, so step
/// 1 passes, Report #1 admits the holder, the preempt names A's key and C reaches its fencing boundary. Admitting only
/// the pairs of live attaches as holders refuses `Holder(NotAdmitted)` at Report #1 after the CAS, with no preempt.
#[test]
fn a_predecessor_recorded_for_an_ended_attach_is_preempted() {
    for kind in [EventKind::Detach, EventKind::Ended] {
        let mut ended = with_c();
        if kind == EventKind::Detach {
            ended.push(kind, owner_host(), ERA);
        } else {
            let at = ended.live(owner_host()).unwrap();
            ended
                .events
                .iter_mut()
                .find(|event| event.seq == at)
                .unwrap()
                .kind = kind;
        }
        let store = restart_tests::store(shard_record(), ended.clone());
        let reservation = a_holds_c_registered();
        let mut card = Card::new(c_pair(), &reservation);
        let taken_over = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap();
        assert_eq!(card.log, FULL, "{kind:?}");
        assert_eq!(
            shard_now(&store),
            taken(&shard_record(), c_host()),
            "{kind:?}"
        );
        assert_eq!(
            reservation.borrow().entries,
            vec![registrant(c_pair(), 2, true)],
            "{kind:?}: the preempt removed A's registration"
        );
        assert_eq!(taken_over.session().target(), own_target(), "{kind:?}");
        assert_eq!(volume_now(&store), ended, "{kind:?}");
    }
}

/// Control for the ended predecessor: a resolver that admits only the pairs of other hosts' live attaches refuses
/// the holder A's takeover must preempt.
#[test]
fn negative_control_live_only_holders_refuse_an_ended_predecessor() {
    let mut ended = with_c();
    let at = ended.live(owner_host()).unwrap();
    ended
        .events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap()
        .kind = EventKind::Ended;
    let reservation = a_holds_c_registered();
    let entries = reservation.borrow().entries.clone();
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: crate::failover::evidence::ReservationType::ExclusiveAccess,
        regctl: entries.len() as u32,
        entries: &entries,
    };
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let live_only = ended
        .pairs
        .iter()
        .filter(|held| held.host != c_host() && ended.live(held.host) == Some(held.attach))
        .map(|held| &held.pair);
    assert_eq!(
        LineagePreempt::resolve(&report, ended.recorded(), live_only, c_pair(), &bounds)
            .map(LineagePreempt::preempted),
        Err(HolderRefusal::NotAdmitted),
        "live-only admitted holders refuse the ended predecessor"
    );
    assert_eq!(
        LineagePreempt::resolve(
            &report,
            ended.recorded(),
            ended.recorded_beside(c_host()),
            c_pair(),
            &bounds
        )
        .map(LineagePreempt::preempted),
        Ok(ended.pinned(owner_host(), at).unwrap().key),
        "the recorded pairs of other hosts in any state admit A"
    );
}

/// C's detector boot nonce.
const OBSERVER_BOOT: [u8; 16] = [0xC5; 16];
/// The indirect probers, each in its own partition outside A's.
const PROBERS: [u64; 2] = [21, 22];
/// A second owner whose shard record also names C its standby.
const OTHER_OWNER: u64 = 31;

fn other_record() -> ShardRecord {
    ShardRecord {
        shard: crate::net::ownership::Shard::new(9).unwrap(),
        owner: Host::new(OTHER_OWNER).unwrap(),
        ..shard_record()
    }
}

/// C's detector over `records`, which suspects itself at `self_suspect` simultaneous suspects, with A, the other
/// owner, B, each prober and C in distinct placement partitions.
pub(crate) fn watch_of(records: &[ShardRecord], self_suspect: usize) -> Watch {
    watch_for(c_host(), records, self_suspect)
}

/// `observer`'s detector over `records`, as `watch_of` builds C's.
fn watch_for(observer: Host, records: &[ShardRecord], self_suspect: usize) -> Watch {
    let mut bounds = crate::failover::detect::tests::bounds();
    bounds.self_suspect = self_suspect;
    let mut watch = Watch::new(observer, OBSERVER_BOOT, bounds).unwrap();
    watch.sync(records, &placement(), 0).unwrap();
    watch
}

/// The placement partition of every host the detector fixtures name.
fn placement() -> Vec<(Host, Partition)> {
    [
        (owner_host().get(), 1),
        (OTHER_OWNER, 5),
        (b_host().get(), 6),
        (PROBERS[0], 2),
        (PROBERS[1], 3),
        (c_host().get(), 9),
        (d_host().get(), 10),
    ]
    .into_iter()
    .map(|(host, partition)| (Host::new(host).unwrap(), Partition(partition)))
    .collect()
}

/// Ticks C's detector every window after `from` through `until`, answering each open probe DEAD from both probers
/// before the tick, and returns the nominations the ticks published and the last repair demand. Every owner is silent
/// except the other owner while `other_beats_until` covers the window, which heartbeats once within it.
fn run_watch(
    watch: &mut Watch,
    from: u64,
    until: u64,
    other_beats_until: u64,
) -> (Vec<Nominated>, Option<RepairDemand>) {
    use crate::failover::detect::tests as detect;
    let h = detect::bounds().detect.h;
    let (mut published, mut demand) = (Vec::new(), None);
    for (sequence, t) in (from / h + 1..=until / h).map(|n| (n, n * h)) {
        if t <= other_beats_until {
            let beat = detect::sealed(
                &detect::header(OTHER_OWNER, 7, sequence),
                &[],
                c_host().get(),
            );
            watch.heartbeat(&beat, detect::key, t - h / 2).unwrap();
        }
        let requests: Vec<_> = watch.probes().collect();
        for request in requests {
            for prober in PROBERS {
                let reply = detect::reply(request, prober, detect::SILENT);
                watch.probe(reply, t - h).unwrap();
            }
        }
        demand = watch.tick(t, clock(t), true).unwrap();
        published.extend(watch.published().iter().copied());
    }
    (published, demand)
}

pub(crate) fn silent_owners(
    watch: &mut Watch,
    until: u64,
) -> (Vec<Nominated>, Option<RepairDemand>) {
    run_watch(watch, 0, until, 0)
}

/// The takeover an in-process caller starts: `watch` revalidates `nominated` at `now`, and the witness it mints
/// builds the takeover at that same time.
pub(crate) fn nominated_by<'a>(
    restart: Restart<'a>,
    watch: &Watch,
    nominated: &Nominated,
    now: u64,
    clock: Clock,
    healthy: bool,
) -> Option<Takeover<'a>> {
    let witness = watch.revalidate(nominated, now, clock, healthy)?;
    Takeover::nominated(restart, &witness, now)
}

/// C's same-host inputs: its holder of the shard's active volume and the fixture's bounds and limits.
fn standby_c() -> Restart<'static> {
    restart_tests::restart_of(shard(), holder_of(c_host()))
}

/// Host loss never invokes the flip: A goes silent, C's detector nominates A's `(g, owner, E)` once the probers
/// answer DEAD, the nomination starts one takeover, and its CAS commits C as owner at `E + 1` with the generation,
/// the active volume, the spare and the volume record unchanged, so the retained volume stays at its generation and
/// no write names the spare active. A rerun of the same nomination refuses `Restart` with no device call, and its
/// only next step is C's same-host restart. The same nomination starts nothing for an observer that reports itself
/// unhealthy or reads an untrusted clock.
#[test]
fn a_nominated_host_loss_takes_over_the_retained_volume_and_never_flips() {
    let store = restart_tests::store(shard_record(), with_c());
    let mut watch = watch_of(&[shard_record()], 3);
    let (published, demand) = silent_owners(&mut watch, 40);
    assert_eq!(demand, None);
    assert_eq!(published.len(), 1);
    let nominated = published[0];
    assert_eq!(
        (nominated.shard, nominated.nomination.target),
        (shard(), Target::of(&shard_record()))
    );
    for (observed, healthy) in [(clock(40), false), (Clock::Untrusted, true)] {
        assert!(
            nominated_by(standby_c(), &watch, &nominated, 40, observed, healthy).is_none(),
            "{observed:?} {healthy}"
        );
    }
    let path = nominated_by(standby_c(), &watch, &nominated, 40, clock(40), true).unwrap();
    assert_eq!(
        (path.restart.shard, path.target),
        (shard(), Target::of(&shard_record()))
    );
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    path.run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    let after = shard_now(&store);
    assert_eq!(after, taken(&shard_record(), c_host()));
    let before = shard_record();
    assert_eq!(
        (after.generation, after.active, after.spare),
        (before.generation, before.active, before.spare)
    );
    assert!(
        before.spare.is_some(),
        "the record names a spare the flip would activate"
    );
    assert_eq!(volume_now(&store), with_c());

    let settled = stored(&store);
    let mut card = Card::new(c_pair(), &reservation);
    let rerun = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((&rerun.check, rerun.recovery), (&Check::Restart, None));
    assert!(card.log.is_empty());
    assert!(matches!(
        path.next(&rerun),
        Next::Restart(restart) if restart.shard == shard() && restart.holder == holder_of(c_host())
    ));
    assert_eq!(stored(&store), settled);
}

/// DETECTION-CARRIES-NO-SAFETY: a witness for this standby's shard builds the takeover while `now < until_us`. The
/// same witness at `until_us` or later, and a witness for another shard, build nothing; the constructor takes no
/// store client, and `host::standby_tests` traces the requests of a standby that receives such a witness. A second nomination of the target the first takeover consumed refuses `Restart` at step 1 with no write and no
/// device call (NAMED-STANDBY).
#[test]
fn a_witness_starts_one_takeover_until_it_expires() {
    use crate::failover::detect::host::Revalidated;
    let store = restart_tests::store(shard_record(), with_c());
    let target = Target::of(&shard_record());
    let witness = Revalidated {
        shard: shard(),
        target,
        until_us: 50,
    };
    for now in [50, 51, u64::MAX] {
        assert!(
            Takeover::nominated(standby_c(), &witness, now).is_none(),
            "expired at {now}"
        );
    }
    let elsewhere = Revalidated {
        shard: other_record().shard,
        ..witness
    };
    assert!(Takeover::nominated(standby_c(), &elsewhere, 40).is_none());

    let reservation = a_holds_c_registered();
    let first = Takeover::nominated(standby_c(), &witness, 49).unwrap();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    first
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));

    let settled = stored(&store);
    let second = Takeover::nominated(standby_c(), &witness, 49).unwrap();
    let mut card = Card::new(c_pair(), &reservation);
    let recorder = crate::storage::store::sim::Recorder::new(&store);
    let mut traced = Client::open(
        recorder.clone(),
        crate::storage::store::sim::MemLog::default(),
    )
    .unwrap();
    let refused = second.run(&mut traced, &stored_c(), &mut card).unwrap_err();
    assert_eq!((&refused.check, refused.recovery), (&Check::Restart, None));
    assert!(card.log.is_empty());
    assert_eq!(
        recorder.take(),
        [
            Request::Read(Key::Shard(shard())),
            Request::Read(Key::Volume(volume_id()))
        ],
        "the second nomination issued its two step-1 reads, shard then volume, and attempted no write"
    );
    assert_eq!(stored(&store), settled);
}

/// A self-suspecting standby takes nothing over. The other owner heartbeats through 40 while A is silent, so C's
/// detector publishes A's nomination and that nomination starts the takeover. The other owner then goes silent; at a
/// self-suspicion threshold of two, its suspicion makes C suspect itself at 70, the detector reports the repair
/// demand, and the kept nomination starts nothing, so the store sees no write. At a threshold of three the same
/// evidence keeps the nomination startable at 70. When both owners go silent together, the detector suspects itself
/// before any nomination and publishes none.
#[test]
fn a_self_suspecting_standby_takes_nothing_over() {
    let records = [shard_record(), other_record()];
    for threshold in [2, 3] {
        let mut watch = watch_of(&records, threshold);
        let (published, _) = run_watch(&mut watch, 0, 40, 40);
        let nominated = *published
            .iter()
            .find(|n| n.shard == shard())
            .expect("A's nomination is published while the other owner beats");
        assert!(nominated_by(standby_c(), &watch, &nominated, 40, clock(40), true).is_some());
        let (_, demand) = run_watch(&mut watch, 40, 70, 40);
        let started = nominated_by(standby_c(), &watch, &nominated, 70, clock(70), true);
        if threshold == 2 {
            assert_eq!(demand.map(|d| d.suspects), Some(2));
            assert!(started.is_none());
        } else {
            assert_eq!(demand, None);
            assert!(started.is_some());
        }
    }

    let mut suspecting = watch_of(&records, 2);
    let (published, demand) = silent_owners(&mut suspecting, 40);
    assert!(published.is_empty());
    assert_eq!(demand.map(|d| d.suspects), Some(2));

    let mut both = watch_of(&records, 3);
    let (published, _) = silent_owners(&mut both, 40);
    let other = *published
        .iter()
        .find(|n| n.shard == other_record().shard)
        .expect("the other owner's nomination");
    assert!(both.revalidate(&other, 40, clock(40), true).is_some());
    assert!(
        nominated_by(standby_c(), &both, &other, 40, clock(40), true).is_none(),
        "a nomination of another shard than the standby's own starts nothing"
    );
}

/// No named standby: with A silent and the probers answering DEAD, C's detector publishes nothing for a record that
/// names no standby or names B, and the nomination C published while named starts nothing after a sync that drops the
/// designation. A takeover run against the record naming no standby refuses `Stale` with no write and no device
/// call, and its next step is `Stop`.
#[test]
fn a_record_naming_no_standby_or_another_starts_no_takeover() {
    for standby in [None, Some(b_host())] {
        let record = ShardRecord {
            standby,
            ..shard_record()
        };
        let mut watch = watch_of(&[record], 3);
        let (published, _) = silent_owners(&mut watch, 60);
        assert!(published.is_empty(), "{standby:?}");
    }
    let mut watch = watch_of(&[shard_record()], 3);
    let (published, _) = silent_owners(&mut watch, 40);
    let nominated = published[0];
    let unnamed = ShardRecord {
        standby: None,
        ..shard_record()
    };
    watch.sync(&[unnamed], &placement(), 40).unwrap();
    assert!(nominated_by(standby_c(), &watch, &nominated, 40, clock(40), true).is_none());

    let store = restart_tests::store(unnamed, with_c());
    let unwritten = stored(&store);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let path = takeover(Target::of(&unnamed), c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((&refused.check, refused.recovery), (&Check::Stale, None));
    assert!(matches!(path.next(&refused), Next::Stop));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), unwritten);
}

/// The takeover CAS's unknown outcome leaves C only its same-host restart: `next` returns that restart for every
/// unknown arm, and running it preempts A's recorded registration through its lineage arm and reaches FB when the
/// CAS committed, and refuses `Deposed` with no device call and no flip when it did not. A CAS that fails its condition after a designation moved stops
/// with no restart.
#[test]
fn an_unknown_takeover_cas_continues_only_by_the_restart_it_names() {
    for arm in UNKNOWN {
        let store = restart_tests::store(shard_record(), with_c());
        let reservation = a_holds_c_registered();
        let path = takeover_of(&store, c_host());
        for scheduled in [Arm::Pass, Arm::Pass, arm] {
            store.schedule(scheduled);
        }
        let mut card = Card::new(c_pair(), &reservation);
        let refused = path
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap_err();
        assert_eq!(
            &refused.check,
            &Check::TakeOver(StoreError::Unknown),
            "{arm:?}"
        );
        assert!(card.log.is_empty(), "{arm:?}");
        let Next::Restart(restart) = path.next(&refused) else {
            panic!("{arm:?}: an unknown CAS continues by the restart");
        };
        let mut restarting = restart_tests::Card::new();
        restarting.entries = reservation.borrow().entries.clone();
        let ran = restart.run(&mut client(&store), &stored_c(), &mut restarting);
        if committed(arm) {
            assert!(ran.unwrap().lineage(), "{arm:?}");
            assert_eq!(restarting.log, restart_tests::ARM, "{arm:?}");
        } else {
            let held = ran.unwrap_err();
            assert_eq!(
                (held.check, held.flip),
                (crate::failover::restart::Check::Deposed, None),
                "{arm:?}"
            );
            assert!(restarting.log.is_empty(), "{arm:?}");
        }
    }

    let store = restart_tests::store(shard_record(), with_c_and_b());
    let st = store.clone();
    let local = hooked(stored_c(), move || designate(&st, Some(b_host())));
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(
            &mut client(&store),
            &local,
            &mut Card::new(c_pair(), &a_holds_c_registered()),
        )
        .unwrap_err();
    assert_eq!(&refused.check, &Check::TakeOver(CONDITION));
    assert!(matches!(path.next(&refused), Next::Stop));
}

/// Fences coverage page 0 in the shard record's generation, the owner's fresh Report evidence that standby
/// admission requires.
pub(crate) fn fence_page_zero(store: &Shared) {
    fence_page_zero_of(store, shard(), shard_record().generation.get());
}

/// The fence on coverage page 0 of `shard` at generation `generation` supplies the owner's fresh Report evidence.
pub(crate) fn fence_page_zero_of(
    store: &Shared,
    shard: crate::net::ownership::Shard,
    generation: u64,
) {
    let mut fencer = client(store);
    let page = fencer
        .read::<crate::failover::records::CoveragePage>(Key::Page(shard, 0))
        .unwrap();
    let fenced = crate::failover::records::CoveragePage {
        fence: (generation << 32) | 2,
        ..page.value().clone()
    };
    fencer.replace(&page, fenced).unwrap();
}

/// The reconciler's fresh-host steps for D at the stored record's target: its census slot, a designation that
/// refuses `Conflict` with no write before D's attach is recorded and again before D's pair is enrolled, then the
/// designation. Returns D's local record.
pub(crate) fn designate_fresh_host(store: &Shared) -> LocalRecord {
    try_designate_fresh_host(store).expect("D's designation")
}

/// [`designate_fresh_host`], returning the reconciler's first refusal of D's attach record or designation.
pub(crate) fn try_designate_fresh_host(
    store: &Shared,
) -> Result<LocalRecord, crate::failover::reconcile::ReconcileError> {
    use crate::failover::reconcile::{ReconcileError, Reconciler, StandbyGate, enroll_standby};
    use crate::failover::standbys::{Population, Zone, tests::roomy};
    let gate = StandbyGate::qualified();
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let mut reconciler = Reconciler::new(client(store));
    let slot = reconciler
        .reserve(
            &gate,
            &Population { cap: 1 },
            &bounds,
            Zone(1),
            shard(),
            &roomy(d_host()),
            |h| h != d_host(),
        )
        .unwrap();
    assert_eq!(slot.target(), Target::of(&shard_now(store)));
    let mut d_record = None;
    // The fixture instances of the attached hosts, so the attach write binds each unbound live entry to the instance
    // its host's takeover or restart runs under (INSTANCE-BOUND).
    let peers = [owner_host(), b_host(), c_host()].map(|host| crate::failover::attachments::Peer {
        host,
        instance: instance_of(host),
    });
    for step in ["attach", "enroll"] {
        let unwritten = stored(store);
        assert_eq!(
            reconciler.designate(&gate, &slot, volume_id()),
            Err(ReconcileError::Conflict),
            "before the {step}"
        );
        assert_eq!(stored(store), unwritten, "before the {step}");
        if step == "attach" {
            reconciler.record_standby(
                &gate,
                shard(),
                volume_id(),
                d_host(),
                ERA,
                &bounds,
                &crate::failover::reconcile::Binding {
                    instance: holder_of(d_host()).instance,
                    unbound: &peers,
                    ..crate::failover::sim::binding(d_host())
                },
            )?;
        } else {
            let pair = enroll_standby(
                &gate,
                shard(),
                &holder_of(d_host()),
                &bounds,
                &mut client(store),
                |key| {
                    Ok(d_record
                        .insert(successor_record(d_host(), key.encode(), 0x5d))
                        .clone())
                },
            )
            .unwrap();
            assert_eq!(Some(pair), d_record.as_ref().map(LocalRecord::pair));
        }
    }
    reconciler.designate(&gate, &slot, volume_id())?;
    Ok(d_record.expect("D's enrollment"))
}

/// The fresh-host path after owner and standby loss: A and C are lost, so the shard needs a fresh host. The
/// reconciler attaches, enrolls and designates D in C's census slot; D's detector, which never heard from A,
/// nominates the silent A once the probers answer DEAD, and the nomination starts D's takeover, which commits at the
/// retained
/// generation and volume, registers D's pair and preempts A's key, so D holds the reservation and the shard serves
/// from the retained volume with no flip.
#[test]
fn a_fresh_host_takes_over_the_retained_volume_after_owner_and_standby_loss() {
    use crate::failover::standbys::{Need, need};
    let store = restart_tests::store(shard_record(), with_c());
    fence_page_zero(&store);
    let lost = |h: Host| h == owner_host() || h == c_host();
    assert_eq!(need(&shard_now(&store), lost), Some(Need::Fresh));
    let target = Target::of(&shard_record());
    let d_record = designate_fresh_host(&store);
    let designated = shard_now(&store);
    assert_eq!(designated.standby, Some(d_host()));

    let mut watch = watch_for(d_host(), &[designated], 3);
    let (published, _) = silent_owners(&mut watch, 40);
    let nominated = *published
        .first()
        .expect("D's detector nominates the silent A");
    let restart = restart_tests::restart_of(shard(), holder_of(d_host()));
    let path = nominated_by(restart, &watch, &nominated, 40, clock(40), true).unwrap();
    assert_eq!(path.target, target);
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, d_record.pair(), d_host(), &reservation);
    path.run(
        &mut client(&store),
        &Stored(Ok(d_record.clone())),
        &mut card,
    )
    .unwrap();
    assert_eq!(
        card.log,
        [
            "start", "ready", "host", "report", "register", "preempt", "report"
        ]
    );
    assert_eq!(shard_now(&store), taken(&designated, d_host()));
    assert_eq!(
        (shard_now(&store).generation, shard_now(&store).active),
        (shard_record().generation, volume_id())
    );
    assert_eq!(
        reservation.borrow().entries,
        vec![
            registrant(c_pair(), 2, false),
            registrant(d_record.pair(), 9, true)
        ]
    );
}

/// The step-7 tenure check alone stops a preempt of a later tenure: after C's CAS and before C's Report #1, B,
/// designated over C's tenure, takes over to its capability and preempts A, so C's Report #1 shows B holding under a
/// pair the volume record enrolls for B's live attach. C refuses `Superseded` at the shard read before its preempt,
/// with no preempt issued, and B stays the one holder.
#[test]
fn a_later_tenures_holder_at_report_1_stops_at_the_tenure_check() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(registrant(b_pair(), 3, false));
    let mut card_c = Card::new(c_pair(), &reservation);
    let (st, rs) = (store.clone(), reservation.clone());
    card_c.before_report = Some(Box::new(move || {
        designate(&st, Some(b_host()));
        let mut card_b = card_after_cas(&st, b_pair(), b_host(), &rs);
        takeover_of(&st, b_host())
            .run(&mut client(&st), &stored_b(), &mut card_b)
            .unwrap();
        assert_eq!(card_b.log, FULL);
    }));
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card_c)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Superseded, Some(own_target()))
    );
    assert_eq!(card_c.log, TO_REPORT);
    let holders: Vec<Pair> = reservation
        .borrow()
        .entries
        .iter()
        .filter(|e| e.holder)
        .map(|e| e.pair)
        .collect();
    assert_eq!(holders, [b_pair()]);
    assert_eq!(
        shard_now(&store),
        taken(&taken(&shard_record(), c_host()), b_host())
    );
}

/// A takeover CAS whose reply is lost after it committed, while A holds: C's same-host restart bumps C's tenure and
/// holds when its lineage preempt of A's recorded registration fails, and C stays live. The test supplies the unhealthy heartbeat that the caller of a host whose
/// restart holds sends, so the detector of D, designated over C's tenure, reads C's hold as declared; the two DEAD
/// votes read gray, which needs two observer classes, and the votes of two classes nominate C's tenure. D's takeover commits, preempts A, whose tenure C's committed write
/// superseded, and reaches its capability on the retained volume; the held state ends without a fresh volume.
#[test]
fn a_held_successor_after_an_unknown_cas_is_taken_over_by_the_next_standby() {
    use crate::failover::detect::tests as detect;
    let store = restart_tests::store(shard_record(), with_c());
    fence_page_zero(&store);
    let reservation = a_holds_c_registered();
    let path = takeover_of(&store, c_host());
    for scheduled in [Arm::Pass, Arm::Pass, Arm::Timeout { commit: true }] {
        store.schedule(scheduled);
    }
    let refused = path
        .run(
            &mut client(&store),
            &stored_c(),
            &mut Card::new(c_pair(), &reservation),
        )
        .unwrap_err();
    let Next::Restart(restart) = path.next(&refused) else {
        panic!("an unknown CAS continues by the restart");
    };
    let mut restarting = restart_tests::Card::new();
    restarting.entries = reservation.borrow().entries.clone();
    restarting.stop_at = Some(4);
    let held = restart
        .run(&mut client(&store), &stored_c(), &mut restarting)
        .unwrap_err();
    assert_eq!(
        (held.check, held.flip),
        (
            crate::failover::restart::Check::Lineage(crate::failover::restart::Lineage::Preempt(
                Failed(None)
            )),
            None
        )
    );
    assert_eq!(restarting.log, restart_tests::ARM[..5]);

    let d_record = designate_fresh_host(&store);
    let designated = shard_now(&store);
    assert_eq!(
        (designated.owner, designated.standby),
        (c_host(), Some(d_host()))
    );
    let mut watch = watch_for(d_host(), &[designated], 3);
    let h = detect::bounds().detect.h;
    let mut published = Vec::new();
    for (sequence, t) in (1..=6).map(|n| (n, n * h)) {
        let unhealthy = crate::failover::detect::beat::Header {
            healthy: false,
            ..detect::header(c_host().get(), 7, sequence)
        };
        let beat = detect::sealed(&unhealthy, &[], d_host().get());
        watch.heartbeat(&beat, detect::key, t - h / 2).unwrap();
        let requests: Vec<_> = watch.probes().collect();
        for request in requests {
            for prober in PROBERS {
                let gray = Reading::Dead(crate::failover::detect::Failure::Gray);
                watch
                    .probe(detect::reply(request, prober, gray), t - h)
                    .unwrap();
            }
        }
        watch.tick(t, clock(t), true).unwrap();
        published.extend(watch.published().iter().copied());
    }
    let nominated = *published.first().expect("D nominates the held C");
    assert_eq!(nominated.nomination.target, Target::of(&designated));
    let now = 6 * h;
    let restart = restart_tests::restart_of(shard(), holder_of(d_host()));
    let path = nominated_by(restart, &watch, &nominated, now, clock(now), true).unwrap();
    let mut card = card_after_cas(&store, d_record.pair(), d_host(), &reservation);
    let recovered = path
        .run(
            &mut client(&store),
            &Stored(Ok(d_record.clone())),
            &mut card,
        )
        .unwrap();
    assert_eq!(
        card.log,
        [
            "start", "ready", "host", "report", "register", "preempt", "report"
        ]
    );
    assert_eq!(
        recovered.session().target(),
        Target::of(&taken(&designated, d_host()))
    );
    let manifest = |r: &ShardRecord| (r.generation, r.active, r.checkpoint, r.cut, r.ancestry);
    assert_eq!(manifest(&shard_now(&store)), manifest(&shard_record()));
}

/// A chain may revisit an attached host, so its depth is not bounded by the attached hosts: with A holding, C takes
/// over and stops at Report #1, B, designated over C's tenure, takes over and stops at Report #1, and C, designated
/// again over B's tenure, takes over a second time. C's Report #1 shows A holding, three takeovers back on three
/// attached hosts, and C preempts A's key and reaches its capability at the retained generation, checkpoint, cut and
/// ancestry.
#[test]
fn a_chain_that_revisits_an_attached_host_preempts_the_holder_three_takeovers_back() {
    let store = restart_tests::store(shard_record(), with_c_and_b());
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(registrant(b_pair(), 3, false));
    for (host, local) in [(c_host(), stored_c()), (b_host(), stored_b())] {
        let own = if host == c_host() { c_pair() } else { b_pair() };
        if host == b_host() {
            designate(&store, Some(b_host()));
        }
        let mut card = Card::new(own, &reservation);
        card.stop_at = Some(3);
        let refused = takeover_of(&store, host)
            .run(&mut client(&store), &local, &mut card)
            .unwrap_err();
        assert_eq!(refused.check, Check::FirstReport(Failed(None)), "{host:?}");
        assert_eq!(card.log, TO_REPORT, "{host:?}");
    }
    let after_b = taken(&taken(&shard_record(), c_host()), b_host());
    assert_eq!(shard_now(&store), after_b);
    designate(&store, Some(c_host()));
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let recovered = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    let designated = ShardRecord {
        standby: Some(c_host()),
        ..after_b
    };
    let after_c = taken(&designated, c_host());
    assert_eq!(shard_now(&store), after_c);
    assert_eq!(recovered.session().target(), Target::of(&after_c));
    let holders: Vec<Pair> = reservation
        .borrow()
        .entries
        .iter()
        .filter(|e| e.holder)
        .map(|e| e.pair)
        .collect();
    assert_eq!(holders, [c_pair()]);
    let manifest = |r: &ShardRecord| (r.generation, r.active, r.checkpoint, r.cut, r.ancestry);
    assert_eq!(manifest(&after_c), manifest(&shard_record()));
}

/// The takeover fences every coverage page under its new session before the capability returns, and carries the
/// warm source the committed record names; a record whose page cap holds no page refuses `Coverage` after the CAS and
/// every device step, with the own tenure as the recovery hint and no further command. A record naming certified
/// suffixes and no checkpoint refuses `SuffixOnly` before the CAS and any device command.
#[test]
fn a_takeover_fences_the_coverage_pages_before_its_capability_and_a_fencing_refusal_names_the_own_tenure()
 {
    let store = restart_tests::store(shard_record(), with_c());
    let taken = takeover_of(&store, c_host())
        .run(
            &mut client(&store),
            &stored_c(),
            &mut Card::new(c_pair(), &a_holds_c_registered()),
        )
        .unwrap();
    assert!(taken.fencing().coverage().is_some(), "every page is fenced");
    assert_eq!(taken.fencing().session(), taken.session().get());
    for page in 0..shard_now(&store).pages.get() {
        let read = client(&store)
            .read::<crate::failover::records::CoveragePage>(crate::storage::store::Key::Page(
                shard(),
                page,
            ))
            .unwrap();
        assert_eq!(read.value().fence, taken.session().get(), "page {page}");
    }
    let source = taken.warm().expect("the record names a checkpoint");
    assert_eq!(*source.layout(), with_c().layout);
    let narrow = ShardRecord {
        page_cap: std::num::NonZeroU32::MIN,
        ..shard_record()
    };
    let store = restart_tests::store(narrow, with_c());
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (
            Check::Coverage(crate::storage::page_coverage::FenceRefused::Fencing(
                crate::storage::page_coverage::FencingRefusal::PageCap
            )),
            Some(own_target())
        )
    );
    assert_eq!(card.log, FULL, "every device step ran before the fencing");
    // Certified suffixes with no checkpoint hold the retained set, so the takeover refuses before its CAS.
    let suffix_only = ShardRecord {
        checkpoint: None,
        cut: 0,
        ..shard_record()
    };
    let store = restart_tests::store(suffix_only, with_c());
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::SuffixOnly, None));
    assert!(card.log.is_empty(), "no device command: {:?}", card.log);
    assert_eq!(shard_now(&store), suffix_only, "the record is unchanged");
}

/// C's live entry in `volume` set to `kind`.
fn c_entry_as(volume: &mut VolumeRecord, kind: EventKind) {
    let at = volume.live(c_host()).unwrap();
    volume
        .events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap()
        .kind = kind;
}

/// ENDED-GRANTS-NOTHING at the takeover: a named standby whose entry the record ended before step 1 refuses
/// `Local(Ended)` before the CAS with no device command and no recovery hint; one ended between the CAS and Report #1
/// commits the CAS, and the reread after Report #1 refuses `Local(Ended)` with no preempt, so the next step is C's
/// same-host restart.
#[test]
fn an_ended_standby_takes_nothing_over() {
    let mut ended = with_c();
    c_entry_as(&mut ended, EventKind::Ended);
    let store = restart_tests::store(shard_record(), ended.clone());
    let before = stored(&store);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Local(Local::Ended), None)
    );
    assert!(matches!(path.next(&refused), Next::Stop));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), before);

    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let st = store.clone();
    card.on_report = Some(Box::new(move || {
        let mut writer = client(&st);
        let read = writer
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let mut next = read.value().clone();
        c_entry_as(&mut next, EventKind::Ended);
        writer.replace(&read, next).unwrap();
    }));
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Local(Local::Ended), Some(own_target()))
    );
    assert_eq!(card.log, TO_REPORT, "no preempt");
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
    assert!(matches!(path.next(&refused), Next::Restart(_)));
    assert_eq!(
        reservation.borrow().entries[0],
        registrant(owner_pair(), 1, true),
        "A still holds"
    );
}

/// A holder under a dropped pair's key, the key of B's ended entry whose pair left the record, refuses Report #1
/// `Holder(Unrecorded)` after the CAS, with no preempt.
#[test]
fn a_holder_under_a_dropped_pairs_key_is_not_preempted() {
    let mut volume = with_c_and_b();
    let b_attach = volume.live(b_host()).unwrap();
    volume
        .events
        .iter_mut()
        .find(|event| event.seq == b_attach)
        .unwrap()
        .kind = EventKind::Ended;
    volume.pairs.retain(|recorded| recorded.host != b_host());
    volume.fence = shard_record().generation.get() << 32 | 8;
    let store = restart_tests::store(shard_record(), volume);
    let dropped = Pair {
        key: crate::failover::records::attachment_key(b_attach).unwrap(),
        ..b_pair()
    };
    let reservation = Rc::new(RefCell::new(Reservation {
        entries: vec![
            registrant(owner_pair(), 1, false),
            registrant(c_pair(), 2, false),
            registrant(dropped, 3, true),
        ],
        rtype: 2,
        ..Reservation::default()
    }));
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::Holder(HolderRefusal::Unrecorded), Some(own_target()))
    );
    assert_eq!(card.log, TO_REPORT);
}

/// SUPERSEDED-TENURE-PREEMPT names another host's key. C's earlier entry ended with its pair still recorded, and C
/// holds a later live attach with its own pair enrolled. When the earlier pair holds at Report #1, C's takeover
/// refuses `Holder(NotAdmitted)` after the CAS with no preempt: the admitted holders are the pairs recorded for
/// other hosts. The same Report with A's pair holding resolves A's key.
#[test]
fn a_holder_recorded_for_the_own_hosts_earlier_entry_is_not_preempted() {
    let mut volume = with_c();
    c_entry_as(&mut volume, EventKind::Ended);
    let earlier = Pair {
        exhid: Exhid::new([0x4c; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((3 << 32) | 5).unwrap(),
    };
    volume
        .pairs
        .iter_mut()
        .find(|recorded| recorded.host == c_host())
        .unwrap()
        .pair = earlier;
    let new = volume.push(EventKind::Attach, c_host(), ERA).unwrap();
    volume.pairs.push(RecordedPair {
        host: c_host(),
        pair: c_pair(),
        attach: new,
    });
    assert_eq!(VolumeRecord::decode(&volume.encode()), Ok(volume.clone()));
    for (holder, expected) in [
        (earlier, Some(Check::Holder(HolderRefusal::NotAdmitted))),
        (owner_pair(), None),
    ] {
        let store = restart_tests::store(shard_record(), volume.clone());
        let reservation = Rc::new(RefCell::new(Reservation {
            entries: [owner_pair(), c_pair(), earlier]
                .iter()
                .zip(1..)
                .map(|(&pair, cntlid)| registrant(pair, cntlid, pair == holder))
                .collect(),
            rtype: 2,
            ..Reservation::default()
        }));
        let before = reservation.borrow().entries.clone();
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        let ran = takeover_of(&store, c_host()).run(&mut client(&store), &stored_c(), &mut card);
        match expected {
            Some(check) => {
                let refused = ran.expect_err("the own host's earlier pair is no admitted holder");
                assert_eq!(
                    (refused.check, refused.recovery),
                    (check, Some(own_target()))
                );
                assert_eq!(card.log, TO_REPORT);
                assert_eq!(reservation.borrow().entries, before);
            }
            None => {
                ran.unwrap();
                assert_eq!(card.log, FULL);
            }
        }
    }
}

/// The reservation after a Preempt-and-Abort naming `key` lands: every registration under `key` leaves, and when
/// that key held, `issuer`'s registration takes the reservation.
fn stale_preempt_lands(
    entries: &[Registrant],
    issuer: Pair,
    key: crate::failover::identity::Key,
) -> Vec<Registrant> {
    let transfers = entries
        .iter()
        .any(|entry| entry.holder && entry.pair.key == key);
    entries
        .iter()
        .filter(|entry| entry.pair.key != key)
        .map(|entry| Registrant {
            holder: if transfers {
                entry.pair == issuer
            } else {
                entry.holder
            },
            ..*entry
        })
        .collect()
}

/// H's reattach after its earlier attach ended, its pair dropped and its entry went: the volume record with H's new
/// live attach enrolled under `key`, and the reservation H holds under that key beside the paused successor X.
fn reattached_holder(key: crate::failover::identity::Key) -> (VolumeRecord, Pair, Pair) {
    let mut volume = with_c();
    let old = volume.live(c_host()).unwrap();
    c_entry_as(&mut volume, EventKind::Gone);
    volume.pairs.retain(|recorded| recorded.host != c_host());
    volume.fence = shard_record().generation.get() << 32 | 8;
    let new = volume.push(EventKind::Attach, c_host(), ERA).unwrap();
    let h = Pair { key, ..c_pair() };
    volume.pairs.push(RecordedPair {
        host: c_host(),
        pair: h,
        attach: new,
    });
    let x = Pair {
        exhid: Exhid::new([0x5d; 16]).unwrap(),
        key: crate::failover::records::attachment_key(old + 7).unwrap(),
    };
    (volume, h, x)
}

/// KEY-PER-ATTACH, the stale-preempt half: a paused successor X captured the key of H's attach at its Report #1; that
/// attach then ended, its pair dropped, its entry went, and H attached again under a new entry that took tenure. X's
/// stale preempt naming the captured key lands and removes nothing, so H's pair still holds and H's Report passes
/// among the recorded pairs. The new attach enrolls only under its own key, so the old key refuses `Key`.
#[test]
fn a_stale_preempt_spares_a_reattached_holder() {
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let captured =
        crate::failover::records::attachment_key(with_c().live(c_host()).unwrap()).unwrap();
    let (volume, _, _) = reattached_holder(captured);
    let new_key = volume.attach_key(c_host()).unwrap();
    assert_ne!(new_key, captured);
    let (volume, h, x) = reattached_holder(new_key);
    let mut unenrolled = volume.clone();
    unenrolled.pairs.pop();
    assert_eq!(
        unenrolled.enroll(c_host(), Pair { key: captured, ..h }, &bounds),
        Err(crate::failover::records::Enrollment::Key)
    );
    let entries = [registrant(h, 1, true), registrant(x, 2, false)];
    let landed = stale_preempt_lands(&entries, x, captured);
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: crate::failover::evidence::ReservationType::ExclusiveAccess,
        regctl: landed.len() as u32,
        entries: &landed,
    };
    let mut recorded = volume.recorded_pairs();
    recorded.push(x);
    assert_eq!(report.registrants(h, Some(&recorded), &bounds), Ok(()));
}

/// Control for KEY-PER-ATTACH: H's new attach enrolled under the key of its earlier attach lets X's stale preempt
/// remove H's registration and move the reservation to X, so H's Report refuses, and the assertion that H's
/// Report passes after the stale preempt fails.
#[test]
#[should_panic(expected = "the reattached holder's Report passes after the stale preempt")]
fn negative_control_a_reattach_under_the_old_key_is_deposed_by_the_stale_preempt() {
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let captured =
        crate::failover::records::attachment_key(with_c().live(c_host()).unwrap()).unwrap();
    let (volume, h, x) = reattached_holder(captured);
    let entries = [registrant(h, 1, true), registrant(x, 2, false)];
    let landed = stale_preempt_lands(&entries, x, captured);
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: crate::failover::evidence::ReservationType::ExclusiveAccess,
        regctl: landed.len() as u32,
        entries: &landed,
    };
    let mut recorded = volume.recorded_pairs();
    recorded.push(x);
    assert_eq!(
        report.registrants(h, Some(&recorded), &bounds),
        Ok(()),
        "the reattached holder's Report passes after the stale preempt"
    );
}

/// ENDED-NEVER-RETIRES at the takeover: a late Register under B's dropped ended key beside A's holding, listed at
/// Report #1 or first at Report #2, is admitted as a non-holding registrant. The preempt names A's key alone, the
/// takeover reaches its capability, and the tenure starts with the late pair after the recorded pairs.
#[test]
fn a_late_register_under_an_ended_key_is_admitted_at_both_takeover_reports() {
    for at_first in [true, false] {
        let mut volume = with_c_and_b();
        let b_attach = volume.live(b_host()).unwrap();
        volume
            .events
            .iter_mut()
            .find(|event| event.seq == b_attach)
            .unwrap()
            .kind = EventKind::Ended;
        volume.pairs.retain(|recorded| recorded.host != b_host());
        volume.fence = shard_record().generation.get() << 32 | 8;
        let store = restart_tests::store(shard_record(), volume.clone());
        let late = Pair {
            key: crate::failover::records::attachment_key(b_attach).unwrap(),
            ..b_pair()
        };
        assert_eq!(
            volume.registrant(&late),
            crate::failover::records::Registration::Ended
        );
        let reservation = a_holds_c_registered();
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        if at_first {
            reservation
                .borrow_mut()
                .entries
                .push(registrant(late, 3, false));
        } else {
            let shared = Rc::clone(&reservation);
            card.on_report = Some(Box::new(move || {
                shared.borrow_mut().entries.push(registrant(late, 3, false));
            }));
        }
        let taken_over = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap();
        assert_eq!(card.log, FULL, "at Report #1 {at_first}");
        let (_, fenced, (recorded, ended), _, _, _) = taken_over.into_parts();
        assert_eq!(ended, 1, "at Report #1 {at_first}");
        assert_eq!(fenced.own(), c_pair());
        let mut expected = volume.recorded_pairs();
        expected.push(late);
        assert_eq!(recorded, expected, "at Report #1 {at_first}");
        assert!(
            reservation
                .borrow()
                .entries
                .iter()
                .all(|entry| entry.pair != owner_pair()),
            "the preempt named A's key"
        );
        assert!(
            reservation
                .borrow()
                .entries
                .iter()
                .any(|entry| entry.pair == late && !entry.holder),
            "the late Register survives the preempt"
        );
    }
}

/// The volume record and the reservation of a Report #1 with `ended + 1` registrants that lists no record of C's
/// pair: A holds, beside `ended` non-holding registrants under the keys of ended attaches, each an `Ended` entry of
/// a host of its own that binds that host's instance, as the attach write leaves a record: one instance on at most
/// one attach or ended entry.
fn a_holds_beside_ended_registrants(ended: u8) -> (VolumeRecord, Rc<RefCell<Reservation>>) {
    let mut volume = with_c();
    let reservation = holds_registered(owner_pair(), &[]);
    for at in 0..ended {
        let seq = volume.next;
        volume.next += 1;
        let host = successor_host(7 + u64::from(at));
        volume
            .events
            .push(crate::failover::records::AttachmentEvent {
                seq,
                kind: EventKind::Ended,
                host,
                era: ERA,
                instance: Some(crate::failover::sim::instance_of_host(host)),
            });
        reservation.borrow_mut().entries.push(registrant(
            Pair {
                exhid: Exhid::new([0x70 + at; 16]).unwrap(),
                key: crate::failover::records::attachment_key(seq).unwrap(),
            },
            3 + u16::from(at),
            false,
        ));
    }
    (volume, reservation)
}

/// The takeover's Register at a full table. REGISTER-ROOM is the restart's lineage arm's check alone: at a Report #1
/// of `N_reg` registrants that lists no record of C's pair, C's takeover registers, which leaves `N_reg + 1` until its
/// preempt removes A's registration. With no fault the takeover reaches its capability and Report #2 reads `N_reg`.
/// With the preempt failed the table stays at `N_reg + 1`, and C's same-host restart refuses Report #1 as
/// `NotHolding(Excess)` with the flip request, which parks the process and which no automatic step serves. This test
/// pins that limit of the registrant bound: a change of the bound's rule changes these expectations.
#[test]
fn a_takeover_registers_into_a_full_table_and_a_failed_preempt_leaves_its_restart_the_excess_refusal()
 {
    let n_reg = usize::try_from(restart_tests::restart().bounds.registrant_max()).unwrap();
    let ended = u8::try_from(n_reg).unwrap() - 1;
    let registering = [
        "start", "ready", "host", "report", "register", "preempt", "report",
    ];

    let (volume, reservation) = a_holds_beside_ended_registrants(ended);
    assert_eq!(reservation.borrow().entries.len(), n_reg);
    let store = restart_tests::store(shard_record(), volume);
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let taken_over = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, registering, "the takeover registers and preempts");
    assert_eq!(taken_over.into_parts().1.own(), c_pair());
    assert_eq!(
        reservation.borrow().entries.len(),
        n_reg,
        "the preempt removed A's registration, so Report #2 read `N_reg`"
    );
    assert!(
        reservation
            .borrow()
            .entries
            .iter()
            .all(|entry| entry.holder == (entry.pair == c_pair())),
        "C alone holds"
    );

    let (volume, reservation) = a_holds_beside_ended_registrants(ended);
    let store = restart_tests::store(shard_record(), volume);
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    card.fault = Some(Fault::Preempt);
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Preempt(Failed(Some(CONFLICT))), Some(own_target()))
    );
    assert_eq!(
        card.log,
        registering[..6],
        "the Register precedes the failed preempt"
    );
    assert_eq!(
        reservation.borrow().entries.len(),
        n_reg + 1,
        "the Register stands beside A's holding"
    );
    assert!(matches!(path.next(&refused), Next::Restart(_)));
    let mut restarting = restart_tests::Card::new();
    restarting.entries = reservation.borrow().entries.clone();
    let rerun = restart_tests::restart_of(shard(), holder_of(c_host()))
        .run(&mut client(&store), &stored_c(), &mut restarting)
        .unwrap_err();
    assert_eq!(
        rerun.check,
        crate::failover::restart::Check::NotHolding(NotSole::Excess)
    );
    assert_eq!(
        rerun.flip,
        Some(own_target()),
        "the flip request names C's tenure"
    );
    assert_eq!(restarting.log, TO_REPORT, "no command after Report #1");
    assert_eq!(
        shard_now(&store),
        taken(&shard_record(), c_host()),
        "the restart bumped nothing"
    );
}

/// HOST-LOSS-KEEPS-VOLUME at a table a stopped successor left at `N_reg + 1`: C registered into a full table and its
/// preempt failed, C's host is lost, and the reconciler attaches, enrolls and designates the fresh host D over C's
/// tenure. D's CAS commits and its Report #1 counts `N_reg + 1` registrants, above the reservation limits, so D's
/// takeover refuses `Unparsed(Excess)` with Report #1 as its last device command and names D's same-host restart.
/// That restart refuses Report #1 as `NotHolding(Excess)` with the flip request and leaves the shard record at D's
/// takeover write, so the fresh host parks as C's restart does and A keeps the reservation on the retained volume.
#[test]
fn a_fresh_host_designated_over_a_table_above_the_bound_refuses_the_excess_before_its_preempt() {
    let n_reg = usize::try_from(restart_tests::restart().bounds.registrant_max()).unwrap();
    let (volume, reservation) = a_holds_beside_ended_registrants(u8::try_from(n_reg).unwrap() - 1);
    let store = restart_tests::store(shard_record(), volume);
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    card.fault = Some(Fault::Preempt);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(refused.check, Check::Preempt(Failed(Some(CONFLICT))));
    let left = reservation.borrow().entries.clone();
    assert_eq!(
        left.len(),
        n_reg + 1,
        "C's Register stands beside A's holding"
    );

    fence_page_zero(&store);
    let d_record = designate_fresh_host(&store);
    let designated = shard_now(&store);
    assert_eq!(
        (designated.owner, designated.standby),
        (c_host(), Some(d_host()))
    );
    let d_target = Target::of(&taken(&designated, d_host()));
    let mut card_d = card_after_cas(&store, d_record.pair(), d_host(), &reservation);
    let path = takeover_of(&store, d_host());
    let refused = path
        .run(
            &mut client(&store),
            &Stored(Ok(d_record.clone())),
            &mut card_d,
        )
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Unparsed(NotSole::Excess), Some(d_target)),
        "D's CAS committed and its Report #1 is over the bound"
    );
    assert_eq!(card_d.log, TO_REPORT, "Report #1 is the last command");
    assert_eq!(reservation.borrow().entries, left, "A still holds");
    assert!(matches!(path.next(&refused), Next::Restart(_)));

    let mut restarting = restart_tests::Card::new();
    restarting.entries = left;
    let rerun = restart_tests::restart_of(shard(), holder_of(d_host()))
        .run(&mut client(&store), &Stored(Ok(d_record)), &mut restarting)
        .unwrap_err();
    assert_eq!(
        rerun.check,
        crate::failover::restart::Check::NotHolding(NotSole::Excess)
    );
    assert_eq!(
        rerun.flip,
        Some(d_target),
        "the flip request names D's tenure"
    );
    assert_eq!(restarting.log, TO_REPORT, "Report #1 is the last command");
    assert_eq!(
        shard_now(&store),
        taken(&designated, d_host()),
        "the record stays at D's takeover write"
    );
}

/// ENDED-GRANTS-NOTHING at the takeover's Report #2 reread: an end of C's entry committed after Report #2 refuses
/// `Local(Ended)` after the preempt, with no capability, and the next step is C's same-host restart.
#[test]
fn an_end_seen_at_the_second_takeover_reread_refuses_with_no_capability() {
    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let st = store.clone();
    card.on_second = Some(Box::new(move || {
        let mut writer = client(&st);
        let read = writer
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let mut next = read.value().clone();
        c_entry_as(&mut next, EventKind::Ended);
        writer.replace(&read, next).unwrap();
    }));
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Local(Local::Ended), Some(own_target()))
    );
    assert_eq!(card.log, FULL, "no command after Report #2");
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
    assert!(matches!(path.next(&refused), Next::Restart(_)));
}

/// Where [`Interleaved`] runs its race inside the takeover's step-1 reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// After the first step-1 read returned, before the second is issued.
    AfterFirstRead,
    /// Before the shard read is issued.
    BeforeShardRead,
}

/// A store over [`Shared`] that runs its race once at `cut` of the takeover's own reads; the racing actors write
/// through their own clients on the shared store.
struct Interleaved {
    inner: Shared,
    cut: Cut,
    reads: usize,
    race: Option<Box<dyn FnOnce()>>,
}

impl Interleaved {
    fn over(store: &Shared, cut: Cut, race: impl FnOnce() + 'static) -> Self {
        Self {
            inner: store.clone(),
            cut,
            reads: 0,
            race: Some(Box::new(race)),
        }
    }

    fn run(&mut self, at: Cut) {
        if self.cut == at
            && let Some(race) = self.race.take()
        {
            race();
        }
    }
}

impl Store for Interleaved {
    fn read(
        &mut self,
        key: &Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        if matches!(key, Key::Shard(_)) {
            self.run(Cut::BeforeShardRead);
        }
        let read = self.inner.read(key);
        self.reads += 1;
        if self.reads == 1 {
            self.run(Cut::AfterFirstRead);
        }
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// The race of the takeover's step-1 reads: the reconciler ends C's attach, the owner's reclaim drops C's ended pair
/// (a raw exact-version write, as the owner's View whose shard read named no standby makes it), and a designation of
/// C whose own volume read preceded the end writes the shard record.
fn end_drop_designate(store: &Shared) {
    let mut writer = client(store);
    let read = writer
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    let mut ended = read.value().clone();
    c_entry_as(&mut ended, EventKind::Ended);
    let read = writer.replace(&read, ended).unwrap();
    let mut dropped = read.value().clone();
    dropped.pairs.retain(|recorded| recorded.host != c_host());
    writer.replace(&read, dropped).unwrap();
    designate(store, Some(c_host()));
}

/// The store before the race: A owns at `E = 4` with page 0 fenced, the record names no standby, and A and C are
/// attached and enrolled.
fn unnamed_store() -> Shared {
    let store = restart_tests::store(
        ShardRecord {
            standby: None,
            ..shard_record()
        },
        with_c(),
    );
    fence_page_zero(&store);
    store
}

/// HOST-LOSS-KEEPS-VOLUME, the read order of step 1: the end of C's attach, the drop of its pair and a designation
/// of C race C's step-1 reads. Step 1 reads the shard record first, so a shard read before the designation refuses
/// `Stale`, and one that sees the designation is followed by a volume read that shows C's entry ended and refuses
/// `Local(Ended)`; neither writes the shard record or issues a device command, and a fresh host D is then reserved,
/// attached, enrolled and designated.
#[test]
fn a_takeover_whose_step_1_follows_a_designation_after_the_end_refuses_before_the_cas() {
    for (cut, check) in [
        (Cut::AfterFirstRead, Check::Stale),
        (Cut::BeforeShardRead, Check::Local(Local::Ended)),
    ] {
        let store = unnamed_store();
        let path = takeover(Target::of(&shard_record()), c_host());
        let st = store.clone();
        let mut racing = Client::open(
            Interleaved::over(&store, cut, move || end_drop_designate(&st)),
            crate::storage::store::sim::MemLog::default(),
        )
        .unwrap();
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        let refused = path.run(&mut racing, &stored_c(), &mut card).unwrap_err();
        assert_eq!((refused.check, refused.recovery), (check, None), "{cut:?}");
        assert!(card.log.is_empty(), "{cut:?}: {:?}", card.log);
        let designated = shard_now(&store);
        assert_eq!(designated, shard_record(), "{cut:?}: no CAS");
        assert!(!volume_now(&store).records_pair_of(c_host()), "{cut:?}");
        designate_fresh_host(&store);
        assert_eq!(shard_now(&store).standby, Some(d_host()), "{cut:?}");
    }
}

/// Control for the read order: step 1 reading the volume record first, with the same checks and the same CAS, and
/// nothing else changed. On either cut the race lands between the volume read, which shows C's pair recorded and its
/// entry live, and the shard read, which sees the designation; the CAS commits, C owns the shard with no pair
/// recorded, and a fresh host's attach record refuses `Conflict` with no write, so no designation can follow.
#[test]
fn negative_control_a_volume_first_step_1_strands_the_shard() {
    use crate::failover::reconcile::{ReconcileError, Reconciler, StandbyGate};
    use crate::failover::standbys::{Population, Zone, tests::roomy};
    for cut in [Cut::AfterFirstRead, Cut::BeforeShardRead] {
        let store = unnamed_store();
        let path = takeover(Target::of(&shard_record()), c_host());
        let st = store.clone();
        let mut racing = Client::open(
            Interleaved::over(&store, cut, move || end_drop_designate(&st)),
            crate::storage::store::sim::MemLog::default(),
        )
        .unwrap();
        let volume = racing
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let tenure = racing.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let (tenure, _) = path.step_one(tenure, volume).unwrap();
        racing.take_over(&tenure, path.target, c_host()).unwrap();
        assert_eq!(
            shard_now(&store),
            taken(&shard_record(), c_host()),
            "{cut:?}"
        );
        assert!(
            !volume_now(&store).records_pair_of(c_host()),
            "a takeover commits over a dropped pair and strands the shard: {cut:?}"
        );
        let gate = StandbyGate::qualified();
        let bounds = crate::storage::gate_fixture::bounds_of(limits());
        let before = stored(&store);
        let mut reconciler = Reconciler::new(client(&store));
        let slot = reconciler
            .reserve(
                &gate,
                &Population { cap: 1 },
                &bounds,
                Zone(1),
                shard(),
                &roomy(d_host()),
                |h| h != d_host(),
            )
            .unwrap();
        assert_eq!(
            reconciler.record_standby(
                &gate,
                shard(),
                volume_id(),
                d_host(),
                ERA,
                &bounds,
                &crate::failover::sim::binding(d_host()),
            ),
            Err(ReconcileError::Conflict),
            "{cut:?}"
        );
        assert_eq!(
            reconciler.designate(&gate, &slot, volume_id()),
            Err(ReconcileError::Conflict),
            "{cut:?}"
        );
        assert_eq!(stored(&store), before, "{cut:?}");
    }
}

/// INSTANCE-BOUND at the takeover: C's live entry bound to another instance than C's refuses `Local(Binding)` at step
/// 2, before the CAS, with no device command and no recovery hint, and the next step is none; bound to C's own
/// instance the takeover reaches its capability; an unbound entry that a write binds to another instance after the
/// CAS refuses at the reread after Report #1 with no preempt, and the next step is C's same-host restart.
#[test]
fn a_takeover_whose_attach_entry_binds_another_instance_refuses() {
    use crate::failover::restart::tests::{OTHER_INSTANCE, bind_entry};
    let c_bound_to = |instance: InstanceId| {
        let mut volume = with_c();
        let live = volume.live(c_host()).unwrap();
        volume
            .events
            .iter_mut()
            .find(|event| event.seq == live)
            .unwrap()
            .instance = Some(instance);
        volume
    };
    let store = restart_tests::store(
        shard_record(),
        c_bound_to(InstanceId::new(OTHER_INSTANCE).unwrap()),
    );
    let before = stored(&store);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Local(Local::Binding), None)
    );
    assert!(matches!(path.next(&refused), Next::Stop));
    assert!(card.log.is_empty());
    assert_eq!(stored(&store), before);

    let store = restart_tests::store(shard_record(), c_bound_to(instance_of(c_host())));
    let mut card = card_after_cas(&store, c_pair(), c_host(), &a_holds_c_registered());
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);

    let store = restart_tests::store(shard_record(), with_c());
    let reservation = a_holds_c_registered();
    let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
    let writer = store.clone();
    card.on_report = Some(Box::new(move || bind_entry(&writer, c_host())));
    let path = takeover_of(&store, c_host());
    let refused = path
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check.clone(), refused.recovery),
        (Check::Local(Local::Binding), Some(own_target()))
    );
    assert_eq!(card.log, TO_REPORT, "no preempt");
    assert!(matches!(path.next(&refused), Next::Restart(_)));
    assert_eq!(
        reservation.borrow().entries[0],
        registrant(owner_pair(), 1, true),
        "A still holds"
    );
}

/// Control for INSTANCE-BOUND at the takeover: step 2 without the entry's instance admits C over its entry bound to
/// another instance, where `bound` refuses `Binding` before the CAS.
#[test]
fn negative_control_a_takeover_step_2_without_the_entry_instance_admits_another_instances_attach() {
    use crate::failover::restart::tests::{OTHER_INSTANCE, unbound_step_2};
    let mut volume = with_c();
    let live = volume.live(c_host()).unwrap();
    volume
        .events
        .iter_mut()
        .find(|event| event.seq == live)
        .unwrap()
        .instance = Some(InstanceId::new(OTHER_INSTANCE).unwrap());
    assert_eq!(
        unbound_step_2(&holder_of(c_host()), &c_record(), &volume),
        Ok(c_pair()),
        "a standby on another instance than its attach entry's takes over"
    );
    assert_eq!(
        bound(&holder_of(c_host()), &stored_c(), &volume),
        Err(Local::Binding)
    );
}

/// A, C and a third host B, each bound to its instance; B's pair carries its entry's key, so the reconciler can end
/// its attach. Returns the record and B's pair.
fn with_c_and_bound_b() -> (VolumeRecord, Pair) {
    let mut volume = with_c();
    let seq = volume.push(EventKind::Attach, b_host(), ERA).unwrap();
    for event in &mut volume.events {
        event.instance = Some(instance_of(event.host));
    }
    let pair = Pair {
        key: crate::failover::records::attachment_key(seq).unwrap(),
        ..b_pair()
    };
    volume.pairs.push(RecordedPair {
        host: b_host(),
        pair,
        attach: seq,
    });
    (volume, pair)
}

/// ENDED-NEVER-RETIRES at the takeover, through the reconciler's steps: the reconciler ends B's attach, the owner's
/// reclaim drops B's ended pair (a raw exact-version write), and, for the gone row, the detach witness and two clean
/// listings mark B's entry gone; a late Register of B then arrives under the dropped key. A, the owner, is lost, and
/// C's takeover commits: both Reports admit the late registrant beside A's holding, the preempt names A's key alone,
/// and the tenure starts with the late pair after the record's pairs. The registrant holds nothing, and B's own entry
/// is ended or gone.
#[test]
fn a_late_register_under_a_dropped_key_does_not_strand_the_takeover() {
    use crate::failover::reconcile::{Listing, Reconciler, Settle, StandbyGate};
    for gone in [false, true] {
        let (volume, b) = with_c_and_bound_b();
        let seq = volume.live(b_host()).unwrap();
        let store = restart_tests::store(shard_record(), volume);
        let gate = StandbyGate::qualified();
        let mut reconciler = Reconciler::new(client(&store));
        let ended = reconciler
            .end_attach(&gate, shard(), volume_id(), b_host(), seq)
            .unwrap();
        assert!(!ended.named(), "gone {gone}");
        let mut writer = client(&store);
        let read = writer
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        let mut dropped = read.value().clone();
        dropped.pairs.retain(|recorded| recorded.host != b_host());
        writer.replace(&read, dropped).unwrap();
        if gone {
            let witness = reconciler.detachable(volume_id(), b_host()).unwrap();
            let others: Vec<String> = [owner_host(), c_host()]
                .map(|host| instance_of(host).as_str().to_owned())
                .to_vec();
            let listings = [
                Listing {
                    at: 400,
                    instances: &others,
                },
                Listing {
                    at: 700,
                    instances: &others,
                },
            ];
            let settle = Settle {
                requested: 100,
                settle: 300,
            };
            reconciler
                .release_attach(&gate, &witness, &listings, settle)
                .unwrap();
        }
        let record = volume_now(&store);
        assert!(record.ended(b_host()) && !record.records_pair_of(b_host()));
        assert_eq!(
            record.registrant(&b),
            crate::failover::records::Registration::Ended,
            "gone {gone}"
        );
        let reservation = a_holds_c_registered();
        reservation
            .borrow_mut()
            .entries
            .push(registrant(b, 3, false));
        let mut card = card_after_cas(&store, c_pair(), c_host(), &reservation);
        let taken_over = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut card)
            .unwrap();
        assert_eq!(card.log, FULL, "gone {gone}");
        assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
        let (_, fenced, (recorded, late), _, _, _) = taken_over.into_parts();
        assert_eq!(fenced.own(), c_pair());
        let mut expected = record.recorded_pairs();
        expected.push(b);
        assert_eq!((recorded, late), (expected, 1), "gone {gone}");
        assert_eq!(
            reservation.borrow().entries,
            vec![registrant(c_pair(), 2, true), registrant(b, 3, false)],
            "gone {gone}: the preempt named A's key and B's late Register holds nothing"
        );
    }
}

/// Control for the takeover's Report census: the census over the record's pairs alone, the form before the takeover
/// admitted registrants under an ended attach's key, refuses B's late Register under its dropped key as
/// `Registrants(ForeignRegistrant)`, so C's takeover would stop after its CAS; the admitted set resolves A's key.
#[test]
fn negative_control_a_recorded_only_takeover_census_refuses_a_late_register() {
    let (mut volume, b) = with_c_and_bound_b();
    let at = volume.live(b_host()).unwrap();
    volume
        .events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap()
        .kind = EventKind::Ended;
    volume.pairs.retain(|recorded| recorded.host != b_host());
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(registrant(b, 3, false));
    let entries = reservation.borrow().entries.clone();
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: crate::failover::evidence::ReservationType::ExclusiveAccess,
        regctl: entries.len() as u32,
        entries: &entries,
    };
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    assert_eq!(
        LineagePreempt::resolve(
            &report,
            volume.recorded(),
            volume.recorded_beside(c_host()),
            c_pair(),
            &bounds
        )
        .map(LineagePreempt::preempted),
        Err(HolderRefusal::Registrants(NotSole::ForeignRegistrant)),
        "a recorded-only census refuses the late Register"
    );
    let admitted: Vec<Pair> = volume.admitted(&entries).copied().collect();
    assert_eq!(
        LineagePreempt::resolve(
            &report,
            &admitted,
            volume.recorded_beside(c_host()),
            c_pair(),
            &bounds
        )
        .map(LineagePreempt::preempted),
        Ok(owner_pair().key)
    );
}

fn takeover_over_a_tally(arms: &[Arm], preload: bool, plant: bool) -> restart_tests::Run<Refused> {
    let store = restart_tests::store(shard_record(), with_c());
    let mut recording = restart_tests::Recording::open(&store, preload, plant);
    let path = takeover_of(&store, c_host());
    for arm in arms {
        store.schedule(*arm);
    }
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    card.trace = Some(recording.recorder.clone());
    let result = path.run(&mut recording.client, &stored_c(), &mut card);
    recording.finish(card.log, result)
}

/// Monitors observe for the takeover: a takeover that reaches its capability with the warm source its record's
/// checkpoint names, and one whose compare-and-swap commits with an unknown outcome, issue the same requests and
/// commands, return the same result and leave the same record, log writes and alarm whatever the tally holds.
#[test]
fn a_takeover_issues_the_same_requests_and_commands_whatever_the_tally_holds() {
    assert!(shard_record().checkpoint.is_some());
    let lost = restart_tests::same_runs_whatever_the_tally(
        takeover_over_a_tally,
        // The two step-1 reads precede the compare-and-swap.
        (2, Arm::Timeout { commit: true }),
        own_target(),
        true,
        |refused| refused.check == Check::TakeOver(StoreError::Unknown),
    );
    assert!(
        lost.commands.is_empty(),
        "the unknown reply authorized a device command"
    );
}

/// The planned transfer and the named standby's takeover condition on one shard-record version, and exactly one of
/// them commits, in either order. The outgoing owner A's session comes from its own acknowledged bump; C's takeover
/// runs its full sequence. When the transfer commits first, between the takeover's record reads and its CAS, the
/// takeover refuses its condition with no device command, no session and no recovery target. When the takeover
/// commits first, the transfer over the saved read refuses its condition. The record holds the winner's write.
#[test]
fn a_transfer_and_a_takeover_over_one_version_commit_exactly_one() {
    use crate::failover::reconcile::StandbyGate;
    use crate::storage::Session;
    use crate::storage::store::{Outgoing, Refusal, StoreError};
    let prepared = || {
        let store = restart_tests::store(shard_record(), with_c());
        let mut owner = client(&store);
        let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let session = Session::activate(owner.bump(&read).unwrap()).unwrap();
        let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        assert_eq!(
            read.value().standby,
            Some(c_host()),
            "A's tenure names C standby"
        );
        (store, owner, session, read)
    };
    let commits = |store: &Shared| store.0.borrow().commit_count(&Key::Shard(shard()));

    let (store, owner, session, read) = prepared();
    let before = commits(&store);
    let won = Rc::new(RefCell::new(None));
    let (writer, saved) = (RefCell::new(owner), won.clone());
    let local = hooked(stored_c(), move || {
        let transferred = writer.borrow_mut().transfer(
            &StandbyGate::qualified(),
            &read,
            &Outgoing::of(&session),
            c_host(),
        );
        *saved.borrow_mut() = Some(transferred.map(drop));
    });
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &local, &mut card)
        .unwrap_err();
    assert_eq!(*won.borrow(), Some(Ok(())), "the transfer committed");
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(
        card.log.is_empty(),
        "the losing takeover issued no device command"
    );
    assert_eq!(commits(&store), before + 1, "one ownership write");
    let base = ShardRecord {
        attempts: shard_record().attempts + 1,
        ..shard_record()
    };
    assert_eq!(shard_now(&store), taken(&base, c_host()));

    let (store, mut owner, session, read) = prepared();
    let before = commits(&store);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    let won = shard_now(&store);
    assert_eq!(
        owner
            .transfer(
                &StandbyGate::qualified(),
                &read,
                &Outgoing::of(&session),
                c_host()
            )
            .map(drop),
        Err(StoreError::Refused(Refusal::Condition)),
        "the transfer over the saved read loses"
    );
    assert_eq!(commits(&store), before + 1, "one ownership write");
    assert_eq!(shard_now(&store), won);
}
