use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::*;
use crate::failover::attachments::{InstanceId, Mismatch};
use crate::failover::evidence::RESERVATION_CONFLICT;
use crate::failover::poll_tests::volume as volume_of;
use crate::failover::reconcile::{OperatorRelease, ReconcileError, Reconciler, StandbyGate};
use crate::failover::record::LocalRecord;
use crate::failover::records::{
    CoveragePage, ERA, EventKind, Host, RecordedPair, VolumeId, VolumeState,
};
use crate::failover::restart::{self, Restarted};
use crate::failover::retire::{Retirement, Role, Stale};
use crate::failover::sim::{FOREIGN, Plane};
use crate::storage::DeviceStatus;
use crate::storage::activation::{Activation, Damage};
use crate::storage::gate_fixture::{bounds_of, encode_report, foreign, limits};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store_tests::{SPARE, client, record as shard_of, shard};

pub(crate) type Log = Rc<RefCell<Vec<&'static str>>>;

/// The fresh path's local record: the binding and host ID of [`assignment_tests::record`] under the key of the
/// owner's attach, entry 0 of the fresh volume (KEY-PER-ATTACH).
///
/// [`assignment_tests::record`]: crate::failover::assignment_tests::record
pub(crate) fn local_record() -> LocalRecord {
    let issued = crate::failover::assignment_tests::record();
    LocalRecord::fresh(
        issued.binding().clone(),
        crate::failover::records::attachment_key(0).unwrap(),
        || Some(issued.pair().exhid.bytes()),
    )
    .unwrap()
}

fn volume_id() -> VolumeId {
    VolumeId::new(&local_record().binding().volume).unwrap()
}

fn host() -> Host {
    shard_of().owner
}

/// The fresh path's pair, the pair of [`local_record`].
pub(crate) fn own() -> Pair {
    local_record().pair()
}

pub(crate) fn holder() -> Holder {
    Holder {
        volume: volume_id(),
        host: host(),
        instance: InstanceId::new(&local_record().binding().instance).unwrap(),
    }
}

pub(crate) fn shard_record(attempts: u32) -> ShardRecord {
    ShardRecord {
        active: volume_id(),
        attempts,
        ..shard_of()
    }
}

pub(crate) fn volume_record() -> VolumeRecord {
    VolumeRecord {
        volume: volume_id(),
        ..volume_of(VolumeState::Active, host())
    }
}

pub(crate) fn store(shard: ShardRecord, volume: VolumeRecord) -> Shared {
    let store = Shared::new();
    let mut seed = client(&store);
    seed.create_shard(shard).unwrap();
    seed.create(Key::Volume(volume.volume), volume).unwrap();
    let spare = VolumeRecord {
        volume: spare_id(),
        ..volume_of(VolumeState::Fresh, Host::new(SPARE).unwrap())
    };
    seed.create(Key::Volume(spare.volume), spare).unwrap();
    store
}

fn spare_id() -> VolumeId {
    shard_of().spare.unwrap().0
}

pub(crate) fn shard_now(store: &Shared) -> ShardRecord {
    *client(store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
        .value()
}

pub(crate) fn plane() -> Plane {
    Plane {
        listed: BTreeMap::from([(volume_id(), vec![holder().instance.as_str().to_owned()])]),
        down: 0,
    }
}

pub(crate) fn fresh_of(shard: Shard, holder: Holder) -> Fresh {
    Fresh {
        shard,
        holder,
        bounds: bounds_of(limits()),
        limits: limits(),
        intervals: 4,
    }
}

fn fresh() -> Fresh {
    fresh_of(shard(), holder())
}

pub(crate) fn registrant(pair: Pair, cntlid: u16, holder: bool) -> Registrant {
    Registrant {
        cntlid,
        pair,
        holder,
    }
}

pub(crate) struct Records {
    log: Log,
    record: Option<LocalRecord>,
    crash: bool,
    pub(crate) refused: bool,
    retain_fails: bool,
    release_fails: bool,
    after_bump: Option<Box<dyn FnOnce()>>,
    /// The log's length when the last successful release ran.
    released_at: Option<usize>,
}

impl restart::LocalSource for Records {
    fn local(&self) -> Result<LocalRecord, Local> {
        if self.refused {
            return Err(Local::Retained);
        }
        self.record.clone().ok_or(Local::Absent)
    }
}

impl LocalRecords for Records {
    fn persist(
        &mut self,
        holder: &Holder,
        attempt: u32,
        key: ReservationKey,
    ) -> Result<LocalRecord, AdmissionError> {
        if self.refused {
            return Err(AdmissionError::Retained);
        }
        if let Some(record) = &self.record
            && (record.binding().instance != holder.instance.as_str()
                || record.binding().volume != holder.volume.as_str())
        {
            return Err(AdmissionError::Binding);
        }
        if attempt > 0 {
            return Err(AdmissionError::AttemptConsumed);
        }
        if self.record.clone().unwrap_or_else(local_record).pair().key != key {
            return Err(AdmissionError::Key);
        }
        self.log.borrow_mut().push("record");
        self.record.get_or_insert_with(local_record);
        if self.crash {
            return Err(AdmissionError::DurableWrite);
        }
        Ok(self.record.clone().unwrap())
    }

    fn retain_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        assert_eq!(record.binding(), self.record.as_ref().unwrap().binding());
        assert_eq!(
            record.pair().key.incarnation(),
            self.record.as_ref().unwrap().pair().key.incarnation()
        );
        if self.retain_fails {
            self.record = None;
            return Err(AdmissionError::DurableWrite);
        }
        self.refused = true;
        Ok(())
    }

    fn release_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        assert_eq!(record.binding(), self.record.as_ref().unwrap().binding());
        if self.release_fails {
            return Err(AdmissionError::DurableWrite);
        }
        self.refused = false;
        self.released_at = Some(self.log.borrow().len());
        Ok(())
    }
}

pub(crate) struct Card {
    pub(crate) log: Log,
    entries: Vec<Registrant>,
    rtype: u8,
    unit0: Option<Vec<u8>>,
    /// A predecessor's delayed unit-0 write, landing after the own write and before its read-back.
    landed: Option<Vec<u8>>,
    pub(crate) stop_at: Option<usize>,
    pub(crate) fail: Option<&'static str>,
    pub(crate) loss: Option<&'static str>,
    pub(crate) torn: u32,
    pub(crate) read_status: Option<DeviceStatus>,
    pub(crate) write_status: Option<DeviceStatus>,
    pub(crate) report_override: Option<Vec<u8>>,
    pub(crate) on: Option<OnCommand>,
    /// The pair the unit-0 write and read must carry: [`own`] by default, or with `None` the pair last registered.
    pub(crate) own: Option<Pair>,
    registered: Option<Pair>,
}

/// A command name and the hook that runs when the card issues that command.
pub(crate) type OnCommand = (&'static str, Box<dyn FnOnce()>);

impl Card {
    pub(crate) fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            entries: Vec::new(),
            rtype: 0,
            unit0: None,
            landed: None,
            stop_at: None,
            fail: None,
            loss: None,
            torn: 0,
            read_status: None,
            write_status: None,
            report_override: None,
            on: None,
            own: Some(own()),
            registered: None,
        }
    }

    fn command(&mut self, name: &'static str) -> Result<(), Failed> {
        self.log.borrow_mut().push(name);
        if self.on.as_ref().is_some_and(|(at, _)| *at == name) {
            (self.on.take().unwrap().1)();
        }
        let stopped = self.stop_at.is_some_and(|at| self.log.borrow().len() > at);
        if stopped || self.fail == Some(name) {
            return Err(Failed(None));
        }
        Ok(())
    }

    fn after(&mut self, name: &'static str) {
        if self.loss == Some(name) {
            self.entries = vec![registrant(foreign(), 9, true)];
            self.rtype = 2;
        }
    }
}

impl Device for Card {
    fn set_host_id(&mut self, _: Exhid) -> Result<(), Failed> {
        self.command("host")?;
        self.after("host");
        Ok(())
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.command("register")?;
        self.registered = Some(own);
        if self.entries.iter().all(|entry| entry.pair != own) {
            self.entries.push(registrant(own, 1, false));
        }
        self.after("register");
        Ok(())
    }

    fn acquire(&mut self, own: Pair) -> Result<(), Failed> {
        self.command("acquire")?;
        if self
            .entries
            .iter()
            .any(|entry| entry.holder && entry.pair != own)
        {
            return Err(Failed(Some(DeviceStatus::Nvme(RESERVATION_CONFLICT << 1))));
        }
        for entry in &mut self.entries {
            entry.holder = entry.pair == own;
        }
        self.rtype = 2;
        self.after("acquire");
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        self.command("report")?;
        Ok(self
            .report_override
            .clone()
            .unwrap_or_else(|| encode_report(self.rtype, &self.entries)))
    }

    fn write(
        &mut self,
        fenced: &Fenced,
        unit: u64,
        bytes: &[u8; RECORD_LEN],
    ) -> Result<(), Failed> {
        assert_eq!(Some(fenced.own()), self.own.or(self.registered));
        self.command("write")?;
        assert_eq!(unit, 0);
        if let Some(status) = self.write_status.take() {
            return Err(Failed(Some(status)));
        }
        self.unit0 = Some(self.landed.take().unwrap_or_else(|| bytes.to_vec()));
        Ok(())
    }

    fn read(&mut self, fenced: &Fenced, unit: u64) -> Result<Vec<u8>, Failed> {
        assert_eq!(Some(fenced.own()), self.own.or(self.registered));
        self.command("read")?;
        assert_eq!(unit, 0);
        if let Some(status) = self.read_status.take() {
            return Err(Failed(Some(status)));
        }
        if self.torn > 0 {
            self.torn -= 1;
            return Ok(vec![0; RECORD_LEN]);
        }
        self.unit0.clone().ok_or(Failed(None))
    }
}

impl restart::Device for Card {
    fn start(&mut self) -> Result<(), restart::Driver> {
        self.command("start")
            .map_err(|_| restart::Driver::LiveQueues)
    }

    fn ready(&mut self) -> Result<(), Failed> {
        self.command("ready")
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        Device::set_host_id(self, exhid)
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        Device::report(self)
    }

    fn preempt(&mut self, preempt: crate::storage::SelfPreempt) -> Result<(), Failed> {
        assert_eq!(preempt.pair(), own());
        self.command("preempt")
    }

    fn register(&mut self, _: Pair) -> Result<(), Failed> {
        unreachable!("the fresh path's records name no recorded holder of another host")
    }

    fn preempt_lineage(&mut self, _: crate::storage::LineagePreempt) -> Result<(), Failed> {
        unreachable!("the fresh path's records name no recorded holder of another host")
    }
}

pub(crate) fn records(log: &Log) -> Records {
    Records {
        log: log.clone(),
        record: None,
        crash: false,
        refused: false,
        retain_fails: false,
        release_fails: false,
        after_bump: None,
        released_at: None,
    }
}

/// [`records`] holding `record`, as a restart finds it.
pub(crate) fn holding(log: &Log, record: LocalRecord) -> Records {
    Records {
        record: Some(record),
        ..records(log)
    }
}

fn run(
    store: &Shared,
    plane: &mut Plane,
    local: &mut Records,
    card: &mut Card,
) -> Result<Activated, Refused> {
    run_with(store, plane, local, card, &mut Refusals::default())
}

fn run_with(
    store: &Shared,
    plane: &mut Plane,
    local: &mut Records,
    card: &mut Card,
    refusals: &mut Refusals,
) -> Result<Activated, Refused> {
    let mut client = fresh_client(store, local);
    fresh().run(&mut client, plane, local, card, refusals)
}

fn restart_run(
    store: &Shared,
    local: &Records,
    card: &mut Card,
) -> Result<Restarted, restart::Refused> {
    restart::tests::restart_of(shard(), holder()).run(&mut client(store), local, card)
}

const FULL: [&str; 8] = [
    "record", "bump", "host", "register", "acquire", "report", "write", "read",
];

/// A refused coverage fence refuses the fresh attempt with no flip, whatever its cause: a page past the tenure's
/// interval bound, entry bytes short of one entry, or a page record that does not decode. A replacement volume
/// reads the same pages, so the retention releases, no retirement is requested and the bump committed `E = 1`. The
/// next start takes the restart sequence on the same volume, which holds at its coverage check with the bumped
/// tenure as its recovery hint, and the page stays as it was.
#[test]
fn a_refused_coverage_fence_requests_no_replacement() {
    use crate::failover::records::CodecError;
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{FenceRefused, Interval, encode_entries};
    use crate::storage::store::{Outcome, Store, Write};
    let one = |version| Interval::new(CacheVersion(version), CacheVersion(version)).unwrap();
    let past_bound = encode_entries(&[1, 3, 5, 7, 9].map(|version| ([0; 32], one(version))));
    assert!(past_bound.len() / crate::storage::page_coverage::ENTRY_LEN > fresh().intervals);
    let malformed = Withdraw::Malformed { page: 0 };
    let undecodable = Withdraw::Store(StoreError::Codec(CodecError::Length));
    // Each case seeds page 0 with entry bytes through the client, or with a whole record through the store.
    let cases = [
        (past_bound, false, malformed),
        (vec![0; 7], false, malformed),
        (vec![0; 3], true, undecodable),
    ];
    for (bytes, record, withdraw) in cases {
        let store = store(shard_record(0), volume_record());
        let key = Key::Page(shard(), 0);
        let stored = || store.0.borrow().current(&key).cloned().unwrap();
        if record {
            let write = Write::Exact {
                expect: stored().version,
                value: bytes,
            };
            let written = Store::write(&mut store.clone(), &key, &write);
            assert!(matches!(written, Outcome::Committed(_)));
        } else {
            let mut seed = client(&store);
            let page = seed.read::<CoveragePage>(key).unwrap();
            let seeded = CoveragePage {
                entries: bytes,
                ..page.value().clone()
            };
            seed.replace(&page, seeded).unwrap();
        }
        let seeded = stored();
        let log = Log::default();
        let mut card = Card::new(&log);
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (Check::Fence(withdraw), None)
        );
        assert_eq!(
            refused.retirement(volume_id()),
            None,
            "{withdraw:?}: no replacement is requested"
        );
        assert!(!local.refused, "{withdraw:?}: the retention released");
        assert_eq!(shard_now(&store).attempts, 1);
        let held = restart_run(&store, &local, &mut card).unwrap_err();
        assert_eq!(
            (held.check, held.flip),
            (
                restart::Check::Coverage(FenceRefused::Fence(withdraw)),
                None
            )
        );
        assert_eq!(
            held.recovery.map(|target| target.attempts),
            Some(2),
            "{withdraw:?}: the restart holds with its bumped tenure as the recovery hint"
        );
        let kept = stored();
        assert_eq!(
            (kept.version, kept.value),
            (seeded.version, seeded.value),
            "{withdraw:?}: the page is unchanged"
        );
    }
}

/// A predecessor's activation record or another volume's landing over the own unit-0 write, a crc-valid record that
/// `encode` never writes, or two torn read-backs, refuse the attempt with no flip: the retention releases, no
/// retirement is requested, the bump committed `E = 1`, and the next start takes the restart sequence on the same
/// volume, which activates at `E = 2` with no unit-0 command and leaves the volume active.
#[test]
fn a_foreign_activation_read_back_requests_no_replacement() {
    let encoded = |activation: Activation| {
        let mut landed = [0; crate::storage::activation::RECORD_LEN];
        activation.encode(crate::storage::Crc32c::detect(), &mut landed);
        landed.to_vec()
    };
    let predecessor = Activation::of(volume_id(), &crate::storage::session_at(3, 2));
    let other = Activation::of(
        VolumeId::new("vol-0fedcba9876543210").unwrap(),
        &crate::storage::session_at(3, 2),
    );
    // A record whose magic byte differs, resealed under the crc at bytes 48..52.
    let mut invalid = encoded(predecessor);
    invalid[0] ^= 1;
    invalid[48..52].fill(0);
    let sum = crate::storage::Crc32c::detect().checksum(&invalid);
    invalid[48..52].copy_from_slice(&sum.to_le_bytes());
    let cases = [
        (Some(encoded(predecessor)), Fault::Foreign(predecessor)),
        (Some(encoded(other)), Fault::Foreign(other)),
        (Some(invalid), Fault::Damaged(Damage::Invalid)),
        (None, Fault::Damaged(Damage::Torn)),
    ];
    for (landed, fault) in cases {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut card = Card::new(&log);
        match landed {
            Some(landed) => card.landed = Some(landed),
            None => card.torn = 2,
        }
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (Check::Activation(fault), None)
        );
        assert_eq!(
            refused.retirement(volume_id()),
            None,
            "no replacement is requested"
        );
        assert!(!local.refused, "the retention released");
        assert_eq!(shard_now(&store).attempts, 1);
        assert_eq!(
            run(&store, &mut plane(), &mut local, &mut card)
                .unwrap_err()
                .check,
            Check::Restart
        );
        log.borrow_mut().clear();
        let restarted = restart_run(&store, &local, &mut card).expect("the restart activates");
        assert_eq!(
            *log.borrow(),
            ["start", "ready", "host", "report", "preempt", "report"],
            "{fault:?}: the restart issues no unit-0 command"
        );
        assert_eq!(
            (
                restarted.session().epoch().get(),
                shard_now(&store).attempts
            ),
            (4, 2),
            "{fault:?}: the restart's own bump activates E = 2"
        );
        assert_eq!(
            client(&store)
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap()
                .value()
                .state,
            VolumeState::Active
        );
    }
}

#[test]
fn a_status_outside_the_tenure_ending_set_keeps_the_own_target() {
    let status = DeviceStatus::Nvme(0x02 << 1);
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    card.write_status = Some(status);
    let mut local = records(&log);
    let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
    assert_eq!(refused.check, Check::Write(Failed(Some(status))));
    assert_eq!(refused.flip, Some(own_target()));
    assert!(local.refused);
    let store = self::store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    card.read_status = Some(status);
    run(&store, &mut plane(), &mut records(&log), &mut card)
        .expect("the read-back takes the failed read as torn and reads again");
    assert_eq!(
        log.borrow()
            .iter()
            .filter(|command| **command == "read")
            .count(),
        2
    );
}

#[test]
fn terminal_read_status_stops_before_confirm_and_page_fencing() {
    for (on_write, code) in [false, true]
        .into_iter()
        .flat_map(|on_write| [0x83, 0x1b, 0x07, 0x08].map(|code| (on_write, code)))
    {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut card = Card::new(&log);
        let status = DeviceStatus::Nvme(code << 1);
        if on_write {
            card.write_status = Some(status);
        } else {
            card.read_status = Some(status);
        }
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        let check = if on_write {
            Check::Write(Failed(Some(status)))
        } else {
            Check::Read(Failed(Some(status)))
        };
        assert_eq!(refused.check, check);
        assert_eq!(
            refused.flip, None,
            "{code:#x} ends the tenure without a retirement"
        );
        assert!(!local.refused, "{code:#x} leaves the restart sequence open");
        assert_eq!(
            log.borrow().as_slice(),
            &FULL[..FULL.len() - usize::from(on_write)]
        );
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 2);
        for page in 0..shard_record(0).pages.get() {
            assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), page)), 1);
        }
    }
}

#[test]
fn activation_requires_every_page_fenced_and_retries_transient_outcomes() {
    for arm in [
        Arm::Unavailable,
        Arm::Timeout { commit: false },
        Arm::Timeout { commit: true },
    ] {
        let store = store(shard_record(0), volume_record());
        let pages = usize::from(shard_record(0).pages.get());
        let passes = if arm == Arm::Unavailable {
            5
        } else {
            5 + pages
        };
        for _ in 0..passes {
            store.schedule(Arm::Pass);
        }
        store.schedule(arm);
        let log = Log::default();
        let activated = run(
            &store,
            &mut plane(),
            &mut records(&log),
            &mut Card::new(&log),
        )
        .unwrap();
        assert!(activated.fencing().coverage().is_some(), "{arm:?}");
        for page in 0..shard_record(0).pages.get() {
            let read = client(&store)
                .read::<CoveragePage>(Key::Page(shard(), page))
                .unwrap();
            assert_eq!(read.value().fence, activated.session().get());
        }
    }
    let store = store(shard_record(0), volume_record());
    for _ in 0..5 {
        store.schedule(Arm::Pass);
    }
    for arm in [Arm::Unavailable, Arm::Pass, Arm::Pass] {
        store.schedule(arm);
    }
    for _ in 2..FENCE_ROUNDS {
        store.schedule(Arm::Unavailable);
    }
    let log = Log::default();
    run(
        &store,
        &mut plane(),
        &mut records(&log),
        &mut Card::new(&log),
    )
    .expect("the last of page 0's fence steps succeeds");
    let store = self::store(shard_record(0), volume_record());
    for _ in 0..5 {
        store.schedule(Arm::Pass);
    }
    for arm in [Arm::Unavailable, Arm::Pass, Arm::Pass] {
        store.schedule(arm);
    }
    for _ in 1..FENCE_ROUNDS {
        store.schedule(Arm::Unavailable);
    }
    let log = Log::default();
    let mut local = records(&log);
    let refused = run(&store, &mut plane(), &mut local, &mut Card::new(&log)).unwrap_err();
    assert_eq!(refused.check, Check::UnresolvedPage { page: 0 });
    assert_eq!(refused.flip, None, "an unavailable read observes nothing");
    assert!(!local.refused);
    assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), 0)), 1);
    assert_eq!(
        store.0.borrow().commit_count(&Key::Page(shard(), 1)),
        2,
        "page 1 is fenced while page 0 stays unresolved, and activation still refuses"
    );
}

#[test]
fn a_retained_refusal_prevents_fresh_rerun_and_restart_activation() {
    for (after_fb, committed) in [(true, true), (false, false), (false, true)] {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut local = records(&log);
        let mut card = Card::new(&log);
        if after_fb {
            card.fail = Some("write");
        } else {
            for arm in [
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: committed },
            ] {
                store.schedule(arm);
            }
        }
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        assert!(local.refused);
        let before = log.borrow().clone();
        let rerun = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        if committed {
            assert_eq!(rerun.check, Check::Restart);
            assert_eq!(
                restart_run(&store, &local, &mut card).unwrap_err().check,
                restart::Check::Local(Local::Retained)
            );
        } else {
            assert_eq!(rerun.check, Check::Persist(AdmissionError::Retained));
            assert_eq!(shard_now(&store).attempts, 0);
            assert_eq!(
                rerun.retirement(volume_id()),
                Retirement::recovering(volume_id(), rerun.flip.unwrap(), Trigger::Activation),
                "the bump behind the marker may still commit"
            );
        }
        assert_eq!(*log.borrow(), before);
        reconcile(&store, refused.retirement(volume_id()));
        assert_eq!(
            client(&store)
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap()
                .value()
                .state,
            VolumeState::Retired
        );
    }
}

#[test]
fn a_restart_after_a_retained_refusal_retires_the_spare_and_after_a_failed_retention_requests_nothing()
 {
    for (after_fb, retain_fails) in [(true, false), (false, false), (true, true), (false, true)] {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut local = records(&log);
        local.retain_fails = retain_fails;
        let mut card = Card::new(&log);
        if after_fb {
            card.fail = Some("write");
        } else {
            for arm in [
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: true },
            ] {
                store.schedule(arm);
            }
        }
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        assert_eq!(local.refused, !retain_fails);
        if retain_fails {
            if after_fb {
                assert_eq!(refused.check, Check::Hold(AdmissionError::DurableWrite));
                assert!(
                    !log.borrow().contains(&"write"),
                    "a failed hold at FB precedes the medium write"
                );
            } else {
                let Check::Retention { original, error } = &refused.check else {
                    panic!("{:?}", refused.check);
                };
                assert_eq!(*error, AdmissionError::DurableWrite);
                assert_eq!(original.as_ref(), &Check::Bump(StoreError::Unknown));
            }
            let request = refused.retirement(volume_id()).unwrap();
            assert_eq!(
                request.admit(&shard_now(&store)).is_err(),
                !after_fb,
                "a failed retention requests the exact target"
            );
        }
        let before = log.borrow().clone();
        let restarted = restart_run(&store, &local, &mut card).unwrap_err();
        assert_eq!(*log.borrow(), before);
        if retain_fails {
            assert_eq!(restarted.check, restart::Check::Local(Local::Absent));
            assert_eq!(restarted.flip, None);
            continue;
        }
        assert_eq!(restarted.check, restart::Check::Local(Local::Retained));
        reconcile(
            &store,
            Retirement::new(
                volume_id(),
                Role::Active,
                restarted.flip.unwrap(),
                Trigger::Activation,
            ),
        );
        assert_eq!(
            client(&store)
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap()
                .value()
                .state,
            VolumeState::Retired
        );
    }
}

#[test]
fn a_failed_release_keeps_the_retention_and_restart_refusing() {
    for fenced in [true, false] {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut local = records(&log);
        local.release_fails = true;
        let mut card = Card::new(&log);
        let status = DeviceStatus::Nvme(0x83 << 1);
        if !fenced {
            card.read_status = Some(status);
        }
        let refused = run(&store, &mut plane(), &mut local, &mut card).unwrap_err();
        let expected = if fenced {
            Refused {
                check: Check::Release(AdmissionError::DurableWrite),
                flip: Some(own_target()),
            }
        } else {
            Refused {
                check: Check::Retention {
                    original: Box::new(Check::Read(Failed(Some(status)))),
                    error: AdmissionError::DurableWrite,
                },
                flip: None,
            }
        };
        assert_eq!(refused, expected);
        assert!(local.refused);
        let before = log.borrow().clone();
        assert_eq!(
            restart_run(&store, &local, &mut card)
                .map(drop)
                .unwrap_err()
                .check,
            restart::Check::Local(Local::Retained)
        );
        assert_eq!(*log.borrow(), before);
    }
}

#[test]
fn fresh_activation_preserves_inherited_coverage_and_saturation() {
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{Interval, encode_entries};
    for saturated in [false, true] {
        let store = store(shard_record(0), volume_record());
        let mut originals = Vec::new();
        for page in 0..shard_record(0).pages.get() {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&u64::from(page).to_le_bytes());
            let original = CoveragePage {
                fence: 1,
                saturated: saturated && page == 1,
                entries: if saturated && page == 1 {
                    Vec::new()
                } else {
                    encode_entries(&[(
                        key,
                        Interval::new(CacheVersion(5), CacheVersion(9)).unwrap(),
                    )])
                },
            };
            let mut client = client(&store);
            let read = client
                .read::<CoveragePage>(Key::Page(shard(), page))
                .unwrap();
            client.replace(&read, original.clone()).unwrap();
            originals.push((key, original));
        }
        let log = Log::default();
        let activated = run(
            &store,
            &mut plane(),
            &mut records(&log),
            &mut Card::new(&log),
        )
        .unwrap();
        let coverage = activated.fencing().coverage().unwrap();
        for (page, (key, original)) in originals.into_iter().enumerate() {
            let read = client(&store)
                .read::<CoveragePage>(Key::Page(shard(), page as u16))
                .unwrap();
            assert_eq!(
                read.value(),
                &CoveragePage {
                    fence: activated.session().get(),
                    ..original.clone()
                }
            );
            for version in [5, 7, 9] {
                assert!(coverage.covers(&key, CacheVersion(version)));
            }
            assert_eq!(coverage.covers(&key, CacheVersion(4)), original.saturated);
            assert_eq!(coverage.covers(&key, CacheVersion(10)), original.saturated);
            let mut other = key;
            other[31] = 1;
            assert_eq!(coverage.covers(&other, CacheVersion(7)), original.saturated);
        }
    }
}

#[test]
fn flip_for_refuses_spare_roles_and_recognizes_completed_flips() {
    let store = store(shard_record(0), volume_record());
    let target = Target::of(&shard_record(0));
    let spare = Retirement::new(spare_id(), Role::Spare, target, Trigger::Activation).unwrap();
    let mut reconciler = Reconciler::new(client(&store));
    assert_eq!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &spare),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(shard_now(&store), shard_record(0));
    let active = Retirement::new(volume_id(), Role::Active, target, Trigger::Activation).unwrap();
    assert!(matches!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &active),
        Ok(crate::failover::reconcile::Flip::Flipped(_))
    ));
    assert_eq!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &active),
        Ok(crate::failover::reconcile::Flip::Past)
    );
    let mut record = shard_record(0);
    record.attempts = u32::MAX;
    let target = Target::of(&record);
    assert!(
        Retirement::new(volume_id(), Role::Active, target, Trigger::Activation)
            .unwrap()
            .admit(&record)
            .is_ok()
    );
    assert!(
        Retirement::recovering(volume_id(), target, Trigger::Activation)
            .unwrap()
            .admit(&record)
            .is_ok()
    );
}

#[test]
fn fresh_report_refusals_preserve_observed_trigger_evidence() {
    let own = own();
    let alias = Pair {
        key: crate::failover::identity::Key::attachment(
            crate::failover::identity::Incarnation::new(900).unwrap(),
        ),
        ..own
    };
    let reports = [
        (
            encode_report(2, &[registrant(own, 1, true), registrant(alias, 2, false)]),
            NotSole::DuplicateOwnRecord,
        ),
        (
            encode_report(
                2,
                &[registrant(own, 1, true), registrant(foreign(), 2, false)],
            ),
            NotSole::ForeignRegistrant,
        ),
        (
            encode_report(0, &[registrant(own, 1, true)]),
            NotSole::ReservationType,
        ),
        (Vec::new(), NotSole::Unreadable),
    ];
    for (report, check) in reports {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut card = Card::new(&log);
        card.report_override = Some(report);
        let refused = run(&store, &mut plane(), &mut records(&log), &mut card).unwrap_err();
        assert_eq!(refused.check, Check::NotSole(check));
        assert_eq!(log.borrow().as_slice(), &FULL[..6]);
        let retirement = refused.retirement(volume_id()).unwrap();
        assert_eq!(retirement.target, own_target());
        assert_eq!(
            retirement.trigger(),
            &if check.observed() {
                Trigger::Report(check)
            } else {
                Trigger::Activation
            }
        );
    }
}

#[test]
fn successor_before_confirm_refuses_without_a_retirement_or_page_write() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let racing = store.clone();
    let mut local = Records {
        after_bump: Some(Box::new(move || {
            Reconciler::new(client(&racing))
                .flip(&StandbyGate::qualified(), shard(), own_target())
                .unwrap();
        })),
        ..records(&log)
    };
    let refused = run(&store, &mut plane(), &mut local, &mut Card::new(&log)).unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Superseded,
            flip: None
        }
    );
    assert_eq!(refused.retirement(volume_id()), None);
    assert!(!refused.check.restarts());
    assert_eq!(log.borrow().as_slice(), FULL);
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 3);
    for page in 0..shard_record(0).pages.get() {
        assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), page)), 1);
    }
}

#[test]
fn the_confirm_writes_on_the_bumped_version_without_a_read() {
    let store = store(shard_record(0), unactivated_record());
    let recorder = crate::storage::store::sim::Recorder::new(&store);
    let mut client = Client::open(recorder.clone(), MemLog::default()).unwrap();
    let log = Log::default();
    let activated = fresh()
        .run(
            &mut client,
            &mut plane(),
            &mut records(&log),
            &mut Card::new(&log),
            &mut Refusals::default(),
        )
        .unwrap();
    assert!(activated.fencing().coverage().is_some());
    let page = |page| Key::Page(shard(), page);
    let calls: Vec<(bool, Key)> = recorder
        .take()
        .into_iter()
        .filter_map(|request| match request {
            crate::storage::store::sim::Request::Read(key) => Some((false, key)),
            crate::storage::store::sim::Request::Write(key, _) => Some((true, key)),
            crate::storage::store::sim::Request::Device(_) => None,
        })
        .collect();
    assert_eq!(
        calls,
        [
            (false, Key::Volume(volume_id())),
            (false, Key::Shard(shard())),
            (true, Key::Volume(volume_id())),
            (true, Key::Shard(shard())),
            (true, Key::Shard(shard())),
            (false, page(0)),
            (false, page(1)),
            (true, page(0)),
            (true, page(1)),
        ]
    );
    let confirmed = shard_now(&store);
    assert_eq!(Target::of(&confirmed), own_target());
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 3);
}

/// A write that keeps the own `(g, owner, E)` between the bump and the Confirm fails the Confirm's condition on the
/// bumped version; the Confirm then reads the record and confirms on the read version, and an unavailable read
/// refuses with `flip: None`.
#[test]
fn a_write_after_the_bump_moves_the_confirm_to_the_read_version() {
    for unavailable in [false, true] {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let racing = store.clone();
        let mut local = Records {
            after_bump: Some(Box::new(move || {
                let mut other = client(&racing);
                let read = other.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                let dropped = ShardRecord {
                    spare: None,
                    ..*read.value()
                };
                other.replace(&read, dropped).unwrap();
                if unavailable {
                    racing.schedule(Arm::Pass);
                    racing.schedule(Arm::Unavailable);
                }
            })),
            ..records(&log)
        };
        let result = run(&store, &mut plane(), &mut local, &mut Card::new(&log));
        assert_eq!(log.borrow().as_slice(), FULL, "{unavailable}");
        let confirmed = shard_now(&store);
        assert_eq!(confirmed.spare, None);
        assert_eq!(Target::of(&confirmed), own_target());
        if unavailable {
            assert_eq!(
                result.unwrap_err(),
                Refused {
                    check: Check::Confirm(StoreError::Unavailable),
                    flip: None,
                }
            );
            assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 3);
        } else {
            assert!(result.unwrap().fencing().coverage().is_some());
            assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 4);
        }
    }
}

#[test]
fn flip_for_exhaustion_is_retryable_after_four_version_losses() {
    struct Contended {
        inner: Shared,
        losses: Rc<std::cell::Cell<usize>>,
        reads: Rc<std::cell::Cell<usize>>,
    }
    impl Store for Contended {
        fn namespace(&self) -> crate::failover::records::Namespace {
            self.inner.namespace()
        }

        fn read(
            &mut self,
            key: &Key,
        ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable>
        {
            if matches!(key, Key::Shard(_)) {
                self.reads.set(self.reads.get() + 1);
            }
            self.inner.read(key)
        }
        fn write(
            &mut self,
            key: &Key,
            write: &crate::storage::store::Write,
        ) -> crate::storage::store::Outcome {
            if *key == Key::Volume(spare_id()) && self.losses.get() < 4 {
                self.losses.set(self.losses.get() + 1);
                let mut other = client(&self.inner);
                let read = other.read::<VolumeRecord>(*key).unwrap();
                other.replace(&read, read.value().clone()).unwrap();
            }
            self.inner.write(key, write)
        }
    }
    let store = store(shard_record(0), volume_record());
    let losses = Rc::new(std::cell::Cell::new(0));
    let reads = Rc::new(std::cell::Cell::new(0));
    let request = Retirement::new(
        volume_id(),
        Role::Active,
        Target::of(&shard_record(0)),
        Trigger::Activation,
    )
    .unwrap();
    let client = Client::open(
        Contended {
            inner: store.clone(),
            losses: losses.clone(),
            reads: reads.clone(),
        },
        MemLog::default(),
    )
    .unwrap();
    let mut reconciler = Reconciler::new(client);
    assert_eq!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request),
        Err(ReconcileError::Retry)
    );
    assert_eq!((losses.get(), reads.get()), (4, 4));
    assert_eq!(shard_now(&store), shard_record(0));
    assert!(matches!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request),
        Ok(crate::failover::reconcile::Flip::Flipped(_))
    ));
    assert_eq!(shard_now(&store).active, spare_id());
}

#[test]
fn record_only_routing_issues_no_attachment_listing() {
    struct Counting {
        calls: usize,
    }
    impl ControlPlane for Counting {
        fn attachments(
            &mut self,
            _: &VolumeId,
        ) -> Result<Vec<String>, crate::failover::attachments::Unlisted> {
            self.calls += 1;
            Ok(vec![holder().instance.as_str().to_owned()])
        }
    }
    for (record, expected) in [
        (shard_record(1), Check::Restart),
        (
            ShardRecord {
                owner: Host::new(99).unwrap(),
                ..shard_record(0)
            },
            Check::Deposed,
        ),
    ] {
        let store = store(record, volume_record());
        let log = Log::default();
        let mut plane = Counting { calls: 0 };
        let refused = fresh()
            .run(
                &mut client(&store),
                &mut plane,
                &mut records(&log),
                &mut Card::new(&log),
                &mut Refusals::default(),
            )
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: expected,
                flip: None
            }
        );
        assert_eq!(plane.calls, 0);
        assert!(log.borrow().is_empty());
    }
}

#[test]
fn reaches_the_boundary_then_activates_in_order() {
    let store = store(shard_record(0), unactivated_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    let activated = run(&store, &mut plane(), &mut records(&log), &mut card).unwrap();
    assert_eq!(log.borrow().as_slice(), FULL);
    let session = activated.session();
    assert_eq!(session.epoch().get(), 2);
    assert_eq!(session.target(), Target::of(&shard_record(1)));
    assert_eq!(shard_now(&store), shard_record(1));
    assert_eq!(
        store.0.borrow().commit_count(&Key::Shard(shard())),
        3,
        "the creation, the bump and the Confirm"
    );
    assert_eq!(
        Activation::decode(Crc32c::detect(), card.unit0.as_deref().unwrap()),
        Ok(Activation::of(volume_id(), session))
    );
    assert!(activated.fencing().coverage().is_some());
    for page in 0..shard_record(0).pages.get() {
        let read = client(&store)
            .read::<CoveragePage>(Key::Page(shard(), page))
            .unwrap();
        assert_eq!(read.value().fence, session.get(), "page {page}");
    }
    let held = client(&store)
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    assert_eq!(
        (held.value().state, held.value().enrolled(host())),
        (VolumeState::Fresh, Some(own())),
        "the enrollment is the fresh path's one volume-record change"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flip {
    None,
    Read,
    Own,
}

struct Case {
    name: &'static str,
    shard: ShardRecord,
    volume: VolumeRecord,
    plane: Plane,
    arms: Vec<Arm>,
    card: fn(&mut Card),
    fence: Option<u64>,
    check: Check,
    flip: Flip,
    log: Vec<&'static str>,
}

fn case(name: &'static str, check: Check, flip: Flip, issued: usize) -> Case {
    let log = FULL.iter().chain(&["read"]).take(issued).copied().collect();
    Case {
        name,
        shard: shard_record(0),
        volume: unactivated_record(),
        plane: plane(),
        arms: Vec::new(),
        card: |_| {},
        fence: None,
        check,
        flip,
        log,
    }
}

fn cases() -> Vec<Case> {
    let failed = Failed(None);
    let mut force = volume_record();
    force.push(EventKind::Force, host(), ERA);
    let mut listed = plane();
    listed
        .listed
        .get_mut(&volume_id())
        .unwrap()
        .push(FOREIGN.to_owned());
    vec![
        Case {
            arms: vec![Arm::Unavailable],
            ..case(
                "unavailable records",
                Check::Records(StoreError::Unavailable),
                Flip::None,
                0,
            )
        },
        Case {
            shard: ShardRecord {
                generation: crate::net::ownership::ShardGeneration::new(u64::from(u32::MAX))
                    .unwrap(),
                ..shard_record(0)
            },
            ..case(
                "exhausted generation",
                Check::Exhausted(SessionRefusal::GenerationExhausted),
                Flip::Read,
                0,
            )
        },
        Case {
            shard: ShardRecord {
                checkpoint: Some(crate::failover::records::NamedCheckpoint {
                    slot: 0,
                    session: (3 << 32) | 2,
                    capture: 1,
                    units: 1,
                }),
                ..shard_record(0)
            },
            ..case("named checkpoint", Check::Named, Flip::Own, 8)
        },
        Case {
            shard: ShardRecord {
                page_cap: std::num::NonZeroU32::new(1).unwrap(),
                ..shard_record(0)
            },
            ..case(
                "page cap",
                Check::Fencing(FencingRefusal::PageCap),
                Flip::None,
                8,
            )
        },
        Case {
            arms: vec![
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: false },
            ],
            ..case(
                "unknown Confirm",
                Check::Confirm(StoreError::Unknown),
                Flip::None,
                8,
            )
        },
        Case {
            arms: vec![
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: false },
                Arm::Pass,
                Arm::Unavailable,
                Arm::Unavailable,
                Arm::Unavailable,
            ],
            ..case(
                "fence timeout retried",
                Check::UnresolvedPage { page: 0 },
                Flip::None,
                8,
            )
        },
        Case {
            shard: shard_record(1),
            ..case("E > 0", Check::Restart, Flip::None, 0)
        },
        Case {
            shard: ShardRecord {
                owner: Host::new(99).unwrap(),
                ..shard_record(0)
            },
            ..case("another owner", Check::Deposed, Flip::None, 0)
        },
        Case {
            plane: Plane { down: 1, ..plane() },
            ..case("no listing", Check::Unobserved, Flip::None, 0)
        },
        Case {
            plane: listed,
            ..case(
                "a foreign attachment",
                Check::Volume(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))),
                Flip::Read,
                0,
            )
        },
        Case {
            volume: force,
            ..case(
                "a force detach",
                Check::Volume(Trigger::Events),
                Flip::Read,
                0,
            )
        },
        Case {
            volume: VolumeRecord {
                source: CreationSource::Foreign,
                ..volume_record()
            },
            ..case("a foreign creation", Check::Origin, Flip::Read, 0)
        },
        Case {
            volume: VolumeRecord {
                lineage: Lineage::Snapshot,
                ..volume_record()
            },
            ..case("snapshot lineage", Check::Origin, Flip::Read, 0)
        },
        Case {
            arms: vec![
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: true },
            ],
            ..case(
                "a bump of unknown outcome",
                Check::Bump(StoreError::Unknown),
                Flip::Read,
                1,
            )
        },
        Case {
            card: |card| card.fail = Some("host"),
            ..case("host ID", Check::HostId(failed), Flip::Own, 3)
        },
        Case {
            card: |card| card.fail = Some("register"),
            ..case("Register", Check::Register(failed), Flip::Own, 4)
        },
        Case {
            card: |card| card.fail = Some("acquire"),
            ..case("Acquire", Check::Acquire(failed), Flip::Own, 5)
        },
        Case {
            card: |card| card.fail = Some("report"),
            ..case("the fresh Report", Check::Report(failed), Flip::Own, 6)
        },
        Case {
            card: |card| card.loss = Some("acquire"),
            ..case(
                "a foreign holder",
                Check::NotSole(NotSole::ForeignHolder),
                Flip::Own,
                6,
            )
        },
        Case {
            card: |card| card.fail = Some("write"),
            ..case("the activation write", Check::Write(failed), Flip::Own, 7)
        },
        Case {
            card: |card| card.torn = 2,
            ..case(
                "two torn read-backs",
                Check::Activation(Fault::Damaged(Damage::Torn)),
                Flip::None,
                9,
            )
        },
        Case {
            arms: vec![Arm::Pass, Arm::Pass, Arm::Pass, Arm::Pass, Arm::Unavailable],
            ..case(
                "an unavailable Confirm write",
                Check::Confirm(StoreError::Unknown),
                Flip::None,
                8,
            )
        },
        Case {
            fence: Some(u64::MAX),
            ..case(
                "a newer fence",
                Check::Fence(Withdraw::NewerFence {
                    page: 0,
                    fence: u64::MAX,
                }),
                Flip::None,
                8,
            )
        },
    ]
}

#[test]
fn refuses_at_each_check_with_no_later_command() {
    for mut case in cases() {
        let store = store(case.shard, case.volume.clone());
        if let Some(fence) = case.fence {
            let mut seed = client(&store);
            let page = seed.read::<CoveragePage>(Key::Page(shard(), 0)).unwrap();
            seed.replace(
                &page,
                CoveragePage {
                    fence,
                    ..page.value().clone()
                },
            )
            .unwrap();
        }
        for arm in case.arms.drain(..) {
            store.schedule(arm);
        }
        let log = Log::default();
        let mut card = Card::new(&log);
        (case.card)(&mut card);
        let mut monitor = Refusals::default();
        let mut local = records(&log);
        let mut traced = fresh_client(&store, &mut local);
        let refused = fresh()
            .run(
                &mut traced,
                &mut case.plane,
                &mut local,
                &mut card,
                &mut monitor,
            )
            .expect_err(case.name);
        let read = Target::of(&case.shard);
        let flip = match case.flip {
            Flip::None => None,
            Flip::Read => Some(read),
            Flip::Own => Some(Target {
                attempts: 1,
                ..read
            }),
        };
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (case.check, flip),
            "{}",
            case.name
        );
        assert_eq!(*log.borrow(), case.log, "{}", case.name);
        let retirement = refused.retirement(volume_id());
        assert_eq!(
            retirement.as_ref().map(|request| request.target),
            flip,
            "{}",
            case.name
        );
        if let Some(retirement) = retirement {
            assert!(
                retirement.admit(&shard_now(&store)).is_ok(),
                "{}",
                case.name
            );
        }
        if case.log.is_empty() {
            assert_eq!(
                store.0.borrow().commit_count(&Key::Shard(shard())),
                1,
                "{}",
                case.name
            );
        }
        let retained = case.flip == Flip::Own && case.log.len() > 6
            || refused.check == Check::Bump(StoreError::Unknown);
        assert_eq!(local.refused, retained, "{}", case.name);
        let phase = match case.log.len() {
            0..=2 => (1, 0, 0),
            3..=6 => (0, 1, 0),
            _ => (0, 0, 1),
        };
        assert_eq!(
            (monitor.before_commands, monitor.before_fb, monitor.after_fb),
            phase,
            "{}",
            case.name
        );
        assert_eq!(
            monitor.flip_requests,
            u64::from(flip.is_some()),
            "{}",
            case.name
        );
    }
}

fn own_target() -> Target {
    Target::of(&shard_record(1))
}

fn reconcile(store: &Shared, request: Option<Retirement>) {
    let Some(request) = request else {
        return;
    };
    let mut reconciler = Reconciler::new(client(store));
    retire_through(&mut reconciler, &request);
}

fn retire_through<S: Store, L: WatermarkLog>(
    reconciler: &mut Reconciler<S, L>,
    request: &Retirement,
) {
    match reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), request) {
        Ok(_) => {
            reconciler.retire(shard(), request.volume).unwrap();
        }
        Err(ReconcileError::Stale) => {}
        Err(error) => panic!("the reconciler's flip failed: {error:?}"),
    }
}

type Hook = Box<dyn FnOnce(&Shared)>;

struct Racing {
    inner: Shared,
    before_shard_write: Option<Hook>,
    after_shard_write: Option<Box<dyn FnOnce()>>,
    bump_log: Option<Log>,
}

impl Store for Racing {
    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }

    fn read(
        &mut self,
        key: &Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        if matches!(key, Key::Shard(_))
            && let Some(hook) = self.before_shard_write.take()
        {
            hook(&self.inner);
        }
        let outcome = self.inner.write(key, write);
        if matches!(key, Key::Shard(_)) {
            if matches!(outcome, crate::storage::store::Outcome::Committed(_))
                && let Some(log) = self.bump_log.take()
            {
                log.borrow_mut().push("bump");
            }
            if let Some(hook) = self.after_shard_write.take() {
                hook();
            }
        }
        outcome
    }
}

fn fresh_client(store: &Shared, local: &mut Records) -> Client<Racing, MemLog> {
    Client::open(
        Racing {
            inner: store.clone(),
            before_shard_write: None,
            after_shard_write: local.after_bump.take(),
            bump_log: Some(local.log.clone()),
        },
        MemLog::default(),
    )
    .unwrap()
}

fn racing(store: &Shared, hook: impl FnOnce(&Shared) + 'static) -> Reconciler<Racing, MemLog> {
    Reconciler::new(
        Client::open(
            Racing {
                inner: store.clone(),
                before_shard_write: Some(Box::new(hook)),
                after_shard_write: None,
                bump_log: None,
            },
            MemLog::default(),
        )
        .unwrap(),
    )
}

fn replaced(store: &Shared, local: &Records, card: &mut Card) -> Result<(), String> {
    let state = client(store)
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap()
        .value()
        .state;
    if state != VolumeState::Retired {
        return Err(format!("the refused volume is {state:?}"));
    }
    let now = shard_now(store);
    if now.active != spare_id() || now.generation <= shard_of().generation {
        return Err(format!(
            "the shard names {:?} at {:?}",
            now.active, now.generation
        ));
    }
    let before = card.log.borrow().clone();
    let mut rerun = Records {
        record: local.record.clone(),
        ..records(&card.log)
    };
    let fresh = run(store, &mut plane(), &mut rerun, card).map(drop);
    let restart = restart_run(store, local, card).map(drop);
    if *card.log.borrow() != before {
        return Err(format!(
            "the refused volume received {:?}",
            card.log.borrow()
        ));
    }
    if fresh.is_ok() || restart.is_ok() {
        return Err("a later start activated the refused volume".to_owned());
    }
    Ok(())
}

#[test]
fn fresh_crash_after_the_local_record_reruns_fresh() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    let mut local = Records {
        crash: true,
        ..records(&log)
    };
    run(&store, &mut plane(), &mut local, &mut card).expect_err("the process stops");
    assert_eq!(*log.borrow(), ["record"]);
    assert_eq!(shard_now(&store), shard_record(0));
    let landed = local.record.clone().unwrap();
    log.borrow_mut().clear();
    local.crash = false;
    let activated = run(&store, &mut plane(), &mut local, &mut card).unwrap();
    assert_eq!(*log.borrow(), FULL);
    assert_eq!(activated.session().epoch().get(), 2);
    assert_eq!(
        local.record,
        Some(landed),
        "the rerun keeps the landed host ID"
    );
}

/// A fresh path that stops after its bump, before Register at `stop_at` 2 or before Acquire at 4, leaves the shard
/// record at `E = 1` with nobody holding beside its own pair. The fresh rerun requests nothing at `E = 1`, and each
/// restart refuses `Unheld` at Report #1 (NO-HOLDER-HOLD) with no self preempt, no flip and the own target as the
/// recovery hint: a Report with nobody holding shows no volume loss, so the volume stays active for the fresh-host
/// attach and the shard record and volume record stay as the crash left them.
fn retained_after_a_crash_after_the_bump(stop_at: usize) {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card {
        stop_at: Some(stop_at),
        ..Card::new(&log)
    };
    let mut local = records(&log);
    run(&store, &mut plane(), &mut local, &mut card).expect_err("the process stops");
    assert_eq!(*log.borrow(), FULL[..=stop_at]);
    assert_eq!(shard_now(&store), shard_record(1));
    assert_eq!(
        run(&store, &mut plane(), &mut local, &mut card).map(drop),
        Err(Refused {
            check: Check::Restart,
            flip: None
        }),
        "at E = 1 the fresh path requests nothing"
    );
    card.stop_at = None;
    let crashed = client(&store)
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap()
        .value()
        .clone();
    assert_eq!(crashed.state, VolumeState::Active);
    for attempt in ["restart", "rerun"] {
        log.borrow_mut().clear();
        let refused = restart_run(&store, &local, &mut card).expect_err("nobody holds");
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (restart::Check::Unheld, None, Some(own_target())),
            "{attempt}"
        );
        assert_eq!(
            *log.borrow(),
            ["start", "ready", "host", "report"],
            "{attempt}: no self preempt"
        );
        assert_eq!(shard_now(&store), shard_record(1), "{attempt}: no bump");
        assert_eq!(
            client(&store)
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap()
                .value(),
            &crashed,
            "{attempt}: the volume stays active"
        );
    }
}

#[test]
fn fresh_crash_after_the_bump_holds_the_volume_at_restart() {
    retained_after_a_crash_after_the_bump(2);
}

#[test]
fn fresh_crash_after_register_holds_the_volume_at_restart_without_a_self_preempt() {
    retained_after_a_crash_after_the_bump(4);
}

/// The replacement oracle rejects a refusal whose requested retirement never ran and one whose flip ran without the
/// volume's retirement: a reservation loss at the fresh Acquire requests the retirement.
#[test]
fn the_replacement_oracle_refuses_a_suppressed_retirement() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card {
        loss: Some("acquire"),
        ..Card::new(&log)
    };
    let mut local = records(&log);
    let refused = run(&store, &mut plane(), &mut local, &mut card).expect_err("the loss refuses");
    assert!(refused.retirement(volume_id()).is_some());
    card.loss = None;
    let unretired = replaced(&store, &local, &mut card);
    assert!(
        unretired.is_err(),
        "the oracle passed a refused volume left active or unretired: {unretired:?}"
    );
    let flipped_only = store.clone();
    Reconciler::new(client(&flipped_only))
        .flip(&StandbyGate::qualified(), shard(), own_target())
        .unwrap();
    let unrecorded = replaced(&flipped_only, &local, &mut card);
    assert!(
        unrecorded.is_err(),
        "the oracle passed a refused volume left active or unretired: {unrecorded:?}"
    );
}

#[test]
fn fresh_crash_after_acquire_restarts_at_epoch_four() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card {
        stop_at: Some(5),
        ..Card::new(&log)
    };
    let mut local = records(&log);
    run(&store, &mut plane(), &mut local, &mut card).expect_err("the process stops");
    assert_eq!(*log.borrow(), FULL[..6]);
    assert!(
        card.unit0.is_none(),
        "no medium command before the fresh Report"
    );
    log.borrow_mut().clear();
    card.stop_at = None;
    let restarted = restart_run(&store, &local, &mut card).unwrap();
    assert_eq!(
        *log.borrow(),
        ["start", "ready", "host", "report", "preempt", "report"]
    );
    assert_eq!(restarted.session().epoch().get(), 4);
    assert_eq!(shard_now(&store), shard_record(2));
}

#[test]
fn fresh_reservation_loss_before_the_boundary_refuses_and_retires() {
    let conflict = Check::Acquire(Failed(Some(DeviceStatus::Nvme(RESERVATION_CONFLICT << 1))));
    for (step, check) in [
        ("host", conflict.clone()),
        ("register", conflict),
        ("acquire", Check::NotSole(NotSole::ForeignHolder)),
    ] {
        let store = store(shard_record(0), volume_record());
        let log = Log::default();
        let mut card = Card {
            loss: Some(step),
            ..Card::new(&log)
        };
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut card).expect_err(step);
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (check, Some(own_target())),
            "{step}"
        );
        assert!(
            !log.borrow()
                .iter()
                .any(|command| ["write", "read"].contains(command)),
            "{step}: no medium command"
        );
        reconcile(&store, refused.retirement(volume_id()));
        replaced(&store, &local, &mut card).unwrap_or_else(|error| panic!("{step}: {error}"));
    }
}

#[test]
fn fresh_unknown_bump_retires_the_spare_in_both_arms() {
    for commit in [false, true] {
        let store = store(shard_record(0), volume_record());
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Timeout { commit }] {
            store.schedule(arm);
        }
        let log = Log::default();
        let mut card = Card::new(&log);
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut card).expect_err("unknown bump");
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (
                Check::Bump(StoreError::Unknown),
                Some(Target::of(&shard_record(0)))
            ),
            "commit {commit}"
        );
        assert_eq!(
            *log.borrow(),
            ["record"],
            "commit {commit}: no device command"
        );
        reconcile(&store, refused.retirement(volume_id()));
        replaced(&store, &local, &mut card)
            .unwrap_or_else(|error| panic!("commit {commit}: {error}"));
    }
}

fn held_bump(log: &Log) -> (Shared, Records, Card, Refused) {
    let store = store(shard_record(0), volume_record());
    for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Hold] {
        store.schedule(arm);
    }
    let mut card = Card::new(log);
    let mut local = records(log);
    let refused = run(&store, &mut plane(), &mut local, &mut card).expect_err("held bump");
    assert_eq!(
        (refused.check.clone(), refused.flip),
        (
            Check::Bump(StoreError::Unknown),
            Some(Target::of(&shard_record(0)))
        )
    );
    assert_eq!(*log.borrow(), ["record"], "no device command");
    assert_eq!(shard_now(&store), shard_record(0), "the bump is held");
    (store, local, card, refused)
}

#[test]
fn fresh_held_bump_released_after_the_refusal_retires_and_replaces() {
    let log = Log::default();
    let (store, local, mut card, refused) = held_bump(&log);
    store.release();
    assert_eq!(
        shard_now(&store),
        shard_record(1),
        "the held bump commits after Fresh returned"
    );
    let exact = Retirement::new(
        volume_id(),
        Role::Active,
        Target::of(&shard_record(0)),
        Trigger::Activation,
    )
    .unwrap();
    assert_eq!(
        exact.admit(&shard_now(&store)),
        Err(Stale::Target),
        "an exact request stays stale"
    );
    assert_eq!(
        run(&store, &mut plane(), &mut records(&log), &mut card).map(drop),
        Err(Refused {
            check: Check::Restart,
            flip: None
        })
    );
    reconcile(&store, refused.retirement(volume_id()));
    replaced(&store, &local, &mut card).unwrap();
}

#[test]
fn fresh_held_bump_is_resolved_after_a_stale_manual_flip() {
    let log = Log::default();
    let (store, local, mut card, refused) = held_bump(&log);
    let request = refused.retirement(volume_id()).unwrap();
    let now = shard_now(&store);
    request.admit(&now).unwrap();
    let target = Target::of(&now);
    assert_eq!(target, Target::of(&shard_record(0)));
    store.release();
    assert_eq!(
        Reconciler::new(client(&store)).flip(&StandbyGate::qualified(), shard(), target),
        Err(ReconcileError::Stale),
        "the competing bump won"
    );
    reconcile(&store, Some(request));
    replaced(&store, &local, &mut card).unwrap();
}

#[test]
fn a_held_bump_released_between_the_flip_read_and_its_write_is_retried() {
    let log = Log::default();
    let (store, _, _, refused) = held_bump(&log);
    let request = refused.retirement(volume_id()).unwrap();
    let now = shard_now(&store);
    request.admit(&now).unwrap();
    let target = Target::of(&now);
    assert_eq!(
        racing(&store, |inner| drop(inner.release())).flip(
            &StandbyGate::qualified(),
            shard(),
            target
        ),
        Err(ReconcileError::Store(StoreError::Refused(
            crate::storage::store::Refusal::Condition
        ))),
        "the held bump commits after the flip's read, so its write fails its version condition"
    );
    assert_eq!(shard_now(&store), shard_record(1));

    let log = Log::default();
    let (store, local, mut card, refused) = held_bump(&log);
    let request = refused.retirement(volume_id()).unwrap();
    let mut reconciler = racing(&store, |inner| drop(inner.release()));
    retire_through(&mut reconciler, &request);
    log.borrow_mut().clear();
    replaced(&store, &local, &mut card).unwrap();
}

#[test]
fn a_successor_between_the_flip_read_and_its_write_is_not_retired() {
    let log = Log::default();
    let (store, _, _, refused) = held_bump(&log);
    let request = refused.retirement(volume_id()).unwrap();
    let mut reconciler = racing(&store, |inner| {
        let now = *client(inner)
            .read::<ShardRecord>(Key::Shard(shard()))
            .unwrap()
            .value();
        Reconciler::new(client(inner))
            .flip(&StandbyGate::qualified(), shard(), Target::of(&now))
            .unwrap();
    });
    assert_eq!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request),
        Ok(crate::failover::reconcile::Flip::Past)
    );
    store.release();
    let successor = shard_now(&store);
    assert_eq!(successor.active, spare_id());
    assert_eq!(successor.generation.get(), shard_of().generation.get() + 1);
    assert_eq!(request.admit(&successor), Err(Stale::Target));
}

#[test]
fn flip_for_refuses_a_retry_read_that_names_another_spare() {
    let log = Log::default();
    let (store, _, _, refused) = held_bump(&log);
    let request = refused.retirement(volume_id()).unwrap();
    let replacement = VolumeId::new("vol-ee").unwrap();
    let mut reconciler = racing(&store, move |inner| {
        let mut writer = client(inner);
        let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let mut swapped = *read.value();
        swapped.spare = Some((replacement, Host::new(SPARE).unwrap()));
        writer.replace(&read, swapped).unwrap();
    });
    assert_eq!(
        reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request),
        Err(ReconcileError::Conflict)
    );
    let now = shard_now(&store);
    assert_eq!(now.active, volume_id());
    assert_eq!(now.generation, shard_of().generation);
    assert_eq!(now.spare.unwrap().0, replacement);
}

#[test]
fn a_held_bump_without_recovery_leaves_the_spare_unretired() {
    let log = Log::default();
    let (store, local, mut card, refused) = held_bump(&log);
    store.release();
    let exact = Retirement::new(
        volume_id(),
        Role::Active,
        refused.flip.unwrap(),
        Trigger::Activation,
    );
    reconcile(&store, exact);
    let unretired = replaced(&store, &local, &mut card);
    assert!(
        unretired.is_err(),
        "the oracle passed a refused volume left active or unretired: {unretired:?}"
    );
}

#[test]
fn a_bump_that_loses_its_version_condition_to_a_same_tenure_write_requests_nothing() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    let mut local = records(&log);
    let mut client = Client::open(
        Racing {
            inner: store.clone(),
            before_shard_write: Some(Box::new(|inner| {
                let mut writer = client(inner);
                let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                writer.replace(&read, *read.value()).unwrap();
            })),
            after_shard_write: None,
            bump_log: Some(log.clone()),
        },
        MemLog::default(),
    )
    .unwrap();
    let mut refusals = Refusals::default();
    let refused = fresh()
        .run(
            &mut client,
            &mut plane(),
            &mut local,
            &mut card,
            &mut refusals,
        )
        .expect_err("the bump lost its version condition");
    assert_eq!(
        refused.check,
        Check::Bump(StoreError::Refused(
            crate::storage::store::Refusal::Condition
        ))
    );
    assert_eq!(refused.flip, None, "a failed condition committed nothing");
    assert_eq!(refused.retirement(volume_id()), None);
    assert_eq!(*log.borrow(), vec!["record"]);
    assert!(!local.refused);
    assert_eq!(refusals.flip_requests, 0);
    assert_eq!(shard_now(&store), shard_record(0));
    log.borrow_mut().clear();
    run(&store, &mut plane(), &mut local, &mut card).expect("the rerun activates");
    assert_eq!(shard_now(&store), shard_record(1));
}

#[test]
fn fresh_unknown_bump_after_a_successor_retires_nothing() {
    for arm in [
        Arm::Timeout { commit: false },
        Arm::Timeout { commit: true },
        Arm::Hold,
    ] {
        let store = store(shard_record(0), volume_record());
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, arm] {
            store.schedule(arm);
        }
        let log = Log::default();
        let mut card = Card::new(&log);
        let racing = store.clone();
        let mut local = Records {
            after_bump: Some(Box::new(move || {
                let now = shard_now(&racing);
                Reconciler::new(client(&racing))
                    .flip(&StandbyGate::qualified(), shard(), Target::of(&now))
                    .unwrap();
            })),
            ..records(&log)
        };
        let refused = run(&store, &mut plane(), &mut local, &mut card).expect_err("unknown bump");
        assert_eq!(refused.check, Check::Bump(StoreError::Unknown), "{arm:?}");
        store.release();
        let successor = shard_now(&store);
        assert_eq!(successor.active, spare_id(), "{arm:?}");
        let request = refused.retirement(volume_id()).unwrap();
        assert_eq!(request.admit(&successor), Err(Stale::Target), "{arm:?}");
        reconcile(&store, Some(request));
        assert_eq!(shard_now(&store), successor, "{arm:?}: the successor stays");
        assert_eq!(*log.borrow(), ["record"]);
    }
}

#[test]
fn the_monitored_entry_records_each_refusal_once() {
    let mut monitor = Refusals::default();
    let log = Log::default();
    let activating = store(shard_record(0), volume_record());
    run_with(
        &activating,
        &mut plane(),
        &mut records(&log),
        &mut Card::new(&log),
        &mut monitor,
    )
    .unwrap();
    assert_eq!(
        monitor,
        Refusals::default(),
        "an activation records nothing"
    );
    let mut listed = plane();
    listed
        .listed
        .get_mut(&volume_id())
        .unwrap()
        .push(FOREIGN.to_owned());
    let failing = |name| {
        let log = Log::default();
        let card = Card {
            fail: Some(name),
            ..Card::new(&log)
        };
        (log, card)
    };
    let read = Target::of(&shard_record(0));
    let runs: [(Plane, &str, Option<Target>); 3] = [
        (listed, "none", Some(read)),
        (plane(), "acquire", Some(own_target())),
        (plane(), "write", Some(own_target())),
    ];
    let mut checks = Vec::new();
    for (mut listing, fail, flip) in runs {
        let store = store(shard_record(0), volume_record());
        let (log, mut card) = failing(fail);
        let refused = run_with(
            &store,
            &mut listing,
            &mut records(&log),
            &mut card,
            &mut monitor,
        )
        .expect_err(fail);
        assert_eq!(
            refused.flip, flip,
            "{fail}: the monitor leaves the flip as it was"
        );
        checks.push(refused.check);
    }
    assert_eq!(
        checks,
        [
            Check::Volume(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))),
            Check::Acquire(Failed(None)),
            Check::Write(Failed(None)),
        ]
    );
    assert_eq!(
        monitor,
        Refusals {
            before_commands: 1,
            before_fb: 1,
            after_fb: 1,
            flip_requests: 3,
            last: Some(Check::Write(Failed(None))),
        }
    );
}

pub(crate) fn activate(log: &Log) -> (Activated, Pair) {
    let store = store(shard_record(0), volume_record());
    let activated = run(&store, &mut plane(), &mut records(log), &mut Card::new(log)).unwrap();
    (activated, own())
}

/// A local record whose pair differs from the pair the volume record enrolls for this attach refuses before any
/// device command and requests the empty spare's retirement. A key mismatch refuses before the local record's write;
/// a host ID mismatch under the recorded key refuses at the enrollment.
#[test]
fn an_altered_local_record_refuses_before_any_device_command() {
    let altered = |pair| VolumeRecord {
        pairs: vec![RecordedPair {
            host: host(),
            pair,
            attach: 0,
        }],
        ..volume_record()
    };
    let other_key = Pair {
        key: foreign().key,
        ..own()
    };
    let other_exhid = Pair {
        exhid: foreign().exhid,
        ..own()
    };
    for (recorded, check, written) in [
        (other_key, Check::Persist(AdmissionError::Key), &[][..]),
        (
            other_exhid,
            Check::EnrollRefused(Enrollment::Altered),
            &["record"][..],
        ),
    ] {
        let store = store(shard_record(0), altered(recorded));
        let log = Log::default();
        let refused = run(
            &store,
            &mut plane(),
            &mut records(&log),
            &mut Card::new(&log),
        )
        .unwrap_err();
        assert_eq!(refused.check, check);
        assert_eq!(refused.flip, Some(Target::of(&shard_record(0))));
        assert_eq!(*log.borrow(), written);
        assert_eq!(shard_now(&store).attempts, 0);
        assert_eq!(store.0.borrow().commit_count(&Key::Volume(volume_id())), 1);
    }
}

/// A store that logs each committed write of the volume and shard records into the card's log.
struct Ordered {
    inner: Shared,
    log: Log,
}

impl Store for Ordered {
    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }

    fn read(
        &mut self,
        key: &Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        let outcome = self.inner.write(key, write);
        if matches!(outcome, crate::storage::store::Outcome::Committed(_)) {
            match key {
                Key::Volume(_) => self.log.borrow_mut().push("volume"),
                Key::Shard(_) => self.log.borrow_mut().push("shard"),
                _ => {}
            }
        }
        outcome
    }
}

#[test]
fn the_fresh_path_enrolls_its_pair_after_the_local_record_and_before_the_bump() {
    let store = store(shard_record(0), unactivated_record());
    let log = Log::default();
    let mut local = records(&log);
    let mut ordered = Client::open(
        Ordered {
            inner: store.clone(),
            log: log.clone(),
        },
        MemLog::default(),
    )
    .unwrap();
    let activated = fresh()
        .run(
            &mut ordered,
            &mut plane(),
            &mut local,
            &mut Card::new(&log),
            &mut Refusals::default(),
        )
        .unwrap();
    let (.., recorded, ended) = activated.into_parts();
    assert_eq!((recorded, ended), (vec![own()], Vec::new()));
    assert_eq!(log.borrow()[..4], ["record", "volume", "shard", "host"]);
    assert_eq!(
        log.borrow()
            .iter()
            .filter(|&&step| step == "volume")
            .count(),
        1,
        "the enrollment is the one volume-record write"
    );
    assert_eq!(
        local.released_at,
        Some(log.borrow().len()),
        "the retention is released after every logged step"
    );
    let enrolled = |store: &Shared| {
        client(store)
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap()
            .value()
            .clone()
    };
    assert_eq!(enrolled(&store).enrolled(host()), Some(own()));
    let issued = crate::failover::assignment_tests::record();
    let store = self::store(shard_record(0), unactivated_record());
    let log = Log::default();
    let mut local = Records {
        record: Some(issued.clone()),
        ..records(&log)
    };
    let requests = crate::storage::store::sim::Requests::default();
    let mut counted = Client::open(
        crate::storage::store::sim::Counting {
            store: store.clone(),
            requests: requests.clone(),
        },
        MemLog::default(),
    )
    .unwrap();
    let refused = fresh()
        .run(
            &mut counted,
            &mut plane(),
            &mut local,
            &mut Card::new(&log),
            &mut Refusals::default(),
        )
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::Persist(AdmissionError::Key),
            Some(Target::of(&shard_record(0)))
        ),
        "a local record under another key than the owner's attach entry's (KEY-PER-ATTACH)"
    );
    assert_ne!(
        Some(issued.pair().key),
        unactivated_record().attach_key(host())
    );
    assert_eq!(
        (log.borrow().len(), requests.seen().1),
        (0, 0),
        "no local-record write, store write request or device command"
    );
    assert_eq!(enrolled(&store), unactivated_record());
    assert_eq!(shard_now(&store).attempts, 0);
    let replayed = VolumeRecord {
        pairs: vec![RecordedPair {
            host: host(),
            pair: issued.pair(),
            attach: 0,
        }],
        ..volume_record()
    };
    let store = self::store(shard_record(0), replayed);
    let log = Log::default();
    let mut local = Records {
        record: Some(issued.clone()),
        ..records(&log)
    };
    let mut card = Card::new(&log);
    card.own = Some(issued.pair());
    run(&store, &mut plane(), &mut local, &mut card).unwrap();
    assert_eq!(
        log.borrow()[..2],
        ["record", "bump"],
        "a pair recorded under a key no entry derives replays with no enrollment write"
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Volume(volume_id())), 1);
    for commit in [false, true] {
        let store = self::store(shard_record(0), volume_record());
        for arm in [Arm::Pass, Arm::Pass, Arm::Timeout { commit }] {
            store.schedule(arm);
        }
        let log = Log::default();
        let mut local = records(&log);
        let refused = run(&store, &mut plane(), &mut local, &mut Card::new(&log)).unwrap_err();
        assert_eq!(
            (refused.check, refused.flip),
            (Check::EnrollWrite(StoreError::Unknown), None),
            "{commit}: an enrollment write of unknown outcome requests nothing"
        );
        assert_eq!(*log.borrow(), ["record"], "{commit}");
        assert_eq!(shard_now(&store).attempts, 0, "{commit}");
        run(&store, &mut plane(), &mut local, &mut Card::new(&log)).unwrap();
        assert_eq!(
            enrolled(&store).pairs,
            vec![RecordedPair {
                host: host(),
                pair: own(),
                attach: 0,
            }],
            "{commit}"
        );
    }
}

/// A checkpoint named after the bump fails the Confirm's condition; the Confirm's read then finds it and refuses
/// with the own target's flip.
#[test]
fn a_checkpoint_named_after_the_bump_refuses_the_confirm() {
    let store = store(shard_record(0), volume_record());
    let log = Log::default();
    let racing = store.clone();
    let mut local = Records {
        after_bump: Some(Box::new(move || {
            let mut writer = client(&racing);
            let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            let next = ShardRecord {
                checkpoint: Some(crate::failover::records::NamedCheckpoint {
                    slot: 0,
                    session: (3 << 32) | 2,
                    capture: 1,
                    units: 1,
                }),
                ..*read.value()
            };
            writer.replace(&read, next).unwrap();
        })),
        ..records(&log)
    };
    let refused = run(&store, &mut plane(), &mut local, &mut Card::new(&log)).unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::Named, Some(own_target()))
    );
    for page in 0..shard_record(0).pages.get() {
        assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), page)), 1);
    }
}

/// The refusal names the lowest page still unfenced after its fence steps, here page 1 after page 0 fenced in the
/// first round.
#[test]
fn an_unresolved_page_after_its_fence_steps_names_that_page() {
    let store = store(shard_record(0), volume_record());
    for arm in [Arm::Pass; 5] {
        store.schedule(arm);
    }
    for arm in [Arm::Pass, Arm::Unavailable, Arm::Pass] {
        store.schedule(arm);
    }
    for _ in 1..FENCE_ROUNDS {
        store.schedule(Arm::Unavailable);
    }
    let log = Log::default();
    let refused = run(
        &store,
        &mut plane(),
        &mut records(&log),
        &mut Card::new(&log),
    )
    .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::UnresolvedPage { page: 1 }, None)
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), 0)), 2);
    assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), 1)), 1);
}

/// The active volume as the flip leaves it: the owner's spare record in its fresh state.
fn unactivated_record() -> VolumeRecord {
    VolumeRecord {
        state: VolumeState::Fresh,
        ..volume_record()
    }
}

#[test]
fn a_standby_waits_for_the_fresh_owners_activation() {
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let store = store(shard_record(0), unactivated_record());
    let standby = Holder {
        host: Host::new(SPARE).unwrap(),
        instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
        ..holder()
    };
    let volume = Key::Volume(volume_id());
    let log = Log::default();
    let mut card = Card::new(&log);
    let raced = store.clone();
    let checked = Rc::new(std::cell::Cell::new(false));
    let seen = Rc::clone(&checked);
    card.on = Some((
        "register",
        Box::new(move || {
            let gate = StandbyGate::qualified();
            assert_eq!(shard_now(&raced).attempts, 1, "the bump committed");
            let before = raced.0.borrow().commit_count(&volume);
            assert_eq!(
                Reconciler::new(client(&raced)).record_standby(
                    &gate,
                    shard(),
                    volume_id(),
                    standby.host,
                    2,
                    &bounds_of(limits()),
                    &crate::failover::sim::binding(standby.host)
                ),
                Err(ReconcileError::Conflict)
            );
            assert_eq!(
                enroll_standby(
                    &gate,
                    shard(),
                    &standby,
                    &bounds_of(limits()),
                    &mut client(&raced),
                    |_| panic!("the standby persists nothing before the owner's activation")
                ),
                Err(StandbyRefusal::Tenure)
            );
            assert_eq!(raced.0.borrow().commit_count(&volume), before);
            seen.set(true);
        }),
    ));
    run(&store, &mut plane(), &mut records(&log), &mut card).unwrap();
    assert!(
        checked.get(),
        "the standby ran between the bump and the fresh Report"
    );
    let page = client(&store)
        .read::<CoveragePage>(Key::Page(shard(), 0))
        .unwrap();
    assert_eq!(page.value().fence >> 32, shard_record(0).generation.get());
    Reconciler::new(client(&store))
        .record_standby(
            &StandbyGate::qualified(),
            shard(),
            volume_id(),
            standby.host,
            2,
            &bounds_of(limits()),
            &crate::failover::sim::binding(standby.host),
        )
        .unwrap();
}
