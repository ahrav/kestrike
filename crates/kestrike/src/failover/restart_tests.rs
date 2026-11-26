use super::*;
use crate::failover::assignment_tests::record as local_record;
use crate::failover::attachments::{InstanceId, Peer};
use crate::failover::evidence::Registrant;
use crate::failover::poll_tests::volume as volume_of;
use crate::failover::record::Binding;
use crate::failover::records::{
    ATTEMPTS_MAX, AttachmentEvent, ERA, EventKind, Host, Layout, LayoutRefusal, Modification,
    RecordedPair, VolumeId, VolumeState,
};
use crate::failover::retire::{Admitted, Retirement, Stale};
use crate::failover::takeover::tests::lineage;
use crate::storage::gate_fixture::{ZeroClock, encode_report, limits};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store_tests::{client, record as shard_of, shard};

/// A restart defect a control plants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The restart refuses a resolvable recorded holder of another host at Report #1 as `RecordedHolder`.
    NoLineage,
    /// The lineage arm activates its session from the step-1 read and preempts with no bump.
    NoBump,
    /// The lineage arm registers and preempts before its bump.
    PreemptBeforeBump,
    /// The lineage arm fences from the step-1 read with no shard reread after Report #2.
    NoFinalReread,
    /// The lineage arm registers into a Report #1 table at `N_reg` (REGISTER-ROOM removed).
    NoRoom,
}

thread_local! {
    static PLANTED: std::cell::Cell<Option<Plant>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn planted(plant: Plant) -> bool {
    PLANTED.with(std::cell::Cell::get) == Some(plant)
}

pub(crate) fn with_plant<T>(plant: Plant, f: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = f();
    PLANTED.with(|cell| cell.set(None));
    out
}

pub(crate) fn volume_id() -> VolumeId {
    VolumeId::new(&local_record().binding().volume).unwrap()
}

pub(crate) fn host() -> Host {
    shard_of().owner
}

pub(crate) fn own() -> Pair {
    local_record().pair()
}

fn restart_holder() -> Holder {
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
    volume_record_of(volume_id(), host(), own())
}

/// `host` occupies the first attachment slot on `volume` and enrolls under `pair`.
pub(crate) fn volume_record_of(volume: VolumeId, host: Host, pair: Pair) -> VolumeRecord {
    VolumeRecord {
        volume,
        pairs: vec![RecordedPair {
            host,
            pair,
            attach: 0,
        }],
        ..volume_of(VolumeState::Active, host)
    }
}

pub(crate) fn store(shard: ShardRecord, volume: VolumeRecord) -> Shared {
    let store = Shared::new();
    seed(&store, shard, volume);
    store
}

/// `seed` adds `shard`, its coverage pages, and `volume` to `store`, preserving existing records.
pub(crate) fn seed(store: &Shared, shard: ShardRecord, volume: VolumeRecord) {
    let mut seed = client(store);
    seed.create_shard(shard).unwrap();
    seed.create(Key::Volume(volume.volume), volume).unwrap();
}

pub(crate) fn restart() -> Restart<'static> {
    restart_of(shard(), restart_holder())
}

pub(crate) fn restart_of(shard: Shard, holder: Holder) -> Restart<'static> {
    Restart {
        shard,
        holder,
        bounds: crate::storage::gate_fixture::bounds_of(limits()),
        limits: limits(),
        peers: &[],
        intervals: 4,
    }
}

pub(crate) fn shard_now(store: &Shared) -> ShardRecord {
    shard_now_of(store, shard())
}

pub(crate) fn shard_now_of(store: &Shared, shard: Shard) -> ShardRecord {
    *client(store)
        .read::<ShardRecord>(Key::Shard(shard))
        .unwrap()
        .value()
}

pub(crate) fn holder(pair: Pair, cntlid: u16) -> Registrant {
    Registrant {
        cntlid,
        pair,
        holder: true,
    }
}

fn foreign() -> Pair {
    crate::storage::gate_fixture::foreign()
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Fault {
    Start(Driver),
    Ready,
    HostId,
    FirstReportFails,
    /// The `nth` Report completes with the generic status `code`.
    ReportStatus(usize, u16),
    /// The `nth` Report returns its bytes short of the last entry's final byte.
    ReportTruncated(usize),
    Preempt(u16),
    /// The lineage arm's Register completes with the generic status `code`.
    Register(u16),
    PreemptUnregisters,
    PreemptLeaves(fn(&mut Vec<Registrant>)),
}

pub(crate) struct Card {
    pub(crate) log: Vec<&'static str>,
    pub(crate) entries: Vec<Registrant>,
    rtype: u8,
    exhid: Option<Exhid>,
    pub(crate) fault: Option<Fault>,
    /// The number of device commands that complete; every later command ends with no completion.
    pub(crate) stop_at: Option<usize>,
    on_report: Option<Box<dyn FnOnce()>>,
    /// The Report, counted from 1, after whose bytes `on_report` runs.
    on_report_at: usize,
    /// Runs before the Report's bytes are taken, so a sequence of another host may change the registration a
    /// Report then shows; `entries_from` supplies those entries when set.
    pub(crate) before_report: Option<Box<dyn FnOnce()>>,
    pub(crate) entries_from: Option<std::rc::Rc<std::cell::RefCell<Vec<Registrant>>>>,
    /// Traces each command, at its entry, in order with the store requests the recorder holds.
    pub(crate) trace: Option<crate::storage::store::sim::Recorder>,
    /// The keys the lineage preempts named, in order.
    pub(crate) preempted: Vec<crate::failover::identity::Key>,
    /// Runs once over the registrations after the lineage arm's Register completes, so another actor may change the
    /// record or the reservation before the preempt.
    pub(crate) after_register: Option<CardStep>,
    /// Runs once over the registrations after the lineage preempt completes.
    pub(crate) after_lineage: Option<CardStep>,
}

/// A step another actor takes inside a device command of the restart, over the card's registrations.
pub(crate) type CardStep = Box<dyn FnOnce(&mut Vec<Registrant>)>;

impl Card {
    pub(crate) fn new() -> Self {
        Self {
            log: Vec::new(),
            entries: vec![holder(own(), 1)],
            rtype: 2,
            exhid: None,
            fault: None,
            stop_at: None,
            on_report: None,
            on_report_at: 1,
            before_report: None,
            entries_from: None,
            trace: None,
            preempted: Vec::new(),
            after_register: None,
            after_lineage: None,
        }
    }

    fn command(&mut self, name: &'static str) -> Result<(), Failed> {
        if let Some(trace) = &self.trace {
            trace.device(name);
        }
        self.log.push(name);
        if self.stop_at.is_some_and(|at| self.log.len() > at) {
            return Err(Failed(None));
        }
        Ok(())
    }
}

impl Device for Card {
    fn start(&mut self) -> Result<(), Driver> {
        self.command("start").map_err(|_| Driver::LiveQueues)?;
        match self.fault {
            Some(Fault::Start(driver)) => Err(driver),
            _ => Ok(()),
        }
    }

    fn ready(&mut self) -> Result<(), Failed> {
        self.command("ready")?;
        match self.fault {
            Some(Fault::Ready) => Err(Failed(None)),
            _ => Ok(()),
        }
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        self.command("host")?;
        if matches!(self.fault, Some(Fault::HostId)) {
            return Err(Failed(None));
        }
        self.exhid = Some(exhid);
        Ok(())
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        self.command("report")?;
        let reports = self
            .log
            .iter()
            .filter(|&&command| command == "report")
            .count();
        if matches!(self.fault, Some(Fault::FirstReportFails)) {
            return Err(Failed(Some(DeviceStatus::Nvme(0x02 << 1))));
        }
        if let Some(Fault::ReportStatus(nth, code)) = self.fault
            && reports == nth
        {
            return Err(Failed(Some(DeviceStatus::Nvme(code << 1))));
        }
        if let Some(hook) = self.before_report.take() {
            hook();
        }
        if let Some(shared) = &self.entries_from {
            self.entries = shared.borrow().clone();
        }
        let mut bytes = encode_report(self.rtype, &self.entries);
        if matches!(self.fault, Some(Fault::ReportTruncated(nth)) if nth == reports) {
            bytes.pop();
        }
        if reports >= self.on_report_at
            && let Some(hook) = self.on_report.take()
        {
            hook();
        }
        Ok(bytes)
    }

    fn preempt(&mut self, preempt: SelfPreempt) -> Result<(), Failed> {
        self.command("preempt")?;
        assert_eq!(preempt.pair(), own(), "the preempt names the own pair");
        assert_eq!(
            self.exhid,
            Some(own().exhid),
            "the host ID is set before the preempt"
        );
        match self.fault {
            Some(Fault::Preempt(code)) => Err(Failed(Some(DeviceStatus::Nvme(code << 1)))),
            Some(Fault::PreemptUnregisters) => {
                self.entries.retain(|entry| entry.pair != own());
                self.rtype = 0;
                Ok(())
            }
            Some(Fault::PreemptLeaves(edit)) => {
                edit(&mut self.entries);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The lineage arm's Register adds the own pair as a registrant that holds nothing.
    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.command("register")?;
        assert_eq!(
            self.exhid,
            Some(own.exhid),
            "the host ID is set before the Register"
        );
        if let Some(Fault::Register(code)) = self.fault {
            return Err(Failed(Some(DeviceStatus::Nvme(code << 1))));
        }
        self.entries.push(Registrant {
            cntlid: 9,
            pair: own,
            holder: false,
        });
        if let Some(hook) = self.after_register.take() {
            hook(&mut self.entries);
        }
        Ok(())
    }

    /// The lineage preempt, as the shared reservation table applies it: an issuer that holds no registration gets a
    /// reservation conflict; otherwise the registrations under the preempted key leave, and the issuer becomes the one
    /// holder only when that key held the reservation.
    fn preempt_lineage(&mut self, preempt: LineagePreempt) -> Result<(), Failed> {
        self.command("lineage")?;
        assert_eq!(
            self.exhid,
            Some(preempt.pair().exhid),
            "the host ID is set before the preempt"
        );
        if let Some(Fault::Preempt(code)) = self.fault {
            return Err(Failed(Some(DeviceStatus::Nvme(code << 1))));
        }
        if !self
            .entries
            .iter()
            .any(|entry| entry.pair == preempt.pair())
        {
            return Err(Failed(Some(DeviceStatus::Nvme(0x83 << 1))));
        }
        self.preempted.push(preempt.preempted());
        let held = (self.entries.iter())
            .any(|entry| entry.holder && entry.pair.key == preempt.preempted());
        self.entries
            .retain(|entry| entry.pair.key != preempt.preempted());
        if held {
            for entry in &mut self.entries {
                entry.holder = entry.pair == preempt.pair();
            }
        }
        if let Some(hook) = self.after_lineage.take() {
            hook(&mut self.entries);
        }
        Ok(())
    }
}

pub(crate) struct Stored(pub(crate) Result<LocalRecord, Local>);

impl LocalSource for Stored {
    fn local(&self) -> Result<LocalRecord, Local> {
        self.0.clone()
    }
}

pub(crate) fn sample() -> Stored {
    Stored(Ok(local_record()))
}

fn bound(binding: Binding) -> LocalRecord {
    let pair = local_record().pair();
    LocalRecord::fresh(binding, pair.key, || Some(pair.exhid.bytes())).unwrap()
}

pub(crate) const FULL: [&str; 6] = ["start", "ready", "host", "report", "preempt", "report"];

/// The lineage arm's commands for a Report #1 that lists the own pair: the preempt names the holder's key.
pub(crate) const ARM: [&str; 6] = ["start", "ready", "host", "report", "lineage", "report"];

struct Case {
    name: &'static str,
    shard: ShardRecord,
    volume: VolumeRecord,
    local: Result<LocalRecord, Local>,
    card: Card,
    arms: Vec<Arm>,
    hook: Hook,
    issued: usize,
    flip: Flip,
    recovery: Flip,
    moved: bool,
    check: Check,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hook {
    None,
    Race,
    FailLog,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flip {
    None,
    Read,
    Bumped,
}

fn case(name: &'static str, issued: usize, check: Check) -> Case {
    Case {
        name,
        shard: shard_record(4),
        volume: volume_record(),
        local: Ok(local_record()),
        card: Card::new(),
        arms: Vec::new(),
        hook: Hook::None,
        issued,
        flip: Flip::Read,
        recovery: Flip::None,
        moved: false,
        check,
    }
}

fn torn_bytes() -> [u8; 512] {
    let mut bytes = local_record().encode().unwrap();
    bytes[200] ^= 1;
    bytes
}

fn torn() -> Result<LocalRecord, RecordError> {
    LocalRecord::decode(&torn_bytes())
}

fn step_one_rows() -> Vec<Case> {
    vec![
        Case {
            volume: VolumeRecord {
                state: VolumeState::Retired,
                ..volume_record()
            },
            ..case("records not active", 0, Check::Volume(Trigger::VolumeState))
        },
        Case {
            shard: ShardRecord {
                owner: Host::new(host().get() + 1).unwrap(),
                ..shard_record(4)
            },
            flip: Flip::None,
            ..case("owner changed", 0, Check::Deposed)
        },
        Case {
            shard: ShardRecord {
                active: VolumeId::new("vol-0c").unwrap(),
                ..shard_record(4)
            },
            flip: Flip::None,
            ..case("another active volume", 0, Check::Deposed)
        },
        Case {
            shard: shard_record(0),
            flip: Flip::None,
            ..case("E = 0 awaits the fresh path", 0, Check::Fresh)
        },
        Case {
            arms: vec![Arm::Unavailable],
            flip: Flip::None,
            ..case(
                "volume record unavailable",
                0,
                Check::Records(StoreError::Unavailable),
            )
        },
        Case {
            arms: vec![Arm::Pass, Arm::Unavailable],
            flip: Flip::None,
            ..case(
                "shard record unavailable",
                0,
                Check::Records(StoreError::Unavailable),
            )
        },
        Case {
            volume: VolumeRecord {
                layout: Layout {
                    slots: 2,
                    ..volume_record().layout
                },
                ..volume_record()
            },
            ..case(
                "layout with too few slots",
                0,
                Check::Volume(Trigger::Layout(LayoutRefusal::TooFewSlots { slots: 2 })),
            )
        },
        Case {
            volume: VolumeRecord {
                next: 4,
                events: (0..4)
                    .map(|at| AttachmentEvent {
                        seq: at as u32,
                        kind: EventKind::Attach,
                        host: Host::new(host().get() + at).unwrap(),
                        era: ERA,
                        instance: None,
                    })
                    .collect(),
                pairs: (0..4)
                    .map(|at| RecordedPair {
                        host: Host::new(host().get() + u64::from(at)).unwrap(),
                        pair: match at {
                            0 => own(),
                            _ => Pair {
                                exhid: Exhid::new([0x60 + at as u8; 16]).unwrap(),
                                key: crate::failover::identity::Key::decode(
                                    (3 << 32) | u64::from(at + 10),
                                )
                                .unwrap(),
                            },
                        },
                        attach: at,
                    })
                    .collect(),
                ..volume_record()
            },
            ..case(
                "fourth enrolled live attachment",
                0,
                Check::Volume(Trigger::Events),
            )
        },
        Case {
            volume: VolumeRecord {
                modification: Some(Modification::InProgress),
                ..volume_record()
            },
            ..case("modification", 0, Check::Volume(Trigger::Modification))
        },
        Case {
            volume: {
                let mut forced = volume_record();
                forced.push(EventKind::Force, host(), ERA);
                forced
            },
            ..case("force", 0, Check::Volume(Trigger::Events))
        },
        Case {
            shard: ShardRecord {
                generation: crate::net::ownership::ShardGeneration::new(u64::from(u32::MAX))
                    .unwrap(),
                ..shard_record(4)
            },
            ..case(
                "generation exhausted",
                0,
                Check::Exhausted(SessionRefusal::GenerationExhausted),
            )
        },
        Case {
            shard: shard_record(ATTEMPTS_MAX),
            ..case(
                "attempts exhausted",
                0,
                Check::Exhausted(SessionRefusal::AttemptsExhausted),
            )
        },
    ]
}

fn local_rows() -> Vec<Case> {
    vec![
        Case {
            local: Err(Local::Absent),
            flip: Flip::None,
            ..case("local record absent", 0, Check::Local(Local::Absent))
        },
        Case {
            local: Err(Local::Unreadable),
            flip: Flip::None,
            ..case(
                "local record unreadable",
                0,
                Check::Local(Local::Unreadable),
            )
        },
        Case {
            local: torn().map_err(Local::Invalid),
            flip: Flip::None,
            ..case(
                "local record torn",
                0,
                Check::Local(Local::Invalid(RecordError::Torn)),
            )
        },
        Case {
            local: Ok(crate::failover::assignment_tests::other_record()),
            flip: Flip::None,
            ..case(
                "local record bound to another volume",
                0,
                Check::Local(Local::Binding),
            )
        },
        Case {
            local: Ok(bound(Binding {
                instance: "i-0fffffffffffffff0".into(),
                ..local_record().binding().clone()
            })),
            flip: Flip::None,
            ..case(
                "local record of this volume bound to another instance",
                0,
                Check::Local(Local::Binding),
            )
        },
    ]
}

fn device_rows() -> Vec<Case> {
    let with = |mut row: Case, fault| {
        row.card.fault = Some(fault);
        row
    };
    // DEVICE-FAILURE-HOLD: a host-local driver refusal and a device step that ends without success, with no
    // completion, a generic status or a deposing one, show no volume loss. Each refuses with no flip and names the
    // step-1 target as the recovery hint.
    let hold = |mut row: Case| {
        (row.flip, row.recovery) = (Flip::None, Flip::Read);
        row
    };
    vec![
        hold(with(
            case("live queues", 1, Check::Driver(Driver::LiveQueues)),
            Fault::Start(Driver::LiveQueues),
        )),
        hold(with(
            case("kernel binding", 1, Check::Driver(Driver::KernelBinding)),
            Fault::Start(Driver::KernelBinding),
        )),
        hold(with(
            case(
                "Report #1 reservation conflict",
                4,
                Check::FirstReport(Failed(Some(DeviceStatus::Nvme(0x83 << 1)))),
            ),
            Fault::ReportStatus(1, 0x83),
        )),
        hold(with(
            case("controller not ready", 2, Check::Ready(Failed(None))),
            Fault::Ready,
        )),
        hold(with(
            case("host ID unset", 3, Check::HostId(Failed(None))),
            Fault::HostId,
        )),
        hold(with(
            case(
                "Report #1 fails",
                4,
                Check::FirstReport(Failed(Some(DeviceStatus::Nvme(0x02 << 1)))),
            ),
            Fault::FirstReportFails,
        )),
        with(
            report_row(
                "Report #1 truncated",
                Some(NotSole::Unreadable),
                ReportStep::First,
            ),
            Fault::ReportTruncated(1),
        ),
    ]
}

type Edit = fn(&mut Vec<Registrant>);

/// Each edit of a Report's registrants and the refusal it yields, `None` for `Check::Unheld`: a Report with nobody
/// holding beside the own pair and recorded pairs only shows a registration that ended without a preempt, no volume
/// loss, so it holds with no flip and the recovery hint (NO-HOLDER-HOLD), and every other edit keeps its refusal and
/// its flip, nobody holding beside an unrecorded registrant included.
const REGISTRANT_EDITS: [(&str, &str, Option<NotSole>, Edit); 6] = [
    (
        "Report #1 without registration",
        "Report #2 without the own entry",
        None,
        |entries| entries.clear(),
    ),
    (
        "Report #1 own pair registered without holding",
        "Report #2 own entry without holding",
        None,
        |entries| entries[0].holder = false,
    ),
    (
        "Report #1 foreign holder",
        "Report #2 foreign holder",
        Some(NotSole::ForeignHolder),
        |entries| {
            entries[0].holder = false;
            entries.push(holder(foreign(), 2));
        },
    ),
    (
        "Report #1 foreign registrant",
        "Report #2 foreign registrant",
        Some(NotSole::ForeignRegistrant),
        |entries| {
            entries.push(Registrant {
                holder: false,
                ..holder(foreign(), 2)
            });
        },
    ),
    (
        "Report #1 nobody holding beside an unrecorded registrant",
        "Report #2 nobody holding beside an unrecorded registrant",
        Some(NotSole::ForeignRegistrant),
        |entries| {
            entries[0].holder = false;
            entries.push(Registrant {
                holder: false,
                ..holder(foreign(), 2)
            });
        },
    ),
    (
        "Report #1 duplicate own record",
        "Report #2 duplicate own record",
        Some(NotSole::DuplicateOwnRecord),
        |entries| {
            entries.push(Registrant {
                holder: false,
                ..holder(
                    Pair {
                        key: foreign().key,
                        ..own()
                    },
                    2,
                )
            });
        },
    ),
];

#[derive(Clone, Copy, Debug)]
enum ReportStep {
    First,
    Second,
}

/// The row of `refusal` at the Report of `step`, with the step's command count, refusal and flip target: an observed
/// refusal requests the flip, and an unreadable Report (DEVICE-FAILURE-HOLD) and a `None` refusal (`Check::Unheld`)
/// hold with no flip and that target as the recovery hint.
fn report_row(name: &'static str, refusal: Option<NotSole>, step: ReportStep) -> Case {
    let (issued, flip, refused): (usize, Flip, fn(NotSole) -> Check) = match step {
        ReportStep::First => (4, Flip::Read, Check::NotHolding),
        ReportStep::Second => (6, Flip::Bumped, Check::NotSole),
    };
    match refusal {
        Some(refusal) if refusal.observed() => Case {
            flip,
            ..case(name, issued, refused(refusal))
        },
        Some(refusal) => Case {
            flip: Flip::None,
            recovery: flip,
            ..case(name, issued, refused(refusal))
        },
        None => Case {
            flip: Flip::None,
            recovery: flip,
            ..case(name, issued, Check::Unheld)
        },
    }
}

fn first_report_rows() -> Vec<Case> {
    let mut rtype = report_row("Report #1 rtype 0", None, ReportStep::First);
    rtype.card.rtype = 0;
    // Under rtype 0 the Report refuses `ReservationType` before any registrant check, so NO-HOLDER-HOLD's own-record
    // and membership tests alone keep these two refusals and their flips.
    let mut stranger = report_row(
        "Report #1 rtype 0 beside an unrecorded registrant",
        Some(NotSole::ReservationType),
        ReportStep::First,
    );
    stranger.card.rtype = 0;
    stranger.card.entries.push(Registrant {
        holder: false,
        ..holder(foreign(), 2)
    });
    let mut twice = report_row(
        "Report #1 rtype 0 with the own pair twice",
        Some(NotSole::ReservationType),
        ReportStep::First,
    );
    twice.card.rtype = 0;
    let own_entry = twice.card.entries[0];
    twice.card.entries.push(Registrant {
        holder: false,
        ..own_entry
    });
    // A racing bump after Report #1 moves the record past the step-1 target, so the observed refusal's flip admits
    // as stale.
    let mut raced = report_row(
        "Report #1 foreign registrant behind a racing bump",
        Some(NotSole::ForeignRegistrant),
        ReportStep::First,
    );
    raced.card.entries.push(Registrant {
        holder: false,
        ..holder(foreign(), 2)
    });
    (raced.hook, raced.moved) = (Hook::Race, true);
    let mut rows = vec![rtype, stranger, twice, raced];
    for (name, _, refusal, edit) in REGISTRANT_EDITS {
        let mut row = report_row(name, refusal, ReportStep::First);
        edit(&mut row.card.entries);
        rows.push(row);
    }
    rows
}

/// DEVICE-FAILURE-HOLD: a bump without an acknowledged success shows a store fault, no volume loss, so every bump
/// arm holds with no flip. The hint names the step-1 target, or the bumped target once the client saw the commit.
fn bump_rows() -> Vec<Case> {
    let bump = |name, arm, moved| Case {
        arms: vec![Arm::Pass, Arm::Pass, Arm::Pass, arm],
        moved,
        flip: Flip::None,
        recovery: Flip::Read,
        ..case(name, 4, Check::Bump(StoreError::Unknown))
    };
    vec![
        Case {
            hook: Hook::Race,
            check: Check::Bump(StoreError::Refused(
                crate::storage::store::Refusal::Condition,
            )),
            arms: Vec::new(),
            ..bump("CAS failure", Arm::Pass, true)
        },
        bump(
            "CAS timeout that commits",
            Arm::Timeout { commit: true },
            true,
        ),
        bump(
            "CAS timeout that does not commit",
            Arm::Timeout { commit: false },
            false,
        ),
        bump(
            "CAS acknowledgment lost",
            Arm::Failure { commit: true },
            true,
        ),
        bump("CAS unavailable", Arm::Unavailable, false),
        Case {
            hook: Hook::FailLog,
            flip: Flip::None,
            recovery: Flip::Bumped,
            ..case(
                "watermark log fails after the commit",
                4,
                Check::Bump(StoreError::Log),
            )
        },
    ]
}

fn second_report_rows() -> Vec<Case> {
    let after_preempt = |name, check, fault| {
        let mut row = case(name, 5, check);
        row.card.fault = Some(fault);
        row
    };
    // DEVICE-FAILURE-HOLD: the self preempt or Report #2 ending without success, with no completion, a generic
    // status or a deposing one (STATUS-IS-DEPOSITION), and an unreadable Report #2 hold the volume with the bumped
    // target as the recovery hint and no flip; the rerun's Report #1 judges the holder.
    let hold = |mut row: Case| {
        (row.flip, row.recovery) = (Flip::None, Flip::Bumped);
        row
    };
    let mut fails = case("Report #2 fails", 6, Check::SecondReport(Failed(None)));
    fails.card.stop_at = Some(5);
    let mut second_status = case(
        "Report #2 generic status",
        6,
        Check::SecondReport(Failed(Some(DeviceStatus::Nvme(0x02 << 1)))),
    );
    second_status.card.fault = Some(Fault::ReportStatus(2, 0x02));
    let mut truncated = report_row(
        "Report #2 truncated",
        Some(NotSole::Unreadable),
        ReportStep::Second,
    );
    truncated.card.fault = Some(Fault::ReportTruncated(2));
    let generic = after_preempt(
        "Preempt-and-Abort generic status",
        Check::Preempt(Failed(Some(DeviceStatus::Nvme(0x02 << 1)))),
        Fault::Preempt(0x02),
    );
    let conflict = after_preempt(
        "Preempt-and-Abort conflict",
        Check::Preempt(Failed(Some(DeviceStatus::Nvme(0x83 << 1)))),
        Fault::Preempt(0x83),
    );
    let aborted = after_preempt(
        "Preempt-and-Abort aborted",
        Check::Preempt(Failed(Some(DeviceStatus::Nvme(0x1B << 1)))),
        Fault::Preempt(0x1B),
    );
    let mut deposed_second = case(
        "Report #2 preempt aborted",
        6,
        Check::SecondReport(Failed(Some(DeviceStatus::Nvme(0x1B << 1)))),
    );
    deposed_second.card.fault = Some(Fault::ReportStatus(2, 0x1B));
    let mut unregistered = report_row("Report #2 unregistered", None, ReportStep::Second);
    unregistered.card.fault = Some(Fault::PreemptUnregisters);
    let mut rows = vec![
        hold(conflict),
        hold(aborted),
        hold(deposed_second),
        hold(fails),
        hold(second_status),
        hold(generic),
        truncated,
        unregistered,
    ];
    for (_, name, refusal, edit) in REGISTRANT_EDITS {
        let mut row = report_row(name, refusal, ReportStep::Second);
        row.card.fault = Some(Fault::PreemptLeaves(edit));
        rows.push(row);
    }
    rows
}

fn cases() -> Vec<Case> {
    let mut rows = step_one_rows();
    rows.extend(local_rows());
    rows.extend(device_rows());
    rows.extend(first_report_rows());
    rows.extend(bump_rows());
    rows.extend(second_report_rows());
    rows
}

/// The refusal witness of every `cases()` row over `run`: the row's check, no device command after the refusal, the
/// flip request, the recovery hint, the bumps the shard record shows and the reconciler's verdict on the flip.
fn refuses_every_row(
    run: impl Fn(&mut Client<Shared, MemLog>, &Stored, &mut Card) -> Result<Restarted, Refused>,
) {
    for mut row in cases() {
        let store = store(row.shard, row.volume.clone());
        let log = MemLog::default();
        row.card.on_report = match row.hook {
            Hook::None => None,
            Hook::Race => {
                let racer = store.clone();
                Some(Box::new(move || {
                    let mut other = client(&racer);
                    let read = other.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                    other.bump(&read).unwrap();
                }))
            }
            Hook::FailLog => {
                let fail = log.fail.clone();
                Some(Box::new(move || fail.set(true)))
            }
        };
        for arm in &row.arms {
            store.schedule(*arm);
        }
        let read = row.shard;
        let mut restarting = Client::open(store.clone(), log).unwrap();
        let refused =
            run(&mut restarting, &Stored(row.local.clone()), &mut row.card).expect_err(row.name);
        assert_eq!(refused.check, row.check, "{}", row.name);
        assert_eq!(
            row.card.log,
            FULL[..row.issued],
            "{}: no device command after the refusal",
            row.name
        );
        let expected = |flip| match flip {
            Flip::None => None,
            Flip::Read => Some(Target::of(&read)),
            Flip::Bumped => Some(Target {
                attempts: read.attempts + 1,
                ..Target::of(&read)
            }),
        };
        assert_eq!(
            refused.flip,
            expected(row.flip),
            "{}: the flip request",
            row.name
        );
        assert_eq!(
            refused.recovery,
            expected(row.recovery),
            "{}: the recovery hint",
            row.name
        );
        let after = shard_now(&store);
        let bumps =
            u32::from(row.moved || Flip::Bumped == row.flip || Flip::Bumped == row.recovery);
        assert_eq!(
            after.attempts,
            read.attempts + bumps,
            "{}: the bump follows Report #1's verdict",
            row.name
        );
        if let Some(target) = refused.flip {
            let admitted = Retirement::new(volume_id(), Role::Active, target, Trigger::Events)
                .unwrap()
                .admit(&after);
            let expected = if row.moved {
                Err(Stale::Target)
            } else {
                Ok(Admitted::Flip)
            };
            assert_eq!(admitted, expected, "{}: the reconciler's verdict", row.name);
        }
    }
}

/// Each row's check refuses with its flip and recovery hint and no later device command. A Report with nobody
/// holding beside the own pair and recorded pairs, the rtype-0, unregistered and own-not-holding rows at Report #1 and
/// #2, refuses `Unheld` with no flip and the Report's tenure as the hint (NO-HOLDER-HOLD): such a Report shows a
/// registration that ended without a preempt, which host loss leaves and which is no evidence of volume loss. Every
/// driver, device-step, unreadable-Report and bump row holds the same way (DEVICE-FAILURE-HOLD): a missing
/// completion, a status, unparseable bytes or a store fault shows no volume loss. Only the rows on observed evidence
/// or exhausted counters request the flip, which the reconciler admits against the record after the refusal.
#[test]
fn refuse_at_each_check() {
    refuses_every_row(|client, local, card| restart().run(client, local, card));
}

/// The negative control "a device command after the refusal": a restart that refuses as the production sequence
/// does and then waits for the device once more leaves one command past the row's issued prefix, so the witness
/// rejects it at its first row.
#[test]
#[should_panic(expected = "no device command after the refusal")]
fn negative_control_a_restart_that_commands_the_device_after_its_refusal() {
    refuses_every_row(|client, local, card| {
        let refused = restart().run(client, local, card);
        if refused.is_err() {
            let _ = card.ready();
        }
        refused
    });
}

/// Every `Check` falls in exactly one class: the flip on observed evidence or exhausted counters, the hold with a
/// recovery hint (DEVICE-FAILURE-HOLD), or neither. The match names every variant, so a new one cannot compile
/// without a class. A Report refusal flips exactly when its retirement trigger retires (ACTIONABLE-TRIGGER), the
/// evidence rule `Retirement::new` applies.
#[test]
fn a_restart_flips_only_on_observed_evidence() {
    use crate::failover::evidence::{PREEMPT_ABORTED, RESERVATION_CONFLICT};
    use crate::storage::page_coverage::{FenceRefused, FencingRefusal, Withdraw};
    use crate::storage::store::{Refusal, Regression};
    use Disposition as Class;
    let refusals = [
        NotSole::Excess,
        NotSole::Unreadable,
        NotSole::ReservationType,
        NotSole::DuplicateOwnRecord,
        NotSole::ForeignHolder,
        NotSole::ForeignRegistrant,
        NotSole::NotHolder,
    ];
    let failed = [
        None,
        Some(0x02),
        Some(RESERVATION_CONFLICT),
        Some(PREEMPT_ABORTED),
    ]
    .map(|status| Failed(status.map(|code| DeviceStatus::Nvme(code << 1))));
    let mut checks = vec![
        Check::Records(StoreError::Unavailable),
        Check::Deposed,
        Check::RecordedHolder,
        Check::Unheld,
        Check::Fresh,
        Check::SuffixOnly,
        Check::Coverage(FenceRefused::Fencing(FencingRefusal::PageCap)),
        Check::Coverage(FenceRefused::Fence(Withdraw::NewerFence {
            page: 0,
            fence: 9,
        })),
        Check::Coverage(FenceRefused::Fence(Withdraw::Store(
            StoreError::Unavailable,
        ))),
        Check::Coverage(FenceRefused::Unresolved { page: 0 }),
        Check::Volume(Trigger::VolumeState),
        Check::Volume(Trigger::Events),
        Check::Volume(Trigger::Modification),
        Check::Volume(Trigger::Layout(LayoutRefusal::TooFewSlots { slots: 2 })),
        Check::Exhausted(SessionRefusal::GenerationExhausted),
        Check::Exhausted(SessionRefusal::AttemptsExhausted),
        Check::Unobserved,
        Check::Driver(Driver::LiveQueues),
        Check::Driver(Driver::KernelBinding),
        Check::Bump(StoreError::Unavailable),
        Check::Bump(StoreError::Unknown),
        Check::Bump(StoreError::Refused(Refusal::Condition)),
        Check::Bump(StoreError::Log),
        Check::Bump(StoreError::Regression(Regression::Value(Key::Shard(
            shard(),
        )))),
    ];
    checks.extend(
        [
            Local::Absent,
            Local::Unreadable,
            Local::Invalid(RecordError::Torn),
            Local::Binding,
            Local::Retained,
            Local::Unenrolled,
            Local::Altered,
        ]
        .map(Check::Local),
    );
    for failed in failed {
        checks.extend([
            Check::Ready(failed),
            Check::HostId(failed),
            Check::FirstReport(failed),
            Check::Preempt(failed),
            Check::SecondReport(failed),
        ]);
    }
    for failed in failed {
        checks.extend([
            Check::Lineage(Lineage::Register(failed)),
            Check::Lineage(Lineage::Preempt(failed)),
        ]);
    }
    checks.push(Check::Lineage(Lineage::Superseded));
    checks.push(Check::Lineage(Lineage::Full));
    checks.extend(refusals.map(Check::NotHolding));
    checks.extend(refusals.map(Check::NotSole));
    for check in checks {
        let class = match &check {
            Check::Volume(_) | Check::Exhausted(_) => Class::Flip,
            Check::Local(Local::Retained) => Class::Flip,
            Check::NotHolding(refusal) | Check::NotSole(refusal) => {
                assert_eq!(
                    disposition(&check) == Class::Flip,
                    Trigger::Report(*refusal).retires(),
                    "{check:?}: the flip follows the trigger's evidence rule"
                );
                if refusal.observed() {
                    Class::Flip
                } else {
                    Class::Hold
                }
            }
            Check::RecordedHolder
            | Check::Lineage(_)
            | Check::Unheld
            | Check::Unobserved
            | Check::Driver(_)
            | Check::Coverage(_)
            | Check::Ready(_)
            | Check::HostId(_)
            | Check::FirstReport(_)
            | Check::Bump(_)
            | Check::Preempt(_)
            | Check::SecondReport(_) => Class::Hold,
            Check::Records(_)
            | Check::Deposed
            | Check::Fresh
            | Check::SuffixOnly
            | Check::Local(_) => Class::Neither,
        };
        assert_eq!(disposition(&check), class, "{check:?}");
    }
}

fn reach_fb(store: &Shared, card: &mut Card, local: &impl LocalSource) -> Restarted {
    card.log.clear();
    let restarted = restart().run(&mut client(store), local, card).unwrap();
    assert_eq!(card.log, FULL);
    assert_eq!(restarted.fenced().own(), own());
    restarted
}

#[derive(Clone, Copy, Debug)]
enum Crash {
    Device(usize),
    Bump(Arm),
    AfterFb,
}

#[test]
fn crash_at_each_step() {
    let mut crashes: Vec<Crash> = (0..FULL.len()).map(Crash::Device).collect();
    crashes.extend([
        Crash::Bump(Arm::Unavailable),
        Crash::Bump(Arm::Timeout { commit: false }),
        Crash::Bump(Arm::Timeout { commit: true }),
        Crash::Bump(Arm::Failure { commit: true }),
        Crash::AfterFb,
    ]);
    let n = 4;
    let read = Target::of(&shard_record(n));
    let bumped = Target {
        attempts: n + 1,
        ..read
    };
    for crash in crashes {
        let store = store(shard_record(n), volume_record());
        let mut card = Card::new();
        let mut activated = Vec::new();
        match crash {
            Crash::Device(at) => {
                card.stop_at = Some(at);
                let refused = restart()
                    .run(&mut client(&store), &sample(), &mut card)
                    .expect_err("the crash refuses");
                let check = match at {
                    0 => Check::Driver(Driver::LiveQueues),
                    1 => Check::Ready(Failed(None)),
                    2 => Check::HostId(Failed(None)),
                    3 => Check::FirstReport(Failed(None)),
                    4 => Check::Preempt(Failed(None)),
                    _ => Check::SecondReport(Failed(None)),
                };
                // DEVICE-FAILURE-HOLD: a crash at any device step, the driver start included, holds with no flip and
                // names the step-1 target, or the bumped target after the bump, as the recovery hint.
                let hint = if at >= 4 { bumped } else { read };
                assert_eq!(
                    (refused.check, refused.flip, refused.recovery),
                    (check, None, Some(hint)),
                    "{crash:?}"
                );
                assert_eq!(
                    card.log.len(),
                    at + 1,
                    "{crash:?}: the process stops at its crash"
                );
                card.stop_at = None;
            }
            Crash::Bump(arm) => {
                store.schedule(Arm::Pass);
                store.schedule(Arm::Pass);
                store.schedule(Arm::Pass);
                store.schedule(arm);
                let refused = restart()
                    .run(&mut client(&store), &sample(), &mut card)
                    .expect_err("the crash refuses");
                assert_eq!(refused.check, Check::Bump(StoreError::Unknown), "{crash:?}");
                assert_eq!(
                    (refused.flip, refused.recovery),
                    (None, Some(read)),
                    "{crash:?}: an unknown bump outcome holds"
                );
            }
            Crash::AfterFb => {
                let first = reach_fb(&store, &mut card, &sample());
                activated.push(first.session.get());
            }
        }
        let after = shard_record(shard_now(&store).attempts);
        let committed = after.attempts - n;
        let expected = match crash {
            Crash::Device(at) => u32::from(at >= 4),
            Crash::Bump(Arm::Timeout { commit } | Arm::Failure { commit }) => u32::from(commit),
            Crash::Bump(_) => 0,
            Crash::AfterFb => 1,
        };
        assert_eq!(
            committed, expected,
            "{crash:?}: the shard record after the crash"
        );
        let next = reach_fb(&store, &mut card, &sample());
        assert_eq!(
            next.session.epoch().get(),
            2 * after.attempts + 2,
            "{crash:?}"
        );
        activated.push(next.session.get());
        assert!(
            activated.len() < 2 || activated[0] != activated[1],
            "{crash:?}: sessions"
        );
        let final_attempts = shard_now(&store).attempts;
        assert_eq!(final_attempts, after.attempts + 1, "{crash:?}");
        let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
        assert_eq!(
            commits as u32,
            1 + final_attempts - n,
            "{crash:?}: every commit after the creation raised E by one"
        );
    }
}

/// A self Preempt-and-Abort that succeeds while unregistering its caller leaves nobody holding. Report #2 and the
/// rerun's Report #1 each refuse `Unheld` with no flip and the bumped target as the recovery hint (NO-HOLDER-HOLD): a
/// registration that ended without a preempt of another pair shows no volume loss, so the retained volume stays
/// active; the rerun issues no preempt and no bump.
#[test]
fn a_rerun_after_an_unregistering_preempt_refuses_at_report_1() {
    let n = 4;
    let store = store(shard_record(n), volume_record());
    let mut card = Card::new();
    card.fault = Some(Fault::PreemptUnregisters);
    let bumped = Target {
        attempts: n + 1,
        ..Target::of(&shard_record(n))
    };
    let first = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("Report #2 refuses");
    assert_eq!(
        (first.check, first.flip, first.recovery),
        (Check::Unheld, None, Some(bumped))
    );
    card.log.clear();
    let rerun = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("Report #1 refuses");
    assert_eq!(
        (rerun.check, rerun.flip, rerun.recovery),
        (Check::Unheld, None, Some(bumped))
    );
    assert_eq!(card.log, FULL[..4]);
    assert_eq!(shard_now(&store).attempts, n + 1);
}

/// DEVICE-FAILURE-HOLD after NO-HOLDER-HOLD: a self preempt that unregisters its caller leaves Report #2 refusing
/// `Unheld`. Each rerun whose ready wait, host ID or Report #1 then fails, with no completion, a generic status or
/// unparseable bytes, holds with no flip and the bumped target as the hint, and leaves the shard and volume records at their versions,
/// so a transient fault on a rerun cannot turn the hold into a cold replacement. The next clean rerun refuses `Unheld`
/// again.
#[test]
fn an_unheld_hold_survives_a_rerun_whose_device_step_fails() {
    let n = 4;
    let store = store(shard_record(n), volume_record());
    let mut card = Card::new();
    card.fault = Some(Fault::PreemptUnregisters);
    let bumped = Target {
        attempts: n + 1,
        ..Target::of(&shard_record(n))
    };
    let first = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("Report #2 refuses");
    assert_eq!((first.check, first.flip), (Check::Unheld, None));
    let versions = |store: &Shared| {
        let mut reader = client(store);
        (
            reader
                .read::<ShardRecord>(Key::Shard(shard()))
                .unwrap()
                .version(),
            reader
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap()
                .version(),
        )
    };
    let held = versions(&store);
    let reruns: [(Option<Fault>, Option<usize>, Check); 5] = [
        (Some(Fault::Ready), None, Check::Ready(Failed(None))),
        (Some(Fault::HostId), None, Check::HostId(Failed(None))),
        (None, Some(3), Check::FirstReport(Failed(None))),
        (
            Some(Fault::FirstReportFails),
            None,
            Check::FirstReport(Failed(Some(DeviceStatus::Nvme(0x02 << 1)))),
        ),
        (
            Some(Fault::ReportTruncated(1)),
            None,
            Check::NotHolding(NotSole::Unreadable),
        ),
    ];
    for (fault, stop_at, check) in reruns {
        (card.fault, card.stop_at) = (fault, stop_at);
        card.log.clear();
        let rerun = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .expect_err("the rerun's device step fails");
        assert_eq!(
            (rerun.check, rerun.flip, rerun.recovery),
            (check.clone(), None, Some(bumped)),
            "{check:?}"
        );
        assert_eq!(versions(&store), held, "{check:?}: no record write");
    }
    (card.fault, card.stop_at) = (None, None);
    card.log.clear();
    let last = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("the clean rerun refuses at Report #1");
    assert_eq!(
        (last.check, last.flip, last.recovery),
        (Check::Unheld, None, Some(bumped))
    );
    assert_eq!(card.log, FULL[..4]);
    assert_eq!(versions(&store), held);
}

/// A hold on a transient device failure, a generic status or an unreadable Report, ends with the rerun once the fault
/// clears; `crash_at_each_step` covers the steps that end with no completion. A failure before the bump
/// consumes no `E`, so the rerun activates `2n + 2`; a failure after the bump consumed one, so the rerun takes the
/// next `E` through its own bump and activates `2(n + 1) + 2`, never the held attempt's session (NoEpochReuse).
#[test]
fn a_rerun_after_each_held_device_failure_reaches_fb() {
    let n = 4;
    let status = |code: u16| Failed(Some(DeviceStatus::Nvme(code << 1)));
    let faults: [(Option<Fault>, Option<usize>, Check, u32); 5] = [
        (
            Some(Fault::FirstReportFails),
            None,
            Check::FirstReport(status(0x02)),
            0,
        ),
        (
            Some(Fault::ReportTruncated(1)),
            None,
            Check::NotHolding(NotSole::Unreadable),
            0,
        ),
        (
            Some(Fault::Preempt(0x02)),
            None,
            Check::Preempt(status(0x02)),
            1,
        ),
        (
            Some(Fault::ReportStatus(2, 0x02)),
            None,
            Check::SecondReport(status(0x02)),
            1,
        ),
        (
            Some(Fault::ReportTruncated(2)),
            None,
            Check::NotSole(NotSole::Unreadable),
            1,
        ),
    ];
    for (fault, stop_at, check, consumed) in faults {
        let store = store(shard_record(n), volume_record());
        let mut card = Card::new();
        (card.fault, card.stop_at) = (fault, stop_at);
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .expect_err("the device step fails");
        let held = Target {
            attempts: n + consumed,
            ..Target::of(&shard_record(n))
        };
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (check.clone(), None, Some(held)),
            "{check:?}"
        );
        assert_eq!(shard_now(&store).attempts, n + consumed, "{check:?}");
        (card.fault, card.stop_at) = (None, None);
        let rerun = reach_fb(&store, &mut card, &sample());
        assert_eq!(
            rerun.session.epoch().get(),
            2 * (n + consumed) + 2,
            "{check:?}: the rerun's own bump"
        );
        assert_eq!(shard_now(&store).attempts, n + consumed + 1, "{check:?}");
    }
}

/// An unknown bump outcome and the rerun's bump that loses to its late commit each hold with no flip and the step-1
/// target as the hint (DEVICE-FAILURE-HOLD), and the next run activates the next epoch.
#[test]
fn a_late_commit_of_an_earlier_bump_refuses_the_rerun_and_the_next_run_takes_the_next_epoch() {
    let n = 4;
    let store = store(shard_record(n), volume_record());
    let read = Target::of(&shard_record(n));
    let mut card = Card::new();
    store.schedule(Arm::Pass);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Hold);
    let first = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("the held bump has an unknown outcome");
    assert_eq!(
        (first.check, first.flip, first.recovery),
        (Check::Bump(StoreError::Unknown), None, Some(read))
    );
    assert_eq!(
        shard_now(&store).attempts,
        n,
        "the held bump has not applied"
    );
    card.log.clear();
    let releasing = store.clone();
    card.on_report = Some(Box::new(move || {
        releasing.release();
    }));
    let rerun = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect_err("the rerun's bump loses to the late commit");
    assert_eq!(
        rerun.check,
        Check::Bump(StoreError::Refused(
            crate::storage::store::Refusal::Condition
        ))
    );
    assert_eq!((rerun.flip, rerun.recovery), (None, Some(read)));
    assert_eq!(shard_now(&store).attempts, n + 1);
    let third = reach_fb(&store, &mut card, &sample());
    assert_eq!(third.session.epoch().get(), 2 * (n + 1) + 2);
    assert_eq!(shard_now(&store).attempts, n + 2);
}

struct Skewed(Shared);

impl crate::storage::store::Store for Skewed {
    fn namespace(&self) -> crate::failover::records::Namespace {
        self.0.namespace()
    }

    fn read(
        &mut self,
        key: &Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.0.read(key)
    }

    fn write(
        &mut self,
        key: &Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        use crate::storage::store::Outcome;
        match (self.0.write(key, write), key) {
            (Outcome::Committed(version), Key::Shard(_)) => {
                Outcome::Committed(version.next().unwrap())
            }
            (outcome, _) => outcome,
        }
    }
}

#[test]
fn a_bump_that_commits_at_an_unexpected_version_names_the_committed_value() {
    let n = 4;
    let shared = store(shard_record(n), volume_record());
    let mut card = Card::new();
    let mut skewed = Client::open(Skewed(shared.clone()), MemLog::default()).unwrap();
    let refused = restart()
        .run(&mut skewed, &sample(), &mut card)
        .expect_err("the regression refuses");
    assert_eq!(
        refused.check,
        Check::Bump(StoreError::Regression(
            crate::storage::store::Regression::Value(Key::Shard(shard()))
        ))
    );
    let target = Target {
        attempts: n + 1,
        ..Target::of(&shard_record(n))
    };
    assert_eq!(
        (refused.flip, refused.recovery),
        (None, Some(target)),
        "a regression after the commit holds and names the committed target"
    );
    assert_eq!(card.log, FULL[..4]);
    assert_eq!(Target::of(&shard_now(&shared)), target);
}

#[test]
fn restart_reads_no_assignment() {
    reaches_fb_with_the_assignment_and_host_key_absent(|lock, _| lock.local());
}

/// Control for `restart_reads_no_assignment`: a host-local source that reads the signed assignment beside the
/// local record, and refuses when it is absent, makes the restart depend on the assignment, and the restart's
/// reach to FB fails.
#[test]
#[should_panic(expected = "check: Local(Unreadable)")]
fn negative_control_a_local_source_that_reads_the_assignment_stops_the_restart() {
    reaches_fb_with_the_assignment_and_host_key_absent(|lock, state| {
        std::fs::read(state.join("assignment")).map_err(|_| Local::Unreadable)?;
        lock.local()
    });
}

/// A host-local source the restart reads at step 2: `local`, given the owner lock and the state directory.
struct Sourced<'a, F>(&'a crate::bind::OwnerLock, &'a std::path::Path, F);

impl<F: Fn(&crate::bind::OwnerLock, &std::path::Path) -> Result<LocalRecord, Local>> LocalSource
    for Sourced<'_, F>
{
    fn local(&self) -> Result<LocalRecord, Local> {
        (self.2)(self.0, self.1)
    }
}

/// Removes the assignment and the host key from a seeded state directory and checks that the restart, reading the
/// host-local record through `local`, reaches FB at `E = 1` and activates epoch 4.
fn reaches_fb_with_the_assignment_and_host_key_absent(
    local: impl Fn(&crate::bind::OwnerLock, &std::path::Path) -> Result<LocalRecord, Local>,
) {
    let setup = crate::bind::authority_tests::Setup::new();
    std::fs::remove_file(setup.state.join("assignment")).unwrap();
    std::fs::remove_file(setup.state.join("host.key")).unwrap();
    let store = store(shard_record(1), volume_record());
    let source = Sourced(&setup.lock, &setup.state, local);
    let restarted = reach_fb(&store, &mut Card::new(), &source);
    assert_eq!(restarted.session().epoch().get(), 4);
}

#[test]
fn restart_ignores_a_conflicting_assignment() {
    use crate::failover::assignment_tests::{HOST_KEY, sample as assignment};
    let setup = crate::bind::authority_tests::Setup::new();
    let mut other = assignment();
    other.volume = "vol-0fffffffffffffff0".into();
    other.incarnation = crate::failover::identity::Incarnation::new(7).unwrap();
    std::fs::write(
        setup.state.join("assignment"),
        other.sign(&HOST_KEY).unwrap(),
    )
    .unwrap();
    let store = store(shard_record(1), volume_record());
    let restarted = reach_fb(&store, &mut Card::new(), &setup.lock);
    assert_eq!(restarted.session().epoch().get(), 4);
}

#[test]
fn the_owner_lock_local_source_refuses_each_unusable_record() {
    use std::os::unix::fs::PermissionsExt;
    type Damage = fn(&std::path::Path);
    let rows: [(&str, Damage, Local); 4] = [
        (
            "absent",
            |state| std::fs::remove_file(state.join("authority")).unwrap(),
            Local::Absent,
        ),
        (
            "state directory open to others",
            |state| {
                std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o755)).unwrap()
            },
            Local::Unreadable,
        ),
        (
            "record file open to others",
            |state| {
                std::fs::set_permissions(
                    state.join("authority"),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap()
            },
            Local::Unreadable,
        ),
        (
            "torn",
            |state| {
                std::fs::write(state.join("authority"), torn_bytes()).unwrap();
            },
            Local::Invalid(RecordError::Torn),
        ),
    ];
    for (name, edit, refusal) in rows {
        let setup = crate::bind::authority_tests::Setup::new();
        edit(&setup.state);
        let store = store(shard_record(1), volume_record());
        let mut card = Card::new();
        let refused = restart()
            .run(&mut client(&store), &setup.lock, &mut card)
            .unwrap_err();
        assert_eq!(refused.check, Check::Local(refusal), "{name}");
        assert!(card.log.is_empty(), "{name}");
        std::fs::set_permissions(&setup.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn fb_value_passes_the_attach_gate_without_a_gate_command() {
    use crate::failover::serving::State;
    use crate::storage::gate_fixture::{arena, attach_reserving, ticks};
    let store = store(shard_record(2), volume_record());
    let mut card = Card::new();
    let restarted = reach_fb(&store, &mut card, &sample());
    let expected = (
        restarted.session().generation(),
        restarted.session().epoch(),
    );
    let (authority, _) = crate::storage::ServingAuthority::restarted(
        restart().bounds,
        Box::new(ZeroClock),
        restarted,
    );
    let arena = arena();
    let storage = crate::storage::owner_fixture::storage(8);
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    {
        let mut registry = registry.borrow_mut();
        registry.entries.push(holder(own(), 10));
        registry.rtype = 2;
    }
    ticks(&mut volume, &control, 4);
    assert_eq!(
        (volume.authority_state(), volume.authority_withdrawal()),
        (State::Recovering, None)
    );
    let token = volume
        .serving_token()
        .expect("the crossing issues the token");
    assert_eq!((token.exhid, token.key), (own().exhid, own().key));
    assert_eq!((token.generation, token.epoch), expected);
    let log = registry.borrow().log.clone();
    assert!(
        !log.is_empty() && log.iter().all(|command| command.is_report()),
        "no Register, Acquire or Preempt-and-Abort at the gate; only the periodic Reports after the crossing: {log:?}"
    );
}

pub(crate) fn standby_host() -> Host {
    Host::new(host().get() + 100).unwrap()
}

pub(crate) fn standby_pair() -> Pair {
    Pair {
        exhid: Exhid::new([0x5a; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((3 << 32) | 3).unwrap(),
    }
}

/// The owner's volume with a standby attached after it and both pairs enrolled.
pub(crate) fn with_standby() -> VolumeRecord {
    lineage(&[(standby_host(), standby_pair())])
}

fn shard_version(store: &Shared) -> crate::storage::store::Version {
    client(store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
        .version()
}

/// Runs the restart over `volume` and `local` and asserts that it refused with `check` before any device command,
/// left the shard record's version, and requested `flip`.
fn refuses_before_commands(
    holder: Holder,
    volume: VolumeRecord,
    local: Result<LocalRecord, Local>,
    check: Check,
    flip: Option<Target>,
) {
    let store = store(shard_record(4), volume);
    let before = shard_version(&store);
    let mut card = Card::new();
    let refused = restart_of(shard(), holder)
        .run(&mut client(&store), &Stored(local), &mut card)
        .unwrap_err();
    assert_eq!((&refused.check, refused.flip), (&check, flip), "{check:?}");
    assert!(card.log.is_empty(), "{check:?}");
    assert_eq!(shard_version(&store), before, "{check:?}");
}

/// An own record the volume record does not enroll refuses before any device command and requests no flip, since
/// host-local state never retires a retained volume, as the absent, unreadable, torn and misbound rows of
/// `local_rows` also show; a re-attach of the own host whose pair pins its earlier attach refuses the same way, and a
/// retained refusal keeps its flip.
#[test]
fn a_missing_own_record_refuses_without_requesting_a_flip() {
    let stale = VolumeRecord {
        next: 3,
        events: vec![
            volume_record().events[0],
            AttachmentEvent {
                seq: 1,
                kind: EventKind::Detach,
                host: host(),
                era: ERA,
                instance: None,
            },
            AttachmentEvent {
                seq: 2,
                ..volume_record().events[0]
            },
        ],
        ..volume_record()
    };
    let unenrolled = VolumeRecord {
        pairs: Vec::new(),
        ..volume_record()
    };
    refuses_before_commands(
        restart_holder(),
        unenrolled,
        Ok(local_record()),
        Check::Local(Local::Unenrolled),
        None,
    );
    refuses_before_commands(
        restart_holder(),
        stale,
        Ok(local_record()),
        Check::Local(Local::Unenrolled),
        None,
    );
    refuses_before_commands(
        restart_holder(),
        volume_record(),
        Err(Local::Retained),
        Check::Local(Local::Retained),
        Some(Target::of(&shard_record(4))),
    );
}

/// A local record whose pair differs from the pair the volume record enrolls for this attach refuses before any
/// device command and requests no flip.
#[test]
fn an_altered_local_record_refuses_without_requesting_a_flip() {
    let altered = VolumeRecord {
        pairs: vec![RecordedPair {
            pair: Pair {
                key: foreign().key,
                ..own()
            },
            ..volume_record().pairs[0]
        }],
        ..volume_record()
    };
    refuses_before_commands(
        restart_holder(),
        altered,
        Ok(local_record()),
        Check::Local(Local::Altered),
        None,
    );
}

/// An enrolled standby's registration survives the self Preempt-and-Abort, which names the own pair, and the
/// restart reaches FB at `(g, 2E + 2)`. The serving authority built from it carries the recorded pairs, so its
/// periodic Reports list the standby as registered while the owner continues serving.
/// The authority retains ended attach pairs from the restart's volume record, so the registrant judgment returns
/// `Recorded` for a live standby and `Ended` for a detached one.
#[test]
fn an_enrolled_standby_registration_survives_the_restart() {
    use crate::failover::serving::State;
    use crate::storage::RegistrantJudgment;
    use crate::storage::gate_fixture::{arena, attach_reserving, ticks};
    let mut detached = with_standby();
    detached.push(EventKind::Detach, standby_host(), ERA);
    for (record, judgment) in [
        (with_standby(), RegistrantJudgment::Recorded),
        (detached, RegistrantJudgment::Ended),
    ] {
        let store = store(shard_record(4), record);
        let mut card = Card::new();
        card.entries.push(Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        });
        let restarted = reach_fb(&store, &mut card, &sample());
        assert_eq!(restarted.session().epoch().get(), 10);
        assert_eq!(restarted.session().generation(), shard_of().generation);
        assert_eq!(shard_now(&store).attempts, 5);
        let (authority, _) = crate::storage::ServingAuthority::restarted(
            restart().bounds,
            Box::new(ZeroClock),
            restarted,
        );
        let arena = arena();
        let storage = crate::storage::owner_fixture::storage(8);
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        {
            let mut registry = registry.borrow_mut();
            registry.rtype = 2;
            registry.entries.extend([
                holder(own(), 10),
                Registrant {
                    holder: false,
                    ..holder(standby_pair(), 11)
                },
            ]);
        }
        ticks(&mut volume, &control, 8);
        let reports = registry
            .borrow()
            .log
            .iter()
            .filter(|command| command.is_report())
            .count();
        assert!(reports > 0, "the serving authority evaluated a Report");
        let report = volume.authority_report();
        assert_eq!(report.state, State::Recovering);
        assert_eq!(report.own_records, Some(1));
        assert_eq!(
            (report.withdrawal, report.flip, report.pending),
            (None, None, false),
            "the restart's recorded pairs admit the standby"
        );
        assert_eq!(report.registrants, Some(judgment));
    }
}

/// OVER-BOUND-NO-FLIP: under `N_reg = 1`, Report #1 lists the own holder and the enrolled standby, so it is over the
/// bound with every registrant recorded. Under reservation limits wider than `N_reg` the parser reads the entries, and
/// the restart refuses after Report #1 with `Check::Unobserved`, no flip, no bump and no later device command. An
/// unrecorded second registrant under the same bound still refuses with `Excess` and the flip, and so does the
/// recorded standby under limits equal to `N_reg`, whose parser refuses the count before reading the entries.
#[test]
fn an_enrolled_standby_over_a_narrow_bound_refuses_the_restart_without_a_flip() {
    let narrow = Restart {
        bounds: crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap(),
        ..restart()
    };
    for (second, check, flip) in [
        (standby_pair(), Check::Unobserved, None),
        (
            crate::storage::gate_fixture::foreign(),
            Check::NotHolding(NotSole::Excess),
            Some(Target::of(&shard_record(4))),
        ),
    ] {
        let store = store(shard_record(4), with_standby());
        let mut card = Card::new();
        card.entries.push(Registrant {
            holder: false,
            ..holder(second, 2)
        });
        let refused = narrow
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        let hint = flip.is_none().then(|| Target::of(&shard_record(4)));
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (check, flip, hint)
        );
        assert_eq!(card.log, FULL[..4]);
        assert_eq!(shard_now(&store).attempts, 4, "no bump");
    }
    let store = self::store(shard_record(4), with_standby());
    let mut card = Card::new();
    card.entries.extend([
        Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        },
        Registrant {
            holder: false,
            ..holder(standby_pair(), 3)
        },
    ]);
    let refused = narrow
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::NotHolding(NotSole::Excess),
            Some(Target::of(&shard_record(4)))
        ),
        "every listed pair recorded and a count above the recorded pairs"
    );
    let parsed = Restart {
        limits: crate::storage::ReservationLimits::new(1, 2, 100, 100).unwrap(),
        ..narrow
    };
    let store = self::store(shard_record(4), with_standby());
    let mut card = Card::new();
    card.entries.push(Registrant {
        holder: false,
        ..holder(standby_pair(), 2)
    });
    let refused = parsed
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::NotHolding(NotSole::Excess),
            Some(Target::of(&shard_record(4)))
        ),
        "a parser at N_reg refuses the count before reading the entries, so no listed pair is shown recorded"
    );
    assert_eq!(card.log, FULL[..4]);
}

/// A standby in `peers` that attached before enrolling its pair lets the restart reach FB with only `own()` recorded;
/// the same attach without a matching peer refuses at step 1 with the flip, before any device command.
#[test]
fn a_bound_standby_attach_before_its_enrollment_keeps_the_restart() {
    let pending = VolumeRecord {
        pairs: volume_record().pairs,
        ..with_standby()
    };
    let peers = [Peer {
        host: standby_host(),
        instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
    }];
    let store = store(shard_record(4), pending.clone());
    let mut card = Card::new();
    let restarted = Restart {
        peers: &peers,
        ..restart()
    }
    .run(&mut client(&store), &sample(), &mut card)
    .unwrap();
    assert_eq!(card.log, FULL);
    assert_eq!(shard_now(&store).attempts, 5);
    assert_eq!(restarted.into_parts().2, (vec![own()], 0));
    refuses_before_commands(
        restart_holder(),
        pending,
        Ok(local_record()),
        Check::Volume(Trigger::Events),
        Some(Target::of(&shard_record(4))),
    );
}

/// A standby whose attach the volume record ended keeps its recorded pair: when it holds at Report #1 the owner's
/// restart takes the lineage arm, bumps `E` once, preempts that pair's key and reaches FB at the bumped tenure with
/// no flip, so the loss of the holder's host retires no volume (ENDED-NEVER-RETIRES).
#[test]
fn a_holder_recorded_for_an_ended_attach_is_preempted_by_the_lineage_arm() {
    let mut detached = with_standby();
    detached.push(EventKind::Detach, standby_host(), ERA);
    preempts_the_standby_through_the_arm(detached);
}

/// Runs the owner's restart over `volume` with `standby_pair()` holding at Report #1, and asserts that it takes the
/// lineage arm, preempts that pair's key and reaches FB at the bumped tenure with the shard record bumped once.
fn preempts_the_standby_through_the_arm(volume: VolumeRecord) {
    let store = self::store(shard_record(4), volume);
    let before = crate::storage::store_tests::stored(&store);
    let mut card = Card::new();
    card.entries = vec![
        Registrant {
            holder: false,
            ..holder(own(), 1)
        },
        holder(standby_pair(), 2),
    ];
    let restarted = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .expect("a holder the volume record lists takes the lineage arm with no flip");
    assert!(restarted.lineage());
    assert_eq!(restarted.session().target(), Target::of(&shard_record(5)));
    assert_eq!(card.log, ARM);
    assert_eq!(card.preempted, [standby_pair().key]);
    let (version, record) = crate::storage::store_tests::stored(&store);
    assert_eq!(
        (version, record),
        (before.0.next().unwrap(), shard_record(5))
    );
}

/// The lineage arm requires the volume record to list the pair holding the reservation at Report #1: an unrecorded
/// holder refuses the restart with the flip.
#[test]
#[should_panic(expected = "a holder the volume record lists takes the lineage arm with no flip")]
fn negative_control_an_unrecorded_holder_fails_the_recorded_holder_refusal() {
    let mut unrecorded = lineage(&[]);
    unrecorded.push(EventKind::Attach, standby_host(), ERA);
    unrecorded.push(EventKind::Detach, standby_host(), ERA);
    preempts_the_standby_through_the_arm(unrecorded);
}

/// An enrolled standby takes no tenure: its restart and its fresh start are deposed before any device command with
/// flip set to None. While the shard record names the owner, the owner's restart preempts the live enrolled standby
/// through its lineage arm when Report #1 identifies it as holder, and refuses `RecordedHolder` with no flip and the
/// bumped target as the recovery hint when Report #2 does. It is deposed once the shard record names the standby's
/// host.
#[test]
fn an_enrolled_standby_takes_no_tenure() {
    use crate::failover::fresh::tests as fresh;
    let standby = Holder {
        host: standby_host(),
        instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
        ..restart_holder()
    };
    refuses_before_commands(
        standby,
        with_standby(),
        Ok(local_record()),
        Check::Deposed,
        None,
    );
    let store = fresh::store(fresh::shard_record(0), with_standby());
    let before = shard_version(&store);
    let log = fresh::Log::default();
    let refused = fresh::fresh_of(shard(), standby)
        .run(
            &mut client(&store),
            &mut fresh::plane(),
            &mut fresh::records(&log),
            &mut fresh::Card::new(&log),
            &mut crate::failover::fresh::Refusals::default(),
        )
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (crate::failover::fresh::Check::Deposed, None)
    );
    assert!(log.borrow().is_empty());
    assert_eq!(shard_version(&store), before);

    let store = self::store(shard_record(4), with_standby());
    let mut card = Card::new();
    card.entries = vec![
        Registrant {
            holder: false,
            ..holder(own(), 1)
        },
        holder(standby_pair(), 2),
    ];
    let restarted = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert!(restarted.lineage());
    assert_eq!(card.log, ARM);
    assert_eq!(card.preempted, [standby_pair().key]);
    assert_eq!(shard_now(&store).attempts, 5);

    let store = self::store(shard_record(4), with_standby());
    let mut card = Card::new();
    card.fault = Some(Fault::PreemptLeaves(|entries| {
        entries[0].holder = false;
        entries.push(holder(standby_pair(), 2));
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::RecordedHolder,
            flip: None,
            recovery: Some(Target::of(&shard_record(5))),
        }
    );
    assert_eq!(card.log, FULL);

    let spare_host = shard_of().spare.unwrap().1;
    let successor = lineage(&[(spare_host, standby_pair())]);
    let store = self::store(shard_record(4), successor);
    let mut card = Card::new();
    card.entries = vec![
        Registrant {
            holder: false,
            ..holder(own(), 1)
        },
        holder(standby_pair(), 2),
    ];
    let flipper = store.clone();
    card.on_report = Some(Box::new(move || {
        let mut writer = client(&flipper);
        let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        writer.flip(&read).unwrap();
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::Deposed, None),
        "a shard record naming the holder's host at a later tenure"
    );
    assert_eq!(card.log, FULL[..4]);
}

/// Report #1 names a standby whose pair the volume record enrolled after step 1 read it: the restart re-reads the
/// volume record and reaches FB. The restart refuses with a flip when the re-read volume record lacks a reported registrant.
#[test]
fn a_report_is_judged_against_a_volume_record_read_after_it() {
    let store = store(shard_record(4), volume_record());
    let mut card = Card::new();
    card.entries.push(Registrant {
        holder: false,
        ..holder(standby_pair(), 2)
    });
    let writer = store.clone();
    card.on_report = Some(Box::new(move || {
        let mut standby = client(&writer);
        let read = standby
            .read::<VolumeRecord>(Key::Volume(volume_id()))
            .unwrap();
        standby.replace(&read, with_standby()).unwrap();
    }));
    let restarted = reach_fb(&store, &mut card, &sample());
    assert_eq!(shard_now(&store).attempts, 5);
    assert_eq!(restarted.session().epoch().get(), 10);

    let store = self::store(shard_record(4), volume_record());
    let mut card = Card::new();
    card.entries.push(Registrant {
        holder: false,
        ..holder(standby_pair(), 2)
    });
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::NotHolding(NotSole::ForeignRegistrant),
            Some(Target::of(&shard_record(4)))
        )
    );
}

/// DEPOSE-ONLY-BY-SUCCESSOR needs the Report's holder to be the later owner's enrolled pair: under a shard record at a
/// later tenure naming the standby's host, a foreign holder refuses with `ForeignHolder` and the step-1 flip.
#[test]
fn a_later_tenure_deposes_only_through_its_owners_enrolled_holder() {
    let spare_host = shard_of().spare.unwrap().1;
    let successor = lineage(&[(spare_host, standby_pair())]);
    let store = self::store(shard_record(4), successor);
    let mut card = Card::new();
    card.entries = vec![
        Registrant {
            holder: false,
            ..holder(own(), 1)
        },
        holder(foreign(), 2),
    ];
    let flipper = store.clone();
    card.on_report = Some(Box::new(move || {
        let mut writer = client(&flipper);
        let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        writer.flip(&read).unwrap();
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::NotHolding(NotSole::ForeignHolder),
            Some(Target::of(&shard_record(4)))
        )
    );
    assert_eq!(card.log, FULL[..4]);
}

/// A standby that detached and re-attached keeps only its earlier attach's pair, which enrolls nothing for its live
/// attach: unbound, step 1 retires with `Events` and the flip before any device command; bound as a peer, its pending
/// enrollment lets the restart reach FB.
#[test]
fn a_reattached_standby_with_only_its_earlier_pair_needs_its_binding() {
    let mut reattached = with_standby();
    reattached.push(EventKind::Detach, standby_host(), ERA);
    reattached.push(EventKind::Attach, standby_host(), ERA);
    refuses_before_commands(
        restart_holder(),
        reattached.clone(),
        Ok(local_record()),
        Check::Volume(Trigger::Events),
        Some(Target::of(&shard_record(4))),
    );
    let peers = [Peer {
        host: standby_host(),
        instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
    }];
    let store = store(shard_record(4), reattached);
    let mut card = Card::new();
    Restart {
        peers: &peers,
        ..restart()
    }
    .run(&mut client(&store), &sample(), &mut card)
    .unwrap();
    assert_eq!(card.log, FULL);
}

/// The volume record `admit` rereads after either Report passes step 1's checks again: a modification recorded with
/// the standby's enrollment refuses with `Modification` and the flip, and a reread that enrolls no pair or another
/// pair for the own attach refuses with `Unenrolled` or `Altered` and no flip. After Report #1 neither bumps; after
/// Report #2, whose unrecorded registrant the preempt leaves, the flip names the bumped tenure.
#[test]
fn the_reread_volume_record_passes_step_one_again() {
    type Edit = fn(VolumeRecord) -> VolumeRecord;
    let rows: [(Edit, Check, Option<Target>); 3] = [
        (
            |held| VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held
            },
            Check::Volume(Trigger::Modification),
            Some(Target::of(&shard_record(4))),
        ),
        (
            |held| VolumeRecord {
                pairs: vec![held.pairs[1]],
                fence: (1 << 32) | 10,
                ..held
            },
            Check::Local(Local::Unenrolled),
            None,
        ),
        (
            |held| VolumeRecord {
                pairs: vec![
                    RecordedPair {
                        pair: Pair {
                            key: foreign().key,
                            ..own()
                        },
                        ..held.pairs[0]
                    },
                    held.pairs[1],
                ],
                fence: (1 << 32) | 10,
                ..held
            },
            Check::Local(Local::Altered),
            None,
        ),
    ];
    for &(edit, ref check, flip) in &rows {
        let store = store(shard_record(4), volume_record());
        let mut card = Card::new();
        card.entries.push(Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        });
        let writer = store.clone();
        card.on_report = Some(Box::new(move || {
            let mut standby = client(&writer);
            let read = standby
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            standby.replace(&read, edit(with_standby())).unwrap();
        }));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!((&refused.check, refused.flip), (check, flip), "{check:?}");
        assert_eq!(card.log, FULL[..4], "{check:?}");
        assert_eq!(shard_now(&store).attempts, 4, "{check:?}");
    }
    for (edit, check, flip) in rows {
        let store = store(shard_record(4), volume_record());
        let mut card = Card::new();
        card.fault = Some(Fault::PreemptLeaves(|entries| {
            entries.push(Registrant {
                holder: false,
                ..holder(standby_pair(), 2)
            });
        }));
        let writer = store.clone();
        card.on_report_at = 2;
        card.on_report = Some(Box::new(move || {
            let mut standby = client(&writer);
            let read = standby
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            standby.replace(&read, edit(with_standby())).unwrap();
        }));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        let flip = flip.map(|_| Target::of(&shard_record(5)));
        assert_eq!(
            (&refused.check, refused.flip),
            (&check, flip),
            "#2 {check:?}"
        );
        assert_eq!(card.log, FULL, "#2 {check:?}");
        assert_eq!(shard_now(&store).attempts, 5, "#2 {check:?}");
    }
}

/// `admit` reapplies step 1's volume checks after each clean Report because the volume record can change during
/// the Report. If a concurrent writer records an in-progress modification or an unbound live attach by another host
/// during the Report, `admit` rereads the volume record and returns `Check::Volume` with the flip target. At
/// Report #1 the restart stops before the bump. At Report #2 it stops after the bump and the self preempt, and the
/// flip names the bumped tenure.
#[test]
fn the_reread_after_a_clean_report_passes_step_one_again() {
    type Edit = fn(VolumeRecord) -> VolumeRecord;
    let rows: [(Edit, Trigger); 2] = [
        (
            |held| VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held
            },
            Trigger::Modification,
        ),
        (
            |mut held| {
                held.push(EventKind::Attach, Host::new(host().get() + 7).unwrap(), ERA);
                held
            },
            Trigger::Events,
        ),
    ];
    for (edit, trigger) in rows {
        for at in [1, 2] {
            let store = store(shard_record(4), volume_record());
            let mut card = Card::new();
            card.on_report_at = at;
            let writer = store.clone();
            card.on_report = Some(Box::new(move || {
                let mut writer = client(&writer);
                let read = writer
                    .read::<VolumeRecord>(Key::Volume(volume_id()))
                    .unwrap();
                let next = edit(read.value().clone());
                writer.replace(&read, next).unwrap();
            }));
            let refused = restart()
                .run(&mut client(&store), &sample(), &mut card)
                .unwrap_err();
            let (log, attempts) = if at == 1 {
                (&FULL[..4], 4)
            } else {
                (&FULL[..], 5)
            };
            assert_eq!(
                (&refused.check, refused.flip),
                (
                    &Check::Volume(trigger.clone()),
                    Some(Target::of(&shard_record(attempts)))
                ),
                "Report #{at}, {trigger:?}"
            );
            assert_eq!(card.log, log, "Report #{at}, {trigger:?}");
            assert_eq!(
                shard_now(&store).attempts,
                attempts,
                "Report #{at}, {trigger:?}"
            );
        }
    }
}

/// NO-HOLDER-HOLD judges a Report with nobody holding against the volume record `admit` rereads after it, whichever
/// refusal sends the Report to the reread: `ForeignRegistrant` for a standby the step-1 record omits, `ReservationType`
/// under rtype 0, and `NotHolder` for a standby the step-1 record enrolls, at Report #1 and, for the type-2 cases, at
/// Report #2. A reread that enrolls the standby refuses `Unheld` with no flip and the Report's tenure as the recovery
/// hint; without an edit the step-1 record that omits the standby keeps the refusal and its flip, and a reread that
/// drops the step-1 record's standby pair refuses `ForeignRegistrant` with the flip. Each store edit runs
/// after the bytes of the Report it follows. The reread passes step 1's
/// checks first: a recorded modification refuses with the flip, an unenrolled or altered own pair refuses with no
/// flip, and a failed reread refuses `Records` with no flip.
#[test]
fn a_report_with_nobody_holding_is_judged_against_the_reread() {
    fn unheld(entries: &mut Vec<Registrant>) {
        entries[0].holder = false;
        entries.push(Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        });
    }
    type Edit = fn(VolumeRecord) -> VolumeRecord;
    let modified: Edit = |held| VolumeRecord {
        modification: Some(Modification::InProgress),
        ..held
    };
    let unenrolled: Edit = |held| VolumeRecord {
        pairs: vec![held.pairs[1]],
        fence: (1 << 32) | 10,
        ..held
    };
    let altered: Edit = |held| VolumeRecord {
        pairs: vec![
            RecordedPair {
                pair: Pair {
                    key: foreign().key,
                    ..own()
                },
                ..held.pairs[0]
            },
            held.pairs[1],
        ],
        fence: (1 << 32) | 10,
        ..held
    };
    let dropped: Edit = |mut held| {
        held.push(EventKind::Detach, standby_host(), ERA);
        held.pairs
            .retain(|recorded| recorded.host != standby_host());
        held.fence = (1 << 32) | 10;
        held
    };
    // (Report step, rtype, the step-1 record enrolls the standby, the refusal that sends the Report to the reread)
    let sources = [
        (ReportStep::First, 2, false, NotSole::ForeignRegistrant),
        (ReportStep::First, 0, false, NotSole::ReservationType),
        (ReportStep::First, 2, true, NotSole::NotHolder),
        (ReportStep::Second, 2, false, NotSole::ForeignRegistrant),
        (ReportStep::Second, 2, true, NotSole::NotHolder),
    ];
    for (step, rtype, seeded, first) in sources {
        let (read, issued, refusal): (u32, usize, fn(NotSole) -> Check) = match step {
            ReportStep::First => (4, 4, Check::NotHolding),
            ReportStep::Second => (5, 6, Check::NotSole),
        };
        let tenure = Some(Target::of(&shard_record(read)));
        // (reread edit of the enrolling record, or none for the step-1 record; refusal; flip; recovery hint)
        type Row = (Option<Edit>, Check, Option<Target>, Option<Target>);
        let mut rows: Vec<Row> = vec![
            (Some(|held| held), Check::Unheld, None, tenure),
            (
                Some(modified),
                Check::Volume(Trigger::Modification),
                tenure,
                None,
            ),
            (
                Some(unenrolled),
                Check::Local(Local::Unenrolled),
                None,
                None,
            ),
            (Some(altered), Check::Local(Local::Altered), None, None),
        ];
        if seeded {
            rows.push((
                Some(dropped),
                refusal(NotSole::ForeignRegistrant),
                tenure,
                None,
            ));
        } else {
            rows.push((None, refusal(first), tenure, None));
        }
        let card = |store: &Shared, edit: Option<Edit>| {
            let mut card = Card::new();
            card.rtype = rtype;
            match step {
                ReportStep::First => unheld(&mut card.entries),
                ReportStep::Second => {
                    card.fault = Some(Fault::PreemptLeaves(unheld));
                    card.on_report_at = 2;
                }
            }
            if let Some(edit) = edit {
                let writer = store.clone();
                card.on_report = Some(Box::new(move || {
                    let mut standby = client(&writer);
                    let read = standby
                        .read::<VolumeRecord>(Key::Volume(volume_id()))
                        .unwrap();
                    standby.replace(&read, edit(with_standby())).unwrap();
                }));
            }
            card
        };
        let seed = || {
            if seeded {
                with_standby()
            } else {
                volume_record()
            }
        };
        for (edit, check, flip, recovery) in rows {
            let store = store(shard_record(4), seed());
            let mut card = card(&store, edit);
            let refused = restart()
                .run(&mut client(&store), &sample(), &mut card)
                .unwrap_err();
            assert_eq!(
                (&refused.check, refused.flip, refused.recovery),
                (&check, flip, recovery),
                "{first:?} at {step:?}: {check:?}"
            );
            assert_eq!(card.log, FULL[..issued], "{first:?} at {step:?}: {check:?}");
            assert_eq!(
                shard_now(&store).attempts,
                read,
                "{first:?} at {step:?}: {check:?}"
            );
        }
        let store = self::store(shard_record(4), seed());
        let passes = match step {
            ReportStep::First => 2,
            ReportStep::Second => 4,
        };
        for _ in 0..passes {
            store.schedule(Arm::Pass);
        }
        store.schedule(Arm::Unavailable);
        let mut card = card(&store, None);
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip),
            (Check::Records(StoreError::Unavailable), None),
            "{first:?}: a failed reread after {step:?}"
        );
        assert_eq!(
            card.log,
            FULL[..issued],
            "{first:?}: a failed reread after {step:?}"
        );
        assert_eq!(
            shard_now(&store).attempts,
            read,
            "{first:?}: a failed reread after {step:?}"
        );
    }
}

/// A failed volume reread after either Report refuses with `Records` and no flip, before the bump after Report #1 and
/// before FB after Report #2. A failed shard reread in `superseded` shows no successor, so the restart's lineage arm
/// preempts the validated recorded holder and reaches FB.
#[test]
fn failed_rereads_after_a_report_request_no_flip_or_show_no_successor() {
    let unrecorded = Registrant {
        holder: false,
        ..holder(standby_pair(), 2)
    };
    let store = self::store(shard_record(4), volume_record());
    for arm in [Arm::Pass, Arm::Pass, Arm::Unavailable] {
        store.schedule(arm);
    }
    let mut card = Card::new();
    card.entries.push(unrecorded);
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::Records(StoreError::Unavailable), None)
    );
    assert_eq!(card.log, FULL[..4]);
    assert_eq!(shard_now(&store).attempts, 4);

    let store = self::store(shard_record(4), volume_record());
    for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Pass, Arm::Unavailable] {
        store.schedule(arm);
    }
    let mut card = Card::new();
    card.fault = Some(Fault::PreemptLeaves(|entries| {
        entries.push(Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        });
    }));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::Records(StoreError::Unavailable), None)
    );
    assert_eq!(card.log, FULL);
    assert_eq!(shard_now(&store).attempts, 5);

    let store = self::store(shard_record(4), with_standby());
    for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Unavailable] {
        store.schedule(arm);
    }
    let mut card = Card::new();
    card.entries = vec![
        Registrant {
            holder: false,
            ..holder(own(), 1)
        },
        holder(standby_pair(), 2),
    ];
    let restarted = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert!(restarted.lineage());
    assert_eq!(card.log, ARM);
    assert_eq!(shard_now(&store).attempts, 5);
}

/// A successor's takeover that also drops the own pair from the volume record, or also records a modification,
/// still reads as a deposition: the reread's successor check precedes its step-1 and enrollment checks.
#[test]
fn a_successor_that_drops_the_own_pair_deposes_the_restart() {
    let spare_host = shard_of().spare.unwrap().1;
    let successor = lineage(&[(spare_host, standby_pair())]);
    type Edit = fn(&VolumeRecord) -> VolumeRecord;
    let edits: [Edit; 2] = [
        |held| VolumeRecord {
            pairs: vec![held.pairs[1]],
            fence: (1 << 32) | 10,
            ..held.clone()
        },
        |held| VolumeRecord {
            modification: Some(Modification::InProgress),
            ..held.clone()
        },
    ];
    for edit in edits {
        let store = self::store(shard_record(4), successor.clone());
        let mut card = Card::new();
        card.entries = vec![
            Registrant {
                holder: false,
                ..holder(own(), 1)
            },
            holder(standby_pair(), 2),
        ];
        let flipper = store.clone();
        card.on_report = Some(Box::new(move || {
            let mut writer = client(&flipper);
            let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            writer.flip(&read).unwrap();
            let read = writer
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            let next = edit(read.value());
            writer.replace(&read, next).unwrap();
        }));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!((refused.check, refused.flip), (Check::Deposed, None));
        assert_eq!(card.log, FULL[..4]);
    }
}

/// Report #2 is judged under the bumped tenure: a fence raise after the bump that enrolls a foreign pair for the own
/// host, which then holds, is no successor of the bumped tenure, so the reread refuses with `Altered` and no flip, or
/// with `Modification` and the bumped flip when it also records a modification. Under `N_reg = 1` and wider
/// reservation limits, a recorded standby that the preempt leaves registered makes Report #2 `Unobserved`, with no
/// flip after the bump.
#[test]
fn report_two_is_judged_under_the_bumped_tenure() {
    type Edit = fn(VolumeRecord) -> VolumeRecord;
    let rows: [(Edit, Check, Option<Target>); 2] = [
        (|held| held, Check::Local(Local::Altered), None),
        (
            |held| VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held
            },
            Check::Volume(Trigger::Modification),
            Some(Target::of(&shard_record(5))),
        ),
    ];
    for (edit, check, flip) in rows {
        let store = self::store(shard_record(4), volume_record());
        let mut card = Card::new();
        card.fault = Some(Fault::PreemptLeaves(|entries| {
            entries[0].holder = false;
            entries.push(holder(foreign(), 2));
        }));
        let writer = store.clone();
        card.on_report_at = 2;
        card.on_report = Some(Box::new(move || {
            let mut other = client(&writer);
            let read = other
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            let next = VolumeRecord {
                pairs: vec![RecordedPair {
                    pair: foreign(),
                    ..volume_record().pairs[0]
                }],
                fence: (1 << 32) | 10,
                ..read.value().clone()
            };
            other.replace(&read, edit(next)).unwrap();
        }));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!((&refused.check, refused.flip), (&check, flip), "{check:?}");
        assert_eq!(card.log, FULL, "{check:?}");
        assert_eq!(shard_now(&store).attempts, 5, "{check:?}");
    }
    let narrow = Restart {
        bounds: crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap(),
        ..restart()
    };
    let store = self::store(shard_record(4), with_standby());
    let mut card = Card::new();
    card.fault = Some(Fault::PreemptLeaves(|entries| {
        entries.push(Registrant {
            holder: false,
            ..holder(standby_pair(), 2)
        });
    }));
    let refused = narrow
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (Check::Unobserved, None, Some(Target::of(&shard_record(5))))
    );
    assert_eq!(card.log, FULL);
    assert_eq!(shard_now(&store).attempts, 5);
}

/// A restart fences every coverage page under its new session before its capability returns, and carries the warm
/// source its record names: a record naming a checkpoint yields the source under the volume record's layout, a record
/// naming none yields no source and the tenure starts cold. A record whose page cap holds no page refuses `Coverage`
/// with no flip, and the record keeps its bumped tenure. A record naming certified suffixes and no checkpoint refuses
/// `SuffixOnly` at step 1 with no flip, no bump and no device command.
#[test]
fn a_restart_fences_the_coverage_pages_and_carries_the_records_warm_source() {
    use crate::failover::records::NamedCheckpoint;
    let session = crate::net::ownership::session_of(shard_of().generation.get() as u32, 4);
    let named = NamedCheckpoint {
        slot: 1,
        session,
        capture: 3,
        units: 2,
    };
    let warm = ShardRecord {
        checkpoint: Some(named),
        cut: 5,
        ..shard_record(2)
    };
    for (record, names) in [(warm, true), (shard_record(2), false)] {
        let store = store(record, volume_record());
        let mut card = Card::new();
        let restarted = reach_fb(&store, &mut card, &sample());
        assert!(
            restarted.fencing().coverage().is_some(),
            "every page is fenced under the new session"
        );
        assert_eq!(restarted.fencing().session(), restarted.session().get());
        let bumped = shard_now(&store);
        for page in 0..bumped.pages.get() {
            let read = client(&store)
                .read::<crate::failover::records::CoveragePage>(Key::Page(shard(), page))
                .unwrap();
            assert_eq!(read.value().fence, restarted.session().get(), "page {page}");
        }
        assert_eq!(restarted.warm().is_some(), names);
        if let Some(source) = restarted.warm() {
            assert_eq!(*source.layout(), volume_record().layout);
        }
    }
    let narrow = ShardRecord {
        page_cap: std::num::NonZeroU32::MIN,
        ..shard_record(2)
    };
    let store = store(narrow, volume_record());
    let mut card = Card::new();
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        refused.check,
        Check::Coverage(crate::storage::page_coverage::FenceRefused::Fencing(
            crate::storage::page_coverage::FencingRefusal::PageCap
        ))
    );
    assert_eq!(
        refused.flip, None,
        "a fencing refusal requests no replacement"
    );
    assert_eq!(
        refused.recovery,
        Some(Target::of(&shard_record(3))),
        "a fencing refusal holds with the bumped target"
    );
    assert_eq!(card.log, FULL, "the device steps all ran");
    assert_eq!(shard_now(&store).attempts, 3, "the bumped tenure stands");
    // A record whose certified suffix carries the retained set with no checkpoint refuses at step 1, so the cold path
    // never overwrites the suffix: no bump, no device command, no flip.
    let suffix_only = ShardRecord {
        ancestry: crate::failover::records::Ancestry::new(&[crate::failover::records::Suffix {
            session,
            start: 0,
            certified: 3,
            end: 3,
        }])
        .unwrap(),
        ..shard_record(2)
    };
    let held = self::store(suffix_only, volume_record());
    let mut card = Card::new();
    let refused = restart()
        .run(&mut client(&held), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (Check::SuffixOnly, None, None)
    );
    assert!(card.log.is_empty(), "no device command: {:?}", card.log);
    assert_eq!(shard_now(&held), suffix_only, "the record is unchanged");
}

/// ENDED-GRANTS-NOTHING at the restart: an ended or gone own entry under a shard record that names this host refuses
/// `Local::Ended` before any device command, with no flip and no recovery hint. Control: a format-2 detach of the own
/// host, which the events rule judges, requests the flip.
#[test]
fn an_ended_own_entry_refuses_the_restart_with_no_flip() {
    let mut ended = volume_record();
    ended.events[0].kind = EventKind::Ended;
    refuses_before_commands(
        restart_holder(),
        ended.clone(),
        Ok(local_record()),
        Check::Local(Local::Ended),
        None,
    );
    let mut gone = ended;
    gone.pairs.clear();
    gone.fence = (shard_record(4).generation.get() << 32) | 2;
    gone.events[0].kind = EventKind::Gone;
    refuses_before_commands(
        restart_holder(),
        gone,
        Ok(local_record()),
        Check::Local(Local::Ended),
        None,
    );
    assert_eq!(
        disposition(&Check::Local(Local::Ended)),
        Disposition::Neither
    );
    let mut detached = volume_record();
    detached.push(EventKind::Detach, host(), ERA);
    refuses_before_commands(
        restart_holder(),
        detached,
        Ok(local_record()),
        Check::Volume(Trigger::Events),
        Some(Target::of(&shard_record(4))),
    );
}

/// The restart judges no history clause at `E > 0`: a record whose next number lies above its retained entries
/// reaches the fencing boundary.
#[test]
fn a_record_with_removed_entries_passes_the_restart() {
    let mut removed = volume_record();
    removed.events[0].seq = 4;
    removed.next = 5;
    removed.pairs[0].attach = 4;
    assert!(!removed.uncompacted());
    let store = store(shard_record(4), removed);
    let mut card = Card::new();
    restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
}

/// ENDED-NEVER-RETIRES at the restart: a late Register under an ended entry's key beside the own holding passes both
/// Reports, and the tenure starts with that pair among its admitted pairs. Control: a registrant under a key no
/// ended entry carries refuses Report #1 with the flip.
#[test]
fn both_restart_reports_admit_a_registrant_under_an_ended_key() {
    let (ended, late) = with_ended_late();
    let store = store(shard_record(4), ended);
    let mut card = Card::new();
    card.entries.push(Registrant {
        cntlid: 2,
        pair: late,
        holder: false,
    });
    let restarted = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    let (_, _, admitted, _, _, _) = restarted.into_parts();
    assert_eq!(admitted, (vec![own(), late], 1));
    let stranger = Pair {
        key: crate::failover::records::attachment_key(3).unwrap(),
        ..late
    };
    let store = self::store(shard_record(4), volume_record());
    let mut card = Card::new();
    card.entries.push(Registrant {
        cntlid: 2,
        pair: stranger,
        holder: false,
    });
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (
            Check::NotHolding(NotSole::ForeignRegistrant),
            Some(Target::of(&shard_record(4)))
        ),
        "control: a key past the record's next number"
    );
}

/// The own volume record with an ended entry of another host at entry 2 whose pair the record dropped, and the late
/// Register under that entry's key.
fn with_ended_late() -> (VolumeRecord, Pair) {
    let mut ended = volume_record();
    ended.next = 3;
    ended.events.push(AttachmentEvent {
        seq: 2,
        kind: EventKind::Ended,
        host: Host::new(host().get() + 7).unwrap(),
        era: ERA,
        instance: Some(InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap()),
    });
    let late = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::records::attachment_key(2).unwrap(),
    };
    (ended, late)
}

/// NO-HOLDER-HOLD and the lineage arm at the restart beside a late Register under an ended key: nobody holding
/// refuses Report #1 `Unheld` with no flip and no further device command, and a recorded pair of another host's live
/// attach holding takes the lineage arm, which admits the late registrant beside it, bumps the tenure, preempts that
/// pair's key and reaches the fencing boundary. The same Reports with a registrant under a key past the record's next
/// number request the flip.
#[test]
fn the_restart_holds_admit_a_late_register_under_an_ended_key() {
    let (mut ended, late) = with_ended_late();
    let third_host = Host::new(host().get() + 9).unwrap();
    let at = ended.push(EventKind::Attach, third_host, ERA).unwrap();
    let third = Pair {
        exhid: Exhid::new([0x33; 16]).unwrap(),
        key: crate::failover::records::attachment_key(at).unwrap(),
    };
    ended.pairs.push(RecordedPair {
        host: third_host,
        pair: third,
        attach: at,
    });
    ended.events.last_mut().unwrap().instance =
        Some(InstanceId::new("i-0333333333333333a").unwrap());
    assert_eq!(
        ended.registrant(&late),
        crate::failover::records::Registration::Ended
    );
    let stranger = Pair {
        key: crate::failover::records::attachment_key(9).unwrap(),
        ..late
    };
    let flip = Some(Target::of(&shard_record(4)));
    for (registrant, unheld, recorded_holder) in [
        (late, Some((Check::Unheld, None)), None),
        (
            stranger,
            Some((Check::NotHolding(NotSole::ForeignRegistrant), flip)),
            Some((Check::NotHolding(NotSole::ForeignHolder), flip)),
        ),
    ] {
        for (third_holds, expected) in [(false, unheld), (true, recorded_holder)] {
            let store = store(shard_record(4), ended.clone());
            let mut card = Card::new();
            card.entries = vec![
                Registrant {
                    cntlid: 1,
                    pair: own(),
                    holder: false,
                },
                Registrant {
                    cntlid: 2,
                    pair: registrant,
                    holder: false,
                },
                Registrant {
                    cntlid: 3,
                    pair: third,
                    holder: third_holds,
                },
            ];
            let result = restart().run(&mut client(&store), &sample(), &mut card);
            let Some(expected) = expected else {
                let restarted = result.expect("the lineage arm preempts the recorded holder");
                assert!(restarted.lineage(), "{registrant:?}");
                assert_eq!(card.log, ARM, "{registrant:?}");
                assert_eq!(card.preempted, [third.key], "{registrant:?}");
                assert_eq!(shard_now(&store).attempts, 5, "{registrant:?}");
                let (_, _, (admitted, _), _, _, _) = restarted.into_parts();
                assert!(admitted.contains(&registrant), "{admitted:?}");
                continue;
            };
            let refused = result.unwrap_err();
            assert_eq!(
                (refused.check, refused.flip),
                expected,
                "{registrant:?} third holds {third_holds}"
            );
            assert_eq!(
                card.log,
                FULL[..4],
                "{registrant:?} third holds {third_holds}"
            );
            assert_eq!(shard_now(&store).attempts, 4);
        }
    }
}

/// ENDED-GRANTS-NOTHING on a volume reread: an end of the own entry committed after a Report's bytes refuses
/// `Local::Ended` with no flip at that Report's reread, on a Report the step-1 record accepts and on one whose unknown
/// registrant the reread judges. At Report #1 the refusal precedes the bump; at Report #2 it follows the bump and the
/// self preempt and returns no fencing capability.
#[test]
fn an_end_of_the_own_entry_seen_at_a_report_reread_refuses_with_no_flip() {
    let stranger = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::records::attachment_key(9).unwrap(),
    };
    for (at, listed) in [(1, true), (1, false), (2, false)] {
        let store = store(shard_record(4), volume_record());
        let mut card = Card::new();
        if listed {
            card.entries.push(Registrant {
                cntlid: 2,
                pair: stranger,
                holder: false,
            });
        }
        card.on_report_at = at;
        let writer = store.clone();
        card.on_report = Some(Box::new(move || {
            let mut writer = client(&writer);
            let read = writer
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            let mut next = read.value().clone();
            next.events[0].kind = EventKind::Ended;
            writer.replace(&read, next).unwrap();
        }));
        let refused = restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip, refused.recovery),
            (Check::Local(Local::Ended), None, None),
            "Report #{at}, stranger listed: {listed}"
        );
        let (log, attempts) = if at == 1 {
            (&FULL[..4], 4)
        } else {
            (&FULL[..], 5)
        };
        assert_eq!(card.log, log, "Report #{at}, stranger listed: {listed}");
        assert_eq!(
            shard_now(&store).attempts,
            attempts,
            "Report #{at}, stranger listed: {listed}"
        );
    }
}

/// OWNER-EVENTS at the restart over a live attach of another host with no enrolled pair and no caller-bound peer: an
/// entry that binds its instance passes and reaches the fencing boundary; the twin entry that binds none refuses
/// `Volume(Events)` with the flip before any device command.
#[test]
fn the_restart_admits_a_live_attach_that_binds_its_instance() {
    let mut bound = volume_record();
    bound.push(EventKind::Attach, Host::new(host().get() + 7).unwrap(), ERA);
    bound.events[1].instance = Some(InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap());
    let store = store(shard_record(4), bound.clone());
    let mut card = Card::new();
    restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    bound.events[1].instance = None;
    refuses_before_commands(
        restart_holder(),
        bound,
        Ok(local_record()),
        Check::Volume(Trigger::Events),
        Some(Target::of(&shard_record(4))),
    );
}

/// A host that attached again after its earlier entry went, with its pair pinning the new live attach, is no ended
/// host: its restart reaches the fencing boundary.
#[test]
fn a_host_attached_again_after_its_entry_went_restarts() {
    let mut returned = volume_record();
    returned.events[0].kind = EventKind::Gone;
    let at = returned.push(EventKind::Attach, host(), ERA).unwrap();
    returned.pairs[0].attach = at;
    assert!(!returned.ended(host()));
    let store = store(shard_record(4), returned);
    let mut card = Card::new();
    restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
}

/// A holder under a dropped ended key at Report #1 refuses `NotHolding(ForeignHolder)` with the flip, as an unrecorded
/// holder does, and stops at Report #1 with no bump. A pair still recorded for a format-3 ended entry that holds is a
/// recorded pair of another host, which the lineage arm preempts as the takeover preempts an ended predecessor's
/// recorded pair (SUPERSEDED-TENURE-PREEMPT): after its own bump the restart preempts that entry's key and reaches the
/// fencing boundary, and the pair stays among the ended pairs the tenure carries.
#[test]
fn an_ended_key_holder_and_a_recorded_ended_holder_part_at_the_restart() {
    let (dropped, late) = with_ended_late();
    let mut kept = dropped.clone();
    kept.pairs.push(RecordedPair {
        host: Host::new(host().get() + 7).unwrap(),
        pair: late,
        attach: 2,
    });
    let flip = Some(Target::of(&shard_record(4)));
    for (record, class, expected) in [
        (
            dropped,
            crate::failover::records::Registration::Ended,
            Some((Check::NotHolding(NotSole::ForeignHolder), flip)),
        ),
        (kept, crate::failover::records::Registration::Recorded, None),
    ] {
        assert_eq!(record.registrant(&late), class);
        let store = store(shard_record(4), record);
        let mut card = Card::new();
        card.entries = vec![
            Registrant {
                cntlid: 1,
                pair: own(),
                holder: false,
            },
            holder(late, 2),
        ];
        let result = restart().run(&mut client(&store), &sample(), &mut card);
        let Some(expected) = expected else {
            let restarted =
                result.expect("the lineage arm preempts the ended entry's recorded pair");
            assert!(restarted.lineage(), "{class:?}");
            assert_eq!(card.log, ARM, "{class:?}");
            assert_eq!(card.preempted, [late.key], "{class:?}");
            assert_eq!(shard_now(&store).attempts, 5, "{class:?}");
            let (_, _, _, _, _, ended) = restarted.into_parts();
            assert_eq!(&ended[..], [late], "{class:?}");
            continue;
        };
        let refused = result.unwrap_err();
        assert_eq!((refused.check, refused.flip), expected, "{class:?}");
        assert_eq!(card.log, FULL[..4], "{class:?}");
        assert_eq!(shard_now(&store).attempts, 4, "{class:?}");
    }
}

/// Under `N_reg` below the reservation limits, a Report #1 whose count the own pair and a late Register under an ended
/// key account for is no observation with no flip and no bump; a registrant under a key past the record's next number
/// in its place refuses `Excess` with the flip.
#[test]
fn an_over_bound_restart_report_counts_a_late_register_under_an_ended_key() {
    let narrow = Restart {
        bounds: crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap(),
        limits: crate::storage::ReservationLimits::new(2, 2, 100, 100).unwrap(),
        ..restart()
    };
    let (ended, late) = with_ended_late();
    let stranger = Pair {
        key: crate::failover::records::attachment_key(9).unwrap(),
        ..late
    };
    for (second, check, flip) in [
        (late, Check::Unobserved, None),
        (
            stranger,
            Check::NotHolding(NotSole::Excess),
            Some(Target::of(&shard_record(4))),
        ),
    ] {
        let store = store(shard_record(4), ended.clone());
        let mut card = Card::new();
        card.entries.push(Registrant {
            cntlid: 2,
            pair: second,
            holder: false,
        });
        let refused = narrow
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!((refused.check, refused.flip), (check, flip), "{second:?}");
        assert_eq!(card.log, FULL[..4]);
        assert_eq!(shard_now(&store).attempts, 4, "no bump");
    }
}

/// Another instance than any test host's.
pub(crate) const OTHER_INSTANCE: &str = "i-0aaaaaaaaaaaaaaa0";

/// The owner's volume with its live entry bound to `instance`.
fn owner_bound_to(instance: &str) -> VolumeRecord {
    let mut volume = volume_record();
    volume.events[0].instance = Some(InstanceId::new(instance).unwrap());
    volume
}

/// Binds `host`'s stored live entry, which binds no instance, to [`OTHER_INSTANCE`] by an exact-version write, as a
/// standby attach write that names that instance for the unbound entry would.
pub(crate) fn bind_entry(store: &Shared, host: Host) {
    let mut writer = client(store);
    let read = writer
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    let mut bound = read.value().clone();
    let live = bound.live(host).unwrap();
    bound
        .events
        .iter_mut()
        .find(|event| event.seq == live)
        .unwrap()
        .instance = Some(InstanceId::new(OTHER_INSTANCE).unwrap());
    writer.replace(&read, bound).unwrap();
}

/// INSTANCE-BOUND at the restart: an own live entry bound to another instance than the holder's refuses
/// `Local(Binding)` at step 2 with no flip and no device command, though the local record binds the holder's
/// instance and the record enrolls its pair; the entry bound to the holder's own instance reaches the fencing
/// boundary; an unbound entry that a write binds to another instance during Report #1 refuses at the reread after it,
/// before the bump, with no flip.
#[test]
fn a_restart_whose_attach_entry_binds_another_instance_refuses_with_no_flip() {
    refuses_before_commands(
        restart_holder(),
        owner_bound_to(OTHER_INSTANCE),
        Ok(local_record()),
        Check::Local(Local::Binding),
        None,
    );
    let own = store(
        shard_record(4),
        owner_bound_to(restart_holder().instance.as_str()),
    );
    let mut card = Card::new();
    restart()
        .run(&mut client(&own), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);

    let store = store(shard_record(4), volume_record());
    let mut card = Card::new();
    let writer = store.clone();
    card.on_report = Some(Box::new(move || bind_entry(&writer, host())));
    let refused = restart()
        .run(&mut client(&store), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip, refused.recovery),
        (Check::Local(Local::Binding), None, None)
    );
    assert_eq!(card.log, FULL[..4]);
    assert_eq!(shard_now(&store).attempts, 4, "no bump");
}

/// Step 2 as it stood before INSTANCE-BOUND: the local record's binding and the enrolled pair, with no look at the
/// instance the live entry binds.
pub(crate) fn unbound_step_2(
    holder: &Holder,
    record: &LocalRecord,
    volume: &VolumeRecord,
) -> Result<Pair, Local> {
    if !holder.binds(record.binding()) {
        return Err(Local::Binding);
    }
    match volume.enrolled(holder.host) {
        None => Err(Local::Unenrolled),
        Some(enrolled) if enrolled != record.pair() => Err(Local::Altered),
        Some(enrolled) => Ok(enrolled),
    }
}

/// Control for INSTANCE-BOUND at the restart: step 2 without the entry's instance admits the holder over the entry
/// bound to another instance, where `bound` refuses `Binding`.
#[test]
fn negative_control_a_restart_step_2_without_the_entry_instance_admits_another_instances_attach() {
    let volume = owner_bound_to(OTHER_INSTANCE);
    assert_eq!(
        unbound_step_2(&restart_holder(), &local_record(), &volume),
        Ok(own()),
        "a holder on another instance than its attach entry's takes the restart"
    );
    assert_eq!(
        super::bound(&restart_holder(), &sample(), &volume),
        Err(Local::Binding)
    );
}

/// One recovery run over a recording store: the store requests it issued with each write's whole value, traced in
/// order with its device commands, the names of those commands, its result, the shard record it left, every log write
/// in order, the watermark its log holds and the client's alarm after it. A run that reached its capability carries
/// the session target, whether a warm source came with it and the success value's `Debug` rendering; a refused run
/// carries the typed refusal.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Run<R> {
    requests: Vec<crate::storage::store::sim::Request>,
    pub(crate) commands: Vec<&'static str>,
    result: Result<(Target, bool, String), R>,
    record: ShardRecord,
    writes: Vec<crate::storage::store::sim::Entry>,
    held: crate::storage::store::Watermark,
    alarm: crate::storage::store::Alarm,
}

/// The recording client, store and log of one run, with the tally preloaded when asked and the planted read issued.
pub(crate) struct Recording {
    pub(crate) client:
        Client<crate::storage::store::sim::Recorder, crate::storage::store::sim::Journal>,
    pub(crate) recorder: crate::storage::store::sim::Recorder,
    journal: crate::storage::store::sim::Journal,
    store: Shared,
}

impl Recording {
    /// Opens a client over `store` through a recorder and a journal. `preload` tallies outcomes on the client with
    /// [`crate::storage::store::tally_tests::preloaded`], whose requests and log writes stay out of the run, and
    /// `plant` issues one extra shard read through the client as the run's first request, the planted-read control.
    pub(crate) fn open(store: &Shared, preload: bool, plant: bool) -> Self {
        let recorder = crate::storage::store::sim::Recorder::new(store);
        let journal = crate::storage::store::sim::Journal::default();
        let mut client = Client::open(recorder.clone(), journal.clone()).unwrap();
        if preload {
            crate::storage::store::tally_tests::preloaded(&mut client, store);
        }
        recorder.take();
        journal.take();
        if plant {
            client.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        }
        Self {
            client,
            recorder,
            journal,
            store: store.clone(),
        }
    }

    /// Collects the run that issued `commands` and returned `result`. An admitted client's watermark is the one its
    /// log holds (WATERMARK).
    pub(crate) fn finish<R>(
        self,
        commands: Vec<&'static str>,
        result: Result<Restarted, R>,
    ) -> Run<R> {
        let alarm = self.client.alarm();
        let held = self.journal.log.held();
        if alarm == crate::storage::store::Alarm::Clear {
            assert_eq!(&held, self.client.watermark(), "the log holds the mark");
        }
        Run {
            requests: self.recorder.take(),
            commands,
            result: result.map(|reached| {
                (
                    reached.session().target(),
                    reached.warm().is_some(),
                    without_fencing_ids(&format!("{reached:?}")),
                )
            }),
            record: crate::storage::store_tests::stored(&self.store).1,
            writes: self.journal.take(),
            held,
            alarm,
        }
    }
}

/// `debug` with each fencing's process-unique `id` replaced by `_`, so two runs that fenced alike compare equal.
fn without_fencing_ids(debug: &str) -> String {
    const FIELD: &str = " id: ";
    let mut blanked = String::with_capacity(debug.len());
    let mut rest = debug;
    while let Some(at) = rest.find(FIELD) {
        let (head, tail) = rest.split_at(at + FIELD.len());
        blanked.push_str(head);
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            blanked.push('_');
        }
        rest = &tail[digits..];
    }
    blanked.push_str(rest);
    blanked
}

/// Monitors observe: equal records, device double and faults give equal runs whether the client's tally is zero or
/// preloaded by [`crate::storage::store::tally_tests::preloaded`], for a run that reaches `target`, with a warm
/// source exactly when `warm`, and for one whose write after `passes` passing requests ends with `unknown`, which
/// `refused` names; returns the zero-tally run of that unknown outcome. `run(arms, preload, plant)` schedules `arms`
/// over a [`Recording`]. The log cells of the tally and a withdrawn alarm are never preloaded, since either withdraws
/// the client before the run.
///
/// Three in-test controls show what the comparison sees. The planted read, one extra shard read in one of two runs
/// over equal tallies, makes the runs differ, and removing that one request makes them equal. A trace with one
/// store request moved across one device command differs while the two lists it interleaves stay equal. A journal
/// with one log write dropped differs.
pub(crate) fn same_runs_whatever_the_tally<R: Clone + PartialEq + std::fmt::Debug>(
    run: impl Fn(&[Arm], bool, bool) -> Run<R>,
    (passes, unknown): (usize, Arm),
    target: Target,
    warm: bool,
    refused: impl Fn(&R) -> bool,
) -> Run<R> {
    let reached = run(&[], false, false);
    assert_eq!(
        reached,
        run(&[], true, false),
        "a run that reaches its capability"
    );
    let Ok((at, warmed, _)) = &reached.result else {
        panic!("the clean run refused: {:?}", reached.result);
    };
    assert_eq!((at, *warmed), (&target, warm));
    assert_eq!(reached.alarm, crate::storage::store::Alarm::Clear);
    assert!(!reached.writes.is_empty(), "the run wrote the log");

    let mut arms = vec![Arm::Pass; passes];
    arms.push(unknown);
    let lost = run(&arms, false, false);
    assert_eq!(lost, run(&arms, true, false), "{unknown:?}");
    assert!(!lost.requests.is_empty(), "{unknown:?}");
    assert_eq!(
        lost.alarm,
        crate::storage::store::Alarm::Clear,
        "{unknown:?}"
    );
    match &lost.result {
        Err(refusal) => assert!(refused(refusal), "{refusal:?}"),
        Ok(_) => panic!("the {unknown:?} run reached its capability"),
    }

    let mut planted = run(&[], true, true);
    assert_ne!(
        planted, reached,
        "the planted read is invisible to the comparison"
    );
    assert_eq!(
        planted.requests.remove(0),
        crate::storage::store::sim::Request::Read(Key::Shard(shard()))
    );
    assert_eq!(planted, reached, "the planted read is the only difference");

    let device = |request: &crate::storage::store::sim::Request| {
        matches!(request, crate::storage::store::sim::Request::Device(_))
    };
    let at = (1..reached.requests.len())
        .find(|&at| device(&reached.requests[at]) != device(&reached.requests[at - 1]))
        .expect("the run interleaves store requests and device commands");
    let mut moved = reached.clone();
    moved.requests.swap(at - 1, at);
    let split = |run: &Run<R>| -> (Vec<_>, Vec<_>) {
        run.requests
            .iter()
            .cloned()
            .partition(|request| device(request))
    };
    assert_eq!(split(&moved), split(&reached));
    assert_ne!(
        moved, reached,
        "the order of store requests and device commands is invisible"
    );

    let mut dropped = reached.clone();
    dropped.writes.remove(0);
    assert_ne!(dropped, reached, "a dropped log write is invisible");
    lost
}

/// One restart from `record`: see [`Recording::open`] for `preload` and `plant`.
fn restart_over_a_tally(
    record: ShardRecord,
    arms: &[Arm],
    preload: bool,
    plant: bool,
) -> Run<Refused> {
    let store = self::store(record, volume_record());
    let mut recording = Recording::open(&store, preload, plant);
    for arm in arms {
        store.schedule(*arm);
    }
    let mut card = Card::new();
    card.trace = Some(recording.recorder.clone());
    let result = restart().run(&mut recording.client, &sample(), &mut card);
    recording.finish(card.log, result)
}

/// Monitors observe for the restart: a cold restart that reaches FB, one whose bump ends with an unknown outcome after
/// its device commands, and a warm restart whose record names a checkpoint issue the same requests and commands,
/// return the same result and leave the same record, log writes and alarm whatever the tally holds.
#[test]
fn a_restart_issues_the_same_requests_and_commands_whatever_the_tally_holds() {
    let cold = shard_record(4);
    assert_eq!(cold.checkpoint, None);
    let lost = same_runs_whatever_the_tally(
        |arms, preload, plant| restart_over_a_tally(cold, arms, preload, plant),
        // The volume read, the shard read and the volume reread after Report #1 precede the bump.
        (3, Arm::Timeout { commit: false }),
        Target::of(&shard_record(5)),
        false,
        |refused| refused.check == Check::Bump(StoreError::Unknown),
    );
    assert!(
        !lost.commands.is_empty(),
        "the unknown bump follows device commands"
    );

    let warm = ShardRecord {
        checkpoint: Some(crate::failover::records::NamedCheckpoint {
            slot: 1,
            session: crate::net::ownership::session_of(shard_of().generation.get() as u32, 4),
            capture: 3,
            units: 2,
        }),
        cut: 5,
        ..cold
    };
    let reached = restart_over_a_tally(warm, &[], false, false);
    assert_eq!(reached, restart_over_a_tally(warm, &[], true, false));
    assert!(
        matches!(reached.result, Ok((at, true, _)) if at == Target::of(&ShardRecord { attempts: 5, ..warm })),
        "{:?}",
        reached.result
    );
}
