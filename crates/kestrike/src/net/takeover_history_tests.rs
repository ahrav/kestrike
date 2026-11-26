//! Histories of one shard across host loss, recorded from the production takeover sequence, the warm attach, an
//! owner over the taken volume and a client with the shared shard routes, and judged by the history oracle.
//!
//! Tenure A publishes objects whose bytes the oracle generates, captures them and writes its checkpoint through its
//! own unit commands, the capture and the unit writes driven from the test; its volume drops without quiesce. In the
//! suffix cases the tenure before A is that capturing tenure. A successor runs `Takeover::run` over the store double and
//! a scripted reservation card, attaches the same media with the capability it reached, and serves a client through
//! `Owner::poll`. A fresh host is attached, enrolled and designated by the reconciler's own steps. The history holds
//! A's publications and captures, each fault the test injected as a damage row on the device unit it changed, the
//! activation each attach reached with the entries its index holds as restores, and every client GET with the
//! route's high-water and the bytes the client received. A successor's loss report excuses nothing: a damage row
//! comes only from the injector.
//!
//! One reservation table serves every host's card and every tenure's medium commands. A takeover's card preempts on it,
//! and each tenure's device completes a read or a write with Reservation Conflict once that table holds no registration
//! of the tenure's pair (the no-fence control alone clears that script), so a deposed tenure's medium commands end as
//! an exclusive-access reservation ends them for a command issued after the preempt, NEW-EXCLUSION. A command that
//! executed before the preempt keeps its bytes, and each test asserts that a tenure it keeps stepping holds no waiting
//! command when a takeover preempts it, so no history relies on the reservation ending a command queued before the
//! preempt, END. The device's Reservation Report is answered from a table of the tenure's own, which shows the tenure
//! holding until the tenure is deposed and from then on takes the shared reservation's registrants at each owner turn.
//! Each tenure's serving clock reads the tenure's own true-time cell through the world's strategy. The cell advances
//! `ROUND_US` for each round the tenure steps or pauses, and a nested tenure's rounds leave it unchanged, so the outer
//! tenure's clock stands still until its next round. The strategy is `Frozen` under the fixture bounds by default: a
//! frozen tenure submits no periodic Report after its first, so it observes deposition through its medium commands
//! and its coverage page writes, while its client's route refuses its frames at receive and tells the tenure nothing.
//! A history that sets `Honest` or `Slow` with a finite window also lets a deposed tenure observe a Report that shows
//! its successor holding.
//!
//! The suffix cases add a tenure before A: it runs the volume, captures the cut and publishes a replacement, whose
//! one suffix block the test places on its delta unit. A, the owner the record then names, runs no volume: the store
//! records A's suffix by `checkpoint::reserve_suffix`, the test appends A's removal records to a bare `SuffixLog`,
//! takes each sealed block and marks it written with no device write, `checkpoint::certify` certifies it, and the
//! test copies the blocks' bytes onto the media, since the owner runs no suffix writer. An acknowledged INVALIDATE
//! before the loss is a coverage page write by the store client.
//!
//! Every history is judged by [`preserved`], which runs the tenure-ordered checker and then requires each member of
//! a retained set to be served or to lie on an injected unit. The client high-water rule spans every key of the
//! shard, so [`check_clients`] first judges the client's acceptances over the whole recorded history. The oracle
//! judges at most `MAX_KEYS` keys a history, so the recorded events are then judged once for each group of that
//! many objects, every group beside the activations and the damage rows, and the accounts of one activation are
//! summed over the groups; each object is in exactly one group. Each tenure that serves looks up every object it
//! knows, so a key's own first lookup, which bounds the damage that excuses it, is in its group. `World::judged`
//! asserts that premise for every tenure that read before a damage row.
//!
//! When the client judgment and every group's judgment pass, `World::judged` returns the ownership monitor's verdict
//! over the volume's steps: each takeover and restart that returns its capability emits `Fenced`, each owner turn
//! emits `Commands`, the first turn whose authority reads `Withdrawn` emits `Withdrawn`, as does a stale-owner
//! history after a coverage call that withdrew the tenure between turns, and each activation emits
//! `Recovered`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use crate::failover::evidence::{Pair, RESERVATION_CONFLICT};
use crate::failover::record::LocalRecord;
use crate::failover::records::Host;
use crate::failover::restart::Restarted;
use crate::failover::restart::tests as restart_tests;
use crate::failover::takeover::Refused;
use crate::failover::takeover::tests::{
    CONDITION, Card, Reservation, a_holds_c_registered, b_host, b_pair, c_host, c_pair, d_host,
    designate_fresh_host, fence_page_zero, hooked, stored_b, stored_c, takeover_of,
};
use crate::oracle::ownership::{self, Step};
use crate::oracle::{
    Acceptance, BoundaryEvent, ClientId, CutId, Failure, Hypothesis, Inconclusive, KeyId, Label,
    MAX_KEYS, NoInformation, Obligation, Outcome, Preserved, Recorder, Script, Tenure, Verdict,
    check_clients, preserved,
};
use crate::storage::device::sim::{Fault, ScriptReason, ScriptRefusal, SimControl, Stage};
use crate::storage::gate_fixture::{
    Control, OwnerClock, Reserving, Strategy, bounds_of, bounds_with, limits,
};
use crate::storage::owner_fixture::TestPlatform;
use crate::storage::page_coverage::Interval;
use crate::storage::store::sim::Shared;
use crate::storage::store::{Client as StoreClient, Store, WatermarkLog};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::warm_sim::{
    Appended, TenureA, acknowledged_invalidation, attach_successor, object_key, payload_unit,
    row_unit, shard_store, storage, tenure_a_with,
};
use crate::storage::write_guard::{self, Guarded};
use crate::storage::{
    CacheVersion, CommandToken, DeviceStatus, EngineBudget, IO_UNIT, LoadRefusal, MetadataOutcome,
    Operation, Readiness, ServingAuthority, Storage, WorkBudget,
};

use super::ShardRoutes;
use super::client::{Client, PollReport, SessionState};
use super::fetch::{Outcome as Fetched, Releases};
use super::frame::Status;
use super::link::{Faults, LinkEnd, Net, network};
use super::owner::{Bundle, Keys, Owner};
use super::owner_tests::{Mux, OWNER, PRINCIPALS, collect, entries};
use super::requests::RequestId;

mod alarm_histories;
pub(crate) mod cycles;
#[warn(clippy::disallowed_methods, clippy::disallowed_types)]
pub(crate) mod fleet;
mod gameday_export;
mod hold_order;
mod stale_owner;

/// The hypothesis the recovery rows are recorded under.
const EVIDENCE: Hypothesis = Hypothesis("warm-takeover");
/// The retained cut: the capturing tenure's capture 9 and the suffixes the record names.
const CUT: CutId = CutId(9);
const CLIENT: ClientId = ClientId(1);
const METADATA: u32 = 4;
const BODY: u64 = 40;
const ACK: Outcome = Outcome::Acknowledged;
/// The microseconds one round of a tenure lasts: each round advances the tenure's true-time cell by this much, and
/// the tenure's client and owner poll at its round number times this.
const ROUND_US: u64 = 100;
/// The device log of a takeover by a host that registers its key first.
const REGISTERING: [&str; 7] = [
    "start", "ready", "host", "report", "register", "preempt", "report",
];

/// The bytes of object `n` under `label`, from the oracle's generator.
fn content(n: u8, label: Label) -> Vec<u8> {
    Recorder::content(KeyId(n), label, METADATA, BODY)
}

/// The label the capturing tenure published object `n` under.
fn first(n: u8) -> Label {
    Label(u64::from(n))
}

/// The tenure of session `session`.
fn tenure_of(session: u64) -> Tenure {
    Tenure {
        g: session >> 32,
        a: session & 0xFFFF_FFFF,
    }
}

/// One object the history knows: its number, when the cut's checkpoint captured its first label, that label's
/// slot row's and payload's device units, and a later label with its payload's device unit.
struct Object {
    n: u8,
    units: Option<(u32, u32)>,
    later: Option<(Label, u32)>,
}

impl Object {
    /// The labels a GET of the object may return, the latest first.
    fn labels(&self) -> Vec<Label> {
        (self.later.iter().map(|(label, _)| *label))
            .chain([first(self.n)])
            .collect()
    }
}

/// What a client GET returned.
enum Answer {
    /// A complete read of a label's bytes.
    Hit(Label, Vec<u8>),
    /// The owner found the label's record and its header failed the read's checks; no byte was surfaced.
    Unreadable(Label),
    /// The client surfaced these bytes, a prefix of the label's content, and the read then ended without its
    /// completion.
    Cut(Label, Vec<u8>),
    Missing,
    /// Any other outcome, with no byte surfaced.
    Refused,
}

/// One recorded event of a shard's history.
enum Event {
    /// An acknowledged publication of an object's label, before the host loss or in a successor's tenure.
    Publish {
        n: u8,
        label: Label,
        tenure: Option<Tenure>,
    },
    /// The cut's capture of an object's label on its row and payload units.
    Captured {
        n: u8,
        label: Label,
        units: (u32, u32),
    },
    /// An acknowledged INVALIDATE of every label of an object, before the host loss or in a successor's tenure.
    Invalidate { n: u8, tenure: Option<Tenure> },
    /// An eviction of an object's label before the host loss; `durable` when its removal record reached the media.
    Evict { n: u8, label: Label, durable: bool },
    /// A fault the test injected on a device unit.
    Damaged { unit: u32 },
    /// The loss of the whole volume.
    VolumeLost,
    /// A successor's activation, from the cut or from none.
    Activate { tenure: Tenure, cut: Option<CutId> },
    /// An object's label the successor's index holds from the cut.
    Restore { n: u8, label: Label, tenure: Tenure },
    /// A client GET a tenure answered, with the route's high-water when the GET ended and whether the client
    /// admitted the response: false when its shard route refused a response frame during the GET.
    Read {
        n: u8,
        tenure: Tenure,
        high_water: Option<Tenure>,
        accepted: bool,
        answer: Answer,
    },
}

impl Event {
    /// The object the event is about; `None` for an event every group's history holds.
    fn object(&self) -> Option<u8> {
        match self {
            Self::Publish { n, .. }
            | Self::Captured { n, .. }
            | Self::Invalidate { n, .. }
            | Self::Evict { n, .. }
            | Self::Restore { n, .. }
            | Self::Read { n, .. } => Some(*n),
            Self::Damaged { .. } | Self::VolumeLost | Self::Activate { .. } => None,
        }
    }

    fn record(&self, script: &mut Script) {
        match self {
            Self::Publish { n, label, tenure } => {
                script.in_tenure(*tenure);
                script.publish_sized(KeyId(*n), *label, METADATA, BODY);
            }
            Self::Captured { n, label, units } => {
                script.captured(EVIDENCE, (KeyId(*n), *label), CUT, *units);
            }
            Self::Invalidate { n, tenure } => {
                script.in_tenure(*tenure);
                script.invalidate(KeyId(*n), ACK);
            }
            Self::Evict { n, label, durable } => {
                if !durable {
                    script.without_information_next();
                }
                script.evict(KeyId(*n), *label);
            }
            Self::Damaged { unit } => script.damaged(EVIDENCE, Some(*unit)),
            Self::VolumeLost => script.damaged(EVIDENCE, None),
            Self::Activate { tenure, cut } => {
                script.activate(EVIDENCE, Some(*tenure), *cut);
            }
            Self::Restore { n, label, tenure } => {
                script.in_tenure(Some(*tenure));
                script.restore(KeyId(*n), *label, CUT);
            }
            Self::Read {
                n,
                tenure,
                high_water,
                accepted,
                answer,
            } => {
                script.in_tenure(Some(*tenure));
                script.by_client(Some(CLIENT));
                script.observe_next(Acceptance {
                    high_water: *high_water,
                    accepted: *accepted,
                });
                let (key, lengths) = (KeyId(*n), (METADATA, BODY));
                match answer {
                    Answer::Hit(label, bytes) => {
                        let op = script.lookup(key, Outcome::Hit, Some(*label));
                        let (complete, bytes) = (Outcome::Complete, bytes.clone());
                        script.deliver_sized(op, key, *label, lengths, complete, bytes);
                    }
                    Answer::Unreadable(label) => {
                        let op = script.lookup(key, Outcome::Hit, Some(*label));
                        let damaged = Outcome::Damaged(Failure::HeaderMismatch);
                        script.deliver_sized(op, key, *label, lengths, damaged, Vec::new());
                    }
                    Answer::Cut(label, bytes) => {
                        let op = script.lookup(key, Outcome::Hit, Some(*label));
                        let lost = Outcome::Damaged(Failure::Lost);
                        script.deliver_sized(op, key, *label, lengths, lost, bytes.clone());
                    }
                    Answer::Missing => {
                        script.lookup(key, Outcome::Missing, None);
                    }
                    Answer::Refused => {
                        let refused = Outcome::NoInformation(NoInformation::Refused);
                        script.lookup(key, refused, None);
                    }
                }
                script.by_client(None);
            }
        }
        script.in_tenure(None);
    }
}

/// One shard: the capturing tenure's media and write attempts, the store, the reservation every host's card and
/// device share, the client's routes, the fresh host's local record once the reconciler enrolled it, the history so
/// far, and the one ownership-step list every tenure of the volume emits into.
struct World {
    shard: crate::net::ownership::Shard,
    /// Whether the world holds the single-shard fixture's shard, hosts and pairs. The methods that name those
    /// hosts or that shard's keys assert it before any store request.
    fixture: bool,
    a: TenureA,
    records: Shared,
    reservation: Rc<RefCell<Reservation>>,
    routes: Arc<ShardRoutes>,
    events: Vec<Event>,
    objects: Vec<Object>,
    fresh: Option<LocalRecord>,
    /// `World::host` uses the first matching `generated` record in preference to the host's fixture record.
    generated: Vec<(Host, LocalRecord)>,
    /// The successors served so far, which numbers each one's boot nonces.
    served: u8,
    steps: Rc<RefCell<Steps>>,
    /// What the write guard saw over every tenure served.
    guarded: Guarded,
    /// The serving clock strategy and the bounds the next tenure starts under: `Frozen` and the fixture bounds
    /// unless a history sets a moving clock with a finite window.
    strategy: Strategy,
    bounds: crate::failover::bounds::Bounds,
}

/// The volume's ownership steps in emission order, and whether a tenure's device capture passed its bound.
#[derive(Default)]
struct Steps {
    list: Vec<Step>,
    /// Set in each deposed turn, whose success list reads the capture, when each tenure's `serve` call returns and
    /// when a torn-down tenure's drain ends.
    /// A judgment inside a tenure sees that tenure's overflow only from a deposed turn it follows; no later tenure
    /// clears the flag.
    overflowed: bool,
    /// The length of `World::events` at the previous `Fenced` step, zero before the first, which bounds the events
    /// a fence scans for a recorded whole-volume loss.
    events_at_fence: usize,
}

impl World {
    /// Tenure A published and captured objects `1..=count`; the record names C as standby and, when `with_b`, the
    /// volume record also enrolls B, attached and registered.
    fn new(count: u8, with_b: bool) -> Self {
        let a = tenure_a_with(count, |n| content(n, first(n)));
        let records = shard_store(a.named, with_b);
        Self::over(a, records, with_b, |_| None)
    }

    /// The shard of `a`'s media and `records`: a publication and a capture of each object of `a`'s checkpoint
    /// under the object's first label, the later label and payload unit `later` gives an object, A's activation
    /// evidence on coverage page 0, and A holding the reservation with C registered and, when `with_b`, B.
    fn over(
        a: TenureA,
        records: Shared,
        with_b: bool,
        later: impl Fn(u8) -> Option<(Label, u32)>,
    ) -> Self {
        fence_page_zero(&records);
        let reservation = a_holds_c_registered();
        if with_b {
            let b = crate::failover::fresh::tests::registrant(b_pair(), 3, false);
            reservation.borrow_mut().entries.push(b);
        }
        let held = (shard(), records, reservation);
        let mut world = Self::assemble(a, held, super::client_tests::routes(), later);
        world.fixture = true;
        world
    }

    /// Panics unless the world holds the single-shard fixture: `what` acts on that fixture's shard and hosts.
    fn fixture_only(&self, what: &str) {
        assert!(
            self.fixture,
            "{what} acts on the single-shard fixture, and this world holds shard {}",
            self.shard.get()
        );
    }

    /// The world uses `a`'s media, `records`, and the volume reservation table `reservation` for `shard`, and its
    /// clients share `routes`. Its history starts with a publication and a capture of each object of `a`'s
    /// checkpoint under the object's first label; `later` gives an object its later label and that label's payload
    /// unit. The caller seeds the records and fences the shard's coverage. `invalidate`, `designate_fresh`, `host`,
    /// `takeover`, `restart_of_a` and `evidence` serve only a world `over` built.
    fn assemble(
        a: TenureA,
        (shard, records, reservation): (
            crate::net::ownership::Shard,
            Shared,
            Rc<RefCell<Reservation>>,
        ),
        routes: Arc<ShardRoutes>,
        later: impl Fn(u8) -> Option<(Label, u32)>,
    ) -> Self {
        let number = |key: &[u8; 32]| {
            let n = (1..=u8::MAX).find(|&n| object_key(n) == *key);
            n.expect("a published key")
        };
        let mut objects = Vec::new();
        for (index, entry) in a.entries.iter().enumerate() {
            let n = number(&entry.key);
            objects.push(Object {
                n,
                units: Some((row_unit(a.named, index), payload_unit(entry))),
                later: later(n),
            });
        }
        let published = objects.iter().map(|o| Event::Publish {
            n: o.n,
            label: first(o.n),
            tenure: None,
        });
        let captured = objects.iter().map(|o| Event::Captured {
            n: o.n,
            label: first(o.n),
            units: o.units.expect("a captured object"),
        });
        let events = published.chain(captured).collect();
        Self {
            shard,
            fixture: false,
            a,
            records,
            reservation,
            routes,
            events,
            objects,
            fresh: None,
            generated: Vec::new(),
            served: 0,
            steps: Rc::default(),
            guarded: Guarded::default(),
            strategy: Strategy::Frozen,
            bounds: bounds_of(limits()),
        }
    }

    fn units(&self, n: u8) -> (u32, u32) {
        let object = self.objects.iter().find(|object| object.n == n);
        object
            .and_then(|object| object.units)
            .expect("a captured object")
    }

    /// The objects with a row on device unit `unit` or their payload on it.
    fn on_unit(&self, unit: u32) -> Vec<u8> {
        (self.objects.iter())
            .filter(|o| {
                o.units
                    .is_some_and(|(row, payload)| row == unit || payload == unit)
            })
            .map(|o| o.n)
            .collect()
    }

    /// Flips every byte of device unit `unit` and records the damage.
    fn corrupt(&mut self, unit: u32) {
        self.flip(unit);
        self.events.push(Event::Damaged { unit });
    }

    /// Flips every byte of device unit `unit`, with no damage row.
    fn flip(&self, unit: u32) {
        let at = unit as usize * IO_UNIT;
        for byte in &mut self.a.media.borrow_mut()[at..at + IO_UNIT] {
            *byte ^= 0xA5;
        }
    }

    /// Writes `bytes` over device unit `unit`.
    fn land(&self, unit: u32, bytes: &[u8]) {
        let at = unit as usize * IO_UNIT;
        self.a.media.borrow_mut()[at..at + IO_UNIT].copy_from_slice(bytes);
    }

    /// The bytes of device unit `unit`.
    fn unit(&self, unit: u32) -> Vec<u8> {
        let at = unit as usize * IO_UNIT;
        self.a.media.borrow()[at..at + IO_UNIT].to_vec()
    }

    /// Lands again every write attempt of A that wrote device unit `unit`, in A's order.
    fn land_again(&self, unit: u32) -> usize {
        let mut landed = 0;
        for attempt in &self.a.attempts {
            if attempt.covers(u64::from(unit)) {
                attempt.land(&self.a.media);
                landed += 1;
            }
        }
        landed
    }

    /// A's acknowledged INVALIDATE of object `n`: its coverage page write and its row.
    fn invalidate(&mut self, n: u8) {
        self.fixture_only("invalidate");
        acknowledged_invalidation(&self.records, object_key(n));
        self.events.push(Event::Invalidate { n, tenure: None });
    }

    /// The coverage page key of object `n`.
    fn page_key(&self, n: u8) -> crate::storage::store::Key {
        let pages = restart_tests::shard_now_of(&self.records, self.shard).pages;
        let page = crate::storage::page_coverage::page_of(&object_key(n), pages);
        crate::storage::store::Key::Page(self.shard, page)
    }

    /// The reconciler's fresh-host steps for D over the record as it stands: a census slot, D's recorded attach, its
    /// enrolled pair, and the designation that names D standby.
    fn designate_fresh(&mut self) {
        self.fixture_only("designate_fresh");
        self.fresh = Some(designate_fresh_host(&self.records));
        let record = restart_tests::shard_now(&self.records);
        assert_eq!(record.standby, Some(d_host()));
    }

    /// `host`'s card on the shared reservation, its pair and its local record.
    fn host(&self, host: Host) -> (Card, restart_tests::Stored) {
        self.fixture_only("host");
        let (pair, local) =
            if let Some((_, record)) = self.generated.iter().find(|(known, _)| *known == host) {
                (record.pair(), restart_tests::Stored(Ok(record.clone())))
            } else if host == restart_tests::host() {
                (restart_tests::own(), restart_tests::sample())
            } else if host == c_host() {
                (c_pair(), stored_c())
            } else if host == b_host() {
                (b_pair(), stored_b())
            } else {
                assert_eq!(host, d_host(), "a host the world knows");
                let record = self.fresh.clone().expect("the reconciler enrolled D");
                (record.pair(), restart_tests::Stored(Ok(record)))
            };
        (Card::new(pair, &self.reservation), local)
    }

    /// `host`'s takeover of the record as it stands, over the store and its card, with the card's device log. A
    /// takeover that returns `Restarted` emits its tenure's `Fenced` step and starts the next loss window; a refusal
    /// emits nothing.
    fn takeover(&self, host: Host) -> (Result<Restarted, Refused>, Vec<&'static str>) {
        let (mut card, local) = self.host(host);
        let path = takeover_of(&self.records, host);
        let taken = path.run(&mut store_client(&self.records), &local, &mut card);
        if let Ok(taken) = &taken {
            self.fence(taken);
        }
        (taken, card.log)
    }

    /// Emits `taken`'s `Fenced` step, as [`World::fence_tenure`] states for its tenure.
    fn fence(&self, taken: &Restarted) {
        self.fence_tenure(tenure_of(taken.session().get()));
    }

    /// Emits `tenure`'s `Fenced` step. Its durable cut is [`CUT`] when the shard record names a checkpoint and the
    /// history recorded no whole-volume loss since the previous fence.
    fn fence_tenure(&self, tenure: Tenure) {
        let mut steps = self.steps.borrow_mut();
        let since = std::mem::replace(&mut steps.events_at_fence, self.events.len());
        let lost = (self.events[since..].iter()).any(|event| matches!(event, Event::VolumeLost));
        let named = (restart_tests::shard_now_of(&self.records, self.shard).checkpoint).is_some();
        let durable = (named && !lost).then_some(CUT);
        steps.list.push(Step::Fenced { tenure, durable });
    }

    /// The ownership monitor's verdict over the volume's steps; `Truncated` when a device capture passed its bound, as
    /// sampled at a deposed turn or at a tenure's end.
    fn ownership(&self) -> Result<(), Verdict> {
        let steps = self.steps.borrow();
        if steps.overflowed {
            return Err(Verdict::Inconclusive(Inconclusive::Truncated));
        }
        ownership::judge(&steps.list)
    }

    /// A's restart, with the registrants the shared reservation shows.
    fn restart_of_a(&self) -> crate::failover::restart::Refused {
        self.fixture_only("restart_of_a");
        let mut card = restart_tests::Card::new();
        card.entries = self.reservation.borrow().entries.clone();
        restart_tests::restart()
            .run(
                &mut store_client(&self.records),
                &restart_tests::sample(),
                &mut card,
            )
            .unwrap_err()
    }

    /// The shard record's generation, volume, checkpoint, cut and ancestry, and the media's metadata prefix.
    fn evidence(&self) -> (crate::storage::warm_sim::Manifest, Vec<u8>) {
        self.fixture_only("evidence");
        let prefix = crate::storage::warm_sim::PREFIX as usize * IO_UNIT;
        let manifest = crate::storage::warm_sim::manifest(&self.records);
        (manifest, self.a.media.borrow()[..prefix].to_vec())
    }

    /// The client's high-water for the shard, as its routes hold it.
    fn high_water(&self) -> Option<Tenure> {
        self.routes.route(self.shard).map(|route| Tenure {
            g: route.generation().get(),
            a: u64::from(route.epoch().get()),
        })
    }

    /// Whether a recorded GET of object `n` returned `label`'s bytes.
    fn served_label(&self, n: u8, label: Label) -> bool {
        self.events.iter().any(|event| {
            matches!(event, Event::Read { n: of, answer: Answer::Hit(hit, _), .. } if *of == n && *hit == label)
        })
    }

    fn missed(&self, n: u8) -> bool {
        self.events.iter().any(
            |event| matches!(event, Event::Read { n: of, answer: Answer::Missing, .. } if *of == n),
        )
    }

    fn restored(&self) -> Vec<u8> {
        let mut restored: Vec<u8> = (self.events.iter())
            .filter_map(|event| match event {
                Event::Restore { n, .. } => Some(*n),
                _ => None,
            })
            .collect();
        restored.sort_unstable();
        restored
    }

    /// Records a restore for each slot `serving`'s storage holds resident: the object whose key routes to the slot's
    /// fingerprint, under its later label when the slot starts on that label's payload unit.
    fn record_restores(&mut self, serving: &Serving<'_>) {
        for (fingerprint, unit) in serving.resident() {
            let routed = |o: &&Object| {
                let route = serving.storage.fingerprint_of(&object_key(o.n));
                route.expect("a route").2 == fingerprint
            };
            let object = (self.objects.iter().find(routed))
                .expect("a resident slot of a key the history knows");
            let label = match object.later {
                Some((label, at)) if u64::from(at) == unit => label,
                _ => first(object.n),
            };
            let (n, tenure) = (object.n, serving.tenure);
            self.events.push(Event::Restore { n, label, tenure });
        }
    }

    /// The history of the objects of `group`, or of every object when `group` is `None`, beside the activations and
    /// the damage rows.
    fn history(&self, group: Option<&[u8]>) -> crate::oracle::History {
        let mut script = Script::new();
        for event in &self.events {
            if event
                .object()
                .is_none_or(|n| group.is_none_or(|group| group.contains(&n)))
            {
                event.record(&mut script);
            }
        }
        script.finish()
    }

    /// Asserts the premise under which each group's judgment equals the whole history's: no damage row lies between
    /// two reads of one tenure, and a tenure that read before a damage row had by then read every object an earlier
    /// event names. A member whose key is never looked up takes its damage bound from the first lookup of any key in
    /// the judged history, so with every object read, each group holds a read before the row when the whole history
    /// does.
    fn damage_outside_reads(&self) {
        let reads: Vec<(usize, Tenure, u8)> = (self.events.iter().enumerate())
            .filter_map(|(at, event)| match event {
                Event::Read { n, tenure, .. } => Some((at, *tenure, *n)),
                _ => None,
            })
            .collect();
        for (at, event) in self.events.iter().enumerate() {
            let row = match event {
                Event::Damaged { unit } => format!("unit {unit}"),
                Event::VolumeLost => "the whole volume".to_owned(),
                _ => continue,
            };
            for &(_, tenure, _) in reads.iter().filter(|&&(before, ..)| before < at) {
                let split = reads.iter().any(|&(after, t, _)| t == tenure && after > at);
                assert!(
                    !split,
                    "damage on {row} lies between two reads of one tenure"
                );
                let read = |n| {
                    let by_tenure = |&(before, t, of): &(usize, Tenure, u8)| {
                        before < at && t == tenure && of == n
                    };
                    reads.iter().any(by_tenure)
                };
                let known = self.events[..at].iter().filter_map(Event::object);
                if let Some(unread) = known.into_iter().find(|&n| !read(n)) {
                    panic!(
                        "tenure {tenure:?} read before the damage on {row} and never read object {unread}"
                    );
                }
            }
        }
    }

    /// The verdict of the history of `group` beside the activations and the damage rows.
    fn judged_group(&self, group: &[u8]) -> Result<Vec<Preserved>, Verdict> {
        preserved(&self.history(Some(group)))
    }

    /// The history's verdict: [`World::judged_history`], then, when it passes, the ownership monitor's verdict over
    /// the volume's steps: a violation under `Restart`, `Inconclusive::Malformed`, or `Inconclusive::Truncated` when a
    /// device capture passed its bound. An ownership verdict's op indexes the volume's step list, not a history row;
    /// for an empty step list the monitor returns `Malformed` at op 0.
    /// A pass returns the summed accounts.
    /// Call `judged` after all tenures end so `world` holds their guard records.
    fn judged(&self) -> Result<Vec<Preserved>, Verdict> {
        let total = self.judged_history()?;
        self.ownership()?;
        assert!(
            !write_guard::armed(),
            "a history is judged after its tenures end, when their guard records are in the world"
        );
        assert!(
            self.guarded.clean(),
            "a passing history records no write-guard conflict and skips no slot: {:?}",
            self.guarded
        );
        Ok(total)
    }

    /// The history rows' verdict: the client acceptances over the whole history, then for each group of `MAX_KEYS`
    /// objects the checker's verdict and the positive-preservation judgment of each activation, summed over the
    /// groups. A failing client judgment gives the verdict, then the first group's violation, then the first group's
    /// other failure.
    fn judged_history(&self) -> Result<Vec<Preserved>, Verdict> {
        self.damage_outside_reads();
        check_clients(&self.history(None))?;
        let numbers: Vec<u8> = self.objects.iter().map(|object| object.n).collect();
        let judged: Vec<_> = (numbers.chunks(MAX_KEYS))
            .map(|group| self.judged_group(group))
            .collect();
        let violation = judged
            .iter()
            .find(|judged| matches!(judged, Err(Verdict::Violation(_))));
        if let Some(Err(verdict)) = violation.or_else(|| judged.iter().find(|j| j.is_err())) {
            return Err(*verdict);
        }
        let mut total: Vec<Preserved> = Vec::new();
        for accounts in judged.into_iter().flatten() {
            for (at, account) in accounts.into_iter().enumerate() {
                match total.get_mut(at) {
                    Some(sum) => add_account(sum, account),
                    None => total.push(account),
                }
            }
        }
        Ok(total)
    }
}

/// Adds `account`, one group's account of an activation, to `sum`, the account of the same activation over the
/// groups judged before it.
fn add_account(sum: &mut Preserved, account: Preserved) {
    assert_eq!(sum.tenure, account.tenure, "one activation's accounts");
    sum.members += account.members;
    sum.served += account.served;
    sum.served_bytes += account.served_bytes;
    sum.excused.extend(account.excused);
}

/// A read of object `n` by `tenure` that missed.
fn missed(n: u8, tenure: Tenure) -> Event {
    Event::Read {
        n,
        tenure,
        high_water: Some(tenure),
        accepted: true,
        answer: Answer::Missing,
    }
}

/// The grouped judgment's premise passes a tenure that read every object before a damage row.
#[test]
fn a_tenure_that_read_every_object_before_a_damage_row_passes_the_premise() {
    let mut world = World::new(4, false);
    let tenure = Tenure { g: 3, a: 10 };
    (world.events).extend((1..=4).map(|n| missed(n, tenure)));
    world.events.push(Event::Damaged { unit: 7 });
    world.damage_outside_reads();
}

/// The grouped judgment's premise refuses a tenure that reads one object and then meets a damage row: the objects it
/// never read take their damage bound from that read in the whole history and from no read in their own group.
#[test]
#[should_panic(expected = "read before the damage on unit 7 and never read object")]
fn a_tenure_that_reads_before_a_damage_row_has_read_every_object() {
    let mut world = World::new(4, false);
    world.events.push(missed(1, Tenure { g: 3, a: 10 }));
    world.events.push(Event::Damaged { unit: 7 });
    world.damage_outside_reads();
}

/// The premise holds a whole-volume damage row to the same rule: a tenure that read one object before the row
/// and never read the others is refused.
#[test]
#[should_panic(expected = "read before the damage on the whole volume and never read object")]
fn a_tenure_that_reads_before_a_volume_loss_row_has_read_every_object() {
    let mut world = World::new(4, false);
    world.events.push(missed(1, Tenure { g: 3, a: 10 }));
    world.events.push(Event::VolumeLost);
    world.damage_outside_reads();
}

/// A whole-volume damage row between two reads of one tenure is refused.
#[test]
#[should_panic(expected = "damage on the whole volume lies between two reads of one tenure")]
fn a_volume_loss_row_between_two_reads_of_one_tenure_is_refused() {
    let mut world = World::new(4, false);
    let tenure = Tenure { g: 3, a: 10 };
    (world.events).extend((1..=4).map(|n| missed(n, tenure)));
    world.events.push(Event::VolumeLost);
    world.events.push(missed(1, tenure));
    world.damage_outside_reads();
}

/// How a successor's attach finds its entries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The warm source the takeover named.
    Named,
    /// No source: the attach starts cold.
    Cold,
}

/// The production serving duties a fleet tenure runs after each owner poll of a fleet round, over an inline store
/// lane whose client reaches the store through its own fault actor, inside its holder host's outages.
type FleetDuties<'w> = crate::host::Duties<
    'w,
    fleet::HostOut<crate::storage::store::sim::Faulted<fleet::DutyCounted>>,
    crate::storage::store::sim::MemLog,
    TestPlatform,
>;

/// The suffix bounds of a tenure's suffix open: the World's own (`Serving::open_suffix`) and a fleet tenure's serving
/// duties take the same bounds.
fn suffix_bounds() -> crate::storage::checkpoint::SuffixBounds {
    crate::storage::checkpoint::SuffixBounds {
        limits: crate::storage::checkpoint::SuffixLimits {
            flush_ns: 1,
            queue_blocks: 8,
            oldest_ns: 1 << 40,
            uncertified: 16,
        },
        step: 2,
        margin: 1,
    }
}

/// One tenure serving: the owner over the taken volume, a client on one link to it, the device, and the shared
/// reservation with the tenure's pair.
struct Serving<'w> {
    owner: Owner<'w, 'w, 'w, TestPlatform, Reserving, Mux<'w>>,
    /// The tenure's serving duties, which a fleet tenure runs once `Live`; `None` in the single-shard histories,
    /// whose owners run no record view.
    duties: Option<Box<FleetDuties<'w>>>,
    /// The exit the duties named. The duties then take no further turn, and their last observations stay for the
    /// owner's status.
    duty_exit: Option<crate::host::Exit>,
    client: Client<'w, LinkEnd<'w>>,
    net: Rc<RefCell<Net<'w>>>,
    control: SimControl,
    storage: &'w Storage<TestPlatform>,
    reservation: Rc<RefCell<Reservation>>,
    own: Pair,
    shard: crate::net::ownership::Shard,
    turn: u64,
    tenure: Tenure,
    /// The response frames the client's shard route refused at receive, summed over the client's polls.
    unrouted: u32,
    /// The commands the deposed tenure's device completes with Reservation Conflict.
    conflicted: Vec<CommandToken>,
    /// Whether a deposed tenure's waiting commands complete with Reservation Conflict; the no-fence control clears it.
    scripts_conflict: bool,
    /// The world's ownership-step list.
    steps: Rc<RefCell<Steps>>,
    /// Whether this tenure's `Withdrawn` step was emitted; the owner's authority report holds its current state.
    withdrawn: bool,
    /// The tenure's Report table, from which its device answers a Report.
    registry: Control,
    /// The Reports `registry` had logged when the tenure started serving.
    reports_from: usize,
    /// The true elapsed microseconds the tenure's serving clock reads through its strategy.
    now: Rc<Cell<u64>>,
    /// While the production bring-up (`host::serve::turn_up`) drives the owner, the tenure's `(g, owner, E)`; each
    /// owner turn is one `turn_up`, and the first turn that ends the bring-up sets `risen` and clears this.
    rising: Option<crate::failover::retire::Target>,
    /// How the production bring-up ended: `Live` or its exit short of `Live`.
    risen: Option<crate::host::serve::Rising>,
    /// The tenure's recovery line, once its first-safe-hit span has closed.
    recovery_line: Option<String>,
}

impl<'w> Serving<'w> {
    /// Whether a takeover's preempt removed the tenure's registration.
    fn deposed(&self) -> bool {
        let reservation = self.reservation.borrow();
        !reservation
            .entries
            .iter()
            .any(|entry| entry.pair == self.own)
    }

    /// The device's round ([`device_round`]), fenced once the tenure is `deposed` while `scripts_conflict` holds.
    fn device_round(&mut self, deposed: bool) {
        let fenced = deposed && self.scripts_conflict;
        device_round(&self.control, &mut self.conflicted, fenced);
    }

    /// The owner's turn at the current time. Once the tenure is deposed, its Report table first takes the shared
    /// reservation's registrants, so a Report the device answers from then on shows the successor holding.
    fn turn_owner(&mut self) {
        let deposed = self.deposed();
        // A tenure whose device answers Reports from the volume's shared table already reads its registrants.
        if deposed && !Rc::ptr_eq(&self.registry, &self.reservation) {
            let reservation = self.reservation.borrow();
            (self.registry.borrow_mut().entries).clone_from(&reservation.entries);
        }
        self.device_round(deposed);
        match self.rising {
            Some(_) => {
                let gate = crate::host::HostGate::qualified();
                let now = self.time();
                let risen = crate::host::serve::turn_up(&gate, &mut self.owner, || now);
                if risen != crate::host::serve::Rising::Initializing {
                    (self.rising, self.risen) = (None, Some(risen));
                }
            }
            None => self.owner.poll(self.time()),
        }
        self.record_turn(deposed);
    }

    /// The link, the device's medium commands, the round counter and the true-time cell advance for `rounds` rounds
    /// between owner polls.
    fn pause(&mut self, rounds: u64) {
        for _ in 0..rounds {
            self.begin_round();
            self.device_round(self.deposed());
            self.turn += 1;
        }
    }

    /// The current round's time in microseconds.
    fn time(&self) -> u64 {
        self.turn * ROUND_US
    }

    /// The client's poll at the current round's time, which puts a started GET on the link.
    fn poll_client(&mut self) -> PollReport {
        let polled = self.client.poll(self.time());
        self.unrouted += polled.unrouted;
        polled
    }

    /// Starts a round: the true-time cell takes the round's time and the link advances. Returns the round's time in
    /// microseconds.
    fn begin_round(&mut self) -> u64 {
        let now = self.time();
        self.now.set(now);
        self.net.borrow_mut().advance(self.turn);
        now
    }

    /// Emits the turn's `Commands` step ([`commands_step`]), then `Withdrawn` in the first turn whose authority report
    /// reads `Withdrawn`, unless a history emitted it already.
    fn record_turn(&mut self, deposed: bool) {
        commands_step(&self.steps, &self.control, self.tenure, deposed);
        self.note_withdrawal();
    }

    /// Emits the tenure's `Withdrawn` step, once, when its authority report reads `Withdrawn`. Each owner turn calls
    /// it after the turn's `Commands` step, and a history calls it after a coverage call that withdrew the tenure
    /// between turns.
    fn note_withdrawal(&mut self) {
        let state = self.owner.authority_report().state;
        if !self.withdrawn && state == crate::failover::serving::State::Withdrawn {
            self.withdrawn = true;
            self.steps.borrow_mut().list.push(Step::Withdrawn {
                tenure: self.tenure,
            });
        }
    }

    /// Emits a `Commands` step and then the tenure's `Withdrawn` step when its authority reads `Withdrawn` and no
    /// `Withdrawn` step was emitted yet: a withdrawal after the turn's `Commands` step, such as one the serving duties
    /// made. The ownership monitor then holds the accepted count at the withdrawal, before the device's next round.
    fn note_late_withdrawal(&mut self) {
        let state = self.owner.authority_report().state;
        if !self.withdrawn && state == crate::failover::serving::State::Withdrawn {
            self.record_turn(self.deposed());
        }
    }

    /// One round without the client: the link, the device, the owner.
    fn step_without_client(&mut self) {
        self.begin_round();
        self.turn_owner();
        self.turn += 1;
    }

    /// One round: the link, the client, the device, the owner. Returns the round's time in microseconds.
    fn step(&mut self) -> u64 {
        let now = self.begin_round();
        self.poll_client();
        self.turn_owner();
        self.turn += 1;
        now
    }

    /// Ends the tenure as `serve` ends it: `serve::teardown` closes the owner and drains it for at most `rounds`
    /// rounds past the close. Each clock read of the drain is one further round of the tenure's true-time cell and
    /// device alone: the cell takes the round's time and the device runs its round, fenced as in a serving turn,
    /// before the close or the poll that the read gates. Once the drain ends, the tenure's last `Commands` step and
    /// the overflow of its capture are sampled, so the ownership monitor judges the commands the device accepted
    /// while the owner closed. Returns whether the owner shut down with its parts returned.
    fn tear_down(self, rounds: u64) -> bool {
        let deposed = self.deposed();
        let fenced = deposed && self.scripts_conflict;
        let Serving {
            owner,
            control,
            mut conflicted,
            steps,
            now,
            tenure,
            mut turn,
            ..
        } = self;
        let clock = || {
            let at = turn * ROUND_US;
            now.set(at);
            device_round(&control, &mut conflicted, fenced);
            turn += 1;
            at
        };
        let gate = crate::host::HostGate::qualified();
        let shut = crate::host::serve::teardown(&gate, owner, clock, rounds * ROUND_US).is_ok();
        commands_step(&steps, &control, tenure, deposed);
        sample_overflow(&steps, &control);
        shut
    }

    /// Invalidates object `n` in the owner's RAM. Returns whether the invalidation removed an entry.
    fn drop_entry(&mut self, n: u8) -> bool {
        let mut budget = crate::storage::WorkBudget::new(1 << 20);
        let removed = self.owner.invalidate(&object_key(n), 4, &mut budget);
        removed.is_ok_and(|invalidation| invalidation.removed.is_some())
    }

    /// Asserts that the device holds no command accepted and not yet posted, so a preempt now ends no waiting
    /// command.
    fn idle_device(&self) {
        assert_eq!(self.control.pending(), 0, "a command waits on the device");
    }

    /// Starts a client GET of `key` with a deadline of 30 s.
    fn send(&mut self, key: [u8; 32]) -> RequestId {
        self.send_within(key, 30_000_000)
    }

    /// Starts a client GET of `key` with a deadline of `wait_us` microseconds, after one round.
    fn send_within(&mut self, key: [u8; 32], wait_us: u64) -> RequestId {
        let now = self.step();
        (self.client)
            .get(key, 1 << 16, 1 << 20, now, wait_us)
            .expect("an admitted GET")
    }

    /// Runs rounds until GET `id` has its outcome; returns it with every byte the client surfaced and whether the
    /// client's shard route admitted every response frame it received meanwhile.
    fn finish(&mut self, id: RequestId) -> (Fetched, Vec<u8>, bool) {
        let (mut bytes, unrouted) = (Vec::new(), self.unrouted);
        for _ in 0..8_000 {
            self.step();
            collect(&mut self.client, id, &mut bytes);
            if let Some(outcome) = self.client.outcome(id) {
                let _ = self.client.retire(id);
                return (outcome, bytes, self.unrouted == unrouted);
            }
        }
        panic!("the GET reached no outcome");
    }

    /// The fingerprint and the first device unit of each slot the storage holds resident.
    fn resident(&self) -> Vec<(u64, u64)> {
        let mut facts = Vec::new();
        (self.storage.slot_facts_into(&mut facts)).expect("a live pool");
        (facts.iter().filter(|fact| fact.resident))
            .map(|fact| (fact.fingerprint, fact.device_unit))
            .collect()
    }

    /// Records the outcome of a GET of object `n`, with the route's high-water now and whether the client admitted
    /// the response: a complete read as a hit of the label of `labels` whose bytes it returned, or of the first when
    /// it returned none of them; a failed header check as an unreadable hit of the first label; a miss; any other
    /// outcome as a refusal. Only a complete read may have surfaced bytes. Returns whether the read completed.
    fn record(
        &self,
        world: &mut World,
        n: u8,
        labels: &[Label],
        got: (Fetched, Vec<u8>, bool),
    ) -> bool {
        let (outcome, bytes, accepted) = got;
        let complete = outcome == Fetched::Complete;
        assert!(
            complete || bytes.is_empty(),
            "object {n}: {outcome:?} surfaced bytes"
        );
        let answer = match outcome {
            Fetched::Complete => {
                let returned = labels.iter().find(|&&label| content(n, label) == bytes);
                Answer::Hit(*returned.unwrap_or(&labels[0]), bytes)
            }
            Fetched::Failed(Status::IntegrityError) => Answer::Unreadable(labels[0]),
            Fetched::Missing => Answer::Missing,
            _ => Answer::Refused,
        };
        world.events.push(Event::Read {
            n,
            tenure: self.tenure,
            high_water: world.high_water(),
            accepted,
            answer,
        });
        complete
    }

    /// A client GET of object `n`, recorded; returns whether it completed.
    fn read(&mut self, world: &mut World, n: u8, labels: &[Label]) -> bool {
        let id = self.send(object_key(n));
        let got = self.finish(id);
        self.record(world, n, labels, got)
    }

    /// Reads every object the history knows; returns the objects that completed, ascending.
    fn read_all(&mut self, world: &mut World) -> Vec<u8> {
        let objects: Vec<(u8, Vec<Label>)> = (world.objects.iter())
            .map(|object| (object.n, object.labels()))
            .collect();
        let mut served = Vec::new();
        for (n, labels) in objects {
            if self.read(world, n, &labels) {
                served.push(n);
            }
        }
        served.sort_unstable();
        served
    }

    /// The tenure records its suffix and opens its log through `checkpoint::open_suffix` over the store double, once
    /// per tenure. A warm load requires the log, so a membership change of the tenure publishes only once the log is
    /// open. The call passes no certified ends, so it raises no predecessor suffix's certified end. Returns true when
    /// the call recorded the suffix and opened the log, and false when the store refused the reservation `Chain`.
    ///
    /// # Panics
    ///
    /// On any other refusal, and when the store recorded the suffix and the log stayed closed.
    fn open_suffix(&self, records: &Shared) -> bool {
        use crate::storage::checkpoint::{PossiblyNamed, WriteRefused, open_suffix};
        let mut host = store_client(records);
        let key = crate::storage::store::Key::Shard(self.shard);
        let read = (host.read::<crate::failover::records::ShardRecord>(key)).unwrap();
        let record = *read.value();
        let session =
            crate::net::ownership::session_of(record.generation.get() as u32, record.attempts * 2);
        let layout = crate::storage::warm_sim::layout();
        let mut possible = PossiblyNamed::new((self.shard, session), layout, record.checkpoint);
        let own = crate::failover::retire::Target::of(&record);
        let bounds = suffix_bounds();
        let opened = open_suffix(
            &mut host,
            &mut possible,
            (read, own),
            (self.storage, &[]),
            bounds,
        );
        match opened {
            Ok((_, opened)) => {
                assert!(opened, "a recorded suffix opens the tenure's log");
                true
            }
            Err(WriteRefused::Chain) => false,
            Err(refused) => panic!("the suffix reservation: {refused:?}"),
        }
    }

    fn fill(&mut self, world: &mut World, n: u8) -> bool {
        self.fill_at(world, n, crate::storage::CacheVersion(0))
    }

    /// A local fill of object `n` under its first label, streamed through the owner and published when every write
    /// completed, which records the tenure's publication. Returns whether it published.
    fn fill_at(&mut self, world: &mut World, n: u8, version: crate::storage::CacheVersion) -> bool {
        self.fill_stepped(world, n, version, |serving| {
            serving.step();
        })
    }

    /// [`Serving::fill_at`] with `step` as the round the fill runs between its writes. `step` polls the owner once.
    fn fill_stepped(
        &mut self,
        world: &mut World,
        n: u8,
        version: crate::storage::CacheVersion,
        mut step: impl FnMut(&mut Self),
    ) -> bool {
        let label = first(n);
        let payload = content(n, label);
        let (metadata, body) = (METADATA as usize, BODY as usize);
        let key = object_key(n);
        let reserved =
            crate::storage::owner_fixture::reserve_at(self.storage, &key, version, metadata, body);
        let Ok(mut fill) = reserved else {
            return false;
        };
        let mut taken = 0;
        for _ in 0..400 {
            if self.owner.fill_progress(&fill).is_ready() {
                break;
            }
            let mut budget = crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
            let rest = &payload[taken..];
            if !rest.is_empty()
                && let Ok(n) = self.owner.receive_fill(&mut fill, rest, &mut budget)
            {
                taken += n;
            }
            step(self);
        }
        if !self.owner.fill_progress(&fill).is_ready() {
            return false;
        }
        let mut budget = crate::storage::WorkBudget::new(1024);
        if (self.owner.publish_fill(fill, u64::MAX, 2, &mut budget)).is_err() {
            return false;
        }
        let tenure = Some(self.tenure);
        world.events.push(Event::Publish { n, label, tenure });
        world.objects.push(Object {
            n,
            units: None,
            later: None,
        });
        true
    }
}

/// One round of a tenure's device. While `fenced`, each medium command the device has not executed completes with
/// Reservation Conflict; a command an earlier round already gave that conflict keeps it, and any other refusal of
/// the fault, a command carrying another fault included, fails the test. Then the device ticks.
fn device_round(device: &SimControl, conflicted: &mut Vec<CommandToken>, fenced: bool) {
    if fenced {
        let conflict = Fault::Status(DeviceStatus::Nvme(RESERVATION_CONFLICT << 1));
        for token in device.ready(Stage::Execute) {
            match device.try_fault(token, conflict) {
                Ok(()) => conflicted.push(token),
                Err(ScriptRefusal {
                    reason: ScriptReason::Faulted(faulted),
                    ..
                }) if conflicted.contains(&faulted) => {}
                Err(refusal) => panic!("the conflict is refused: {refusal:?}"),
            }
        }
    }
    device.tick(64);
}

/// Emits `tenure`'s `Commands` step from `device`: the medium commands it accepted over its life and, only while
/// the tenure is `deposed`, the successes its capture lists, whose overflow then marks `steps`.
fn commands_step(steps: &RefCell<Steps>, device: &SimControl, tenure: Tenure, deposed: bool) {
    let accepted = device.accepted(Operation::Read) + device.accepted(Operation::Write);
    let mut steps = steps.borrow_mut();
    let mut succeeded = Vec::new();
    if deposed {
        let capture = device.capture();
        steps.overflowed |= capture.overflow;
        succeeded = successes(&capture);
    }
    steps.list.push(Step::Commands {
        tenure,
        accepted: accepted as u64,
        succeeded,
    });
}

/// Marks `steps` overflowed when `device`'s capture passed its bound.
fn sample_overflow(steps: &RefCell<Steps>, device: &SimControl) {
    if device.capture().overflow {
        steps.borrow_mut().overflowed = true;
    }
}

/// The acceptance ordinals of the commands `capture` delivered with success.
fn successes(capture: &crate::storage::device::sim::Capture) -> Vec<u64> {
    let mut ordinals: Vec<(u64, u64)> = Vec::new();
    let mut succeeded = Vec::new();
    for event in super::adapters::boundary(capture) {
        match event {
            BoundaryEvent::Submitted { token, ordinal, .. } => ordinals.push((token, ordinal)),
            BoundaryEvent::Delivered {
                token,
                success: true,
            } => {
                let submitted = ordinals.iter().rev().find(|(of, _)| *of == token);
                succeeded.extend(submitted.map(|&(_, ordinal)| ordinal));
            }
            BoundaryEvent::Delivered { .. } => {}
        }
    }
    succeeded
}

/// Sets the thread's inline-recovery flag and restores its prior value on drop, a drop by unwinding included.
struct Inline(bool);

impl Inline {
    fn set() -> Self {
        Self(crate::storage::INLINE_RECOVERY.with(|inline| inline.replace(true)))
    }
}

impl Drop for Inline {
    fn drop(&mut self) {
        crate::storage::INLINE_RECOVERY.with(|inline| inline.set(self.0));
    }
}

/// Each serving tenure borrows its storage, device buffers, two packet arenas, and release table for its lifetime,
/// so several tenures serve at once only over grounds that outlive them all.
struct Grounds {
    storage: Storage<TestPlatform>,
    buffers: crate::storage::BufferArena<TestPlatform>,
    packets: [crate::storage::BufferArena<TestPlatform>; 2],
    releases: Releases,
    /// The clock a fleet tenure's recovery fencer times its device steps on, which outlives the tenure as its arena
    /// does.
    fencer: fleet::owners::FencerClock,
}

impl Grounds {
    fn over(storage: Storage<TestPlatform>) -> Self {
        Self {
            storage,
            buffers: crate::storage::gate_fixture::arena_with(16, 9),
            packets: [
                super::packet::test_arena(32, 16384),
                super::packet::test_arena(32, 16384),
            ],
            releases: Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
            fencer: fleet::owners::FencerClock::default(),
        }
    }
}

struct Pools<'g> {
    receive: super::packet::PacketPool<'g>,
    client: super::packet::PacketPool<'g>,
}

impl<'g> Pools<'g> {
    fn new(grounds: &'g Grounds) -> Self {
        let view = |arena| {
            super::packet::PacketPool::new(arena, crate::storage::PoolKind::PacketReceive, 8)
                .expect("a packet pool")
        };
        Self {
            receive: view(&grounds.packets[0]),
            client: view(&grounds.packets[1]),
        }
    }
}

/// The interval every held INVALIDATE covers: the one version the capturing tenure published.
fn interval() -> Interval {
    Interval::new(CacheVersion(0), CacheVersion(0)).expect("an ordered interval")
}

/// Holds an INVALIDATE of object `n` in the tenure's coverage. Returns the owner's refusal, rendered, or whether
/// the INVALIDATE removed a resident entry.
fn hold(serving: &mut Serving<'_>, n: u8) -> Result<bool, String> {
    let mut budget = WorkBudget::new(1 << 20);
    let held = (serving.owner).invalidate_interval(&object_key(n), interval(), 4, &mut budget);
    let held = held.map_err(|refused| format!("{refused:?}"))?;
    Ok(held.is_some_and(|invalidation| invalidation.removed.is_some()))
}

/// Runs the held INVALIDATE of object `n` through its coverage page write, at most 64 rounds, and records it once
/// the owner acknowledges an entry of `n`'s key. Returns whether it was acknowledged. An INVALIDATE whose page write
/// is still unresolved after the rounds stays held. A coverage call that withdraws the owner, or one on an owner
/// already withdrawn, drops the held entries unacknowledged. Each coverage write goes through `client`.
fn publish<S: Store, L: WatermarkLog>(
    world: &mut World,
    serving: &mut Serving<'_>,
    n: u8,
    client: &mut StoreClient<S, L>,
) -> bool {
    let key = object_key(n);
    let mut acknowledged = Vec::new();
    for _ in 0..64 {
        let now = serving.step();
        if serving
            .owner
            .cover_pending(client, &mut acknowledged, now)
            .is_err()
        {
            return false;
        }
        if acknowledged.iter().any(|(of, _)| *of == key) {
            let tenure = Some(serving.tenure);
            world.events.push(Event::Invalidate { n, tenure });
            return true;
        }
    }
    false
}

/// The successor that reached `taken` attaches the media from `source` behind the shared reservation, runs its
/// bootstrap under an owner, and is recorded as the activation of its session: from the cut when the attach wrote
/// no device unit, with a restore for every resident slot of an opened load, and from no cut when it wrote. A load
/// that opened is brought to `Live` and a client session opened before `body` runs; `body` sees the bootstrap's
/// outcome. Beside the activation it emits the tenure's `Recovered` step, for a refused load as for an opened one,
/// and after `body` it sets the world's overflow flag when the tenure's capture overflowed. The guard's record moves
/// into `world` when the tenure ends, so a caller that nests a tenure must pass the same `world` as the enclosing
/// tenure.
fn serve<R>(
    world: &mut World,
    taken: Restarted,
    source: Source,
    body: impl for<'w> FnOnce(&mut World, &mut Serving<'w>, MetadataOutcome) -> R,
) -> R {
    let grounds = Grounds::over(storage(1));
    let pools = Pools::new(&grounds);
    let mut serving = open(world, (&grounds, &pools), taken, source, 0);
    // Every tenure's bootstrap, a nested one's included, runs unarmed; the guard is armed once the loop ends.
    let outer = write_guard::arm(false);
    // The recovery helpers the bootstrap starts run inline, so its ticks do not depend on thread timing.
    let inline = Inline::set();
    for _ in 0..2_000 {
        if !serving.owner.readiness().initializing() {
            break;
        }
        serving.step();
    }
    drop(inline);
    assert!(
        !serving.owner.readiness().initializing(),
        "the bootstrap finished"
    );
    // Every slot-word change from here on happens on this thread, the guard's premise.
    write_guard::arm(true);
    let outcome = activate(world, &mut serving, source);
    if outcome == MetadataOutcome::Open {
        let now = serving.step();
        serving.client.session(now);
        for _ in 0..2_000 {
            if serving.client.state() == SessionState::Active {
                break;
            }
            serving.step();
        }
        assert_eq!(serving.client.state(), SessionState::Active);
        assert_eq!(
            world.high_water(),
            Some(serving.tenure),
            "the READY bound the route"
        );
    }
    let result = body(world, &mut serving, outcome);
    closed(world, &serving);
    write_guard::arm(outer);
    world.guarded.merge(write_guard::take());
    result
}

/// `open` attaches the world's media using `taken`'s authority and `grounds`, and starts the tenure's owner and one
/// client on a link to the owner. The tenure's round counter and true-time cell start at round `turn`, before the
/// authority's first clock reading. The caller runs the bootstrap.
fn open<'w>(
    world: &mut World,
    (grounds, pools): (&'w Grounds, &'w Pools<'w>),
    taken: Restarted,
    source: Source,
    turn: u64,
) -> Serving<'w> {
    let own = taken.fenced().own();
    let tenure = tenure_of(taken.session().get());
    let now = Rc::new(Cell::new(turn * ROUND_US));
    let clock = OwnerClock {
        strategy: world.strategy,
        now: Rc::clone(&now),
    };
    let (mut authority, fencing) =
        ServingAuthority::restarted(world.bounds, Box::new(clock), taken);
    if source == Source::Cold {
        drop(authority.take_warm());
    }
    let storage = &grounds.storage;
    let (volume, control, registry) =
        attach_successor(storage, &grounds.buffers, &world.a.media, authority, own);
    let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    // Each successor's owner and client take their boot nonces from the count of successors served.
    world.served += 1;
    let served = world.served;
    let transport = Mux::new(vec![owner_end]);
    let mut budget = EngineBudget::new(1 << 26);
    let started = Owner::start_with_nonce(
        OWNER,
        bundle,
        keys,
        transport,
        &pools.receive,
        &mut budget,
        boot_nonce(served, 1),
    );
    let mut owner = started
        .map_err(|refused| refused.error)
        .expect("the owner starts");
    (owner.install_coverage(fencing)).expect("the tenure's fencing");
    Serving::started(
        world,
        (grounds, pools),
        (owner, control, registry, own),
        (tenure, now, turn),
        (client_end, net),
    )
}

/// The boot nonce of the `served`-th successor's owner (`side` 1) or client (`side` 2).
fn boot_nonce(
    served: u8,
    side: u8,
) -> impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError> {
    move |nonce: &mut [u8; 16]| {
        nonce[..2].copy_from_slice(&[served, side]);
        Ok(())
    }
}

impl<'w> Serving<'w> {
    /// The tenure of `owner`, started over `grounds` with its coverage installed, with one client on the link whose
    /// other end the owner serves. Its round counter and true-time cell start at round `turn`. The client takes its
    /// boot nonce from the world's count of successors served, which the caller has counted.
    ///
    /// # Panics
    ///
    /// When `owner`'s boot nonce is other than the one scripted for that count: every tenure's nonces are a function
    /// of the run.
    fn started(
        world: &World,
        (grounds, pools): (&'w Grounds, &'w Pools<'w>),
        (owner, control, registry, own): (
            Owner<'w, 'w, 'w, TestPlatform, Reserving, Mux<'w>>,
            SimControl,
            Control,
            Pair,
        ),
        (tenure, now, turn): (Tenure, Rc<Cell<u64>>, u64),
        (client_end, net): (LinkEnd<'w>, Rc<RefCell<Net<'w>>>),
    ) -> Self {
        let reports_from = registry.borrow().reports();
        let mut scripted = [0; 16];
        boot_nonce(world.served, 1)(&mut scripted).expect("a scripted fill");
        assert_eq!(
            owner.boot_nonce(),
            scripted,
            "the owner's boot nonce is the one scripted for the world's count of successors served"
        );
        let client = super::owner_tests::configured_client(
            0,
            super::owner_tests::client_config(0),
            &pools.client,
            &grounds.releases,
            client_end,
            Box::default(),
            boot_nonce(world.served, 2),
            Arc::clone(&world.routes),
        );
        Serving {
            owner,
            duties: None,
            duty_exit: None,
            client,
            net,
            control,
            storage: &grounds.storage,
            reservation: Rc::clone(&world.reservation),
            own,
            shard: world.shard,
            turn,
            tenure,
            unrouted: 0,
            conflicted: Vec::new(),
            scripts_conflict: true,
            steps: Rc::clone(&world.steps),
            withdrawn: false,
            reports_from,
            registry,
            now,
            rising: None,
            risen: None,
            recovery_line: None,
        }
    }
}

/// `activate` records `serving`'s `Activate` event and `Recovered` step in `world`. Both name the cut when the
/// attach's device write count is zero, and such an opened load also records a restore for every resident slot.
/// `activate` brings an opened load to `Live`. The caller completes the bootstrap first.
fn activate(world: &mut World, serving: &mut Serving<'_>, source: Source) -> MetadataOutcome {
    let tenure = serving.tenure;
    let outcome = serving.owner.volume_metadata_outcome();
    let warm = serving.control.accepted(Operation::Write) == 0;
    assert_eq!(
        warm,
        source == Source::Named,
        "a warm attach writes nothing"
    );
    let cut = warm.then_some(CUT);
    world.events.push(Event::Activate { tenure, cut });
    (world.steps.borrow_mut().list).push(Step::Recovered { tenure, cut });
    if outcome == MetadataOutcome::Open {
        if warm {
            world.record_restores(serving);
        }
        // The production bring-up replayed the load in the turn that ended it.
        if serving.risen.is_none() {
            assert_eq!(serving.owner.readiness(), Readiness::Loaded);
            let feed = serving.storage.feed_contract();
            if serving.owner.begin_replay(feed, 0) == Ok(Readiness::Replaying) {
                assert_eq!(serving.owner.complete_replay(), Ok(Readiness::Live));
            }
            assert_eq!(serving.owner.readiness(), Readiness::Live);
        }
    }
    outcome
}

/// Samples `serving`'s device capture when its tenure ends: a capture past its bound makes the world's ownership
/// verdict `Truncated`. Call it before the tenure drops and before `World::judged`.
fn closed(world: &World, serving: &Serving<'_>) {
    sample_overflow(&world.steps, &serving.control);
}

/// `host`'s takeover, which must succeed, served warm.
fn serve_taken<R>(
    world: &mut World,
    host: Host,
    body: impl for<'w> FnOnce(&mut World, &mut Serving<'w>, MetadataOutcome) -> R,
) -> R {
    let (taken, _) = world.takeover(host);
    serve(world, taken.expect("the takeover"), Source::Named, body)
}

/// The one account of a history with one cut-naming activation.
fn account(judged: Result<Vec<Preserved>, Verdict>) -> Preserved {
    let mut accounts = judged.unwrap_or_else(|verdict| panic!("{verdict:?}"));
    assert_eq!(accounts.len(), 1, "one activation names the cut");
    accounts.remove(0)
}

/// The rule a history's violation names.
fn violated<T: std::fmt::Debug>(judged: Result<T, Verdict>) -> (Obligation, &'static str) {
    match judged {
        Err(verdict) => verdict.violated().unwrap_or_else(|| panic!("{verdict:?}")),
        Ok(accounts) => panic!("the history passed: {accounts:?}"),
    }
}

/// The bytes a set of `served` whole objects delivers.
fn bytes_of(served: usize) -> u64 {
    served as u64 * (u64::from(METADATA) + BODY)
}

/// After host loss the named standby takes the same volume over, loads warm and serves every object of the cut its
/// exact bytes at its own tenure, which the client's route binds; the object A invalidated before the loss misses
/// and is no member of the retained set. No object is excused and the device accepted no write.
/// In the control history the takeover alone retains and serves object 5, which isolates the INVALIDATE's effect.
#[test]
fn a_warm_takeover_serves_the_retained_set_to_a_client_at_the_successors_tenure() {
    for invalidated in [Some(5), None] {
        let name = format!("invalidated {invalidated:?}");
        let mut world = World::new(12, false);
        if let Some(n) = invalidated {
            world.invalidate(n);
        }
        let retained: Vec<u8> = (1..=12).filter(|&n| Some(n) != invalidated).collect();
        let before = world.evidence();
        let (taken, log) = world.takeover(c_host());
        assert_eq!(log, restart_tests::FULL, "{name}");
        let taken = taken.expect("the takeover");
        let record = restart_tests::shard_now(&world.records);
        assert_eq!(
            (record.owner, record.standby, record.attempts),
            (c_host(), None, 5),
            "{name}: the record names C"
        );
        serve(
            &mut world,
            taken,
            Source::Named,
            |world, serving, outcome| {
                assert_eq!(outcome, MetadataOutcome::Open, "{name}");
                assert_eq!(serving.tenure, Tenure { g: 3, a: 10 }, "{name}");
                assert_eq!(
                    world.restored(),
                    retained,
                    "{name}: the restored entries are the retained set"
                );
                let served = serving.read_all(world);
                assert_eq!(served, retained, "{name}: each retained object completes");
                if let Some(n) = invalidated {
                    assert!(world.missed(n), "{name}: the covered object misses");
                }
                assert_eq!(serving.control.accepted(Operation::Write), 0, "{name}");
            },
        );
        assert_eq!(
            world.evidence(),
            before,
            "{name}: the manifest and the prefix are kept"
        );
        let account = account(world.judged());
        let members = retained.len();
        assert_eq!(
            (account.members as usize, account.served as usize),
            (members, members),
            "{name}"
        );
        assert_eq!(account.served_bytes, bytes_of(members), "{name}");
        assert!(account.excused.is_empty(), "{name}");
        assert_eq!(account.tenure, Tenure { g: 3, a: 10 }, "{name}");
    }
}

/// A fault injected on a payload unit, on a row unit of the named slot, or on both loses exactly the objects with a
/// row or their payload on those units, and every other object of the cut serves its exact bytes; the successor's
/// loss report counts the injected row unit and no other. A payload unit damaged after the successor reached `Live`
/// loses its object the same way, with no byte surfaced. A repeated landing of A's own write of the damaged unit,
/// applied after A's completion and its host loss, repairs it, and the whole cut serves. Under the control, a reader
/// that refuses the whole slot on any damaged unit, the same row-unit fault loses objects outside its damage set
/// and the history fails "a retained entry outside every damage set was lost on host loss".
#[test]
fn injected_damage_loses_exactly_its_damage_set_and_a_repeated_landing_repairs_it() {
    use crate::storage::checkpoint::{PLANT, Plant};
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Arm {
        Lost,
        /// The payload unit is damaged after `Live`.
        Late,
        Repaired,
        /// The all-or-nothing reader.
        Control,
    }
    let count = 50;
    for (payload, row, arm) in [
        (true, false, Arm::Lost),
        (false, true, Arm::Lost),
        (true, true, Arm::Lost),
        (true, false, Arm::Late),
        (true, false, Arm::Repaired),
        (false, true, Arm::Repaired),
        (false, true, Arm::Control),
    ] {
        let name = format!("payload {payload}, row {row}, {arm:?}");
        let mut world = World::new(count, false);
        let last = world.objects.last().expect("an object").n;
        let (row_unit, payload_unit) = world.units(last);
        let units: Vec<u32> = [(payload, payload_unit), (row, row_unit)]
            .into_iter()
            .filter_map(|(injected, unit)| injected.then_some(unit))
            .collect();
        let mut lost: Vec<u8> = units.iter().flat_map(|&unit| world.on_unit(unit)).collect();
        lost.sort_unstable();
        lost.dedup();
        assert!(
            !lost.is_empty() && lost.len() < usize::from(count),
            "{name}"
        );
        if arm != Arm::Late {
            for &unit in &units {
                world.corrupt(unit);
                if arm == Arm::Repaired {
                    assert!(world.land_again(unit) > 0, "{name}: A wrote unit {unit}");
                }
            }
        }
        let before = world.evidence();
        let (taken, _) = world.takeover(c_host());
        let taken = taken.expect("the takeover");
        PLANT.with(|plant| plant.set((arm == Arm::Control).then_some(Plant::AllOrNothing)));
        let (outcome, served, failed) = serve(
            &mut world,
            taken,
            Source::Named,
            |world, serving, outcome| {
                PLANT.with(|plant| plant.set(None));
                let failed = serving.owner.recovery_report().warm.failed_units;
                if outcome != MetadataOutcome::Open {
                    return (outcome, Vec::new(), failed);
                }
                if arm == Arm::Late {
                    let resident = serving.resident().len();
                    assert_eq!(resident, usize::from(count), "{name}: the whole cut loaded");
                    for &unit in &units {
                        world.corrupt(unit);
                    }
                }
                (outcome, serving.read_all(world), failed)
            },
        );
        assert_eq!(
            world.evidence(),
            before,
            "{name}: the manifest and the prefix are kept"
        );
        if arm == Arm::Control {
            assert_eq!(
                outcome,
                MetadataOutcome::Unloadable(LoadRefusal::StaleWrite),
                "{name}: the control refused the load"
            );
            let rule = "a retained entry outside every damage set was lost on host loss";
            assert_eq!(
                violated(world.judged()),
                (Obligation::Restart, rule),
                "{name}"
            );
            continue;
        }
        assert_eq!(outcome, MetadataOutcome::Open, "{name}");
        let expected: Vec<u8> = if arm == Arm::Repaired {
            Vec::new()
        } else {
            lost
        };
        let reported = u32::from(row && arm != Arm::Repaired);
        assert_eq!(
            failed, reported,
            "{name}: the report counts the injected row unit"
        );
        let mut missed: Vec<u8> = (world.objects.iter().map(|object| object.n))
            .filter(|n| !served.contains(n))
            .collect();
        missed.sort_unstable();
        assert_eq!(missed, expected, "{name}: the loss is the damage set");
        let account = account(world.judged());
        let mut excused: Vec<u8> = account.excused.iter().map(|(key, _)| key.0).collect();
        excused.sort_unstable();
        assert_eq!(excused, expected, "{name}");
        let kept = usize::from(count) - expected.len();
        assert_eq!(
            (account.members, account.served as usize),
            (u32::from(count), kept),
            "{name}"
        );
        assert_eq!(
            account.served_bytes,
            bytes_of(kept),
            "{name}: every other object's bytes"
        );
    }
}

/// The fresh-host path. After the owner and the standby are lost, the record, the prefix and the payload are as A
/// left them; the reconciler attaches, enrolls and designates D, which registers, preempts A and serves the whole
/// cut. A successor that stops after its takeover write and before its preempt leaves the record naming it owner
/// with no standby and A's registration holding, and A's restart refuses with no flip; D, designated over the
/// stopped successor's tenure, preempts A, whose tenure D's write superseded through the stopped successor's. A
/// successor that stops after its preempt, before it attaches, holds the reservation, and D preempts it. In both
/// D serves the whole cut at the next tenure, the stopped successor's tenure is never activated, and no arm writes
/// the device or changes the manifest.
#[test]
fn owner_and_standby_loss_and_a_successor_lost_around_its_preempt_recover_by_the_fresh_host_path() {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Lost {
        OwnerAndStandby,
        SuccessorBeforePreempt,
        SuccessorAfterPreempt,
    }
    for lost in [
        Lost::OwnerAndStandby,
        Lost::SuccessorBeforePreempt,
        Lost::SuccessorAfterPreempt,
    ] {
        let mut world = World::new(6, false);
        let before = world.evidence();
        if lost == Lost::SuccessorBeforePreempt {
            let (mut card, local) = world.host(c_host());
            card.stop_at = Some(3);
            let refused = takeover_of(&world.records, c_host())
                .run(&mut store_client(&world.records), &local, &mut card)
                .unwrap_err();
            let check = refused.check;
            let at_report = matches!(check, crate::failover::takeover::Check::FirstReport(_));
            assert!(at_report, "{check:?}");
            let refused = world.restart_of_a();
            let deposed = crate::failover::restart::Check::Deposed;
            assert_eq!(
                (refused.check, refused.flip),
                (deposed, None),
                "A requests no flip"
            );
        }
        if lost == Lost::SuccessorAfterPreempt {
            let (taken, log) = world.takeover(c_host());
            assert!(
                taken.is_ok() && log == restart_tests::FULL,
                "C fenced and was lost"
            );
        }
        if lost != Lost::OwnerAndStandby {
            let record = restart_tests::shard_now(&world.records);
            assert_eq!(
                (record.owner, record.standby, record.attempts),
                (c_host(), None, 5)
            );
        }
        world.designate_fresh();
        assert_eq!(
            world.evidence(),
            before,
            "{lost:?}: host loss changed nothing on the volume"
        );
        let (taken, log) = world.takeover(d_host());
        assert_eq!(
            log, REGISTERING,
            "{lost:?}: D registers and preempts the holder"
        );
        let a = if lost == Lost::OwnerAndStandby {
            10
        } else {
            12
        };
        let tenure = Tenure { g: 3, a };
        let taken = taken.expect("D's takeover");
        serve(
            &mut world,
            taken,
            Source::Named,
            |world, serving, outcome| {
                assert_eq!(outcome, MetadataOutcome::Open);
                assert_eq!(serving.tenure, tenure);
                assert_eq!(serving.read_all(world).len(), 6);
                assert_eq!(serving.control.accepted(Operation::Write), 0);
            },
        );
        assert_eq!(world.evidence(), before, "{lost:?}");
        let account = account(world.judged());
        assert_eq!(
            (account.tenure, account.members, account.served),
            (tenure, 6, 6)
        );
    }
}

/// A standby designation the reconciler replaced after C formed its takeover refuses C before any write and any
/// device command: replaced before C's record reads, the reread refuses `Stale` before any write; replaced
/// between those reads and C's compare-and-swap, the write fails its version condition. Of two attached hosts the
/// record names C: B, attached, enrolled and registered, refuses `Stale` at its record read before any write, and
/// the store client refuses B's compare-and-swap before any request. A takeover write whose reply is lost issues no device
/// command; C continues only by the same-host restart, which bumps C's tenure, preempts the owner's recorded holder
/// through its lineage arm and serves. In each case no session is minted for the refused attempt, one host takes the
/// volume over, and the history holds one activation, whose tenure answers every hit.
#[test]
fn a_stale_designation_an_unnamed_host_and_an_unknown_takeover_write_mint_no_session() {
    use crate::failover::takeover::{Check, Next};
    use crate::storage::store::sim::Arm;
    use crate::storage::store::{Key, StoreError};
    let commits = |world: &World| world.records.0.borrow().commit_count(&Key::Shard(shard()));
    let all_served = |world: &mut World, host: Host, tenure: Tenure| {
        serve_taken(world, host, |world, serving, _| {
            assert_eq!(serving.read_all(world).len(), 4);
        });
        let account = account(world.judged());
        assert_eq!((account.tenure, account.served), (tenure, 4));
    };

    // A stale standby designation.
    let mut world = World::new(4, false);
    let (mut card, local) = world.host(c_host());
    let stale = takeover_of(&world.records, c_host());
    world.designate_fresh();
    let written = commits(&world);
    let refused = stale
        .run(&mut store_client(&world.records), &local, &mut card)
        .unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(card.log.is_empty() && commits(&world) == written);
    all_served(&mut world, d_host(), Tenure { g: 3, a: 10 });

    // A standby designation replaced between C's record reads and its compare-and-swap.
    let mut world = World::new(4, false);
    let owner = restart_tests::shard_now(&world.records).owner;
    let mut card = world.host(c_host()).0;
    let (records, fresh) = (world.records.clone(), Rc::new(RefCell::new(None)));
    let designated = Rc::clone(&fresh);
    let local = hooked(stored_c(), move || {
        *designated.borrow_mut() = Some(designate_fresh_host(&records));
    });
    let refused = takeover_of(&world.records, c_host())
        .run(&mut store_client(&world.records), &local, &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (Check::TakeOver(CONDITION), None)
    );
    assert!(card.log.is_empty());
    world.fresh = fresh.take();
    let record = restart_tests::shard_now(&world.records);
    assert_eq!((record.owner, record.standby), (owner, Some(d_host())));
    all_served(&mut world, d_host(), Tenure { g: 3, a: 10 });

    // Two attached hosts, one named standby.
    let mut world = World::new(4, true);
    let written = commits(&world);
    let (refused, log) = world.takeover(b_host());
    let refused = refused.unwrap_err();
    assert_eq!((refused.check, refused.recovery), (Check::Stale, None));
    assert!(log.is_empty() && commits(&world) == written);
    let mut b = store_client(&world.records);
    let read = b
        .read::<crate::failover::records::ShardRecord>(Key::Shard(shard()))
        .unwrap();
    let target = crate::failover::retire::Target::of(read.value());
    let taken = b.take_over(&read, target, b_host()).map(drop);
    assert!(matches!(taken, Err(StoreError::Stale(_))), "{taken:?}");
    assert_eq!(commits(&world), written);
    all_served(&mut world, c_host(), Tenure { g: 3, a: 10 });

    // The takeover write's reply is lost after it committed.
    let mut world = World::new(4, false);
    let before = world.evidence();
    let (mut card, local) = world.host(c_host());
    let path = takeover_of(&world.records, c_host());
    for arm in [Arm::Pass, Arm::Pass, Arm::Timeout { commit: true }] {
        world.records.schedule(arm);
    }
    let refused = path
        .run(&mut store_client(&world.records), &local, &mut card)
        .unwrap_err();
    assert_eq!(refused.check, Check::TakeOver(StoreError::Unknown));
    assert!(
        card.log.is_empty(),
        "an unknown outcome issues no device command"
    );
    let Next::Restart(restart) = path.next(&refused) else {
        panic!("an unknown outcome continues by the restart alone");
    };
    let (mut restarting, _) = world.host(c_host());
    let restarted = restart
        .run(&mut store_client(&world.records), &local, &mut restarting)
        .unwrap();
    assert!(restarted.lineage());
    world.fence(&restarted);
    serve(&mut world, restarted, Source::Named, |world, serving, _| {
        assert_eq!(serving.read_all(world).len(), 4);
    });
    let account = account(world.judged());
    assert_eq!(
        (account.tenure, account.served),
        (Tenure { g: 3, a: 12 }, 4)
    );
    assert_eq!(world.evidence(), before);
}

/// What the client's route does with a reply of a deposed tenure, and the control "omit session check", under each
/// owner clock strategy. C takes the volume over and serves. A GET's reply is read from the device and waits on the
/// link while C stops answering its peers; the reconciler designates D, D takes the volume over and preempts C, and
/// the client's route binds D's tenure. The buffered reply still reaches the client, whose shard route refuses its
/// frames at receive because the route is above C's tenure; the GET ends with no byte surfaced, and the history
/// records it as a response the client rejected, so the history of both tenures passes. Plant: `NO_ROUTE_CHECK`, a
/// client that checks no route, admits the frames and surfaces the reply's bytes, the history records them as
/// accepted, and `World::judged` fails "a client accepted a response tagged below its high-water". Under `Frozen`
/// C stays serving and the planted GET completes; when a moving clock's Report withdraws C before the completion,
/// the planted GET ends incomplete after surfacing the same bytes. D's whole tenure runs inside C's closure and
/// advances D's clock alone, so C resumes one round after its last turn: under `Honest` and `Slow` the arms model a
/// successor whose takeover and service fit inside one of C's rounds. The control witnesses the order of the route
/// and the reply under each strategy; C and D share no elapsed timeline in it. Before D is designated C has
/// reported periodically under a moving clock and once under `Frozen`.
#[test]
fn control_a_client_that_checks_no_route_accepts_a_deposed_tenures_reply_and_fails() {
    use super::client::NO_ROUTE_CHECK;
    use crate::failover::serving::State;
    let arms = STRATEGIES
        .into_iter()
        .flat_map(|strategy| [(strategy, false), (strategy, true)]);
    for (strategy, planted) in arms {
        let mut world = World::new(4, false);
        world.set_moving_clock(strategy);
        serve_taken(&mut world, c_host(), |world, c, _| {
            assert_eq!(c.read_all(world).len(), 4);
            let reads = c.control.accepted(Operation::Read);
            let id = c.send(object_key(1));
            // The client's next poll sends the GET; from then on it polls nothing until D has taken over.
            c.step();
            for _ in 0..200 {
                c.step_without_client();
            }
            assert!(
                c.control.accepted(Operation::Read) > reads,
                "C read the reply from the device"
            );
            match strategy {
                Strategy::Frozen => assert_eq!(reports(c), 1, "a frozen clock reports once"),
                _ => assert!(reports(c) > 1, "{strategy:?}: a moving clock reports"),
            }
            world.designate_fresh();
            c.idle_device();
            let (taken, log) = world.takeover(d_host());
            assert_eq!(log, REGISTERING, "D preempts C");
            let taken = taken.expect("D's takeover");
            serve(world, taken, Source::Named, |world, d, _| {
                assert_eq!(d.read_all(world).len(), 4);
                assert_eq!(world.high_water(), Some(d.tenure));
                assert!(c.tenure < d.tenure && c.deposed());
            });
            NO_ROUTE_CHECK.with(|plant| plant.set(planted));
            let got = c.finish(id);
            NO_ROUTE_CHECK.with(|plant| plant.set(false));
            let complete = got.0 == Fetched::Complete;
            let withdrawn = c.owner.authority_report().state == State::Withdrawn;
            if strategy == Strategy::Frozen {
                assert!(!withdrawn, "a frozen C stays serving");
                assert_eq!(complete, planted, "{:?}", got.0);
            } else if !planted {
                assert!(!complete, "{strategy:?}: {:?}", got.0);
            }
            assert_eq!(got.1.is_empty(), !planted, "the bytes surfaced");
            assert_eq!(
                got.2, planted,
                "the route refused the reply's frames at receive"
            );
            if planted {
                assert_eq!(got.1, content(1, first(1)), "the reply's bytes surfaced");
            }
            if complete || !planted {
                let surfaced = c.record(world, 1, &[first(1)], got);
                assert_eq!(surfaced, planted, "the deposed reply is surfaced");
            } else {
                // The client surfaced the reply's bytes and the read ended incomplete.
                assert!(matches!(got.0, Fetched::Incomplete(_)), "{:?}", got.0);
                world.events.push(Event::Read {
                    n: 1,
                    tenure: c.tenure,
                    high_water: world.high_water(),
                    accepted: true,
                    answer: Answer::Cut(first(1), got.1),
                });
            }
        });
        if planted {
            let rule = "a client accepted a response tagged below its high-water";
            assert_eq!(violated(world.judged()), (Obligation::History, rule));
        } else {
            let accounts = world
                .judged()
                .unwrap_or_else(|verdict| panic!("{verdict:?}"));
            let served: Vec<_> = accounts.iter().map(|a| (a.tenure.a, a.served)).collect();
            assert_eq!(served, [(10, 4), (12, 4)]);
        }
    }
}

/// C serves, D takes the volume over and preempts C, and C, still running, starts a fill, with the harness's
/// Reservation Conflict script as `scripts_conflict` says; D then serves the whole cut. Returns the world, whether
/// the media changed, and C's authority report and readiness after the fill.
fn deposed_fill(
    scripts_conflict: bool,
) -> (World, bool, crate::storage::AuthorityReport, Readiness) {
    let mut world = World::new(4, false);
    let (changed, authority, readiness) = serve_taken(&mut world, c_host(), |world, c, _| {
        assert_eq!(c.read_all(world).len(), 4);
        world.designate_fresh();
        c.idle_device();
        let (taken, _) = world.takeover(d_host());
        assert!(taken.is_ok() && c.deposed());
        let media = world.a.media.borrow().clone();
        let writes = c.control.accepted(Operation::Write);
        c.scripts_conflict = scripts_conflict;
        assert!(!c.fill(world, 9), "the deposed fill publishes nothing");
        assert!(
            c.control.accepted(Operation::Write) > writes,
            "the fill reached the device"
        );
        let changed = world.a.media.borrow()[..] != media[..];
        let (authority, readiness) = (c.owner.authority_report(), c.owner.readiness());
        let taken = taken.expect("D's takeover");
        serve(world, taken, Source::Named, |world, d, _| {
            assert_eq!(d.read_all(world), [1, 2, 3, 4]);
        });
        assert!(
            write_guard::arm(true),
            "D's tenure restores C's armed state when it ends"
        );
        (changed, authority, readiness)
    });
    assert!(
        !write_guard::arm(false),
        "C's tenure restores the unarmed state it started from"
    );
    (world, changed, authority, readiness)
}

/// A deposed tenure's write after its successor's fence. C serves, D takes the volume over and preempts C, and C,
/// still running, starts a fill: its write reaches the device and completes with Reservation Conflict, so the fill
/// publishes nothing, the media is as it was, C's authority withdraws on the conflict and its volume stops
/// serving. D serves the whole cut. The ownership steps show C's fence before D's, C's write accepted after D's
/// fence, C's withdrawal right after a `Commands` step of C, a turn of C while withdrawn, and D's recovery from the
/// cut.
#[test]
fn a_deposed_tenures_fill_after_the_successors_fence_writes_nothing_and_withdraws_it() {
    use crate::failover::serving::State;
    use crate::storage::AuthorityRefusal;
    let (world, changed, authority, readiness) = deposed_fill(true);
    assert!(!changed, "no deposed write landed");
    assert!(world.guarded.checked > 0, "the guard checked C's write");
    assert_eq!(
        (authority.state, authority.refusal),
        (State::Withdrawn, Some(AuthorityRefusal::Conflict))
    );
    assert_ne!(readiness, Readiness::Live);
    let accounts = world
        .judged()
        .unwrap_or_else(|verdict| panic!("{verdict:?}"));
    let served: Vec<_> = accounts.iter().map(|a| (a.tenure.a, a.served)).collect();
    assert_eq!(served, [(10, 4), (12, 4)]);
    let (c, d) = (Tenure { g: 3, a: 10 }, Tenure { g: 3, a: 12 });
    let steps = world.steps.borrow();
    let at = |wanted: &Step| steps.list.iter().position(|step| step == wanted);
    let fenced = |tenure| Step::Fenced {
        tenure,
        durable: Some(CUT),
    };
    let (c_fence, d_fence) = (at(&fenced(c)), at(&fenced(d)));
    assert!(
        c_fence.is_some() && c_fence < d_fence,
        "C's fence precedes D's"
    );
    let d_fence = d_fence.expect("D's fence");
    let commands_of_c = |step: &Step| match step {
        Step::Commands {
            tenure, accepted, ..
        } if *tenure == c => Some(*accepted),
        _ => None,
    };
    let floor = (steps.list[..d_fence].iter().rev())
        .find_map(commands_of_c)
        .expect("a turn of C before D's fence");
    assert!(
        (steps.list[d_fence..].iter().filter_map(commands_of_c)).any(|accepted| accepted > floor),
        "C's write was accepted after D's fence"
    );
    let withdrawn = at(&Step::Withdrawn { tenure: c }).expect("C's withdrawal");
    let withdrawals = (steps.list.iter()).filter(|step| **step == Step::Withdrawn { tenure: c });
    assert_eq!(
        withdrawals.count(),
        1,
        "C's first withdrawal alone is a step"
    );
    assert!(commands_of_c(&steps.list[withdrawn - 1]).is_some());
    assert!(
        (steps.list[withdrawn + 1..].iter()).any(|step| commands_of_c(step).is_some()),
        "C took a turn while withdrawn"
    );
    assert!(
        at(&Step::Recovered {
            tenure: d,
            cut: Some(CUT)
        })
        .is_some_and(|recovered| recovered > d_fence)
    );
}

/// The device accepts C's write after D's fence, and the write changes the media. The history fails "a deposed
/// tenure's medium command, accepted after its successor's fence, succeeded". In the deposed-fill history, the device
/// completes C's write with Reservation Conflict.
#[test]
fn control_a_deposed_fill_with_no_fence_lands_and_fails_one_owner_at_a_time() {
    let (world, changed, _, _) = deposed_fill(false);
    assert!(changed, "the deposed write landed");
    let rule = "a deposed tenure's medium command, accepted after its successor's fence, succeeded";
    assert_eq!(violated(world.judged()), (Obligation::Restart, rule));
}

/// The client's high-water spans every key of the shard. When the client's read of the first object of the second
/// group records no high-water, below the successor's tenure the reads of the first group recorded, each group's
/// judgment still passes, since the falling reads lie in different groups, and the whole history's client judgment
/// fails "a client's recorded high-water fell". Unchanged, the history passes.
#[test]
fn a_high_water_that_falls_across_key_groups_fails_the_client_judgment() {
    for fallen in [false, true] {
        let mut world = World::new(4, false);
        serve_taken(&mut world, c_host(), |world, serving, _| {
            assert_eq!(serving.read_all(world).len(), 4);
        });
        let numbers: Vec<u8> = world.objects.iter().map(|object| object.n).collect();
        if fallen {
            let second = numbers[MAX_KEYS];
            let read = (world.events.iter_mut())
                .find(|event| matches!(event, Event::Read { n, .. } if *n == second));
            let Some(Event::Read { high_water, .. }) = read else {
                panic!("a read of object {second}");
            };
            *high_water = None;
        }
        for group in numbers.chunks(MAX_KEYS) {
            let judged = world.judged_group(group);
            assert!(judged.is_ok(), "{fallen}: {group:?}: {judged:?}");
        }
        if fallen {
            let rule = "a client's recorded high-water fell";
            assert_eq!(violated(world.judged()), (Obligation::History, rule));
        } else {
            assert_eq!(account(world.judged()).served, 4);
        }
    }
}

/// The control "count a cold start as success": a successor that attaches the taken volume with no warm source
/// writes its own roots, opens and serves, every GET a miss; the history fails "host loss replaced a retained cut
/// with a cold start" though every answer is a safe miss. The ownership monitor over the world's steps fails "a
/// successor recovered from a cut other than the one its volume last made durable": the fence's durable cut is the
/// cut the record names, and the cold attach recovers from none.
#[test]
fn control_a_cold_start_after_host_loss_fails_though_every_lookup_misses() {
    let mut world = World::new(4, false);
    let (taken, _) = world.takeover(c_host());
    let taken = taken.expect("the takeover");
    serve(
        &mut world,
        taken,
        Source::Cold,
        |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "the cold attach opens");
            assert!(
                serving.resident().is_empty(),
                "the cold attach holds nothing"
            );
            assert!(serving.read_all(world).is_empty(), "every lookup misses");
        },
    );
    let rule = "host loss replaced a retained cut with a cold start";
    assert_eq!(violated(world.judged()), (Obligation::Restart, rule));
    let recovered =
        "a successor recovered from a cut other than the one its volume last made durable";
    assert_eq!(
        violated(world.ownership()),
        (Obligation::Restart, recovered)
    );
}

/// The control "shrink coverage". A acknowledges an INVALIDATE of one object and then of another on the same
/// coverage page, each page value computed by `page_coverage::merged` through `merge`, the rule every coverage
/// write runs, `Fencing::cover_page` included. Both objects miss after the takeover and the history passes. With
/// `merge` keeping the new entry alone, `SHRINKS`, the second write drops the first object's coverage, the successor
/// restores and serves that object, and the history fails "a recorded restore of a covered version".
#[test]
fn control_a_coverage_write_that_drops_an_entry_serves_a_covered_version_and_fails() {
    use crate::storage::page_coverage::SHRINKS;
    for planted in [false, true] {
        let mut world = World::new(6, false);
        let numbers: Vec<u8> = world.objects.iter().map(|object| object.n).collect();
        let shared = numbers.iter().find_map(|&x| {
            let same = |y: &&u8| **y != x && world.page_key(**y) == world.page_key(x);
            numbers.iter().find(same).map(|&y| (x, y))
        });
        let (x, y) = shared.expect("two objects share a coverage page");
        world.invalidate(x);
        SHRINKS.with(|plant| plant.set(planted));
        world.invalidate(y);
        SHRINKS.with(|plant| plant.set(false));
        let served = serve_taken(&mut world, c_host(), |world, serving, _| {
            serving.read_all(world)
        });
        assert_eq!(
            served.contains(&x),
            planted,
            "the fault is reached only under the plant"
        );
        assert!(!served.contains(&y));
        if planted {
            let rule = "a recorded restore of a covered version";
            assert_eq!(violated(world.judged()), (Obligation::History, rule));
        } else {
            assert_eq!(account(world.judged()).served, 4);
        }
    }
}

/// The control "open FILLs before allocator commit". After a warm takeover reaches `Live` and the tenure opens its
/// suffix, a fill through the owner places outside the restored extents, and the cut and the new object both serve.
/// With the warm bootstrap's hold skipping the restore of the restored extents into the allocator,
/// `HOLD_SKIPS_RESTORE`, the allocator holds the state a fill admitted before the allocator's commit would find: the
/// fill places over a restored payload unit, the object there is never served though no fault was injected, and the
/// history fails "a retained entry outside every damage set was never served after host loss". The readiness order
/// is unchanged under the plant.
#[test]
fn control_fills_opened_before_the_allocator_holds_the_cut_overwrite_it_and_fail() {
    use crate::storage::warm_sim::HOLD_SKIPS_RESTORE;
    for planted in [false, true] {
        let mut world = World::new(4, false);
        let (taken, _) = world.takeover(c_host());
        let taken = taken.expect("the takeover");
        HOLD_SKIPS_RESTORE.with(|plant| plant.set(planted));
        let (served, restored, filled) = serve(
            &mut world,
            taken,
            Source::Named,
            |world, serving, outcome| {
                HOLD_SKIPS_RESTORE.with(|plant| plant.set(false));
                assert_eq!(outcome, MetadataOutcome::Open);
                assert!(
                    serving.open_suffix(&world.records),
                    "the tenure's suffix opens"
                );
                let mut restored = Vec::new();
                (serving.storage.held_extents_into(&mut restored)).expect("a live pool");
                let mut facts = Vec::new();
                (serving.storage.slot_facts_into(&mut facts)).expect("a live pool");
                restored.retain(|extent| facts[extent.holder.slot_index()].resident);
                assert_eq!(restored.len(), 4, "the cut's four slots are resident");
                assert!(serving.fill(world, 9));
                let mut after = Vec::new();
                (serving.storage.held_extents_into(&mut after)).expect("a live pool");
                after.retain(|extent| !restored.contains(extent));
                let [filled] = &after[..] else {
                    panic!("the fill holds the one slot outside the cut: {after:?}");
                };
                (serving.read_all(world), restored, filled.holder)
            },
        );
        let Guarded {
            first: conflict,
            skipped,
            checked,
        } = world.guarded;
        assert_eq!(skipped, 0, "the lens skipped no slot");
        assert!(checked > 0, "the guard checked the fill's writes");
        if planted {
            let overwrote = served.contains(&9) && served.len() < 5;
            assert!(overwrote, "the fill overwrote a restored unit: {served:?}");
            let rule = "a retained entry outside every damage set was never served after host loss";
            assert_eq!(violated(world.judged()), (Obligation::Restart, rule));
            let conflict = conflict.expect("the guard recorded the fill's write");
            let w1 = "a payload write overlapped an extent another slot holds";
            assert_eq!(conflict.rule, w1);
            let restored_holder = restored
                .iter()
                .any(|extent| extent.holder == conflict.holder);
            assert!(
                restored_holder,
                "the holder is a slot restored resident before the fill"
            );
            let index = (world.a.entries.iter())
                .position(|entry| entry.allocation == conflict.holder.record_tag())
                .expect("the holder is an allocation tenure A captured");
            let (_, payload) = world.objects[index].units.expect("a captured object");
            let unit = u64::from(payload) * IO_UNIT as u64;
            let range = conflict.range;
            assert!(
                range.start() < unit + IO_UNIT as u64 && unit < range.end(),
                "the write overlaps the holder's captured payload unit"
            );
            let lost = world.objects[index].n;
            assert!(
                !served.contains(&lost),
                "the overwritten object is never served"
            );
            assert_eq!(conflict.writer, filled, "the writer is the fill's own slot");
        } else {
            assert_eq!(conflict, None, "the unplanted fill overlaps no held extent");
            assert_eq!(served, [1, 2, 3, 4, 9]);
            assert_eq!(account(world.judged()).served, 4);
        }
    }
}

/// A delayed landing of an earlier checkpoint's unit, and the control "reuse capture identity". The earlier
/// checkpoint's row for the last object names another key, which the cut never captured. A unit of the tenure's
/// capture 8 landed over the named slot fails the reader's identity check, and its objects are lost to that
/// injected unit alone. A stage of the same entries under the named capture's identity is refused before any unit
/// is encoded, so nothing can land and the whole cut serves. With the reservation admitting a capture identity the
/// set already found named, the stage encodes its units on another slot, since the named slot is unavailable to a
/// reservation. The test lands one of those units over the named slot: a misdirected write, the fault a hostile
/// device profile injects, recorded as a damage row. It passes the reader, the successor restores the uncaptured
/// key, and the history fails "a recovery restored an entry its cut never captured".
#[test]
fn control_a_reused_capture_identity_restores_an_entry_the_cut_never_captured_and_fails() {
    use crate::storage::checkpoint::{PLANT, Plant, ReserveRefusal, StageRefusal};
    use crate::storage::warm_sim::{layout, restaged, stale_landing};
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Arm {
        EarlierCapture,
        ReuseRefused,
        ReusePlanted,
    }
    for arm in [Arm::EarlierCapture, Arm::ReuseRefused, Arm::ReusePlanted] {
        let mut world = World::new(50, false);
        let last = world.a.entries.len() - 1;
        let (row, _) = world.units(world.objects[last].n);
        let mut earlier = world.a.entries.clone();
        earlier[last].key = object_key(200);
        let data_unit = row - 1 - world.a.named.slot * layout().slot_units;
        let landed = match arm {
            Arm::EarlierCapture => {
                let (media, named) = (&world.a.media, world.a.named);
                stale_landing(media, named, &earlier, data_unit);
                true
            }
            Arm::ReuseRefused | Arm::ReusePlanted => {
                let planted = (arm == Arm::ReusePlanted).then_some(Plant::CaptureReuse);
                PLANT.with(|plant| plant.set(planted));
                let staged = restaged(world.a.named, &earlier);
                PLANT.with(|plant| plant.set(None));
                match staged {
                    Ok((slot, units)) => {
                        assert_ne!(slot, world.a.named.slot, "the stage takes another slot");
                        world.land(row, &units[data_unit as usize]);
                    }
                    Err(refusal) => {
                        let capture = StageRefusal::Reserve(ReserveRefusal::Capture);
                        assert_eq!(refusal, capture);
                    }
                }
                arm == Arm::ReusePlanted
            }
        };
        if landed {
            world.events.push(Event::Damaged { unit: row });
        }
        world.events.push(Event::Publish {
            n: 200,
            label: first(200),
            tenure: None,
        });
        world.objects.push(Object {
            n: 200,
            units: None,
            later: None,
        });
        let lost = world.on_unit(row);
        let (failed, served) = serve_taken(&mut world, c_host(), |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open);
            let failed = serving.owner.recovery_report().warm.failed_units;
            (failed, serving.read_all(world))
        });
        let rejected = u32::from(arm == Arm::EarlierCapture);
        assert_eq!(
            failed, rejected,
            "{arm:?}: the reader rejects only the earlier capture's unit"
        );
        match arm {
            Arm::ReusePlanted => {
                let rule = "a recovery restored an entry its cut never captured";
                assert_eq!(violated(world.judged()), (Obligation::Restart, rule));
            }
            Arm::ReuseRefused => {
                let account = account(world.judged());
                assert_eq!((account.members, account.served), (50, 50));
            }
            Arm::EarlierCapture => {
                assert!(lost.iter().all(|n| !served.contains(n)));
                let account = account(world.judged());
                assert_eq!((account.members, account.excused.len()), (50, lost.len()));
                assert_eq!(account.served as usize, 50 - lost.len());
            }
        }
    }
}

/// The later label of object 2 in a [`suffixed`] shard.
const SECOND: Label = Label(102);

/// The suffix chain the record of a [`suffixed`] shard names before A's suffix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Chain {
    /// The earlier tenure's suffix alone; A's `E` is 4.
    Short,
    /// That suffix and one unwritten block of each of the three tenures between: the chain at its cap; A's `E` is 5.
    Full,
    /// `Full` created without the earlier tenure's suffix.
    WithoutOldest,
}

/// How A's suffix reaches the media and the record in [`suffixed`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Suffix {
    /// The blocks are on the media and the store certified the suffix to its durable end.
    Certified,
    /// The blocks are on the media and the store holds the suffix uncertified.
    Landed,
    /// The blocks never reached the media and the store holds the suffix uncertified.
    Unwritten,
}

/// A shard whose cut is a checkpoint and a chain of suffixes one lap into the delta region. The tenure before A
/// captured objects `1..=4` and then published a second label of object 2; the test places its suffix's one
/// block, the replacement's record, on the lap's first unit. `chain` says which suffixes the record names. A, the owner the record names,
/// then evicts objects `3..3 + evictions`, one removal record a block, from the lap's last unit on: the store
/// records the suffix by `reserve_suffix`, a `SuffixLog` over the record's floor seals the blocks, and `suffix`
/// says whether they land and are certified. An eviction the store or the log refused happened to no entry and
/// enters no history. Returns the shard and what A's appender did.
fn suffixed(evictions: u8, suffix: Suffix, chain: Chain) -> (World, Appended) {
    let count = 4;
    use crate::failover::records::Suffix as Recorded;
    use crate::storage::warm_sim::{
        append_suffix, block_unit, region, removal_of, replacement_unit, shard_store_with,
        suffix_block, tenure_replacing,
    };
    let session = |attempts: u32| crate::storage::session_at(3, attempts).get();
    let replaced = Some((2, content(2, SECOND)));
    let capturing = crate::storage::session_at(3, 0);
    let before = capturing.get();
    let (a, replace) = tenure_replacing(capturing, count, |n| content(n, first(n)), replaced);
    let replace = replace.expect("the replacement's record");
    let new_unit = replacement_unit(&replace);
    let lap = region();
    // A tenure between reserved one block and wrote none: an uncertified tail.
    let unwritten = |attempts: u32| Recorded {
        session: session(attempts),
        start: lap + u64::from(attempts),
        certified: lap + u64::from(attempts),
        end: lap + u64::from(attempts) + 1,
    };
    let mut recorded = vec![Recorded {
        session: before,
        start: lap,
        certified: lap + 1,
        end: lap + 1,
    }];
    if chain != Chain::Short {
        recorded.extend([unwritten(1), unwritten(2), unwritten(3)]);
    }
    if chain == Chain::WithoutOldest {
        recorded.remove(0);
    }
    let attempts = if chain == Chain::Short { 4 } else { 5 };
    let records = shard_store_with(a.named, false, attempts, (lap, &recorded));
    let removals: Vec<_> = (3..3 + evictions)
        .map(|n| {
            let entry = a.entries.iter().find(|entry| entry.key == object_key(n));
            removal_of(entry.expect("a captured object"))
        })
        .collect();
    let later = |n: u8| (n == 2).then_some((SECOND, new_unit));
    let mut world = World::over(a, records, false, later);
    world.land(block_unit(lap), &suffix_block(before, lap, &[replace]));
    let certify = suffix == Suffix::Certified;
    let appended = append_suffix(&world.records, 2 * lap - 1, &removals, certify);
    world.events.push(Event::Publish {
        n: 2,
        label: SECOND,
        tenure: None,
    });
    world.events.push(Event::Captured {
        n: 2,
        label: SECOND,
        units: (block_unit(lap), new_unit),
    });
    for (at, (lsn, bytes)) in appended.blocks.iter().enumerate() {
        let durable = suffix != Suffix::Unwritten;
        if durable {
            world.land(block_unit(*lsn), bytes);
        }
        let n = 3 + at as u8;
        world.events.push(Event::Evict {
            n,
            label: first(n),
            durable,
        });
    }
    (world, appended)
}

/// A takeover replays the checkpoint and the suffixes. Object 2 serves the bytes of the label that replaced the
/// captured one, the evicted object 3 misses and is no member of the retained set, and every other object serves;
/// a removal record on the media excludes its object whether or not the store certified its suffix. When the
/// removal record never reached the media, object 3 stays in the retained set and serves.
#[test]
fn a_takeover_replays_the_suffixes_and_a_removal_that_never_landed_keeps_its_entry() {
    for suffix in [Suffix::Certified, Suffix::Landed, Suffix::Unwritten] {
        let (mut world, appended) = suffixed(1, suffix, Chain::Short);
        assert!(
            appended.unreserved.is_none() && appended.blocks.len() == 1,
            "{suffix:?}"
        );
        let served = serve_taken(&mut world, c_host(), |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "{suffix:?}");
            serving.read_all(world)
        });
        assert!(
            world.served_label(2, SECOND),
            "{suffix:?}: object 2 serves its second label"
        );
        let kept = if suffix == Suffix::Unwritten { 4 } else { 3 };
        assert_eq!(served.contains(&3), kept == 4, "{suffix:?}: {served:?}");
        let account = account(world.judged());
        assert_eq!(
            (account.members, account.served),
            (kept, kept),
            "{suffix:?}"
        );
        assert!(account.excused.is_empty(), "{suffix:?}");
    }
}

/// A qualification failure, kept as a test of the present behavior. The accepted suffix contract loses to a damaged
/// delta block only the entries that depend on it. Here one certified delta block is damaged and recorded as an
/// injected fault: A's removal of object 3, on which no member of the retained set depends, or the earlier tenure's
/// replacement of object 2. The warm load refuses the whole slot, restores nothing, and the history fails "a
/// retained entry outside every damage set was lost on host loss" for the pair of objects 1 and 4, which no
/// damaged unit holds. The volume, the record and every other unit stay as they were.
#[test]
fn a_damaged_certified_suffix_block_refuses_the_whole_load_and_fails_fault_local_retention() {
    let lost = "a retained entry outside every damage set was lost on host loss";
    use crate::storage::warm_sim::{block_unit, region};
    for lsn in [2 * region() - 1, region()] {
        let (mut world, _) = suffixed(1, Suffix::Certified, Chain::Short);
        world.corrupt(block_unit(lsn));
        let before = world.evidence();
        let outcome = serve_taken(&mut world, c_host(), |world, serving, outcome| {
            assert!(serving.resident().is_empty(), "nothing was restored");
            assert_eq!(serving.control.accepted(Operation::Write), 0);
            let recovered = Step::Recovered {
                tenure: serving.tenure,
                cut: Some(CUT),
            };
            assert!(
                world.steps.borrow().list.contains(&recovered),
                "the refused load's recovery is a step"
            );
            outcome
        });
        assert_eq!(
            outcome,
            MetadataOutcome::Unloadable(LoadRefusal::StaleWrite),
            "block {lsn}: the load refuses"
        );
        assert_eq!(
            world.evidence().0,
            before.0,
            "the record keeps its manifest"
        );
        assert_eq!(
            violated(world.judged_group(&[1, 4])),
            (Obligation::Restart, lost),
            "block {lsn}"
        );
    }
}

/// The control "release history after grace". A's suffix of two removal records starts on the lap's last unit, so
/// its second block would take the lap's first unit, which holds the earlier tenure's replacement record, at or
/// above the floor a replay of the settled record reads. Two rules keep that history: the store refuses a
/// reservation ending past `min(floor, start) + J` (`reserve_suffix`), and the log refuses an append past its
/// capacity over the floor (`SuffixLog::covered`). With both rules, the store refuses the reservation before any
/// request, nothing is evicted, and the history passes. With the log's capacity alone ignoring the floor, the store
/// still refuses the reservation. With the reservation bound alone ignoring it, the store records the suffix, the
/// log refuses the second append before any change, object 4 stays, and the history passes. With both ignoring the
/// floor, the append is admitted, its block lands over the replacement record, and the history of object 2 alone
/// fails "a retained entry outside every damage set was lost on host loss": its later label is in the cut and no
/// fault was injected. That verdict holds whether the load refuses the whole slot, as it does here, or drops only
/// what the overwritten block carried.
#[test]
fn control_a_suffix_block_over_history_the_floor_still_requires_loses_a_retained_entry() {
    let lost = "a retained entry outside every damage set was lost on host loss";
    use crate::storage::checkpoint::{PLANT, Plant, WriteRefused};
    use crate::storage::warm_sim::{FLOORLESS, block_unit, region};
    for (log_floorless, store_floorless) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        FLOORLESS.with(|plant| plant.set(log_floorless));
        PLANT.with(|plant| plant.set(store_floorless.then_some(Plant::Floorless)));
        let (mut world, appended) = suffixed(2, Suffix::Certified, Chain::Short);
        FLOORLESS.with(|plant| plant.set(false));
        PLANT.with(|plant| plant.set(None));
        let arm = (log_floorless, store_floorless);
        let reached = log_floorless && store_floorless;
        let replacement = block_unit(region());
        match (store_floorless, &appended.unreserved) {
            (false, Some(WriteRefused::Chain)) | (true, None) => {}
            (_, refusal) => panic!("{arm:?}: {refusal:?}"),
        }
        let sealed = match arm {
            (_, false) => 0,
            (false, true) => 1,
            (true, true) => 2,
        };
        assert_eq!(appended.blocks.len(), sealed, "{arm:?}");
        assert_eq!(
            appended
                .blocks
                .last()
                .is_some_and(|reused| world.unit(replacement) == reused.1),
            reached,
            "{arm:?}: the fault is reached under both plants alone"
        );
        let (outcome, served) = serve_taken(&mut world, c_host(), |world, serving, outcome| {
            let served = match outcome {
                MetadataOutcome::Open => serving.read_all(world),
                _ => Vec::new(),
            };
            (outcome, served)
        });
        if reached {
            let refused = MetadataOutcome::Unloadable(LoadRefusal::StaleWrite);
            assert!(
                outcome == refused || outcome == MetadataOutcome::Open,
                "{outcome:?}"
            );
            assert!(!world.served_label(2, SECOND), "the replacement is lost");
            assert_eq!(
                violated(world.judged_group(&[2])),
                (Obligation::Restart, lost)
            );
        } else {
            let kept: &[u8] = if store_floorless {
                &[1, 2, 4]
            } else {
                &[1, 2, 3, 4]
            };
            assert_eq!(outcome, MetadataOutcome::Open, "{arm:?}");
            assert_eq!(served, kept, "{arm:?}");
            assert!(world.served_label(2, SECOND), "{arm:?}");
            assert_eq!(account(world.judged()).served, kept.len() as u32, "{arm:?}");
        }
    }
}

/// The control "drop an ancestor". The record's chain is at its cap, so the chain rewrite refuses A's suffix
/// before any request, A evicts nothing, and the successor replays the earlier tenure's replacement: the whole cut
/// serves. With the rewrite dropping the oldest suffix past the cap, the store client's successor rule refuses the
/// write before any request, so the record keeps its chain and the history is the same. A record created without
/// that oldest suffix is the state both rules exclude: the successor serves object 2's captured label, and the
/// history fails "a retained entry outside every damage set was lost on host loss".
#[test]
fn control_a_chain_rewrite_that_drops_its_oldest_suffix_is_refused_and_a_dropped_ancestor_loses_an_entry()
 {
    let lost = "a retained entry outside every damage set was lost on host loss";
    use crate::storage::checkpoint::{PLANT, Plant, WriteRefused};
    use crate::storage::store::StoreError;
    let drops = Some(Plant::ChainDropsOldest);
    for (chain, planted) in [
        (Chain::Full, None),
        (Chain::Full, drops),
        (Chain::WithoutOldest, None),
    ] {
        PLANT.with(|plant| plant.set(planted));
        let (mut world, appended) = suffixed(1, Suffix::Certified, chain);
        PLANT.with(|plant| plant.set(None));
        match (chain, planted, &appended.unreserved) {
            (Chain::Full, None, Some(WriteRefused::Chain))
            | (Chain::WithoutOldest, None, None)
            | (Chain::Full, Some(_), Some(WriteRefused::Store(StoreError::Successor(_)))) => {}
            (_, _, refusal) => panic!("{chain:?} {planted:?}: {refusal:?}"),
        }
        let recorded = restart_tests::shard_now(&world.records).ancestry;
        let oldest = recorded.as_slice()[0].session;
        let kept = oldest == crate::storage::session_at(3, 0).get();
        assert_eq!(kept, chain != Chain::WithoutOldest, "{chain:?}");
        let served = serve_taken(&mut world, c_host(), |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open);
            assert_eq!(serving.tenure, Tenure { g: 3, a: 12 });
            serving.read_all(world)
        });
        if chain == Chain::WithoutOldest {
            assert!(
                served.contains(&2) && !world.served_label(2, SECOND),
                "{served:?}"
            );
            assert_eq!(violated(world.judged()), (Obligation::Restart, lost));
        } else {
            assert_eq!(served, [1, 2, 3, 4], "{chain:?}");
            assert!(world.served_label(2, SECOND), "{chain:?}");
            assert_eq!(account(world.judged()).served, 4, "{chain:?}");
        }
    }
}

/// An injected end state, for the control "skip a removal dependency". The rule that holds an evicted entry's
/// payload unit until its removal record is durable belongs to the owner's suffix writer, which this crate's owner
/// does not run, so no implementation rule is varied here. The test writes the state that rule excludes: A's
/// removal record of object 3 never reached the media, and object 3's payload unit holds another key's record, as
/// a fill that reused the unit would leave it. The cut still holds object 3, its read fails the header check with
/// no byte surfaced, and the history fails "a retained entry outside every damage set was never served after host
/// loss".
#[test]
fn a_payload_unit_reused_before_its_removal_record_landed_leaves_a_retained_entry_unserved() {
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let (mut world, _) = suffixed(1, Suffix::Unwritten, Chain::Short);
    let ((_, freed), (_, other)) = (world.units(3), world.units(4));
    world.land(freed, &world.unit(other));
    let served = serve_taken(&mut world, c_host(), |world, serving, outcome| {
        assert_eq!(outcome, MetadataOutcome::Open);
        serving.read_all(world)
    });
    assert_eq!(served, [1, 2, 4], "object 3 is restored and unreadable");
    assert_eq!(violated(world.judged()), (Obligation::Restart, unserved));
}

/// Moving-clock histories use the fixture's Report deadline `T_report` and period `P_report`, both one round. The
/// 1,000 µs window `delta` exceeds `P_report + T_report + tau`, with `tau` = 9 µs. The 10 µs `Honest` granule divides
/// `T_report`, and `Slow` with divisor 2 loses 500 µs per window.
fn moving_bounds() -> crate::failover::bounds::Bounds {
    bounds_with(limits(), WINDOW, TAU)
}

/// The window `delta` of [`moving_bounds`], in microseconds.
const WINDOW: u64 = 1_000;
/// The clock error `tau` of [`moving_bounds`], in microseconds.
const TAU: u64 = 9;
// A `Slow` reading at divisor 2, the smallest `check_moving` accepts, loses more than `tau` over one window; a
// larger divisor loses at least as much.
const _: () = assert!(WINDOW - WINDOW / 2 > TAU);

/// The 10 µs `Honest` granule divides `ROUND_US`.
const fn honest(offset_us: u64) -> Strategy {
    Strategy::Honest {
        offset_us,
        error_us: TAU,
    }
}

const fn slow(offset_us: u64) -> Strategy {
    Strategy::Slow {
        offset_us,
        divisor: 2,
    }
}

/// The three owner clock strategies, at offset zero.
const STRATEGIES: [Strategy; 3] = [honest(0), slow(0), Strategy::Frozen];

/// The Reports the tenure has submitted to its device.
fn reports(serving: &Serving<'_>) -> usize {
    serving.registry.borrow().reports()
}

fn check_moving(strategy: Strategy) {
    match strategy {
        Strategy::Honest { error_us, .. } => {
            assert!(error_us <= TAU, "{strategy:?}: an honest error above tau");
            assert!(
                ROUND_US.is_multiple_of(error_us + 1),
                "{strategy:?}: an honest granule that leaves part of a round"
            );
        }
        Strategy::Slow { divisor, .. } => {
            assert!(divisor >= 2, "{strategy:?}: a slow divisor below 2");
        }
        Strategy::Frozen => {}
    }
}

impl World {
    /// Serves the next tenures under `strategy` and [`moving_bounds`], after [`check_moving`] accepts `strategy`.
    fn set_moving_clock(&mut self, strategy: Strategy) {
        check_moving(strategy);
        self.strategy = strategy;
        self.bounds = moving_bounds();
    }
}

/// [`check_moving`] refuses a `Slow` divisor of 0 or 1, an `Honest` error of 19 µs (above `tau`, granule 20 µs) and an
/// `Honest` error of 6 µs (within `tau`, granule 7 µs), each through the assertion that names its condition.
/// [`Strategy::read`] refuses a reading that does not fit a `u64`: an offset that fits at `t = 5` and overflows at
/// `t = 6`, a `Slow` divisor of 0 and an `Honest` error of `u64::MAX`.
#[test]
fn an_unfit_strategy_is_refused() {
    let refusal = |run: &dyn Fn()| -> String {
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
            .expect_err("the strategy is refused");
        *payload.downcast::<String>().expect("a formatted message")
    };
    for (strategy, expected) in [
        (
            Strategy::Slow {
                offset_us: 0,
                divisor: 0,
            },
            "a slow divisor below 2",
        ),
        (
            Strategy::Slow {
                offset_us: 0,
                divisor: 1,
            },
            "a slow divisor below 2",
        ),
        (
            Strategy::Honest {
                offset_us: 0,
                error_us: 19,
            },
            "an honest error above tau",
        ),
        (
            Strategy::Honest {
                offset_us: 0,
                error_us: 6,
            },
            "leaves part of a round",
        ),
    ] {
        let message = refusal(&|| check_moving(strategy));
        assert!(message.contains(expected), "{strategy:?}: {message}");
    }
    let late = Strategy::Honest {
        offset_us: u64::MAX - 5,
        error_us: 0,
    };
    assert_eq!(late.read(5), u64::MAX);
    for (strategy, t) in [
        (late, 6),
        (
            Strategy::Slow {
                offset_us: u64::MAX - 2,
                divisor: 2,
            },
            6,
        ),
        (
            Strategy::Slow {
                offset_us: 0,
                divisor: 0,
            },
            1,
        ),
        (
            Strategy::Honest {
                offset_us: 0,
                error_us: u64::MAX,
            },
            1,
        ),
    ] {
        let message = refusal(&|| {
            strategy.read(t);
        });
        assert!(
            message.contains("has no u64 reading"),
            "{strategy:?} at {t}: {message}"
        );
    }
}

/// At offsets 0 and 7,000 µs, over one window: `Honest` readings advance in 10 µs steps and lag `offset_us + t` by
/// 0 to 9 µs; `Slow` readings start at `offset_us`, gain 1 µs every 2 µs and end more than `tau` behind; `Frozen`
/// readings stay zero. Each strategy produces nondecreasing readings. The granule divides the round, and the bounds
/// take the round as their Report deadline and period.
#[test]
fn each_strategy_reads_as_declared() {
    use crate::storage::ServingClock;
    assert!(
        ROUND_US.is_multiple_of(TAU + 1),
        "the granule divides a round"
    );
    let bounds = moving_bounds();
    assert_eq!(
        (bounds.report_deadline(), bounds.report_period()),
        (ROUND_US, ROUND_US)
    );
    let moving = [0, 7_000]
        .into_iter()
        .flat_map(|offset_us| [honest(offset_us), slow(offset_us)]);
    for strategy in moving.chain([Strategy::Frozen]) {
        let now = Rc::new(Cell::new(0));
        let clock = OwnerClock {
            strategy,
            now: Rc::clone(&now),
        };
        let readings: Vec<u64> = (0..=WINDOW)
            .map(|t| {
                now.set(t);
                clock.now_us().expect("a reading")
            })
            .collect();
        assert!(readings.is_sorted(), "{strategy:?}: a reading fell");
        let (start, last) = (readings[0], readings[readings.len() - 1]);
        match strategy {
            Strategy::Honest {
                offset_us,
                error_us,
            } => {
                for (t, &reading) in (0..).zip(&readings) {
                    let within = reading <= offset_us + t && offset_us + t - reading <= error_us;
                    assert!(within, "{strategy:?}: {reading} at {t}");
                }
                assert_eq!(
                    (start, readings[9], readings[10]),
                    (offset_us, offset_us, offset_us + 10),
                    "{strategy:?}"
                );
            }
            Strategy::Slow { offset_us, .. } => {
                assert_eq!(
                    (start, readings[9], readings[10]),
                    (offset_us, offset_us + 4, offset_us + 5),
                    "{strategy:?}"
                );
                let elapsed = last - start;
                assert!(elapsed < WINDOW - TAU, "{strategy:?} advanced {elapsed}");
            }
            Strategy::Frozen => assert!(readings.iter().all(|&reading| reading == 0)),
        }
    }
}

/// C serves, D takes the volume over, and C runs 50 idle rounds. At the end of C's first deposed turn C's Report
/// table equals the shared reservation under both strategies. Under `Honest` the Report pending at D's fence is
/// answered from that table in the same turn, shows D holding, and C is `Withdrawn` by the end of the turn with a
/// cause the `Withdrawal` label groups as a Report; the exact cause and flip request are printed. Under `Frozen` C's
/// Report count stays fixed after D's fence and C remains `Serving`. C's send count stays fixed after the fence under
/// both strategies, and the history judgment accepts both with one account.
#[test]
fn an_idle_deposed_tenure_withdraws_on_its_report_only_when_its_clock_moves() {
    use crate::failover::report::Withdrawal;
    use crate::failover::serving::State;
    for strategy in [honest(0), Strategy::Frozen] {
        let mut world = World::new(4, false);
        world.set_moving_clock(strategy);
        serve_taken(&mut world, c_host(), |world, c, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "{strategy:?}");
            assert_eq!(c.read_all(world).len(), 4);
            assert_eq!(c.owner.authority_report().state, State::Serving);
            world.designate_fresh();
            c.idle_device();
            let (taken, log) = world.takeover(d_host());
            assert!(taken.is_ok() && c.deposed(), "{log:?}");
            let (sent, before) = (c.owner.report().sent, c.registry.borrow().reports());
            c.step_without_client();
            assert_eq!(
                c.registry.borrow().entries,
                world.reservation.borrow().entries,
                "{strategy:?}: C's Report table follows the reservation from its first deposed turn"
            );
            let first = c.owner.authority_report().state;
            let pending_answered = if strategy == Strategy::Frozen {
                State::Serving
            } else {
                State::Withdrawn
            };
            assert_eq!(
                first, pending_answered,
                "{strategy:?}: the Report pending at D's fence is answered from the copied table"
            );
            for _ in 1..50 {
                c.step_without_client();
            }
            let d_holds = {
                let pair = world.fresh.as_ref().expect("D's record").pair();
                let registry = c.registry.borrow();
                (registry.entries.iter()).any(|entry| entry.pair == pair && entry.holder)
            };
            assert!(d_holds, "{strategy:?}: C's Report table shows D holding");
            let authority = c.owner.authority_report();
            assert_eq!(c.owner.report().sent, sent, "{strategy:?}: C sent nothing");
            if strategy == Strategy::Frozen {
                assert_eq!(
                    c.registry.borrow().reports(),
                    before,
                    "a frozen clock submits no Report"
                );
                assert_eq!(authority.state, State::Serving);
            } else {
                assert_eq!(authority.state, State::Withdrawn);
                let (cause, flip) = (authority.withdrawal, authority.flip);
                assert_eq!(
                    cause.map(Withdrawal::from),
                    Some(Withdrawal::Report),
                    "a Report withdrew C: {cause:?}"
                );
                println!("{strategy:?}: C withdrew with {cause:?} and flip request {flip:?}");
            }
        });
        let accounts = world
            .judged()
            .unwrap_or_else(|verdict| panic!("{strategy:?}: {verdict:?}"));
        assert_eq!(accounts.len(), 1, "{strategy:?}");
    }
}

/// A 30-round pause advances the tenure's round counter by 30 and its true-time cell by 3,000 µs, while the owner's
/// send count, the ownership-step list and the submitted Report count stay fixed. The Report age the installed clock
/// gives grows by the whole pause under `Honest`, by half under `Slow` and by zero under `Frozen`. After the pause the
/// read gate refuses `WindowExpired` under the moving clocks, past the 1,000 µs window, and still admits under
/// `Frozen`.
#[test]
fn a_pause_advances_true_time_and_skips_the_owner() {
    use crate::failover::serving::Denial;
    use crate::storage::AuthorityRefusal;
    for strategy in [honest(0), slow(0), Strategy::Frozen] {
        let mut world = World::new(4, false);
        world.set_moving_clock(strategy);
        serve_taken(&mut world, c_host(), |world, c, _| {
            assert_eq!(c.read_all(world).len(), 4);
            let (sent, turn, t) = (c.owner.report().sent, c.turn, c.now.get());
            let submitted = c.registry.borrow().reports();
            let steps = world.steps.borrow().list.len();
            let before = c.owner.authority_report();
            let age = before.report_age_us.expect("a certified Report window");
            assert_eq!(before.refusal, None, "{strategy:?}: the read gate admits");
            c.pause(30);
            assert_eq!(c.owner.report().sent, sent, "{strategy:?}: nothing sent");
            assert_eq!(world.steps.borrow().list.len(), steps, "no owner turn");
            assert_eq!(c.turn, turn + 30);
            let paused = c.now.get() - t;
            assert_eq!(
                paused,
                30 * ROUND_US,
                "{strategy:?}: the true-time cell advanced 30 rounds"
            );
            assert_eq!(
                c.registry.borrow().reports(),
                submitted,
                "{strategy:?}: under a moving clock a polled owner would report"
            );
            let after = c.owner.authority_report();
            let grown = after.report_age_us.expect("the same Report window") - age;
            let expected = match strategy {
                Strategy::Honest { .. } => paused,
                Strategy::Slow { divisor, .. } => paused / divisor,
                Strategy::Frozen => 0,
            };
            assert_eq!(grown, expected, "{strategy:?}");
            let expired = Some(AuthorityRefusal::Admission(Denial::WindowExpired));
            let refusal = if strategy == Strategy::Frozen {
                None
            } else {
                expired
            };
            assert_eq!(after.refusal, refusal, "{strategy:?}");
        });
        assert!(world.judged().is_ok(), "{strategy:?}");
    }
}
