use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::tests::{Wire, attachment, content, endpoint_on, host_over, inline, warm_volume};
use super::{Attachment, Served, Teardown, bring_up, recovery_line, serve, teardown};
use crate::failover::fresh::tests::registrant;
use crate::failover::records::{ShardRecord, VolumeRecord};
use crate::failover::restart::tests::{own, shard_now, volume_id};
use crate::failover::retire::Target;
use crate::failover::serving::{Cause, Deposing, Event, State};
use crate::failover::takeover::tests::{c_host, c_pair, rewrite, stored_c, takeover_of};
use crate::host::fencer_tests::{Driving, commands, fencer_of, shared_table};
use crate::host::recover::{Recovery, Role};
use crate::host::recover_tests::{own_holds, recovered, recovered_on, tenure};
use crate::host::{Exit, HostGate, Rerun};
use crate::net::link::{Faults, Landed, LinkEnd, Net, network};
use crate::net::owner_tests::{Mux, collect, sourced_client};
use crate::net::ownership::{ActivatedEpoch, session_of};
use crate::net::{Client, Outcome as Fetched, Owner, Releases, RequestId, SessionState};
use crate::storage::device::sim::{Fault, Media, SimControl, Unwind};
use crate::storage::gate_fixture::Ticking;
use crate::storage::gate_fixture::{Control, OwnerClock, Reserving, Strategy, arena_with};
use crate::storage::portable::scripted::{ClockScript, ScriptedClock, TEST_EARLIEST};
use crate::storage::store::Key;
use crate::storage::store::sim::Shared;
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::{object_key, storage};
use crate::storage::{
    Bomb, BufferArena, DeviceStatus, Dropped, EngineBudget, RecoveryPhase, RecoveryReport, Storage,
};

/// The microseconds one round lasts.
pub(crate) const ROUND_US: u64 = 100;
/// The network end of the stage's client, and the end of its owner.
pub(crate) const CLIENT_END: usize = 0;
pub(crate) const OWNER_END: usize = 1;

pub(crate) type TestOwner<'w> = Owner<'w, 'w, 'w, TestPlatform, Reserving, Mux<'w>>;

/// One `Live` tenure of this host over the warm volume, restarted at `E = 5`, with a client on one link to its
/// owner. The tenure's serving clock reads `now`, which each round advances by [`ROUND_US`].
pub(crate) struct Stage<'w> {
    pub(crate) owner: Option<TestOwner<'w>>,
    pub(crate) rounds: Rounds<'w>,
    pub(crate) store: Shared,
    pub(crate) storage: &'w Storage<TestPlatform>,
    pub(crate) media: Media,
    pub(crate) registry: Control,
    /// The script of the volume's physical-clock provider, which reads trusted until a test queues another reading.
    pub(crate) clock: ClockScript,
    /// The drain bound each `serve` and `teardown` of the stage takes.
    patience: u64,
}

/// The world outside the owner: each round advances the link and the clock cell, polls the client and ticks the
/// device, unless `frozen` holds the device's commands.
pub(crate) struct Rounds<'w> {
    pub(crate) client: RefCell<Client<'w, LinkEnd<'w>>>,
    net: Rc<RefCell<Net<'w>>>,
    pub(crate) control: SimControl,
    pub(crate) now: Rc<Cell<u64>>,
    turn: Cell<u64>,
    pub(crate) frozen: Cell<bool>,
    /// The bytes `serve` wrote to its record sink so far.
    record: Rc<RefCell<Vec<u8>>>,
    /// How the record sink answers a write, and the write calls it took.
    sink: Cell<Answer>,
    writes: Cell<u32>,
    /// The destructors that ran for the payload of an [`Answer::Bomb`] write.
    dropped: Dropped,
    /// The serving clock's readings so far.
    pub(crate) clock_reads: Rc<Cell<u32>>,
    /// Microseconds added to every round's time, so a test can move the clock past the round bound.
    pub(crate) skip: Cell<u64>,
}

/// How the record sink answers a write.
#[derive(Clone, Copy)]
enum Answer {
    Accept,
    Refuse,
    Unwind,
    /// Unwinds with a [`Bomb`] payload.
    Bomb,
}

/// The stage's record sink, which a script reads between turns.
struct Sink<'r, 'w>(&'r Rounds<'w>);

impl std::io::Write for Sink<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.writes.set(self.0.writes.get() + 1);
        match self.0.sink.get() {
            Answer::Accept => self.0.record.borrow_mut().extend_from_slice(bytes),
            Answer::Refuse => return Err(std::io::ErrorKind::BrokenPipe.into()),
            Answer::Unwind => panic!("a sink that unwinds"),
            Answer::Bomb => std::panic::panic_any(Bomb(self.0.dropped.clone())),
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Rounds<'_> {
    /// Runs one round and returns its time, the owner's next poll time.
    pub(crate) fn round(&self) -> u64 {
        let turn = self.turn.get();
        assert!(turn < 20_000, "the tenure never ended");
        let now = turn * ROUND_US + self.skip.get();
        self.now.set(now);
        self.net.borrow_mut().advance(turn);
        self.client.borrow_mut().poll(now);
        if !self.frozen.get() {
            self.control.tick(64);
        }
        self.turn.set(turn + 1);
        now
    }

    /// Replaces the faults of the link's direction toward the client.
    pub(crate) fn fault_toward_client(&self, faults: Faults) {
        self.net.borrow_mut().set_faults(CLIENT_END, faults);
    }

    /// The carried ordinal the network gives its next datagram: a datagram sent after this call carries it or a
    /// later one.
    pub(crate) fn carried(&self) -> u64 {
        self.net.borrow().carried()
    }

    /// The datagrams that reached end `toward`, [`CLIENT_END`] or [`OWNER_END`], carrying an ordinal of `from` or
    /// later. Each was sent at or after the [`Rounds::carried`] call that returned `from`.
    pub(crate) fn delivered_since(&self, toward: usize, from: u64) -> usize {
        let net = self.net.borrow();
        let (deliveries, overflowed) = net.deliveries();
        assert!(!overflowed, "the delivery log holds every delivery");
        (deliveries.iter())
            .filter(|delivery| delivery.toward == toward && delivery.ordinal >= from)
            .count()
    }

    /// Whether the datagram carrying `ordinal` reached end `toward` whole.
    pub(crate) fn delivered(&self, toward: usize, ordinal: u64) -> bool {
        let net = self.net.borrow();
        let (deliveries, overflowed) = net.deliveries();
        assert!(!overflowed, "the delivery log holds every delivery");
        deliveries.iter().any(|delivery| {
            delivery.toward == toward
                && delivery.ordinal == ordinal
                && delivery.landed == Landed::Delivered
        })
    }

    /// The datagrams in flight toward end `toward`.
    pub(crate) fn in_flight(&self, toward: usize) -> usize {
        self.net.borrow().pending(toward)
    }

    pub(crate) fn get(&self, n: u8) -> RequestId {
        self.try_get(n).expect("an admitted GET")
    }

    /// A GET of object `n`, or the client's refusal of it.
    pub(crate) fn try_get(&self, n: u8) -> Result<RequestId, crate::net::GetRefused> {
        let now = self.turn.get() * ROUND_US + self.skip.get();
        (self.client.borrow_mut()).get(object_key(n), 1 << 16, 1 << 20, now, 30_000_000)
    }

    /// The lines `serve` wrote to its record sink so far.
    fn lines(&self) -> Vec<String> {
        let record = String::from_utf8(self.record.borrow().clone()).unwrap();
        record.lines().map(str::to_owned).collect()
    }

    /// The outcome of GET `id` once the client has it, with the bytes it surfaced.
    pub(crate) fn fetched(&self, id: RequestId, bytes: &mut Vec<u8>) -> Option<Fetched> {
        let mut client = self.client.borrow_mut();
        collect(&mut client, id, bytes);
        let outcome = client.outcome(id)?;
        let _ = client.retire(id);
        Some(outcome)
    }
}

/// A serving clock that counts its readings.
struct Counted(OwnerClock, Rc<Cell<u32>>);

impl crate::storage::ServingClock for Counted {
    fn now_us(&self) -> Option<u64> {
        self.1.set(self.1.get() + 1);
        self.0.now_us()
    }
}

/// Runs `body` over a [`Stage`].
pub(crate) fn staged<R>(body: impl for<'w> FnOnce(Stage<'w>) -> R) -> R {
    staged_over(warm_volume(), body)
}

/// [`staged`] under a serving clock that reads `ahead_us` above the turn clock.
pub(crate) fn staged_ahead<R>(ahead_us: u64, body: impl for<'w> FnOnce(Stage<'w>) -> R) -> R {
    staged_clocked(warm_volume(), ahead_us, body)
}

/// [`staged`] over the store and media of `volume`.
pub(crate) fn staged_over<R>(
    volume: (Shared, Media),
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    staged_clocked(volume, 0, body)
}

fn staged_clocked<R>(
    volume: (Shared, Media),
    ahead_us: u64,
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    staged_as(
        Role::Restart,
        own_holds(),
        volume,
        || storage(1),
        ahead_us,
        body,
    )
}

/// A same-host restart over the store and media of `volume` and the reservation table `registry`, as an earlier
/// stage left them, over the storage `make` builds.
pub(crate) fn staged_over_on<R>(
    volume: (Shared, Media),
    registry: Control,
    make: fn() -> Storage<TestPlatform>,
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    staged_as(Role::Restart, registry, volume, make, 0, body)
}

/// [`staged`] over a fresh first acquisition of `store`'s shard on blank media, which formats the media and serves
/// an empty index.
pub(crate) fn staged_fresh<R>(store: Shared, body: impl for<'w> FnOnce(Stage<'w>) -> R) -> R {
    staged_fresh_on(store, || storage(1), body)
}

/// [`staged_fresh`] over the storage `make` builds.
pub(crate) fn staged_fresh_on<R>(
    store: Shared,
    make: fn() -> Storage<TestPlatform>,
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    let media = crate::storage::device::sim::media(crate::storage::volume_fixture::MEDIA);
    staged_as(
        Role::Fresh,
        shared_table(Vec::new()),
        (store, media),
        make,
        0,
        body,
    )
}

/// The stage of `role` over `registry`, the store and media and the storage `make` builds, under a serving clock
/// that reads `ahead_us` above the turn clock.
fn staged_as<R>(
    role: Role,
    registry: Control,
    (store, media): (Shared, Media),
    make: fn() -> Storage<TestPlatform>,
    ahead_us: u64,
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    let recovered = store.clone();
    let pair = crate::host::recover_tests::role_pair(role, &store);
    staged_by(
        (registry, pair, role == Role::Fresh),
        (store, media),
        (make, ahead_us),
        move |disk, arena, fencing_clock, serving| {
            tenure(recovered_on(
                role,
                &recovered,
                disk,
                arena,
                fencing_clock,
                serving,
            ))
        },
        body,
    )
}

/// A same-host restart of `identity` over the store and media of `volume` and the reservation table `registry`.
pub(crate) fn staged_restart_as<R>(
    identity: crate::host::recover_tests::Identity,
    (volume, registry): ((Shared, Media), Control),
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    let recovered = volume.0.clone();
    staged_by(
        (registry, identity.pair, false),
        volume,
        (|| storage(1), 0),
        move |disk, arena, fencing_clock, serving| {
            tenure(crate::host::recover_tests::restarted_as(
                identity,
                &recovered,
                (disk, arena, fencing_clock),
                serving,
            ))
        },
        body,
    )
}

/// The serving clock of a [`Stage`]'s owner, which reads the rounds' time.
pub(crate) type ServingClock = Box<dyn crate::storage::ServingClock>;

/// A [`Stage`] over the storage `make` builds, whose tenure `recover` acquires for the host issuing as `own` on
/// `registry`, over its driver, an arena, a fencing clock and the owner's serving clock, which reads `ahead_us` above
/// the turn clock. With `driving`, the fencing clock ticks the device, as a fresh acquisition's Register and Acquire
/// need.
pub(crate) fn staged_by<R>(
    (registry, own, driving): (Control, crate::failover::evidence::Pair, bool),
    (store, media): (Shared, Media),
    (make, ahead_us): (fn() -> Storage<TestPlatform>, u64),
    recover: impl for<'a> FnOnce(
        Reserving,
        &'a BufferArena<TestPlatform>,
        &'a dyn crate::storage::ServingClock,
        ServingClock,
    ) -> crate::host::Tenure<'a, TestPlatform, Reserving>,
    body: impl for<'w> FnOnce(Stage<'w>) -> R,
) -> R {
    let (disk, control) = host_over(&registry, &media, own);
    let arena = arena_with(16, 9);
    // A fresh acquisition's Register and Acquire complete only while the fencer's clock ticks the device.
    let fencing_clock: Box<dyn crate::storage::ServingClock> = if driving {
        Box::new(Driving::new(&control, []))
    } else {
        Box::new(Ticking::default())
    };
    let now = Rc::new(Cell::new(0));
    let serving = OwnerClock {
        strategy: Strategy::Honest {
            offset_us: ahead_us,
            error_us: 0,
        },
        now: Rc::clone(&now),
    };
    let clock_reads = Rc::new(Cell::new(0));
    let serving = Counted(serving, Rc::clone(&clock_reads));
    let tenure = recover(disk, &arena, &*fencing_clock, Box::new(serving));
    let storage = make();
    let (clock, script) = ScriptedClock::with_script();
    script.trusted(TEST_EARLIEST, TEST_EARLIEST + 2_000_000);
    let wire = Wire::new();
    let receive = wire.pool();
    let client_wire = Wire::new();
    let client_pool = client_wire.pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let client = sourced_client(
        0,
        &client_pool,
        &releases,
        client_end,
        Box::default(),
        |nonce: &mut [u8; 16]| {
            nonce[0] = 2;
            Ok(())
        },
    );
    let rounds = Rounds {
        client: RefCell::new(client),
        net,
        control,
        now,
        turn: Cell::new(0),
        frozen: Cell::new(false),
        record: Rc::default(),
        sink: Cell::new(Answer::Accept),
        writes: Cell::new(0),
        dropped: Dropped::default(),
        clock_reads,
        skip: Cell::new(0),
    };
    let endpoint = endpoint_on(&wire, &receive, owner_end);
    let mut budget = EngineBudget::new(1 << 26);
    let owner = inline(|| {
        bring_up(
            &HostGate::qualified(),
            tenure,
            Attachment {
                clock,
                ..attachment(&storage)
            },
            endpoint,
            &mut budget,
            || rounds.round(),
        )
    })
    .unwrap_or_else(|unbrought| panic!("the bring-up ended {:?}", unbrought.exit));
    rounds
        .client
        .borrow_mut()
        .session(rounds.turn.get() * ROUND_US);
    body(Stage {
        owner: Some(owner),
        rounds,
        store,
        storage: &storage,
        media,
        registry,
        clock: script,
        patience: u64::MAX,
    })
}

type TestTeardown<'w> = Teardown<'w, 'w, 'w, TestPlatform, Reserving, Mux<'w>>;

/// What `serve` returned: the exit, with the shut-down owner's parts for [`Served::Ended`] or the kept owner and
/// its blockers for [`Served::Kept`].
pub(crate) struct TestServed<'w> {
    pub(crate) exit: Exit,
    pub(crate) teardown: TestTeardown<'w>,
}

impl<'w> Stage<'w> {
    /// `serve` over the stage's owner: `script` runs before each round with the round number and may set `stop`.
    pub(crate) fn serve(
        &mut self,
        script: impl FnMut(&Rounds<'w>, u64, &AtomicBool),
        mut duties: impl FnMut(&mut TestOwner<'w>, u64),
    ) -> TestServed<'w> {
        self.serve_until(script, |owner, now| {
            duties(owner, now);
            None
        })
        .0
    }

    /// [`Stage::serve`] over `duties` that may end the tenure with an exit, with the record the tenure wrote.
    pub(crate) fn serve_until(
        &mut self,
        mut script: impl FnMut(&Rounds<'w>, u64, &AtomicBool),
        duties: impl FnMut(&mut TestOwner<'w>, u64) -> Option<Exit>,
    ) -> (TestServed<'w>, String) {
        let stop = AtomicBool::new(false);
        let rounds = &self.rounds;
        let served = serve(
            &HostGate::qualified(),
            self.owner.take().expect("one tenure a stage"),
            &stop,
            || {
                script(rounds, rounds.turn.get(), &stop);
                rounds.round()
            },
            duties,
            &mut Sink(rounds),
            self.patience,
        );
        let served = match served {
            Served::Ended { exit, shutdown } => TestServed {
                exit,
                teardown: Ok(*shutdown),
            },
            Served::Kept { ending, kept } => TestServed {
                exit: ending,
                teardown: Err(kept),
            },
        };
        (served, rounds.lines().join("\n"))
    }

    /// `teardown` of `owner` over the stage's rounds.
    fn teardown(&self, owner: TestOwner<'w>) -> TestTeardown<'w> {
        teardown(
            &HostGate::qualified(),
            owner,
            || self.rounds.round(),
            self.patience,
        )
    }
}

/// C's takeover of the volume on `media` through a fencer on the shared reservation table `registry`: it commits
/// in `store` and preempts.
fn take_over(registry: &Control, media: &Media, store: &Shared) {
    let (disk, _control) = host_over(registry, media, c_pair());
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
    takeover_of(store, c_host())
        .run(&mut store_client(store), &stored_c(), &mut fencer)
        .expect("C's takeover");
}

fn idle(_: &mut TestOwner<'_>, _: u64) {}

/// The shard view an owner's record duty observes: the volume record, then the shard record, read from `store`.
/// The simulated store answers inside the call, which stands in for the result a store lane holds.
pub(crate) fn observe(store: &Shared, owner: &mut TestOwner<'_>, now: u64) {
    let mut reader = store_client(store);
    let volume = reader.read::<VolumeRecord>(Key::Volume(volume_id())).ok();
    let record = reader.read::<ShardRecord>(Key::Shard(shard())).ok();
    owner.observe_shard_view(volume_id(), record.as_ref(), volume.as_ref(), None, now);
}

/// The tick at which `owner`'s report closed its first-safe-hit span.
fn first_hit(owner: &TestOwner<'_>) -> Option<u64> {
    owner
        .recovery_report()
        .phase(RecoveryPhase::FirstSafeHit)
        .end
}

/// The recovery record line is written once per tenure, on the turn whose poll closed the first-safe-hit span: no
/// line precedes that turn, a second completed GET adds none, and a stop request then ends the tenure `Stopped`
/// with the driver returned. The line names the tenure, each phase in order with the hit's tick, and the warm
/// load's counts; each GET returns the recovered object's bytes.
#[test]
fn the_recovery_line_is_written_once_after_the_first_safe_hit() {
    staged(|mut stage| {
        let mut gets: Vec<(RequestId, Vec<u8>)> = Vec::new();
        let mut done = 0;
        let lines = Rc::clone(&stage.rounds.record);
        let written = move || lines.borrow().iter().filter(|byte| **byte == b'\n').count();
        let mut hit = None;
        let mut tenure = None;
        let mut report: Option<RecoveryReport> = None;
        let served = stage.serve(
            |rounds, _, stop| {
                let active = rounds.client.borrow().state() == SessionState::Active;
                if active && gets.len() == done && done < 2 {
                    gets.push((rounds.get(1 + done as u8), Vec::new()));
                }
                if let Some((id, bytes)) = gets.get_mut(done)
                    && let Some(outcome) = rounds.fetched(*id, bytes)
                {
                    assert_eq!(outcome, Fetched::Complete);
                    done += 1;
                }
                if done == 2 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                // A duty runs after its turn's poll and before its turn's write.
                assert_eq!(
                    written(),
                    usize::from(hit.is_some()),
                    "one line, from the turn that closed the span"
                );
                if hit.is_none() && first_hit(owner).is_some() {
                    hit = Some(now);
                    report = Some(owner.recovery_report());
                }
                tenure = Some(owner.authority_report().tenure);
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(served.teardown.is_ok(), "the owner shut down");
        assert_eq!(gets[0].1, content(1, 1));
        assert_eq!(gets[1].1, content(2, 0xee), "the suffix's replacement");
        let lines = stage.rounds.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        // The head, then six fields a phase, then a label and a value for each warm count.
        const HEAD: usize = 5;
        const PHASE: usize = 6;
        let fields: Vec<_> = lines[0].split(' ').collect();
        let (generation, epoch) = tenure.expect("a serving turn");
        assert_eq!(
            fields[..HEAD],
            [
                "recovery",
                "g",
                &generation.get().to_string(),
                "a",
                &epoch.get().to_string()
            ]
        );
        let report = report.expect("the report of the turn that closed the span");
        let tick = |tick: Option<u64>| tick.map_or("-".to_owned(), |tick| tick.to_string());
        let phases = [
            ("initialization", RecoveryPhase::Initialization),
            ("adoption", RecoveryPhase::Adoption),
            ("replay", RecoveryPhase::Replay),
            ("first-safe-hit", RecoveryPhase::FirstSafeHit),
            ("retained-readiness", RecoveryPhase::RetainedReadiness),
            ("fill-readiness", RecoveryPhase::FillReadiness),
        ];
        for (at, (name, phase)) in phases.into_iter().enumerate() {
            let span = report.phase(phase);
            assert_eq!(
                fields[HEAD + PHASE * at..HEAD + PHASE * (at + 1)],
                [
                    name,
                    &format!("{}..{}", tick(span.start), tick(span.end)),
                    "operations",
                    &span.operations.to_string(),
                    "rows",
                    &span.rows.to_string()
                ],
                "{lines:?}"
            );
        }
        let hit_span = report.phase(RecoveryPhase::FirstSafeHit);
        assert_eq!(hit_span.end, hit, "the tick that closed the span");
        assert!(hit_span.start.is_some());
        let fill = report.phase(RecoveryPhase::FillReadiness);
        assert_eq!(
            (fill.start, fill.end),
            (None, None),
            "no fill was submitted by the first hit"
        );
        let warm = report.warm;
        let counts: [(&str, u64); 10] = [
            ("installed", warm.installed),
            ("omitted", warm.omitted),
            ("failed-units", warm.failed_units.into()),
            ("unread-units", warm.unread_units.into()),
            ("suffix-damage", warm.suffix_damage.into()),
            ("suffix-tails", warm.suffix_tails.into()),
            ("suffix-dropped", warm.suffix_dropped),
            ("suffix-unread", warm.suffix_unread),
            ("slot-superseded", warm.slot_superseded),
            ("slot-withheld", warm.slot_withheld),
        ];
        let expected: Vec<String> = counts
            .iter()
            .flat_map(|(label, count)| [(*label).to_owned(), count.to_string()])
            .collect();
        assert_eq!(fields[HEAD + PHASE * phases.len()..], expected[..]);
        assert_eq!((warm.installed, warm.omitted), (4, 0));
    });
}

/// A duty that unwinds on the turn whose poll closed the first-safe-hit span ends the tenure `Rerun(Unwound)`, and
/// that turn still writes the line.
#[test]
fn a_turn_that_unwinds_after_closing_the_first_safe_hit_still_writes_the_line() {
    staged(|mut stage| {
        let mut sent = false;
        let served = stage.serve(
            |rounds, _, _| {
                if !sent && rounds.client.borrow().state() == SessionState::Active {
                    rounds.get(1);
                    sent = true;
                }
            },
            |owner, _| assert!(first_hit(owner).is_none(), "a duty that unwinds"),
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert!(served.teardown.is_ok());
        assert_eq!(stage.rounds.lines().len(), 1);
    });
}

/// NoPredecessorEffectAfterFB: a stop request while a GET's read is outstanding at the device ends the serving
/// turns at the turn that read it, with the read still at the device. The close keeps a blocker until the device
/// returns the read; the teardown polls through it and `shutdown` returns the driver only then.
#[test]
fn a_stop_with_a_request_in_flight_shuts_down_only_after_the_blockers_clear() {
    staged(|mut stage| {
        let mut sent = None;
        let mut stopped_at = None;
        let last_duty = Cell::new((0, 0));
        let control = stage.rounds.control.clone();
        let served = stage.serve(
            |rounds, turn, stop| {
                if read_held(rounds, &mut sent) && stopped_at.is_none() {
                    stop.store(true, Ordering::Release);
                    stopped_at = Some(turn);
                }
                // The device answers again three rounds after the stop, during the teardown.
                if stopped_at.is_some_and(|at| turn >= at + 3) {
                    rounds.frozen.set(false);
                }
            },
            |_, now| last_duty.set((now, control.pending())),
        );
        assert_eq!(served.exit, Exit::Stopped);
        let stopped_at = stopped_at.expect("the read was outstanding at the stop");
        let (last, pending) = last_duty.get();
        assert_eq!(
            last,
            stopped_at * ROUND_US,
            "no serving turn followed the stop"
        );
        assert!(
            pending > 0,
            "the read was at the device in the last serving turn"
        );
        if let Err(kept) = served.teardown {
            panic!("shutdown ran with custody outstanding: {:?}", kept.1);
        }
        assert!(
            stage.rounds.turn.get() > stopped_at + 3,
            "the teardown polled while the read blocked it"
        );
        assert_eq!(stage.rounds.control.pending(), 0);
        for _ in 0..8 {
            stage.rounds.round();
        }
        let completed = stage.rounds.fetched(sent.unwrap(), &mut Vec::new());
        assert_ne!(
            completed,
            Some(Fetched::Complete),
            "the owner closed before the device returned the read"
        );
    });
}

/// Sends GET 1 once the session is active, with the device frozen, and reports whether its read is at the device.
pub(crate) fn read_held(rounds: &Rounds<'_>, sent: &mut Option<RequestId>) -> bool {
    if sent.is_none() && rounds.client.borrow().state() == SessionState::Active {
        rounds.frozen.set(true);
        *sent = Some(rounds.get(1));
    }
    sent.is_some() && rounds.control.pending() > 0
}

/// Runs a stop with a GET's read held at the device, as `script` extends it, and returns the kept owner's
/// teardown. `script` takes the rounds and the turns since the stop.
fn stopped_with_a_held_read<'w>(
    stage: &mut Stage<'w>,
    mut script: impl FnMut(&Rounds<'w>, u64),
) -> TestServed<'w> {
    let mut sent = None;
    let mut stopped_at = None;
    let served = stage.serve(
        |rounds, turn, stop| {
            if read_held(rounds, &mut sent) && stopped_at.is_none() {
                stop.store(true, Ordering::Release);
                stopped_at = Some(turn);
            }
            if let Some(at) = stopped_at {
                script(rounds, turn - at);
            }
        },
        idle,
    );
    assert_eq!(served.exit, Exit::Stopped);
    served
}

/// The owner a refused teardown kept, after checking that a live request blocks it.
fn kept<'w>(teardown: TestTeardown<'w>) -> TestOwner<'w> {
    let (owner, blockers) = *teardown.err().expect("the owner kept its custody");
    assert!(blockers.census.live() > 0, "{blockers:?}");
    assert!(!blockers.open, "the owner closed before it drained");
    owner
}

/// A device that never returns the read: the teardown polls for the caller's patience and no longer, `shutdown`
/// refuses with the live request in its blockers, and the owner comes back whole. Once the device answers, a
/// second teardown of that owner drains it and returns the driver.
#[test]
fn a_drain_past_the_callers_patience_returns_the_owner_with_its_blockers() {
    staged(|mut stage| {
        stage.patience = 5 * ROUND_US;
        let last = Cell::new(0);
        let served = stopped_with_a_held_read(&mut stage, |_, since| last.set(since));
        // The close reads the clock at 1, so the polls run at 2 to 6 and the reading at 7 ends them.
        assert_eq!(
            last.get(),
            7,
            "the drain lasted its patience from the close"
        );
        let owner = kept(served.teardown);
        assert_eq!(
            stage.rounds.control.pending(),
            1,
            "the read kept its custody"
        );
        stage.rounds.frozen.set(false);
        stage.patience = u64::MAX;
        assert!(stage.teardown(owner).is_ok());
    });
}

/// A device that returns the read on the last poll the caller's patience admits: the teardown drains and returns
/// the driver.
#[test]
fn a_drain_that_ends_inside_the_callers_patience_returns_the_driver() {
    staged(|mut stage| {
        stage.patience = 5 * ROUND_US;
        let served = stopped_with_a_held_read(&mut stage, |rounds, since| {
            if since == 6 {
                rounds.frozen.set(false);
            }
        });
        assert!(served.teardown.is_ok());
        assert_eq!(stage.rounds.control.pending(), 0);
    });
}

/// A teardown clock read that unwinds while the read still blocks ends the polls, and the owner comes back with
/// the live request.
#[test]
fn a_teardown_clock_that_unwinds_under_a_blocker_returns_the_owner() {
    staged(|mut stage| {
        let served = stopped_with_a_held_read(&mut stage, |_, since| {
            assert!(since < 3, "a clock that unwinds");
        });
        let owner = kept(served.teardown);
        stage.rounds.frozen.set(false);
        assert!(stage.teardown(owner).is_ok());
    });
}

/// A teardown clock read whose unwind payload panics as it drops, the close's read or a poll's, ends the polls
/// with that payload dropped once, and the owner comes back with the live request. An owner whose close never ran
/// comes back open.
#[test]
fn a_teardown_clock_whose_unwind_payload_panics_on_drop_returns_the_owner() {
    // The stop turn is 0, the close's clock call is 1 and the first poll's is 2.
    for unwinds in [1, 2] {
        staged(|mut stage| {
            let dropped = Dropped::default();
            let served = stopped_with_a_held_read(&mut stage, |_, since| {
                if since == unwinds {
                    std::panic::panic_any(Bomb(dropped.clone()));
                }
            });
            let (owner, blockers) = *served.teardown.err().expect("the owner kept its custody");
            assert!(blockers.census.live() > 0, "{blockers:?}");
            assert_eq!(blockers.open, unwinds == 1, "{blockers:?}");
            assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
            stage.rounds.frozen.set(false);
            assert!(stage.teardown(owner).is_ok());
        });
    }
}

/// A teardown poll that unwinds while the read still blocks ends the polls: `shutdown` refuses and returns the
/// owner with the live request. A second teardown drains it once the device answers.
#[test]
fn a_teardown_poll_that_unwinds_under_a_blocker_returns_the_owner() {
    staged(|mut stage| {
        // The stop turn is 0 and the close's clock call is 1, so the driver call armed at 2 is a teardown poll's.
        let served = stopped_with_a_held_read(&mut stage, |rounds, since| {
            if since == 2 {
                rounds.control.unwind_next(Some(Unwind::Pick));
            }
        });
        let owner = kept(served.teardown);
        assert!(owner.poisoned());
        stage.rounds.frozen.set(false);
        assert!(stage.teardown(owner).is_ok());
    });
}

/// A close whose driver call unwinds runs no teardown poll: `shutdown` refuses and returns the owner with the live
/// request. A second teardown drains it once the device answers.
#[test]
fn a_close_that_unwinds_returns_the_owner_without_a_poll() {
    staged(|mut stage| {
        let last = Cell::new(0);
        // The stop turn is 0 and the close's clock call is 1, so the driver call armed at 1 is the close's.
        let served = stopped_with_a_held_read(&mut stage, |rounds, since| {
            last.set(since);
            if since == 1 {
                rounds.control.unwind_next(Some(Unwind::Pick));
            }
        });
        assert_eq!(last.get(), 1, "no poll followed the close");
        let owner = kept(served.teardown);
        stage.rounds.frozen.set(false);
        assert!(stage.teardown(owner).is_ok());
    });
}

/// A serving poll whose driver call unwinds, with a GET's read at the device, ends the tenure `Rerun(Unwound)`.
/// The teardown keeps the read's custody until the device returns it and then returns the driver.
#[test]
fn a_poll_that_unwinds_with_a_read_in_flight_reruns_and_drains() {
    staged(|mut stage| {
        let mut sent = None;
        let mut armed_at = None;
        let served = stage.serve(
            |rounds, turn, _| {
                if read_held(rounds, &mut sent) && armed_at.is_none() {
                    rounds.control.unwind_next(Some(Unwind::Pick));
                    armed_at = Some(turn);
                }
                if armed_at.is_some_and(|at| turn >= at + 3) {
                    rounds.frozen.set(false);
                }
            },
            idle,
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        let armed_at = armed_at.expect("the read was outstanding at the unwind");
        if let Err(kept) = served.teardown {
            panic!("shutdown refused: {:?}", kept.1);
        }
        assert!(stage.rounds.turn.get() > armed_at + 3);
        assert_eq!(stage.rounds.control.pending(), 0);
    });
}

/// ROLE-BOUND: C, the record's standby, takes the volume over and preempts this tenure. The tenure's record view
/// reads C as owner at `E + 1`, the tenure withdraws and ends `Deposed` with no retirement request, and this host's
/// next role read is `Unnamed`.
#[test]
fn a_deposed_tenure_withdraws_closes_and_requests_no_retirement() {
    staged(|mut stage| {
        let store = stage.store.clone();
        let start = stage.rounds.turn.get() * ROUND_US;
        let taken = Cell::new(false);
        let (registry, media) = (stage.registry.clone(), stage.media.clone());
        let served = stage.serve(
            |_, _, _| {},
            |owner, now| {
                if !taken.get() && now >= start + 20 * ROUND_US {
                    take_over(&registry, &media, &store);
                    taken.set(true);
                }
                observe(&store, owner, now);
            },
        );
        assert_eq!(served.exit, Exit::Deposed);
        assert!(stage.rounds.lines().is_empty(), "no GET completed");
        let shutdown = served
            .teardown
            .unwrap_or_else(|kept| panic!("{:?}", kept.1));
        drop(shutdown);
        let record = shard_now(&stage.store);
        assert_eq!((record.owner, record.attempts), (c_host(), 6));
        let holder = crate::failover::fresh::tests::holder();
        let next = crate::host::role(&mut store_client(&stage.store), shard(), &holder);
        assert_eq!(next, Ok(Role::Unnamed));
    });
}

/// A Report that precedes the record view: C's takeover commits and preempts, and the tenure's own Report shows
/// C's recorded pair holding before any view read C as owner. The tenure keeps polling withdrawn until its next
/// view reads C's later tenure and ends `Deposed` with no retirement request. The next incarnation reads the role
/// `Unnamed`, and its recovery waits with no device command.
#[test]
fn a_takeover_the_report_shows_first_ends_deposed_at_the_next_view_and_the_next_role_read_is_unnamed()
 {
    staged(|mut stage| {
        let store = stage.store.clone();
        let (registry, media) = (stage.registry.clone(), stage.media.clone());
        let start = stage.rounds.turn.get() * ROUND_US;
        let taken = Cell::new(false);
        let flip = Cell::new(None);
        let served = stage.serve(
            |_, _, _| {},
            |owner, now| {
                if taken.get() {
                    flip.set(owner.authority_report().flip);
                    if owner.authority_report().withdrawal == Some(Cause::RecordedHolder) {
                        observe(&store, owner, now);
                    }
                } else if now >= start + 20 * ROUND_US {
                    take_over(&registry, &media, &store);
                    taken.set(true);
                } else {
                    observe(&store, owner, now);
                }
            },
        );
        assert_eq!(served.exit, Exit::Deposed);
        assert_eq!(flip.get(), None);
        assert!(served.teardown.is_ok());
        let holder = crate::failover::fresh::tests::holder();
        let next = crate::host::role(&mut store_client(&stage.store), shard(), &holder)
            .expect("the next incarnation's role read");
        assert_eq!(next, Role::Unnamed);
        let before = commands(&stage.registry).len();
        let (disk, control) = host_over(&stage.registry, &stage.media, own());
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        let recovery = recovered(next, &stage.store, disk, &arena, &clock);
        assert!(matches!(recovery, Recovery::Waits));
        assert_eq!(commands(&stage.registry).len(), before);
        assert_eq!(control.driver_calls(), 0);
    });
}

/// NoEpochReuse: a controller event leaves the driver refusing every submit, so the volume loses its device at
/// the tenure's next Report and the tenure ends `Rerun(ControllerEvent)`. The next incarnation runs the restart
/// from its step 1 and bumps to the next `E`.
#[test]
fn a_controller_event_reruns_and_the_next_incarnation_restarts_from_step_one() {
    staged(|mut stage| {
        let registry = stage.registry.clone();
        let start = stage.rounds.turn.get();
        let served = stage.serve(
            |rounds, turn, _| {
                if turn == start + 20 {
                    rounds.control.set_gone();
                    registry.borrow_mut().refuse = Some(crate::storage::RefusalReason::DeviceGone);
                }
            },
            idle,
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::ControllerEvent));
        assert!(served.teardown.is_ok(), "the lost volume still tears down");
        stage.registry.borrow_mut().refuse = None;
        let before = commands(&stage.registry).len();
        let (disk, _control) = host_over(&stage.registry, &stage.media, own());
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        let next = tenure(recovered(Role::Restart, &stage.store, disk, &arena, &clock));
        assert_eq!(next.authority.session().target().attempts, 6);
        assert_eq!(
            commands(&stage.registry)[before..],
            ["report", "preempt", "report"]
        );
    });
}

/// C's recorded pair takes the reservation while this host stays registered and the shard record still names this host
/// owner at its tenure: the already-registered branch of the lineage arm. The tenure withdraws under the recorded
/// holder and ends `Rerun(RecordedHolder)`, and the next incarnation's restart runs from step 1, meets the holder at
/// its Report #1, bumps `E` and preempts C's key through its lineage arm, and holds a tenure at the next `E` with the
/// own pair as the one holder.
#[test]
fn a_tenure_withdrawn_under_a_recorded_holder_reruns_through_the_restart() {
    staged(|mut stage| {
        let registry = stage.registry.clone();
        let store = stage.store.clone();
        let start = stage.rounds.turn.get() * ROUND_US;
        let mut landed = false;
        let lane = crate::host::Lane::inline(store_client(&store), stage.storage);
        let mut duties = crate::host::Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            lane,
            crate::host::duties::tests::records(),
            None,
            crate::host::lane::tests::bounds(),
            crate::host::duties::tests::periods(),
        );
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !landed && now >= start + 20 * ROUND_US {
                    registry.borrow_mut().entries =
                        vec![registrant(own(), 1, false), registrant(c_pair(), 2, true)];
                    landed = true;
                }
                duties.turn(owner, now)
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::RecordedHolder));
        assert!(served.teardown.is_ok());
        assert_eq!(
            shard_now(&stage.store).attempts,
            5,
            "the record names this tenure"
        );
        let before = commands(&stage.registry).len();
        let (disk, _control) = host_over(&stage.registry, &stage.media, own());
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        let next = tenure(recovered(Role::Restart, &stage.store, disk, &arena, &clock));
        assert_eq!(next.authority.session().target().attempts, 6);
        assert_eq!(
            commands(&stage.registry)[before..],
            ["report", "lineage", "report"]
        );
        let holders: Vec<_> = (stage.registry.borrow().entries.iter())
            .filter(|entry| entry.holder)
            .map(|entry| entry.pair)
            .collect();
        assert_eq!(holders, [own()]);
    });
}

/// Composed over the production restart, fencer, duties and owner: a stale Preempt-and-Abort naming this host's key
/// leaves C's recorded pair the one holder and this host unregistered, while the record still names this host owner
/// at `E = 5`. The serving tenure withdraws for the recorded holder, the process ends `Rerun(RecordedHolder)`, and the
/// next incarnation's same-host restart bumps to `E = 6`, registers its own pair, preempts C's key through its lineage
/// arm, comes up `Live` over the same volume and serves every object
/// of the retained set with its retained bytes.
#[test]
fn a_stale_preempt_on_a_serving_tenure_reruns_through_the_lineage_arm_and_serves_the_retained_set()
{
    let (volume, registry) = staged(|mut stage| {
        let registry = stage.registry.clone();
        let store = stage.store.clone();
        let start = stage.rounds.turn.get() * ROUND_US;
        let mut landed = false;
        let lane = crate::host::Lane::inline(store_client(&store), stage.storage);
        let mut duties = crate::host::Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            lane,
            crate::host::duties::tests::records(),
            None,
            crate::host::lane::tests::bounds(),
            crate::host::duties::tests::periods(),
        );
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !landed && now >= start + 20 * ROUND_US {
                    registry.borrow_mut().entries = vec![registrant(c_pair(), 2, true)];
                    landed = true;
                }
                duties.turn(owner, now)
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::RecordedHolder));
        assert!(served.teardown.is_ok());
        (
            (stage.store.clone(), stage.media.clone()),
            stage.registry.clone(),
        )
    });
    let before = commands(&registry).len();
    let keys = [1, 2, 3, 4];
    let (exit, done, attempts) = staged_over_on(
        volume,
        registry.clone(),
        || storage(1),
        |mut stage| {
            let attempts = shard_now(&stage.store).attempts;
            let mut gets: Vec<(u8, RequestId, Vec<u8>)> = Vec::new();
            let mut done = Vec::new();
            let served = stage.serve(
                |rounds, _, stop| {
                    let active = rounds.client.borrow().state() == SessionState::Active;
                    if active && gets.len() == done.len() && done.len() < keys.len() {
                        let n = keys[done.len()];
                        gets.push((n, rounds.get(n), Vec::new()));
                    }
                    if let Some((n, id, bytes)) = gets.get_mut(done.len())
                        && let Some(outcome) = rounds.fetched(*id, bytes)
                    {
                        done.push((*n, outcome, std::mem::take(bytes)));
                    }
                    if done.len() == keys.len() {
                        stop.store(true, Ordering::Release);
                    }
                },
                idle,
            );
            (served.exit, done, attempts)
        },
    );
    assert_eq!(attempts, 6, "the arm's own bump activated the tenure");
    assert_eq!(
        commands(&registry)[before..before + 4],
        ["report", "register", "lineage", "report"]
    );
    assert_eq!(exit, Exit::Stopped);
    let expected: Vec<_> = (keys.iter())
        .map(|&n| {
            (
                n,
                Fetched::Complete,
                crate::host::duties::capture_tests::replaced(n),
            )
        })
        .collect();
    assert_eq!(done, expected);
}

/// Clears every holder bit on `registry` at round `at`, and records in `cause` the withdrawal a duty sees.
fn unheld_at<'c>(
    registry: &'c Control,
    at: u64,
    cause: &'c Cell<Option<Cause>>,
) -> (impl FnMut(u64) + 'c, impl FnMut(&mut TestOwner<'_>) + 'c) {
    (
        move |turn| {
            if turn == at {
                for entry in &mut registry.borrow_mut().entries {
                    entry.holder = false;
                }
            }
        },
        move |owner| {
            let authority = owner.authority_report();
            if authority.state == State::Withdrawn {
                cause.set(authority.withdrawal);
            }
        },
    )
}

/// NO-HOLDER-HOLD: a Report with nobody holding withdraws the tenure with `Cause::Unheld`, and the tenure stays
/// withdrawn and polling, with no exit, until a stop request ends it.
#[test]
fn a_tenure_withdrawn_with_nobody_holding_keeps_polling() {
    staged(|mut stage| {
        let registry = stage.registry.clone();
        let cause = Cell::new(None);
        let (mut clear, mut watch) = unheld_at(&registry, stage.rounds.turn.get() + 20, &cause);
        let mut withdrawn_at = None;
        let served = stage.serve(
            |_, turn, stop| {
                clear(turn);
                if cause.get().is_some() && withdrawn_at.is_none() {
                    withdrawn_at = Some(turn);
                }
                if withdrawn_at.is_some_and(|at| turn >= at + 50) {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, _| watch(owner),
        );
        assert_eq!(cause.get(), Some(Cause::Unheld));
        assert_eq!(
            served.exit,
            Exit::Stopped,
            "50 withdrawn rounds raised no exit"
        );
        assert!(served.teardown.is_ok());
    });
}

/// ROLE-BOUND: a tenure already withdrawn with nobody holding keeps `Cause::Unheld` as its cause. Once its record
/// view reads a successor's takeover write, it ends `Deposed` with no retirement request and no stop.
#[test]
fn a_tenure_withdrawn_with_nobody_holding_ends_deposed_once_it_reads_a_successor() {
    staged(|mut stage| {
        let registry = stage.registry.clone();
        let store = stage.store.clone();
        let cause = Cell::new(None);
        let (mut clear, mut watch) = unheld_at(&registry, stage.rounds.turn.get() + 20, &cause);
        let mut withdrawn_at = None;
        let flip = Cell::new(None);
        let served = stage.serve(
            |_, turn, _| {
                clear(turn);
                if cause.get().is_some() && withdrawn_at.is_none() {
                    withdrawn_at = Some(turn);
                }
                if withdrawn_at.is_some_and(|at| turn == at + 10) {
                    rewrite(&store, |record| ShardRecord {
                        owner: c_host(),
                        attempts: record.attempts + 1,
                        standby: None,
                        ..record
                    });
                }
            },
            |owner, now| {
                observe(&store, owner, now);
                watch(owner);
                flip.set(owner.authority_report().flip);
            },
        );
        assert_eq!(
            cause.get(),
            Some(Cause::Unheld),
            "the machine keeps its first cause"
        );
        assert_eq!(served.exit, Exit::Deposed);
        assert_eq!(flip.get(), None);
        assert!(served.teardown.is_ok());
    });
}

/// A duty that unwinds ends the tenure `Rerun(Unwound)`, and the teardown still closes the owner and returns its
/// driver.
#[test]
fn a_duty_that_unwinds_reruns_and_still_tears_down() {
    staged(|mut stage| {
        let start = stage.rounds.turn.get() * ROUND_US;
        let served = stage.serve(
            |_, _, _| {},
            |_, now| assert!(now < start + 5 * ROUND_US, "a duty that unwinds"),
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert!(served.teardown.is_ok());
    });
}

/// A duty whose unwind payload panics as it drops ends the tenure `Rerun(Unwound)` with that payload dropped once,
/// and the teardown still closes the owner and returns its driver.
#[test]
fn a_duty_whose_unwind_payload_panics_on_drop_reruns_and_still_tears_down() {
    staged(|mut stage| {
        let dropped = Dropped::default();
        let start = stage.rounds.turn.get() * ROUND_US;
        let served = stage.serve(
            |_, _, _| {},
            |_, now| {
                if now >= start + 5 * ROUND_US {
                    std::panic::panic_any(Bomb(dropped.clone()));
                }
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert!(served.teardown.is_ok());
        assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
    });
}

/// A duty unwinds on the turn whose poll closed the first-safe-hit span, and the line's write then unwinds with a
/// payload that panics as it drops: the tenure ends `Rerun(Unwound)` after that one attempt, and the teardown
/// still returns the driver.
#[test]
fn a_reading_whose_unwind_payload_panics_on_drop_reruns_and_still_tears_down() {
    staged(|mut stage| {
        stage.rounds.sink.set(Answer::Bomb);
        let mut sent = false;
        let served = stage.serve(
            |rounds, _, _| {
                if !sent && rounds.client.borrow().state() == SessionState::Active {
                    rounds.get(1);
                    sent = true;
                }
            },
            |owner, _| assert!(first_hit(owner).is_none(), "a duty that unwinds"),
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert!(served.teardown.is_ok());
        assert_eq!(stage.rounds.writes.get(), 1);
        assert_eq!(*stage.rounds.dropped.lock().unwrap(), ["bomb"]);
    });
}

/// ONE-EXIT: a turn that shows an exit ends the tenure with that exit when the same turn reads the stop flag set,
/// so a withdrawal's rerun is not lost behind `Stopped`.
#[test]
fn a_turn_that_shows_an_exit_ends_with_it_when_the_stop_flag_is_set() {
    staged(|mut stage| {
        let withdraws = stage.rounds.turn.get() + 5;
        let served = stage.serve(
            |_, turn, stop| {
                if turn == withdraws {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                if now == withdraws * ROUND_US {
                    owner.authority_event(Event::Withdraw(Cause::Regression), now);
                }
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
        assert!(served.teardown.is_ok());
    });
}

/// The exit `ended` names for a `Live` owner after `events` reached its authority, with the owner torn down.
fn mapped(events: &[Event]) -> Option<Exit> {
    staged(|mut stage| {
        let mut owner = stage.owner.take().unwrap();
        let now = stage.rounds.round();
        for event in events {
            owner.authority_event(*event, now);
        }
        let exit = super::ended(&owner);
        assert!(stage.teardown(owner).is_ok());
        exit
    })
}

/// The exit mapping of `ended`, one row per withdrawal cause class and per closed authority. The retirement rows
/// carry the tenure's own `(g, owner, E)`.
#[test]
fn each_withdrawal_maps_to_its_exit() {
    use Event::{Close, Withdraw};
    let target = staged(|stage| Target::of(&shard_now(&stage.store)));
    let retire = Some(Exit::Retire(target));
    let rerun = Some(Exit::Rerun(Rerun::Withdrawn));
    let planned = Some(Exit::Rerun(Rerun::Planned));
    let deposed = Some(Exit::Deposed);
    let fenced = |fence| Cause::NewerFence { page: 0, fence };
    // A page fence names a later tenure only when it is an activated session: a generation that is nonzero and
    // below `u32::MAX`, with an even, nonzero epoch of at most `ActivatedEpoch::MAX`. Odd epochs identify
    // candidates; epoch zero identifies an unactivated tenure.
    let newer = fenced(session_of(9, 2));
    let candidate = fenced(u64::MAX);
    let unactivated = fenced(session_of(9, 0));
    let held = Some(Exit::Rerun(Rerun::RecordedHolder));
    let rows: [(&[Event], Option<Exit>); 47] = [
        (&[], None),
        // A planned exit requests no flip, so its tenure reruns `Planned` and the next tenure takes over the same
        // volume.
        (&[Withdraw(Cause::Planned)], planned.clone()),
        (&[Withdraw(Cause::ForceDetach)], retire.clone()),
        (&[Withdraw(Cause::Flipped)], deposed.clone()),
        (&[Withdraw(newer)], deposed.clone()),
        (&[Withdraw(candidate)], rerun.clone()),
        (&[Withdraw(unactivated)], rerun.clone()),
        (&[Withdraw(fenced(session_of(9, 3)))], rerun.clone()),
        (&[Withdraw(fenced(session_of(0, 2)))], rerun.clone()),
        (&[Withdraw(fenced(session_of(u32::MAX, 2)))], rerun.clone()),
        (
            &[Withdraw(fenced(session_of(9, ActivatedEpoch::MAX + 2)))],
            rerun.clone(),
        ),
        (&[Withdraw(candidate), Close], rerun.clone()),
        // A fence that is no activated session hides no later tenure a second cause names, on either side of a
        // close.
        (
            &[Withdraw(candidate), Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        (
            &[Withdraw(candidate), Withdraw(Cause::LaterTenure)],
            deposed.clone(),
        ),
        (&[Withdraw(unactivated), Withdraw(newer)], deposed.clone()),
        (
            &[Withdraw(candidate), Close, Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        (
            &[Withdraw(Cause::Flipped), Withdraw(candidate)],
            deposed.clone(),
        ),
        // Such a fence after another cause names no tenure either: the first cause keeps its row, and a flip
        // request it made stands.
        (
            &[Withdraw(Cause::ForceDetach), Withdraw(candidate)],
            retire.clone(),
        ),
        (
            &[Withdraw(Cause::ForceDetach), Withdraw(unactivated)],
            retire.clone(),
        ),
        (
            &[Withdraw(Cause::Planned), Withdraw(candidate)],
            planned.clone(),
        ),
        (
            &[Withdraw(Cause::ForceDetach), Withdraw(candidate), Close],
            retire.clone(),
        ),
        (
            &[Withdraw(Cause::ForceDetach), Withdraw(newer)],
            deposed.clone(),
        ),
        (
            &[Withdraw(Cause::RecordedHolder), Withdraw(candidate)],
            None,
        ),
        (&[Withdraw(Cause::Unheld), Withdraw(candidate)], None),
        (&[Close, Withdraw(candidate)], rerun.clone()),
        (&[Close, Withdraw(newer)], deposed.clone()),
        // The machine closes its flip on every fence above its session, so a trigger after one requests nothing.
        (
            &[Withdraw(candidate), Withdraw(Cause::ForceDetach)],
            rerun.clone(),
        ),
        (&[Withdraw(Cause::LaterTenure)], deposed.clone()),
        (
            &[Withdraw(Cause::Status(Deposing::Conflict))],
            rerun.clone(),
        ),
        (
            &[Withdraw(Cause::Status(Deposing::PreemptAborted))],
            rerun.clone(),
        ),
        (&[Withdraw(Cause::RecordedHolder)], None),
        (&[Withdraw(Cause::Unheld)], None),
        (&[Withdraw(Cause::Regression)], rerun.clone()),
        (&[Withdraw(Cause::ActivationRecord)], rerun.clone()),
        // A successor read after a flip request or a recorded holder ends `Deposed`: the tenure requests nothing.
        (
            &[Withdraw(Cause::ForceDetach), Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        (
            &[Withdraw(Cause::Planned), Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        (
            &[Withdraw(Cause::RecordedHolder), Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        // A closed authority keeps its cause; closed with none, or with nobody holding, it reruns.
        (&[Withdraw(Cause::ForceDetach), Close], retire),
        (&[Withdraw(Cause::Planned), Close], planned),
        (&[Withdraw(Cause::Unheld), Close], rerun.clone()),
        // LAPSE-UNVERIFIED: open and unverified it keeps polling, closed it reruns, and a successor deposes it.
        (&[Withdraw(Cause::Unverified)], None),
        (&[Withdraw(Cause::Unverified), Close], rerun.clone()),
        (
            &[Withdraw(Cause::Unverified), Withdraw(Cause::Flipped)],
            deposed.clone(),
        ),
        (&[Withdraw(Cause::RecordedHolder), Close], held),
        // A closed authority latches a successor on either side of its close, ahead of the flip it holds.
        (
            &[
                Withdraw(Cause::ForceDetach),
                Withdraw(Cause::Flipped),
                Close,
            ],
            deposed.clone(),
        ),
        (
            &[
                Withdraw(Cause::ForceDetach),
                Close,
                Withdraw(Cause::Flipped),
            ],
            deposed.clone(),
        ),
        (&[Close, Withdraw(Cause::LaterTenure)], deposed),
    ];
    for (events, exit) in rows {
        assert_eq!(mapped(events), exit, "{events:?}");
    }
    assert_eq!(mapped(&[Close]), rerun);
}

/// An owner whose earlier poll unwound outside `serve` enters its serving turn poisoned and ends
/// `Rerun(Poisoned)`.
#[test]
fn an_owner_poisoned_before_its_serving_turn_reruns() {
    staged(|mut stage| {
        let mut owner = stage.owner.take().unwrap();
        stage.rounds.control.unwind_next(Some(Unwind::Pick));
        let now = stage.rounds.round();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.poll(now)));
        assert!(unwound.is_err());
        assert_eq!(super::ended(&owner), Some(Exit::Rerun(Rerun::Poisoned)));
        assert!(stage.teardown(owner).is_ok());
    });
}

/// A record sink that refuses the line takes one write attempt for the tenure: a second completed GET adds none,
/// and the refusal changes neither the exit nor the teardown.
#[test]
fn a_refused_recovery_line_is_attempted_once() {
    staged(|mut stage| {
        stage.rounds.sink.set(Answer::Refuse);
        let mut gets: Vec<RequestId> = Vec::new();
        let mut done = 0;
        let served = stage.serve(
            |rounds, _, stop| {
                let active = rounds.client.borrow().state() == SessionState::Active;
                if active && gets.len() == done && done < 2 {
                    gets.push(rounds.get(1 + done as u8));
                }
                if let Some(id) = gets.get(done)
                    && rounds.fetched(*id, &mut Vec::new()).is_some()
                {
                    done += 1;
                }
                if done == 2 {
                    stop.store(true, Ordering::Release);
                }
            },
            idle,
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(served.teardown.is_ok());
        assert_eq!(stage.rounds.writes.get(), 1, "one attempt, with no retry");
        assert!(stage.rounds.lines().is_empty());
    });
}

/// A record sink that unwinds on the turn that closed the first-safe-hit span ends the tenure `Rerun(Unwound)`,
/// and the teardown still returns the driver.
#[test]
fn a_record_sink_that_unwinds_reruns_and_still_tears_down() {
    staged(|mut stage| {
        stage.rounds.sink.set(Answer::Unwind);
        let mut sent = false;
        let served = stage.serve(
            |rounds, _, _| {
                if !sent && rounds.client.borrow().state() == SessionState::Active {
                    rounds.get(1);
                    sent = true;
                }
            },
            idle,
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert!(served.teardown.is_ok());
        assert_eq!(stage.rounds.writes.get(), 1);
    });
}

/// STATUS-IS-DEPOSITION: a GET's read that completes with a deposing status withdraws the tenure before any Report
/// judges the holder. The tenure ends `Rerun(Withdrawn)` with no flip request and no completed GET, and the
/// teardown returns the driver.
#[test]
fn a_deposing_status_on_a_read_reruns_before_any_report_judges_the_holder() {
    for status in [0x83_u16, 0x1b] {
        staged(|mut stage| {
            let mut sent = None;
            let mut faulted = false;
            let seen = Cell::new((None, None));
            let served = stage.serve(
                |rounds, _, _| {
                    if read_held(rounds, &mut sent) && !faulted {
                        let held = rounds.control.held()[0].token;
                        rounds
                            .control
                            .fault(held, Fault::Status(DeviceStatus::Nvme(status << 1)));
                        rounds.frozen.set(false);
                        faulted = true;
                    }
                },
                |owner, _| {
                    let authority = owner.authority_report();
                    seen.set((authority.withdrawal, authority.flip));
                },
            );
            assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn), "{status:#x}");
            let (cause, flip) = seen.get();
            assert!(matches!(cause, Some(Cause::Status(_))), "{cause:?}");
            assert_eq!(flip, None);
            assert!(served.teardown.is_ok());
            for _ in 0..8 {
                stage.rounds.round();
            }
            let completed = stage.rounds.fetched(sent.unwrap(), &mut Vec::new());
            assert_ne!(completed, Some(Fetched::Complete));
        });
    }
}

/// On a healthy serving turn `ended` reads the authority's state and takes no reading of the serving clock.
#[test]
fn the_exit_reading_of_a_serving_turn_takes_no_clock_reading() {
    staged(|mut stage| {
        let mut owner = stage.owner.take().unwrap();
        owner.poll(stage.rounds.round());
        let before = stage.rounds.clock_reads.get();
        assert_eq!(super::ended(&owner), None);
        assert_eq!(stage.rounds.clock_reads.get(), before);
        assert!(stage.teardown(owner).is_ok());
    });
}

#[test]
fn an_owner_exit_outranks_a_duty_exit_on_the_same_turn() {
    staged(|mut stage| {
        let start = stage.rounds.turn.get() * ROUND_US;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if now < start + 5 * ROUND_US {
                    return None;
                }
                owner.authority_event(Event::Withdraw(Cause::Flipped), now);
                Some(Exit::Rerun(Rerun::Unwound))
            },
        );
        assert_eq!(served.exit, Exit::Deposed);
        assert!(served.teardown.is_ok());
    });
}

#[test]
fn a_duty_exit_on_the_first_safe_hit_still_writes_the_recovery_line() {
    staged(|mut stage| {
        let mut get: Option<(RequestId, Vec<u8>)> = None;
        let (served, record) = stage.serve_until(
            |rounds, _, _| {
                let active = rounds.client.borrow().state() == SessionState::Active;
                if active && get.is_none() {
                    get = Some((rounds.get(1), Vec::new()));
                }
                if let Some((id, bytes)) = get.as_mut() {
                    rounds.fetched(*id, bytes);
                }
            },
            |owner, _| recovery_line(owner).map(|_| Exit::Stopped),
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(served.teardown.is_ok());
        assert_eq!(record.lines().count(), 1, "{record}");
    });
}

#[test]
fn the_exit_reading_of_a_withdrawn_tenure_takes_no_clock_reading() {
    let target = staged(|stage| Target::of(&shard_now(&stage.store)));
    let rows = [
        (Cause::Unheld, None),
        (Cause::ForceDetach, Some(Exit::Retire(target))),
        (Cause::Planned, Some(Exit::Rerun(Rerun::Planned))),
        (Cause::RecordedHolder, None),
        (Cause::Regression, Some(Exit::Rerun(Rerun::Withdrawn))),
    ];
    for (cause, exit) in rows {
        staged(|mut stage| {
            let mut owner = stage.owner.take().unwrap();
            let now = stage.rounds.round();
            owner.authority_event(Event::Withdraw(cause), now);
            let before = stage.rounds.clock_reads.get();
            assert_eq!(super::ended(&owner), exit, "{cause:?}");
            assert_eq!(stage.rounds.clock_reads.get(), before, "{cause:?}");
            assert!(stage.teardown(owner).is_ok());
        });
    }
}
