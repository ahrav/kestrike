//! LAPSE-UNVERIFIED at the host. A tenure whose deferral of an unrecorded, non-holding registrant lapses while its
//! store reads fail withdraws with `Cause::Unverified` and no flip request, and its status shows the `unverified`
//! label. The tenure keeps its periodic Report and its record view, and ends by one of three exits: `Deposed` on a
//! shard read that shows a later tenure, `Retire` with one flip request on a volume-record read that does not enroll
//! a pair a Report inside its window lists, and `Rerun(Withdrawn)` once a shard read naming the tenure meets a volume
//! record that enrolls the pair or a Report that no longer lists it.

use std::cell::Cell;
use std::rc::Rc;

use super::tests::{TEST_VIEW_US, periods, records};
use super::{Duties, Linked};
use crate::failover::evidence::Pair;
use crate::failover::identity::{Exhid, Key as ReservationKey};
use crate::failover::records::{
    AttachmentEvent, ERA, EventKind, Host, Record, RecordedPair, ShardRecord, VolumeRecord,
};
use crate::failover::report::{Phase, RecoveryStatus, VolumeEntry, Withdrawal};
use crate::failover::restart::tests::{shard_now, volume_id};
use crate::failover::retire::Target;
use crate::failover::serving::State;
use crate::failover::takeover::tests::{b_host, b_pair, d_host, instance_of, rewrite};
use crate::host::lane::Lane;
use crate::host::lane::tests::bounds;
use crate::host::link::Link;
use crate::host::serve::loop_tests::{ROUND_US, Stage, staged};
use crate::host::{Exit, HostGate, Rerun};
use crate::storage::gate_fixture::Control;
use crate::storage::lapse_plant::{AGE_AT_THE_POLL, FLIP_AT_LAPSE, IGNORE_REPORTS};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Item, Key, Outcome, Store, Unavailable, Write};
use crate::storage::test_platform::TestPlatform;

/// The deferral window the scenarios lapse, sixty rounds.
const WINDOW: u64 = 6_000;
/// The store outage, three windows long.
const OUTAGE: u64 = 3 * WINDOW;

/// A store over [`Shared`] whose every request takes [`Arm::Unavailable`] while `down` holds: a read returns no
/// value and a write is unknown and does not apply. Writes the test makes on [`Shared`] itself take no arm.
#[derive(Clone)]
struct Outage {
    inner: Shared,
    down: Rc<Cell<bool>>,
}

impl Store for Outage {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if self.down.get() {
            self.inner.schedule(Arm::Unavailable);
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if self.down.get() {
            self.inner.schedule(Arm::Unavailable);
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// A pair no record of the shard names: its own host ID and a key no attach derives.
fn stranger() -> Pair {
    Pair {
        exhid: Exhid::new([0x5e; 16]).unwrap(),
        key: ReservationKey::decode((7 << 32) | 3).unwrap(),
    }
}

/// Adds `pair` to the reservation table as a non-holding registrant.
fn register(registry: &Control, pair: Pair) {
    registry
        .borrow_mut()
        .entries
        .push(crate::failover::fresh::tests::registrant(pair, 30, false));
}

/// Enrolls `pair` for `host` in the stored volume record, with an attach event of `host` that binds its instance,
/// by a raw exact-version write: the reconciler's enrollment ahead of the host's Register (CAS-BEFORE-DEVICE).
fn enroll(store: &Shared, host: Host, pair: Pair) {
    let key = Key::Volume(volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    let seq = record.next;
    record.next += 1;
    record.events.push(AttachmentEvent {
        seq,
        kind: EventKind::Attach,
        host,
        era: ERA,
        instance: Some(instance_of(host)),
    });
    record.pairs.push(RecordedPair {
        host,
        pair,
        attach: seq,
    });
    let write = Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let mut raw = store.clone();
    assert!(matches!(raw.write(&key, &write), Outcome::Committed(_)));
}

/// What one scenario showed.
struct Run {
    exit: Exit,
    /// The tenure's own `(g, owner, E)`, read before the scenario.
    target: Target,
    /// The flip requests the authority made: the turns on which its report went from no flip to one.
    flips: u32,
    /// Whether a flip request stood on a turn of the outage.
    flipped_down: bool,
    /// The published statuses' phases and entries, in order.
    statuses: Vec<(Phase, VolumeEntry)>,
    /// The owner's report entry after the last turn the tenure served.
    last: Option<VolumeEntry>,
    /// The microseconds from the outage's end to the first turn on which a flip request stood.
    flipped_after: Option<u64>,
}

/// Serves the stage's tenure with linked duties over an [`Outage`] store. One hundred rounds after the first turn,
/// `arrive` runs and the outage begins; `before_up` runs ten rounds before the outage ends. The scenario stops the
/// tenure `Stopped` forty view periods after the outage.
fn run<'w>(
    stage: &mut Stage<'w>,
    arrive: impl Fn(&Shared, &Control),
    before_up: impl Fn(&Shared, &Control),
) -> Run {
    run_slow(stage, arrive, before_up, 0)
}

/// [`run`] over a store that, once the outage ends, answers each store-lane job `latency` microseconds after its
/// submit: the job's requests run at the submit and its completion reaches the duties that much later.
fn run_slow<'w>(
    stage: &mut Stage<'w>,
    arrive: impl Fn(&Shared, &Control),
    before_up: impl Fn(&Shared, &Control),
    latency: u64,
) -> Run {
    let down = Rc::new(Cell::new(false));
    let client = Client::open(
        Outage {
            inner: stage.store.clone(),
            down: Rc::clone(&down),
        },
        MemLog::default(),
    )
    .unwrap();
    let link: &'static Link = Box::leak(Box::default());
    let mut duties: Duties<'w, Outage, MemLog, TestPlatform> = Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        None,
        bounds(),
        periods(),
    )
    .linked(Linked {
        link,
        pid: 7,
        status_us: TEST_VIEW_US,
        recovery: Some(RecoveryStatus::NO_ATTEMPT),
    });
    let (store, registry) = (stage.store.clone(), stage.registry.clone());
    let mut run = Run {
        exit: Exit::Stopped,
        target: Target::of(&shard_now(&store)),
        flips: 0,
        flipped_down: false,
        statuses: Vec::new(),
        last: None,
        flipped_after: None,
    };
    let mut held_since = None::<u64>;
    let mut begin = None;
    let (mut flipped, mut arrived, mut readied) = (false, false, false);
    let (served, _) = stage.serve_until(
        |_, _, _| {},
        |owner, now| {
            let begin = *begin.get_or_insert_with(|| {
                owner.set_deferral_window(WINDOW);
                now + 100 * ROUND_US
            });
            let up = begin + OUTAGE;
            if !arrived && now >= begin {
                down.set(true);
                arrive(&store, &registry);
                arrived = true;
            }
            if !readied && now >= up - 10 * ROUND_US {
                before_up(&store, &registry);
                readied = true;
            }
            if down.get() && now >= up {
                down.set(false);
                if latency > 0 {
                    duties.lane.inline_mut().hold();
                }
            }
            if now >= up + 40 * TEST_VIEW_US {
                return Some(Exit::Stopped);
            }
            // The slow store: the oldest held completion lands once `latency` passed since the lane first held it.
            if duties.lane.inline_mut().held() > 0 {
                let since = *held_since.get_or_insert(now);
                if now >= since + latency {
                    duties.lane.inline_mut().release();
                    held_since = None;
                }
            }
            let exit = duties.turn(owner, now);
            let flip = owner.authority_report().flip.is_some();
            if flip && run.flipped_after.is_none() {
                run.flipped_after = Some(now.saturating_sub(up));
            }
            run.flips += u32::from(flip && !flipped);
            run.flipped_down |= flip && down.get();
            flipped = flip;
            if let Some(status) = link.status.take()
                && let Some(entry) = status.entry
            {
                run.statuses.push((status.phase, entry));
            }
            run.last = owner.report_entry(now, &duties.observed());
            exit
        },
    );
    run.exit = served.exit;
    assert!(served.teardown.is_ok());
    run
}

/// Whether a published status showed the tenure withdrawn under the `unverified` label with no flip request.
fn showed_unverified(run: &Run) -> bool {
    run.statuses.iter().any(|(phase, entry)| {
        *phase == Phase::Withdrawn
            && entry.serving == Some(State::Withdrawn)
            && entry.withdrawal == Some(Withdrawal::Unverified)
            && !entry.flip
    })
}

/// B's takeover during the outage, as injected successor state: a raw write names B owner at `E + 1`, a raw write
/// enrolls B's pair, and the pair registers, all while this tenure's store reads fail. The fixture writes the
/// outcomes the takeover's checked writes leave; it does not run the takeover's sequence.
fn take_over(store: &Shared, registry: &Control) {
    rewrite(store, |record| ShardRecord {
        owner: b_host(),
        attempts: record.attempts + 1,
        standby: None,
        ..record
    });
    enroll(store, b_host(), b_pair());
    register(registry, b_pair());
}

/// A takeover during a store outage that outlasts the deferral window, by a successor that registered and had not
/// preempted when the old owner's reads returned: B's takeover write, B's enrollment and B's Register all land while
/// the old owner's reads fail. The old owner's deferral of B's pair lapses, it withdraws with `Cause::Unverified`, its
/// status shows the `unverified` label, and once its reads return the shard read ends it `Deposed` with no flip
/// request. Control: with `FLIP_AT_LAPSE` planted, the lapse requests the flip, and the same schedule parks
/// `Retire` with no status showing the unverified state.
#[test]
fn a_takeover_during_a_store_outage_past_the_window_ends_deposed_with_no_flip() {
    for control in [false, true] {
        FLIP_AT_LAPSE.set(control);
        let run = staged(|mut stage| run(&mut stage, take_over, |_, _| {}));
        FLIP_AT_LAPSE.set(false);
        if control {
            assert!(
                run.flips > 0 && matches!(run.exit, Exit::Retire(_)),
                "control: the lapse's flip fails the no-request check: {:?}",
                run.exit
            );
            assert!(
                !showed_unverified(&run),
                "control: a lapse that requests the flip shows no unverified status"
            );
            continue;
        }
        assert_eq!(run.exit, Exit::Deposed);
        assert_eq!(run.flips, 0, "no flip request");
        assert!(
            showed_unverified(&run),
            "the status shows the unverified state"
        );
        assert!(!run.last.expect("the entry at the exit").flip);
    }
}

/// A persistent foreign non-holding pair at the tenure's unchanged target while the reads fail past the lapse: the
/// tenure withdraws with `Cause::Unverified` and requests no flip while the reads fail. The first view after the
/// outage reads a volume record that does not admit the pair beside a Report inside its window that lists it, and
/// the tenure requests the flip once, at its own target, and parks `Retire`; its entry then shows the Report
/// withdrawal and the flip. The scenario bounds the flip only by its stop, forty view periods after the outage.
/// Control: with `IGNORE_REPORTS` planted, no Report counts after the lapse, and the tenure stays withdrawn with no
/// request until the scenario stops it.
#[test]
fn a_foreign_pair_past_the_lapse_flips_once_after_a_read_recovers() {
    for control in [false, true] {
        IGNORE_REPORTS.set(control);
        let run = staged(|mut stage| {
            run(
                &mut stage,
                |_, registry| register(registry, stranger()),
                |_, _| {},
            )
        });
        IGNORE_REPORTS.set(false);
        assert!(!run.flipped_down, "no flip while the reads fail");
        assert!(
            showed_unverified(&run),
            "the status shows the unverified state"
        );
        if control {
            assert!(
                run.flips == 0 && run.exit == Exit::Stopped,
                "control: no flip after the lapse fails the one-flip check: {:?}",
                run.exit
            );
            continue;
        }
        assert_eq!(run.exit, Exit::Retire(run.target));
        assert_eq!(run.flips, 1, "one flip request stood, once");
        let last = run.last.expect("the entry at the exit");
        assert_eq!(
            (last.withdrawal, last.flip),
            (Some(Withdrawal::Report), true)
        );
    }
}

/// The verified exits: once the reads return, a shard read naming the tenure beside a volume record that enrolls
/// the lapsed pair, or beside a Report that no longer lists it, ends the withdrawn tenure `Rerun(Withdrawn)` with no
/// flip request ("A withdrawn tenure never resumes"). Each showed the `unverified` label while withdrawn.
#[test]
fn a_verified_lapse_reruns_withdrawn_with_no_flip() {
    type Ready = fn(&Shared, &Control);
    let enrolls: Ready = |store, _| enroll(store, d_host(), stranger());
    let leaves: Ready = |_, registry| {
        registry
            .borrow_mut()
            .entries
            .retain(|entry| entry.pair != stranger())
    };
    for (name, before_up) in [("enrolled", enrolls), ("unlisted", leaves)] {
        let run = staged(|mut stage| {
            run(
                &mut stage,
                |_, registry| register(registry, stranger()),
                before_up,
            )
        });
        assert_eq!(run.exit, Exit::Rerun(Rerun::Withdrawn), "{name}");
        assert_eq!(run.flips, 0, "{name}: no flip request");
        assert!(
            showed_unverified(&run),
            "{name}: the status shows the state"
        );
        let last = run.last.expect("the entry at the exit");
        assert_eq!(
            (last.withdrawal, last.flip),
            (Some(Withdrawal::Unverified), false),
            "{name}"
        );
    }
}

/// A successor that preempts during the outage: after B's takeover state lands and the old owner withdraws with
/// `Cause::Unverified`, B's pair takes the reservation while the old owner's reads still fail. The withdrawn
/// authority's next Report shows an unrecorded holder, which keeps its immediate flip: one flip request at the old
/// owner's own `(g, owner, E)`, during the outage, and `Retire`.
#[test]
fn a_successor_that_preempts_during_the_outage_flips_at_once() {
    let preempts = |_: &Shared, registry: &Control| {
        for entry in &mut registry.borrow_mut().entries {
            entry.holder = entry.pair == b_pair();
        }
    };
    let run = staged(|mut stage| run(&mut stage, take_over, preempts));
    assert!(
        showed_unverified(&run),
        "the status shows the unverified state first"
    );
    assert_eq!(run.exit, Exit::Retire(run.target));
    assert_eq!(run.flips, 1);
    assert!(
        run.flipped_down,
        "the Report showing the holder flips during the outage"
    );
}

/// LAPSE-UNVERIFIED under a store slower than a serving window. The persistent foreign pair
/// of [`a_foreign_pair_past_the_lapse_flips_once_after_a_read_recovers`] lapses during the outage. Once the outage
/// ends the store answers each view only after more than one deferral window, so every Report a view carries is
/// older than a window when the duties adopt that view. The view was sent while its Report lay inside its window,
/// and the volume record it read after that Report does not admit the pair, so the first view the slow store
/// answers requests the flip, once, at the tenure's own target: the slow store delays the flip by its latency, by
/// no more than one view period beyond the fast store's flip plus that latency. Control: with `AGE_AT_THE_POLL`
/// planted, the poll measures each Report's age when the view is adopted, every Report reads unread, and the slow
/// store's tenure requests no flip before the scenario stops it, forty view periods after the outage.
#[test]
fn a_store_slower_than_a_window_delays_the_lapse_s_flip_by_its_latency_alone() {
    let latency = WINDOW + 10 * ROUND_US;
    let arrive = |_: &Shared, registry: &Control| register(registry, stranger());
    let fast = staged(|mut stage| run(&mut stage, arrive, |_, _| {}));
    let slow = staged(|mut stage| run_slow(&mut stage, arrive, |_, _| {}, latency));
    for (name, run) in [("fast", &fast), ("slow", &slow)] {
        assert!(!run.flipped_down, "{name}: no flip while the reads fail");
        assert!(
            showed_unverified(run),
            "{name}: the unverified state showed"
        );
        assert_eq!(run.exit, Exit::Retire(run.target), "{name}");
        assert_eq!(run.flips, 1, "{name}: one flip request");
    }
    let (fast, slow) = (fast.flipped_after.unwrap(), slow.flipped_after.unwrap());
    assert!(
        slow >= latency,
        "premise: the slow store's first answer comes a latency after the outage: {slow}"
    );
    assert!(
        slow <= fast + latency + TEST_VIEW_US,
        "the flip waited {slow} us after the outage; the fast store's waited {fast} us and the latency is {latency} us"
    );
    AGE_AT_THE_POLL.set(true);
    let aged = staged(|mut stage| run_slow(&mut stage, arrive, |_, _| {}, latency));
    AGE_AT_THE_POLL.set(false);
    assert!(
        aged.flips == 0 && aged.exit == Exit::Stopped,
        "control: a Report aged at the poll fails the one-flip check: {:?}",
        aged.exit
    );
}

/// B's takeover during the outage through the checked sequence, on a second store client and a fencer over the
/// shared reservation table: the reconciler's enrollment of B's pair and its designation of B are raw writes, as
/// functions outside the cache hosts make them, and `Takeover::run` then commits B's compare-and-swap, takes
/// Report #1, registers B's pair, rereads the shard record and issues its Preempt-and-Abort. With `completions`,
/// the table delivers that many reservation completions to B, so a count of two leaves the preempt pending and the
/// takeover holds after its Register; the pending command ends with a proven stop of B's device. Returns the
/// takeover's refusal, if any, and the reservation commands B issued.
fn checked_takeover(
    store: &Shared,
    registry: &Control,
    completions: Option<usize>,
) -> (Option<crate::failover::takeover::Check>, Vec<&'static str>) {
    use crate::failover::takeover::tests::{designate, stored_b, takeover_of};
    use crate::host::fencer::Release;
    use crate::host::fencer_tests::{commands, fencer_of, host, stop};
    enroll(store, b_host(), b_pair());
    designate(store, Some(b_host()));
    let before = commands(registry).len();
    registry.borrow_mut().budget = completions;
    let (disk, control) = host(registry, b_pair(), 9);
    let arena = crate::storage::gate_fixture::arena_with(16, 9);
    let clock = crate::storage::gate_fixture::Ticking::default();
    let mut fencer = fencer_of(disk, b_pair(), &arena, &clock);
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    let refused = takeover_of(store, b_host())
        .run(&mut client, &stored_b(), &mut fencer)
        .err()
        .map(|refused| refused.check);
    // The proven stop ends the pending command while the table still withholds its completion.
    if let Release::Outstanding(table) = fencer.release() {
        drop(stop(table, &control));
    }
    registry.borrow_mut().budget = None;
    let issued = commands(registry)[before..].to_vec();
    (refused, issued)
}

/// The takeover scenario of [`a_takeover_during_a_store_outage_past_the_window_ends_deposed_with_no_flip`] with
/// the successor's state made by the checked takeover sequence. B's takeover commits its
/// compare-and-swap, registers its pair and stops before its preempt completes, all while the old owner's reads
/// fail: the table then lists B's pair as a registrant that does not hold, beside the old owner's holding pair. The
/// old owner defers B's pair, the deferral lapses, it withdraws `Unverified` with no flip request, and once its
/// reads return the shard record B's own write committed ends it `Deposed`. Control: with `FLIP_AT_LAPSE`
/// planted, the lapse requests the flip against the takeover B committed.
#[test]
fn a_checked_takeover_that_holds_before_its_preempt_ends_the_old_owner_deposed_with_no_flip() {
    use crate::failover::takeover::Check;
    for control in [false, true] {
        let taken = Rc::new(std::cell::RefCell::new(None));
        let result = Rc::clone(&taken);
        let arrive = move |store: &Shared, registry: &Control| {
            *result.borrow_mut() = Some(checked_takeover(store, registry, Some(2)));
        };
        FLIP_AT_LAPSE.set(control);
        let (run, record) = staged(|mut stage| {
            let run = run(&mut stage, arrive, |_, _| {});
            (run, shard_now(&stage.store))
        });
        FLIP_AT_LAPSE.set(false);
        let (refused, issued) = taken.borrow_mut().take().expect("the takeover ran");
        assert!(
            matches!(refused, Some(Check::Preempt(_))),
            "premise: the takeover held at its preempt: {refused:?}"
        );
        assert_eq!(issued, ["report", "register", "lineage"]);
        assert_eq!(
            (record.owner, record.attempts, record.standby),
            (b_host(), run.target.attempts + 1, None),
            "B's own compare-and-swap named it owner"
        );
        if control {
            assert!(
                run.flips > 0 && matches!(run.exit, Exit::Retire(_)),
                "control: the lapse's flip fails the no-request check: {:?}",
                run.exit
            );
            continue;
        }
        assert_eq!(run.exit, Exit::Deposed);
        assert_eq!(run.flips, 0, "no flip request");
        assert!(
            showed_unverified(&run),
            "the status shows the unverified state"
        );
        assert!(!run.last.expect("the entry at the exit").flip);
    }
}
