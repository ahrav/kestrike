//! Tests the supersession of a replacement receipt under concurrent reconcilers: a later replacement's receipt is
//! committed over an earlier receipt only while the shard record names the volume the earlier receipt records, or
//! once that volume's record reads retired. Two reconcilers run against one simulated store, one request of one of
//! them at a time, in every order of their requests: one starts the later receipt, and the other's shard write
//! leaves the recorded volume named in no role.

use super::*;

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use crate::failover::attachments::Mismatch;
use crate::failover::reconcile_tests::replay_driver::{Message, Proxy, Reply};
use crate::failover::records::{ERA, Record};
use crate::failover::retire::Trigger;
use crate::failover::sim::{host, layout};
use crate::storage::store::Outcome;
use crate::storage::store::sim::{AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store_tests::{OWNER, SPARE, record, shard, stored};

/// The host the created volume attaches at.
const THIRD: u64 = 13;

/// The most schedules one order may hold. The two orders hold a few thousand; the cap ends a search that a change
/// of the steps made unbounded.
const SCHEDULES_MAX: usize = 200_000;

/// The shard record a shard is created with: the active volume and no spare.
fn unspared() -> ShardRecord {
    ShardRecord {
        spare: None,
        ..record()
    }
}

/// The long-running reconciler over `store`, as its principal reaches the store.
fn reconciler_over<S: Store>(store: S) -> Reconciler<AsReconciler<S>, MemLog> {
    Reconciler::new(
        Client::open(AsReconciler(store), MemLog::default())
            .expect("the store opens for the reconciler"),
    )
}

/// A provider whose every create returns the one volume.
struct Makes(VolumeId);

impl Provider for Makes {
    fn create(&mut self, _token: &str, _layout: Layout) -> Result<VolumeId, CreateError> {
        Ok(self.0)
    }
}

/// The step one reconciler runs in the race.
#[derive(Clone, Copy)]
enum Step {
    /// `replacement` for the loss of the named active volume.
    Replacement(VolumeId),
    /// `retire_spare` of the named spare under the tenure.
    RetireSpare(VolumeId, Target),
    /// `flip` from the tenure to its spare.
    Flip(Target),
}

/// A reconciler in its own thread, as the scheduler holds it: the request it waits on, when it has one. The
/// reconciler reaches the store through a [`Proxy`]: each request goes to the scheduler, which holds the one
/// simulated store, and the call returns the scheduler's answer. The reconciler therefore issues its next request
/// only after the scheduler answered the one before, and the scheduler decides which reconciler's request the store
/// receives next.
struct Worker {
    calls: Receiver<Message>,
    /// `None` once the reconciler is stopped.
    replies: Option<Sender<Reply>>,
    pending: Option<Message>,
    thread: JoinHandle<bool>,
}

impl Worker {
    /// Starts a reconciler that runs `step` and returns whether the step returned `Ok`.
    fn start(step: Step) -> Self {
        let (calls, taken) = channel();
        let (replies, answered) = channel();
        let thread = std::thread::spawn(move || {
            let mut reconciler = reconciler_over(Proxy::new(calls, answered));
            match step {
                Step::Replacement(lost) => reconciler
                    .replacement(
                        &StandbyGate::qualified(),
                        shard(),
                        (lost, Health::Lost),
                        0,
                        layout(),
                    )
                    .is_ok(),
                Step::RetireSpare(volume, tenure) => {
                    let request = Retirement::new(
                        volume,
                        Role::Spare,
                        tenure,
                        Trigger::Attachment(Mismatch::Duplicate),
                    )
                    .expect("the request names a spare's removal");
                    reconciler.retire_spare(shard(), &request).is_ok()
                }
                Step::Flip(tenure) => reconciler
                    .flip(&StandbyGate::qualified(), shard(), tenure)
                    .is_ok(),
            }
        });
        let mut worker = Self {
            calls: taken,
            replies: Some(replies),
            pending: None,
            thread,
        };
        worker.wait();
        worker
    }

    /// Waits for the reconciler's next request. The channel closes when its step returned, which leaves none.
    fn wait(&mut self) {
        self.pending = self.calls.recv().ok();
    }

    /// Applies the pending request to `store`, answers it and waits for the next one. Returns whether the request
    /// was a write of the replacement receipt that the store committed.
    fn serve(&mut self, store: &mut Shared) -> bool {
        let call = self
            .pending
            .take()
            .expect("the reconciler waits on a request");
        let (reply, receipt) = match call {
            Message::Read(key) => (Reply::Read(store.read(&key)), false),
            Message::Write(key, write) => {
                let outcome = store.write(&key, &write);
                let committed = matches!(outcome, Outcome::Committed(_));
                (
                    Reply::Write(outcome),
                    committed && key == Key::Replacement(shard()),
                )
            }
            // A step reports its result through its thread and calls no provider, so its channel carries store
            // requests alone.
            Message::Call(..) | Message::Done(_) => {
                unreachable!("a reconciler's step sends store requests only")
            }
        };
        self.replies
            .as_ref()
            .expect("a reconciler with a pending request is not stopped")
            .send(reply)
            .expect("the reconciler takes the answer");
        self.wait();
        receipt
    }

    /// Stops the reconciler: the store receives none of its requests from here on. With the reply sender dropped,
    /// the proxy answers a read as unavailable and a write's outcome as unknown, as for a process whose requests no
    /// longer reach the store. The request channel closes when the step returned, so the scheduler picks again only
    /// after that.
    fn stop(&mut self) {
        self.pending = None;
        self.replies = None;
        while self.calls.recv().is_ok() {}
    }

    /// Whether the step returned `Ok`, after its last request.
    fn returned(self) -> bool {
        self.thread.join().expect("the reconciler's step returns")
    }
}

/// The steps before a race, and what the race judges.
struct Staged {
    store: Shared,
    /// The replacement the earlier receipt names; that receipt records `made`.
    earlier: Request,
    /// The volume the earlier receipt's create returned.
    made: VolumeId,
    /// The active volume whose loss the later replacement reports.
    lost: VolumeId,
    /// The step of the reconciler whose shard write leaves `made` named in no role.
    unnaming: Step,
}

/// The order in which the earlier receipt's volume leaves the shard record.
#[derive(Clone, Copy, Debug)]
enum Order {
    /// The created volume is the spare, and `retire_spare` removes it before it writes the retired state.
    Retirement,
    /// The created volume is active, and a flip to another spare displaces it.
    Flip,
}

/// The steps both orders share: the shard's active volume is lost, and a reconciler starts the receipt of generation
/// `g + 1`, creates its volume and records it in the receipt.
///
/// `Order::Retirement`: before the loss the shard names a second volume spare. After the create the shard flips to
/// that spare, so the shard record holds `g + 1` under a volume the receipt did not make, and the created volume is
/// attached and named the spare of the new tenure. In the race the second volume is lost and one reconciler runs
/// `replacement` for it, while another runs `retire_spare` on the created volume.
///
/// `Order::Flip`: the created volume is attached, named spare and flipped to, so it is the active volume, and a
/// second volume is named the spare of its tenure. In the race the created volume is lost and one reconciler runs
/// `replacement` for it, while another flips the shard to the second volume.
fn stage(order: Order) -> Staged {
    let second = VolumeId::new("vol-0b").expect("the name is a volume id");
    let made = VolumeId::new("vol-0c").expect("the name is a volume id");
    let gate = StandbyGate::qualified();
    let store = Shared::new();
    Reconciler::new(
        Client::open(AsProvisioner(store.clone()), MemLog::default())
            .expect("the store opens for the provisioner"),
    )
    .create_shard(unspared())
    .expect("the shard is created");
    let mut first = reconciler_over(store.clone());
    first
        .provision(record().active, layout())
        .expect("the active volume is provisioned");
    first
        .record_attach(record().active, host(OWNER), ERA)
        .expect("the active volume's attach is recorded");
    first
        .provision(second, layout())
        .expect("the second volume is provisioned");
    let second_attached = first
        .record_attach(second, host(SPARE), ERA)
        .expect("the second volume's attach is recorded");
    if matches!(order, Order::Retirement) {
        first
            .add_spare(shard(), Target::of(&unspared()), &second_attached)
            .expect("the second volume is named spare");
    }
    let earlier = first
        .replacement(&gate, shard(), (record().active, Health::Lost), 0, layout())
        .expect("the loss of the active volume starts a receipt")
        .expect("the decision provisions")
        .value()
        .request;
    let created = first
        .create_replacement(&gate, shard(), 0, &mut Makes(made))
        .expect("the create records its volume");
    assert_eq!(created.value().volume, made);
    let (lost, unnaming) = match order {
        Order::Retirement => {
            first
                .flip(&gate, shard(), Target::of(&unspared()))
                .expect("the shard flips to the second volume");
            let tenure = Target::of(&stored(&store).1);
            let attached = first
                .record_attach(made, host(THIRD), ERA)
                .expect("the created volume's attach is recorded");
            first
                .add_spare(shard(), tenure, &attached)
                .expect("the created volume is named the spare of the new tenure");
            (second, Step::RetireSpare(made, tenure))
        }
        Order::Flip => {
            let attached = first
                .record_attach(made, host(THIRD), ERA)
                .expect("the created volume's attach is recorded");
            first
                .add_spare(shard(), Target::of(&unspared()), &attached)
                .expect("the created volume is named spare");
            first
                .flip(&gate, shard(), Target::of(&unspared()))
                .expect("the shard flips to the created volume");
            let tenure = Target::of(&stored(&store).1);
            first
                .add_spare(shard(), tenure, &second_attached)
                .expect("the second volume is named the spare of the created volume's tenure");
            (made, Step::Flip(tenure))
        }
    };
    assert_eq!(
        (
            named(&stored(&store).1, made),
            receipt(&store).phase,
            receipt(&store).request
        ),
        (true, Phase::Created(made), earlier),
        "before the race the shard record names the created volume and the earlier receipt records it"
    );
    Staged {
        store,
        earlier,
        made,
        lost,
        unnaming,
    }
}

/// The replacement receipt the store holds.
fn receipt(store: &Shared) -> Receipt {
    let sim = store.0.borrow();
    let item = sim
        .current(&Key::Replacement(shard()))
        .expect("the store holds the receipt");
    Receipt::decode(&item.value).expect("the receipt decodes")
}

/// The state the record of `volume` holds in the store.
fn state(store: &Shared, volume: VolumeId) -> VolumeState {
    let sim = store.0.borrow();
    let item = sim
        .current(&Key::Volume(volume))
        .expect("the store holds the volume's record");
    VolumeRecord::decode(&item.value)
        .expect("the record decodes")
        .state
}

/// Whether the shard record names `volume` in no role while its record is short of retired.
fn loose(store: &Shared, volume: VolumeId) -> bool {
    !named(&stored(store).1, volume) && state(store, volume) < VolumeState::Retired
}

/// What one schedule of a race showed.
struct Raced {
    /// The requests the store received, in order: `L` for the reconciler that starts the later receipt, `U` for the
    /// one whose shard write un-names the created volume, and `stop` where that one stopped.
    schedule: String,
    /// Whether a write committed a receipt of a later replacement over the earlier receipt and, when one did, the
    /// state of the created volume's record at that commit when the shard record then named the volume in no role
    /// and the record was short of retired.
    superseded: bool,
    broken: Option<VolumeState>,
    /// Whether the created volume was, after some request, named in no role and short of retired while the earlier
    /// receipt still stood.
    window: bool,
    /// Whether the un-naming reconciler's step returned `Ok`.
    whole: bool,
}

/// Runs one schedule of the race of `order`. Each time a request waits, the schedule picks among the choices open
/// then, in this order: the store receives the later reconciler's request; the store receives the un-naming
/// reconciler's request; the un-naming reconciler stops. `path` holds the picks made so far with the count of
/// choices each had; picks beyond it take the first choice and are appended.
fn race(order: Order, path: &mut Vec<(usize, usize)>) -> Raced {
    let Staged {
        mut store,
        earlier,
        made,
        lost,
        unnaming,
    } = stage(order);
    let mut later = Worker::start(Step::Replacement(lost));
    let mut unnaming = Worker::start(unnaming);
    let mut raced = Raced {
        schedule: String::new(),
        superseded: false,
        broken: None,
        window: false,
        whole: false,
    };
    let mut at = 0;
    loop {
        let mut choices = Vec::new();
        if later.pending.is_some() {
            choices.push('L');
        }
        if unnaming.pending.is_some() {
            choices.push('U');
            choices.push('s');
        }
        if choices.is_empty() {
            break;
        }
        if at == path.len() {
            path.push((0, choices.len()));
        }
        let pick = choices[path[at].0];
        at += 1;
        let receipt_write = match pick {
            'L' => {
                raced.schedule.push('L');
                later.serve(&mut store)
            }
            'U' => {
                raced.schedule.push('U');
                unnaming.serve(&mut store)
            }
            _ => {
                raced.schedule.push_str(" stop ");
                unnaming.stop();
                false
            }
        };
        if receipt_write && !raced.superseded && receipt(&store).request != earlier {
            raced.superseded = true;
            raced.broken = loose(&store, made).then(|| state(&store, made));
        }
        raced.window |= !raced.superseded && loose(&store, made);
    }
    let _ = later.returned();
    raced.whole = unnaming.returned();
    if matches!(order, Order::Retirement) && raced.whole {
        assert_eq!(
            (named(&stored(&store).1, made), state(&store, made)),
            (false, VolumeState::Retired),
            "a whole retirement leaves the created volume unnamed and retired"
        );
        // The later receipt starts once the volume is retired: in the race, or when the step is run again.
        let again = reconciler_over(store.clone()).replacement(
            &StandbyGate::qualified(),
            shard(),
            (lost, Health::Lost),
            0,
            layout(),
        );
        assert!(
            again.is_ok() && receipt(&store).request != earlier,
            "after the created volume is retired, the replacement step starts the later receipt: {again:?} \
             (schedule {})",
            raced.schedule
        );
    }
    raced
}

/// What every schedule of one order showed.
struct Explored {
    schedules: usize,
    /// The schedules in which the later receipt was committed while the created volume was named in no role and
    /// short of retired, and the first of them with the state the volume's record held.
    broken: usize,
    first: Option<(String, VolumeState)>,
    /// The schedules that reached the state the clause is about while the earlier receipt stood.
    window: usize,
    /// Whether the later receipt started when the un-naming reconciler stopped before its first request.
    alone: bool,
}

/// Runs every schedule of the race of `order`, depth first over the picks.
fn explore(order: Order) -> Explored {
    let mut explored = Explored {
        schedules: 0,
        broken: 0,
        first: None,
        window: 0,
        alone: false,
    };
    let mut path = Vec::new();
    loop {
        let raced = race(order, &mut path);
        explored.schedules += 1;
        assert!(
            explored.schedules <= SCHEDULES_MAX,
            "the race of {order:?} holds at most {SCHEDULES_MAX} schedules"
        );
        if let Some(state) = raced.broken {
            explored.broken += 1;
            explored
                .first
                .get_or_insert((raced.schedule.clone(), state));
        }
        explored.window += usize::from(raced.window);
        if raced.schedule.starts_with(" stop ") {
            explored.alone = raced.superseded;
        }
        // The next schedule: the last pick that has a later choice takes it, and the picks after it are dropped.
        while let Some((pick, choices)) = path.pop() {
            if pick + 1 < choices {
                path.push((pick + 1, choices));
                break;
            }
        }
        if path.is_empty() {
            return explored;
        }
    }
}

/// IDEMPOTENT-PROVISIONING: a receipt of an earlier generation recording a volume the shard names in no role is
/// superseded only after that volume is retired.
/// The clause is judged at the commit of the receipt write that supersedes: the shard record then names the recorded
/// volume, or the volume's record reads retired. Two reconcilers run, one request of one of them at a time, in every
/// order of their requests, and the one whose shard write un-names the recorded volume may stop before any of its
/// requests. The un-naming is the removal of a spare by `retire_spare`, which precedes its retired-state write, or
/// a flip that displaces the active volume.
#[test]
fn a_receipt_recording_an_unnamed_volume_is_superseded_only_after_the_volume_is_retired() {
    let retirement = explore(Order::Retirement);
    let flip = explore(Order::Flip);
    for (order, explored) in [("retirement", &retirement), ("flip", &flip)] {
        assert!(
            explored.alone,
            "with the other reconciler stopped before its first request, the replacement step starts the later \
             receipt while the shard record names the recorded volume ({order} order)"
        );
        assert!(
            explored.window > 0,
            "some schedule leaves the recorded volume named in no role and short of retired while the earlier \
             receipt stands ({order} order, {} schedules)",
            explored.schedules
        );
    }
    assert!(
        retirement.broken == 0 && flip.broken == 0,
        "a later replacement's receipt was committed over the earlier receipt while the shard record named its \
         recorded volume in no role and that volume's record was short of retired: retirement order {} of {} \
         schedules, first {:?}; flip order {} of {} schedules, first {:?}",
        retirement.broken,
        retirement.schedules,
        retirement.first,
        flip.broken,
        flip.schedules,
        flip.first
    );
}
