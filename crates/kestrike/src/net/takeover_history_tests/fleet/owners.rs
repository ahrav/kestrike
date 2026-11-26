//! Each per-shard owner incarnation reads its role with `host::survey` and runs `host::recover` through a
//! `host::Fencer` over its host's `Reserving` device double on the shard's media. The fencer and every host's device
//! double of one volume share the cell's reservation table (`World::reservation`), so a fencer's commands and a
//! tenure's Reports read one table. `host::serve::start_up_with_nonce`, the steps of `start_up` under the boot nonce
//! the fleet scripts from the cell's count of tenures served, starts the tenure `recover` returns, and each of its
//! owner turns in the round loop is one `host::serve::turn_up` until the bring-up reads `Live` or ends short of it.
//! A blank volume's format ID is the one `turn_up` draws from the operating system. Bring-ups run one at a time: the
//! fleet steps a rising owner's turns to the end of its bring-up before it starts the next recovery, and the host's
//! other tenures serve in those rounds.

use std::cell::{Cell as Slot, RefCell};
use std::rc::Rc;

use crate::failover::admission::AdmissionError;
use crate::failover::attachments::ControlPlane;
use crate::failover::evidence::Pair;
use crate::failover::fresh::{LocalRecords, Refusals};
use crate::failover::poll::Holder;
use crate::failover::record::LocalRecord;
use crate::failover::records::{Host, Record, ShardRecord};
use crate::failover::report::{RecoveryCheck, RecoveryRefusal};
use crate::failover::restart::tests::Stored;
use crate::failover::restart::{Local, LocalSource};
use crate::failover::retire::Target;
use crate::host::{self, Exit, HostGate, Recovery, Role};
use crate::oracle::Tenure;
use crate::storage::device::sim::{SimControl, sim_attached};
use crate::storage::gate_fixture::{OwnerClock, Reserving, limits, reserving_as};
use crate::storage::owner_fixture::TestPlatform;
use crate::storage::store::{Client, Store, StoreError, WatermarkLog};
use crate::storage::volume_fixture::{BUFFER, DEPTH, TICK, config_for, facts};
use crate::storage::{EngineBudget, ServingClock};

use super::super::super::link::{Faults, network};
use super::super::super::owner::Keys;
use super::super::super::owner_tests::{Mux, OWNER, PRINCIPALS, entries};
use super::super::{Grounds, Pools, ROUND_US, Serving, Source};
use super::topology::Member;
use super::{Cell, Fleet, Live, Stopped, fleet_instance};

/// After `drive` attaches a `SimControl`, each `now_us` call ticks that device, so a held command completes or times
/// out as the readings advance. `release` drops the clock's handle once the fencing that read it has returned.
#[derive(Default)]
pub(crate) struct FencerClock {
    control: RefCell<Option<SimControl>>,
    now: Slot<u64>,
}

impl FencerClock {
    fn drive(&self, control: &SimControl) {
        *self.control.borrow_mut() = Some(control.clone());
    }

    fn release(&self) {
        self.control.borrow_mut().take();
    }
}

impl ServingClock for FencerClock {
    fn now_us(&self) -> Option<u64> {
        if let Some(control) = self.control.borrow().as_ref() {
            control.tick(64);
        }
        let now = self.now.get();
        self.now.set(now + 1);
        Some(now)
    }
}

pub(super) struct OwnerLocal(pub(super) Stored);

impl LocalSource for OwnerLocal {
    fn local(&self) -> Result<LocalRecord, Local> {
        self.0.local()
    }
}

impl LocalRecords for OwnerLocal {
    fn persist(
        &mut self,
        _: &Holder,
        _: u32,
        _: crate::failover::identity::Key,
    ) -> Result<LocalRecord, AdmissionError> {
        Err(AdmissionError::AttemptConsumed)
    }

    fn retain_refusal(&mut self, _: &LocalRecord) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn release_refusal(&mut self, _: &LocalRecord) -> Result<(), AdmissionError> {
        Ok(())
    }
}

pub(super) enum Incarnation<'w> {
    Tenure(
        Box<host::Tenure<'w, TestPlatform, Reserving>>,
        SimControl,
        Rc<Slot<u64>>,
    ),
    Ended(Exit, Option<RecoveryRefusal>),
    Waits(Role),
    Unread(StoreError),
}

/// The names of the reservation commands `table` logged from `from` on, in order.
pub(super) fn commands_since(
    table: &crate::storage::gate_fixture::Control,
    from: usize,
) -> Vec<&'static str> {
    use crate::storage::ReservationCommand as C;
    (table.borrow().log[from..].iter())
        .map(|command| match command {
            C::Register { .. } => "register",
            C::Report { .. } => "report",
            C::Acquire { .. } => "acquire",
            C::PreemptAndAbort(_) => "preempt",
            C::PreemptLineage(_) => "lineage",
            C::PreemptEnded(_) => "ended",
        })
        .collect()
}

/// The device double of the host issuing as `pair` on `cell`'s media and reservation table. A pair the table holds
/// keeps its controller ID; another takes the next. While the volume is stalled or lost, the table delivers no
/// reservation completion, so a sequence's first command times out.
fn device(cell: &Cell, pair: Pair) -> (Reserving, SimControl) {
    let world = &cell.world;
    let (disk, control) = sim_attached(config_for(7), Rc::clone(&world.a.media), facts(BUFFER));
    let mut table = world.reservation.borrow_mut();
    let held = table.entries.iter().find(|entry| entry.pair == pair);
    let next = (table.entries.iter())
        .map(|entry| entry.cntlid)
        .max()
        .unwrap_or(0)
        + 1;
    let cntlid = held.map_or(next, |entry| entry.cntlid);
    table.budget = (cell.device != super::volumes::Device::Up).then_some(0);
    drop(table);
    (
        reserving_as(disk, &world.reservation, pair, cntlid),
        control,
    )
}

/// The incarnation of the owner process of `of`, issuing as `pair`, for `cell` at fleet round `round`: the role read
/// through `client`, then `host::recover` through a fencer over the host's device double, on the arena and clock of
/// `grounds`, under the cell's bounds and serving clock.
///
/// # Panics
///
/// The incarnation panics when `host::recover` ends `Rerun(Unwound)` for a restart or a fresh activation.
pub(super) fn incarnate<'w, S, L, R, K>(
    (cell, of, pair): (&Cell, Member, Pair),
    round: u64,
    grounds: &'w Grounds,
    client: &mut Client<S, L>,
    (local, plane, refusals): (&mut R, &mut K, &mut Refusals),
) -> Incarnation<'w>
where
    S: Store,
    L: WatermarkLog,
    R: LocalSource + LocalRecords,
    K: ControlPlane,
{
    let volume = cell.placement.volume;
    let holder = crate::failover::takeover::tests::holder_on(volume, of.host, of.instance);
    let shard = cell.placement.shard;
    let (role, volume, _) = match host::survey(client, shard, &holder) {
        Ok(surveyed) => surveyed,
        Err(error) => return Incarnation::Unread(error),
    };
    let peers = host::inputs::peers(&holder, &volume, fleet_instance)
        .expect("the holder's own volume record");
    let inputs = host::Inputs::new(shard, holder, cell.world.bounds, limits(), 4)
        .expect("limits that agree with the bounds");
    let now = Rc::new(Slot::new(round * ROUND_US));
    let clock = OwnerClock {
        strategy: cell.world.strategy,
        now: Rc::clone(&now),
    };
    let (disk, control) = device(cell, pair);
    grounds.fencer.drive(&control);
    let gate = HostGate::qualified();
    let fencer = host::fencer::Fencer::new(
        &gate,
        move || Ok((disk, pair)),
        limits(),
        &grounds.buffers,
        &grounds.fencer,
    );
    let sources = host::Sources {
        client,
        local,
        plane,
        refusals,
    };
    let recovered = host::recover(
        &gate,
        role,
        (&inputs, &peers),
        sources,
        fencer,
        Box::new(clock),
    );
    // The fencer reads its clock only inside `recover`.
    grounds.fencer.release();
    match recovered {
        Recovery::Tenure(tenure) => Incarnation::Tenure(tenure, control, now),
        Recovery::Ended(ended) => {
            let host::recover::Ended {
                exit,
                device,
                refusal,
            } = *ended;
            // A table that still owns a command ends through the proven stop, which returns its buffers to the
            // arena the slot's next tenure attaches over.
            if let host::fencer::Release::Outstanding(table) = device {
                stop_table(table, &control);
            }
            // `recover` contains its sequence's unwind and ends `Rerun(Unwound)`. The incarnation fails here, outside
            // that boundary, so a sequence that panicked fails its test.
            let sequence = match role {
                Role::Fresh => "fresh activation",
                _ => "restart",
            };
            assert_ne!(
                exit,
                Exit::Rerun(host::Rerun::Unwound),
                "the {sequence} unwound"
            );
            Incarnation::Ended(exit, refusal)
        }
        Recovery::Waits => Incarnation::Waits(role),
    }
}

/// What one view period of a standby's or unnamed host's wait returned.
pub(super) enum Stood<'w> {
    /// The tenure the period's takeover acquired, its device's control, and its serving clock's true-time cell.
    Tenure(
        Box<host::Tenure<'w, TestPlatform, Reserving>>,
        SimControl,
        Rc<Slot<u64>>,
    ),
    /// The exit the wait ended with: `Exit::Stopped` once the period passed with no takeover that acquired a tenure
    /// or ended the incarnation.
    Ended(Exit, Option<RecoveryRefusal>),
}

/// One view period of the wait of the owner process of `of`, issuing as `pair`, for `cell` at fleet round `round`:
/// `host::stand_by` over `client` and `local`, whose `period` returns once and sets the stop flag on its next call.
/// The period reads `witness` at the time it carries, and the takeover it starts runs through a fencer over the host's device double on the arena and clock of
/// `grounds`. Its connect records whether the shard record already names `of`'s host owner with no standby, read
/// from `store` with no request, and once `host::stand_by` returns the period asserts that every device call
/// followed the committed takeover (CAS-BEFORE-DEVICE) and that no takeover unwound. Under `early`, the fencer
/// starts the device before the period runs, while the record still names the lost owner.
pub(super) fn stand_by<'w, S, L>(
    (cell, of, pair): (&Cell, Member, Pair),
    (round, store): (u64, &crate::storage::store::sim::Shared),
    grounds: &'w Grounds,
    (client, local): (&mut Client<S, L>, &Stored),
    (witness, early): (
        Option<(crate::failover::detect::host::Revalidated, u64)>,
        bool,
    ),
    persist: impl FnMut(crate::failover::identity::Key) -> Result<LocalRecord, AdmissionError>,
) -> Stood<'w>
where
    S: Store,
    L: WatermarkLog,
{
    let volume = cell.placement.volume;
    let holder = crate::failover::takeover::tests::holder_on(volume, of.host, of.instance);
    let shard = cell.placement.shard;
    let inputs = host::Inputs::new(shard, holder, cell.world.bounds, limits(), 4)
        .expect("limits that agree with the bounds");
    let now = Rc::new(Slot::new(round * ROUND_US));
    let clock = OwnerClock {
        strategy: cell.world.strategy,
        now: Rc::clone(&now),
    };
    let (disk, control) = device(cell, pair);
    grounds.fencer.drive(&control);
    let gate = HostGate::qualified();
    let (store, host) = (store.clone(), of.host);
    // The record a device call met before the committed takeover, judged once `host::stand_by` returns, outside
    // its unwind boundary.
    let early_call: Slot<Option<(Host, Option<Host>)>> = Slot::new(None);
    let connect = || {
        let record = {
            let store = store.0.borrow();
            let item = store.current(&crate::storage::store::Key::Shard(shard));
            ShardRecord::decode(&item.expect("a stored shard record").value)
                .expect("a shard record")
        };
        if (record.owner, record.standby) != (host, None) {
            early_call.set(Some((record.owner, record.standby)));
        }
        Ok((disk, pair))
    };
    let mut fencer =
        host::fencer::Fencer::new(&gate, connect, limits(), &grounds.buffers, &grounds.fencer);
    if early {
        let _ = crate::failover::takeover::Device::start(&mut fencer);
    }
    let stop = std::sync::atomic::AtomicBool::new(false);
    let periods = Slot::new(0_u32);
    let period = || {
        periods.set(periods.get() + 1);
        if periods.get() > 1 {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
    };
    let read_at = witness.as_ref().map_or(round * ROUND_US, |(_, at)| *at);
    let mut witness = witness.map(|(witness, _)| witness);
    let signals = host::Signals {
        stop: &stop,
        period,
        nominations: || witness.take(),
        now: || read_at,
    };
    let standby = crate::failover::reconcile::StandbyGate::qualified();
    let stood = host::stand_by(
        (&gate, &standby),
        (&inputs, &fleet_instance),
        client,
        local,
        persist,
        fencer,
        Box::new(clock),
        signals,
    );
    grounds.fencer.release();
    assert_eq!(
        early_call.get(),
        None,
        "the first device call follows the committed takeover"
    );
    match stood {
        Ok(tenure) => Stood::Tenure(tenure, control, now),
        Err(ended) => {
            let host::recover::Ended {
                exit,
                device,
                refusal,
            } = *ended;
            if let host::fencer::Release::Outstanding(table) = device {
                stop_table(table, &control);
            }
            // `host::stand_by` contains a takeover's unwind and ends `Rerun(Unwound)`. The period fails here,
            // outside that boundary.
            assert_ne!(
                exit,
                Exit::Rerun(host::Rerun::Unwound),
                "the takeover unwound"
            );
            Stood::Ended(exit, refusal)
        }
    }
}

impl Fleet<'_> {
    pub(super) fn rise<'w>(
        &mut self,
        live: &mut Live<'w>,
        (grounds, pools): (&'w Grounds, &'w Pools<'w>),
        (at, own): (usize, Pair),
        (tenure, control, now): (
            host::Tenure<'w, TestPlatform, Reserving>,
            SimControl,
            Rc<Slot<u64>>,
        ),
        source: Source,
    ) -> Result<Option<Tenure>, Stopped> {
        let gate = HostGate::qualified();
        let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
        let attachment = host::Attachment {
            storage: &grounds.storage,
            clock: crate::storage::portable::scripted::ScriptedClock::trusted(),
            depth: DEPTH,
            tick: TICK,
        };
        let entries = entries();
        let endpoint = host::Endpoint {
            config: OWNER,
            keys: Keys {
                principals: &PRINCIPALS[..1],
                entries: &entries[..1],
                epoch: 1,
                put: &[],
            },
            transport: Mux::new(vec![owner_end]),
            receive: &pools.receive,
        };
        let mut budget = EngineBudget::new(1 << 26);
        let cell = &mut self.cells[at];
        // The owner's boot nonce is the one of the count this tenure takes once it has started.
        let nonce = super::super::boot_nonce(cell.world.served + 1, 1);
        let started = host::serve::start_up_with_nonce(
            &gate,
            tenure,
            attachment,
            endpoint,
            &mut budget,
            nonce,
        );
        cell.blocked = false;
        let owner = match started {
            Ok(owner) => owner,
            Err(unbrought) => {
                cell.refuse(format!("{:?}", unbrought.exit), false);
                return Ok(None);
            }
        };
        let target = owner.tenure().target();
        let tenure = tenure_at(target);
        cell.world.fence_tenure(tenure);
        let host = self.topology.members[cell.holder].host;
        self.activations.push((at, tenure, host));
        cell.world.served += 1;
        let registry = Rc::clone(&cell.world.reservation);
        let mut serving = Serving::started(
            &cell.world,
            (grounds, pools),
            (owner, control, registry, own),
            (tenure, now, self.round),
            (client_end, net),
        );
        serving.rising = Some(target);
        self.serve_opened(live, at, serving, source)
    }
}

/// Resets `control`'s device and drains `table`, which then holds no command.
fn stop_table(mut table: crate::storage::CommandTable<'_, Reserving>, control: &SimControl) {
    use crate::storage::{QuiesceProgress, Quiesced};
    control.set_quiesce(crate::storage::device::sim::QuiesceMode::Reset);
    let mut out = Vec::with_capacity(8);
    let stopped = table.quiesce(&mut out);
    assert_eq!(stopped, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
    assert!(
        table.release_idle().is_ok(),
        "a stopped table holds no command"
    );
}

pub(super) fn tenure_at(target: Target) -> Tenure {
    Tenure {
        g: target.generation.get(),
        a: u64::from(target.attempts) * 2,
    }
}

/// The check `refusal`'s class names, as a held restart's status reads it.
pub(super) fn check_of(refusal: RecoveryRefusal) -> Option<RecoveryCheck> {
    super::volumes::Held::of_restart(refusal)
        .status(0)
        .recovery(0)
        .check
}

/// The blocker an incarnation that ended with `exit` reports: the check its sequence's refusal class names, and the
/// exit when no sequence refused.
pub(super) fn blocker(exit: &Exit, refusal: Option<RecoveryRefusal>) -> String {
    match refusal.and_then(check_of) {
        Some(check) => format!("{check:?}"),
        None => format!("{exit:?}"),
    }
}
